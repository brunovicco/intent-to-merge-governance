"""Non-authorizing, redacted failure results at CLI boundaries."""
import json
import sqlite3
import subprocess
import sys

from .github import CheckPublicationUnconfirmed
from .policy_schema import InvalidConfiguration


class TelemetryUnavailable(ValueError):
    """The requested optional telemetry runtime is not installed."""


def telemetry_provider(stream):
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    except ModuleNotFoundError as exc:
        if (exc.name or '').startswith('opentelemetry'):
            raise TelemetryUnavailable('install the telemetry extra') from None
        raise
    provider = TracerProvider()
    try:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=stream)))
    except Exception:
        provider.shutdown()
        raise
    return provider


def failure(command, exc, *, remote_write_possible=False):
    if isinstance(exc, InvalidConfiguration):
        code = 'INVALID_CONFIGURATION'
    elif isinstance(exc, TelemetryUnavailable):
        code = 'OPTIONAL_TELEMETRY_UNAVAILABLE'
    elif isinstance(exc, (sqlite3.Error, OSError, subprocess.SubprocessError)):
        code = 'OPERATIONAL_ERROR'
    elif isinstance(exc, (ValueError, KeyError, TypeError)):
        code = 'INPUT_OR_EVALUATION_ERROR'
    else:
        code = 'UNEXPECTED_ERROR'
    # Raw exception messages may contain paths, tokens or inputs.
    result = {
        'command': command,
        'status': 'INVALID_CONFIGURATION' if code == 'INVALID_CONFIGURATION' else 'ERROR',
        'decision': 'BLOCK',
        'authorized': False,
        'merged': False,
        'merge_authority': False,
        'production_ready': False,
        'reason': code,
        'remote_state': 'NOT_CONFIRMED' if remote_write_possible else 'NOT_ASSESSED',
    }
    if isinstance(exc, CheckPublicationUnconfirmed):
        result['remote_state'] = 'NOT_CONFIRMED'
        result['publication'] = exc.correlation
    return result


def emit_failure(command, exc, *, remote_write_possible=False):
    print(json.dumps(failure(command, exc, remote_write_possible=remote_write_possible)), file=sys.stderr)
