"""Versioned, repository-relative path policy. Not gitignore or CODEOWNERS."""
from fnmatch import fnmatchcase
from functools import lru_cache
import re

SEGMENT_V2 = 'segment-v2'
LEGACY_V1 = 'fnmatch-v1'


def _parts(value):
    if (not isinstance(value, str) or not value or len(value) > 4096
            or '\\' in value or re.match(r'^[A-Za-z]:', value)
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ValueError('invalid repository-relative path')
    parts = value.split('/')
    if len(parts) > 128 or any(p in ('', '.', '..') for p in parts):
        raise ValueError('invalid repository-relative path segment')
    return parts


def validate_pattern(pattern):
    parts = _parts(pattern)
    # Deliberately narrow grammar. No negation, bracket classes or escaping.
    if pattern.startswith('!') or any('[' in p or ']' in p or ('**' in p and p != '**') for p in parts):
        raise ValueError('unsupported path pattern')
    return parts


def validate_patterns(patterns, *, nonempty=False):
    if not isinstance(patterns, list) or (nonempty and not patterns) or len(patterns) > 256:
        raise ValueError('invalid path pattern list')
    for pattern in patterns:
        validate_pattern(pattern)
    if len(set(patterns)) != len(patterns):
        raise ValueError('duplicate path pattern')


def matches(path, patterns, *, semantics=SEGMENT_V2):
    """Full-path matching; * and ? stay in one segment; ** spans zero or more."""
    if semantics == LEGACY_V1:
        return any(fnmatchcase(path, pattern) for pattern in patterns)
    if semantics != SEGMENT_V2:
        raise ValueError('unknown path semantics')
    # Invalid candidate paths never match an allowlist. Invalid patterns raise.
    compiled = [validate_pattern(p) for p in patterns]
    try:
        path_parts = _parts(path)
    except ValueError:
        return False

    def match(pattern_parts):
        @lru_cache(maxsize=None)
        def visit(i, j):
            if i == len(pattern_parts):
                return j == len(path_parts)
            if pattern_parts[i] == '**':
                return visit(i + 1, j) or (j < len(path_parts) and visit(i, j + 1))
            return (j < len(path_parts)
                    and fnmatchcase(path_parts[j], pattern_parts[i])
                    and visit(i + 1, j + 1))
        return visit(0, 0)

    return any(match(p) for p in compiled)
