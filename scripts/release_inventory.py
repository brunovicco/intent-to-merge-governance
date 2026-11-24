#!/usr/bin/env python3
"""Release source inventory; unsigned, not an SBOM or a production approval."""
import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', '__pycache__', 'results', '.itm-lab-keys', 'node_modules'}
INVENTORY = 'release-inventory.json'
PROFILE = 'itm-release-inventory-v2'


def files(root):
    result = {}
    for p in sorted(root.rglob('*')):
        rel = p.relative_to(root)
        if any(part in EXCLUDED or part.endswith('.egg-info') for part in rel.parts) or rel.as_posix() == INVENTORY:
            continue
        if p.is_symlink():
            raise ValueError(f'symlink in release: {rel}')
        if not p.is_file():
            continue
        if p.suffix.lower() in {'.pem', '.key', '.sqlite', '.db', '.pyc', '.p12', '.pfx'} or p.name == '.env' or p.name.startswith('.env.'):
            raise ValueError(f'private or runtime artifact: {rel}')
        data = p.read_bytes()
        result[rel.as_posix()] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    return result


def differences(expected, actual):
    return {'extra': sorted(actual.keys() - expected.keys()),
            'missing': sorted(expected.keys() - actual.keys()),
            'modified': sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])}


def load(root):
    p = root / INVENTORY
    if p.is_symlink():
        raise ValueError('inventory symlink')
    expected = json.loads(p.read_text())
    project = tomllib.loads((root / 'pyproject.toml').read_text())['project']
    if expected['profile'] != PROFILE or expected['release'] != project['version']:
        raise ValueError('inventory profile or release mismatch')
    return expected


def verify(root, require_lock=False):
    expected = load(root)
    actual = files(root)
    diff = differences(expected['files'], actual)
    locked = 'uv.lock' in expected['files'] and 'uv.lock' in actual
    ok = not any(diff.values()) and (locked or not require_lock)
    return {'status': 'PASS' if ok else 'FAIL', 'expected_files': len(expected['files']),
            'actual_files': len(actual), **diff, 'lockfile_in_inventory': locked,
            'publication_ready': False, 'merge_authority': False}


def seal_lock(root):
    expected = load(root)
    actual = files(root)
    if differences(expected['files'], actual) != {'extra': ['uv.lock'], 'missing': [], 'modified': []}:
        raise ValueError('seal-lock requires exactly one new file: uv.lock; no other changes permitted')
    # Validate the actual resolver-produced lock, rather than fabricating metadata.
    subprocess.run(['uv', 'lock', '--check'], cwd=root, check=True, timeout=120)
    if files(root) != actual:
        raise ValueError('source changed during lock validation')
    expected['files']['uv.lock'] = actual['uv.lock']
    expected['lockfile_status'] = 'PRESENT_UV_CHECK_PASSED'
    target = root / INVENTORY
    # This is a maintainer-side operation before signing, not an integrity bypass.
    target.write_text(json.dumps(expected, indent=2, sort_keys=True) + '\n')
    return verify(root, require_lock=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['verify', 'seal-lock'])
    parser.add_argument('--require-lock', action='store_true')
    a = parser.parse_args()
    try:
        report = seal_lock(ROOT) if a.mode == 'seal-lock' else verify(ROOT, a.require_lock)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report = {'status': 'FAIL', 'error': type(exc).__name__, 'detail': str(exc), 'merge_authority': False}
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
