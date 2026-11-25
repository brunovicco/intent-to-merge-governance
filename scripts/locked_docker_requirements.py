#!/usr/bin/env python3
"""Export this release's audited CPython wheel graph; no resolver or build fallback."""
import re
import sys
import tomllib
from pathlib import Path

NAMES = {'cffi', 'cryptography', 'opentelemetry-api', 'opentelemetry-sdk',
         'opentelemetry-semantic-conventions', 'pycparser', 'typing-extensions'}


def requirements(path):
    lock = tomllib.loads(Path(path).read_text())
    if lock.get('version') != 1 or lock.get('revision') != 3:
        raise ValueError('unsupported lock schema')
    packages = lock['package']
    by_name = {p['name']: p for p in packages}
    if len(by_name) != len(packages) or set(by_name) != NAMES | {'intent-to-merge-governance'}:
        raise ValueError('unexpected dependency graph')
    if by_name['intent-to-merge-governance']['version'] != '2.0.0rc1':
        raise ValueError('unexpected project version')
    lines = []
    for name in sorted(NAMES):
        p = by_name[name]
        version = p['version']
        if p['source'] != {'registry': 'https://pypi.org/simple'} or not re.fullmatch(r'[0-9][0-9A-Za-z.]*', version):
            raise ValueError('unexpected package source/version')
        if not p.get('wheels'):
            raise ValueError('wheel required')
        hashes = sorted({w['hash'] for w in p['wheels']})
        if any(not re.fullmatch(r'sha256:[0-9a-f]{64}', h) for h in hashes):
            raise ValueError('invalid wheel hash')
        lines.append(f'{name}=={version} ' + ' '.join('--hash='+h for h in hashes))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    print(requirements(sys.argv[1]), end='')
