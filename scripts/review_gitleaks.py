#!/usr/bin/env python3
"""Classify only the four previously reviewed public-key fixture findings.
Preserve the raw redacted report. No blanket scanner suppression.
"""
import argparse
import hashlib
import json
from pathlib import Path

FIXTURE = 'examples/changeset-v1/config.json'
FIXTURE_SHA256 = '087a2e70149641044ff02e3ebc3f6e52a59cb811f77a85b464044beda681c2b9'
LINES = {11, 19, 29, 32}


def classify(root, report):
    root = Path(root).resolve()
    exact_fixture = hashlib.sha256((root / FIXTURE).read_bytes()).hexdigest() == FIXTURE_SHA256
    if not isinstance(report, list):
        raise ValueError('expected scanner findings list')
    reviewed, remaining, seen = [], [], set()
    for item in report:
        if not isinstance(item, dict):
            raise ValueError('invalid finding')
        p = Path(item['File'])
        p = p if p.is_absolute() else root / p
        try:
            path = p.resolve().relative_to(root).as_posix()
        except ValueError:
            path = None
        line = item.get('StartLine')
        meta = {'rule': item.get('RuleID'), 'file': path, 'line': line, 'end': item.get('EndLine')}
        if (exact_fixture and path == FIXTURE and meta['rule'] == 'generic-api-key'
                and type(line) is int and line in LINES and meta['end'] == line and line not in seen):
            reviewed.append(meta)
            seen.add(line)
        else:
            remaining.append(meta)
    return {'status': 'REVIEWED_PUBLIC_KEYS_ONLY' if reviewed and not remaining else 'REVIEW_REQUIRED',
            'reviewed': reviewed, 'remaining': remaining, 'fixture_digest_matches': exact_fixture,
            'publication_ready': False, 'merge_authority': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    r = classify(a.root, json.loads(a.report.read_text()))
    print(json.dumps(r, indent=2))
    return 0 if r['status'] == 'REVIEWED_PUBLIC_KEYS_ONLY' else 2

if __name__ == '__main__':
    raise SystemExit(main())
