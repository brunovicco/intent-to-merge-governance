#!/usr/bin/env python3
"""High-confidence offline pattern preflight, not exhaustive secret scanning."""
import json
import re
from release_inventory import ROOT, files

PATTERNS = {
    'private_key_header': rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----',
    'github_token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{35,})\b',
    'anthropic_token': rb'\bsk-ant-[A-Za-z0-9_-]{20,}\b',
    'openai_token': rb'\bsk-(?:proj-|svcacct-)[A-Za-z0-9_-]{20,}\b',
    'aws_access_key_id': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
}


def scan(root):
    paths = files(root)
    findings = []
    for name in paths:
        data = (root / name).read_bytes()
        for label, pattern in PATTERNS.items():
            for match in re.finditer(pattern, data):
                findings.append({'path': name, 'line': data.count(b'\n', 0, match.start()) + 1, 'rule': label})
    return {'status': 'REVIEW' if findings else 'PASS', 'files_scanned': len(paths), 'findings': findings,
            'scope': 'five high-confidence pattern categories; no history, entropy, external secrets or full SAST',
            'publication_ready': False, 'merge_authority': False}


if __name__ == '__main__':
    r = scan(ROOT)
    print(json.dumps(r, indent=2))
    raise SystemExit(2 if r['findings'] else 0)
