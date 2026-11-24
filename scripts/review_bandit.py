#!/usr/bin/env python3
"""Classify an actual Bandit report against the reviewed, exact-source lab baseline."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def classify(root, report, baseline):
    root = Path(root).resolve()
    if report.get('errors') != [] or not isinstance(report.get('results'), list):
        raise ValueError('missing results or scanner errors')
    if baseline.get('profile') != 'itm-bandit-review-v1':
        raise ValueError('unsupported review baseline')
    def key(x):
        return (x['file'], x['line'], x['rule'], x['severity'], x['confidence'])
    expected = [x for x in baseline['findings'] if x['disposition'] != 'remediated_pending_rescan']
    known = {key(x): x for x in expected}
    if len(known) != len(expected):
        raise ValueError('duplicate reviewed finding')
    reviewed, unresolved, seen = [], [], set()
    for x in report['results']:
        p = (root / x['filename']).resolve()
        try:
            name = p.relative_to(root).as_posix()
        except ValueError:
            name = None
        meta = dict(file=name, line=x['line_number'], rule=x['test_id'], severity=x['issue_severity'], confidence=x['issue_confidence'])
        k = key(meta)
        prior = known.get(k)
        if (prior and k not in seen and meta['severity'] != 'HIGH' and p.is_file()
                and sha(p.read_bytes()) == prior['source_sha256']
                and sha(p.read_text().splitlines()[meta['line']-1].encode()) == prior['line_sha256']):
            reviewed.append(meta | {'disposition': prior['disposition']})
            seen.add(k)
        else:
            unresolved.append(meta)
    missing = [known[k] for k in sorted(known.keys()-seen)]
    return {'status': 'REVIEWED_LAB_BASELINE' if not unresolved and not missing else 'REVIEW_REQUIRED',
            'reviewed': reviewed, 'unresolved': unresolved, 'missing_reviewed_findings': missing,
            'publication_ready': False, 'production_ready': False, 'merge_authority': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    r = classify(root, json.loads(args.report.read_text()), json.loads((root/'docs/bandit-review.json').read_text()))
    print(json.dumps(r, indent=2))
    return 0 if r['status'] == 'REVIEWED_LAB_BASELINE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
