#!/usr/bin/env python3
"""Read the RC6 local readiness checkpoint; compare to a separately trusted digest."""
import argparse,json,sqlite3,sys
from contextlib import closing
from pathlib import Path
from intent_merge.integrated import Lifecycle

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--db',type=Path,required=True);p.add_argument('--expected-digest');a=p.parse_args()
    if not a.db.is_file() or a.db.is_symlink():p.error('existing v2 journal required')
    # A missing/empty journal must not be initialized by an audit operation.
    try:
        with closing(sqlite3.connect(a.db.resolve().as_uri()+'?mode=ro',uri=True)) as probe:
            if probe.execute('PRAGMA user_version').fetchone()[0]!=2:raise ValueError('unsupported journal version')
        j=Lifecycle(a.db)
        try:
            actual=j.checkpoint();matched=None if a.expected_digest is None else actual==a.expected_digest
        finally:j.close()
        print(json.dumps({'profile':'itm-readiness-checkpoint-v2','digest':actual,'matches_external_pin':matched,'merge_authority':False},indent=2))
        return 2 if matched is False else 0
    except (ValueError,OSError,sqlite3.Error):
        print(json.dumps({'status':'INVALID_JOURNAL','merge_authority':False}));return 2
if __name__=='__main__':raise SystemExit(main())
