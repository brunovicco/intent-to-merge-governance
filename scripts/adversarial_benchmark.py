#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from intent_merge.adversarial import study
p=argparse.ArgumentParser(description='Curated synthetic adversarial replay; no live merge authority')
p.add_argument('--out',type=Path,required=True);p.add_argument('--backend',choices=['local','docker'],default='local');p.add_argument('--image',default='python:3.11-slim');a=p.parse_args()
r=study(a.out,Path(__file__).resolve().parents[1],backend=a.backend,image=a.image);print(json.dumps(r['summary'],indent=2))
raise SystemExit(2 if r['summary']['S3']['unsafe_accepted'] or r['summary']['S3']['safe_blocked'] else 0)
