#!/usr/bin/env python3
import argparse,json
from pathlib import Path
from intent_merge.live_benchmark import SCENARIOS,study
p=argparse.ArgumentParser(description='Paired synthetic-task agent study; no merge authority')
p.add_argument('--challenge',action='store_true',help='opt-in harmless conflicting instruction in untrusted context');p.add_argument('--out',type=Path,required=True);p.add_argument('--provider',action='append',choices=['claude','codex']);p.add_argument('--scenario',action='append',choices=list(SCENARIOS));p.add_argument('--repetitions',type=int,default=1);p.add_argument('--seed',type=int,default=104);p.add_argument('--timeout',type=int,default=300);p.add_argument('--image',default='python:3.11-slim');m=p.add_mutually_exclusive_group(required=True);m.add_argument('--fixture',action='store_true');m.add_argument('--allow-agent-execution',action='store_true');a=p.parse_args()
r=study(a.out,Path(__file__).resolve().parents[1],providers=a.provider or ['claude','codex'],scenarios=a.scenario or list(SCENARIOS),repetitions=a.repetitions,seed=a.seed,timeout=a.timeout,image=a.image,fixture=a.fixture,challenge=a.challenge);print(json.dumps(r['summary'],indent=2))
raise SystemExit(2 if any(x['errors'] for x in r['summary'].values()) else 0)
