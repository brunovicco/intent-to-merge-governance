"""Static, offline Governance Explorer; verifies bundles before displaying them."""
from html import escape
import json
from .bundle import verify

def render(bundles, public_key, output, *, pr_reports=(), sessions=()):
    def e(v): return escape(str(v),quote=True)
    cards=[]
    for b in bundles:
        result=verify(b,public_key)
        report=json.loads((b/'evidence/report.json').read_text())
        coverage=report.get('requirement_coverage',[])
        decision=report.get('decision',{})
        rows=''.join(f'<tr><td>{e(r.get("id"))}</td><td><pre>{e(json.dumps(r,indent=2))}</pre></td></tr>' for r in coverage)
        details=''.join(f'<details><summary>{e(name)}</summary><pre>{e((b/"evidence"/name).read_text())}</pre></details>' for name in ('intent-graph.json','checkpoints.json','intent-drift.json','verification.json','convergence.json') if (b/'evidence'/name).is_file())
        status='MERGED' if result['merged'] else 'BLOCKED'
        cards.append(f'<article><header><span class="tag">{e(result["profile"])}</span><h2>{e(report.get("scenario",b.name))}</h2><strong class="{status.lower()}">{status}</strong></header><div class="stats"><div><small>Signature</small><b>Verified</b></div><div><small>Artifacts</small><b>{result["subjects"]}</b></div><div><small>Requirements</small><b>{len(coverage)}</b></div></div><p>Commit <code>{e(result["candidate"])}</code></p><h3>Policy decision</h3><pre>{e(json.dumps(decision,indent=2))}</pre><h3>Requirement evidence</h3><table>{rows}</table><h3>Evidence explorer</h3>{details}</article>')
    for path in pr_reports:
        r=json.loads(path.read_text())
        if r.get('profile')!='github-live-preflight' or r.get('full_itm_authorization') is not False: raise ValueError('invalid preflight report')
        rows=''.join(f'<tr><td>{e(g["name"])}</td><td>{"PASS" if g["passed"] is True else "BLOCK"}</td></tr>' for g in r['gates'])
        cards.append(f'<article><header><span class="tag">{"Synthetic API fixture" if r.get("fixture") is True else "Imported snapshot"} — not authenticated</span><h2>{e(r["repository"])} / PR #{e(r["pr"])}</h2><strong>{e(r["decision"])}</strong></header><p>GitHub preflight only. Not full ITM authorization. Report may be stale.</p><p>Head <code>{e(r["head"])}</code> · Base <code>{e(r["base"])}</code></p><table>{rows}</table></article>')
    for path in sessions:
        r=json.loads(path.read_text()); session=r['session']
        if r.get('trust')!='self_reported' or r.get('merge_authority') is not False: raise ValueError('invalid session report')
        cards.append(f'<article><header><span class="tag">{"Synthetic session fixture" if r.get("fixture") is True else "Self-reported"} — not authenticated</span><h2>{e(session["runtime"])}</h2></header><p>Claimed commit: <code>{e(r.get("claimed_head"))}</code></p><p>Events: {e(r["event_count"])} · Tool categories: {e(", ".join(session["tool_types"]))}</p><p>Source digest: <code>{e(r["source_sha256"])}</code></p></article>')
    html='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>ITM Governance Explorer</title><style>body{font:16px system-ui;color:#dbe7f4;background:#0c1420;margin:0}main{max-width:1050px;margin:auto;padding:32px 20px}h1{font-size:36px;margin:8px 0}p{color:#a9b9cc}article{background:#142131;border:1px solid #34465d;border-radius:12px;padding:24px;margin:20px 0}header{display:flex;gap:14px;align-items:center;flex-wrap:wrap}header h2{margin:0;flex:1}.tag{font-size:12px;color:#a9b9cc}.merged{color:#79e0b7}.blocked{color:#ffb3a5}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:18px}.stats div{padding:14px;background:#0c1420;border-radius:6px}small,b{display:block}small{color:#a9b9cc}b{font-size:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:#0c1420;padding:12px;border-radius:6px}code{overflow-wrap:anywhere}td{vertical-align:top;padding:4px}details{border-top:1px solid #34465d;padding:12px 0}summary{cursor:pointer}</style><main><p>INTENT-TO-MERGE / v0.5</p><h1>Governance Explorer</h1><p>Offline evidence inspection. Each signed bundle was verified against the supplied external key at export time. Imported PR and session reports are separately labeled and not authenticated. Synthetic results are not production authorization. This HTML is a presentation, not an attestation.</p>'''+''.join(cards)+'</main></html>'
    with output.open('x',encoding='utf-8') as f: f.write(html)
    return {'output':str(output),'verified_bundles':len(bundles),'imported_pr_reports':len(pr_reports),'imported_sessions':len(sessions)}
