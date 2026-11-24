"""Import native JSONL streams without retaining prompts or tool payloads."""
from __future__ import annotations
import hashlib, json, re
from .checkpoints import normalize_session
from .agent_telemetry import project

MAX_BYTES=32*1024*1024

def import_agent(provider,path,agent_id='coding-agent',head=None):
    if provider not in ('claude','codex'): raise ValueError('unsupported provider')
    if head is not None and not re.fullmatch(r'[0-9a-f]{40}',head): raise ValueError('invalid claimed commit SHA')
    with path.open('rb') as f: raw=f.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise ValueError('session export too large')
    ids=set(); tools=set(); events=0; completed=False; failed=False; terminal_events=[]
    for line in raw.splitlines():
        if not line.strip(): continue
        e=json.loads(line); events+=1
        if not isinstance(e,dict): raise ValueError('invalid native event')
        kind=e.get('type')
        if kind==('result' if provider=='claude' else 'turn.completed'):
            terminal_events.append({k:e[k] for k in ('type','usage','total_cost_usd','modelUsage') if k in e})
        if provider=='codex':
            if kind=='thread.started' and isinstance(e.get('thread_id'),str): ids.add(e['thread_id'])
            if kind=='turn.completed': completed=True
            if kind in ('turn.failed','error'): failed=True
            if kind=='item.completed':
                item=e.get('item',{}); t=item.get('type')
                category={'command_execution':'shell','file_change':'write','web_search':'search','mcp_tool_call':'other'}.get(t)
                if category: tools.add(category)
        else:
            if isinstance(e.get('session_id'),str): ids.add(e['session_id'])
            if kind=='result':
                completed=e.get('subtype')=='success' and e.get('is_error') is False
                failed=failed or not completed
            if kind=='assistant':
                for item in e.get('message',{}).get('content',[]):
                    if item.get('type')=='tool_use': tools.add({'Read':'read','Edit':'write','Write':'write','Bash':'shell','Grep':'search','Glob':'search'}.get(item.get('name'),'other'))
    if len(ids)!=1 or not completed or failed: raise ValueError('expected one successfully completed native session')
    sid=hashlib.sha256(next(iter(ids)).encode()).hexdigest()
    normalized=normalize_session({'schema_version':'1.0','provider':'anthropic' if provider=='claude' else 'openai','runtime':'claude-code' if provider=='claude' else 'codex','session_id':sid,'agent_id':agent_id,'tool_types':sorted(tools),'claimed_requirements':[]})
    return {'schema_version':'1.0','session':normalized,'source_sha256':hashlib.sha256(raw).hexdigest(),'event_count':events,'telemetry':project(provider,terminal_events),'claimed_head':head,'commit_binding':'self_reported','trust':'self_reported','merge_authority':False,'note':'Native stream imported, not authenticated; no prompts, commands, tool arguments or outputs retained.'}
