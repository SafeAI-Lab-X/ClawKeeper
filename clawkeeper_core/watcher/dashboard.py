"""Self-contained dashboard HTML served at GET / by the Watcher daemon."""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClawKeeper Monitor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#1f3a68;--dknav:#162d55;--gold:#e1a039;--white:#f5f7fa;
  --green:#27ae60;--red:#e74c3c;--amber:#f39c12;--blue:#2e86c1;
  --purple:#8e44ad;--gray:#8899bb;--bg:#0d1b33;--card:#162d55;
  --border:#1f3a68;--text:#ccdeff;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* TOP BAR */
#topbar{background:var(--dknav);border-bottom:2px solid var(--gold);padding:8px 16px;display:flex;align-items:center;gap:24px;flex-shrink:0}
#topbar .logo{font-size:18px;font-weight:700;color:var(--white);letter-spacing:.5px}
#topbar .logo span{color:var(--gold)}
.stat{display:flex;flex-direction:column;align-items:center}
.stat .val{font-size:20px;font-weight:700;color:var(--gold)}
.stat .lbl{font-size:10px;color:var(--gray);text-transform:uppercase;letter-spacing:.5px}
#conn-dot{width:8px;height:8px;border-radius:50%;background:#555;margin-left:auto;transition:background .3s}
#conn-dot.live{background:var(--green);box-shadow:0 0 6px var(--green)}
#conn-lbl{font-size:11px;color:var(--gray)}

/* MAIN LAYOUT */
#main{display:flex;flex:1;overflow:hidden;gap:0}

/* LEFT: event feed */
#feed-col{flex:0 0 62%;display:flex;flex-direction:column;border-right:1px solid var(--border)}
#feed-header{padding:8px 12px;background:var(--dknav);font-size:11px;font-weight:600;color:var(--gray);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);flex-shrink:0}
#feed{flex:1;overflow-y:auto;padding:8px;display:flex;flex-direction:column;gap:6px}

/* EVENT CARDS */
.ev{background:var(--card);border-radius:6px;border-left:4px solid #555;padding:8px 10px;cursor:pointer;transition:border-color .2s}
.ev.allow{border-left-color:var(--green)}
.ev.ask{border-left-color:var(--amber)}
.ev.deny{border-left-color:var(--red)}
.ev.new{animation:flash .6s ease-out}
@keyframes flash{0%{background:#2a4a7a}100%{background:var(--card)}}
.ev-top{display:flex;align-items:center;gap:8px}
.ev-tool{font-weight:600;color:var(--white);font-size:12px}
.ev-cmd{color:var(--gray);font-family:monospace;font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.badge.allow{background:#1a4a2a;color:var(--green)}
.badge.ask{background:#4a3a0a;color:var(--amber)}
.badge.deny{background:#4a1a1a;color:var(--red)}
.badge.guard{background:#1a2a4a;color:var(--blue)}
.badge.watcher{background:#2a1a4a;color:var(--purple)}
.ev-meta{font-size:10px;color:var(--gray);margin-top:3px;display:flex;gap:10px}
.ev-detail{display:none;margin-top:8px;border-top:1px solid var(--border);padding-top:8px}
.ev.open .ev-detail{display:block}
.guard-row{display:flex;align-items:center;gap:6px;padding:3px 0;font-size:11px}
.guard-name{color:var(--blue);font-family:monospace;min-width:140px}
.guard-sev{font-size:10px;padding:1px 5px;border-radius:3px}
.sev-hardline,.sev-critical{background:#4a0a0a;color:#ff6666}
.sev-high{background:#3a1a0a;color:#ff9944}
.sev-medium{background:#3a2a0a;color:#ffcc44}
.sev-low{background:#1a2a1a;color:#88cc88}
.guard-reason{color:var(--gray);font-size:10px;flex:1}
.watcher-box{background:#1a1a2a;border:1px solid var(--purple);border-radius:4px;padding:6px 8px;margin-top:6px;font-size:11px}
.watcher-box .wlbl{color:var(--purple);font-weight:600;font-size:10px;text-transform:uppercase;margin-bottom:3px}
.watcher-reason{color:var(--text)}
.conf-bar{height:4px;background:#2a2a4a;border-radius:2px;margin-top:4px}
.conf-fill{height:100%;border-radius:2px;background:var(--purple)}

/* LEARNED event */
.ev.learned{border-left-color:var(--gold)}
.ev-pattern{font-family:monospace;font-size:11px;color:var(--gold);margin-top:4px;word-break:break-all}

/* RIGHT PANEL */
#right-col{flex:1;display:flex;flex-direction:column;overflow:hidden}
#right-inner{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:12px}

.panel{background:var(--card);border-radius:6px;padding:10px}
.panel-title{font-size:10px;font-weight:700;color:var(--gray);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}

/* DECISION DONUT (CSS only) */
#donut-wrap{display:flex;align-items:center;gap:12px}
.donut{width:64px;height:64px;border-radius:50%;flex-shrink:0}
.donut-legend{display:flex;flex-direction:column;gap:4px;font-size:11px}
.dl-row{display:flex;align-items:center;gap:6px}
.dl-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* GUARD BARS */
.gbar-row{display:flex;align-items:center;gap:6px;margin-bottom:5px}
.gbar-name{font-family:monospace;font-size:10px;color:var(--blue);min-width:120px}
.gbar-track{flex:1;height:8px;background:#0d1b33;border-radius:4px;overflow:hidden}
.gbar-fill{height:100%;background:var(--blue);border-radius:4px;transition:width .4s}
.gbar-count{font-size:10px;color:var(--gray);min-width:24px;text-align:right}

/* SESSIONS */
.sess-row{display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid var(--border);font-size:11px}
.sess-id{font-family:monospace;color:var(--blue);min-width:80px;overflow:hidden;text-overflow:ellipsis}
.sess-intent{color:var(--gray);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sess-calls{color:var(--gold);font-weight:600;min-width:28px;text-align:right}

/* LEARNED PATTERNS */
.pat-chip{display:inline-flex;align-items:center;gap:5px;background:#1a1a0a;border:1px solid var(--gold);border-radius:12px;padding:3px 8px;margin:3px;font-size:10px;font-family:monospace;color:var(--gold)}
.pat-chip .pt{color:var(--gray)}

/* BOTTOM TICKER */
#ticker{background:var(--dknav);border-top:1px solid var(--red);padding:5px 12px;font-size:11px;color:var(--red);flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#ticker span{color:var(--gray);margin-right:8px}

/* SCROLLBAR */
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#2a3a5a;border-radius:2px}
</style>
</head>
<body>

<div id="topbar">
  <div class="logo">Claw<span>Keeper</span> Monitor</div>
  <div class="stat"><div class="val" id="s-total">0</div><div class="lbl">Total Calls</div></div>
  <div class="stat"><div class="val" id="s-blocked">0</div><div class="lbl">Blocked</div></div>
  <div class="stat"><div class="val" id="s-rate">0%</div><div class="lbl">Block Rate</div></div>
  <div class="stat"><div class="val" id="s-sessions">0</div><div class="lbl">Sessions</div></div>
  <div class="stat"><div class="val" id="s-learned">0</div><div class="lbl">Learned</div></div>
  <div id="conn-dot"></div><div id="conn-lbl">connecting…</div>
</div>

<div id="main">
  <div id="feed-col">
    <div id="feed-header">Live Event Feed</div>
    <div id="feed"></div>
  </div>
  <div id="right-col">
    <div id="right-inner">

      <div class="panel">
        <div class="panel-title">Decision Distribution</div>
        <div id="donut-wrap">
          <canvas id="donut" width="64" height="64"></canvas>
          <div class="donut-legend">
            <div class="dl-row"><div class="dl-dot" style="background:#27ae60"></div><span id="dl-allow">Allow: 0</span></div>
            <div class="dl-row"><div class="dl-dot" style="background:#f39c12"></div><span id="dl-ask">Ask: 0</span></div>
            <div class="dl-row"><div class="dl-dot" style="background:#e74c3c"></div><span id="dl-deny">Deny: 0</span></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">Guard Activity</div>
        <div id="guard-bars"></div>
      </div>

      <div class="panel">
        <div class="panel-title">Active Sessions</div>
        <div id="sessions-list"><div style="color:var(--gray);font-size:11px">No sessions yet</div></div>
      </div>

      <div class="panel">
        <div class="panel-title">Learned Patterns <span id="pat-count" style="color:var(--gold)"></span></div>
        <div id="patterns-list"><div style="color:var(--gray);font-size:11px">None yet</div></div>
      </div>

    </div>
  </div>
</div>

<div id="ticker"><span>BLOCKED:</span> waiting for events…</div>

<script>
const $ = id => document.getElementById(id);
const feed = $('feed');

// State
let stats = {total:0, blocked:0, allow:0, ask:0, deny:0};
let guardCounts = {};
let sessions = {};
let blocked_cmds = [];
const GUARD_NAMES = ['exec_gate','path_guard','script_body_scan','url_safety','credential_redact','return_content_scan','input_validator','budget'];

function sev_class(s){ return 'sev-'+(s||'low').toLowerCase(); }

function fmt_cmd(cmd){ return cmd ? cmd.slice(0,80)+(cmd.length>80?'…':'') : '(no command)'; }

function ts_str(ts){ return ts ? new Date(ts*1000).toLocaleTimeString() : ''; }

function update_stats(){
  $('s-total').textContent = stats.total;
  $('s-blocked').textContent = stats.blocked;
  $('s-rate').textContent = stats.total ? Math.round(stats.blocked/stats.total*100)+'%' : '0%';
  $('s-sessions').textContent = Object.keys(sessions).length;
  $('dl-allow').textContent = 'Allow: '+stats.allow;
  $('dl-ask').textContent = 'Ask: '+stats.ask;
  $('dl-deny').textContent = 'Deny: '+stats.deny;
  draw_donut();
}

function draw_donut(){
  const c = document.getElementById('donut');
  if(!c) return;
  const ctx = c.getContext('2d');
  const total = stats.allow+stats.ask+stats.deny||1;
  const slices = [
    [stats.allow/total, '#27ae60'],
    [stats.ask/total,   '#f39c12'],
    [stats.deny/total,  '#e74c3c'],
  ];
  ctx.clearRect(0,0,64,64);
  let start = -Math.PI/2;
  for(const [frac,color] of slices){
    const end = start + frac*2*Math.PI;
    ctx.beginPath(); ctx.moveTo(32,32);
    ctx.arc(32,32,30,start,end); ctx.closePath();
    ctx.fillStyle = color; ctx.fill();
    start = end;
  }
  // donut hole
  ctx.beginPath(); ctx.arc(32,32,18,0,2*Math.PI);
  ctx.fillStyle = '#162d55'; ctx.fill();
}

function update_guard_bars(){
  const el = $('guard-bars');
  const max = Math.max(1,...Object.values(guardCounts));
  el.innerHTML = GUARD_NAMES.map(n=>{
    const cnt = guardCounts[n]||0;
    const pct = Math.round(cnt/max*100);
    return `<div class="gbar-row">
      <div class="gbar-name">${n}</div>
      <div class="gbar-track"><div class="gbar-fill" style="width:${pct}%"></div></div>
      <div class="gbar-count">${cnt}</div>
    </div>`;
  }).join('');
}

function update_sessions(){
  const el = $('sessions-list');
  const rows = Object.entries(sessions);
  if(!rows.length){ el.innerHTML='<div style="color:var(--gray);font-size:11px">No sessions yet</div>'; return; }
  el.innerHTML = rows.map(([id,s])=>`
    <div class="sess-row">
      <div class="sess-id">${id.slice(0,12)}</div>
      <div class="sess-intent">${s.intent||'(no intent)'}</div>
      <div class="sess-calls">${s.calls}</div>
    </div>`).join('');
}

function update_ticker(){
  if(!blocked_cmds.length) return;
  $('ticker').innerHTML = '<span>BLOCKED:</span> '+blocked_cmds.slice(-5).reverse().map(c=>
    `<span style="color:#ff6666;margin-right:16px">[${c.tool}] ${fmt_cmd(c.cmd)}</span>`
  ).join('');
}

function make_guard_rows(findings){
  if(!findings||!findings.length) return '<div style="color:var(--gray);font-size:11px;padding:4px 0">No deterministic guard findings</div>';
  return findings.map(f=>`
    <div class="guard-row">
      <div class="guard-name">${f.source||'?'}</div>
      <div class="guard-sev ${sev_class(f.severity)}">${f.severity||'?'}</div>
      <div style="color:${f.block?'#ff6666':'#88cc88'};font-size:11px;min-width:40px">${f.block?'BLOCK':'pass'}</div>
      <div class="guard-reason">${(f.reason||'').slice(0,120)}</div>
    </div>`).join('');
}

function add_event(ev){
  const d = ev.decision||'allow';
  const cmd = (ev.command||ev.args&&JSON.stringify(ev.args)||'').slice(0,200);
  const findings = ev.det_findings||[];
  const watcher_used = ev.watcher_used||false;
  const latency = ev.latency_ms ? `${ev.latency_ms}ms` : '';
  const conf = ev.confidence!=null ? Math.round(ev.confidence*100) : null;

  // guard pipeline detail
  const guard_html = make_guard_rows(findings);

  // watcher box
  let watcher_html = '';
  if(watcher_used && ev.reason){
    const conf_pct = conf||0;
    watcher_html = `<div class="watcher-box">
      <div class="wlbl">⬡ Watcher LLM</div>
      <div class="watcher-reason">${ev.reason}</div>
      ${conf!=null?`<div class="conf-bar"><div class="conf-fill" style="width:${conf_pct}%"></div></div>
      <div style="font-size:10px;color:var(--gray);margin-top:2px">confidence ${conf_pct}%${ev.post_filter_overrode?' · <span style="color:#ff9944">post-filter overrode</span>':''}</div>`:''}
    </div>`;
  }

  const card = document.createElement('div');
  card.className = `ev ${d} new`;
  card.innerHTML = `
    <div class="ev-top">
      <div class="ev-tool">${ev.tool_name||'?'}</div>
      <div class="ev-cmd">${fmt_cmd(cmd)}</div>
      <div class="badge ${d}">${d.toUpperCase()}</div>
      ${watcher_used?'<div class="badge watcher">LLM</div>':'<div class="badge guard">⚡ guard</div>'}
    </div>
    <div class="ev-meta">
      <span>${ts_str(ev.ts)}</span>
      ${ev.session_id?`<span>session: ${ev.session_id.slice(0,10)}</span>`:''}
      ${latency?`<span>${latency}</span>`:''}
      ${ev.severity?`<span style="color:${ev.severity==='hardline'||ev.severity==='critical'?'#ff6666':ev.severity==='high'?'#ff9944':'#88cc88'}">${ev.severity}</span>`:''}
    </div>
    <div class="ev-detail">
      <div style="font-size:10px;color:var(--gray);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px">Guard Pipeline</div>
      ${guard_html}
      ${watcher_html}
    </div>`;
  card.addEventListener('click', ()=>card.classList.toggle('open'));
  feed.insertBefore(card, feed.firstChild);
  // keep max 200 cards
  while(feed.children.length > 200) feed.removeChild(feed.lastChild);
  setTimeout(()=>card.classList.remove('new'), 700);
}

function add_learned_event(ev){
  const card = document.createElement('div');
  card.className = 'ev learned new';
  card.innerHTML = `
    <div class="ev-top">
      <div class="ev-tool" style="color:var(--gold)">⟳ Pattern Learned</div>
      <div class="badge" style="background:#2a1a00;color:var(--gold)">${ev.guard_target||'?'}</div>
      <div class="badge" style="background:#1a1a00;color:#aaa">conf ${Math.round((ev.confidence||0)*100)}%</div>
    </div>
    <div class="ev-pattern">${ev.pattern||''}</div>
    <div class="ev-meta"><span>${ts_str(ev.ts)}</span></div>`;
  feed.insertBefore(card, feed.firstChild);
  setTimeout(()=>card.classList.remove('new'), 700);
}

function handle_event(ev){
  if(ev.type === 'eval'){
    stats.total++;
    const d = ev.decision||'allow';
    stats[d] = (stats[d]||0)+1;
    if(d==='deny'||d==='ask') stats.blocked++;
    // guard counts
    for(const f of (ev.det_findings||[])){
      const src = (f.source||'').split(':')[0];
      if(src) guardCounts[src] = (guardCounts[src]||0)+1;
    }
    // session
    const sid = ev.session_id||'default';
    if(!sessions[sid]) sessions[sid]={intent:'',calls:0};
    sessions[sid].calls++;
    // blocked ticker
    if(d==='deny') blocked_cmds.push({tool:ev.tool_name,cmd:ev.command||''});
    add_event(ev);
    update_stats(); update_guard_bars(); update_sessions(); update_ticker();
  } else if(ev.type === 'learned'){
    stats.learned = (stats.learned||0)+1;
    $('s-learned').textContent = stats.learned;
    add_learned_event(ev);
    fetch_patterns();
  } else if(ev.type === 'intent'){
    const sid = ev.session_id||'default';
    if(!sessions[sid]) sessions[sid]={intent:'',calls:0};
    sessions[sid].intent = ev.intent||'';
    update_sessions();
  }
}

// SSE connection
function connect(){
  const es = new EventSource('/watcher/stream');
  es.onopen = ()=>{ $('conn-dot').className='live'; $('conn-lbl').textContent='live'; };
  es.onmessage = e=>{ try{ handle_event(JSON.parse(e.data)); }catch(err){} };
  es.onerror = ()=>{ $('conn-dot').className=''; $('conn-lbl').textContent='reconnecting…'; setTimeout(connect,3000); es.close(); };
}

// Poll learned patterns
function fetch_patterns(){
  fetch('/watcher/learned').then(r=>r.json()).then(pats=>{
    const el = $('patterns-list');
    $('pat-count').textContent = pats.length ? `(${pats.length})` : '';
    if(!pats.length){ el.innerHTML='<div style="color:var(--gray);font-size:11px">None yet</div>'; return; }
    el.innerHTML = pats.map(p=>`
      <div class="pat-chip">
        <span class="pt">${p.guard_target}</span>
        <span>${(p.pattern||'').slice(0,40)}</span>
        <span class="pt">${Math.round((p.confidence||0)*100)}%</span>
      </div>`).join('');
  }).catch(()=>{});
}

// Poll sessions from API
function fetch_sessions(){
  fetch('/watcher/sessions').then(r=>r.json()).then(data=>{
    for(const s of (data.sessions||[])){
      if(!sessions[s.id]) sessions[s.id]={intent:'',calls:0};
      sessions[s.id].intent = s.intent||sessions[s.id].intent;
      sessions[s.id].calls = Math.max(sessions[s.id].calls, s.calls||0);
    }
    $('s-sessions').textContent = Object.keys(sessions).length;
    update_sessions();
  }).catch(()=>{});
}

connect();
fetch_patterns();
fetch_sessions();
setInterval(fetch_patterns, 10000);
setInterval(fetch_sessions, 5000);
draw_donut();
update_guard_bars();
</script>
</body>
</html>"""
