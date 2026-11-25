PAGE = """<!doctype html><meta charset="utf-8"><title>Bank SOC console</title>
<style>
body{font:14px system-ui;margin:0;background:#0f1720;color:#e6edf3}header{padding:12px 20px;background:#16212c;display:flex;gap:24px;align-items:center}
h1{font-size:16px;margin:0}.kpi b{font-size:18px}main{display:flex;height:calc(100vh - 50px)}
#list{width:46%;overflow:auto;border-right:1px solid #243242}#detail{flex:1;overflow:auto;padding:16px}
.row{padding:10px 16px;border-bottom:1px solid #1d2a38;cursor:pointer}.row:hover{background:#16212c}
.sev{display:inline-block;padding:1px 8px;border-radius:9px;font-size:12px;color:#000}
.critical{background:#ff6b6b}.high{background:#ffa94d}.medium{background:#ffe066}.low{background:#8ce99a}
button{background:#238636;color:#fff;border:0;padding:5px 10px;border-radius:4px;margin:2px;cursor:pointer}
textarea{width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d}.alert{margin:6px 0;padding:8px;background:#16212c;border-radius:4px}
</style>
<header><h1>Bank SOC console</h1><span class="kpi" id="kpi"></span></header>
<main><div id="list"></div><div id="detail">Select an incident.</div></main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(p,o){const r=await fetch(p,o);return r.json()}
async function load(){
  const m=await api('/api/metrics');
  $('#kpi').innerHTML='incidents <b>'+m.incidents+'</b> &nbsp; open critical <b>'+m.open_critical+'</b> &nbsp; mean ack (min) <b>'+(m.mean_minutes_to_ack??'-')+'</b>';
  const l=await api('/api/incidents');
  $('#list').innerHTML=l.map(i=>'<div class="row" data-id="'+i.id+'"><span class="sev '+esc(i.severity)+'">'+esc(i.severity)+'</span> #'+i.id+' score '+i.score+' <i>'+esc(i.status)+'</i><br>'+esc(i.title)+'</div>').join('');
  document.querySelectorAll('.row').forEach(r=>r.onclick=()=>show(r.dataset.id));
}
async function show(id){
  const i=await api('/api/incidents/'+id);
  $('#detail').innerHTML='<h2>#'+i.id+' '+esc(i.title)+'</h2><p><span class="sev '+esc(i.severity)+'">'+esc(i.severity)+'</span> score '+i.score+' | status <b>'+esc(i.status)+'</b> | '+esc(i.tactics.join(', '))+'</p>'
   +['triaging','true_positive','false_positive','closed'].map(s=>'<button data-s="'+s+'">'+s+'</button>').join('')
   +'<h3>Alerts</h3>'+i.alerts.map(a=>'<div class="alert"><b>'+esc(a.detector)+'</b> ['+esc(a.severity)+'] '+esc(a.time)+'<br>'+esc(a.summary)+'<br><small>'+esc(a.technique)+' | '+esc(a.entities.join(', '))+'</small></div>').join('')
   +'<h3>Notes</h3>'+i.notes.map(n=>'<div class="alert">'+esc(n.ts)+' '+esc(n.author)+': '+esc(n.text)+'</div>').join('')
   +'<textarea id="note" rows="3" placeholder="Add a note"></textarea><button id="add">Add note</button>';
  document.querySelectorAll('button[data-s]').forEach(b=>b.onclick=async()=>{await api('/api/incidents/'+id+'/status',{method:'POST',body:JSON.stringify({status:b.dataset.s})});load();show(id)});
  $('#add').onclick=async()=>{const t=$('#note').value;if(!t)return;await api('/api/incidents/'+id+'/notes',{method:'POST',body:JSON.stringify({text:t})});show(id)};
}
load();
</script>"""
