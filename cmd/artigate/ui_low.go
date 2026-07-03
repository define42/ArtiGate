package main

// Low-side dashboard UI. A single self-contained HTML page (no external assets,
// so it works in restricted environments) served at "/". It lets an operator
// re-export a bundle number/range that needs to be retransmitted through the
// diode, and shows the current export/bundle status. Re-export itself is done
// by POSTing to the existing /admin/reexport endpoint.

import "net/http"

func (s *LowServer) serveLowUI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/", "/ui", "/ui/":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		writeHTML(w, lowUIHTML)
	case "/ui/api/status":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		writeJSON(w, s.BundleStatus())
	default:
		return false
	}
	return true
}

const lowUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ArtiGate low-side</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
  header { padding: 1rem 1.5rem; background: #161a22; border-bottom: 1px solid #2a2f3a; display: flex; align-items: center; gap: 1rem; }
  header h1 { font-size: 1.25rem; margin: 0; }
  header button { margin-left: auto; background: #2a2f3a; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .4rem .8rem; cursor: pointer; }
  main { padding: 1.5rem; max-width: 960px; }
  .card { background: #161a22; border: 1px solid #2a2f3a; border-radius: 8px; padding: 1.1rem 1.25rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1rem; margin: 0 0 .75rem; }
  .hint { color: #8b93a5; font-size: .85rem; margin: .1rem 0 .8rem; }
  form { display: flex; gap: .6rem; flex-wrap: wrap; }
  input[type=text] { flex: 1; min-width: 240px; background: #0f1115; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .55rem .7rem; font-family: ui-monospace, monospace; }
  button.primary { background: #1f6f43; color: #eafff2; border: 1px solid #2b8f59; border-radius: 6px; padding: .55rem 1.1rem; cursor: pointer; font-weight: 600; }
  #result { margin-top: .9rem; padding: .7rem .9rem; border-radius: 6px; display: none; }
  #result.ok { display: block; background: #10281a; border: 1px solid #1f6f43; color: #7ee2a8; }
  #result.err { display: block; background: #2e1416; border: 1px solid #7f2a30; color: #ff9ea3; }
  .meta { display: flex; flex-wrap: wrap; gap: 1.25rem; font-size: .9rem; color: #a9b2c3; margin-bottom: 1rem; }
  .meta b { color: #e6e6e6; }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid #2a2f3a; }
  th { color: #8b93a5; font-weight: 600; }
  td.mono { font-family: ui-monospace, monospace; }
  .empty { color: #8b93a5; font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>ArtiGate <span style="color:#8b93a5;font-weight:400">low-side exporter</span></h1>
  <button onclick="loadStatus()">Refresh</button>
</header>
<main>
  <div class="card">
    <h2>Re-transmit bundles</h2>
    <p class="hint">Enter a bundle number or range that the high side is missing, e.g. <code>42</code>, <code>45-47</code>, or <code>42,45-47</code>. The bundle files are regenerated in the export directory to be sent through the diode again.</p>
    <form onsubmit="reexport(event)">
      <input id="seq" type="text" placeholder="42,45-47" autocomplete="off" autofocus>
      <button class="primary" type="submit">Re-export</button>
    </form>
    <div id="result"></div>
  </div>

  <div class="card">
    <h2>Export status</h2>
    <div id="meta" class="meta">Loading…</div>
    <div id="bundles"></div>
  </div>
</main>
<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

function showResult(cls, html){
  const el=document.getElementById('result');
  el.className=cls;
  el.innerHTML=html;
}

async function reexport(ev){
  ev.preventDefault();
  const v=document.getElementById('seq').value.trim();
  if(!v){ showResult('err','Enter a bundle number or range.'); return; }
  try{
    const r=await fetch('/admin/reexport',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sequences:v})});
    const text=await r.text();
    if(!r.ok){ showResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    const done=(d.reexported||[]).map(x=>'#'+x.sequence);
    const failed=d.failed||[];
    let msg='Re-exported '+(done.length?esc(done.join(', ')):'nothing');
    if(failed.length) msg+='<br>Failed: '+esc(failed.join('; '));
    showResult(failed.length?'err':'ok', msg);
    loadStatus();
  }catch(e){ showResult('err','Request failed: '+esc(e.message)); }
}

async function loadStatus(){
  try{
    const r=await fetch('/ui/api/status',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const s=await r.json();
    document.getElementById('meta').innerHTML=
      '<span>Next sequence: <b>#'+esc(s.next_sequence)+'</b></span>'+
      '<span>Pending modules: <b>'+esc(s.pending_modules)+'</b></span>';
    const rows=(s.exported_sequences||[]);
    const box=document.getElementById('bundles');
    if(!rows.length){ box.innerHTML='<p class="empty">No bundles exported yet.</p>'; return; }
    box.innerHTML='<table><thead><tr><th>Sequence</th><th>Bundle</th><th>Modules</th><th>Files present</th></tr></thead><tbody>'+
      rows.map(x=>'<tr><td class="mono">#'+esc(x.sequence)+'</td><td class="mono">'+esc(x.bundle_id)+
        '</td><td>'+esc(x.modules)+'</td><td>'+(x.files_present?'✓':'&#10007; missing')+'</td></tr>').join('')+
      '</tbody></table>';
  }catch(e){
    document.getElementById('meta').textContent='Failed to load status: '+e.message;
  }
}
loadStatus();
</script>
</body>
</html>
`
