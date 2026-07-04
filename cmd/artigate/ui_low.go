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
  header { padding: 1rem 1.5rem; background: #161a22; border-bottom: 1px solid #2a2f3a; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
  header h1 { font-size: 1.25rem; margin: 0; }
  nav { display: flex; gap: .4rem; flex-wrap: wrap; }
  nav button { background: #2a2f3a; color: #c7cedb; border: 1px solid #3a4150; border-radius: 6px; padding: .4rem .9rem; cursor: pointer; font: inherit; }
  nav button.active { background: #1f6f43; color: #eafff2; border-color: #2b8f59; }
  header .refresh { margin-left: auto; background: #2a2f3a; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .4rem .8rem; cursor: pointer; font: inherit; }
  main { padding: 1.5rem; max-width: 960px; }
  .card { background: #161a22; border: 1px solid #2a2f3a; border-radius: 8px; padding: 1.1rem 1.25rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1rem; margin: 0 0 .75rem; }
  .hint { color: #8b93a5; font-size: .85rem; margin: .1rem 0 .8rem; }
  form { display: flex; gap: .6rem; flex-wrap: wrap; }
  input[type=text] { flex: 1; min-width: 240px; background: #0f1115; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .55rem .7rem; font-family: ui-monospace, monospace; }
  select.restream { background: #0f1115; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .55rem .7rem; font: inherit; cursor: pointer; }
  button.primary { background: #1f6f43; color: #eafff2; border: 1px solid #2b8f59; border-radius: 6px; padding: .55rem 1.1rem; cursor: pointer; font-weight: 600; }
  .rbox { margin-top: .9rem; padding: .7rem .9rem; border-radius: 6px; display: none; }
  .rbox.busy { display: block; background: #12161f; border: 1px solid #3a4150; color: #a9b2c3; }
  .rbox.ok { display: block; background: #10281a; border: 1px solid #1f6f43; color: #7ee2a8; }
  .rbox.warn { display: block; background: #2a2410; border: 1px solid #6b5320; color: #d8b26a; }
  .rbox.err { display: block; background: #2e1416; border: 1px solid #7f2a30; color: #ff9ea3; }
  .rbox ul { margin: .4rem 0 0; padding-left: 1.1rem; }
  .rbox code { font-family: ui-monospace, monospace; }
  .gomod-form { flex-direction: column; align-items: stretch; }
  .filelabel { display: flex; flex-direction: column; gap: .3rem; font-size: .85rem; color: #c7cedb; }
  .filelabel .opt { color: #8b93a5; font-weight: 400; }
  .filelabel input[type=file] { font: inherit; color: #a9b2c3; background: #0f1115; border: 1px dashed #3a4150; border-radius: 6px; padding: .5rem .6rem; cursor: pointer; }
  .filelabel textarea { color: #e6e6e6; background: #0f1115; border: 1px solid #3a4150; border-radius: 6px; padding: .5rem .6rem; font-family: ui-monospace, monospace; font-size: .82rem; resize: vertical; }
  .gomod-form button.primary { align-self: flex-start; }
  button.primary:disabled { opacity: .6; cursor: progress; }
  .pytarget { border: 1px solid #2a2f3a; border-radius: 6px; padding: .2rem .7rem; }
  .pytarget summary { cursor: pointer; color: #c7cedb; font-size: .85rem; padding: .35rem 0; }
  .pytarget-check { display: flex; align-items: center; gap: .45rem; font-size: .82rem; color: #c7cedb; margin: .5rem 0 .2rem; }
  .pytarget-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .6rem; margin: .6rem 0 .2rem; }
  .pytarget-grid label { display: flex; flex-direction: column; gap: .25rem; font-size: .8rem; color: #a9b2c3; }
  .pytarget-grid input[type=text] { min-width: 0; font-size: .8rem; padding: .4rem .55rem; }
  @media (max-width: 620px) { .pytarget-grid { grid-template-columns: 1fr; } }
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
  <nav>
    <button type="button" data-view="go" class="active" onclick="setView('go')">Go</button>
    <button type="button" data-view="python" onclick="setView('python')">Python</button>
    <button type="button" data-view="java" onclick="setView('java')">Java</button>
    <button type="button" data-view="apt" onclick="setView('apt')">APT</button>
    <button type="button" data-view="rpm" onclick="setView('rpm')">RPM</button>
    <button type="button" data-view="status" onclick="setView('status')">Status</button>
  </nav>
  <button type="button" class="refresh" onclick="loadStatus()">Refresh</button>
</header>
<main>
  <section class="view" id="view-go">
  <div class="card">
    <h2>Mirror a Go project (go.mod)</h2>
    <p class="hint">Upload a project's <code>go.mod</code> (optionally its <code>go.sum</code>). ArtiGate resolves and fetches exactly the module graph that project builds and writes it to a signed bundle &mdash; the same as POSTing the file to <code>/admin/go/collect</code>. This is the closest to &ldquo;download everything needed to build this project offline&rdquo;.</p>
    <form class="gomod-form" onsubmit="collectGoMod(event)">
      <label class="filelabel">go.mod
        <input id="gomod" type="file" accept=".mod,text/plain" required>
      </label>
      <label class="filelabel">go.sum <span class="opt">&mdash; optional, pins the exact versions</span>
        <input id="gosum" type="file" accept=".sum,text/plain">
      </label>
      <button class="primary" type="submit" id="goBtn">Collect &amp; export</button>
    </form>
    <div id="goResult" class="rbox"></div>
  </div>
  </section>

  <section class="view" id="view-python" hidden>
  <div class="card">
    <h2>Mirror Python packages (requirements)</h2>
    <p class="hint">List packages to mirror &mdash; one requirement per line, requirements.txt format (e.g. <code>requests==2.32.4</code>). ArtiGate runs <code>pip download</code> and writes the wheels into a signed bundle, the same as POSTing to <code>/admin/python/collect</code>. Lines starting with <code>#</code> are ignored; pip option lines (<code>-r</code>, <code>--hash</code>, &hellip;) are skipped.</p>
    <form class="gomod-form" onsubmit="collectPython(event)">
      <label class="filelabel">Requirements <span class="opt">&mdash; one per line</span>
        <textarea id="pyreqs" rows="5" placeholder="requests==2.32.4" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or load a requirements.txt
        <input id="pyfile" type="file" accept=".txt,text/plain" onchange="loadPyFile()">
      </label>
      <details class="pytarget">
        <summary>Cross-target for a different interpreter (optional)</summary>
        <label class="pytarget-check"><input id="pyonly" type="checkbox"> Wheels only (recommended for air-gapped builds)</label>
        <div class="pytarget-grid">
          <label>Python version<input id="pyver" type="text" placeholder="3.12" autocomplete="off"></label>
          <label>Implementation<input id="pyimpl" type="text" placeholder="cp" autocomplete="off"></label>
          <label>ABI<input id="pyabi" type="text" placeholder="cp312" autocomplete="off"></label>
          <label>Platforms (comma-separated)<input id="pyplat" type="text" placeholder="manylinux_2_28_x86_64, manylinux_2_34_x86_64" autocomplete="off"></label>
        </div>
        <p class="hint">Set these to download wheels for the high-side interpreter rather than this host; any of them forces <code>--only-binary=:all:</code>.</p>
      </details>
      <button class="primary" type="submit" id="pyBtn">Collect &amp; export</button>
    </form>
    <div id="pyResult" class="rbox"></div>
  </div>
  </section>

  <section class="view" id="view-java" hidden>
  <div class="card">
    <h2>Mirror Java/Maven artifacts</h2>
    <p class="hint">List Maven coordinates (one <code>groupId:artifactId:version</code> per line) or upload a <code>pom.xml</code>. ArtiGate runs <code>mvn dependency:go-offline</code> to resolve the full closure (including plugins) and writes it to a signed bundle, the same as POSTing to <code>/admin/maven/collect</code>. Release versions only &mdash; SNAPSHOTs and version ranges are rejected.</p>
    <form class="gomod-form" onsubmit="collectMaven(event)">
      <label class="filelabel">Coordinates <span class="opt">&mdash; groupId:artifactId:version, one per line</span>
        <textarea id="mvncoords" rows="4" placeholder="org.slf4j:slf4j-api:2.0.16" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or upload a pom.xml <span class="opt">&mdash; takes precedence over the list</span>
        <input id="mvnpom" type="file" accept=".xml,text/xml">
      </label>
      <button class="primary" type="submit" id="mvnBtn">Collect &amp; export</button>
    </form>
    <div id="mvnResult" class="rbox"></div>
  </div>
  </section>

  <section class="view" id="view-apt" hidden>
  <div class="card">
    <h2>Mirror an APT (deb) repository</h2>
    <p class="hint">Paste a deb822 source stanza (the <code>.sources</code> format). ArtiGate downloads and verifies the upstream <code>Release</code> and <code>Packages</code> index, mirrors every referenced <code>.deb</code> for the suite/components/architectures, and writes them to a signed bundle. The high side regenerates and (optionally) re-signs the repository. This is <code>/admin/apt/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectApt(event)">
      <label class="filelabel">Source (deb822)
        <textarea id="aptsrc" rows="6" placeholder="Types: deb&#10;URIs: https://packages.microsoft.com/repos/code&#10;Suites: stable&#10;Components: main&#10;Architectures: amd64&#10;Signed-By: /usr/share/keyrings/microsoft.gpg" autocomplete="off"></textarea>
      </label>
      <button class="primary" type="submit" id="aptBtn">Collect &amp; export</button>
    </form>
    <div id="aptResult" class="rbox"></div>
  </div>
  </section>

  <section class="view" id="view-rpm" hidden>
  <div class="card">
    <h2>Mirror an RPM (yum/dnf) repository</h2>
    <p class="hint">Paste a yum/dnf <code>.repo</code> stanza. ArtiGate downloads and verifies <code>repomd.xml</code> and the <code>primary</code> index, mirrors every referenced <code>.rpm</code>, and writes a signed bundle. The high side regenerates <code>repodata</code> and (optionally) re-signs it. This is <code>/admin/rpm/collect</code>. <code>baseurl</code> must be concrete (no <code>$releasever</code>/<code>$basearch</code>).</p>
    <form class="gomod-form" onsubmit="collectRpm(event)">
      <label class="filelabel">Repo file (.repo)
        <textarea id="rpmrepo" rows="6" placeholder="[code]&#10;name=Visual Studio Code&#10;baseurl=https://packages.microsoft.com/yumrepos/vscode&#10;enabled=1&#10;gpgcheck=1&#10;gpgkey=https://packages.microsoft.com/keys/microsoft.asc" autocomplete="off"></textarea>
      </label>
      <button class="primary" type="submit" id="rpmBtn">Collect &amp; export</button>
    </form>
    <div id="rpmResult" class="rbox"></div>
  </div>
  </section>

  <section class="view" id="view-status" hidden>
  <div class="card">
    <h2>Re-transmit bundles</h2>
    <p class="hint">Pick the stream, then enter a bundle number or range the high side is missing, e.g. <code>42</code>, <code>45-47</code>, or <code>42,45-47</code>. Each ecosystem has its own independent bundle numbering, so choose the matching stream. The bundle files are regenerated in the export directory to be sent through the diode again.</p>
    <form onsubmit="reexport(event)">
      <select id="restream" class="restream" aria-label="Stream">
        <option value="go">Go</option>
        <option value="python">Python</option>
        <option value="maven">Maven</option>
        <option value="apt">APT</option>
        <option value="rpm">RPM</option>
      </select>
      <input id="seq" type="text" placeholder="42,45-47" autocomplete="off" autofocus>
      <button class="primary" type="submit">Re-export</button>
    </form>
    <div id="result" class="rbox"></div>
  </div>

  <div class="card">
    <h2>Export status</h2>
    <div id="meta" class="meta">Loading…</div>
    <div id="bundles"></div>
  </div>
  </section>
</main>
<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function streamLabel(name){return ({go:'Go',python:'Python',maven:'Maven',apt:'APT',rpm:'RPM'})[name]||name;}

// setView shows one ecosystem (or the status) page and hides the rest, matching
// the active nav button. The status page is refreshed each time it is opened.
function setView(view){
  for(const v of ['go','python','java','apt','rpm','status']){
    document.getElementById('view-'+v).hidden = (v!==view);
  }
  document.querySelectorAll('nav button[data-view]').forEach(b=>{
    b.classList.toggle('active', b.dataset.view===view);
  });
  if(view==='status') loadStatus();
}

function showResult(cls, html){
  const el=document.getElementById('result');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function reexport(ev){
  ev.preventDefault();
  const stream=document.getElementById('restream').value;
  const v=document.getElementById('seq').value.trim();
  if(!v){ showResult('err','Enter a bundle number or range.'); return; }
  try{
    const r=await fetch('/admin/reexport',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stream:stream, sequences:v})});
    const text=await r.text();
    if(!r.ok){ showResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    const done=(d.reexported||[]).map(x=>'#'+x.sequence);
    const failed=d.failed||[];
    let msg='Re-exported '+esc(streamLabel(stream))+' '+(done.length?esc(done.join(', ')):'nothing');
    if(failed.length) msg+='<br>Failed: '+esc(failed.join('; '));
    showResult(failed.length?'err':'ok', msg);
    loadStatus();
  }catch(e){ showResult('err','Request failed: '+esc(e.message)); }
}

function showGoResult(cls, html){
  const el=document.getElementById('goResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectGoMod(ev){
  ev.preventDefault();
  const modInput=document.getElementById('gomod');
  const sumInput=document.getElementById('gosum');
  const modFile=modInput.files && modInput.files[0];
  if(!modFile){ showGoResult('err','Choose a go.mod file to upload.'); return; }
  const btn=document.getElementById('goBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showGoResult('busy','Resolving and fetching the module graph… this can take a while for a large project.');
  try{
    const go_mod=await modFile.text();
    const sumFile=sumInput.files && sumInput.files[0];
    const go_sum=sumFile ? await sumFile.text() : '';
    const r=await fetch('/admin/go/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({go_mod:go_mod, go_sum:go_sum})});
    const text=await r.text();
    if(!r.ok){ showGoResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    let msg='&#10003; Collected '+esc(d.exported_modules)+' module(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
    const skipped=d.skipped_modules||[];
    if(skipped.length){
      msg+='<br>&#9888; Skipped '+esc(skipped.length)+' unfetchable module(s); they stay pending for retry:<ul>'+
        skipped.map(m=>'<li><code>'+esc(m.module)+'@'+esc(m.version)+'</code></li>').join('')+'</ul>';
      showGoResult('warn', msg);
    } else {
      showGoResult('ok', msg);
    }
    loadStatus();
  }catch(e){ showGoResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showPyResult(cls, html){
  const el=document.getElementById('pyResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function loadPyFile(){
  const f=document.getElementById('pyfile');
  const file=f.files && f.files[0];
  if(!file) return;
  file.text().then(t=>{ document.getElementById('pyreqs').value=t; });
}

// parseRequirements turns requirements.txt text into a list of specifiers,
// dropping blank lines and comments and setting aside pip option lines (which
// the collector does not accept as requirements).
function parseRequirements(text){
  const reqs=[], skipped=[];
  for(const raw of text.split(/\r?\n/)){
    let line=raw.replace(/\s+#.*$/,'');
    line=line.replace(/\\\s*$/,'').trim();
    if(!line || line.charAt(0)==='#') continue;
    if(line.charAt(0)==='-'){ skipped.push(line); continue; }
    reqs.push(line);
  }
  return {reqs:reqs, skipped:skipped};
}

function pyTarget(){
  const g=id=>document.getElementById(id).value.trim();
  const ver=g('pyver'), impl=g('pyimpl'), abi=g('pyabi'), platRaw=g('pyplat');
  const onlyBin=document.getElementById('pyonly').checked;
  const plats=platRaw?platRaw.split(',').map(s=>s.trim()).filter(Boolean):[];
  if(!ver && !impl && !abi && !plats.length && !onlyBin) return null;
  const t={};
  if(onlyBin) t.only_binary=true;
  if(ver) t.python_version=ver;
  if(impl) t.implementation=impl;
  if(abi) t.abi=abi;
  if(plats.length) t.platforms=plats;
  return t;
}

async function collectPython(ev){
  ev.preventDefault();
  const parsed=parseRequirements(document.getElementById('pyreqs').value);
  if(!parsed.reqs.length){ showPyResult('err','Enter at least one requirement (one per line).'); return; }
  const btn=document.getElementById('pyBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showPyResult('busy','Running pip download for '+esc(parsed.reqs.length)+' requirement(s)… this can take a while.');
  try{
    const body={requirements:parsed.reqs};
    const target=pyTarget();
    if(target) body.target=target;
    const r=await fetch('/admin/python/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const text=await r.text();
    if(!r.ok){ showPyResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    let msg='&#10003; Collected '+esc(d.exported_modules)+' package(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
    if(parsed.skipped.length){
      msg+='<br>&#9888; Skipped '+esc(parsed.skipped.length)+' pip option line(s) not supported here (e.g. <code>'+esc(parsed.skipped[0])+'</code>).';
      showPyResult('warn', msg);
    } else {
      showPyResult('ok', msg);
    }
    loadStatus();
  }catch(e){ showPyResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showMvnResult(cls, html){
  const el=document.getElementById('mvnResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectMaven(ev){
  ev.preventDefault();
  const pomInput=document.getElementById('mvnpom');
  const pomFile=pomInput.files && pomInput.files[0];
  const coords=document.getElementById('mvncoords').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim())
    .filter(l=>l && l.charAt(0)!=='#');
  if(!pomFile && !coords.length){ showMvnResult('err','Enter Maven coordinates or upload a pom.xml.'); return; }
  const btn=document.getElementById('mvnBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showMvnResult('busy','Running mvn dependency:go-offline to resolve the closure… this can take a while.');
  try{
    const body = pomFile ? {pom_xml: await pomFile.text()} : {coordinates: coords};
    const r=await fetch('/admin/maven/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const text=await r.text();
    if(!r.ok){ showMvnResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    showMvnResult('ok','&#10003; Collected '+esc(d.exported_modules)+' artifact(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').');
    loadStatus();
  }catch(e){ showMvnResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showAptResult(cls, html){
  const el=document.getElementById('aptResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectApt(ev){
  ev.preventDefault();
  const src=document.getElementById('aptsrc').value.trim();
  if(!src){ showAptResult('err','Paste a deb822 source stanza.'); return; }
  const btn=document.getElementById('aptBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Mirroring…';
  showAptResult('busy','Downloading and verifying the upstream Release, Packages index, and every .deb… this can take a while.');
  try{
    const r=await fetch('/admin/apt/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_list:src})});
    const text=await r.text();
    if(!r.ok){ showAptResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    showAptResult('ok','&#10003; Mirrored '+esc(d.exported_modules)+' package(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').');
    loadStatus();
  }catch(e){ showAptResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showRpmResult(cls, html){
  const el=document.getElementById('rpmResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectRpm(ev){
  ev.preventDefault();
  const repo=document.getElementById('rpmrepo').value.trim();
  if(!repo){ showRpmResult('err','Paste a yum/dnf .repo stanza.'); return; }
  const btn=document.getElementById('rpmBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Mirroring…';
  showRpmResult('busy','Downloading and verifying repomd.xml, the primary index, and every .rpm… this can take a while.');
  try{
    const r=await fetch('/admin/rpm/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repo_file:repo})});
    const text=await r.text();
    if(!r.ok){ showRpmResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    showRpmResult('ok','&#10003; Mirrored '+esc(d.exported_modules)+' package(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').');
    loadStatus();
  }catch(e){ showRpmResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

async function loadStatus(){
  try{
    const r=await fetch('/ui/api/status',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const s=await r.json();
    const streams=s.streams||[];
    const nextSummary=streams.map(st=>esc(streamLabel(st.stream))+' <b>#'+esc(st.next_sequence)+'</b>').join(' &middot; ');
    document.getElementById('meta').innerHTML=
      '<span>Pending Go modules: <b>'+esc(s.pending_modules)+'</b></span>'+
      (nextSummary?'<span>Next bundle &mdash; '+nextSummary+'</span>':'');
    // One combined table across every stream; each ecosystem numbers its own
    // bundles independently, so the stream is shown alongside the sequence.
    const rows=[];
    for(const st of streams){
      for(const x of (st.exported_sequences||[])){
        rows.push('<tr><td>'+esc(streamLabel(st.stream))+'</td><td class="mono">#'+esc(x.sequence)+
          '</td><td class="mono">'+esc(x.bundle_id)+'</td><td>'+(x.files_present?'✓':'&#10007; missing')+'</td></tr>');
      }
    }
    const box=document.getElementById('bundles');
    if(!rows.length){ box.innerHTML='<p class="empty">No bundles exported yet.</p>'; return; }
    box.innerHTML='<table><thead><tr><th>Stream</th><th>Sequence</th><th>Bundle</th><th>Files present</th></tr></thead><tbody>'+
      rows.join('')+'</tbody></table>';
  }catch(e){
    document.getElementById('meta').textContent='Failed to load status: '+e.message;
  }
}
loadStatus();
</script>
</body>
</html>
`
