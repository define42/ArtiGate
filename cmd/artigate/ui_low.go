package main

// Low-side dashboard UI. A single self-contained HTML page (no external assets,
// so it works in restricted environments) served at "/". It lets an operator
// re-export a bundle number/range that needs to be retransmitted through the
// diode, and shows the current export/bundle status. Re-export itself is done
// by POSTing to the existing /admin/reexport endpoint.

import (
	"net/http"
	"strings"
)

func (s *LowServer) serveLowUI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/", "/ui", "/ui/":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		writeHTML(w, s.renderLowUI())
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

// renderLowUI fills in the dashboard's optional bits: the "Log out" button is
// only shown when authentication is enabled.
func (s *LowServer) renderLowUI() string {
	logout := ""
	if s.authEnabled {
		logout = `<form method="post" action="/logout" style="margin:0"><button type="submit" class="refresh">Log out</button></form>`
	}
	return strings.Replace(lowUIHTML, "{{LOGOUT}}", logout, 1)
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
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .empty { color: #8b93a5; font-style: italic; }
  .sched { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; margin-top: 1rem; padding-top: .9rem; border-top: 1px solid #2a2f3a; }
  .sched-label { color: #8b93a5; font-size: .85rem; }
  button.secondary { background: #2a2f3a; color: #c7cedb; border: 1px solid #3a4150; border-radius: 6px; padding: .5rem 1rem; cursor: pointer; font: inherit; }
  .watchlist { margin-top: .8rem; }
  .every { display: flex; gap: .4rem; align-items: center; }
  .every input[type=number] { width: 5rem; background: #0f1115; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .55rem .6rem; font: inherit; }
  .pill { display: inline-block; border-radius: 999px; padding: .05rem .5rem; font-size: .72rem; font-weight: 600; }
  .pill.ok { background: #10281a; border: 1px solid #1f6f43; color: #7ee2a8; }
  .pill.warn { background: #2e1416; border: 1px solid #7f2a30; color: #ff9ea3; }
  .wmsg { color: #8b93a5; font-size: .75rem; }
  .wactions { white-space: nowrap; }
  .wactions button { background: #2a2f3a; color: #c7cedb; border: 1px solid #3a4150; border-radius: 5px; padding: .25rem .55rem; margin-left: .3rem; cursor: pointer; font: inherit; font-size: .78rem; }
  .wactions button:first-child { margin-left: 0; }
</style>
</head>
<body>
<header>
  <h1>ArtiGate <span style="color:#8b93a5;font-weight:400">low-side exporter</span></h1>
  <nav>
    <button type="button" data-view="overview" class="active" onclick="setView('overview')">Overview</button>
    <button type="button" data-view="go" onclick="setView('go')">Go</button>
    <button type="button" data-view="python" onclick="setView('python')">Python</button>
    <button type="button" data-view="maven" onclick="setView('maven')">Maven</button>
    <button type="button" data-view="npm" onclick="setView('npm')">NPM</button>
    <button type="button" data-view="apt" onclick="setView('apt')">APT</button>
    <button type="button" data-view="rpm" onclick="setView('rpm')">RPM</button>
    <button type="button" data-view="containers" onclick="setView('containers')">Containers</button>
    <button type="button" data-view="status" onclick="setView('status')">Status</button>
  </nav>
  <button type="button" class="refresh" onclick="loadStatus();loadAllWatches()">Refresh</button>
  {{LOGOUT}}
</header>
<main>
  <section class="view" id="view-overview">
  <div class="card">
    <h2>Scheduled pulls</h2>
    <p class="hint">Every schedule across all ecosystems, with its last run, status, and next run &mdash; so you can see at a glance whether they are working. Add or edit schedules on each ecosystem's page.</p>
    <div id="allWatches"><p class="empty">Loading&hellip;</p></div>
  </div>
  </section>

  <section class="view" id="view-go" hidden>
  <div class="card">
    <h2>Mirror Go modules</h2>
    <p class="hint">List modules to fetch &mdash; one per line: <code>module@v1.2.3</code> to pin, or just <code>module</code> (or <code>module@latest</code>) for the newest version, e.g. <code>github.com/caddyserver/certmagic</code>. Each listed module is fetched together with its full dependency graph. <em>Or</em> upload a project's <code>go.mod</code> to mirror exactly that project's module graph. Same as POSTing to <code>/admin/go/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectGoMod(event)">
      <label class="filelabel">Modules <span class="opt">&mdash; one per line; a bare path fetches the newest version, with dependencies</span>
        <textarea id="gomods" rows="3" placeholder="github.com/caddyserver/certmagic&#10;golang.org/x/text@v0.14.0" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or upload a go.mod <span class="opt">&mdash; mirrors exactly that project's graph</span>
        <input id="gomod" type="file" accept=".mod,text/plain">
      </label>
      <label class="filelabel">go.sum <span class="opt">&mdash; optional, with go.mod; pins the exact versions</span>
        <input id="gosum" type="file" accept=".sum,text/plain">
      </label>
      <button class="primary" type="submit" id="goBtn">Collect &amp; export</button>
    </form>
    <div id="goResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="goEvery" type="number" min="1" value="1" autocomplete="off"> <select id="goUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleGo()">Add schedule</button>
    </div>
    <div id="goWatches" class="watchlist"></div>
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
    <div class="sched">
      <span class="sched-label">Schedule these requirements:</span>
      <span class="every"><input id="pyEvery" type="number" min="1" value="1" autocomplete="off"> <select id="pyUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="schedulePython()">Add schedule</button>
    </div>
    <div id="pyWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-maven" hidden>
  <div class="card">
    <h2>Mirror Maven artifacts</h2>
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
    <div class="sched">
      <span class="sched-label">Schedule these coordinates/pom:</span>
      <span class="every"><input id="mvnEvery" type="number" min="1" value="1" autocomplete="off"> <select id="mvnUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleMaven()">Add schedule</button>
    </div>
    <div id="mvnWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-npm" hidden>
  <div class="card">
    <h2>Mirror NPM packages</h2>
    <p class="hint">List packages to mirror &mdash; one per line: <code>lodash@4.17.21</code> to pin, a bare <code>lodash</code> (or <code>lodash@latest</code>) for the newest version, or a semver range like <code>react@^18.2</code>; scoped names (<code>@types/node</code>) work too. The full dependency graph is resolved with <code>npm</code> (scripts never run) and every registry tarball is bundled. <em>Or</em> upload a project's <code>package.json</code> to mirror exactly what that project resolves. Same as POSTing to <code>/admin/npm/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectNpm(event)">
      <label class="filelabel">Packages <span class="opt">&mdash; one per line; name, name@version, or name@range</span>
        <textarea id="npmpkgs" rows="4" placeholder="lodash@4.17.21&#10;@types/node&#10;react@^18.2" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or upload a package.json <span class="opt">&mdash; mirrors exactly that project's graph</span>
        <input id="npmjson" type="file" accept=".json,application/json">
      </label>
      <label class="filelabel">package-lock.json <span class="opt">&mdash; optional, with package.json; pins the exact resolved versions</span>
        <input id="npmlock" type="file" accept=".json,application/json">
      </label>
      <button class="primary" type="submit" id="npmBtn">Collect &amp; export</button>
    </form>
    <div id="npmResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="npmEvery" type="number" min="1" value="1" autocomplete="off"> <select id="npmUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleNpm()">Add schedule</button>
    </div>
    <div id="npmWatches" class="watchlist"></div>
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
      <label class="filelabel">&hellip;or load a .sources file
        <input id="aptfile" type="file" accept=".sources,.list,text/plain" onchange="loadAptFile()">
      </label>
      <label class="pytarget-check"><input id="aptnewest" type="checkbox" checked> Newest version of each package only (uncheck to mirror every version)</label>
      <button class="primary" type="submit" id="aptBtn">Collect &amp; export</button>
    </form>
    <div id="aptResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule this source:</span>
      <span class="every"><input id="aptEvery" type="number" min="1" value="1" autocomplete="off"> <select id="aptUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleApt()">Add schedule</button>
    </div>
    <div id="aptWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-rpm" hidden>
  <div class="card">
    <h2>Mirror an RPM (yum/dnf) repository</h2>
    <p class="hint">Paste a yum/dnf <code>.repo</code> stanza. ArtiGate downloads and verifies <code>repomd.xml</code> and the <code>primary</code> index, mirrors every referenced <code>.rpm</code>, and writes a signed bundle. The high side regenerates <code>repodata</code> and (optionally) re-signs it. This is <code>/admin/rpm/collect</code>. <code>baseurl</code> must be concrete (no <code>$releasever</code>/<code>$basearch</code>).</p>
    <form class="gomod-form" onsubmit="collectRpm(event)">
      <label class="filelabel">Repo definition (.repo)
        <textarea id="rpmrepo" rows="6" placeholder="[code]&#10;name=Visual Studio Code&#10;baseurl=https://packages.microsoft.com/yumrepos/vscode&#10;enabled=1&#10;gpgcheck=1&#10;gpgkey=https://packages.microsoft.com/keys/microsoft.asc" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or load a .repo file
        <input id="rpmfile" type="file" accept=".repo,text/plain" onchange="loadRpmFile()">
      </label>
      <label class="pytarget-check"><input id="rpmnewest" type="checkbox" checked> Newest version of each package only (uncheck to mirror every version)</label>
      <button class="primary" type="submit" id="rpmBtn">Collect &amp; export</button>
    </form>
    <div id="rpmResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule this repo:</span>
      <span class="every"><input id="rpmEvery" type="number" min="1" value="1" autocomplete="off"> <select id="rpmUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleRpm()">Add schedule</button>
    </div>
    <div id="rpmWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-containers" hidden>
  <div class="card">
    <h2>Mirror container images</h2>
    <p class="hint">List images to mirror &mdash; one reference per line, e.g. <code>alpine:3.20</code>, <code>ghcr.io/org/app:v1</code>, or <code>registry.access.redhat.com/ubi9/ubi@sha256:&hellip;</code>. The tag position also takes a <b>version constraint</b>, resolved to the newest matching numeric tag at collect time: <code>golang:1.26.x</code>, <code>golang:&lt;2.0.0</code>, or <code>golang:&gt;=1.24, &lt;2.0</code> (variant tags like <code>1.26.3-alpine</code> are never picked &mdash; pin those explicitly). Only <b>linux/amd64</b> is fetched. Each upstream registry keeps its own namespace on the high side (<code>docker.io/&hellip;</code>, <code>ghcr.io/&hellip;</code>), so sources never mix. Same as POSTing to <code>/admin/containers/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectContainers(event)">
      <label class="filelabel">Images <span class="opt">&mdash; one per line; a missing tag means <code>latest</code>; scheduled pulls re-resolve constraints each run</span>
        <textarea id="ctrimages" rows="5" placeholder="alpine:3.20&#10;golang:1.26.x&#10;ghcr.io/org/app:v1" autocomplete="off"></textarea>
      </label>
      <button class="primary" type="submit" id="ctrBtn">Collect &amp; export</button>
    </form>
    <div id="ctrResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule these images:</span>
      <span class="every"><input id="ctrEvery" type="number" min="1" value="1" autocomplete="off"> <select id="ctrUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleContainers()">Add schedule</button>
    </div>
    <div id="ctrWatches" class="watchlist"></div>
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
        <option value="npm">NPM</option>
        <option value="apt">APT</option>
        <option value="rpm">RPM</option>
        <option value="containers">Containers</option>
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
// If the session has expired, any API call returns 401; bounce to the login page.
(function(){const _f=window.fetch;window.fetch=async(...a)=>{const r=await _f(...a);if(r.status===401){location.href='/login';}return r;};})();
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function streamLabel(name){return ({go:'Go',python:'Python',maven:'Maven',npm:'NPM',apt:'APT',rpm:'RPM',containers:'Containers'})[name]||name;}
// handleSkip renders the Tier-1 dedup no-op result: when a collect resolves only
// content already forwarded, no bundle is produced. Returns true when it handled
// the result so the caller can stop.
function handleSkip(d, showFn){
  if(!d || !d.skipped) return false;
  showFn('ok','&#10003; No new content since the last export &mdash; nothing to send across the diode.');
  loadStatus();
  return true;
}
function formatBytes(n){
  n=Number(n)||0;
  const u=['B','KiB','MiB','GiB','TiB'];
  let i=0;
  while(n>=1024 && i<u.length-1){ n/=1024; i++; }
  return (i===0 ? n : n.toFixed(n<10?1:0))+' '+u[i];
}

// archiveCell shows whether a retained copy is kept in the low-side archive, so
// the bundle can be re-transmitted. A missing archive copy (only expected once
// retention pruning exists) is flagged because it can no longer be re-exported.
function archiveCell(inArchive){
  return inArchive ? '✓ kept' : '<span style="color:#ff9ea3">&#10007; not kept</span>';
}

// outboundCell shows whether the bundle is still staged in the export directory
// (waiting to be carried across the diode) or has already been forwarded. Both
// are normal states, so neither is styled as an error — "sent" just means the
// transfer has moved the files out of the export dir.
function outboundCell(inOutbound){
  return inOutbound
    ? '<span style="color:#7ee2a8">staged</span>'
    : '<span style="color:#8b93a5">sent</span>';
}

// setView shows one ecosystem (or the status) page and hides the rest, matching
// the active nav button. The status page is refreshed each time it is opened.
// VIEW_STREAM maps each ecosystem view to its backend stream (now identical
// names); views without a stream (overview, status) are absent, so it doubles as
// the "is this an ecosystem page" test.
const VIEW_STREAM={go:'go',python:'python',maven:'maven',npm:'npm',apt:'apt',rpm:'rpm',containers:'containers'};
function setView(view){
  for(const v of ['overview','go','python','maven','npm','apt','rpm','containers','status']){
    document.getElementById('view-'+v).hidden = (v!==view);
  }
  document.querySelectorAll('nav button[data-view]').forEach(b=>{
    b.classList.toggle('active', b.dataset.view===view);
  });
  if(view==='overview') loadAllWatches();
  if(view==='status') loadStatus();
  if(VIEW_STREAM[view]) loadWatchesInto(VIEW_STREAM[view]);
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

// goSpec builds the /admin/go/collect payload from the Go page inputs: a module
// list (a bare path fetches the newest version) or an uploaded go.mod (with an
// optional go.sum). Returns {spec, label}, or null when nothing is entered.
async function goSpec(){
  const modFile=document.getElementById('gomod').files[0];
  if(modFile){
    const go_mod=await modFile.text();
    const sumFile=document.getElementById('gosum').files[0];
    const go_sum=sumFile ? await sumFile.text() : '';
    return {spec:{go_mod:go_mod, go_sum:go_sum}, label:'Go: '+modFile.name};
  }
  const mods=document.getElementById('gomods').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
  if(mods.length){
    // Always fetch the full dependency graph of the listed modules.
    return {spec:{modules:mods, resolve_deps:true}, label:'Go: '+mods.slice(0,3).join(', ')};
  }
  return null;
}

async function collectGoMod(ev){
  ev.preventDefault();
  const built=await goSpec();
  if(!built){ showGoResult('err','List at least one module, or upload a go.mod.'); return; }
  const btn=document.getElementById('goBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showGoResult('busy','Resolving and fetching the module graph… this can take a while for a large project.');
  try{
    const r=await fetch('/admin/go/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(built.spec)});
    const text=await r.text();
    if(!r.ok){ showGoResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    if(handleSkip(d, showGoResult)) return;
    let msg='&#10003; Collected '+esc(d.exported_modules)+' module(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
    const skipped=d.skipped_modules||[];
    if(skipped.length){
      msg+='<br>&#9888; Skipped '+esc(skipped.length)+' unfetchable module(s); re-run the collect to retry them:<ul>'+
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

function loadAptFile(){
  const f=document.getElementById('aptfile');
  const file=f.files && f.files[0];
  if(!file) return;
  file.text().then(t=>{ document.getElementById('aptsrc').value=t; });
}

function loadRpmFile(){
  const f=document.getElementById('rpmfile');
  const file=f.files && f.files[0];
  if(!file) return;
  file.text().then(t=>{ document.getElementById('rpmrepo').value=t; });
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
    if(handleSkip(d, showPyResult)) return;
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
    if(handleSkip(d, showMvnResult)) return;
    showMvnResult('ok','&#10003; Collected '+esc(d.exported_modules)+' artifact(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').');
    loadStatus();
  }catch(e){ showMvnResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showNpmResult(cls, html){
  const el=document.getElementById('npmResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

// npmSpec builds the /admin/npm/collect payload from the NPM page inputs: a
// package list or an uploaded package.json (with an optional package-lock.json).
// Returns {spec, label}, or null when nothing is entered.
async function npmSpec(){
  const jsonFile=document.getElementById('npmjson').files[0];
  if(jsonFile){
    const package_json=await jsonFile.text();
    const lockFile=document.getElementById('npmlock').files[0];
    const package_lock=lockFile ? await lockFile.text() : '';
    return {spec:{package_json:package_json, package_lock:package_lock}, label:'NPM: '+jsonFile.name};
  }
  const pkgs=document.getElementById('npmpkgs').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
  if(pkgs.length){
    return {spec:{packages:pkgs}, label:'NPM: '+pkgs.slice(0,3).join(', ')};
  }
  return null;
}

async function collectNpm(ev){
  ev.preventDefault();
  const built=await npmSpec();
  if(!built){ showNpmResult('err','List at least one package, or upload a package.json.'); return; }
  const btn=document.getElementById('npmBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showNpmResult('busy','Resolving the dependency graph with npm and downloading tarballs… this can take a while for a large project.');
  try{
    const r=await fetch('/admin/npm/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(built.spec)});
    const text=await r.text();
    if(!r.ok){ showNpmResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    if(handleSkip(d, showNpmResult)) return;
    let msg='&#10003; Collected '+esc(d.exported_modules)+' package(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
    const skipped=d.skipped_modules||[];
    if(skipped.length){
      msg+='<br>&#9888; Skipped '+esc(skipped.length)+' package(s) that could not be mirrored:<ul>'+
        skipped.map(m=>'<li><code>'+esc(m.module)+'@'+esc(m.version)+'</code> &mdash; '+esc(m.error)+'</li>').join('')+'</ul>';
      showNpmResult('warn', msg);
    } else {
      showNpmResult('ok', msg);
    }
    loadStatus();
  }catch(e){ showNpmResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

async function scheduleNpm(){
  const built=await npmSpec();
  if(!built){ showNpmResult('err','List at least one package, or upload a package.json, to schedule.'); return; }
  createWatch('npm', built.label, built.spec, 'npmEvery','npmUnit', showNpmResult);
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
    const r=await fetch('/admin/apt/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_list:src, newest_only:document.getElementById('aptnewest').checked})});
    const text=await r.text();
    if(!r.ok){ showAptResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    if(handleSkip(d, showAptResult)) return;
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
    const r=await fetch('/admin/rpm/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repo_file:repo, newest_only:document.getElementById('rpmnewest').checked})});
    const text=await r.text();
    if(!r.ok){ showRpmResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    if(handleSkip(d, showRpmResult)) return;
    showRpmResult('ok','&#10003; Mirrored '+esc(d.exported_modules)+' package(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').');
    loadStatus();
  }catch(e){ showRpmResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

function showCtrResult(cls, html){
  const el=document.getElementById('ctrResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

// ctrImages reads the image list: one reference per line, comments dropped.
function ctrImages(){
  return document.getElementById('ctrimages').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
}

async function collectContainers(ev){
  ev.preventDefault();
  const images=ctrImages();
  if(!images.length){ showCtrResult('err','List at least one image reference.'); return; }
  const btn=document.getElementById('ctrBtn');
  const label=btn.textContent;
  btn.disabled=true; btn.textContent='Collecting…';
  showCtrResult('busy','Resolving manifests and downloading layers for '+esc(images.length)+' image(s)… this can take a while.');
  try{
    const r=await fetch('/admin/containers/collect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({images:images})});
    const text=await r.text();
    if(!r.ok){ showCtrResult('err','Error: '+esc(text.trim())); return; }
    const d=JSON.parse(text);
    if(handleSkip(d, showCtrResult)) return;
    let msg='&#10003; Collected '+esc(d.exported_modules)+' image(s) into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
    const skipped=d.skipped_modules||[];
    if(skipped.length){
      msg+='<br>&#9888; Skipped '+esc(skipped.length)+' unfetchable image(s):<ul>'+
        skipped.map(m=>'<li><code>'+esc(m.module)+':'+esc(m.version)+'</code> &mdash; '+esc(m.error)+'</li>').join('')+'</ul>';
      showCtrResult('warn', msg);
    } else {
      showCtrResult('ok', msg);
    }
    loadStatus();
  }catch(e){ showCtrResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; btn.textContent=label; }
}

async function scheduleContainers(){
  const images=ctrImages();
  if(!images.length){ showCtrResult('err','List at least one image reference to schedule.'); return; }
  createWatch('containers','Containers: '+images.slice(0,3).join(', '), {images:images}, 'ctrEvery','ctrUnit', showCtrResult);
}

async function loadStatus(){
  try{
    const r=await fetch('/ui/api/status',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const s=await r.json();
    const streams=s.streams||[];
    const nextSummary=streams.map(st=>esc(streamLabel(st.stream))+' <b>#'+esc(st.next_sequence)+'</b>').join(' &middot; ');
    document.getElementById('meta').innerHTML=
      nextSummary?'<span>Next bundle &mdash; '+nextSummary+'</span>':'<span>No bundles exported yet.</span>';
    // One combined table across every stream; each ecosystem numbers its own
    // bundles independently, so the stream is shown alongside the sequence.
    const rows=[];
    for(const st of streams){
      for(const x of (st.exported_sequences||[])){
        rows.push('<tr><td>'+esc(streamLabel(st.stream))+'</td><td class="mono">#'+esc(x.sequence)+
          '</td><td class="mono">'+esc(x.bundle_id)+'</td><td class="num">'+esc(formatBytes(x.size_bytes))+
          '</td><td>'+archiveCell(x.in_archive)+'</td><td>'+outboundCell(x.in_outbound)+'</td></tr>');
      }
    }
    const box=document.getElementById('bundles');
    if(!rows.length){ box.innerHTML='<p class="empty">No bundles exported yet.</p>'; return; }
    box.innerHTML='<table><thead><tr><th>Stream</th><th>Sequence</th><th>Bundle</th><th class="num">Size</th>'+
      '<th>Archive</th><th>Outbound</th></tr></thead><tbody>'+
      rows.join('')+'</tbody></table>';
  }catch(e){
    document.getElementById('meta').textContent='Failed to load status: '+e.message;
  }
}

// ---- Schedules (watches) ----
// Each ecosystem page schedules a recurring collect from its own inputs, so the
// spec built here is exactly what that page's collect button would POST.
const WATCH_CONTAINERS={go:'goWatches',python:'pyWatches',maven:'mvnWatches',npm:'npmWatches',apt:'aptWatches',rpm:'rpmWatches',containers:'ctrWatches'};
const WATCH_SHOW={go:showGoResult,python:showPyResult,maven:showMvnResult,npm:showNpmResult,apt:showAptResult,rpm:showRpmResult,containers:showCtrResult};

function intervalSeconds(everyId, unitId){
  const n=parseInt(document.getElementById(everyId).value,10);
  const unit=parseInt(document.getElementById(unitId).value,10);
  return (n>0)?n*unit:0;
}

async function createWatch(stream, label, spec, everyId, unitId, showFn){
  const sec=intervalSeconds(everyId, unitId);
  if(!sec){ showFn('err','Enter a positive schedule interval.'); return; }
  try{
    const r=await fetch('/admin/watches',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({stream:stream, label:label, interval_seconds:sec, spec:spec})});
    const t=await r.text();
    if(!r.ok){ showFn('err','Error: '+esc(t.trim())); return; }
    showFn('ok','&#10003; Schedule added: '+esc(label)+'.');
    loadWatchesInto(stream);
  }catch(e){ showFn('err','Request failed: '+esc(e.message)); }
}

async function scheduleGo(){
  const built=await goSpec();
  if(!built){ showGoResult('err','List at least one module, or upload a go.mod, to schedule.'); return; }
  createWatch('go', built.label, built.spec, 'goEvery','goUnit', showGoResult);
}

async function schedulePython(){
  const parsed=parseRequirements(document.getElementById('pyreqs').value);
  if(!parsed.reqs.length){ showPyResult('err','Enter at least one requirement to schedule.'); return; }
  const spec={requirements:parsed.reqs};
  const target=pyTarget(); if(target) spec.target=target;
  createWatch('python','Python: '+parsed.reqs.slice(0,3).join(', '), spec, 'pyEvery','pyUnit', showPyResult);
}

async function scheduleMaven(){
  const pomFile=document.getElementById('mvnpom').files[0];
  let spec, label;
  if(pomFile){ spec={pom_xml: await pomFile.text()}; label='Maven: '+pomFile.name; }
  else {
    const coords=document.getElementById('mvncoords').value.split(/\r?\n/).map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
    if(!coords.length){ showMvnResult('err','Enter Maven coordinates or upload a pom.xml to schedule.'); return; }
    spec={coordinates:coords}; label='Maven: '+coords[0];
  }
  createWatch('maven', label, spec, 'mvnEvery','mvnUnit', showMvnResult);
}

async function scheduleApt(){
  const src=document.getElementById('aptsrc').value.trim();
  if(!src){ showAptResult('err','Paste a deb822 source to schedule.'); return; }
  const m=src.match(/URIs:\s*(\S+)/i);
  createWatch('apt','APT: '+(m?m[1]:'source'), {source_list:src, newest_only:document.getElementById('aptnewest').checked}, 'aptEvery','aptUnit', showAptResult);
}

async function scheduleRpm(){
  const repo=document.getElementById('rpmrepo').value.trim();
  if(!repo){ showRpmResult('err','Paste a .repo stanza to schedule.'); return; }
  const m=repo.match(/^\s*\[([^\]]+)\]/m);
  createWatch('rpm','RPM: '+(m?m[1]:'repo'), {repo_file:repo, newest_only:document.getElementById('rpmnewest').checked}, 'rpmEvery','rpmUnit', showRpmResult);
}

function fmtEvery(sec){
  if(sec%86400===0) return (sec/86400)+' day(s)';
  if(sec%3600===0) return (sec/3600)+' hour(s)';
  return Math.round(sec/60)+' min';
}
function fmtTime(s){ if(!s) return '&mdash;'; const d=new Date(s); return isNaN(d.getTime())?esc(s):esc(d.toLocaleString()); }

function watchRow(wt, showStream){
  const status=wt.last_status==='error'?'<span class="pill warn">error</span>'
    :wt.last_status==='ok'?'<span class="pill ok">ok</span>':'&mdash;';
  const toggle=wt.enabled
    ? '<button onclick="watchAction(\'disable\','+wt.id+',\''+wt.stream+'\')">Disable</button>'
    : '<button onclick="watchAction(\'enable\','+wt.id+',\''+wt.stream+'\')">Enable</button>';
  const streamCell=showStream?'<td>'+esc(streamLabel(wt.stream))+'</td>':'';
  return '<tr>'+streamCell+'<td>'+esc(wt.label)+'</td><td>'+esc(fmtEvery(wt.interval_seconds))+'</td>'+
    '<td>'+(wt.enabled?'yes':'no')+'</td><td>'+fmtTime(wt.last_run_at)+'</td>'+
    '<td>'+status+(wt.last_message?'<br><span class="wmsg">'+esc(wt.last_message)+'</span>':'')+'</td>'+
    '<td>'+fmtTime(wt.next_run_at)+'</td>'+
    '<td class="wactions"><button onclick="watchAction(\'run\','+wt.id+',\''+wt.stream+'\')">Run now</button>'+
    toggle+'<button onclick="watchAction(\'delete\','+wt.id+',\''+wt.stream+'\')">Delete</button></td></tr>';
}

// loadWatchesInto renders the schedules for one stream into that ecosystem's
// page (blank when the stream has none).
async function loadWatchesInto(stream){
  const box=document.getElementById(WATCH_CONTAINERS[stream]);
  if(!box) return;
  try{
    const r=await fetch('/admin/watches',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const list=((await r.json()).watches||[]).filter(w=>w.stream===stream);
    if(!list.length){ box.innerHTML=''; return; }
    box.innerHTML='<table><thead><tr><th>Schedule</th><th>Every</th><th>Enabled</th>'+
      '<th>Last run</th><th>Status</th><th>Next run</th><th>Actions</th></tr></thead><tbody>'+
      list.map(w=>watchRow(w,false)).join('')+'</tbody></table>';
  }catch(e){ box.textContent='Failed to load schedules: '+e.message; }
}

// loadAllWatches renders every schedule across all ecosystems on the Overview
// page, with a Stream column and each schedule's working status.
async function loadAllWatches(){
  const box=document.getElementById('allWatches');
  if(!box) return;
  try{
    const r=await fetch('/admin/watches',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const list=(await r.json()).watches||[];
    if(!list.length){ box.innerHTML='<p class="empty">No schedules yet. Add one from an ecosystem page.</p>'; return; }
    box.innerHTML='<table><thead><tr><th>Stream</th><th>Schedule</th><th>Every</th><th>Enabled</th>'+
      '<th>Last run</th><th>Status</th><th>Next run</th><th>Actions</th></tr></thead><tbody>'+
      list.map(w=>watchRow(w,true)).join('')+'</tbody></table>';
  }catch(e){ box.textContent='Failed to load schedules: '+e.message; }
}

async function watchAction(action, id, stream){
  if(action==='delete' && !confirm('Delete this schedule?')) return;
  const show=WATCH_SHOW[stream]||function(){};
  try{
    const r=await fetch('/admin/watches/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    if(!r.ok){ const t=await r.text(); show('err','Error: '+esc(t.trim())); return; }
    if(action==='run') show('ok','&#10003; Run started; the schedule updates when it finishes.');
    loadWatchesInto(stream);
    loadAllWatches();
  }catch(e){ show('err','Request failed: '+esc(e.message)); }
}

loadStatus();
loadAllWatches();
</script>
</body>
</html>
`
