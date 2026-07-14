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
		// The dashboard's script is inline in this page and changes across
		// versions; never let a browser cache serve a stale copy.
		w.Header().Set("Cache-Control", "no-store")
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
  .btnrow { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
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
  .pill.busy { background: #2a2410; border: 1px solid #6b5320; color: #d8b26a; }
  .pill.q { background: #2a2f3a; border: 1px solid #3a4150; color: #c7cedb; }
  .wmsg { color: #8b93a5; font-size: .75rem; }
  .wactions { white-space: nowrap; }
  .wactions button { background: #2a2f3a; color: #c7cedb; border: 1px solid #3a4150; border-radius: 5px; padding: .25rem .55rem; margin-left: .3rem; cursor: pointer; font: inherit; font-size: .78rem; }
  .wactions button:first-child { margin-left: 0; }
  .cmodal { flex-direction: column; padding: 0; border: 1px solid #2a2f3a; border-radius: 10px; background: #161a22; color: #e6e6e6; width: min(760px, calc(100% - 3rem)); height: min(70vh, calc(100dvh - 4rem)); max-height: calc(100dvh - 4rem); overflow: hidden; box-shadow: 0 24px 60px rgba(0,0,0,.55); }
  /* A closed <dialog> is display:none by the UA stylesheet; only lay it out as a
     flex column when actually open, or it would show on every page load. */
  .cmodal[open] { display: flex; }
  .cmodal::backdrop { background: rgba(6,8,12,.62); }
  .cmodal-head { flex: 0 0 auto; display: flex; align-items: center; gap: .6rem; padding: .9rem 1.1rem; border-bottom: 1px solid #2a2f3a; }
  .cmodal-head h3 { margin: 0; font-size: 1rem; }
  .cmodal-spin { flex: 0 0 auto; width: 14px; height: 14px; border-radius: 50%; border: 2px solid #3a4150; border-top-color: #7ee2a8; animation: cmspin .7s linear infinite; }
  .cmodal[data-done="1"] .cmodal-spin { display: none; }
  @keyframes cmspin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .cmodal-spin { animation: none; } }
  .cmodal-log { flex: 1 1 auto; min-height: 6rem; margin: 0; padding: .8rem 1.1rem; overflow-y: auto; overflow-x: auto; font-family: ui-monospace, monospace; font-size: .8rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word; color: #c7cedb; background: #0f1115; }
  .cmodal-log .l-err { color: #ff9ea3; }
  .cmdl { flex: 0 0 auto; padding: .55rem 1.1rem .65rem; border-top: 1px solid #2a2f3a; background: #12161f; }
  .cmdl-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; margin-bottom: .35rem; font-size: .78rem; }
  .cmdl-name { font-family: ui-monospace, monospace; color: #c7cedb; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cmdl-stats { color: #8b93a5; white-space: nowrap; font-variant-numeric: tabular-nums; }
  .cmdl-bar { height: 6px; border-radius: 3px; background: #2a2f3a; overflow: hidden; }
  .cmdl-fill { height: 100%; width: 0; background: #2b8f59; transition: width .3s linear; }
  .cmodal-foot { flex: 0 0 auto; padding: .8rem 1.1rem; border-top: 1px solid #2a2f3a; }
  .cmodal-foot .rbox { margin-top: 0; }
  .cm-actions { display: flex; justify-content: flex-end; gap: .6rem; margin-top: .7rem; }
  .cm-actions button:disabled { opacity: .5; cursor: default; }
  button.danger { background: #2e1416; color: #ff9ea3; border: 1px solid #7f2a30; border-radius: 6px; padding: .5rem 1rem; cursor: pointer; font: inherit; }
  button.danger:hover:not(:disabled) { background: #3a191c; }
  .wemodal { border: 1px solid #2a2f3a; border-radius: 10px; background: #161a22; color: #e6e6e6; width: min(640px, calc(100% - 3rem)); max-height: calc(100dvh - 4rem); overflow: auto; padding: 1.1rem 1.25rem 1.25rem; box-shadow: 0 24px 60px rgba(0,0,0,.55); }
  .wemodal::backdrop { background: rgba(6,8,12,.62); }
  .wemodal h3 { margin: 0 0 .35rem; font-size: 1rem; }
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
    <button type="button" data-view="hf" onclick="setView('hf')">AI Models</button>
    <button type="button" data-view="crates" onclick="setView('crates')">Crates</button>
    <button type="button" data-view="terraform" onclick="setView('terraform')">Terraform</button>
    <button type="button" data-view="helm" onclick="setView('helm')">Helm</button>
    <button type="button" data-view="nuget" onclick="setView('nuget')">NuGet</button>
    <button type="button" data-view="apk" onclick="setView('apk')">Alpine</button>
    <button type="button" data-view="conda" onclick="setView('conda')">Conda</button>
    <button type="button" data-view="rubygems" onclick="setView('rubygems')">RubyGems</button>
    <button type="button" data-view="composer" onclick="setView('composer')">Composer</button>
    <button type="button" data-view="vsx" onclick="setView('vsx')">VS Code</button>
    <button type="button" data-view="galaxy" onclick="setView('galaxy')">Ansible</button>
    <button type="button" data-view="cran" onclick="setView('cran')">CRAN</button>
    <button type="button" data-view="git" onclick="setView('git')">Git</button>
    <button type="button" data-view="osv" onclick="setView('osv')">OSV</button>
    <button type="button" data-view="uploads" onclick="setView('uploads')">Uploads</button>
    <button type="button" data-view="status" onclick="setView('status')">Status</button>
  </nav>
  <button type="button" class="refresh" onclick="loadStatus();loadAllWatches();loadJobs()">Refresh</button>
  {{LOGOUT}}
</header>
<main>
  <section class="view" id="view-overview">
  <div class="card">
    <h2>Jobs</h2>
    <p class="hint">Every collect &mdash; started here, by another user, or by a schedule &mdash; runs as a job in a per-ecosystem queue: one job per stream at a time, different streams in parallel. All sessions see the same list, live. Finished jobs keep their outcome (and why they failed) until the server restarts.</p>
    <div id="jobsBox"><p class="empty">Loading&hellip;</p></div>
  </div>
  <div class="card">
    <h2>Scheduled pulls</h2>
    <p class="hint">Every schedule across all ecosystems, with its last run, status, and next run &mdash; so you can see at a glance whether they are working. Add schedules on each ecosystem's page; <b>Edit</b> changes a schedule's label, interval, or collect spec in place.</p>
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
      <label class="pytarget-check"><input id="goForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="goBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectGoMod(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('goResult')">Reset</button>
      </div>
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
	      <p class="hint"><strong>Wheels only:</strong> source distributions are never downloaded, because package build hooks must not run beside the signing key. The collect fails when a requirement has no compatible wheel.</p>
      <details class="pytarget">
        <summary>Cross-target for a different interpreter (optional)</summary>
        <div class="pytarget-grid">
          <label>Python version<input id="pyver" type="text" placeholder="3.12" autocomplete="off"></label>
          <label>Implementation<input id="pyimpl" type="text" placeholder="cp" autocomplete="off"></label>
          <label>ABI<input id="pyabi" type="text" placeholder="cp312" autocomplete="off"></label>
          <label>Platforms (comma-separated)<input id="pyplat" type="text" placeholder="manylinux_2_28_x86_64, manylinux_2_34_x86_64" autocomplete="off"></label>
        </div>
	        <p class="hint">Set these to download wheels for the high-side interpreter rather than this host. Wheels-only mode is always enforced.</p>
      </details>
      <label class="pytarget-check"><input id="pyForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="pyBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectPython(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('pyResult')">Reset</button>
      </div>
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
    <p class="hint">List Maven coordinates (one <code>groupId:artifactId:version</code> per line) or upload a <code>pom.xml</code>. Only the pom's dependency information is used (parent as a BOM import, properties, dependencies, dependencyManagement) &mdash; <code>&lt;build&gt;</code>, <code>&lt;profiles&gt;</code>, and <code>&lt;repositories&gt;</code> are rejected, so a pom can never execute code through Maven. ArtiGate runs <code>mvn dependency:go-offline</code> on the sanitized project to resolve the full closure and writes it to a signed bundle, the same as POSTing to <code>/admin/maven/collect</code>. Release versions only &mdash; SNAPSHOTs and version ranges are rejected.</p>
    <form class="gomod-form" onsubmit="collectMaven(event)">
      <label class="filelabel">Coordinates <span class="opt">&mdash; groupId:artifactId:version, one per line</span>
        <textarea id="mvncoords" rows="4" placeholder="org.slf4j:slf4j-api:2.0.16" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or upload a pom.xml <span class="opt">&mdash; takes precedence over the list</span>
        <input id="mvnpom" type="file" accept=".xml,text/xml">
      </label>
      <label class="pytarget-check"><input id="mvnForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="mvnBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectMaven(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('mvnResult')">Reset</button>
      </div>
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
      <label class="pytarget-check"><input id="npmForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="npmBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectNpm(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('npmResult')">Reset</button>
      </div>
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
    <p class="hint">Paste a deb822 source stanza (the <code>.sources</code> format). ArtiGate downloads and verifies each suite's upstream <code>Release</code> and <code>Packages</code> index, mirrors every referenced <code>.deb</code> for the suites/components/architectures (<code>Suites:</code> may list several, e.g. <code>noble noble-updates noble-security</code>), and writes them to a signed bundle. The high side regenerates and (optionally) re-signs the repository. This is <code>/admin/apt/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectApt(event)">
      <label class="filelabel">Source (deb822)
        <textarea id="aptsrc" rows="6" placeholder="Types: deb&#10;URIs: https://packages.microsoft.com/repos/code&#10;Suites: stable&#10;Components: main&#10;Architectures: amd64&#10;Signed-By: /usr/share/keyrings/microsoft.gpg" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or load a .sources file
        <input id="aptfile" type="file" accept=".sources,.list,text/plain" onchange="loadAptFile()">
      </label>
      <label class="pytarget-check"><input id="aptnewest" type="checkbox" checked> Newest version of each package only (uncheck to mirror every version)</label>
      <label class="pytarget-check"><input id="aptForce" type="checkbox"> Full bundle &mdash; re-download and re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="aptBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectApt(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('aptResult')">Reset</button>
      </div>
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
    <p class="hint">Paste a yum/dnf <code>.repo</code> stanza. ArtiGate downloads and verifies <code>repomd.xml</code> and the <code>primary</code> index, mirrors every referenced <code>.rpm</code> for <code>x86_64</code> + <code>noarch</code> (other architectures are skipped; override via the API's <code>architectures</code> field), and writes a signed bundle. Each repo is published under a name derived from its <code>baseurl</code> (section headers like <code>[baseos]</code> are not used, so identical ids across distros never collide). The high side regenerates <code>repodata</code> and (optionally) re-signs it. This is <code>/admin/rpm/collect</code>. <code>baseurl</code> must be concrete (no <code>$releasever</code>/<code>$basearch</code>).</p>
    <form class="gomod-form" onsubmit="collectRpm(event)">
      <label class="filelabel">Repo definition (.repo)
        <textarea id="rpmrepo" rows="6" placeholder="[code]&#10;name=Visual Studio Code&#10;baseurl=https://packages.microsoft.com/yumrepos/vscode&#10;enabled=1&#10;gpgcheck=1&#10;gpgkey=https://packages.microsoft.com/keys/microsoft.asc" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">&hellip;or load a .repo file
        <input id="rpmfile" type="file" accept=".repo,text/plain" onchange="loadRpmFile()">
      </label>
      <label class="pytarget-check"><input id="rpmnewest" type="checkbox" checked> Newest version of each package only (uncheck to mirror every version)</label>
      <label class="pytarget-check"><input id="rpmForce" type="checkbox"> Full bundle &mdash; re-download and re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="rpmBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectRpm(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('rpmResult')">Reset</button>
      </div>
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
      <label class="pytarget-check"><input id="ctrForce" type="checkbox"> Full bundle &mdash; re-download and re-send even blobs the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="ctrBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectContainers(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('ctrResult')">Reset</button>
      </div>
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

  <section class="view" id="view-hf" hidden>
  <div class="card">
    <h2>Mirror AI models (Hugging Face)</h2>
    <p class="hint">Two kinds of references, both optional. <b>GGUF models</b> &mdash; container-style, one per line: <code>hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0</code>; the tag picks a <b>variant/quantization</b> (<code>Q4_K_M</code>, <code>Q8_0</code>, &hellip;), resolved by Hugging Face itself &mdash; omit it for the repository's default; on the high side, Ollama pulls these straight from the mirror. <b>Full repositories</b> &mdash; for safetensors releases such as <code>openai/gpt-oss-20b</code> that publish no GGUF: every file is mirrored at a pinned commit, and the high side serves the Hub API so vLLM/transformers consume them via <code>HF_ENDPOINT</code>; add <code>@branch</code> or <code>@commit</code> to pin. The <code>hf.co/</code> prefix is optional everywhere. Gated models need <code>ARTIGATE_HF_TOKEN</code> on the low side. Same as POSTing to <code>/admin/hf/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectHF(event)">
      <label class="filelabel">GGUF models <span class="opt">&mdash; one per line; a missing tag means the default quantization</span>
        <textarea id="hfmodels" rows="4" placeholder="hf.co/unsloth/gpt-oss-20b-GGUF:Q4_0&#10;bartowski/Llama-3.2-1B-Instruct-GGUF:Q8_0" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">Full repositories <span class="opt">&mdash; one per line; every file at a pinned commit, for vLLM/transformers via the Hub API</span>
        <textarea id="hfrepos" rows="3" placeholder="openai/gpt-oss-20b&#10;openai/gpt-oss-20b@main" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">Skip repository paths <span class="opt">&mdash; optional, comma-separated; a folder name skips its whole subtree (e.g. the extra <code>original</code>/<code>metal</code> copies in gpt-oss)</span>
        <input id="hfexclude" type="text" placeholder="original, metal" autocomplete="off">
      </label>
      <label class="pytarget-check"><input id="hfForce" type="checkbox"> Full bundle &mdash; re-download and re-send even blobs the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="hfBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectHF(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('hfResult')">Reset</button>
      </div>
    </form>
    <div id="hfResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule these models:</span>
      <span class="every"><input id="hfEvery" type="number" min="1" value="1" autocomplete="off"> <select id="hfUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleHF()">Add schedule</button>
    </div>
    <div id="hfWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-crates" hidden>
  <div class="card">
    <h2>Mirror Rust crates</h2>
    <p class="hint">List crates to mirror &mdash; one per line: <code>serde@1.0.203</code> to pin, or a bare <code>serde</code> for the newest release. Each crate's normal and build dependencies are resolved against the sparse index (index.crates.io by default; <code>--crates-index</code> overrides) and bundled too, each <code>.crate</code> verified against the index checksum. The high side serves a sparse registry: <code>sparse+&lt;high&gt;/crates/index/</code>. Same as POSTing to <code>/admin/crates/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectCrates(event)">
      <label class="filelabel">Crates <span class="opt">&mdash; one per line; name or name@version</span>
        <textarea id="crpkgs" rows="4" placeholder="serde@1.0.203&#10;tokio&#10;anyhow" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="crdeps" type="checkbox" checked> Resolve dependencies (normal + build; dev dependencies are never followed)</label>
      <label class="pytarget-check"><input id="croptional" type="checkbox"> Also follow optional dependencies (bigger, but covers feature-enabled builds)</label>
      <label class="pytarget-check"><input id="crForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="crBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectCrates(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('crResult')">Reset</button>
      </div>
    </form>
    <div id="crResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="crEvery" type="number" min="1" value="1" autocomplete="off"> <select id="crUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleCrates()">Add schedule</button>
    </div>
    <div id="crWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-terraform" hidden>
  <div class="card">
    <h2>Mirror Terraform / OpenTofu providers &amp; modules</h2>
    <p class="hint">List providers (<code>hashicorp/aws@5.50.0</code>, or bare for the newest release) and/or registry modules (<code>terraform-aws-modules/vpc/aws@5.8.1</code>). Provider zips are verified against the registry checksum and mirrored together with the upstream <code>SHA256SUMS</code>, its GPG signature, and signing keys, so terraform's own verification works against the mirror. Modules are repacked as deterministic archives (git sources are fetched with <code>git</code>). Point clients at <code>&lt;high&gt;/.well-known/terraform.json</code>'s host. Same as POSTing to <code>/admin/terraform/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectTerraform(event)">
      <label class="filelabel">Providers <span class="opt">&mdash; one per line; namespace/type or namespace/type@version</span>
        <textarea id="tfproviders" rows="3" placeholder="hashicorp/aws@5.50.0&#10;hashicorp/random" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">Modules <span class="opt">&mdash; one per line; namespace/name/system or @version</span>
        <textarea id="tfmodules" rows="2" placeholder="terraform-aws-modules/vpc/aws@5.8.1" autocomplete="off"></textarea>
      </label>
      <label class="filelabel">Platforms <span class="opt">&mdash; comma-separated os_arch for provider zips; default linux_amd64</span>
        <input id="tfplatforms" type="text" placeholder="linux_amd64, darwin_arm64" autocomplete="off">
      </label>
      <label class="filelabel">Registry <span class="opt">&mdash; optional; default is the configured --terraform-registry or registry.terraform.io (use https://registry.opentofu.org for OpenTofu)</span>
        <input id="tfregistry" type="text" placeholder="https://registry.opentofu.org" autocomplete="off">
      </label>
      <label class="pytarget-check"><input id="tfForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="tfBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectTerraform(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('tfResult')">Reset</button>
      </div>
    </form>
    <div id="tfResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="tfEvery" type="number" min="1" value="1" autocomplete="off"> <select id="tfUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleTerraform()">Add schedule</button>
    </div>
    <div id="tfWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-helm" hidden>
  <div class="card">
    <h2>Mirror Helm charts</h2>
    <p class="hint">Give the upstream chart repository URL (what <code>helm repo add</code> takes) and list charts &mdash; one per line: <code>nginx@21.1.0</code> to pin, or a bare <code>nginx</code> for the newest version. Each chart archive is verified against the repository index digest. The high side regenerates <code>index.yaml</code> from the charts' own embedded <code>Chart.yaml</code> and serves the repo at <code>&lt;high&gt;/helm/&lt;mirror&gt;</code>. Same as POSTing to <code>/admin/helm/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectHelm(event)">
      <label class="filelabel">Repository URL
        <input id="helmurl" type="text" placeholder="https://charts.bitnami.com/bitnami" autocomplete="off">
      </label>
      <label class="filelabel">Mirror name <span class="opt">&mdash; optional; the /helm/&lt;name&gt; the high side serves; defaults to a slug of the URL</span>
        <input id="helmname" type="text" placeholder="bitnami" autocomplete="off">
      </label>
      <label class="filelabel">Charts <span class="opt">&mdash; one per line; name or name@version</span>
        <textarea id="helmcharts" rows="4" placeholder="nginx@21.1.0&#10;postgresql" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="helmForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="helmBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectHelm(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('helmResult')">Reset</button>
      </div>
    </form>
    <div id="helmResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="helmEvery" type="number" min="1" value="1" autocomplete="off"> <select id="helmUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleHelm()">Add schedule</button>
    </div>
    <div id="helmWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-nuget" hidden>
  <div class="card">
    <h2>Mirror NuGet packages</h2>
    <p class="hint">List packages to mirror &mdash; one per line: <code>Newtonsoft.Json@13.0.3</code> to pin, or a bare <code>Serilog</code> for the newest stable release. Dependencies from each package's nuspec are resolved like NuGet restore does (lowest applicable version) against the v3 source (api.nuget.org by default; <code>--nuget-source</code> overrides). The high side serves a v3 feed at <code>&lt;high&gt;/nuget/v3/index.json</code>. Same as POSTing to <code>/admin/nuget/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectNuget(event)">
      <label class="filelabel">Packages <span class="opt">&mdash; one per line; id or id@version</span>
        <textarea id="ngpkgs" rows="4" placeholder="Newtonsoft.Json@13.0.3&#10;Serilog" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="ngdeps" type="checkbox" checked> Resolve dependencies (lowest applicable version, like NuGet restore)</label>
      <label class="pytarget-check"><input id="ngForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="ngBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectNuget(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('ngResult')">Reset</button>
      </div>
    </form>
    <div id="ngResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="ngEvery" type="number" min="1" value="1" autocomplete="off"> <select id="ngUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleNuget()">Add schedule</button>
    </div>
    <div id="ngWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-apk" hidden>
  <div class="card">
    <h2>Mirror an Alpine (apk) repository</h2>
    <p class="hint">Name the mirror base and pick branches/repositories/architectures &mdash; or paste an <code>/etc/apk/repositories</code> file. ArtiGate fetches each <code>APKINDEX</code>, mirrors every listed <code>.apk</code> (verified against the index size and control checksum), and writes a signed bundle. The high side regenerates <code>APKINDEX.tar.gz</code> and (optionally, with <code>--apk-rsa-key</code>) signs it so stock <code>apk</code> clients accept it. The upstream index carries no whole-file hash, so a scheduled re-collect re-downloads packages and dedups at export. This is <code>/admin/apk/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectApk(event)">
      <label class="filelabel">Mirror base URL
        <input id="apkuri" type="text" placeholder="https://dl-cdn.alpinelinux.org/alpine" autocomplete="off">
      </label>
      <label class="filelabel">Branches <span class="opt">&mdash; comma-separated, e.g. v3.22 or edge</span>
        <input id="apkbranches" type="text" placeholder="v3.22" autocomplete="off">
      </label>
      <label class="filelabel">Repositories <span class="opt">&mdash; comma-separated; default main</span>
        <input id="apkrepos" type="text" placeholder="main, community" autocomplete="off">
      </label>
      <label class="filelabel">Architectures <span class="opt">&mdash; comma-separated; default x86_64</span>
        <input id="apkarches" type="text" placeholder="x86_64, aarch64" autocomplete="off">
      </label>
      <label class="filelabel">&hellip;or paste an /etc/apk/repositories file <span class="opt">&mdash; overrides the fields above (architectures still apply)</span>
        <textarea id="apkreposfile" rows="2" placeholder="https://dl-cdn.alpinelinux.org/alpine/v3.22/main&#10;https://dl-cdn.alpinelinux.org/alpine/v3.22/community" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="apknewest" type="checkbox" checked> Newest version of each package only (uncheck to mirror every version)</label>
      <label class="pytarget-check"><input id="apkForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="apkBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectApk(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('apkResult')">Reset</button>
      </div>
    </form>
    <div id="apkResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule this mirror:</span>
      <span class="every"><input id="apkEvery" type="number" min="1" value="1" autocomplete="off"> <select id="apkUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleApk()">Add schedule</button>
    </div>
    <div id="apkWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-conda" hidden>
  <div class="card">
    <h2>Mirror Conda packages</h2>
    <p class="hint">Give the channel (a name like <code>conda-forge</code>, or a full channel URL) and the packages to mirror; each package's dependency closure is resolved greedily against the channel's repodata and mirrored with it. The high side serves the channel under <code>&lt;high&gt;/conda/&lt;mirror&gt;</code> with repodata.json regenerated from the verified packages. Same as POSTing to <code>/admin/conda/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectConda(event)">
      <label class="filelabel">Channel
        <input id="condachannel" type="text" placeholder="conda-forge" autocomplete="off">
      </label>
      <label class="filelabel">Subdirs <span class="opt">&mdash; comma-separated platform subdirs; noarch is always included</span>
        <input id="condasubdirs" type="text" placeholder="linux-64" autocomplete="off">
      </label>
      <label class="filelabel">Packages <span class="opt">&mdash; one per line; name, name==1.2.3, or name&gt;=1.2</span>
        <textarea id="condapkgs" rows="4" placeholder="numpy&#10;scipy==1.13.1" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="condaForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="condaBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectConda(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('condaResult')">Reset</button>
      </div>
    </form>
    <div id="condaResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="condaEvery" type="number" min="1" value="1" autocomplete="off"> <select id="condaUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleConda()">Add schedule</button>
    </div>
    <div id="condaWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-rubygems" hidden>
  <div class="card">
    <h2>Mirror Ruby gems</h2>
    <p class="hint">List gems &mdash; one per line, <code>name</code> or <code>name@1.2.3</code>. Each gem's runtime dependency closure is resolved from the upstream compact index and mirrored with it. The high side serves a compact-index gem source at <code>&lt;high&gt;/rubygems</code> for Bundler (<code>source "&lt;high&gt;/rubygems"</code>). Same as POSTing to <code>/admin/rubygems/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectRubygems(event)">
      <label class="filelabel">Gems <span class="opt">&mdash; one per line; name or name@version</span>
        <textarea id="rubygemsgems" rows="4" placeholder="rails&#10;rake@13.2.1" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="rubygemsForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="rubygemsBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectRubygems(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('rubygemsResult')">Reset</button>
      </div>
    </form>
    <div id="rubygemsResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="rubygemsEvery" type="number" min="1" value="1" autocomplete="off"> <select id="rubygemsUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleRubygems()">Add schedule</button>
    </div>
    <div id="rubygemsWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-composer" hidden>
  <div class="card">
    <h2>Mirror PHP Composer packages</h2>
    <p class="hint">List packages &mdash; one per line, <code>vendor/project</code> or <code>vendor/project:1.2.3</code>. Each package's require closure is resolved from the upstream Composer repository and mirrored with it. The high side serves a Composer repository at <code>&lt;high&gt;/composer</code> (point <code>repositories</code> at it and disable packagist.org). Same as POSTing to <code>/admin/composer/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectComposer(event)">
      <label class="filelabel">Packages <span class="opt">&mdash; one per line; vendor/project or vendor/project:version</span>
        <textarea id="composerpkgs" rows="4" placeholder="monolog/monolog&#10;psr/container:2.0.2" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="composerForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="composerBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectComposer(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('composerResult')">Reset</button>
      </div>
    </form>
    <div id="composerResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="composerEvery" type="number" min="1" value="1" autocomplete="off"> <select id="composerUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleComposer()">Add schedule</button>
    </div>
    <div id="composerWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-vsx" hidden>
  <div class="card">
    <h2>Mirror VS Code extensions</h2>
    <p class="hint">List extensions &mdash; one per line, <code>publisher.name</code> or <code>publisher.name@1.2.3</code> &mdash; fetched from the Open VSX registry. Extension dependencies and packs are mirrored with them. The high side answers the VS Code gallery API at <code>&lt;high&gt;/vsx/gallery</code>; point VSCodium's <code>extensionsGallery.serviceUrl</code> (or <code>VSCODE_GALLERY_SERVICE_URL</code>) at it. Same as POSTing to <code>/admin/vsx/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectVsx(event)">
      <label class="filelabel">Extensions <span class="opt">&mdash; one per line; publisher.name or publisher.name@version</span>
        <textarea id="vsxexts" rows="4" placeholder="golang.Go&#10;redhat.vscode-yaml" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="vsxForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="vsxBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectVsx(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('vsxResult')">Reset</button>
      </div>
    </form>
    <div id="vsxResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="vsxEvery" type="number" min="1" value="1" autocomplete="off"> <select id="vsxUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleVsx()">Add schedule</button>
    </div>
    <div id="vsxWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-galaxy" hidden>
  <div class="card">
    <h2>Mirror Ansible collections</h2>
    <p class="hint">List collections &mdash; one per line, <code>namespace.name</code> or <code>namespace.name@1.5.4</code>. Collection dependencies are resolved from the upstream Galaxy server and mirrored too. The high side answers the Galaxy v3 API at <code>&lt;high&gt;/galaxy</code> (<code>ansible-galaxy collection install ns.name -s &lt;high&gt;/galaxy/</code>). Same as POSTing to <code>/admin/galaxy/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectGalaxy(event)">
      <label class="filelabel">Collections <span class="opt">&mdash; one per line; namespace.name or namespace.name@version</span>
        <textarea id="galaxycols" rows="4" placeholder="ansible.posix&#10;community.general@8.5.0" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="galaxyForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="galaxyBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectGalaxy(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('galaxyResult')">Reset</button>
      </div>
    </form>
    <div id="galaxyResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="galaxyEvery" type="number" min="1" value="1" autocomplete="off"> <select id="galaxyUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleGalaxy()">Add schedule</button>
    </div>
    <div id="galaxyWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-cran" hidden>
  <div class="card">
    <h2>Mirror R packages (CRAN)</h2>
    <p class="hint">List packages &mdash; one per line, <code>name</code> or <code>name@1.2-3</code> (older releases come from the mirror's Archive). Each package's runtime dependency closure (Depends/Imports/LinkingTo) is mirrored with it. The high side serves a source CRAN repository at <code>&lt;high&gt;/cran</code> (<code>install.packages("pkg", repos = "&lt;high&gt;/cran")</code>). Same as POSTing to <code>/admin/cran/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectCran(event)">
      <label class="filelabel">Packages <span class="opt">&mdash; one per line; name or name@version</span>
        <textarea id="cranpkgs" rows="4" placeholder="jsonlite&#10;data.table@1.15.4" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="cranForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="cranBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectCran(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('cranResult')">Reset</button>
      </div>
    </form>
    <div id="cranResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="cranEvery" type="number" min="1" value="1" autocomplete="off"> <select id="cranUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleCran()">Add schedule</button>
    </div>
    <div id="cranWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-git" hidden>
  <div class="card">
    <h2>Mirror a git repository</h2>
    <p class="hint">Give the upstream clone URL. The repository's branches and tags are fetched over the smart HTTP protocol and shipped as one self-contained packfile; the high side rebuilds the pack index itself and serves the repository read-only, so <code>git clone &lt;high&gt;/git/&lt;mirror&gt;.git</code> works with stock git. Re-collecting refreshes the mirror to the current upstream state. Same as POSTing to <code>/admin/git/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectGit(event)">
      <label class="filelabel">Repository URL
        <input id="giturl" type="text" placeholder="https://github.com/org/repo.git" autocomplete="off">
      </label>
      <label class="filelabel">Mirror name <span class="opt">&mdash; optional; defaults to a slug of the URL</span>
        <input id="gitname" type="text" placeholder="repo" autocomplete="off">
      </label>
      <label class="filelabel">Refs <span class="opt">&mdash; optional; one full ref per line to restrict the mirror (refs/heads/main, refs/tags/v1.2.3)</span>
        <textarea id="gitrefs" rows="3" placeholder="refs/heads/main" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="gitForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="gitBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectGit(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('gitResult')">Reset</button>
      </div>
    </form>
    <div id="gitResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule the above:</span>
      <span class="every"><input id="gitEvery" type="number" min="1" value="1" autocomplete="off"> <select id="gitUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleGit()">Add schedule</button>
    </div>
    <div id="gitWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-osv" hidden>
  <div class="card">
    <h2>Mirror OSV vulnerability databases</h2>
    <p class="hint">List OSV ecosystem names &mdash; one per line, exactly as <a href="https://osv.dev" rel="noreferrer">osv.dev</a> spells them: <code>npm</code>, <code>PyPI</code>, <code>Go</code>, <code>crates.io</code>, <code>Maven</code>, <code>NuGet</code>, <code>Alpine:v3.22</code>, <code>Debian:12</code>, &hellip; Each name's current <code>all.zip</code> advisory database is fetched and re-exported as a snapshot; an unchanged database dedups to a no-op, so a daily schedule is cheap. The high side serves them under <code>&lt;high&gt;/osv/&hellip;</code> for offline scanners, and the <code>npm</code> database additionally answers <code>npm audit</code> against the mirror. Same as POSTing to <code>/admin/osv/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectOsv(event)">
      <label class="filelabel">Ecosystems <span class="opt">&mdash; one OSV ecosystem name per line</span>
        <textarea id="osvecos" rows="4" placeholder="npm&#10;PyPI&#10;Go" autocomplete="off"></textarea>
      </label>
      <label class="pytarget-check"><input id="osvForce" type="checkbox"> Full bundle &mdash; re-send even content the high side already has (for rebuilding a high side; clears after a successful collect)</label>
      <div class="btnrow">
        <button class="primary" type="submit" id="osvBtn">Collect &amp; export</button>
        <button class="secondary" type="button" title="Dry run: resolve and measure this collect without exporting anything" onclick="collectOsv(event, true)">Estimate size</button>
        <button class="secondary" type="reset" onclick="clearResult('osvResult')">Reset</button>
      </div>
    </form>
    <div id="osvResult" class="rbox"></div>
    <div class="sched">
      <span class="sched-label">Schedule this mirror:</span>
      <span class="every"><input id="osvEvery" type="number" min="1" value="1" autocomplete="off"> <select id="osvUnit" class="restream"><option value="3600">hours</option><option value="86400" selected>days</option></select></span>
      <button type="button" class="secondary" onclick="scheduleOsv()">Add schedule</button>
    </div>
    <div id="osvWatches" class="watchlist"></div>
  </div>
  </section>

  <section class="view" id="view-uploads" hidden>
  <div class="card">
    <h2>Upload files</h2>
    <p class="hint">Send arbitrary files across the diode: pick a folder name and one or more files. The high side serves them under <code>/uploads/&lt;folder&gt;/&lt;name&gt;</code>, shows them on its dashboard, and can delete them again. Re-uploading the same name replaces the file. Uploads always ship in full &mdash; the already-forwarded index is not consulted, so a file deleted on the high side comes back by simply uploading it again. Same as POSTing multipart form data to <code>/admin/uploads/collect</code>.</p>
    <form class="gomod-form" onsubmit="collectUploads(event)">
      <label class="filelabel">Folder <span class="opt">&mdash; a single name, no slashes; created on the high side if new</span>
        <input id="upfolder" type="text" placeholder="tools" autocomplete="off">
      </label>
      <label class="filelabel">File(s)
        <input id="upfiles" type="file" multiple>
      </label>
      <div class="btnrow">
        <button class="primary" type="submit" id="upBtn">Upload &amp; export</button>
        <button class="secondary" type="reset" onclick="clearResult('upResult')">Reset</button>
      </div>
    </form>
    <div id="upResult" class="rbox"></div>
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
        <option value="hf">AI Models (Hugging Face)</option>
        <option value="crates">Rust Crates</option>
        <option value="terraform">Terraform</option>
        <option value="helm">Helm</option>
        <option value="nuget">NuGet</option>
        <option value="apk">Alpine (apk)</option>
        <option value="conda">Conda</option>
        <option value="rubygems">RubyGems</option>
        <option value="composer">Composer</option>
        <option value="vsx">VS Code extensions</option>
        <option value="galaxy">Ansible Galaxy</option>
        <option value="cran">CRAN</option>
        <option value="git">Git</option>
        <option value="osv">OSV</option>
        <option value="uploads">Uploads</option>
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
<dialog id="collectModal" class="cmodal" aria-label="Collect progress">
  <div class="cmodal-head"><span class="cmodal-spin" id="cmSpin" aria-hidden="true"></span><h3 id="cmTitle">Collecting</h3></div>
  <pre class="cmodal-log" id="cmLog" aria-live="polite"></pre>
  <div class="cmdl" id="cmDl" hidden>
    <div class="cmdl-head"><span class="cmdl-name" id="cmDlName"></span><span class="cmdl-stats" id="cmDlStats"></span></div>
    <div class="cmdl-bar"><div class="cmdl-fill" id="cmDlFill"></div></div>
  </div>
  <div class="cmodal-foot">
    <div id="cmResult" class="rbox"></div>
    <p class="hint" id="cmDetachHint" hidden>Closing this window does not stop the job &mdash; it keeps running and stays visible under Jobs on the Overview page.</p>
    <div class="cm-actions">
      <button type="button" class="danger" id="cmStop" onclick="stopCollect()">Stop</button>
      <button type="button" class="secondary" id="cmClose" onclick="closeCollectModal()">Close</button>
    </div>
  </div>
</dialog>
<dialog id="watchEditModal" class="wemodal" aria-label="Edit schedule">
  <h3>Edit schedule</h3>
  <p class="hint" id="weStream"></p>
  <form class="gomod-form" onsubmit="saveWatchEdit(event)">
    <label class="filelabel">Label
      <input id="weLabel" type="text" autocomplete="off">
    </label>
    <label class="filelabel">Run every
      <span class="every"><input id="weEvery" type="number" min="1" autocomplete="off"> <select id="weUnit" class="restream"><option value="60">minutes</option><option value="3600">hours</option><option value="86400">days</option></select></span>
    </label>
    <label class="filelabel">Collect spec <span class="opt">&mdash; the JSON body this schedule replays on each run, exactly what the page's collect would POST</span>
      <textarea id="weSpec" rows="9" spellcheck="false" autocomplete="off"></textarea>
    </label>
    <div id="weResult" class="rbox"></div>
    <div class="cm-actions">
      <button type="button" class="secondary" onclick="closeWatchEdit()">Cancel</button>
      <button type="submit" class="primary" id="weSave">Save</button>
    </div>
  </form>
</dialog>
<script>
// If the session has expired, any API call returns 401; bounce to the login page.
(function(){const _f=window.fetch;window.fetch=async(...a)=>{const r=await _f(...a);if(r.status===401){location.href='/login';}return r;};})();
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function streamLabel(name){return ({go:'Go',python:'Python',maven:'Maven',npm:'NPM',apt:'APT',rpm:'RPM',containers:'Containers',hf:'AI Models',crates:'Crates',terraform:'Terraform',helm:'Helm',nuget:'NuGet',apk:'Alpine',conda:'Conda',rubygems:'RubyGems',composer:'Composer',vsx:'VS Code',galaxy:'Ansible',cran:'CRAN',git:'Git',osv:'OSV',uploads:'Uploads'})[name]||name;}
// clearResult hides an ecosystem's inline result box; the Reset button pairs it
// with the form's native field reset (type="reset").
function clearResult(id){const el=document.getElementById(id); if(el){ el.className='rbox'; el.innerHTML=''; }}
// ---- Collect progress modal ----
// Every "Collect & export" streams its progress into one shared modal: the
// collect runs as a job on its stream's queue, the POST carries ?stream=1, and
// the server answers with newline-delimited JSON events
// ({type:"job"|"log"|"dl"|"done"|"error"}) that this reader renders live. The
// job is server-side: Stop cancels it via /admin/jobs/cancel, and closing the
// modal merely stops following — the job keeps running (except uploads, whose
// bytes stream from this page, so they still live and die with the request).
// The same modal follows any existing job from the Jobs table via viewJob.
let cmRunning=false, cmAbort=null, cmJobId=0, cmDetached=false;

function openCollectModal(title){
  const m=document.getElementById('collectModal');
  document.getElementById('cmTitle').textContent=title;
  document.getElementById('cmLog').textContent='';
  const rb=document.getElementById('cmResult'); rb.className='rbox'; rb.innerHTML='';
  m.dataset.done=''; cmRunning=true; cmJobId=0; cmDetached=false;
  cmAbort=new AbortController();
  hideCollectDl();
  const stop=document.getElementById('cmStop'); stop.disabled=false; stop.textContent='Stop';
  document.getElementById('cmClose').disabled=true;
  document.getElementById('cmDetachHint').hidden=true;
  if(!m.open) m.showModal();
}

// noteCollectJob records which job the modal is following (from the stream's
// leading {type:"job"} event). Knowing the job makes the modal detachable:
// Close only stops following, so it unlocks along with the hint saying so.
function noteCollectJob(id){
  cmJobId=id;
  document.getElementById('cmClose').disabled=false;
  document.getElementById('cmDetachHint').hidden=false;
}

// stopCollect cancels the job the modal is following; the stream then ends
// with its terminal event. Uploads have no server-side life of their own —
// aborting the request cancels them, exactly as before.
function stopCollect(){
  if(!cmRunning) return;
  const stop=document.getElementById('cmStop');
  stop.disabled=true; stop.textContent='Stopping…';
  if(cmJobId){
    appendCollectLog('Stop requested — cancelling job #'+cmJobId+'…');
    fetch('/admin/jobs/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:cmJobId})})
      .then(r=>{ if(!r.ok){ return r.text().then(t=>{ throw new Error((t&&t.trim())||('HTTP '+r.status)); }); } })
      .catch(e=>{ appendCollectLog('Cancel failed: '+e.message,'l-err'); stop.disabled=false; stop.textContent='Stop'; });
    return;
  }
  if(!cmAbort) return;
  appendCollectLog('Stop requested — cancelling the running upload…');
  cmAbort.abort();
}
// ---- Per-file download progress ----
// Downloads within a collect are sequential, so one bar tracks the file in
// flight: {type:"dl", name, done, total, bps} events update it in place
// (total 0 means the size is unknown — bytes and speed only).
function updateCollectDl(ev){
  const done=Number(ev.done)||0, total=Number(ev.total)||0, bps=Number(ev.bps)||0;
  document.getElementById('cmDl').hidden=false;
  document.getElementById('cmDlName').textContent=ev.name||'download';
  let stats='';
  if(total>0) stats+=Math.min(100,Math.floor(done*100/total))+'% · ';
  stats+=formatBytes(done);
  if(total>0) stats+=' / '+formatBytes(total);
  if(bps>0){
    stats+=' · '+formatBytes(bps)+'/s';
    if(total>done) stats+=' · ETA '+fmtETA((total-done)/bps);
  }
  document.getElementById('cmDlStats').textContent=stats;
  document.getElementById('cmDlFill').style.width=(total>0?Math.min(100,done*100/total):0)+'%';
}
function hideCollectDl(){
  const el=document.getElementById('cmDl');
  el.hidden=true;
  document.getElementById('cmDlFill').style.width='0%';
}
function fmtETA(sec){
  sec=Math.max(0,Math.round(sec));
  if(sec<60) return sec+'s';
  if(sec<3600) return Math.floor(sec/60)+'m'+String(sec%60).padStart(2,'0')+'s';
  return Math.floor(sec/3600)+'h'+String(Math.floor(sec/60)%60).padStart(2,'0')+'m';
}
function appendCollectLog(msg, cls){
  const log=document.getElementById('cmLog');
  // Stick to the newest line unless the user has scrolled up to read history.
  // The tolerance must exceed one line height so following never stalls.
  const atBottom = log.scrollTop+log.clientHeight >= log.scrollHeight-24;
  const span=document.createElement('span');
  if(cls) span.className=cls;
  span.textContent=msg+'\n';
  log.appendChild(span);
  if(atBottom) log.scrollTop=log.scrollHeight; // follow the tail unless scrolled up
}
function finishCollectModal(cls, html){
  const m=document.getElementById('collectModal');
  m.dataset.done='1'; cmRunning=false; cmAbort=null;
  document.getElementById('cmDetachHint').hidden=true;
  hideCollectDl();
  const rb=document.getElementById('cmResult'); rb.className='rbox '+cls; rb.innerHTML=html;
  const stop=document.getElementById('cmStop'); stop.disabled=true; stop.textContent='Stop';
  document.getElementById('cmClose').disabled=false;
}
function closeCollectModal(){
  const m=document.getElementById('collectModal');
  if(cmRunning){
    // A job-backed collect detaches: stop following, let the job run on. An
    // upload stays attached — aborting would kill the transfer itself.
    if(!cmJobId) return;
    cmDetached=true;
    if(cmAbort) cmAbort.abort();
    return; // the follower's AbortError handler closes the modal
  }
  if(m.open) m.close();
}

// consumeNDJSON reads a streaming response body line by line, passing each
// line to handle.
async function consumeNDJSON(res, handle){
  const reader=res.body.getReader(), dec=new TextDecoder();
  let buf='';
  for(;;){
    const {value,done}=await reader.read();
    if(value) buf+=dec.decode(value,{stream:true});
    let nl; while((nl=buf.indexOf('\n'))>=0){ handle(buf.slice(0,nl)); buf=buf.slice(nl+1); }
    if(done) break;
  }
  buf+=dec.decode(); if(buf.trim()) handle(buf);
}

// consumeCollectStream renders a job's NDJSON events into the modal. It
// resolves with the final ExportResult, or throws with the job's failure
// reason ("collect canceled" for a canceled job).
async function consumeCollectStream(res){
  let result=null, errMsg=null;
  await consumeNDJSON(res, line=>{
    line=line.trim(); if(!line) return;
    let ev; try{ ev=JSON.parse(line); }catch(_){ return; }
    // A log line follows every finished download (and every phase change), so
    // it doubles as the signal to retire the current file's progress bar.
    if(ev.type==='job'){ noteCollectJob(ev.id); }
    else if(ev.type==='log'){ appendCollectLog(ev.message); hideCollectDl(); }
    else if(ev.type==='dl') updateCollectDl(ev);
    else if(ev.type==='done'){ result=ev.result||{}; hideCollectDl(); }
    else if(ev.type==='error'){ errMsg=ev.error||'collect failed'; appendCollectLog(errMsg,'l-err'); hideCollectDl(); }
  });
  if(errMsg!=null) throw new Error(errMsg);
  return result||{};
}

// streamCollect POSTs a collect with ?stream=1 and consumes the NDJSON progress
// stream, appending each log line to the modal. It resolves with the final
// ExportResult, or throws with the server's error message (or AbortError when
// the follow was aborted). The url may already carry a query (?dry_run=1).
async function streamCollect(url, body, signal){
  // The uploads form posts FormData, which takes the XHR path: the file
  // transfer itself is the long part, and only XHR reports upload progress.
  if((typeof FormData!=='undefined') && body instanceof FormData) return uploadCollect(url, body, signal);
  const res=await fetch(url+(url.includes('?')?'&':'?')+'stream=1',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:signal});
  if(!res.ok || !res.body){
    const t=await res.text().catch(()=>''); throw new Error((t&&t.trim())||('HTTP '+res.status));
  }
  return consumeCollectStream(res);
}

// runCollect wires one ecosystem's button to the progress modal: it disables the
// button, streams the collect, then renders the per-ecosystem summary (o.render)
// in both the modal and the page's inline result box. A dedup skip is
// rendered uniformly here, and so is a dry run (o.dry appends ?dry_run=1: the
// server resolves and measures the collect but exports nothing).
async function runCollect(o){
  const btn=document.getElementById(o.btnId), label=btn.textContent;
  btn.disabled=true; btn.textContent=o.dry?'Estimating…':(o.busyLabel||'Collecting…');
  openCollectModal(o.dry?o.title+' (dry run)':o.title);
  try{
    const d=await streamCollect(o.dry?o.url+'?dry_run=1':o.url, o.body, cmAbort.signal);
    // A forced "full bundle" is a one-shot recovery action: clear the checkbox
    // once the collect worked, so the next collect returns to delta exports
    // instead of silently re-sending everything each time. (A dry run is not
    // a collect — the checkbox stays put for the real one.)
    if(!o.dry && o.forceId && o.body.force) document.getElementById(o.forceId).checked=false;
    let out;
    if(d && d.dry_run) out=dryRunMsg(d);
    else if(d && d.skipped) out={cls:'ok', msg:'&#10003; No new content since the last export &mdash; nothing to send across the diode.'};
    else out=o.render(d);
    // A failed upload to the HTTP diode endpoint is a warning, not an error:
    // the bundle is committed and archived, ready to re-transmit.
    if(d && d.diode_error){
      out={cls:'warn', msg:out.msg+'<br>&#9888; Diode upload failed: '+esc(d.diode_error)+' &mdash; the bundle is archived and still staged; re-transmit it from the Status page.'};
    }
    finishCollectModal(out.cls, out.msg);
    o.showFn(out.cls, out.msg);
    loadStatus();
  }catch(e){
    if(e && e.name==='AbortError' && cmDetached){
      // Close was pressed mid-run: only the follow stream was aborted; the
      // job keeps running server-side.
      const msg='&#8505; Job #'+esc(cmJobId)+' continues in the background &mdash; follow it under Jobs on the Overview page.';
      finishCollectModal('warn', msg);
      closeCollectModal();
      o.showFn('warn', msg);
    }else if(e && e.name==='AbortError'){
      // An upload's Stop: the server cancels the collect with the connection,
      // aborting the transfer and packing alike. Only a stop landing in the
      // final sign-and-archive moment still exports, so point at Status.
      const msg='&#9632; Collect stopped. Nothing was exported &mdash; unless it had already reached the final signing step; check the Status page.';
      finishCollectModal('warn', msg);
      o.showFn('warn', msg);
      loadStatus();
    }else if(e && e.message==='collect canceled'){
      // Stop was pressed (here or in another session): the job's context was
      // cancelled and its stream ended with the terminal error event.
      const msg='&#9632; Collect canceled. Nothing was exported &mdash; unless it had already reached the final signing step; check the Status page.';
      finishCollectModal('warn', msg);
      o.showFn('warn', msg);
      loadStatus();
    }else{
      finishCollectModal('err','Error: '+esc(e.message));
      o.showFn('err','Error: '+esc(e.message));
    }
  }finally{ btn.disabled=false; btn.textContent=label; }
}

// applyForce adds force to a collect body when the page's "full bundle"
// checkbox is ticked, bypassing the forwarded-content index so everything is
// re-downloaded and re-packed. Only the immediate collect carries it — the
// schedule builders never call this, because a recurring forced pull would
// re-send the whole mirror on every run.
function applyForce(body, boxId){
  if(document.getElementById(boxId).checked) body.force=true;
  return body;
}

// dryRunMsg renders a dry-run estimate: what a real collect would send across
// the diode. Nothing was exported and no sequence number was consumed.
function dryRunMsg(d){
  const e=d.estimate||{};
  let msg;
  if(d.skipped){
    msg='&#9878; Dry run: every resolved file ('+esc(e.total_files||0)+' file(s), '+formatBytes(e.total_bytes)+') has already been forwarded &mdash; a collect would skip.';
  }else{
    msg='&#9878; Dry run: a collect would send <b>'+esc(e.new_files)+' new file(s), '+formatBytes(e.new_bytes)+'</b> across the diode in '+esc(e.bundles)+' bundle(s) (&le; '+formatBytes(e.estimated_archive_bytes)+' archived).';
    if(d.prior_files>0) msg+=' '+esc(d.prior_files)+' of '+esc(e.total_files)+' resolved file(s) are already forwarded and would ride along as prior references.';
  }
  const sk=(d.skipped_modules||[]).length;
  if(sk) msg+='<br>&#9888; '+esc(sk)+' item(s) could not be fetched/resolved and are not counted.';
  return {cls:'ok', msg:msg+' Nothing was exported.'};
}

// collectedMsg / skippedListHTML build the shared success line and the optional
// "skipped items" list each ecosystem appends to it.
function collectedMsg(d, verb, noun){
  let msg='&#10003; '+verb+' '+esc(d.exported_modules)+' '+noun+' into <code>'+esc(d.bundle_id)+'</code> (sequence #'+esc(d.sequence)+').';
  if(d.prior_files>0) msg+=' '+esc(d.prior_files)+' file(s) were already forwarded and ride along as prior references (not re-sent).';
  return msg;
}
function skippedListHTML(intro, items, fmt){
  return '<br>&#9888; '+intro+'<ul>'+items.map(m=>'<li>'+fmt(m)+'</li>').join('')+'</ul>';
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
const VIEW_STREAM={go:'go',python:'python',maven:'maven',npm:'npm',apt:'apt',rpm:'rpm',containers:'containers',hf:'hf',crates:'crates',terraform:'terraform',helm:'helm',nuget:'nuget',apk:'apk',conda:'conda',rubygems:'rubygems',composer:'composer',vsx:'vsx',galaxy:'galaxy',cran:'cran',git:'git',osv:'osv'};
function setView(view){
  // The sections themselves are the source of truth (every <section class="view">
  // has id "view-<name>"), so a newly added page can never be missing here and
  // render blank.
  document.querySelectorAll('section.view').forEach(s=>{ s.hidden = (s.id!=='view-'+view); });
  document.querySelectorAll('nav button[data-view]').forEach(b=>{
    b.classList.toggle('active', b.dataset.view===view);
  });
  if(view==='overview'){ loadAllWatches(); loadJobs(); }
  pollJobs(view==='overview'); // live jobs only while the Overview is showing
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

async function collectGoMod(ev, dry){
  ev.preventDefault();
  const built=await goSpec();
  if(!built){ showGoResult('err','List at least one module, or upload a go.mod.'); return; }
  runCollect({dry:dry, btnId:'goBtn', showFn:showGoResult, title:'Collecting Go modules',
    url:'/admin/go/collect', body:applyForce(built.spec,'goForce'), forceId:'goForce', render:d=>{
      const msg=collectedMsg(d,'Collected','module(s)');
      const sk=d.skipped_modules||[];
      if(sk.length) return {cls:'warn', msg:msg+skippedListHTML('Skipped '+esc(sk.length)+' unfetchable module(s); re-run the collect to retry them:', sk, m=>'<code>'+esc(m.module)+'@'+esc(m.version)+'</code>')};
      return {cls:'ok', msg};
    }});
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
	  const plats=platRaw?platRaw.split(',').map(s=>s.trim()).filter(Boolean):[];
	  if(!ver && !impl && !abi && !plats.length) return null;
	  const t={};
  if(ver) t.python_version=ver;
  if(impl) t.implementation=impl;
  if(abi) t.abi=abi;
  if(plats.length) t.platforms=plats;
  return t;
}

async function collectPython(ev, dry){
  ev.preventDefault();
  const parsed=parseRequirements(document.getElementById('pyreqs').value);
  if(!parsed.reqs.length){ showPyResult('err','Enter at least one requirement (one per line).'); return; }
  const body={requirements:parsed.reqs};
  const target=pyTarget(); if(target) body.target=target;
  runCollect({dry:dry, btnId:'pyBtn', showFn:showPyResult, title:'Collecting Python packages',
    url:'/admin/python/collect', body:applyForce(body,'pyForce'), forceId:'pyForce', render:d=>{
      let msg=collectedMsg(d,'Collected','package(s)'), warn=false;
      const sd=d.skipped_modules||[];
      if(sd.length){ warn=true; msg+=skippedListHTML(esc(sd.length)+' package(s) had no wheel (source distribution only) and were not mirrored &mdash; pin a version that ships a wheel, or exclude them:', sd, m=>'<code>'+esc(m.module)+(m.version?' '+esc(m.version):'')+'</code>'); }
      if(parsed.skipped.length){ warn=true; msg+='<br>&#9888; Skipped '+esc(parsed.skipped.length)+' pip option line(s) not supported here (e.g. <code>'+esc(parsed.skipped[0])+'</code>).'; }
      return {cls:warn?'warn':'ok', msg};
    }});
}

function showMvnResult(cls, html){
  const el=document.getElementById('mvnResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectMaven(ev, dry){
  ev.preventDefault();
  const pomInput=document.getElementById('mvnpom');
  const pomFile=pomInput.files && pomInput.files[0];
  const coords=document.getElementById('mvncoords').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim())
    .filter(l=>l && l.charAt(0)!=='#');
  if(!pomFile && !coords.length){ showMvnResult('err','Enter Maven coordinates or upload a pom.xml.'); return; }
  const body = pomFile ? {pom_xml: await pomFile.text()} : {coordinates: coords};
  runCollect({dry:dry, btnId:'mvnBtn', showFn:showMvnResult, title:'Collecting Maven artifacts',
    url:'/admin/maven/collect', body:applyForce(body,'mvnForce'), forceId:'mvnForce',
    render:d=>({cls:'ok', msg:collectedMsg(d,'Collected','artifact(s)')})});
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

async function collectNpm(ev, dry){
  ev.preventDefault();
  const built=await npmSpec();
  if(!built){ showNpmResult('err','List at least one package, or upload a package.json.'); return; }
  runCollect({dry:dry, btnId:'npmBtn', showFn:showNpmResult, title:'Collecting NPM packages',
    url:'/admin/npm/collect', body:applyForce(built.spec,'npmForce'), forceId:'npmForce', render:d=>{
      const msg=collectedMsg(d,'Collected','package(s)');
      const sk=d.skipped_modules||[];
      if(sk.length) return {cls:'warn', msg:msg+skippedListHTML('Skipped '+esc(sk.length)+' package(s) that could not be mirrored:', sk, m=>'<code>'+esc(m.module)+'@'+esc(m.version)+'</code> &mdash; '+esc(m.error))};
      return {cls:'ok', msg};
    }});
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

async function collectApt(ev, dry){
  ev.preventDefault();
  const src=document.getElementById('aptsrc').value.trim();
  if(!src){ showAptResult('err','Paste a deb822 source stanza.'); return; }
  runCollect({dry:dry, btnId:'aptBtn', busyLabel:'Mirroring…', showFn:showAptResult, title:'Mirroring APT repository',
    url:'/admin/apt/collect', forceId:'aptForce',
    body:applyForce({source_list:src, newest_only:document.getElementById('aptnewest').checked},'aptForce'),
    render:d=>({cls:'ok', msg:collectedMsg(d,'Mirrored','package(s)')})});
}

function showRpmResult(cls, html){
  const el=document.getElementById('rpmResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectRpm(ev, dry){
  ev.preventDefault();
  const repo=document.getElementById('rpmrepo').value.trim();
  if(!repo){ showRpmResult('err','Paste a yum/dnf .repo stanza.'); return; }
  runCollect({dry:dry, btnId:'rpmBtn', busyLabel:'Mirroring…', showFn:showRpmResult, title:'Mirroring RPM repository',
    url:'/admin/rpm/collect', forceId:'rpmForce',
    body:applyForce({repo_file:repo, newest_only:document.getElementById('rpmnewest').checked},'rpmForce'),
    render:d=>({cls:'ok', msg:collectedMsg(d,'Mirrored','package(s)')})});
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

async function collectContainers(ev, dry){
  ev.preventDefault();
  const images=ctrImages();
  if(!images.length){ showCtrResult('err','List at least one image reference.'); return; }
  runCollect({dry:dry, btnId:'ctrBtn', showFn:showCtrResult, title:'Collecting container images',
    url:'/admin/containers/collect', body:applyForce({images:images},'ctrForce'), forceId:'ctrForce', render:d=>{
      const msg=collectedMsg(d,'Collected','image(s)');
      const sk=d.skipped_modules||[];
      if(sk.length) return {cls:'warn', msg:msg+skippedListHTML('Skipped '+esc(sk.length)+' unfetchable image(s):', sk, m=>'<code>'+esc(m.module)+':'+esc(m.version)+'</code> &mdash; '+esc(m.error))};
      return {cls:'ok', msg};
    }});
}

async function scheduleContainers(){
  const images=ctrImages();
  if(!images.length){ showCtrResult('err','List at least one image reference to schedule.'); return; }
  createWatch('containers','Containers: '+images.slice(0,3).join(', '), {images:images}, 'ctrEvery','ctrUnit', showCtrResult);
}

function showHFResult(cls, html){
  const el=document.getElementById('hfResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

// hfModels / hfRepos read the two reference lists: one per line, comments
// dropped. hfBody builds the shared collect/schedule payload from them.
function hfModels(){
  return document.getElementById('hfmodels').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
}
function hfRepos(){
  return document.getElementById('hfrepos').value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
}
function hfBody(){
  const models=hfModels(), repos=hfRepos();
  if(!models.length && !repos.length) return null;
  const body={models:models, repos:repos};
  const ex=document.getElementById('hfexclude').value.split(',').map(s=>s.trim()).filter(Boolean);
  if(ex.length) body.repo_exclude=ex;
  return body;
}

async function collectHF(ev, dry){
  ev.preventDefault();
  const body=hfBody();
  if(!body){ showHFResult('err','List at least one model or repository reference.'); return; }
  runCollect({dry:dry, btnId:'hfBtn', showFn:showHFResult, title:'Collecting AI models',
    url:'/admin/hf/collect', body:applyForce(body,'hfForce'), forceId:'hfForce', render:d=>{
      const msg=collectedMsg(d,'Collected','model(s)');
      const sk=d.skipped_modules||[];
      if(sk.length) return {cls:'warn', msg:msg+skippedListHTML('Skipped '+esc(sk.length)+' unfetchable model(s):', sk, m=>'<code>'+esc(m.module)+':'+esc(m.version)+'</code> &mdash; '+esc(m.error))};
      return {cls:'ok', msg};
    }});
}

async function scheduleHF(){
  const body=hfBody();
  if(!body){ showHFResult('err','List at least one model or repository reference to schedule.'); return; }
  const refs=hfModels().concat(hfRepos());
  createWatch('hf','AI Models: '+refs.slice(0,3).join(', '), body, 'hfEvery','hfUnit', showHFResult);
}

function showCrResult(cls, html){
  const el=document.getElementById('crResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

// linesOf reads a textarea as a list: one entry per line, comments dropped.
function linesOf(id){
  return document.getElementById(id).value.split(/\r?\n/)
    .map(s=>s.replace(/\s+#.*$/,'').trim()).filter(l=>l && l.charAt(0)!=='#');
}

// commaList reads a comma-separated input into a trimmed list.
function commaList(id){
  return document.getElementById(id).value.split(',').map(s=>s.trim()).filter(Boolean);
}

// skippedItems renders the shared "these items were skipped" warning for a
// collect result.
function skippedItems(msg, d){
  const sk=d.skipped_modules||[];
  if(!sk.length) return {cls:'ok', msg};
  return {cls:'warn', msg:msg+skippedListHTML('Skipped '+esc(sk.length)+' unfetchable item(s):', sk, m=>'<code>'+esc(m.module)+'@'+esc(m.version)+'</code> &mdash; '+esc(m.error))};
}

function cratesBody(){
  const crates=linesOf('crpkgs');
  if(!crates.length) return null;
  const body={crates:crates, resolve_deps:document.getElementById('crdeps').checked};
  if(document.getElementById('croptional').checked) body.include_optional=true;
  return body;
}

async function collectCrates(ev, dry){
  ev.preventDefault();
  const body=cratesBody();
  if(!body){ showCrResult('err','List at least one crate.'); return; }
  runCollect({dry:dry, btnId:'crBtn', showFn:showCrResult, title:'Collecting Rust crates',
    url:'/admin/crates/collect', body:applyForce(body,'crForce'), forceId:'crForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','crate(s)'), d)});
}

async function scheduleCrates(){
  const body=cratesBody();
  if(!body){ showCrResult('err','List at least one crate to schedule.'); return; }
  createWatch('crates','Crates: '+body.crates.slice(0,3).join(', '), body, 'crEvery','crUnit', showCrResult);
}

function showTfResult(cls, html){
  const el=document.getElementById('tfResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function terraformBody(){
  const providers=linesOf('tfproviders'), modules=linesOf('tfmodules');
  if(!providers.length && !modules.length) return null;
  const body={providers:providers, modules:modules};
  const platforms=commaList('tfplatforms');
  if(platforms.length) body.platforms=platforms;
  const registry=document.getElementById('tfregistry').value.trim();
  if(registry) body.registry=registry;
  return body;
}

async function collectTerraform(ev, dry){
  ev.preventDefault();
  const body=terraformBody();
  if(!body){ showTfResult('err','List at least one provider or module.'); return; }
  runCollect({dry:dry, btnId:'tfBtn', showFn:showTfResult, title:'Collecting Terraform providers/modules',
    url:'/admin/terraform/collect', body:applyForce(body,'tfForce'), forceId:'tfForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','item(s)'), d)});
}

async function scheduleTerraform(){
  const body=terraformBody();
  if(!body){ showTfResult('err','List at least one provider or module to schedule.'); return; }
  const refs=body.providers.concat(body.modules);
  createWatch('terraform','Terraform: '+refs.slice(0,3).join(', '), body, 'tfEvery','tfUnit', showTfResult);
}

function showHelmResult(cls, html){
  const el=document.getElementById('helmResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function helmBody(){
  const url=document.getElementById('helmurl').value.trim();
  const charts=linesOf('helmcharts');
  if(!url || !charts.length) return null;
  const body={url:url, charts:charts};
  const name=document.getElementById('helmname').value.trim();
  if(name) body.name=name;
  return body;
}

async function collectHelm(ev, dry){
  ev.preventDefault();
  const body=helmBody();
  if(!body){ showHelmResult('err','Give the repository URL and at least one chart.'); return; }
  runCollect({dry:dry, btnId:'helmBtn', showFn:showHelmResult, title:'Collecting Helm charts',
    url:'/admin/helm/collect', body:applyForce(body,'helmForce'), forceId:'helmForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','chart(s)'), d)});
}

async function scheduleHelm(){
  const body=helmBody();
  if(!body){ showHelmResult('err','Give the repository URL and at least one chart to schedule.'); return; }
  createWatch('helm','Helm: '+body.charts.slice(0,3).join(', '), body, 'helmEvery','helmUnit', showHelmResult);
}

function showNgResult(cls, html){
  const el=document.getElementById('ngResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function nugetBody(){
  const packages=linesOf('ngpkgs');
  if(!packages.length) return null;
  return {packages:packages, resolve_deps:document.getElementById('ngdeps').checked};
}

async function collectNuget(ev, dry){
  ev.preventDefault();
  const body=nugetBody();
  if(!body){ showNgResult('err','List at least one package.'); return; }
  runCollect({dry:dry, btnId:'ngBtn', showFn:showNgResult, title:'Collecting NuGet packages',
    url:'/admin/nuget/collect', body:applyForce(body,'ngForce'), forceId:'ngForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','package(s)'), d)});
}

async function scheduleNuget(){
  const body=nugetBody();
  if(!body){ showNgResult('err','List at least one package to schedule.'); return; }
  createWatch('nuget','NuGet: '+body.packages.slice(0,3).join(', '), body, 'ngEvery','ngUnit', showNgResult);
}

function showApkResult(cls, html){
  const el=document.getElementById('apkResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function apkBody(){
  const body={newest_only:document.getElementById('apknewest').checked};
  const arches=commaList('apkarches');
  if(arches.length) body.architectures=arches;
  const file=document.getElementById('apkreposfile').value.trim();
  if(file){ body.repositories_file=file; return body; }
  const uri=document.getElementById('apkuri').value.trim();
  const branches=commaList('apkbranches');
  if(!uri || !branches.length) return null;
  body.uri=uri;
  body.branches=branches;
  const repos=commaList('apkrepos');
  if(repos.length) body.repositories=repos;
  return body;
}

async function collectApk(ev, dry){
  ev.preventDefault();
  const body=apkBody();
  if(!body){ showApkResult('err','Give the mirror base URL and at least one branch (or paste a repositories file).'); return; }
  runCollect({dry:dry, btnId:'apkBtn', busyLabel:'Mirroring…', showFn:showApkResult, title:'Mirroring Alpine repository',
    url:'/admin/apk/collect', body:applyForce(body,'apkForce'), forceId:'apkForce',
    render:d=>skippedItems(collectedMsg(d,'Mirrored','package(s)'), d)});
}

async function scheduleApk(){
  const body=apkBody();
  if(!body){ showApkResult('err','Give the mirror base URL and at least one branch (or paste a repositories file) to schedule.'); return; }
  const label='Alpine: '+(body.uri||'repositories file');
  createWatch('apk', label, body, 'apkEvery','apkUnit', showApkResult);
}

function showOsvResult(cls, html){
  const el=document.getElementById('osvResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function osvBody(){
  const ecosystems=linesOf('osvecos');
  if(!ecosystems.length) return null;
  return {ecosystems:ecosystems};
}

async function collectOsv(ev, dry){
  ev.preventDefault();
  const body=osvBody();
  if(!body){ showOsvResult('err','List at least one OSV ecosystem name.'); return; }
  runCollect({dry:dry, btnId:'osvBtn', busyLabel:'Mirroring…', showFn:showOsvResult, title:'Mirroring OSV databases',
    url:'/admin/osv/collect', body:applyForce(body,'osvForce'), forceId:'osvForce',
    render:d=>skippedItems(collectedMsg(d,'Mirrored','database(s)'), d)});
}

async function scheduleOsv(){
  const body=osvBody();
  if(!body){ showOsvResult('err','List at least one OSV ecosystem name to schedule.'); return; }
  createWatch('osv','OSV: '+body.ecosystems.slice(0,3).join(', '), body, 'osvEvery','osvUnit', showOsvResult);
}

function showCondaResult(cls, html){
  const el=document.getElementById('condaResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function condaBody(){
  const channel=document.getElementById('condachannel').value.trim();
  const packages=linesOf('condapkgs');
  if(!channel || !packages.length) return null;
  const body={channel:channel, packages:packages};
  const subdirs=commaList('condasubdirs');
  if(subdirs.length) body.subdirs=subdirs;
  return body;
}

async function collectConda(ev, dry){
  ev.preventDefault();
  const body=condaBody();
  if(!body){ showCondaResult('err','Give the channel and at least one package.'); return; }
  runCollect({dry:dry, btnId:'condaBtn', showFn:showCondaResult, title:'Collecting Conda packages',
    url:'/admin/conda/collect', body:applyForce(body,'condaForce'), forceId:'condaForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','package(s)'), d)});
}

async function scheduleConda(){
  const body=condaBody();
  if(!body){ showCondaResult('err','Give the channel and at least one package to schedule.'); return; }
  createWatch('conda','Conda: '+body.packages.slice(0,3).join(', '), body, 'condaEvery','condaUnit', showCondaResult);
}

function showRubygemsResult(cls, html){
  const el=document.getElementById('rubygemsResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function rubygemsBody(){
  const gems=linesOf('rubygemsgems');
  if(!gems.length) return null;
  return {gems:gems};
}

async function collectRubygems(ev, dry){
  ev.preventDefault();
  const body=rubygemsBody();
  if(!body){ showRubygemsResult('err','List at least one gem.'); return; }
  runCollect({dry:dry, btnId:'rubygemsBtn', showFn:showRubygemsResult, title:'Collecting Ruby gems',
    url:'/admin/rubygems/collect', body:applyForce(body,'rubygemsForce'), forceId:'rubygemsForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','gem(s)'), d)});
}

async function scheduleRubygems(){
  const body=rubygemsBody();
  if(!body){ showRubygemsResult('err','List at least one gem to schedule.'); return; }
  createWatch('rubygems','RubyGems: '+body.gems.slice(0,3).join(', '), body, 'rubygemsEvery','rubygemsUnit', showRubygemsResult);
}

function showComposerResult(cls, html){
  const el=document.getElementById('composerResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function composerBody(){
  const packages=linesOf('composerpkgs');
  if(!packages.length) return null;
  return {packages:packages};
}

async function collectComposer(ev, dry){
  ev.preventDefault();
  const body=composerBody();
  if(!body){ showComposerResult('err','List at least one package.'); return; }
  runCollect({dry:dry, btnId:'composerBtn', showFn:showComposerResult, title:'Collecting Composer packages',
    url:'/admin/composer/collect', body:applyForce(body,'composerForce'), forceId:'composerForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','package(s)'), d)});
}

async function scheduleComposer(){
  const body=composerBody();
  if(!body){ showComposerResult('err','List at least one package to schedule.'); return; }
  createWatch('composer','Composer: '+body.packages.slice(0,3).join(', '), body, 'composerEvery','composerUnit', showComposerResult);
}

function showVsxResult(cls, html){
  const el=document.getElementById('vsxResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function vsxBody(){
  const extensions=linesOf('vsxexts');
  if(!extensions.length) return null;
  return {extensions:extensions};
}

async function collectVsx(ev, dry){
  ev.preventDefault();
  const body=vsxBody();
  if(!body){ showVsxResult('err','List at least one extension.'); return; }
  runCollect({dry:dry, btnId:'vsxBtn', showFn:showVsxResult, title:'Collecting VS Code extensions',
    url:'/admin/vsx/collect', body:applyForce(body,'vsxForce'), forceId:'vsxForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','extension(s)'), d)});
}

async function scheduleVsx(){
  const body=vsxBody();
  if(!body){ showVsxResult('err','List at least one extension to schedule.'); return; }
  createWatch('vsx','VS Code: '+body.extensions.slice(0,3).join(', '), body, 'vsxEvery','vsxUnit', showVsxResult);
}

function showGalaxyResult(cls, html){
  const el=document.getElementById('galaxyResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function galaxyBody(){
  const collections=linesOf('galaxycols');
  if(!collections.length) return null;
  return {collections:collections};
}

async function collectGalaxy(ev, dry){
  ev.preventDefault();
  const body=galaxyBody();
  if(!body){ showGalaxyResult('err','List at least one collection.'); return; }
  runCollect({dry:dry, btnId:'galaxyBtn', showFn:showGalaxyResult, title:'Collecting Ansible collections',
    url:'/admin/galaxy/collect', body:applyForce(body,'galaxyForce'), forceId:'galaxyForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','collection(s)'), d)});
}

async function scheduleGalaxy(){
  const body=galaxyBody();
  if(!body){ showGalaxyResult('err','List at least one collection to schedule.'); return; }
  createWatch('galaxy','Ansible: '+body.collections.slice(0,3).join(', '), body, 'galaxyEvery','galaxyUnit', showGalaxyResult);
}

function showCranResult(cls, html){
  const el=document.getElementById('cranResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function cranBody(){
  const packages=linesOf('cranpkgs');
  if(!packages.length) return null;
  return {packages:packages};
}

async function collectCran(ev, dry){
  ev.preventDefault();
  const body=cranBody();
  if(!body){ showCranResult('err','List at least one package.'); return; }
  runCollect({dry:dry, btnId:'cranBtn', showFn:showCranResult, title:'Collecting R packages',
    url:'/admin/cran/collect', body:applyForce(body,'cranForce'), forceId:'cranForce',
    render:d=>skippedItems(collectedMsg(d,'Collected','package(s)'), d)});
}

async function scheduleCran(){
  const body=cranBody();
  if(!body){ showCranResult('err','List at least one package to schedule.'); return; }
  createWatch('cran','CRAN: '+body.packages.slice(0,3).join(', '), body, 'cranEvery','cranUnit', showCranResult);
}

function showGitResult(cls, html){
  const el=document.getElementById('gitResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function gitBody(){
  const url=document.getElementById('giturl').value.trim();
  if(!url) return null;
  const body={url:url};
  const name=document.getElementById('gitname').value.trim();
  if(name) body.name=name;
  const refs=linesOf('gitrefs');
  if(refs.length) body.refs=refs;
  return body;
}

async function collectGit(ev, dry){
  ev.preventDefault();
  const body=gitBody();
  if(!body){ showGitResult('err','Give the repository URL.'); return; }
  runCollect({dry:dry, btnId:'gitBtn', showFn:showGitResult, title:'Mirroring git repository',
    url:'/admin/git/collect', body:applyForce(body,'gitForce'), forceId:'gitForce',
    render:d=>skippedItems(collectedMsg(d,'Mirrored','repository(ies)'), d)});
}

async function scheduleGit(){
  const body=gitBody();
  if(!body){ showGitResult('err','Give the repository URL to schedule.'); return; }
  createWatch('git','Git: '+body.url, body, 'gitEvery','gitUnit', showGitResult);
}

// uploadCollect POSTs multipart form data with XMLHttpRequest instead of the
// NDJSON stream: fetch exposes no upload progress, and streaming a response
// while the browser is still sending the body trips HTTP/1.1's half-duplex
// default (large uploads died as opaque network errors). The modal's progress
// bar is driven from the browser's own upload progress instead, and the
// response is one buffered JSON result.
function uploadCollect(url, fd, signal){
  return new Promise((resolve, reject)=>{
    const abortErr=()=>{ const e=new Error('upload aborted'); e.name='AbortError'; return e; };
    if(signal && signal.aborted){ reject(abortErr()); return; }
    const xhr=new XMLHttpRequest();
    xhr.open('POST', url);
    const started=Date.now();
    const files=fd.getAll('file').length;
    xhr.upload.onprogress=e=>{
      if(!e.lengthComputable) return;
      const secs=Math.max(0.001,(Date.now()-started)/1000);
      updateCollectDl({name:'uploading '+files+' file'+(files===1?'':'s'), done:e.loaded, total:e.total, bps:Math.round(e.loaded/secs)});
    };
    xhr.upload.onload=()=>{ hideCollectDl(); appendCollectLog('Upload received; packing the signed bundle…'); };
    xhr.onload=()=>{
      if(xhr.status>=200 && xhr.status<300){
        try{ resolve(JSON.parse(xhr.responseText||'{}')); }
        catch(_){ reject(new Error('unexpected response from the server')); }
      }else{
        reject(new Error((xhr.responseText||'').trim()||('HTTP '+xhr.status)));
      }
    };
    xhr.onerror=()=>reject(new Error('network error during the upload'));
    xhr.onabort=()=>reject(abortErr());
    if(signal) signal.addEventListener('abort', ()=>xhr.abort(), {once:true});
    xhr.send(fd);
  });
}

function showUpResult(cls, html){
  const el=document.getElementById('upResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

async function collectUploads(ev, dry){
  ev.preventDefault();
  const folder=document.getElementById('upfolder').value.trim();
  const files=document.getElementById('upfiles').files;
  if(!folder){ showUpResult('err','Enter a folder name.'); return; }
  if(!files || !files.length){ showUpResult('err','Pick at least one file.'); return; }
  const fd=new FormData();
  fd.append('folder', folder);
  for(const f of files) fd.append('file', f);
  runCollect({dry:dry, btnId:'upBtn', busyLabel:'Uploading…', showFn:showUpResult, title:'Uploading files',
    url:'/admin/uploads/collect', body:fd,
    render:d=>({cls:'ok', msg:collectedMsg(d,'Uploaded','file(s)')+' They will appear on the high side under <code>/uploads/'+esc(folder)+'/</code>.'})});
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

// ---- Jobs ----
// The Overview's Jobs card lists every queued/running/finished collect across
// all streams and sessions, refreshed by a light poll while the page shows.
// View follows any job's live log in the collect modal; Cancel stops a queued
// or running job.
let jobsTimer=null, jobsCache={};

function pollJobs(on){
  if(on && jobsTimer==null){ jobsTimer=window.setInterval(()=>{ if(!document.hidden) loadJobs(); }, 2500); }
  if(!on && jobsTimer!=null){ window.clearInterval(jobsTimer); jobsTimer=null; }
}

function jobStatePill(j){
  if(j.state==='running') return '<span class="pill busy">running</span>';
  if(j.state==='queued') return '<span class="pill q">queued'+(j.position?' &middot; '+esc(j.position)+' ahead':'')+'</span>';
  if(j.state==='ok') return '<span class="pill ok">ok</span>';
  if(j.state==='canceled') return '<span class="pill q">canceled</span>';
  return '<span class="pill warn">error</span>';
}

// jobDetail is the small line under a job's state pill: live progress while
// running, the success summary, or why it failed.
function jobDetail(j){
  if(j.state==='running'){
    if(j.dl && j.dl.total>0) return esc(j.dl.name)+' &middot; '+Math.min(100,Math.floor(j.dl.done*100/j.dl.total))+'%';
    return j.last_log?esc(j.last_log):'';
  }
  if(j.state==='error') return esc(j.error||'');
  if(j.state==='ok') return esc(j.message||'');
  return '';
}

function fmtDuration(start, end){
  if(!start) return '&mdash;';
  const s=new Date(start).getTime(), e=end?new Date(end).getTime():Date.now();
  if(isNaN(s)) return '&mdash;';
  let sec=Math.max(0,Math.round((e-s)/1000));
  if(sec<60) return sec+'s';
  if(sec<3600) return Math.floor(sec/60)+'m'+String(sec%60).padStart(2,'0')+'s';
  return Math.floor(sec/3600)+'h'+String(Math.floor(sec/60)%60).padStart(2,'0')+'m';
}

function jobRow(j){
  const by=j.requested_by||(j.kind==='watch'?'schedule':'');
  const detail=jobDetail(j);
  const cancel=(j.state==='queued'||j.state==='running')
    ? '<button onclick="cancelJob('+j.id+')">Cancel</button>' : '';
  return '<tr><td>'+esc(streamLabel(j.stream))+'</td>'+
    '<td>'+esc(j.label)+(by?'<br><span class="wmsg">by '+esc(by)+'</span>':'')+'</td>'+
    '<td>'+jobStatePill(j)+(detail?'<br><span class="wmsg">'+detail+'</span>':'')+'</td>'+
    '<td>'+fmtTime(j.started_at||j.created_at)+'</td>'+
    '<td class="num">'+fmtDuration(j.started_at, j.finished_at)+'</td>'+
    '<td class="wactions"><button onclick="viewJobById('+j.id+')">View</button>'+cancel+'</td></tr>';
}

async function loadJobs(){
  const box=document.getElementById('jobsBox');
  if(!box) return;
  try{
    const r=await fetch('/admin/jobs',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const list=(await r.json()).jobs||[];
    jobsCache={};
    for(const j of list) jobsCache[j.id]=j;
    if(!list.length){ box.innerHTML='<p class="empty">No jobs yet. Start a collect on an ecosystem page, or wait for a schedule.</p>'; return; }
    box.innerHTML='<table><thead><tr><th>Stream</th><th>Job</th><th>Status</th>'+
      '<th>Started</th><th class="num">Duration</th><th>Actions</th></tr></thead><tbody>'+
      list.map(jobRow).join('')+'</tbody></table>';
  }catch(e){ box.textContent='Failed to load jobs: '+e.message; }
}

async function cancelJob(id){
  if(!confirm('Cancel this job?')) return;
  try{
    const r=await fetch('/admin/jobs/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    if(!r.ok){ const t=await r.text(); throw new Error((t&&t.trim())||('HTTP '+r.status)); }
  }catch(e){ window.alert('Cancel failed: '+e.message); }
  loadJobs();
}

function viewJobById(id){
  const j=jobsCache[id];
  viewJob(id, j?streamLabel(j.stream)+' — '+j.label:('Job #'+id));
}

// viewJob opens the collect modal following an existing job — anyone's,
// running or finished — via /admin/jobs/follow.
function viewJob(id, title){
  openCollectModal(title);
  noteCollectJob(id); // known up front: Stop cancels, Close detaches
  void (async()=>{
    try{
      const res=await fetch('/admin/jobs/follow?id='+encodeURIComponent(id),{signal:cmAbort.signal,cache:'no-store'});
      if(!res.ok || !res.body){
        const t=await res.text().catch(()=>''); throw new Error((t&&t.trim())||('HTTP '+res.status));
      }
      const d=await consumeCollectStream(res);
      let out=(d && d.skipped)
        ? {cls:'ok', msg:'&#10003; No new content since the last export &mdash; nothing to send across the diode.'}
        : {cls:'ok', msg:(d && d.bundle_id)?collectedMsg(d,'Collected','unit(s)'):'&#10003; Job finished.'};
      if(d && d.diode_error){
        out={cls:'warn', msg:out.msg+'<br>&#9888; Diode upload failed: '+esc(d.diode_error)+' &mdash; the bundle is archived and still staged; re-transmit it from the Status page.'};
      }
      finishCollectModal(out.cls, out.msg);
    }catch(e){
      if(e && e.name==='AbortError' && cmDetached){
        finishCollectModal('warn','Stopped following; the job continues.');
        closeCollectModal();
      }else if(e && e.message==='collect canceled'){
        finishCollectModal('warn','&#9632; Job canceled.');
      }else if(e && e.name!=='AbortError'){
        finishCollectModal('err','Error: '+esc(e.message));
      }
    }finally{ loadJobs(); }
  })();
}

// ---- Schedules (watches) ----
// Each ecosystem page schedules a recurring collect from its own inputs, so the
// spec built here is exactly what that page's collect button would POST.
const WATCH_CONTAINERS={go:'goWatches',python:'pyWatches',maven:'mvnWatches',npm:'npmWatches',apt:'aptWatches',rpm:'rpmWatches',containers:'ctrWatches',hf:'hfWatches',crates:'crWatches',terraform:'tfWatches',helm:'helmWatches',nuget:'ngWatches',apk:'apkWatches',conda:'condaWatches',rubygems:'rubygemsWatches',composer:'composerWatches',vsx:'vsxWatches',galaxy:'galaxyWatches',cran:'cranWatches',git:'gitWatches',osv:'osvWatches'};
const WATCH_SHOW={go:showGoResult,python:showPyResult,maven:showMvnResult,npm:showNpmResult,apt:showAptResult,rpm:showRpmResult,containers:showCtrResult,hf:showHFResult,crates:showCrResult,terraform:showTfResult,helm:showHelmResult,nuget:showNgResult,apk:showApkResult,conda:showCondaResult,rubygems:showRubygemsResult,composer:showComposerResult,vsx:showVsxResult,galaxy:showGalaxyResult,cran:showCranResult,git:showGitResult,osv:showOsvResult};

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
    '<button onclick="editWatch('+wt.id+')">Edit</button>'+
    toggle+'<button onclick="watchAction(\'delete\','+wt.id+',\''+wt.stream+'\')">Delete</button></td></tr>';
}

// watchesCache remembers each rendered watch by id (across both views), so the
// Edit dialog can prefill from the row that was clicked without refetching.
let watchesCache={};
function cacheWatches(list){ for(const w of list) watchesCache[w.id]=w; }

// loadWatchesInto renders the schedules for one stream into that ecosystem's
// page (blank when the stream has none).
async function loadWatchesInto(stream){
  const box=document.getElementById(WATCH_CONTAINERS[stream]);
  if(!box) return;
  try{
    const r=await fetch('/admin/watches',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const all=(await r.json()).watches||[];
    cacheWatches(all);
    const list=all.filter(w=>w.stream===stream);
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
    cacheWatches(list);
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
    if(action==='run'){
      const d=await r.json().catch(()=>({}));
      show('ok', d && d.job_id
        ? '&#10003; Run queued as job #'+esc(d.job_id)+' &mdash; follow it under Jobs on the Overview page.'
        : '&#10003; A run for this schedule is already queued or running &mdash; see Jobs on the Overview page.');
      loadJobs();
    }
    loadWatchesInto(stream);
    loadAllWatches();
  }catch(e){ show('err','Request failed: '+esc(e.message)); }
}

// ---- Edit schedule dialog ----
// Edit opens a schedule in a small dialog: label, interval, and the stored
// collect spec as pretty-printed JSON. Saving POSTs /admin/watches/update.
// The stream is fixed at creation, and a run already queued or running keeps
// the spec it was enqueued with — edits apply from the next run.
let weWatch=null;

function showWeResult(cls, html){
  const el=document.getElementById('weResult');
  el.className='rbox '+cls;
  el.innerHTML=html;
}

function editWatch(id){
  const wt=watchesCache[id];
  if(!wt) return;
  weWatch=wt;
  document.getElementById('weStream').textContent=streamLabel(wt.stream)+' schedule #'+wt.id+
    ' — the stream is fixed; changes apply from the next run.';
  document.getElementById('weLabel').value=wt.label||'';
  // Prefill the interval in the largest unit that divides it exactly, the same
  // way the tables render it (an odd API-created interval falls back to minutes).
  const sec=Number(wt.interval_seconds)||0;
  const unit=(sec>0 && sec%86400===0)?86400:(sec>0 && sec%3600===0)?3600:60;
  document.getElementById('weUnit').value=String(unit);
  document.getElementById('weEvery').value=String(Math.max(1,Math.round(sec/unit)));
  let spec=wt.spec||'';
  try{ spec=JSON.stringify(JSON.parse(spec),null,2); }catch(_){ /* show the stored text as-is */ }
  document.getElementById('weSpec').value=spec;
  clearResult('weResult');
  document.getElementById('watchEditModal').showModal();
}

function closeWatchEdit(){ document.getElementById('watchEditModal').close(); }

async function saveWatchEdit(ev){
  ev.preventDefault();
  if(!weWatch) return;
  const sec=intervalSeconds('weEvery','weUnit');
  if(!sec){ showWeResult('err','Enter a positive schedule interval.'); return; }
  let spec;
  try{ spec=JSON.parse(document.getElementById('weSpec').value); }
  catch(e){ showWeResult('err','The spec is not valid JSON: '+esc(e.message)); return; }
  if(!spec || typeof spec!=='object' || Array.isArray(spec)){ showWeResult('err','The spec must be a JSON object, like the collect body it replays.'); return; }
  const btn=document.getElementById('weSave');
  btn.disabled=true;
  try{
    const r=await fetch('/admin/watches/update',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({id:weWatch.id, label:document.getElementById('weLabel').value.trim(), interval_seconds:sec, spec:spec})});
    if(!r.ok){ const t=await r.text(); showWeResult('err','Error: '+esc(t.trim())); return; }
    const stream=weWatch.stream;
    closeWatchEdit();
    (WATCH_SHOW[stream]||function(){})('ok','&#10003; Schedule updated.');
    loadWatchesInto(stream);
    loadAllWatches();
  }catch(e){ showWeResult('err','Request failed: '+esc(e.message)); }
  finally{ btn.disabled=false; }
}

// Block Esc/backdrop dismissal while a collect is still streaming.
document.getElementById('collectModal').addEventListener('cancel', e=>{ if(cmRunning) e.preventDefault(); });

loadStatus();
loadAllWatches();
loadJobs();
pollJobs(true); // the initial view is the Overview
</script>
</body>
</html>
`
