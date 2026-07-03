package main

// High-side dashboard UI. A single self-contained HTML page (no external assets,
// so it works air-gapped) served at "/", backed by a JSON overview endpoint. It
// shows import status — prominently flagging any missing bundles — and a tree of
// every mirrored Go module and Python project.

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// UIOverview is the payload rendered by the dashboard.
type UIOverview struct {
	Status ImportStatus `json:"status"`
	Go     []UIModule   `json:"go"`
	Python []UIProject  `json:"python"`
}

type UIModule struct {
	Module   string   `json:"module"`
	Versions []string `json:"versions"`
}

type UIProject struct {
	Project string     `json:"project"`
	Files   []UIPyFile `json:"files"`
}

type UIPyFile struct {
	Filename string `json:"filename"`
	Version  string `json:"version"`
}

func (s *HighServer) serveUI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/", "/ui", "/ui/":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		writeHTML(w, uiHTML)
	case "/ui/api/overview":
		if !isReadMethod(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		s.handleUIOverview(w)
	default:
		return false
	}
	return true
}

func isReadMethod(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

func (s *HighServer) handleUIOverview(w http.ResponseWriter) {
	status, err := s.ImportStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	goMods, err := s.listGoModules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pyProjects, err := s.listPythonProjects()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, UIOverview{Status: status, Go: goMods, Python: pyProjects})
}

// listGoModules walks the module cache and returns every module that has at
// least one complete version, with its versions sorted ascending.
func (s *HighServer) listGoModules() ([]UIModule, error) {
	var mods []UIModule
	err := filepath.WalkDir(s.downloadDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || d.Name() != "@v" {
			return nil
		}
		rel, relErr := filepath.Rel(s.downloadDir, filepath.Dir(p))
		if relErr != nil {
			return nil
		}
		moduleEsc := filepath.ToSlash(rel)
		if moduleEsc == "python" || strings.HasPrefix(moduleEsc, "python/") {
			return filepath.SkipDir
		}
		if mod, ok := s.goModuleAt(moduleEsc); ok {
			mods = append(mods, mod)
		}
		return filepath.SkipDir
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Module < mods[j].Module })
	return mods, nil
}

func (s *HighServer) goModuleAt(moduleEsc string) (UIModule, bool) {
	versions, err := s.completeVersions(moduleEsc)
	if err != nil || len(versions) == 0 {
		return UIModule{}, false
	}
	module, err := unescapeModulePath(moduleEsc)
	if err != nil {
		return UIModule{}, false
	}
	sortVersionsAsc(versions)
	return UIModule{Module: module, Versions: versions}, true
}

// listPythonProjects groups the mirrored wheels by normalized project name.
func (s *HighServer) listPythonProjects() ([]UIProject, error) {
	files, err := s.scanPyFiles()
	if err != nil {
		return nil, err
	}
	byProject := map[string][]UIPyFile{}
	var order []string
	for _, f := range files {
		if _, ok := byProject[f.project]; !ok {
			order = append(order, f.project)
		}
		byProject[f.project] = append(byProject[f.project], UIPyFile{Filename: f.filename, Version: f.version})
	}
	sort.Strings(order)

	projects := make([]UIProject, 0, len(order))
	for _, name := range order {
		fs := byProject[name]
		sort.Slice(fs, func(i, j int) bool { return fs[i].Filename < fs[j].Filename })
		projects = append(projects, UIProject{Project: name, Files: fs})
	}
	return projects, nil
}

const uiHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ArtiGate</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }
  header { padding: 1rem 1.5rem; background: #161a22; border-bottom: 1px solid #2a2f3a; display: flex; align-items: center; gap: 1rem; }
  header h1 { font-size: 1.25rem; margin: 0; }
  header button { margin-left: auto; background: #2a2f3a; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px; padding: .4rem .8rem; cursor: pointer; }
  main { padding: 1.5rem; }
  .banner { padding: .9rem 1.1rem; border-radius: 8px; margin-bottom: 1.5rem; font-weight: 600; }
  .banner.ok { background: #10281a; border: 1px solid #1f6f43; color: #7ee2a8; }
  .banner.warn { background: #2e1416; border: 1px solid #7f2a30; color: #ff9ea3; }
  .meta { display: flex; flex-wrap: wrap; gap: 1.25rem; margin-bottom: 1.75rem; font-size: .9rem; color: #a9b2c3; }
  .meta b { color: #e6e6e6; }
  .cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
  section h2 { font-size: 1rem; border-bottom: 1px solid #2a2f3a; padding-bottom: .4rem; }
  details { background: #161a22; border: 1px solid #2a2f3a; border-radius: 6px; margin: .35rem 0; padding: .1rem .6rem; }
  summary { cursor: pointer; padding: .45rem .1rem; font-weight: 600; }
  summary .count { color: #8b93a5; font-weight: 400; font-size: .85rem; margin-left: .4rem; }
  ul { margin: .2rem 0 .6rem 1.1rem; padding: 0; list-style: none; }
  li { padding: .15rem 0; font-family: ui-monospace, monospace; font-size: .85rem; color: #c7cedb; }
  .empty { color: #8b93a5; font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>ArtiGate <span style="color:#8b93a5;font-weight:400">high-side repository</span></h1>
  <button onclick="load()">Refresh</button>
</header>
<main>
  <div id="banner" class="banner">Loading…</div>
  <div id="meta" class="meta"></div>
  <div class="cols">
    <section><h2>Go modules <span id="goCount" class="count"></span></h2><div id="go"></div></section>
    <section><h2>Python packages <span id="pyCount" class="count"></span></h2><div id="python"></div></section>
  </div>
</main>
<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

function renderStatus(s){
  const banner=document.getElementById('banner');
  const missing=s.missing_ranges||[];
  const quar=s.quarantined_sequences||[];
  if(missing.length){
    banner.className='banner warn';
    banner.innerHTML='&#9888; Missing bundles: '+esc(missing.join(', '))+
      ' &mdash; the repository is waiting for these before it can advance past #'+esc(s.next_expected_sequence);
  } else {
    banner.className='banner ok';
    banner.textContent='✓ All bundles imported through #'+s.last_imported_sequence;
  }
  document.getElementById('meta').innerHTML=
    '<span>Last imported: <b>#'+esc(s.last_imported_sequence)+'</b></span>'+
    '<span>Next expected: <b>#'+esc(s.next_expected_sequence)+'</b></span>'+
    '<span>Highest seen: <b>#'+esc(s.highest_seen_sequence)+'</b></span>'+
    '<span>Quarantined: <b>'+(quar.length?esc(quar.join(', ')):'none')+'</b></span>';
}

function tree(container, items, title){
  const el=document.getElementById(container);
  if(!items.length){el.innerHTML='<p class="empty">none</p>';return;}
  el.innerHTML=items.map(it=>{
    const name=esc(it.name);
    const rows=it.children.map(c=>'<li>'+esc(c)+'</li>').join('');
    return '<details><summary>'+name+'<span class="count">'+it.children.length+' '+title+'</span></summary><ul>'+rows+'</ul></details>';
  }).join('');
}

async function load(){
  try{
    const r=await fetch('/ui/api/overview',{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    renderStatus(d.status||{});
    const go=(d.go||[]).map(m=>({name:m.module, children:(m.versions||[])}));
    const py=(d.python||[]).map(p=>({name:p.project, children:(p.files||[]).map(f=>f.filename)}));
    document.getElementById('goCount').textContent=go.length+' modules';
    document.getElementById('pyCount').textContent=py.length+' projects';
    tree('go', go, 'versions');
    tree('python', py, 'files');
  }catch(e){
    document.getElementById('banner').className='banner warn';
    document.getElementById('banner').textContent='Failed to load overview: '+e.message;
  }
}
load();
</script>
</body>
</html>
`
