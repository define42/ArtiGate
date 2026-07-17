"use strict";
// High-side dashboard. The import status is fetched once; the package trees are
// loaded lazily, one level at a time, from /ui/api/tree. Expanding a node fetches
// only that node's immediate children, so nothing large is transferred or
// rendered up front. The sidebar switches between the per-ecosystem trees, and
// the header's search box finds packages across every ecosystem at once
// (/ui/api/search) — hits are ordinary tree nodes, expanded and selected
// exactly like nodes browsed to by hand.
const VIEW_TITLES = {
    overview: "Overview",
    go: "Go modules",
    python: "Python packages",
    maven: "Maven artifacts",
    npm: "NPM packages",
    apt: "APT packages",
    rpm: "RPM packages",
    containers: "Container images",
    hf: "AI models (Hugging Face)",
    crates: "Rust crates",
    terraform: "Terraform providers & modules",
    helm: "Helm charts",
    nuget: "NuGet packages",
    apk: "Alpine packages",
    conda: "Conda packages",
    rubygems: "Ruby gems",
    composer: "PHP Composer packages",
    vsx: "VS Code extensions",
    galaxy: "Ansible collections",
    cran: "R packages (CRAN)",
    git: "Git repositories",
    osv: "OSV advisories",
    uploads: "Uploaded files",
};
let currentView = "overview";
let selectedLeaf = null;
// True while the header search box owns the tree panel; currentView keeps the
// view the sidebar has selected, so clearing the search restores it.
let searchActive = false;
let searchTimer = 0;
function esc(value) {
    const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    };
    return String(value).replace(/[&<>"']/g, (c) => map[c] ?? c);
}
function byId(id) {
    const el = document.getElementById(id);
    if (!el) {
        throw new Error(`missing element #${id}`);
    }
    return el;
}
function unitFor(kind) {
    switch (kind) {
        case "dir":
            return "packages";
        case "module":
            return "versions";
        case "project":
            return "files";
        default:
            return "";
    }
}
const STREAM_LABELS = {
    go: "Go",
    python: "Python",
    maven: "Maven",
    npm: "NPM",
    apt: "APT",
    rpm: "RPM",
    containers: "Containers",
    hf: "AI Models",
    crates: "Crates",
    terraform: "Terraform",
    helm: "Helm",
    nuget: "NuGet",
    apk: "Alpine",
    conda: "Conda",
    rubygems: "RubyGems",
    composer: "Composer",
    vsx: "VS Code",
    galaxy: "Ansible",
    cran: "CRAN",
    git: "Git",
    osv: "OSV",
    uploads: "Uploads",
};
function streamLabel(name) {
    return STREAM_LABELS[name] ?? name;
}
function renderStatus(status) {
    const banner = byId("banner");
    const streams = status.streams ?? [];
    const blocked = streams.filter((s) => (s.missing_ranges ?? []).length > 0);
    const awaiting = streams.filter((s) => (s.awaiting_from_low ?? []).length > 0);
    if (streams.length === 0) {
        banner.className = "banner ok";
        banner.textContent = "No bundles imported yet.";
    }
    else if (blocked.length > 0) {
        banner.className = "banner warn";
        const names = blocked.map((s) => streamLabel(s.stream)).join(", ");
        banner.innerHTML =
            `&#9888; Waiting on missing bundles in: ${esc(names)} ` +
                "&mdash; those streams pause until the gaps arrive; the rest keep importing independently.";
    }
    else if (awaiting.length > 0) {
        banner.className = "banner ok";
        const names = awaiting.map((s) => streamLabel(s.stream)).join(", ");
        banner.innerHTML =
            `&#10003; No gaps. Awaiting bundles from the low side in: ${esc(names)} ` +
                "&mdash; still crossing the diode, or lost and needing a low-side re-export.";
    }
    else {
        banner.className = "banner ok";
        banner.textContent = "✓ All streams up to date.";
    }
    renderHeartbeat(status.diode_heartbeat);
    renderStreamTable(streams);
}
// HEARTBEAT_STALE_SECONDS is when a once-seen heartbeat counts as overdue: ten
// default broadcast intervals — a dark diode link or a stopped low side.
const HEARTBEAT_STALE_SECONDS = 300;
function formatAge(seconds) {
    if (seconds < 90) {
        return `${seconds}s`;
    }
    if (seconds < 90 * 60) {
        return `${Math.round(seconds / 60)}m`;
    }
    return `${Math.round(seconds / 3600)}h`;
}
// renderHeartbeat shows when the low side last reported its stream indexes
// over the built-in UDP diode. Hidden until a heartbeat has been received, so
// folder/HTTP deployments (which never produce one) see nothing.
function renderHeartbeat(hb) {
    const el = byId("heartbeat");
    if (!hb) {
        el.hidden = true;
        el.textContent = "";
        return;
    }
    el.hidden = false;
    const stale = hb.age_seconds > HEARTBEAT_STALE_SECONDS;
    el.className = stale ? "heartbeat warn" : "heartbeat";
    const version = hb.low_version ? ` (low side ${hb.low_version})` : "";
    el.textContent = stale
        ? `⚠ No diode heartbeat for ${formatAge(hb.age_seconds)}${version} — check the diode link and the low side.`
        : `Diode heartbeat: ${formatAge(hb.age_seconds)} ago${version}.`;
}
// streamPill summarizes one stream: a gap blocks importing (warn); bundles the
// heartbeat says are still on their way are expected traffic (info); otherwise
// the stream is current.
function streamPill(s) {
    if ((s.missing_ranges ?? []).length > 0) {
        return '<span class="pill warn">waiting</span>';
    }
    if ((s.awaiting_from_low ?? []).length > 0) {
        return '<span class="pill info">receiving</span>';
    }
    return '<span class="pill ok">up to date</span>';
}
function streamRow(s) {
    const missing = s.missing_ranges ?? [];
    const awaiting = s.awaiting_from_low ?? [];
    const quarantined = s.quarantined_sequences ?? [];
    const lowAt = s.low_last_sequence ? `#${esc(s.low_last_sequence)}` : "&mdash;";
    return ("<tr>" +
        `<td class="s-name">${esc(streamLabel(s.stream))}</td>` +
        `<td>#${esc(s.last_imported_sequence)}</td>` +
        `<td>#${esc(s.next_expected_sequence)}</td>` +
        `<td>${lowAt}</td>` +
        `<td>${missing.length ? esc(missing.join(", ")) : "&mdash;"}</td>` +
        `<td>${awaiting.length ? esc(awaiting.join(", ")) : "&mdash;"}</td>` +
        `<td>${quarantined.length ? esc(quarantined.join(", ")) : "&mdash;"}</td>` +
        `<td>${streamPill(s)}</td>` +
        "</tr>");
}
function renderStreamTable(streams) {
    const meta = byId("meta");
    if (streams.length === 0) {
        meta.innerHTML = "";
        return;
    }
    meta.innerHTML =
        '<table class="streams"><thead><tr>' +
            "<th>Stream</th><th>Last imported</th><th>Next expected</th>" +
            '<th title="Newest bundle the low side reports exported (diode heartbeat)">Low side</th>' +
            "<th>Missing</th>" +
            '<th title="Exported by the low side but not arrived here yet">Awaiting</th>' +
            "<th>Quarantined</th><th>Status</th>" +
            "</tr></thead><tbody>" +
            streams.map(streamRow).join("") +
            "</tbody></table>";
}
async function fetchChildren(view, path) {
    const url = `/ui/api/tree?eco=${encodeURIComponent(view)}&path=${encodeURIComponent(path)}`;
    const resp = await fetch(url, { cache: "no-store" });
    if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
    }
    const data = (await resp.json());
    return data.nodes ?? [];
}
function setMessage(container, text) {
    container.textContent = "";
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = text;
    container.appendChild(p);
}
// renderNodes renders a level of the tree. eco is the ecosystem the nodes
// belong to — the current view for browsed trees, the hit's own ecosystem for
// search results — so lazy expansion and the detail panel query the right one.
// repoEco is set for the APT/RPM views, where the nodes named by repoGuideRef
// carry their own "Set me up" button.
function renderNodes(container, nodes, eco, repoEco) {
    container.textContent = "";
    if (nodes.length === 0) {
        setMessage(container, "empty");
        return;
    }
    for (const node of nodes) {
        container.appendChild(node.expandable ? expandableNode(node, eco, repoEco) : leafNode(node, eco));
    }
}
// repoGuideRef returns the openRepoGuide target when a tree node should carry
// a "Set me up" button. RPM repositories are the top-level nodes. An APT setup
// is pinned to a component node (mirror/suite/component): where the user
// clicked already decides the release and the channel, so the guide needs no
// further choices.
function repoGuideRef(eco, node) {
    const depth = node.path.split("/").length;
    if (eco === "apt") {
        return depth === 3 ? node.path : null;
    }
    return depth === 1 ? node.path : null;
}
function leafNode(node, eco) {
    const div = document.createElement("div");
    div.className = "leaf";
    div.textContent = node.label;
    div.tabIndex = 0;
    div.setAttribute("role", "button");
    div.addEventListener("click", () => void selectLeaf(div, node, eco));
    div.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            void selectLeaf(div, node, eco);
        }
    });
    return div;
}
function renderDetail(detail) {
    const panel = byId("detail");
    panel.textContent = "";
    const title = document.createElement("h3");
    title.textContent = detail.title;
    panel.appendChild(title);
    if (detail.subtitle) {
        const sub = document.createElement("div");
        sub.className = "subtitle";
        sub.textContent = detail.subtitle;
        panel.appendChild(sub);
    }
    // A full, host-qualified pull reference (containers) as a prominent
    // click-to-copy button, right under the title.
    if (detail.copy_ref) {
        panel.appendChild(copyRefButton(`${window.location.host}/${detail.copy_ref}`));
    }
    const dl = document.createElement("dl");
    for (const field of detail.fields ?? []) {
        const dt = document.createElement("dt");
        dt.textContent = field.label;
        const dd = document.createElement("dd");
        dd.textContent = field.value;
        if (field.mono) {
            dd.className = "mono";
        }
        dl.appendChild(dt);
        dl.appendChild(dd);
    }
    panel.appendChild(dl);
    // A git mirror's full, host-qualified clone command as a copyable code block.
    // The server sends only the host-relative path; the origin (scheme and host)
    // is known only client-side, so any reverse proxy is honored. encodePath
    // percent-encodes the mirror-name segment — a name may hold URL-reserved
    // characters ("#", "?", space, "%") that would otherwise break the URL git
    // requests (fragment, query, shell split) — matching the download links.
    if (detail.clone_url) {
        panel.appendChild(codeBlock({ label: "Clone", code: `git clone ${serverBase()}/${encodePath(detail.clone_url)}` }));
    }
    const downloads = detail.downloads ?? [];
    if (downloads.length > 0) {
        panel.appendChild(downloadRow(downloads));
    }
    if (detail.go_mod) {
        const label = document.createElement("div");
        label.className = "subtitle";
        label.style.margin = ".9rem 0 .3rem";
        label.textContent = "go.mod";
        const pre = document.createElement("pre");
        pre.textContent = detail.go_mod;
        panel.appendChild(label);
        panel.appendChild(pre);
    }
    renderLayers(detail.layers ?? []);
}
// renderLayers fills the box below the detail panel with a container image's
// build history: one numbered step per config-history entry, showing the
// command it ran and (for filesystem layers) the layer size and short digest.
// Hidden when the selection has no layers (every non-container leaf).
function renderLayers(layers) {
    const box = byId("layers");
    box.textContent = "";
    if (layers.length === 0) {
        box.hidden = true;
        return;
    }
    box.hidden = false;
    const heading = document.createElement("h3");
    heading.textContent = "Layers";
    box.appendChild(heading);
    const fsCount = layers.filter((l) => !l.empty).length;
    const sub = document.createElement("p");
    sub.className = "layers-sub";
    sub.textContent = `${layers.length} build steps · ${fsCount} filesystem layer${fsCount === 1 ? "" : "s"} (sizes are compressed)`;
    box.appendChild(sub);
    const list = document.createElement("ol");
    list.className = "layer-list";
    for (const layer of layers) {
        list.appendChild(layerRow(layer));
    }
    box.appendChild(list);
}
function layerRow(layer) {
    const li = document.createElement("li");
    if (layer.empty) {
        li.classList.add("meta");
    }
    const cmd = document.createElement("code");
    cmd.className = "layer-cmd";
    cmd.textContent = layer.command;
    li.appendChild(cmd);
    const meta = document.createElement("div");
    meta.className = "layer-meta";
    if (layer.empty || !layer.size) {
        meta.textContent = "no filesystem layer";
    }
    else {
        const sz = document.createElement("span");
        sz.className = "sz";
        sz.textContent = layer.size;
        meta.appendChild(sz);
        if (layer.digest) {
            meta.appendChild(document.createTextNode(` · ${shortDigest(layer.digest)}`));
        }
    }
    li.appendChild(meta);
    return li;
}
// shortDigest abbreviates a "sha256:<64 hex>" digest to its first 12 hex chars.
function shortDigest(digest) {
    const hex = digest.replace(/^sha256:/, "");
    return `sha256:${hex.slice(0, 12)}`;
}
// copyRefButton renders a prominent click-to-copy control for a full,
// host-qualified image reference — exactly what `docker pull` / `podman pull`
// takes. Clicking anywhere on it copies the reference; only the "Copy" tag
// flashes so the reference text stays visible.
function copyRefButton(ref) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-ref";
    btn.title = "Copy the full image reference for this host";
    const text = document.createElement("span");
    text.className = "copy-ref-text";
    text.textContent = ref;
    const tag = document.createElement("span");
    tag.className = "copy-ref-tag";
    tag.textContent = "Copy";
    btn.appendChild(text);
    btn.appendChild(tag);
    btn.addEventListener("click", () => {
        void (async () => {
            try {
                if (!navigator.clipboard) {
                    throw new Error("clipboard unavailable");
                }
                await navigator.clipboard.writeText(ref);
                flashButton(tag, "Copied ✓");
            }
            catch {
                selectText(text); // insecure context: let the user copy manually
                flashButton(tag, "Press Ctrl+C");
            }
        })();
    });
    return btn;
}
// encodePath percent-encodes each segment of a host-relative artifact path,
// keeping the "/" separators. Mirrored names can contain characters that are
// not URL-safe as-is (npm scopes start with "@", wheel build tags carry "+"),
// so a served path is never usable as a raw href.
function encodePath(p) {
    return p.split("/").map(encodeURIComponent).join("/");
}
// downloadRow renders the artifact's files as direct-download buttons, one per
// file — an APT/RPM version can carry one file per architecture, a Maven
// version a jar plus its pom. The download attribute names the saved file and
// keeps the browser from displaying text-like artifacts (a .pom, a .mod)
// instead of saving them.
function downloadRow(links) {
    const row = document.createElement("div");
    row.className = "downloads";
    for (const link of links) {
        const a = document.createElement("a");
        a.className = "download-link";
        a.href = encodePath(link.url);
        a.setAttribute("download", link.label);
        a.textContent = `↓ ${link.label}`;
        row.appendChild(a);
    }
    return row;
}
async function selectLeaf(el, node, eco) {
    if (selectedLeaf) {
        selectedLeaf.classList.remove("selected");
    }
    selectedLeaf = el;
    el.classList.add("selected");
    const panel = byId("detail");
    setMessage(panel, "loading…");
    hideLayers();
    try {
        const url = `/ui/api/detail?eco=${encodeURIComponent(eco)}&path=${encodeURIComponent(node.path)}`;
        const resp = await fetch(url, { cache: "no-store" });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        renderDetail((await resp.json()));
        if (eco === "uploads") {
            panel.appendChild(uploadActions(node.path));
        }
    }
    catch (err) {
        setMessage(panel, `Failed to load details: ${err.message}`);
    }
}
// splitUploadPath splits a tree path "folder/name" into its two parts.
function splitUploadPath(path) {
    const i = path.indexOf("/");
    if (i <= 0 || i === path.length - 1) {
        return ["", ""];
    }
    return [path.slice(0, i), path.slice(i + 1)];
}
// uploadActions is the action row under an uploaded file's details: the
// delete button. (The download button comes from the detail's downloads row,
// like every other ecosystem.) Uploaded files are the one deletable kind of
// content — operator-owned, not a mirrored artifact some client build depends
// on staying immutable.
function uploadActions(treePath) {
    const row = document.createElement("div");
    row.className = "upload-actions";
    row.appendChild(uploadDeleteButton(treePath));
    return row;
}
// uploadDeleteButton removes one uploaded file from the repository, after a
// confirmation. The tree reloads afterwards, so an emptied folder disappears
// with its last file; the low side can bring a file back by uploading again.
function uploadDeleteButton(treePath) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "delete-upload";
    btn.textContent = "Delete this file";
    btn.addEventListener("click", () => {
        void (async () => {
            const [folder, name] = splitUploadPath(treePath);
            if (!folder || !name || !window.confirm(`Delete ${folder}/${name} from this server?`)) {
                return;
            }
            btn.disabled = true;
            try {
                const resp = await fetch("/admin/uploads/delete", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ folder, name }),
                });
                if (!resp.ok) {
                    throw new Error((await resp.text()).trim() || `HTTP ${resp.status}`);
                }
                await reloadContent(); // re-renders the tree (or search) and clears the detail panel
            }
            catch (err) {
                btn.disabled = false;
                btn.textContent = `Delete failed: ${err.message}`;
            }
        })();
    });
    return btn;
}
// hideLayers clears and hides the layers box (no selection, a non-container
// leaf, or a failed load).
function hideLayers() {
    const box = document.getElementById("layers");
    if (box) {
        box.hidden = true;
        box.textContent = "";
    }
}
function clearDetail() {
    selectedLeaf = null;
    setMessage(byId("detail"), "Select a version to see its details.");
    hideLayers();
}
// repoGuideButton is the per-repository "Set me up" button shown on an RPM
// repository node or an APT component node; it opens the guide pinned to
// exactly that target.
function repoGuideButton(eco, repoRef) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "guide-toggle repo-guide";
    btn.textContent = "Set me up";
    btn.addEventListener("click", (ev) => {
        ev.preventDefault(); // don't toggle the enclosing <details>
        ev.stopPropagation();
        void openRepoGuide(eco, repoRef);
    });
    return btn;
}
function expandableNode(node, eco, repoEco) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = node.label;
    const unit = unitFor(node.kind);
    if (node.count && unit) {
        const count = document.createElement("span");
        count.className = "count";
        count.textContent = `${node.count} ${unit}`;
        summary.appendChild(count);
    }
    const guideRef = repoEco ? repoGuideRef(repoEco, node) : null;
    if (repoEco && guideRef) {
        summary.appendChild(repoGuideButton(repoEco, guideRef));
    }
    details.appendChild(summary);
    const children = document.createElement("div");
    children.className = "children";
    details.appendChild(children);
    let loaded = false;
    details.addEventListener("toggle", () => {
        if (!details.open || loaded) {
            return;
        }
        loaded = true;
        setMessage(children, "loading…");
        fetchChildren(eco, node.path)
            .then((child) => renderNodes(children, child, eco, repoEco))
            .catch((err) => {
            loaded = false; // allow retry on next open
            setMessage(children, `failed to load: ${err.message}`);
        });
    });
    return details;
}
function menuButtons() {
    return document.querySelectorAll("nav button[data-view]");
}
async function loadTree() {
    const tree = byId("tree");
    byId("treeTitle").textContent = VIEW_TITLES[currentView];
    // APT/RPM set up per repository, so the top "Set me up" button is hidden:
    // RPM repo nodes and APT component nodes carry their own instead.
    // (Containers group by upstream registry at the top level, so they keep the
    // whole-ecosystem button.) Uploads need no client setup at all — each file's
    // detail panel shows its plain download URL.
    const perRepo = currentView === "apt" || currentView === "rpm";
    byId("guideBtn").hidden = perRepo || currentView === "uploads";
    clearDetail();
    setMessage(tree, "loading…");
    try {
        const nodes = await fetchChildren(currentView, "");
        renderNodes(tree, nodes, currentView, perRepo ? currentView : undefined);
    }
    catch (err) {
        setMessage(tree, `Failed to load tree: ${err.message}`);
    }
}
// applyView shows a view unconditionally: setView skips the work when the
// view is already showing, but leaving search must re-render it either way.
function applyView(view) {
    currentView = view;
    menuButtons().forEach((btn) => {
        btn.classList.toggle("active", btn.dataset["view"] === view);
    });
    // The Overview page carries the import-status table; the ecosystem views carry
    // the package tree.
    const overview = view === "overview";
    byId("view-overview").hidden = !overview;
    byId("view-tree").hidden = overview;
    if (overview) {
        void loadStatus();
    }
    else {
        void loadTree();
    }
}
function setView(view) {
    const leavingSearch = searchActive;
    clearSearchBox(); // also cancels a pending debounce so it can't hijack the new view
    if (view === currentView && !leavingSearch) {
        return;
    }
    applyView(view);
}
async function loadStatus() {
    try {
        const resp = await fetch("/ui/api/overview", { cache: "no-store" });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        const overview = (await resp.json());
        renderStatus(overview.status);
    }
    catch (err) {
        const banner = byId("banner");
        banner.className = "banner warn";
        banner.textContent = `Failed to load status: ${err.message}`;
    }
}
function refresh() {
    void loadStatus();
    if (searchActive) {
        void runSearch(searchBox().value.trim());
    }
    else if (currentView !== "overview") {
        void loadTree();
    }
}
// reloadContent re-renders whatever owns the tree panel — the search results
// or the current view's tree — after a mutation (an upload delete).
function reloadContent() {
    return searchActive ? runSearch(searchBox().value.trim()) : loadTree();
}
// ---------------------------------------------------------------------------
// Cross-ecosystem package search. Typing in the header box (debounced)
// replaces the tree panel with matches from every ecosystem at once; the hits
// are ordinary tree nodes, so expanding one lazily loads its versions and
// selecting a leaf fills the detail panel — against the hit's own ecosystem,
// not the sidebar's. Clearing the box (or picking a sidebar view) restores
// the view the sidebar has selected.
// ---------------------------------------------------------------------------
function searchBox() {
    return byId("search");
}
function clearSearchBox() {
    searchActive = false;
    window.clearTimeout(searchTimer);
    searchBox().value = "";
}
// scheduleSearch debounces input events so a fast typist triggers one fetch,
// not one per keystroke.
function scheduleSearch() {
    window.clearTimeout(searchTimer);
    const q = searchBox().value.trim();
    searchTimer = window.setTimeout(() => void runSearch(q), 250);
}
async function runSearch(q) {
    if (q === "") {
        if (searchActive) {
            searchActive = false;
            applyView(currentView); // restore the sidebar's view
        }
        return;
    }
    searchActive = true;
    byId("view-overview").hidden = true;
    byId("view-tree").hidden = false;
    byId("guideBtn").hidden = true;
    byId("treeTitle").textContent = `Search: “${q}”`;
    clearDetail();
    const tree = byId("tree");
    setMessage(tree, "searching…");
    try {
        const resp = await fetch(`/ui/api/search?q=${encodeURIComponent(q)}`, { cache: "no-store" });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        const data = (await resp.json());
        if (!searchActive || searchBox().value.trim() !== q) {
            return; // stale response: a newer query or a cleared box owns the panel
        }
        renderSearchResults(tree, data);
    }
    catch (err) {
        setMessage(tree, `Search failed: ${err.message}`);
    }
}
function renderSearchResults(container, data) {
    container.textContent = "";
    const groups = data.groups ?? [];
    if (groups.length === 0) {
        setMessage(container, `No packages match “${data.query}”.`);
        return;
    }
    for (const group of groups) {
        container.appendChild(searchGroupEl(group));
    }
}
// searchGroupEl renders one ecosystem's matches: a heading with the ecosystem
// title and match count, then the hits as ordinary tree nodes.
function searchGroupEl(group) {
    const el = document.createElement("div");
    el.className = "search-group";
    const nodes = group.nodes ?? [];
    const head = document.createElement("div");
    head.className = "search-eco";
    head.textContent = `${group.label} · ${group.total} ${group.total === 1 ? "match" : "matches"}`;
    el.appendChild(head);
    const list = document.createElement("div");
    list.className = "search-list";
    renderNodes(list, nodes, group.eco);
    el.appendChild(list);
    if (group.total > nodes.length) {
        const more = document.createElement("p");
        more.className = "empty";
        more.textContent = `showing the first ${nodes.length} — refine the search to see the rest`;
        el.appendChild(more);
    }
    return el;
}
function serverBase() {
    return window.location.origin; // e.g. https://artigate-high.local (no trailing slash)
}
async function fetchRepos(eco) {
    const resp = await fetch(`/ui/api/repos?eco=${encodeURIComponent(eco)}`, { cache: "no-store" });
    if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
    }
    const data = (await resp.json());
    return data.repos ?? [];
}
function goGuideSection(base) {
    return {
        heading: "Go modules",
        body: "Point the Go toolchain at this mirror as its module proxy. The trailing " +
            "“,off” means Go builds only from what this mirror has imported and never " +
            "reaches out to the internet.",
        blocks: [
            { label: "Configure the client", code: `go env -w GOPROXY=${base}/go,off` },
            { label: "Reproducible builds (CI)", code: "go build -mod=readonly ./...\ngo test -mod=readonly ./..." },
        ],
        note: "GOSUMDB stays on: the mirror serves the checksum database's signed " +
            "records and Merkle proofs under go/sumdb/, captured when each module " +
            "was mirrored, so go verifies modules end to end while offline. Only " +
            "modules mirrored before checksum-db capture existed lack records — " +
            "re-collect them once on the low side, or go env -w GOSUMDB=off.",
    };
}
function pythonGuideSection(base) {
    return {
        heading: "Python packages",
        body: "Use this mirror as pip's only index. Wheels-only is recommended for " +
            "air-gapped builds — no compilers or build backends are needed.",
        blocks: [
            { label: "/etc/pip.conf  (or ~/.config/pip/pip.conf)", code: `[global]\nindex-url = ${base}/simple/\ndisable-pip-version-check = true` },
            { label: "Install", code: "pip install --only-binary=:all: -r requirements.txt" },
        ],
        note: "Do not add --extra-index-url: mixing in another index reopens " +
            "dependency-confusion risk. This mirror is the single source of truth.",
    };
}
function npmGuideSection(base) {
    return {
        heading: "NPM packages",
        body: "Use this mirror as npm's only registry. It serves the npm registry API " +
            "under /npm/, with integrity hashes regenerated from the imported tarballs.",
        blocks: [
            {
                label: "~/.npmrc  (or /etc/npmrc, or per-project .npmrc)",
                code: `registry=${base}/npm/\nfund=false\nupdate-notifier=false`,
            },
            { label: "Install", code: "npm install" },
        ],
        note: "npm audit works once the OSV \"npm\" database is mirrored (see the OSV " +
            "page); until then add audit=false, because the advisory endpoint answers " +
            "404. Do not mix in another registry — this mirror is the single source " +
            "of truth. Only registry tarballs are mirrored (no git dependencies).",
    };
}
function mavenGuideSection(base) {
    return {
        heading: "Java (Maven / Gradle)",
        body: "Point Maven or Gradle at this mirror as the only repository. It serves a " +
            "standard Maven 2 repository under /maven/.",
        blocks: [
            {
                label: "~/.m2/settings.xml (Maven)",
                code: "<settings>\n  <mirrors>\n    <mirror>\n      <id>artigate</id>\n      <mirrorOf>*</mirrorOf>\n" +
                    `      <url>${base}/maven/</url>\n` +
                    "    </mirror>\n  </mirrors>\n</settings>",
            },
            { label: "build.gradle(.kts) (Gradle)", code: `repositories {\n    maven { url = uri("${base}/maven/") }\n}` },
        ],
        note: "Do not add mavenCentral() or other external repositories — ArtiGate is the " +
            "single source of truth. Pin exact versions; SNAPSHOTs and ranges are not mirrored.",
    };
}
// aptSuiteBase returns the release a suite belongs to: "noble-updates" and
// "noble-security" group under "noble"; "resolute" stands alone.
function aptSuiteBase(name) {
    const i = name.indexOf("-");
    return i > 0 ? name.slice(0, i) : name;
}
// aptGuideSection builds setup for one suite/component of a mirrored APT
// repository. The "Set me up" button sits on a component node of the tree
// (mirror -> suite -> component), so where the user clicked already pins the
// release and the channel — the stanza needs no further choices.
function aptGuideSection(base, repo, suiteName, comp) {
    const suite = (repo.suites ?? []).find((s) => s.name === suiteName);
    const arches = suite && suite.architectures && suite.architectures.length ? suite.architectures.join(" ") : "<arch>";
    // Signed repos are verified with ArtiGate's key; unsigned repos are trusted directly.
    const trust = repo.signed ? "Signed-By: /usr/share/keyrings/artigate-apt.gpg" : "Trusted: yes";
    const signNote = repo.signed
        ? "Use ArtiGate's high-side APT key (Signed-By), not the upstream vendor key."
        : "This repository is served unsigned, so apt trusts it directly (Trusted: yes). To verify instead, sign it with --apt-gpg-key on the high side.";
    // Sibling suites of the same release that also carry this component
    // (noble-updates and noble-security next to noble) usually belong on the
    // same machine — point them out rather than silently pinning one suite.
    const related = (repo.suites ?? [])
        .filter((s) => s.name !== suiteName && aptSuiteBase(s.name) === aptSuiteBase(suiteName))
        .filter((s) => (s.components ?? []).includes(comp))
        .map((s) => s.name);
    const relatedNote = related.length
        ? ` This mirror also carries ${related.join(" and ")} for the same release — append them to Suites: to pull their ${comp} packages too.`
        : "";
    return {
        heading: `${repo.name} — ${suiteName}/${comp}`,
        body: "Point apt at exactly this suite and component (deb822 .sources format).",
        blocks: [
            {
                label: "/etc/apt/sources.list.d/artigate.sources",
                code: "Types: deb\n" +
                    `URIs: ${base}/apt/${repo.name}\n` +
                    `Suites: ${suiteName}\n` +
                    `Components: ${comp}\n` +
                    `Architectures: ${arches}\n` +
                    trust,
            },
        ],
        note: signNote + relatedNote,
    };
}
// rpmGuideSection builds setup for one mirrored RPM repository.
function rpmGuideSection(base, repo) {
    // Signed repos verify repomd.xml against ArtiGate's key; unsigned repos turn
    // signature checks off (there is no key to verify against).
    const gpg = repo.signed
        ? "gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate"
        : "gpgcheck=0\nrepo_gpgcheck=0";
    return {
        heading: repo.name,
        body: "Point dnf/yum at this mirrored repository.",
        blocks: [
            {
                label: `/etc/yum.repos.d/artigate-${repo.name}.repo`,
                code: `[artigate-${repo.name}]\n` +
                    `name=ArtiGate ${repo.name}\n` +
                    `baseurl=${base}/rpm/${repo.name}\n` +
                    "enabled=1\n" +
                    gpg,
            },
        ],
        note: repo.signed
            ? "repo_gpgcheck=1 verifies repomd.xml against ArtiGate's high-side key."
            : "This repository is served unsigned, so signature checks are off. To verify instead, sign it with --rpm-gpg-key on the high side.",
    };
}
// flashButton briefly swaps an element's text (a copy button, or just the
// "Copy" tag of the reference control) and restores it.
function flashButton(btn, text) {
    if (btn.dataset["label"] === undefined) {
        btn.dataset["label"] = btn.textContent ?? "Copy";
    }
    btn.textContent = text;
    window.setTimeout(() => {
        btn.textContent = btn.dataset["label"] ?? "Copy";
    }, 1200);
}
function selectText(el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(range);
}
async function copyCode(text, codeEl, btn) {
    try {
        if (!navigator.clipboard) {
            throw new Error("clipboard unavailable");
        }
        await navigator.clipboard.writeText(text);
        flashButton(btn, "Copied ✓");
    }
    catch {
        selectText(codeEl); // insecure context: let the user copy manually
        flashButton(btn, "Press Ctrl+C");
    }
}
function codeBlock(block) {
    const wrap = document.createElement("div");
    wrap.className = "code";
    if (block.label) {
        const lbl = document.createElement("div");
        lbl.className = "code-label";
        lbl.textContent = block.label;
        wrap.appendChild(lbl);
    }
    const pre = document.createElement("pre");
    const codeEl = document.createElement("code");
    codeEl.textContent = block.code;
    pre.appendChild(codeEl);
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy";
    copy.textContent = "Copy";
    copy.addEventListener("click", () => void copyCode(block.code, codeEl, copy));
    pre.appendChild(copy);
    wrap.appendChild(pre);
    return wrap;
}
function guideSectionEl(section) {
    const el = document.createElement("div");
    el.className = "guide-section";
    const h3 = document.createElement("h3");
    h3.textContent = section.heading;
    el.appendChild(h3);
    const body = document.createElement("p");
    body.textContent = section.body;
    el.appendChild(body);
    for (const block of section.blocks) {
        el.appendChild(codeBlock(block));
    }
    if (section.note) {
        const note = document.createElement("p");
        note.className = "note";
        note.textContent = section.note;
        el.appendChild(note);
    }
    return el;
}
function guideIntro(view, base) {
    const intro = document.createElement("p");
    intro.className = "guide-intro";
    intro.innerHTML =
        `Server address: <code>${esc(base)}</code>. Configure a client to pull ` +
            `${esc(VIEW_TITLES[view])} from this air-gapped mirror.`;
    return intro;
}
// renderGuideSections appends the sections: one full-width, several in two
// columns, or an empty note when there is nothing to show.
function renderGuideSections(container, sections) {
    if (sections.length === 0) {
        const p = document.createElement("p");
        p.className = "empty";
        p.textContent = "Nothing mirrored here yet.";
        container.appendChild(p);
        return;
    }
    if (sections.length === 1) {
        container.appendChild(guideSectionEl(sections[0]));
        return;
    }
    const cols = document.createElement("div");
    cols.className = "guide-cols";
    for (const section of sections) {
        cols.appendChild(guideSectionEl(section));
    }
    container.appendChild(cols);
}
function guideDialog() {
    return byId("guide");
}
// containersGuideSection shows how to pull from the mirrored OCI registry.
// Pull names embed the upstream registry (docker.io/..., ghcr.io/...), so the
// example commands are built from what is actually mirrored. When the mirror
// is served over plain HTTP it also renders the exact /etc/docker/daemon.json
// insecure-registries block, with this host and port filled in.
function containersGuideSection(repos) {
    const host = window.location.host; // host:port, honoring any reverse proxy
    const secure = window.location.protocol === "https:";
    const pullName = (r) => `${host}/${r.name}${r.tags && r.tags.length ? `:${r.tags[0]}` : ""}`;
    const pulls = repos
        .slice(0, 8)
        .map((r) => `docker pull ${pullName(r)}`)
        .join("\n");
    // The full daemon.json Docker needs to trust a plain-HTTP registry. Built
    // with JSON.stringify so it is always valid JSON with the live host:port.
    const daemonJSON = JSON.stringify({ "insecure-registries": [host] }, null, 2);
    const blocks = [
        {
            label: "Pull (docker / podman)",
            code: pulls || `docker pull ${host}/docker.io/library/alpine:3.20`,
        },
        {
            label: "/etc/docker/daemon.json  — then: sudo systemctl restart docker",
            code: daemonJSON,
        },
        {
            label: "Podman — /etc/containers/registries.conf.d/artigate.conf",
            code: `[[registry]]\nlocation = "${host}"\ninsecure = true`,
        },
    ];
    return {
        heading: "Container images",
        body: "This mirror is a read-only OCI registry (linux/amd64 only). Each " +
            "upstream registry keeps its own namespace, so the pull name is " +
            "<this-host>/<upstream-registry>/<repository>:<tag>.",
        blocks,
        note: secure
            ? "This host serves HTTPS, so no insecure-registries entry is needed — the " +
                "daemon.json above is only for a plain-HTTP mirror. Restart the Docker " +
                "daemon after editing daemon.json."
            : "Docker rejects plain-HTTP registries unless the host is listed in " +
                "insecure-registries (above); restart the daemon after editing. Serve the " +
                "high side over TLS to drop this entirely.",
    };
}
// hfGuideSection shows how to consume mirrored Hugging Face content. GGUF
// models pull with Ollama (an Ollama model name is host/namespace/model:tag,
// so the pull name is this host followed by the model's own
// <org>/<name>:<variant>) or download as a raw file. Full repository
// snapshots serve the Hub API, so vLLM/transformers/hf point HF_ENDPOINT at
// this mirror. The examples are built from what is actually mirrored.
function hfGuideSection(repos) {
    const host = window.location.host; // host:port, honoring any reverse proxy
    const base = serverBase();
    const secure = window.location.protocol === "https:";
    const insecure = secure ? "" : "--insecure ";
    const gguf = repos.filter((r) => r.kind !== "repo");
    const full = repos.filter((r) => r.kind === "repo");
    // Every section always renders — the guide teaches the workflows even
    // before anything is mirrored — but sections whose content is not mirrored
    // yet are labeled as examples.
    const example = (mirrored) => (mirrored ? "" : " (example — none mirrored yet)");
    const pullName = (r) => `${host}/${r.name}${r.tags && r.tags.length ? `:${r.tags[0]}` : ""}`;
    const pulls = gguf
        .slice(0, 8)
        .map((r) => `ollama pull ${insecure}${pullName(r)}`)
        .join("\n");
    // One concrete model+variant / repository for the runnable examples.
    const firstGguf = gguf.length ? gguf[0] : undefined;
    const ggufName = firstGguf ? firstGguf.name : "unsloth/gpt-oss-20b-GGUF";
    const ggufTag = firstGguf && firstGguf.tags && firstGguf.tags.length ? firstGguf.tags[0] : "Q4_0";
    const file = `${ggufName.split("/")[1] ?? "model"}-${ggufTag}.gguf`;
    const repoName = full.length ? full[0].name : "openai/gpt-oss-20b";
    const blocks = [
        {
            label: `Ollama — pull and run a GGUF model${example(gguf.length > 0)}`,
            code: (pulls || `ollama pull ${insecure}${host}/${ggufName}:${ggufTag}`) +
                `\nollama run ${host}/${ggufName}:${ggufTag}`,
        },
        {
            label: `vLLM / transformers / hf — full repositories via the Hub API${example(full.length > 0)}`,
            code: `export HF_ENDPOINT=${base}\n` +
                `vllm serve ${repoName}\n` +
                `hf download ${repoName}    # or any huggingface_hub client`,
        },
        {
            label: `llama.cpp — download the raw GGUF file${example(gguf.length > 0)}`,
            code: `curl -fL -o ${file} ${base}/hf/${ggufName}/${ggufTag}.gguf\nllama-server -m ${file}`,
        },
    ];
    const notes = [
        secure
            ? "Ollama: this host serves HTTPS, so plain `ollama pull` works as shown."
            : "Ollama: this mirror is plain HTTP, so pass --insecure to ollama pull (or serve the high side over TLS).",
        full.length > 0
            ? "vLLM: setting HF_ENDPOINT redirects every huggingface_hub client to this mirror — no other flags needed."
            : "vLLM: no full repositories are mirrored yet — collect one in the low side's \"Full repositories\" box; GGUF models alone cannot be served over the Hub API.",
        "A downloaded GGUF also works with vLLM's per-architecture GGUF loader " +
            `(HF_HUB_OFFLINE=1 vllm serve ./${file}), but full repositories are the reliable vLLM path.`,
    ];
    return {
        heading: "AI models (Hugging Face)",
        body: "Three ways to consume this mirror: Ollama pulls GGUF models over its own " +
            "registry protocol (pull name: <this-host>/<org>/<model>:<variant>); " +
            "vLLM, transformers, and hf consume full repository snapshots through " +
            "the Hub API by pointing HF_ENDPOINT here; raw GGUF files download from " +
            "/hf/ for llama.cpp.",
        blocks,
        note: notes.join(" "),
    };
}
function cratesGuideSection(base) {
    return {
        heading: "Rust crates",
        body: "Use this mirror as cargo's registry via a sparse index. Replacing " +
            "crates.io with source replacement keeps Cargo.toml files unchanged.",
        blocks: [
            {
                label: "~/.cargo/config.toml",
                code: `[source.crates-io]\nreplace-with = "artigate"\n\n[source.artigate]\n` +
                    `registry = "sparse+${base}/crates/index/"\n\n[registries.artigate]\n` +
                    `index = "sparse+${base}/crates/index/"`,
            },
            { label: "Build", code: "cargo build --locked" },
        ],
        note: "Only crates mirrored here resolve. Dev-dependencies are not followed by " +
            "the low side's resolver — mirror them explicitly if a build needs them.",
    };
}
function terraformGuideSection(base) {
    const host = window.location.host;
    return {
        heading: "Terraform / OpenTofu",
        body: "This mirror speaks the provider and module registry protocols. Use " +
            "this host as the registry part of source addresses, or mirror " +
            "registry.terraform.io wholesale via provider_installation.",
        blocks: [
            {
                label: "~/.terraformrc  (network_mirror needs HTTPS)",
                code: `provider_installation {\n  network_mirror {\n    url = "${base}/terraform/v1/providers/"\n  }\n}`,
            },
            {
                label: "Or address providers/modules explicitly",
                code: `terraform {\n  required_providers {\n    aws = { source = "${host}/hashicorp/aws" }\n  }\n}\n\n` +
                    `module "vpc" {\n  source  = "${host}/terraform-aws-modules/vpc/aws"\n  version = "~> 5.0"\n}`,
            },
        ],
        note: "Provider zips verify against the mirrored upstream SHA256SUMS and its " +
            "GPG signature, so terraform's own trust chain still applies.",
    };
}
function helmGuideSection(base) {
    return {
        heading: "Helm charts",
        body: "Each mirrored upstream repo is served as a classic Helm repository " +
            "under its mirror name (see the tree's top-level folders).",
        blocks: [
            {
                label: "Add the repo",
                code: `helm repo add <mirror> ${base}/helm/<mirror>\nhelm repo update`,
            },
            { label: "Install", code: "helm install my-release <mirror>/<chart> --version <version>" },
        ],
        note: "index.yaml is regenerated on the high side from each chart's own " +
            "Chart.yaml, and chart digests are recomputed from the verified archives.",
    };
}
function nugetGuideSection(base) {
    return {
        heading: "NuGet packages",
        body: "Use this mirror as the only NuGet package source (a standard v3 feed).",
        blocks: [
            {
                label: "nuget.config (next to the solution, or ~/.nuget/NuGet/NuGet.Config)",
                code: `<configuration>\n  <packageSources>\n    <clear />\n    ` +
                    `<add key="artigate" value="${base}/nuget/v3/index.json" protocolVersion="3" />\n` +
                    `  </packageSources>\n</configuration>`,
            },
            { label: "Restore", code: "dotnet restore" },
        ],
        note: "<clear /> removes nuget.org so this mirror is the single source of " +
            "truth. Package metadata is regenerated from each package's own .nuspec.",
    };
}
// apkGuideSection shows /etc/apk/repositories lines for each mirrored Alpine
// mirror, built from the live repo list so they are copy-paste ready.
function osvGuideSection(base) {
    return {
        heading: "OSV advisories",
        body: "Each mirrored OSV ecosystem's advisory database is served in the " +
            "upstream bucket's layout: ecosystems.txt, one all.zip per ecosystem, " +
            "and single advisories by id.",
        blocks: [
            {
                label: "Download databases for an offline scanner (e.g. osv-scanner)",
                code: `curl -fsSL ${base}/osv/ecosystems.txt\n` +
                    `curl -fL -o npm-all.zip ${base}/osv/npm/all.zip    # any listed ecosystem`,
            },
            {
                label: "Fetch one advisory",
                code: `curl -fsSL ${base}/osv/npm/GHSA-xxxx-xxxx-xxxx.json`,
            },
        ],
        note: "Place each all.zip where your scanner expects its offline database " +
            "(osv-scanner: <cache>/osv-scanner/<ecosystem>/all.zip, then run with " +
            "--offline). With the \"npm\" database mirrored, this host also answers " +
            "npm audit on its npm registry — clients no longer need audit=false.",
    };
}
function apkGuideSection(repos) {
    const base = serverBase();
    const lines = [];
    for (const r of repos.slice(0, 4)) {
        for (const s of r.suites ?? []) {
            for (const comp of s.components ?? []) {
                lines.push(`${base}/apk/${r.name}/${s.name}/${comp}`);
            }
        }
    }
    const example = lines.length ? lines.join("\n") : `${base}/apk/<mirror>/<branch>/<repo>`;
    const signed = repos.some((r) => r.signed);
    const blocks = [{ label: "/etc/apk/repositories", code: example }];
    if (signed) {
        blocks.push({
            label: "Install the mirror's signing key (once)",
            code: `wget -O /etc/apk/keys/artigate.rsa.pub ${base}/apk/keys/artigate.rsa.pub\napk update`,
        });
    }
    else {
        blocks.push({ label: "Update (unsigned index)", code: "apk update --allow-untrusted\napk add --allow-untrusted <package>" });
    }
    return {
        heading: "Alpine packages",
        body: "Point apk at the mirrored branches/repositories.",
        blocks,
        note: signed
            ? "The high side re-signs APKINDEX with its own RSA key; install the public key once and apk verifies every update."
            : "The regenerated APKINDEX is unsigned (no --apk-rsa-key configured), so apk needs --allow-untrusted. Content was still hash-verified end-to-end when its signed bundle was imported.",
    };
}
// openGuide shows the whole-ecosystem setup for Go/Python/Maven/containers
// (one config for the mirror). APT/RPM set up per repository instead, via
// openRepoGuide.
function condaGuideSection(base) {
    return {
        heading: "Conda packages",
        body: "Each mirrored channel is served under its mirror name (the tree's " +
            "top-level folders) with repodata.json regenerated from the verified " +
            "packages.",
        blocks: [
            {
                label: "Install with conda / mamba / micromamba",
                code: `conda install --override-channels -c ${base}/conda/<mirror> <package>\n` +
                    `micromamba install -c ${base}/conda/<mirror> --override-channels <package>`,
            },
            {
                label: "Pin the mirror in .condarc",
                code: `channels:\n  - ${base}/conda/<mirror>\noverride_channels_enabled: true`,
            },
        ],
        note: "repodata.json is rebuilt on this host from each package's verified " +
            "repodata entry; only packages that are actually present are listed.",
    };
}
function rubygemsGuideSection(base) {
    return {
        heading: "Ruby gems",
        body: "The mirror serves the compact index Bundler and modern RubyGems " +
            "resolve against, plus the .gem archives.",
        blocks: [
            {
                label: "Gemfile",
                code: `source "${base}/rubygems"\n\ngem "rake"`,
            },
            { label: "Install", code: "bundle install" },
        ],
        note: "/versions and /info/<gem> are regenerated on this host from the " +
            "mirrored gems; each info line's checksum is the verified archive's " +
            "SHA-256, so Bundler's checksum verification keeps working.",
    };
}
function composerGuideSection(base) {
    return {
        heading: "PHP Composer packages",
        body: "The mirror is a Composer v2 repository: point repositories at it and " +
            "disable packagist.org.",
        blocks: [
            {
                label: "composer.json",
                code: `{\n  "repositories": {\n    "packagist.org": false,\n` +
                    `    "mirror": { "type": "composer", "url": "${base}/composer" }\n  }\n}`,
            },
            { label: "Install", code: "composer require <vendor>/<package>" },
        ],
        note: "Package metadata is served from the signed bundle records and each " +
            "dist URL points back at this host's verified zip archives.",
    };
}
function vsxGuideSection(base) {
    return {
        heading: "VS Code extensions",
        body: "The mirror answers the VS Code gallery API, so VSCodium and Code-OSS " +
            "builds can search and install extensions from it.",
        blocks: [
            {
                label: "Point the gallery at the mirror (VSCodium)",
                code: `export VSCODE_GALLERY_SERVICE_URL=${base}/vsx/gallery\n` +
                    `codium --install-extension <publisher>.<name>`,
            },
            {
                label: "Or in product.json",
                code: `"extensionsGallery": { "serviceUrl": "${base}/vsx/gallery" }`,
            },
            {
                label: "Direct .vsix download",
                code: `curl -fL -o ext.vsix ${base}/vsx/files/<publisher>/<name>/<publisher>.<name>-<version>.vsix\ncode --install-extension ext.vsix`,
            },
        ],
        note: "Gallery metadata is regenerated from each extension's own embedded " +
            "package.json; only extensions whose .vsix is present are listed.",
    };
}
function galaxyGuideSection(base) {
    return {
        heading: "Ansible collections",
        body: "The mirror answers the Galaxy v3 API ansible-galaxy installs from.",
        blocks: [
            {
                label: "Install a collection",
                code: `ansible-galaxy collection install <namespace>.<name> -s ${base}/galaxy/`,
            },
            {
                label: "Or pin the server in ansible.cfg",
                code: `[galaxy]\nserver_list = mirror\n\n[galaxy_server.mirror]\nurl=${base}/galaxy/`,
            },
        ],
        note: "Version metadata (and each artifact's SHA-256 the client verifies) is " +
            "regenerated from the mirrored tarballs' own MANIFEST.json.",
    };
}
function cranGuideSection(base) {
    return {
        heading: "R packages (CRAN)",
        body: "The mirror is a source CRAN repository: src/contrib with a PACKAGES " +
            "index regenerated from each tarball's own DESCRIPTION.",
        blocks: [
            {
                label: "Install from R",
                code: `install.packages("<package>", repos = "${base}/cran")`,
            },
            {
                label: "Or pin it for the session",
                code: `options(repos = c(mirror = "${base}/cran"))`,
            },
        ],
        note: "Only source packages are mirrored (type = \"source\"); R builds them " +
            "locally like it does against any CRAN mirror.",
    };
}
function gitGuideSection(base) {
    return {
        heading: "Git repositories",
        body: "Each mirrored repository is served read-only over git's dumb HTTP " +
            "protocol — stock git clones it with no extra setup.",
        blocks: [
            { label: "Clone", code: `git clone ${base}/git/<mirror>.git` },
            { label: "List refs", code: `git ls-remote ${base}/git/<mirror>.git` },
        ],
        note: "The pack index is rebuilt on this host from the verified packfile; " +
            "re-collecting on the low side refreshes the mirror to the current " +
            "upstream refs.",
    };
}
function openGuide() {
    const dialog = guideDialog();
    const body = byId("guideBody");
    const base = serverBase();
    byId("guideTitle").textContent = `Set up ${VIEW_TITLES[currentView]}`;
    body.textContent = "";
    body.appendChild(guideIntro(currentView, base));
    if (currentView === "containers" || currentView === "hf" || currentView === "apk") {
        // Built from the live repo list so the pull commands are copy-paste ready.
        const view = currentView;
        const section = (repos) => view === "hf" ? hfGuideSection(repos) : view === "apk" ? apkGuideSection(repos) : containersGuideSection(repos);
        const loading = document.createElement("p");
        loading.className = "empty";
        loading.textContent = "Loading…";
        body.appendChild(loading);
        fetchRepos(view)
            .then((repos) => {
            loading.remove();
            renderGuideSections(body, [section(repos)]);
        })
            .catch(() => {
            loading.remove();
            renderGuideSections(body, [section([])]);
        });
    }
    else {
        const section = currentView === "python"
            ? pythonGuideSection(base)
            : currentView === "maven"
                ? mavenGuideSection(base)
                : currentView === "npm"
                    ? npmGuideSection(base)
                    : currentView === "crates"
                        ? cratesGuideSection(base)
                        : currentView === "terraform"
                            ? terraformGuideSection(base)
                            : currentView === "helm"
                                ? helmGuideSection(base)
                                : currentView === "nuget"
                                    ? nugetGuideSection(base)
                                    : currentView === "conda"
                                        ? condaGuideSection(base)
                                        : currentView === "rubygems"
                                            ? rubygemsGuideSection(base)
                                            : currentView === "composer"
                                                ? composerGuideSection(base)
                                                : currentView === "vsx"
                                                    ? vsxGuideSection(base)
                                                    : currentView === "galaxy"
                                                        ? galaxyGuideSection(base)
                                                        : currentView === "cran"
                                                            ? cranGuideSection(base)
                                                            : currentView === "git"
                                                                ? gitGuideSection(base)
                                                                : currentView === "osv"
                                                                    ? osvGuideSection(base)
                                                                    : goGuideSection(base);
        renderGuideSections(body, [section]);
    }
    if (!dialog.open) {
        dialog.showModal();
    }
}
// openRepoGuide shows setup for a single mirrored APT/RPM repository, fetched
// live so the URL and (for APT) suite/component/arch are exact. For APT,
// repoRef is a component node's tree path "<mirror>/<suite>/<component>"; for
// RPM it is the repository name.
async function openRepoGuide(eco, repoRef) {
    const dialog = guideDialog();
    const body = byId("guideBody");
    const base = serverBase();
    const parts = repoRef.split("/");
    const repoName = parts[0] ?? repoRef;
    byId("guideTitle").textContent = `Set up ${streamLabel(eco)} — ${repoRef}`;
    body.textContent = "";
    body.appendChild(guideIntro(eco, base));
    const loading = document.createElement("p");
    loading.className = "empty";
    loading.textContent = "Loading…";
    body.appendChild(loading);
    if (!dialog.open) {
        dialog.showModal();
    }
    try {
        const repo = (await fetchRepos(eco)).find((r) => r.name === repoName);
        loading.remove();
        if (!repo) {
            renderGuideSections(body, []);
            return;
        }
        const section = eco === "apt"
            ? aptGuideSection(base, repo, parts[1] ?? "", parts[2] ?? "")
            : eco === "rpm"
                ? rpmGuideSection(base, repo)
                : containersGuideSection([repo]);
        renderGuideSections(body, [section]);
    }
    catch (err) {
        loading.textContent = `Failed to load repository: ${err.message}`;
    }
}
menuButtons().forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset["view"]));
});
byId("refresh").addEventListener("click", refresh);
searchBox().addEventListener("input", scheduleSearch);
searchBox().addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && searchBox().value !== "") {
        ev.preventDefault(); // keep focus; just leave search mode
        searchBox().value = "";
        window.clearTimeout(searchTimer);
        void runSearch(""); // restores the sidebar's view when search was active
    }
});
const guide = guideDialog();
byId("guideBtn").addEventListener("click", openGuide);
byId("guideClose").addEventListener("click", () => guide.close());
guide.addEventListener("click", (ev) => {
    // Content sits in .guide-inner, so a click whose target is the dialog itself
    // landed on the backdrop — dismiss. (Escape is handled natively.)
    if (ev.target === guide) {
        guide.close();
    }
});
refresh();
