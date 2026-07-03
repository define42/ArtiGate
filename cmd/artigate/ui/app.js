"use strict";
// High-side dashboard. The import status is fetched once; the package trees are
// loaded lazily, one level at a time, from /ui/api/tree. Expanding a node fetches
// only that node's immediate children, so nothing large is transferred or
// rendered up front. The top menu switches between the Go and Python trees.
let currentView = "go";
let selectedLeaf = null;
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
function renderStatus(status) {
    const banner = byId("banner");
    const missing = status.missing_ranges ?? [];
    const quarantined = status.quarantined_sequences ?? [];
    if (missing.length > 0) {
        banner.className = "banner warn";
        banner.innerHTML =
            `&#9888; Missing bundles: ${esc(missing.join(", "))} ` +
                `&mdash; waiting for these before advancing past #${esc(status.next_expected_sequence)}`;
    }
    else {
        banner.className = "banner ok";
        banner.textContent = `✓ All bundles imported through #${status.last_imported_sequence}`;
    }
    byId("meta").innerHTML =
        `<span>Last imported: <b>#${esc(status.last_imported_sequence)}</b></span>` +
            `<span>Next expected: <b>#${esc(status.next_expected_sequence)}</b></span>` +
            `<span>Highest seen: <b>#${esc(status.highest_seen_sequence)}</b></span>` +
            `<span>Quarantined: <b>${quarantined.length ? esc(quarantined.join(", ")) : "none"}</b></span>`;
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
function renderNodes(container, nodes) {
    container.textContent = "";
    if (nodes.length === 0) {
        setMessage(container, "empty");
        return;
    }
    for (const node of nodes) {
        container.appendChild(node.expandable ? expandableNode(node) : leafNode(node));
    }
}
function leafNode(node) {
    const div = document.createElement("div");
    div.className = "leaf";
    div.textContent = node.label;
    div.tabIndex = 0;
    div.setAttribute("role", "button");
    div.addEventListener("click", () => void selectLeaf(div, node));
    div.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
            ev.preventDefault();
            void selectLeaf(div, node);
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
}
async function selectLeaf(el, node) {
    if (selectedLeaf) {
        selectedLeaf.classList.remove("selected");
    }
    selectedLeaf = el;
    el.classList.add("selected");
    const panel = byId("detail");
    setMessage(panel, "loading…");
    try {
        const url = `/ui/api/detail?eco=${encodeURIComponent(currentView)}&path=${encodeURIComponent(node.path)}`;
        const resp = await fetch(url, { cache: "no-store" });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        renderDetail((await resp.json()));
    }
    catch (err) {
        setMessage(panel, `Failed to load details: ${err.message}`);
    }
}
function clearDetail() {
    selectedLeaf = null;
    setMessage(byId("detail"), "Select a version to see its details.");
}
function expandableNode(node) {
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
        fetchChildren(currentView, node.path)
            .then((child) => renderNodes(children, child))
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
    byId("treeTitle").textContent = currentView === "go" ? "Go modules" : "Python packages";
    clearDetail();
    setMessage(tree, "loading…");
    try {
        const nodes = await fetchChildren(currentView, "");
        renderNodes(tree, nodes);
    }
    catch (err) {
        setMessage(tree, `Failed to load tree: ${err.message}`);
    }
}
function setView(view) {
    if (view === currentView) {
        return;
    }
    currentView = view;
    menuButtons().forEach((btn) => {
        btn.classList.toggle("active", btn.dataset["view"] === view);
    });
    void loadTree();
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
    void loadTree();
}
menuButtons().forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset["view"]));
});
byId("refresh").addEventListener("click", refresh);
refresh();
