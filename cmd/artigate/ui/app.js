"use strict";
// High-side dashboard. The import status is fetched once; the package trees are
// loaded lazily, one level at a time, from /ui/api/tree. Expanding a node fetches
// only that node's immediate children, so nothing large is transferred or
// rendered up front. The top menu switches between the Go and Python trees.
const VIEW_TITLES = {
    go: "Go modules",
    python: "Python packages",
    maven: "Maven artifacts",
    apt: "APT packages",
    rpm: "RPM packages",
};
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
const STREAM_LABELS = {
    go: "Go",
    python: "Python",
    maven: "Maven",
    apt: "APT",
    rpm: "RPM",
};
function streamLabel(name) {
    return STREAM_LABELS[name] ?? name;
}
function renderStatus(status) {
    const banner = byId("banner");
    const streams = status.streams ?? [];
    const blocked = streams.filter((s) => (s.missing_ranges ?? []).length > 0);
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
    else {
        banner.className = "banner ok";
        banner.textContent = "✓ All streams up to date.";
    }
    renderStreamTable(streams);
}
function statusPill(ok) {
    return ok
        ? '<span class="pill ok">up to date</span>'
        : '<span class="pill warn">waiting</span>';
}
function streamRow(s) {
    const missing = s.missing_ranges ?? [];
    const quarantined = s.quarantined_sequences ?? [];
    return ("<tr>" +
        `<td class="s-name">${esc(streamLabel(s.stream))}</td>` +
        `<td>#${esc(s.last_imported_sequence)}</td>` +
        `<td>#${esc(s.next_expected_sequence)}</td>` +
        `<td>${missing.length ? esc(missing.join(", ")) : "&mdash;"}</td>` +
        `<td>${quarantined.length ? esc(quarantined.join(", ")) : "&mdash;"}</td>` +
        `<td>${statusPill(missing.length === 0)}</td>` +
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
            "<th>Missing</th><th>Quarantined</th><th>Status</th>" +
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
    byId("treeTitle").textContent = VIEW_TITLES[currentView];
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
function serverBase() {
    return window.location.origin; // e.g. https://artigate-high.local (no trailing slash)
}
function guideSections(base) {
    return [
        {
            heading: "Go modules",
            body: "Point the Go toolchain at this mirror as its module proxy. The trailing " +
                "“,off” means Go builds only from what this mirror has imported and " +
                "never reaches out to the internet.",
            blocks: [
                {
                    label: "Configure the client",
                    code: `go env -w GOPROXY=${base},off\ngo env -w GOSUMDB=off`,
                },
                {
                    label: "Reproducible builds (CI)",
                    code: "go build -mod=readonly ./...\ngo test -mod=readonly ./...",
                },
            ],
            note: "GOSUMDB is off because the public checksum database is unreachable when " +
                "air-gapped — rely on your committed go.sum. The mirror serves only " +
                "versions whose hashes were verified when their signed bundle was imported.",
        },
        {
            heading: "Python packages",
            body: "Use this mirror as pip's only index. Wheels-only is recommended for " +
                "air-gapped builds — no compilers or build backends are needed.",
            blocks: [
                {
                    label: "/etc/pip.conf  (or ~/.config/pip/pip.conf)",
                    code: `[global]\nindex-url = ${base}/simple/\ndisable-pip-version-check = true`,
                },
                {
                    label: "Install",
                    code: "pip install --only-binary=:all: -r requirements.txt",
                },
            ],
            note: "Do not add --extra-index-url: mixing in another index reopens " +
                "dependency-confusion risk. This mirror is the single source of truth.",
        },
        {
            heading: "Java (Maven / Gradle)",
            body: "Point Maven or Gradle at this mirror as the only repository. It serves " +
                "a standard Maven 2 repository under /maven/.",
            blocks: [
                {
                    label: "~/.m2/settings.xml (Maven)",
                    code: "<settings>\n" +
                        "  <mirrors>\n" +
                        "    <mirror>\n" +
                        "      <id>artigate</id>\n" +
                        "      <mirrorOf>*</mirrorOf>\n" +
                        `      <url>${base}/maven/</url>\n` +
                        "    </mirror>\n" +
                        "  </mirrors>\n" +
                        "</settings>",
                },
                {
                    label: "build.gradle(.kts) (Gradle)",
                    code: `repositories {\n    maven { url = uri("${base}/maven/") }\n}`,
                },
            ],
            note: "Do not add mavenCentral() or other external repositories — ArtiGate is " +
                "the single source of truth. Pin exact versions; SNAPSHOTs and ranges are " +
                "not mirrored.",
        },
        {
            heading: "APT (Debian / Ubuntu)",
            body: "Point apt at a mirrored repository using the deb822 .sources format. " +
                "Replace <mirror>/<suite>/<component>/<arch> with the values shown in the " +
                "APT packages tab.",
            blocks: [
                {
                    label: "/etc/apt/sources.list.d/artigate.sources",
                    code: "Types: deb\n" +
                        `URIs: ${base}/apt/<mirror>\n` +
                        "Suites: <suite>\n" +
                        "Components: <component>\n" +
                        "Architectures: <arch>\n" +
                        "Signed-By: /usr/share/keyrings/artigate-apt.gpg",
                },
            ],
            note: "Use ArtiGate's high-side APT key (Signed-By), not the upstream vendor " +
                "key. If the mirror is published unsigned, use [trusted=yes] instead of " +
                "Signed-By.",
        },
        {
            heading: "RPM (Fedora / RHEL)",
            body: "Point dnf/yum at a mirrored repository. Replace <mirror> with the value " +
                "from the RPM packages tab.",
            blocks: [
                {
                    label: "/etc/yum.repos.d/artigate.repo",
                    code: "[artigate]\n" +
                        "name=ArtiGate mirror\n" +
                        `baseurl=${base}/rpm/<mirror>\n` +
                        "enabled=1\n" +
                        "gpgcheck=1\n" +
                        "repo_gpgcheck=1\n" +
                        "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-artigate",
                },
            ],
            note: "repo_gpgcheck=1 verifies repomd.xml against ArtiGate's high-side key. If " +
                "the mirror is published unsigned, set repo_gpgcheck=0 (package gpgcheck " +
                "still applies to signed .rpms).",
        },
    ];
}
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
function buildGuide(container) {
    const base = serverBase();
    container.textContent = "";
    const intro = document.createElement("p");
    intro.className = "guide-intro";
    intro.innerHTML =
        `Server address: <code>${esc(base)}</code>. Run these on any machine that ` +
            "should pull Go modules or Python wheels from this air-gapped mirror.";
    container.appendChild(intro);
    const cols = document.createElement("div");
    cols.className = "guide-cols";
    for (const section of guideSections(base)) {
        cols.appendChild(guideSectionEl(section));
    }
    container.appendChild(cols);
}
function guideDialog() {
    return byId("guide");
}
function openGuide() {
    const dialog = guideDialog();
    if (dialog.dataset["built"] !== "1") {
        buildGuide(byId("guideBody")); // lazily built on first open
        dialog.dataset["built"] = "1";
    }
    if (!dialog.open) {
        dialog.showModal();
    }
}
menuButtons().forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset["view"]));
});
byId("refresh").addEventListener("click", refresh);
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
