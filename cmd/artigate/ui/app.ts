// High-side dashboard. The import status is fetched once; the package trees are
// loaded lazily, one level at a time, from /ui/api/tree. Expanding a node fetches
// only that node's immediate children, so nothing large is transferred or
// rendered up front. The top menu switches between the Go and Python trees.

interface StreamStatus {
  stream: string;
  last_imported_sequence: number;
  next_expected_sequence: number;
  highest_seen_sequence: number;
  blocking_missing_sequence?: number;
  missing_ranges: string[];
  quarantined_sequences: number[];
  ready_to_import: boolean;
}

// Each ecosystem is an independently sequenced stream: a gap in one never blocks
// the others, so the status is reported per stream rather than as one counter.
interface ImportStatus {
  streams: StreamStatus[];
}

interface Overview {
  status: ImportStatus;
}

interface TreeNode {
  label: string;
  path: string;
  kind: string; // dir | module | version | project | file
  expandable: boolean;
  count?: number;
}

interface TreeResponse {
  nodes: TreeNode[];
}

interface DetailField {
  label: string;
  value: string;
  mono?: boolean;
}

interface Detail {
  title: string;
  subtitle?: string;
  fields: DetailField[];
  go_mod?: string;
}

type View = "go" | "python" | "maven" | "apt" | "rpm";

const VIEW_TITLES: Record<View, string> = {
  go: "Go modules",
  python: "Python packages",
  maven: "Maven artifacts",
  apt: "APT packages",
  rpm: "RPM packages",
};

let currentView: View = "go";
let selectedLeaf: HTMLElement | null = null;

function esc(value: unknown): string {
  const map: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return String(value).replace(/[&<>"']/g, (c) => map[c] ?? c);
}

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`missing element #${id}`);
  }
  return el;
}

function unitFor(kind: string): string {
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

const STREAM_LABELS: Record<string, string> = {
  go: "Go",
  python: "Python",
  maven: "Maven",
  apt: "APT",
  rpm: "RPM",
};

function streamLabel(name: string): string {
  return STREAM_LABELS[name] ?? name;
}

function renderStatus(status: ImportStatus): void {
  const banner = byId("banner");
  const streams = status.streams ?? [];
  const blocked = streams.filter((s) => (s.missing_ranges ?? []).length > 0);

  if (streams.length === 0) {
    banner.className = "banner ok";
    banner.textContent = "No bundles imported yet.";
  } else if (blocked.length > 0) {
    banner.className = "banner warn";
    const names = blocked.map((s) => streamLabel(s.stream)).join(", ");
    banner.innerHTML =
      `&#9888; Waiting on missing bundles in: ${esc(names)} ` +
      "&mdash; those streams pause until the gaps arrive; the rest keep importing independently.";
  } else {
    banner.className = "banner ok";
    banner.textContent = "✓ All streams up to date.";
  }

  renderStreamTable(streams);
}

function statusPill(ok: boolean): string {
  return ok
    ? '<span class="pill ok">up to date</span>'
    : '<span class="pill warn">waiting</span>';
}

function streamRow(s: StreamStatus): string {
  const missing = s.missing_ranges ?? [];
  const quarantined = s.quarantined_sequences ?? [];
  return (
    "<tr>" +
    `<td class="s-name">${esc(streamLabel(s.stream))}</td>` +
    `<td>#${esc(s.last_imported_sequence)}</td>` +
    `<td>#${esc(s.next_expected_sequence)}</td>` +
    `<td>${missing.length ? esc(missing.join(", ")) : "&mdash;"}</td>` +
    `<td>${quarantined.length ? esc(quarantined.join(", ")) : "&mdash;"}</td>` +
    `<td>${statusPill(missing.length === 0)}</td>` +
    "</tr>"
  );
}

function renderStreamTable(streams: StreamStatus[]): void {
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

async function fetchChildren(view: View, path: string): Promise<TreeNode[]> {
  const url = `/ui/api/tree?eco=${encodeURIComponent(view)}&path=${encodeURIComponent(path)}`;
  const resp = await fetch(url, { cache: "no-store" });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  const data = (await resp.json()) as TreeResponse;
  return data.nodes ?? [];
}

function setMessage(container: HTMLElement, text: string): void {
  container.textContent = "";
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = text;
  container.appendChild(p);
}

// renderNodes renders a level of the tree. repoEco is set only for the top level
// of the APT/RPM views, where each node is a mirrored repository that gets its
// own "Set me up" button.
function renderNodes(container: HTMLElement, nodes: TreeNode[], repoEco?: "apt" | "rpm"): void {
  container.textContent = "";
  if (nodes.length === 0) {
    setMessage(container, "empty");
    return;
  }
  for (const node of nodes) {
    container.appendChild(node.expandable ? expandableNode(node, repoEco) : leafNode(node));
  }
}

function leafNode(node: TreeNode): HTMLElement {
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

function renderDetail(detail: Detail): void {
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

async function selectLeaf(el: HTMLElement, node: TreeNode): Promise<void> {
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
    renderDetail((await resp.json()) as Detail);
  } catch (err) {
    setMessage(panel, `Failed to load details: ${(err as Error).message}`);
  }
}

function clearDetail(): void {
  selectedLeaf = null;
  setMessage(byId("detail"), "Select a version to see its details.");
}

// repoGuideButton is the per-repository "Set me up" button shown on an APT/RPM
// top-level node; it opens the guide for just that repository.
function repoGuideButton(eco: "apt" | "rpm", repoName: string): HTMLButtonElement {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "guide-toggle repo-guide";
  btn.textContent = "Set me up";
  btn.addEventListener("click", (ev) => {
    ev.preventDefault(); // don't toggle the enclosing <details>
    ev.stopPropagation();
    void openRepoGuide(eco, repoName);
  });
  return btn;
}

function expandableNode(node: TreeNode, repoEco?: "apt" | "rpm"): HTMLElement {
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
  if (repoEco) {
    summary.appendChild(repoGuideButton(repoEco, node.label));
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
      .catch((err: unknown) => {
        loaded = false; // allow retry on next open
        setMessage(children, `failed to load: ${(err as Error).message}`);
      });
  });

  return details;
}

function menuButtons(): NodeListOf<HTMLButtonElement> {
  return document.querySelectorAll<HTMLButtonElement>("nav button[data-view]");
}

async function loadTree(): Promise<void> {
  const tree = byId("tree");
  byId("treeTitle").textContent = VIEW_TITLES[currentView];
  // APT/RPM set up per repository, so the top "Set me up" button is hidden and
  // each repo node carries its own instead.
  const perRepo = currentView === "apt" || currentView === "rpm";
  byId("guideBtn").hidden = perRepo;
  clearDetail();
  setMessage(tree, "loading…");
  try {
    const nodes = await fetchChildren(currentView, "");
    renderNodes(tree, nodes, perRepo ? (currentView as "apt" | "rpm") : undefined);
  } catch (err) {
    setMessage(tree, `Failed to load tree: ${(err as Error).message}`);
  }
}

function setView(view: View): void {
  if (view === currentView) {
    return;
  }
  currentView = view;
  menuButtons().forEach((btn) => {
    btn.classList.toggle("active", btn.dataset["view"] === view);
  });
  void loadTree();
}

async function loadStatus(): Promise<void> {
  try {
    const resp = await fetch("/ui/api/overview", { cache: "no-store" });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const overview = (await resp.json()) as Overview;
    renderStatus(overview.status);
  } catch (err) {
    const banner = byId("banner");
    banner.className = "banner warn";
    banner.textContent = `Failed to load status: ${(err as Error).message}`;
  }
}

function refresh(): void {
  void loadStatus();
  void loadTree();
}

// ---------------------------------------------------------------------------
// "Set me up" guide: how to point go / pip clients at this mirror. Built from
// window.location.origin so the shown address is exactly what the operator is
// using (honoring any reverse proxy), and fully client-side so the page stays
// self-contained and air-gapped.
// ---------------------------------------------------------------------------

interface GuideBlock {
  label?: string;
  code: string;
}

interface GuideSection {
  heading: string;
  body: string;
  blocks: GuideBlock[];
  note?: string;
}

function serverBase(): string {
  return window.location.origin; // e.g. https://artigate-high.local (no trailing slash)
}

// A mirrored APT/RPM repository, from /ui/api/repos.
interface UIRepo {
  name: string;
  suite?: string;
  components?: string[];
  architectures?: string[];
  signed?: boolean;
}

async function fetchRepos(eco: View): Promise<UIRepo[]> {
  const resp = await fetch(`/ui/api/repos?eco=${encodeURIComponent(eco)}`, { cache: "no-store" });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  const data = (await resp.json()) as { repos?: UIRepo[] };
  return data.repos ?? [];
}

function goGuideSection(base: string): GuideSection {
  return {
    heading: "Go modules",
    body:
      "Point the Go toolchain at this mirror as its module proxy. The trailing " +
      "“,off” means Go builds only from what this mirror has imported and never " +
      "reaches out to the internet.",
    blocks: [
      { label: "Configure the client", code: `go env -w GOPROXY=${base},off\ngo env -w GOSUMDB=off` },
      { label: "Reproducible builds (CI)", code: "go build -mod=readonly ./...\ngo test -mod=readonly ./..." },
    ],
    note:
      "GOSUMDB is off because the public checksum database is unreachable when " +
      "air-gapped — rely on your committed go.sum. The mirror serves only " +
      "versions whose hashes were verified when their signed bundle was imported.",
  };
}

function pythonGuideSection(base: string): GuideSection {
  return {
    heading: "Python packages",
    body:
      "Use this mirror as pip's only index. Wheels-only is recommended for " +
      "air-gapped builds — no compilers or build backends are needed.",
    blocks: [
      { label: "/etc/pip.conf  (or ~/.config/pip/pip.conf)", code: `[global]\nindex-url = ${base}/simple/\ndisable-pip-version-check = true` },
      { label: "Install", code: "pip install --only-binary=:all: -r requirements.txt" },
    ],
    note:
      "Do not add --extra-index-url: mixing in another index reopens " +
      "dependency-confusion risk. This mirror is the single source of truth.",
  };
}

function mavenGuideSection(base: string): GuideSection {
  return {
    heading: "Java (Maven / Gradle)",
    body:
      "Point Maven or Gradle at this mirror as the only repository. It serves a " +
      "standard Maven 2 repository under /maven/.",
    blocks: [
      {
        label: "~/.m2/settings.xml (Maven)",
        code:
          "<settings>\n  <mirrors>\n    <mirror>\n      <id>artigate</id>\n      <mirrorOf>*</mirrorOf>\n" +
          `      <url>${base}/maven/</url>\n` +
          "    </mirror>\n  </mirrors>\n</settings>",
      },
      { label: "build.gradle(.kts) (Gradle)", code: `repositories {\n    maven { url = uri("${base}/maven/") }\n}` },
    ],
    note:
      "Do not add mavenCentral() or other external repositories — ArtiGate is the " +
      "single source of truth. Pin exact versions; SNAPSHOTs and ranges are not mirrored.",
  };
}

// aptGuideSection builds setup for one mirrored APT repository, filling in the
// suite/components/architectures it was actually mirrored with.
function aptGuideSection(base: string, repo: UIRepo): GuideSection {
  const suite = repo.suite || "<suite>";
  const comps = repo.components && repo.components.length ? repo.components.join(" ") : "<components>";
  const arches = repo.architectures && repo.architectures.length ? repo.architectures.join(" ") : "<arch>";
  // Signed repos are verified with ArtiGate's key; unsigned repos are trusted directly.
  const trust = repo.signed ? "Signed-By: /usr/share/keyrings/artigate-apt.gpg" : "Trusted: yes";
  return {
    heading: repo.name,
    body: "Point apt at this mirrored repository (deb822 .sources format).",
    blocks: [
      {
        label: "/etc/apt/sources.list.d/artigate.sources",
        code:
          "Types: deb\n" +
          `URIs: ${base}/apt/${repo.name}\n` +
          `Suites: ${suite}\n` +
          `Components: ${comps}\n` +
          `Architectures: ${arches}\n` +
          trust,
      },
    ],
    note: repo.signed
      ? "Use ArtiGate's high-side APT key (Signed-By), not the upstream vendor key."
      : "This repository is served unsigned, so apt trusts it directly (Trusted: yes). To verify instead, sign it with --apt-gpg-key on the high side.",
  };
}

// rpmGuideSection builds setup for one mirrored RPM repository.
function rpmGuideSection(base: string, repo: UIRepo): GuideSection {
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
        code:
          `[artigate-${repo.name}]\n` +
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

function flashButton(btn: HTMLButtonElement, text: string): void {
  if (btn.dataset["label"] === undefined) {
    btn.dataset["label"] = btn.textContent ?? "Copy";
  }
  btn.textContent = text;
  window.setTimeout(() => {
    btn.textContent = btn.dataset["label"] ?? "Copy";
  }, 1200);
}

function selectText(el: HTMLElement): void {
  const range = document.createRange();
  range.selectNodeContents(el);
  const sel = window.getSelection();
  sel?.removeAllRanges();
  sel?.addRange(range);
}

async function copyCode(text: string, codeEl: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  try {
    if (!navigator.clipboard) {
      throw new Error("clipboard unavailable");
    }
    await navigator.clipboard.writeText(text);
    flashButton(btn, "Copied ✓");
  } catch {
    selectText(codeEl); // insecure context: let the user copy manually
    flashButton(btn, "Press Ctrl+C");
  }
}

function codeBlock(block: GuideBlock): HTMLElement {
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

function guideSectionEl(section: GuideSection): HTMLElement {
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

function guideIntro(view: View, base: string): HTMLElement {
  const intro = document.createElement("p");
  intro.className = "guide-intro";
  intro.innerHTML =
    `Server address: <code>${esc(base)}</code>. Configure a client to pull ` +
    `${esc(VIEW_TITLES[view])} from this air-gapped mirror.`;
  return intro;
}

// renderGuideSections appends the sections: one full-width, several in two
// columns, or an empty note when there is nothing to show.
function renderGuideSections(container: HTMLElement, sections: GuideSection[]): void {
  if (sections.length === 0) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Nothing mirrored here yet.";
    container.appendChild(p);
    return;
  }
  if (sections.length === 1) {
    container.appendChild(guideSectionEl(sections[0]!));
    return;
  }
  const cols = document.createElement("div");
  cols.className = "guide-cols";
  for (const section of sections) {
    cols.appendChild(guideSectionEl(section));
  }
  container.appendChild(cols);
}

function guideDialog(): HTMLDialogElement {
  return byId("guide") as HTMLDialogElement;
}

// openGuide shows the whole-ecosystem setup for Go/Python/Maven (one config for
// the mirror). APT/RPM set up per repository instead, via openRepoGuide.
function openGuide(): void {
  const dialog = guideDialog();
  const body = byId("guideBody");
  const base = serverBase();
  byId("guideTitle").textContent = `Set up ${VIEW_TITLES[currentView]}`;
  body.textContent = "";
  body.appendChild(guideIntro(currentView, base));
  const section =
    currentView === "python"
      ? pythonGuideSection(base)
      : currentView === "maven"
        ? mavenGuideSection(base)
        : goGuideSection(base);
  renderGuideSections(body, [section]);
  if (!dialog.open) {
    dialog.showModal();
  }
}

// openRepoGuide shows setup for a single mirrored APT/RPM repository, fetched
// live so the URL and (for APT) suite/components/arch are exact.
async function openRepoGuide(eco: "apt" | "rpm", repoName: string): Promise<void> {
  const dialog = guideDialog();
  const body = byId("guideBody");
  const base = serverBase();
  byId("guideTitle").textContent = `Set up ${streamLabel(eco)} — ${repoName}`;
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
    const section = eco === "apt" ? aptGuideSection(base, repo) : rpmGuideSection(base, repo);
    renderGuideSections(body, [section]);
  } catch (err) {
    loading.textContent = `Failed to load repository: ${(err as Error).message}`;
  }
}

menuButtons().forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.dataset["view"] as View));
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
