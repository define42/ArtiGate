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

// ImageLayer is one build step of a container image (from its config history):
// the command it ran and, for steps that produced a filesystem layer, that
// layer's size and digest. empty marks metadata-only steps (ENV, CMD, …).
interface ImageLayer {
  command: string;
  size?: string;
  digest?: string;
  empty?: boolean;
}

interface Detail {
  title: string;
  subtitle?: string;
  fields: DetailField[];
  go_mod?: string;
  // Host-relative pull reference; the panel prepends this host and renders a
  // prominent click-to-copy button (containers only).
  copy_ref?: string;
  // Container build-history breakdown, shown in a box below the detail panel.
  layers?: ImageLayer[];
}

type View = "overview" | "go" | "python" | "maven" | "npm" | "apt" | "rpm" | "containers" | "hf";

// RepoEco are the views whose content is set up per mirrored repository (each
// top-level tree node gets its own "Set me up" button).
type RepoEco = "apt" | "rpm" | "containers";

const VIEW_TITLES: Record<View, string> = {
  overview: "Overview",
  go: "Go modules",
  python: "Python packages",
  maven: "Maven artifacts",
  npm: "NPM packages",
  apt: "APT packages",
  rpm: "RPM packages",
  containers: "Container images",
  hf: "AI models (Hugging Face)",
};

let currentView: View = "overview";
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
  npm: "NPM",
  apt: "APT",
  rpm: "RPM",
  containers: "Containers",
  hf: "AI Models",
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
function renderNodes(container: HTMLElement, nodes: TreeNode[], repoEco?: RepoEco): void {
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
function renderLayers(layers: ImageLayer[]): void {
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

function layerRow(layer: ImageLayer): HTMLElement {
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
  } else {
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
function shortDigest(digest: string): string {
  const hex = digest.replace(/^sha256:/, "");
  return `sha256:${hex.slice(0, 12)}`;
}

// copyRefButton renders a prominent click-to-copy control for a full,
// host-qualified image reference — exactly what `docker pull` / `podman pull`
// takes. Clicking anywhere on it copies the reference; only the "Copy" tag
// flashes so the reference text stays visible.
function copyRefButton(ref: string): HTMLButtonElement {
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
      } catch {
        selectText(text); // insecure context: let the user copy manually
        flashButton(tag, "Press Ctrl+C");
      }
    })();
  });
  return btn;
}

async function selectLeaf(el: HTMLElement, node: TreeNode): Promise<void> {
  if (selectedLeaf) {
    selectedLeaf.classList.remove("selected");
  }
  selectedLeaf = el;
  el.classList.add("selected");

  const panel = byId("detail");
  setMessage(panel, "loading…");
  hideLayers();
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

// hideLayers clears and hides the layers box (no selection, a non-container
// leaf, or a failed load).
function hideLayers(): void {
  const box = document.getElementById("layers");
  if (box) {
    box.hidden = true;
    box.textContent = "";
  }
}

function clearDetail(): void {
  selectedLeaf = null;
  setMessage(byId("detail"), "Select a version to see its details.");
  hideLayers();
}

// repoGuideButton is the per-repository "Set me up" button shown on an APT/RPM
// top-level node; it opens the guide for just that repository.
function repoGuideButton(eco: RepoEco, repoName: string): HTMLButtonElement {
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

function expandableNode(node: TreeNode, repoEco?: RepoEco): HTMLElement {
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
  // each repo node carries its own instead. (Containers group by upstream
  // registry at the top level, so they keep the whole-ecosystem button.)
  const perRepo = currentView === "apt" || currentView === "rpm";
  byId("guideBtn").hidden = perRepo;
  clearDetail();
  setMessage(tree, "loading…");
  try {
    const nodes = await fetchChildren(currentView, "");
    renderNodes(tree, nodes, perRepo ? (currentView as RepoEco) : undefined);
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
  // The Overview page carries the import-status table; the ecosystem views carry
  // the package tree.
  const overview = view === "overview";
  byId("view-overview").hidden = !overview;
  byId("view-tree").hidden = overview;
  if (overview) {
    void loadStatus();
  } else {
    void loadTree();
  }
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
  if (currentView !== "overview") {
    void loadTree();
  }
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
  chooser?: GuideChooser;
}

// GuideChooser renders choice rows above a section's code blocks; changing a
// choice re-renders the blocks. APT uses it to ask which release the client
// machine runs (radio row, shown when a mirror carries several releases) and
// which components the machine should enable (checkbox row from togglesFor,
// all enabled to start; the last enabled one is locked so the stanza never
// goes empty).
interface GuideChooser {
  prompt: string;
  options: { label: string; sub?: string }[];
  togglesFor?: (index: number) => { prompt: string; items: string[] };
  blocksFor: (index: number, enabled: string[]) => GuideBlock[];
}

function serverBase(): string {
  return window.location.origin; // e.g. https://artigate-high.local (no trailing slash)
}

// A mirrored APT/RPM/container/AI-model repository, from /ui/api/repos.
// kind === "repo" marks an AI-model full repository snapshot (consumed via
// HF_ENDPOINT) as opposed to a GGUF model (pulled with Ollama).
interface UIRepo {
  name: string;
  suites?: AptSuite[];
  tags?: string[];
  signed?: boolean;
  kind?: string;
}

// One suite of an APT mirror with the components/architectures it holds.
interface AptSuite {
  name: string;
  components?: string[];
  architectures?: string[];
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
      { label: "Configure the client", code: `go env -w GOPROXY=${base}/go,off\ngo env -w GOSUMDB=off` },
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

function npmGuideSection(base: string): GuideSection {
  return {
    heading: "NPM packages",
    body:
      "Use this mirror as npm's only registry. It serves the npm registry API " +
      "under /npm/, with integrity hashes regenerated from the imported tarballs.",
    blocks: [
      {
        label: "~/.npmrc  (or /etc/npmrc, or per-project .npmrc)",
        code: `registry=${base}/npm/\naudit=false\nfund=false\nupdate-notifier=false`,
      },
      { label: "Install", code: "npm install" },
    ],
    note:
      "audit is off because the security-advisory endpoint needs the public " +
      "registry. Do not mix in another registry — this mirror is the single " +
      "source of truth. Only registry tarballs are mirrored (no git dependencies).",
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

// aptSuiteBase returns the release a suite belongs to: "noble-updates" and
// "noble-security" group under "noble"; "resolute" stands alone.
function aptSuiteBase(name: string): string {
  const i = name.indexOf("-");
  return i > 0 ? name.slice(0, i) : name;
}

// aptSuiteGroups buckets a mirror's suites by release. Vendor repos like
// download.docker.com carry one suite per Ubuntu/Debian release (noble,
// resolute, bookworm…) of which a machine should use exactly one; archive
// repos carry complementary suites of one release (noble, noble-updates,
// noble-security) that belong together.
function aptSuiteGroups(suites: AptSuite[]): { base: string; suites: AptSuite[] }[] {
  const byBase = new Map<string, AptSuite[]>();
  for (const s of suites) {
    const base = aptSuiteBase(s.name);
    const group = byBase.get(base);
    if (group) {
      group.push(s);
    } else {
      byBase.set(base, [s]);
    }
  }
  return [...byBase.entries()]
    .map(([base, ss]) => ({ base, suites: ss }))
    .sort((a, b) => a.base.localeCompare(b.base));
}

// aptSourcesFile renders the .sources stanzas for the chosen suites. Suites
// with identical components/architectures share one stanza; a deb822 stanza
// applies its Components to every suite in it, so suites collected with
// different settings get their own stanza in the same file.
function aptSourcesFile(base: string, repoName: string, suites: AptSuite[], trust: string): string {
  const bySig = new Map<string, AptSuite[]>();
  for (const s of suites) {
    const sig = `${(s.components ?? []).join(" ")}|${(s.architectures ?? []).join(" ")}`;
    const group = bySig.get(sig);
    if (group) {
      group.push(s);
    } else {
      bySig.set(sig, [s]);
    }
  }
  const stanza = (group: AptSuite[]): string => {
    const first = group[0]!;
    const comps = first.components && first.components.length ? first.components.join(" ") : "<components>";
    const arches = first.architectures && first.architectures.length ? first.architectures.join(" ") : "<arch>";
    return (
      "Types: deb\n" +
      `URIs: ${base}/apt/${repoName}\n` +
      `Suites: ${group.map((s) => s.name).join(" ")}\n` +
      `Components: ${comps}\n` +
      `Architectures: ${arches}\n` +
      trust
    );
  };
  if (bySig.size === 0) {
    return stanza([{ name: "<suite>" }]);
  }
  return [...bySig.values()].map(stanza).join("\n\n");
}

// aptGroupComponents returns the distinct components of a suite group, in
// first-occurrence order across its suites.
function aptGroupComponents(suites: AptSuite[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of suites) {
    for (const c of s.components ?? []) {
      if (!seen.has(c)) {
        seen.add(c);
        out.push(c);
      }
    }
  }
  return out;
}

// filterAptComponents restricts each suite to the enabled components and drops
// suites left with none (a stanza without components would be invalid).
function filterAptComponents(suites: AptSuite[], enabled: string[]): AptSuite[] {
  const keep = new Set(enabled);
  const out: AptSuite[] = [];
  for (const s of suites) {
    const comps = (s.components ?? []).filter((c) => keep.has(c));
    if (comps.length === 0) {
      continue;
    }
    const filtered: AptSuite = { name: s.name, components: comps };
    if (s.architectures) {
      filtered.architectures = s.architectures;
    }
    out.push(filtered);
  }
  return out;
}

// aptGuideSection builds setup for one mirrored APT repository from its live
// per-suite data. When the mirror carries suites for more than one release, a
// radio row asks which release the client machine runs and the stanza is built
// for exactly that release's suites — mixing releases would make a foreign
// release's build apt's install candidate. When the chosen release has more
// than one component, a checkbox row lets the machine opt out of channel
// components (e.g. Docker's "test" pre-releases); everything starts enabled.
function aptGuideSection(base: string, repo: UIRepo): GuideSection {
  // Signed repos are verified with ArtiGate's key; unsigned repos are trusted directly.
  const trust = repo.signed ? "Signed-By: /usr/share/keyrings/artigate-apt.gpg" : "Trusted: yes";
  const signNote = repo.signed
    ? "Use ArtiGate's high-side APT key (Signed-By), not the upstream vendor key."
    : "This repository is served unsigned, so apt trusts it directly (Trusted: yes). To verify instead, sign it with --apt-gpg-key on the high side.";
  const groups = aptSuiteGroups(repo.suites ?? []);
  const fileLabel = "/etc/apt/sources.list.d/artigate.sources";
  const blocksFor = (i: number, enabled: string[]): GuideBlock[] => [
    {
      label: fileLabel,
      code: aptSourcesFile(base, repo.name, filterAptComponents(groups[i]?.suites ?? [], enabled), trust),
    },
  ];
  const multiRelease = groups.length > 1;
  const multiComponent = groups.some((g) => aptGroupComponents(g.suites).length > 1);
  if (!multiRelease && !multiComponent) {
    return {
      heading: repo.name,
      body: "Point apt at this mirrored repository (deb822 .sources format).",
      blocks: blocksFor(0, aptGroupComponents(groups[0]?.suites ?? [])),
      note: signNote,
    };
  }
  const componentNote = multiComponent
    ? " Untick components this machine should not use — a channel component like Docker's \"test\" carries pre-releases that would otherwise become apt's upgrade candidates. Unticking only edits this stanza; the mirror keeps serving every component."
    : "";
  return {
    heading: repo.name,
    body: multiRelease
      ? "This mirror carries suites for more than one release. Pick the release " +
        "this machine runs — its codename is `lsb_release -cs` (or " +
        "VERSION_CODENAME in /etc/os-release)."
      : "Point apt at this mirrored repository (deb822 .sources format).",
    blocks: [],
    chooser: {
      prompt: "Which release does this machine run?",
      options: groups.map((g) => {
        const opt: { label: string; sub?: string } = { label: g.base };
        if (g.suites.length > 1) {
          opt.sub = g.suites.map((s) => s.name).join(", ");
        }
        return opt;
      }),
      togglesFor: (i) => ({
        prompt: "Components for this machine:",
        items: aptGroupComponents(groups[i]?.suites ?? []),
      }),
      blocksFor,
    },
    note: signNote + componentNote,
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

// flashButton briefly swaps an element's text (a copy button, or just the
// "Copy" tag of the reference control) and restores it.
function flashButton(btn: HTMLElement, text: string): void {
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

  const blocksEl = document.createElement("div");
  const renderBlocks = (blocks: GuideBlock[]): void => {
    blocksEl.textContent = "";
    for (const block of blocks) {
      blocksEl.appendChild(codeBlock(block));
    }
  };
  if (section.chooser) {
    el.appendChild(guideChooserEl(section.chooser, renderBlocks)); // renders the initial blocks
  } else {
    renderBlocks(section.blocks);
  }
  el.appendChild(blocksEl);

  if (section.note) {
    const note = document.createElement("p");
    note.className = "note";
    note.textContent = section.note;
    el.appendChild(note);
  }
  return el;
}

let guideChoiceSeq = 0;

// guideChooserEl renders a chooser's radio row (only when there is more than
// one option) and its per-option checkbox row (only when there is more than
// one toggle item), keeping the selection state and re-rendering the owning
// section's code blocks via onPick on every change. It emits the initial
// blocks before returning.
function guideChooserEl(chooser: GuideChooser, onPick: (blocks: GuideBlock[]) => void): HTMLElement {
  const wrap = document.createElement("div");
  let selected = 0;
  let enabled: string[] = [];
  const togglesEl = document.createElement("div");

  const emit = (): void => onPick(chooser.blocksFor(selected, enabled));

  // renderToggles rebuilds the checkbox row for the current option; every
  // item starts enabled, and the last enabled one is locked (disabled) so the
  // selection can never become empty.
  const renderToggles = (): void => {
    togglesEl.textContent = "";
    const toggles = chooser.togglesFor?.(selected);
    enabled = toggles ? [...toggles.items] : [];
    if (!toggles || toggles.items.length <= 1) {
      return;
    }
    const prompt = document.createElement("div");
    prompt.className = "code-label";
    prompt.textContent = toggles.prompt;
    togglesEl.appendChild(prompt);

    const row = document.createElement("div");
    row.className = "guide-choices";
    const boxes: HTMLInputElement[] = [];
    const lockLast = (): void => {
      for (const box of boxes) {
        box.disabled = box.checked && enabled.length === 1;
      }
    };
    for (const item of toggles.items) {
      const lbl = document.createElement("label");
      lbl.className = "guide-choice";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = true;
      box.addEventListener("change", () => {
        // Keep enabled in the items' original order.
        const keep = new Set(enabled.filter((x) => x !== item));
        if (box.checked) {
          keep.add(item);
        }
        enabled = toggles.items.filter((x) => keep.has(x));
        lockLast();
        emit();
      });
      boxes.push(box);
      lbl.appendChild(box);
      lbl.appendChild(document.createTextNode(item));
      row.appendChild(lbl);
    }
    togglesEl.appendChild(row);
    lockLast();
  };

  if (chooser.options.length > 1) {
    const prompt = document.createElement("div");
    prompt.className = "code-label";
    prompt.textContent = chooser.prompt;
    wrap.appendChild(prompt);

    const row = document.createElement("div");
    row.className = "guide-choices";
    const group = `guide-choice-${++guideChoiceSeq}`;
    chooser.options.forEach((opt, i) => {
      const lbl = document.createElement("label");
      lbl.className = "guide-choice";
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = group;
      radio.checked = i === 0;
      radio.addEventListener("change", () => {
        selected = i;
        renderToggles();
        emit();
      });
      lbl.appendChild(radio);
      lbl.appendChild(document.createTextNode(opt.label));
      if (opt.sub) {
        const sub = document.createElement("span");
        sub.className = "sub";
        sub.textContent = opt.sub;
        lbl.appendChild(sub);
      }
      row.appendChild(lbl);
    });
    wrap.appendChild(row);
  }
  wrap.appendChild(togglesEl);
  renderToggles();
  emit();
  return wrap;
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

// containersGuideSection shows how to pull from the mirrored OCI registry.
// Pull names embed the upstream registry (docker.io/..., ghcr.io/...), so the
// example commands are built from what is actually mirrored. When the mirror
// is served over plain HTTP it also renders the exact /etc/docker/daemon.json
// insecure-registries block, with this host and port filled in.
function containersGuideSection(repos: UIRepo[]): GuideSection {
  const host = window.location.host; // host:port, honoring any reverse proxy
  const secure = window.location.protocol === "https:";
  const pullName = (r: UIRepo): string =>
    `${host}/${r.name}${r.tags && r.tags.length ? `:${r.tags[0]}` : ""}`;
  const pulls = repos
    .slice(0, 8)
    .map((r) => `docker pull ${pullName(r)}`)
    .join("\n");
  // The full daemon.json Docker needs to trust a plain-HTTP registry. Built
  // with JSON.stringify so it is always valid JSON with the live host:port.
  const daemonJSON = JSON.stringify({ "insecure-registries": [host] }, null, 2);
  const blocks: GuideBlock[] = [
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
    body:
      "This mirror is a read-only OCI registry (linux/amd64 only). Each " +
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
function hfGuideSection(repos: UIRepo[]): GuideSection {
  const host = window.location.host; // host:port, honoring any reverse proxy
  const base = serverBase();
  const secure = window.location.protocol === "https:";
  const insecure = secure ? "" : "--insecure ";
  const gguf = repos.filter((r) => r.kind !== "repo");
  const full = repos.filter((r) => r.kind === "repo");

  // Every section always renders — the guide teaches the workflows even
  // before anything is mirrored — but sections whose content is not mirrored
  // yet are labeled as examples.
  const example = (mirrored: boolean): string => (mirrored ? "" : " (example — none mirrored yet)");

  const pullName = (r: UIRepo): string =>
    `${host}/${r.name}${r.tags && r.tags.length ? `:${r.tags[0]}` : ""}`;
  const pulls = gguf
    .slice(0, 8)
    .map((r) => `ollama pull ${insecure}${pullName(r)}`)
    .join("\n");
  // One concrete model+variant / repository for the runnable examples.
  const firstGguf = gguf.length ? gguf[0]! : undefined;
  const ggufName = firstGguf ? firstGguf.name : "unsloth/gpt-oss-20b-GGUF";
  const ggufTag = firstGguf && firstGguf.tags && firstGguf.tags.length ? firstGguf.tags[0]! : "Q4_0";
  const file = `${ggufName.split("/")[1] ?? "model"}-${ggufTag}.gguf`;
  const repoName = full.length ? full[0]!.name : "openai/gpt-oss-20b";

  const blocks: GuideBlock[] = [
    {
      label: `Ollama — pull and run a GGUF model${example(gguf.length > 0)}`,
      code:
        (pulls || `ollama pull ${insecure}${host}/${ggufName}:${ggufTag}`) +
        `\nollama run ${host}/${ggufName}:${ggufTag}`,
    },
    {
      label: `vLLM / transformers / hf — full repositories via the Hub API${example(full.length > 0)}`,
      code:
        `export HF_ENDPOINT=${base}\n` +
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
    body:
      "Three ways to consume this mirror: Ollama pulls GGUF models over its own " +
      "registry protocol (pull name: <this-host>/<org>/<model>:<variant>); " +
      "vLLM, transformers, and hf consume full repository snapshots through " +
      "the Hub API by pointing HF_ENDPOINT here; raw GGUF files download from " +
      "/hf/ for llama.cpp.",
    blocks,
    note: notes.join(" "),
  };
}

// openGuide shows the whole-ecosystem setup for Go/Python/Maven/containers
// (one config for the mirror). APT/RPM set up per repository instead, via
// openRepoGuide.
function openGuide(): void {
  const dialog = guideDialog();
  const body = byId("guideBody");
  const base = serverBase();
  byId("guideTitle").textContent = `Set up ${VIEW_TITLES[currentView]}`;
  body.textContent = "";
  body.appendChild(guideIntro(currentView, base));
  if (currentView === "containers" || currentView === "hf") {
    // Built from the live repo list so the pull commands are copy-paste ready.
    const view = currentView;
    const section = (repos: UIRepo[]): GuideSection =>
      view === "hf" ? hfGuideSection(repos) : containersGuideSection(repos);
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
  } else {
    const section =
      currentView === "python"
        ? pythonGuideSection(base)
        : currentView === "maven"
          ? mavenGuideSection(base)
          : currentView === "npm"
            ? npmGuideSection(base)
            : goGuideSection(base);
    renderGuideSections(body, [section]);
  }
  if (!dialog.open) {
    dialog.showModal();
  }
}

// openRepoGuide shows setup for a single mirrored APT/RPM repository, fetched
// live so the URL and (for APT) suite/components/arch are exact.
async function openRepoGuide(eco: RepoEco, repoName: string): Promise<void> {
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
    const section =
      eco === "apt"
        ? aptGuideSection(base, repo)
        : eco === "rpm"
          ? rpmGuideSection(base, repo)
          : containersGuideSection([repo]);
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
