// High-side dashboard. The import status is fetched once; the package trees are
// loaded lazily, one level at a time, from /ui/api/tree. Expanding a node fetches
// only that node's immediate children, so nothing large is transferred or
// rendered up front. The top menu switches between the Go and Python trees.

interface ImportStatus {
  last_imported_sequence: number;
  next_expected_sequence: number;
  highest_seen_sequence: number;
  blocking_missing_sequence?: number;
  missing_ranges: string[];
  quarantined_sequences: number[];
  ready_to_import: boolean;
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

type View = "go" | "python";

let currentView: View = "go";

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

function renderStatus(status: ImportStatus): void {
  const banner = byId("banner");
  const missing = status.missing_ranges ?? [];
  const quarantined = status.quarantined_sequences ?? [];

  if (missing.length > 0) {
    banner.className = "banner warn";
    banner.innerHTML =
      `&#9888; Missing bundles: ${esc(missing.join(", "))} ` +
      `&mdash; waiting for these before advancing past #${esc(status.next_expected_sequence)}`;
  } else {
    banner.className = "banner ok";
    banner.textContent = `✓ All bundles imported through #${status.last_imported_sequence}`;
  }

  byId("meta").innerHTML =
    `<span>Last imported: <b>#${esc(status.last_imported_sequence)}</b></span>` +
    `<span>Next expected: <b>#${esc(status.next_expected_sequence)}</b></span>` +
    `<span>Highest seen: <b>#${esc(status.highest_seen_sequence)}</b></span>` +
    `<span>Quarantined: <b>${quarantined.length ? esc(quarantined.join(", ")) : "none"}</b></span>`;
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

function renderNodes(container: HTMLElement, nodes: TreeNode[]): void {
  container.textContent = "";
  if (nodes.length === 0) {
    setMessage(container, "empty");
    return;
  }
  for (const node of nodes) {
    container.appendChild(node.expandable ? expandableNode(node) : leafNode(node));
  }
}

function leafNode(node: TreeNode): HTMLElement {
  const div = document.createElement("div");
  div.className = "leaf";
  div.textContent = node.label;
  return div;
}

function expandableNode(node: TreeNode): HTMLElement {
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
  byId("treeTitle").textContent = currentView === "go" ? "Go modules" : "Python packages";
  setMessage(tree, "loading…");
  try {
    const nodes = await fetchChildren(currentView, "");
    renderNodes(tree, nodes);
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

menuButtons().forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.dataset["view"] as View));
});
byId("refresh").addEventListener("click", refresh);

refresh();
