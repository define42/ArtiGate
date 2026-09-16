import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const script = readFileSync(new URL("app.js", import.meta.url), "utf8");
const lowSource = readFileSync(new URL("../ui_low.go", import.meta.url), "utf8");

function containerStatusUI() {
  const defaults = { Lifecycle: "active", State: "all", Freshness: "all", StaleAfter: "24h" };
  const fields = ["Summary", "Records", "Refresh", "Previous", "Next", "Repository", ...Object.keys(defaults)];
  const elements = new Map(fields.map(field => ["ctrDiscovery" + field, {
    textContent: "", innerHTML: "", disabled: false, value: defaults[field] || "",
    setAttribute(name, value) { this[name] = value; },
  }]));
  const pending = [];
  const context = vm.createContext({
    document: { getElementById: id => elements.get(id) },
    fetch: url => new Promise((resolve, reject) => pending.push({ url, resolve, reject })),
    collectedMsg: () => "Collected image.",
    URLSearchParams,
  });
  const escape = lowSource.split("\n").find(line => line.startsWith("function esc("));
  const helpers = lowSource.slice(lowSource.indexOf("function containerCollectResult("), lowSource.indexOf("async function scheduleContainers("));
  vm.runInContext(escape + "\n" + helpers, context);
  return { context, elements, pending };
}

test("container discovery never turns a partial deduplicated collect into success", () => {
  const { context } = containerStatusUI();
  const result = context.containerCollectResult({ skipped: true, container_discovery: [{ discovery: { state: "incomplete", issues: [{ code: "artifact_fetch" }] } }] });
  assert.equal(result.cls, "warn");
  assert.match(result.msg, /No new content/);
  assert.match(result.msg, /Retry collection/);
  assert.match(result.msg, /required child download failed/);
  assert.equal(context.containerCollectResult({ skipped: true, container_discovery: [{ discovery: { state: "complete" } }] }).cls, "ok");
});

test("container discovery renders legacy state as unknown and escapes stored values", () => {
  const { context } = containerStatusUI();
  assert.match(context.containerDiscoveryHTML({}), /<summary>Unknown/);
  const hostile = '<script>alert("secret")</script>';
  const html = context.containerDiscoveryHTML({ registry: hostile, repository: hostile, digest: hostile, tags: [hostile], discovery: { state: "incomplete", checked_at: hostile, last_success_at: hostile, issues: [{ code: hostile, subject: hostile }] } });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /could not be completed/);
});

test("container discovery refresh rejects stale results and keeps existing data on failure", async () => {
  const { context, elements, pending } = containerStatusUI();
  const old = context.loadContainerDiscovery();
  const current = context.loadContainerDiscovery();
  pending[1].resolve({ ok: true, json: async () => ({ records: [{ repository: "current", discovery: { state: "incomplete" } }], total: 1 }) });
  await current;
  pending[0].resolve({ ok: true, json: async () => ({ records: [] }) });
  await old;
  const box = elements.get("ctrDiscoveryRecords");
  assert.match(box.innerHTML, /current/);
  assert.match(elements.get("ctrDiscoverySummary").textContent, /Showing 1–1 of 1/);
  const failed = context.loadContainerDiscovery();
  pending[2].reject(new Error("private upstream URL"));
  await failed;
  assert.match(box.innerHTML, /current/);
  assert.equal(elements.get("ctrDiscoverySummary").textContent, "Discovery status could not be loaded. Try refreshing. Previous results remain displayed.");
  assert.equal(elements.get("ctrDiscoveryRefresh").disabled, false);
});

test("container discovery pages beyond 100 observations and navigates back", async () => {
  const { context, elements, pending } = containerStatusUI();
  const page = async (direction, start, count, cursor) => {
    const promise = context.loadContainerDiscovery(direction);
    const request = pending.at(-1);
    request.resolve({ ok: true, json: async () => ({ total: 121, next_cursor: cursor, records: Array.from({ length: count }, (_, i) => ({ repository: "item-" + (start + i), lifecycle: "active", freshness: "stale", discovery: { state: "complete" } })) }) });
    await promise;
    return new URL(request.url, "http://localhost").searchParams;
  };
  const first = await page("reset", 0, 50, "cursor-1");
  assert.equal(first.get("limit"), "50");
  assert.equal(first.get("lifecycle"), "active");
  assert.equal(elements.get("ctrDiscoveryPrevious").disabled, true);
  assert.equal((await page("next", 50, 50, "cursor-2")).get("cursor"), "cursor-1");
  assert.equal((await page("next", 100, 21, "")).get("cursor"), "cursor-2");
  assert.match(elements.get("ctrDiscoverySummary").textContent, /Showing 101–121 of 121/);
  assert.match(elements.get("ctrDiscoveryRecords").innerHTML, /item-120/);
  assert.match(elements.get("ctrDiscoveryRecords").innerHTML, /Current reference · Stale/);
  assert.equal(elements.get("ctrDiscoveryNext").disabled, true);
  assert.equal((await page("previous", 50, 50, "cursor-2")).get("cursor"), "cursor-1");
  assert.match(elements.get("ctrDiscoverySummary").textContent, /Showing 51–100 of 121/);
});

test("container discovery resets pagination when filters change or the snapshot expires", async () => {
  const { context, elements, pending } = containerStatusUI();
  let promise = context.loadContainerDiscovery();
  pending[0].resolve({ ok: true, json: async () => ({ total: 2, next_cursor: "old-page", records: [{}] }) });
  await promise;
  elements.get("ctrDiscoveryRepository").value = "docker.io/library/alpine";
  promise = context.loadContainerDiscovery("next");
  let query = new URL(pending[1].url, "http://localhost").searchParams;
  assert.equal(query.get("repository"), "docker.io/library/alpine");
  assert.equal(query.has("cursor"), false);
  pending[1].resolve({ ok: true, json: async () => ({ total: 2, next_cursor: "new-page", records: [{}] }) });
  await promise;
  promise = context.loadContainerDiscovery("next");
  pending[2].resolve({ ok: false, status: 409 });
  await flush();
  query = new URL(pending[3].url, "http://localhost").searchParams;
  assert.equal(query.has("cursor"), false);
  pending[3].resolve({ ok: true, json: async () => ({ total: 1, records: [{ repository: "updated" }] }) });
  await promise;
  assert.match(elements.get("ctrDiscoverySummary").textContent, /Observations changed; returned to the first page/);
  assert.match(elements.get("ctrDiscoveryRecords").innerHTML, /updated/);
  assert.equal(elements.get("ctrDiscoveryPrevious").disabled, true);
  assert.equal(elements.get("ctrDiscoveryRecords")["aria-busy"], "false");
});

// Only the DOM operations used by tree/detail rendering are needed here. Run
// the shipped script unchanged, including its event listeners and startup.
class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.parentElement = null;
    this.className = "";
    this.dataset = {};
    this.style = {};
    this.value = "";
    this.hidden = false;
    this.listeners = new Map();
    this.text = "";
    this.classList = {
      contains: (name) => this.className.split(/\s+/).includes(name),
      add: (name) => this.classList.toggle(name, true),
      remove: (name) => this.classList.toggle(name, false),
      toggle: (name, enabled) => {
        const classes = new Set(this.className.split(/\s+/).filter(Boolean));
        if (enabled ?? !classes.has(name)) classes.add(name);
        else classes.delete(name);
        this.className = [...classes].join(" ");
      },
    };
  }

  set textContent(value) {
    this.text = String(value);
    for (const child of this.children) child.parentElement = null;
    this.children = [];
  }

  get textContent() {
    return this.text + this.children.map((child) => child.textContent).join("");
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  setAttribute(name, value) {
    this[name] = value;
  }

  addEventListener(event, callback) {
    const callbacks = this.listeners.get(event) ?? [];
    callbacks.push(callback);
    this.listeners.set(event, callbacks);
  }

  dispatch(event) {
    for (const callback of this.listeners.get(event) ?? []) {
      callback({ target: this, preventDefault() {}, stopPropagation() {} });
    }
  }

  find(className) {
    if (this.classList.contains(className)) return this;
    for (const child of this.children) {
      const found = child.find(className);
      if (found) return found;
    }
    return null;
  }
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// One event-loop turn drains both fetch and response.json continuations.
const flush = () => new Promise((resolve) => setImmediate(resolve));

function dashboard() {
  const ids = [
    "tree", "treeTitle", "detail", "layers", "guideBtn", "guide", "guideClose",
    "refresh", "search", "view-overview", "view-tree", "banner", "heartbeat", "meta",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  const menus = ["overview", "go", "python", "uploads"].map((view) => {
    const button = new Element("button");
    button.dataset.view = view;
    return button;
  });
  const pending = [];
  const timers = new Map();
  let nextTimer = 0;
  const context = vm.createContext({
    document: {
      getElementById: (id) => elements[id] ?? null,
      querySelectorAll: () => menus,
      createElement: (tag) => new Element(tag),
    },
    window: {
      location: { host: "mirror.test", origin: "https://mirror.test" },
      confirm: () => true,
      setTimeout: (callback) => { timers.set(++nextTimer, callback); return nextTimer; },
      clearTimeout: (id) => timers.delete(id),
    },
    fetch: (url, options) => {
      if (url === "/ui/api/overview") {
        return Promise.resolve({ ok: true, json: async () => ({ status: { streams: [] } }) });
      }
      const request = { url, options, ...deferred() };
      request.respond = (data) => request.resolve({ ok: true, json: async () => data });
      pending.push(request);
      return request.promise;
    },
  });
  vm.runInContext(script, context, { filename: "app.js" });
  return {
    ...elements,
    navigate(view) { menus.find((button) => button.dataset.view === view).dispatch("click"); },
    searchFor(query) {
      elements.search.value = query;
      elements.search.dispatch("input");
      const callbacks = [...timers.values()];
      timers.clear();
      callbacks.forEach((callback) => callback());
    },
    take(path, params = {}) {
      const request = pending.shift();
      assert.ok(request, `expected request for ${path}`);
      const url = new URL(request.url, "https://mirror.test");
      assert.equal(url.pathname, path);
      for (const [key, value] of Object.entries(params)) assert.equal(url.searchParams.get(key), value);
      return request;
    },
  };
}

const node = (label, expandable = false) => ({ label, path: label, kind: expandable ? "project" : "file", expandable });
const detail = (title) => ({ title, fields: [], downloads: [{ label: title, url: `/uploads/${title}` }] });
const results = ["success", "network error", "HTTP error", "delayed JSON", "JSON error"];

// Delay either the HTTP response or its body so checking identity only before
// response.json() cannot make these tests pass.
async function hold(request, outcome, data) {
  if (outcome === "delayed JSON" || outcome === "JSON error") {
    const body = deferred();
    request.resolve({ ok: true, json: () => body.promise });
    await flush();
    return () => outcome === "JSON error" ? body.reject(new Error("invalid JSON")) : body.resolve(data);
  }
  if (outcome === "network error") return () => request.reject(new Error("connection lost"));
  if (outcome === "HTTP error") return () => request.resolve({ ok: false, status: 503 });
  return () => request.respond(data);
}

async function uploadTree(ui) {
  ui.navigate("uploads");
  ui.take("/ui/api/tree", { eco: "uploads" }).respond({ nodes: [node("files/a.txt"), node("files/b.txt")] });
  await flush();
  return ui.tree.children;
}

for (const outcome of results) {
  test(`Go → Python discards old tree ${outcome} and expands Python`, async () => {
    const ui = dashboard();
    ui.navigate("go");
    const finishOld = await hold(ui.take("/ui/api/tree", { eco: "go" }), outcome, { nodes: [node("old-go", true)] });
    ui.navigate("python");
    ui.take("/ui/api/tree", { eco: "python" }).respond({ nodes: [node("requests", true)] });
    await flush();
    finishOld();
    await flush();
    assert.equal(ui.treeTitle.textContent, "Python packages");
    assert.equal(ui.tree.textContent, "requests");
    const project = ui.tree.children[0];
    project.open = true;
    project.dispatch("toggle");
    ui.take("/ui/api/tree", { eco: "python", path: "requests" }).respond({ nodes: [node("requests.whl")] });
    await flush();
    assert.match(ui.tree.textContent, /requests.whl/);
  });

  test(`upload selection B keeps its details and delete action after A ${outcome}`, async () => {
    const ui = dashboard();
    const [a, b] = await uploadTree(ui);
    a.dispatch("click");
    const finishOld = await hold(ui.take("/ui/api/detail", { path: "files/a.txt" }), outcome, detail("a.txt"));
    b.dispatch("click");
    ui.take("/ui/api/detail", { path: "files/b.txt" }).respond(detail("b.txt"));
    await flush();
    finishOld();
    await flush();
    assert.equal(a.classList.contains("selected"), false);
    assert.equal(b.classList.contains("selected"), true);
    assert.equal(ui.detail.children[0].textContent, "b.txt");
    assert.equal(ui.detail.find("download-link").download, "b.txt");
    ui.detail.find("delete-upload").dispatch("click");
    const deletion = ui.take("/admin/uploads/delete");
    assert.equal(deletion.options.method, "POST");
    assert.deepEqual(JSON.parse(deletion.options.body), { folder: "files", name: "b.txt" });
  });
}

for (const transition of ["refresh", "away and back"]) {
  test(`tree ${transition} rejects an earlier response for the same ecosystem`, async () => {
    const ui = dashboard();
    ui.navigate("go");
    const old = ui.take("/ui/api/tree", { eco: "go" });
    if (transition === "refresh") ui.refresh.dispatch("click");
    else {
      ui.navigate("python");
      ui.take("/ui/api/tree", { eco: "python" }).respond({ nodes: [] });
      ui.navigate("go");
    }
    ui.take("/ui/api/tree", { eco: "go" }).respond({ nodes: [node("new-go")] });
    await flush();
    old.respond({ nodes: [node("old-go")] });
    await flush();
    assert.equal(ui.tree.textContent, "new-go");
  });
}

test("selecting A → B → A rejects both earlier detail requests", async () => {
  const ui = dashboard();
  const [a, b] = await uploadTree(ui);
  a.dispatch("click");
  const oldA = ui.take("/ui/api/detail", { path: "files/a.txt" });
  b.dispatch("click");
  const oldB = ui.take("/ui/api/detail", { path: "files/b.txt" });
  a.dispatch("click");
  ui.take("/ui/api/detail", { path: "files/a.txt" }).respond(detail("new a.txt"));
  await flush();
  oldA.respond(detail("old a.txt"));
  oldB.reject(new Error("old B failed"));
  await flush();
  assert.equal(ui.detail.children[0].textContent, "new a.txt");
  assert.equal(a.classList.contains("selected"), true);
});

for (const transition of ["navigation", "overview", "refresh", "search"]) {
  for (const outcome of ["delayed JSON", "network error"]) {
    test(`${transition} invalidates pending detail ${outcome}`, async () => {
      const ui = dashboard();
      const [a] = await uploadTree(ui);
      a.dispatch("click");
      const finishOld = await hold(ui.take("/ui/api/detail"), outcome, detail("a.txt"));
      if (transition === "navigation") ui.navigate("go");
      if (transition === "overview") ui.navigate("overview");
      if (transition === "refresh") ui.refresh.dispatch("click");
      if (transition === "search") ui.searchFor("needle");
      const cleared = ui.detail.textContent;
      assert.equal(cleared, "Select a version to see its details.");
      finishOld();
      await flush();
      assert.equal(ui.detail.textContent, cleared);
      assert.equal(ui.detail.find("delete-upload"), null);
      assert.equal(ui.layers.hidden, true);
    });
  }
}

for (const outcome of ["success", "network error"]) {
  test(`Overview discards a pending tree ${outcome}`, async () => {
    const ui = dashboard();
    ui.navigate("go");
    const finishOld = await hold(ui.take("/ui/api/tree"), outcome, { nodes: [node("old-go")] });
    ui.navigate("overview");
    const previousTree = ui.tree.textContent;
    finishOld();
    await flush();
    assert.equal(ui["view-overview"].hidden, false);
    assert.equal(ui["view-tree"].hidden, true);
    assert.equal(ui.tree.textContent, previousTree);
  });

  test(`navigation discards a pending expansion ${outcome}`, async () => {
    const ui = dashboard();
    ui.navigate("go");
    ui.take("/ui/api/tree").respond({ nodes: [node("go-module", true)] });
    await flush();
    const parent = ui.tree.children[0];
    const children = parent.find("children");
    parent.open = true;
    parent.dispatch("toggle");
    const finishOld = await hold(ui.take("/ui/api/tree", { eco: "go", path: "go-module" }), outcome, { nodes: [node("v1")] });
    ui.navigate("python");
    ui.take("/ui/api/tree").respond({ nodes: [node("requests")] });
    await flush();
    finishOld();
    await flush();
    assert.equal(children.textContent, "loading…");
    assert.equal(ui.tree.textContent, "requests");
  });

  test(`input debounce discards a pending search ${outcome}`, async () => {
    const ui = dashboard();
    ui.searchFor("needle");
    const finishOld = await hold(ui.take("/ui/api/search"), outcome, { query: "needle", groups: [] });
    ui.search.value = "new query";
    ui.search.dispatch("input");
    finishOld();
    await flush();
    assert.equal(ui.tree.textContent, "searching…");
    assert.equal(ui.search.value, "new query");
  });

  test(`search replaces a pending tree ${outcome}`, async () => {
    const ui = dashboard();
    ui.navigate("go");
    const finishOld = await hold(ui.take("/ui/api/tree"), outcome, { nodes: [node("old-go")] });
    ui.searchFor("needle");
    ui.take("/ui/api/search", { q: "needle" }).respond({ query: "needle", groups: [] });
    await flush();
    const rendered = ui.tree.textContent;
    finishOld();
    await flush();
    assert.equal(ui.tree.textContent, rendered);
    assert.match(rendered, /No packages match/);
  });

  test(`leaving search rejects its pending ${outcome}`, async () => {
    const ui = dashboard();
    ui.searchFor("needle");
    const finishOld = await hold(ui.take("/ui/api/search"), outcome, { query: "needle", groups: [] });
    ui.navigate("python");
    ui.take("/ui/api/tree", { eco: "python" }).respond({ nodes: [node("requests")] });
    await flush();
    finishOld();
    await flush();
    assert.equal(ui.tree.textContent, "requests");
  });
}

for (const transition of ["refresh", "query changed and restored"]) {
  test(`search ${transition} rejects an earlier response for the same query`, async () => {
    const ui = dashboard();
    ui.searchFor("needle");
    const old = ui.take("/ui/api/search", { q: "needle" });
    if (transition === "refresh") ui.refresh.dispatch("click");
    else {
      ui.searchFor("other");
      ui.take("/ui/api/search", { q: "other" }).respond({ query: "other", groups: [] });
      ui.searchFor("needle");
    }
    ui.take("/ui/api/search", { q: "needle" }).respond({
      query: "needle", groups: [{ eco: "python", label: "Python", total: 1, nodes: [node("latest")] }],
    });
    await flush();
    old.respond({ query: "needle", groups: [] });
    await flush();
    assert.match(ui.tree.textContent, /latest/);
  });
}

test("current tree, search, and detail failures remain visible", async () => {
  const ui = dashboard();
  ui.navigate("go");
  ui.take("/ui/api/tree").reject(new Error("tree failed"));
  await flush();
  assert.equal(ui.tree.textContent, "Failed to load tree: tree failed");
  ui.searchFor("needle");
  ui.take("/ui/api/search").reject(new Error("search failed"));
  await flush();
  assert.equal(ui.tree.textContent, "Search failed: search failed");
  const [a] = await uploadTree(ui);
  a.dispatch("click");
  ui.take("/ui/api/detail").reject(new Error("detail failed"));
  await flush();
  assert.equal(ui.detail.textContent, "Failed to load details: detail failed");
});
