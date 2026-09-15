import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const script = readFileSync(new URL("app.js", import.meta.url), "utf8");

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
