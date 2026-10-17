"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

class FakeClassList {
  add() {}
  remove() {}
  toggle() {}
}

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.children = [];
    this.classList = new FakeClassList();
    this.style = {};
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.textContent = "";
    this.files = [];
    this.colSpan = 1;
  }

  addEventListener() {}

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  querySelector(selector) {
    if (selector === "span") {
      if (!this._span) this._span = new FakeElement("span");
      return this._span;
    }
    return null;
  }

  setAttribute() {}
  scrollIntoView() {}
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
    this.topbarState = new FakeElement("div");
  }

  getElementById(id) {
    if (!this.elements.has(id)) this.elements.set(id, new FakeElement());
    return this.elements.get(id);
  }

  querySelector(selector) {
    return selector === ".topbar-state" ? this.topbarState : null;
  }

  querySelectorAll() {
    return [];
  }

  createElement(tagName) {
    return new FakeElement(tagName);
  }

  createTextNode(text) {
    const node = new FakeElement("text");
    node.textContent = String(text);
    return node;
  }
}

function makeOption(label, value) {
  const option = new FakeElement("option");
  option.textContent = label;
  option.value = value;
  return option;
}

async function main() {
  const document = new FakeDocument();
  const context = {
    assert,
    document,
    fetch: () => new Promise(() => {}),
    Option: makeOption,
    cancelAnimationFrame() {},
    requestAnimationFrame() { return 1; },
    performance: { now: () => 0 },
    window: {
      matchMedia: () => ({ matches: true }),
      location: { assign() {} },
    },
  };
  vm.createContext(context);
  const dashboard = fs.readFileSync("synapseaudit/static/dashboard.js", "utf8");
  vm.runInContext(dashboard, context, { filename: "dashboard.js" });

  const scan = {
    status: "no_supported_files",
    repository: "octo/allowed",
    branch: "main",
    commit_sha: "a".repeat(40),
    files: [],
    skipped: [
      { path: "README.md", reason: "filename is outside the supported Compose scope" },
    ],
    skipped_counts: { "filename is outside the supported Compose scope": 1 },
  };

  context.updateGitHubScanContext(scan);
  context.setGitHubScanOutcome(scan);
  vm.runInContext('reportSource = "github"; currentReport = { findings: [], attack_paths: [] };', context);
  context.renderFindings({ findings: [], attack_paths: [] });

  assert.equal(document.getElementById("github-status").textContent, "No supported files");
  assert.match(
    document.getElementById("github-connection-copy").textContent,
    /not a clean repository assessment/,
  );
  assert.equal(
    document.getElementById("summary-copy").textContent,
    "No supported Compose files were analyzed; this is not a clean repository assessment.",
  );
  assert.equal(
    document.getElementById("analysis-status").textContent,
    "No supported files analyzed · 0 supported file(s)",
  );
  assert.equal(document.getElementById("overview-status").textContent, "Assessment incomplete; inspect scan status");
  assert.equal(document.getElementById("github-scan-result").hidden, false);
  assert.match(document.getElementById("github-scan-result").textContent, /not a clean assessment/);
  assert.match(document.getElementById("github-scan-result").textContent, /Skipped files:/);
  assert.match(document.getElementById("github-scan-result").textContent, /README\.md/);
  assert.match(document.getElementById("github-scan-result").textContent, /supported Compose scope/);
  assert.match(document.getElementById("findings-table-body").children[0].children[0].textContent, /Assessment incomplete/);
  assert.notEqual(document.getElementById("github-status").textContent, "Scan complete");
  assert.notEqual(document.getElementById("topbar-status").textContent, "Repository scan complete");

  process.stdout.write("dashboard no_supported_files UI behavior: ok\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
