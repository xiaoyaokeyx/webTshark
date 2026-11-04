import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { JSDOM } from "jsdom";

test("parsing preview pages during indexing and aborts requests when switching capture", async () => {
  const output = await mkdtemp(join(process.cwd(), "node_modules/.webtshark-preview-test-"));
  const realFetch = globalThis.fetch;
  let root, dom;
  try {
    await build({ entryPoints: ["src/ParsingPreview.jsx"], bundle: true, platform: "node", format: "esm", packages: "external", outfile: join(output, "preview.mjs"), logLevel: "silent" });
    dom = new JSDOM('<div id="root"></div>', { url: "http://localhost/" });
    globalThis.window = dom.window; globalThis.document = dom.window.document;
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const requests = [];
    globalThis.fetch = async (url, { signal }) => {
      requests.push({ url, signal });
      const page = Number(new URL(url, "http://localhost").searchParams.get("page"));
      return { ok: true, json: async () => ({ total: 250, partial: true, packets: Array.from({ length: 100 }, (_, i) => ({ no: page * 100 + i + 1, time: 1.5, source: "192.0.2.1", destination: "192.0.2.2", protocol: "UDP", length: 64, info: "Partial packet" })) }) };
    };
    const React = await import("react");
    const { createRoot } = await import("react-dom/client");
    const { default: Preview } = await import(pathToFileURL(join(output, "preview.mjs")));
    root = createRoot(document.getElementById("root"));
    const render = (id) => React.act(() => root.render(React.createElement(Preview, { key: id, capture: { id, revision: 1, status: "indexing" }, timeFormat: "relative", formatTime: (p) => p.time.toFixed(6) })));
    await render("one");
    assert.equal(document.querySelectorAll("tbody tr").length, 100);
    assert.equal(document.querySelector("tbody td").textContent, "1");
    await React.act(() => document.querySelector('[aria-label="预览下一页"]').click());
    assert.equal(document.querySelector("tbody td").textContent, "101");
    assert.equal(requests[0].signal.aborted, true);
    await render("two");
    assert.equal(document.querySelector("tbody td").textContent, "1");
    assert.ok(requests.at(-1).url.includes("/two/progress-packets?page=0"));
    await React.act(() => root.unmount()); root = null;
    assert.ok(requests.every((request) => request.signal.aborted));
  } finally {
    if (root) { const React = await import("react"); await React.act(() => root.unmount()); }
    globalThis.fetch = realFetch;
    dom?.window.close();
    await rm(output, { recursive: true, force: true });
  }
});
