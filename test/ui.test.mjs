import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { startTestServer } from "./helpers.mjs";
test("UI boots on real capture; right-click filters, error recovery and per-stream PT save work", async () => {
  const server = await startTestServer();
  const output = await mkdtemp(
    join(process.cwd(), "node_modules/.webshark-ui-test-"),
  );
  let root, dom;
  try {
    await build({
      entryPoints: ["src/App.jsx"],
      bundle: true,
      platform: "node",
      format: "esm",
      packages: "external",
      outfile: join(output, "app.mjs"),
      logLevel: "silent",
    });
    dom = new JSDOM(
      '<!doctype html><html><body><div id="root"></div></body></html>',
      { url: server.base, pretendToBeVisual: true },
    );
    for (const key of [
      "window",
      "document",
      "HTMLElement",
      "Event",
      "MouseEvent",
      "KeyboardEvent",
      "localStorage",
      "sessionStorage",
      "XMLHttpRequest",
    ])
      globalThis[key] = dom.window[key];
    Object.defineProperty(globalThis, "navigator", {
      value: dom.window.navigator,
      configurable: true,
    });
    globalThis.requestAnimationFrame = (callback) => setTimeout(callback, 0);
    dom.window.matchMedia = () => ({ matches: true });
    const realFetch = globalThis.fetch;
    globalThis.fetch = (url, options) =>
      realFetch(new URL(url, server.base), options);
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const React = await import("react");
    const { createRoot } = await import("react-dom/client");
    const { default: App } = await import(
      pathToFileURL(join(output, "app.mjs"))
    );
    root = createRoot(document.getElementById("root"));
    async function act(fn) {
      await React.act(fn);
    }
    async function wait(check, label) {
      for (let i = 0; i < 250; i++) {
        if (check()) return;
        await act(async () => await new Promise((r) => setTimeout(r, 30)));
      }
      throw new Error(
        "Timed out: " + label + " " + document.body.textContent.slice(-1200),
      );
    }
    const button = (text, scope = document) =>
      [...scope.querySelectorAll("button")].find(
        (b) => b.textContent.trim() === text,
      );
    async function click(el) {
      assert.ok(el, "button must exist");
      await act(() =>
        el.dispatchEvent(
          new dom.window.MouseEvent("click", {
            bubbles: true,
            cancelable: true,
          }),
        ),
      );
    }
    async function fill(el, value) {
      await act(() => {
        Object.getOwnPropertyDescriptor(
          dom.window.HTMLInputElement.prototype,
          "value",
        ).set.call(el, value);
        el.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
      });
    }
    async function select(el, value) {
      await act(() => {
        el.value = value;
        el.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
      });
    }
    await act(() => root.render(React.createElement(App)));
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 100,
      "initial packets",
    );
    assert.equal(
      document.querySelector(".capture-file-title strong").textContent,
      "webshark-demo.pcap",
    );
    const row = [...document.querySelectorAll(".packet-table tbody tr")].find(
      (r) => r.cells[0].textContent === "49",
    );
    assert.ok(row);
    await act(() =>
      row.cells[2].dispatchEvent(
        new dom.window.MouseEvent("contextmenu", {
          bubbles: true,
          cancelable: true,
          clientX: 100,
          clientY: 100,
        }),
      ),
    );
    assert.equal(
      document.querySelector(".context-caption code").textContent,
      "ip.src == 10.10.0.10",
    );
    await click(button("应用为过滤器"));
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 69,
      "context filter",
    );
    assert.equal(
      document.querySelector("#packet-filter").value,
      "ip.src == 10.10.0.10",
    );
    await fill(document.querySelector("#packet-filter"), "invalid expression");
    await click(document.querySelector(".apply-button"));
    await wait(
      () => document.querySelector('[role="alert"]'),
      "filter validation",
    );
    assert.equal(
      document.querySelectorAll(".packet-table tbody tr").length,
      69,
    );
    await click(button("全部数据包"));
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 100,
      "clear filter",
    );
    await click(
      [...document.querySelectorAll(".nav-item")].find((b) =>
        b.textContent.includes("RTP 媒体流"),
      ),
    );
    await wait(
      () => document.querySelectorAll(".rtp-table tbody tr").length === 2,
      "RTP view",
    );
    await click(
      document.querySelector(".rtp-table tbody tr .media-actions button"),
    );
    assert.equal(document.querySelector("#mapping-scope").value, "stream");
    assert.equal(document.querySelector("#mapping-pt").value, "96");
    await act(() =>
      document
        .querySelector('[role="dialog"] form')
        .dispatchEvent(
          new dom.window.Event("submit", { bubbles: true, cancelable: true }),
        ),
    );
    await wait(
      () =>
        document.querySelectorAll(".rtp-table tbody tr").length === 2 &&
        document
          .querySelector(".rtp-table tbody tr .media-codec")
          .textContent.includes("PCMU"),
      "PT applied",
    );
    const media = [...document.querySelectorAll(".rtp-table tbody tr")];
    assert.ok(
      media[1]
        .querySelector(".media-codec")
        .textContent.includes("Dynamic PT 96"),
    );
    const plays = [
      ...document.querySelectorAll(".media-actions button"),
    ].filter((b) => b.textContent.includes("试听"));
    assert.equal(plays[0].disabled, false);
    assert.equal(plays[1].disabled, true);
    await click(
      document.querySelector(".rtp-table tbody tr .media-actions button"),
    );
    await select(document.querySelector("#mapping-codec"), "AMR");
    assert.equal(document.querySelector("#mapping-rate").value, "8000");
    assert.equal(document.querySelector("#mapping-octet-align").value, "0");
    await select(document.querySelector("#mapping-codec"), "AMR-WB");
    assert.equal(document.querySelector("#mapping-rate").value, "16000");
    assert.equal(document.querySelector("#mapping-rate").readOnly, true);
    await select(document.querySelector("#mapping-octet-align"), "1");
    await act(() =>
      document
        .querySelector('[role="dialog"] form')
        .dispatchEvent(
          new dom.window.Event("submit", { bubbles: true, cancelable: true }),
        ),
    );
    await wait(
      () =>
        document
          .querySelector(".rtp-table tbody tr .media-codec")
          ?.textContent.includes("AMR-WB"),
      "AMR-WB applied",
    );
    let saved;
    await act(async () => {
      saved = await realFetch(server.base + "/api/captures").then((r) =>
        r.json(),
      );
    });
    assert.equal(saved[0].config.mappings[0].codec, "AMR-WB");
    assert.equal(saved[0].config.mappings[0].clockRate, 16000);
    assert.equal(saved[0].config.mappings[0].octetAlign, true);
    await click(button("编辑", document.querySelector(".mapping-item")));
    assert.equal(document.querySelector("#mapping-codec").value, "AMR-WB");
    assert.equal(document.querySelector("#mapping-octet-align").value, "1");
    await act(() => root.unmount());
    root = null;
    globalThis.fetch = realFetch;
  } finally {
    if (root) {
      const { act } = await import("react");
      await act(() => root.unmount());
    }
    dom?.window.close();
    await server.stop();
    await rm(output, { recursive: true, force: true });
  }
});
