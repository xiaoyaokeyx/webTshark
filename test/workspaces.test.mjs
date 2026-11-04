import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { startTestServer, waitCapture } from "./helpers.mjs";
import { buildCapture } from "../src/compose.js";

test("capture and saved-view tabs restore independent filters, close and reopen", async () => {
  const server = await startTestServer(),
    output = await mkdtemp(
      join(process.cwd(), "node_modules/.workspace-test-"),
    );
  const realFetch = globalThis.fetch;
  let root, dom;
  try {
    const upload = async (name, count) => {
      const r = await realFetch(server.base + "/api/captures", {
        method: "POST",
        headers: { "X-File-Name": name },
        body: buildCapture({ count }),
      });
      const c = await r.json();
      return waitCapture(server.base, c.id);
    };
    const first = await upload("first.pcap", 1),
      second = await upload("second.pcap", 2);
    await build({
      entryPoints: ["src/App.jsx"],
      bundle: true,
      platform: "node",
      format: "esm",
      packages: "external",
      outfile: join(output, "app.mjs"),
      logLevel: "silent",
    });
    dom = new JSDOM('<!doctype html><div id="root"></div>', {
      url: server.base,
      pretendToBeVisual: true,
    });
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
    globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);
    dom.window.matchMedia = () => ({ matches: true });
    globalThis.fetch = (url, options) =>
      realFetch(new URL(url, server.base), options);
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    localStorage.setItem(
      "webshark-saved-views",
      JSON.stringify([
        {
          id: "favorite-one",
          captureId: first.id,
          captureName: first.name,
          label: "收藏单包",
          filter: "frame.number == 1",
          view: "packets",
          savedAt: Date.now(),
        },
      ]),
    );
    const React = await import("react"),
      { createRoot } = await import("react-dom/client"),
      { default: App } = await import(pathToFileURL(join(output, "app.mjs")));
    const act = React.act;
    const wait = async (fn, label) => {
      for (let i = 0; i < 150; i++) {
        if (fn()) return;
        await act(async () => new Promise((r) => setTimeout(r, 30)));
      }
      throw new Error(label + " " + document.body.textContent.slice(0, 1200));
    };
    const click = async (el) => {
      assert.ok(el);
      await act(() =>
        el.dispatchEvent(new MouseEvent("click", { bubbles: true })),
      );
    };
    const current = () =>
      document.querySelector(".capture-file-title strong")?.textContent;
    const button = (text) =>
      [...document.querySelectorAll("button")].find(
        (b) =>
          b.textContent.trim() === text ||
          b.getAttribute("aria-label") === text,
      );
    const recent = (name) =>
      [...document.querySelectorAll(".recent-file")].find((b) =>
        b.textContent.includes(name),
      );
    const apply = async (value) => {
      const input = document.querySelector("#packet-filter");
      await act(() => {
        Object.getOwnPropertyDescriptor(
          dom.window.HTMLInputElement.prototype,
          "value",
        ).set.call(input, value);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
      await click(document.querySelector(".apply-button"));
      await wait(
        () => !document.querySelector(".packet-panel.is-loading"),
        "filter",
      );
    };
    root = createRoot(document.getElementById("root"));
    await act(() => root.render(React.createElement(App)));
    await wait(() => current() === "second.pcap", "boot second");
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 2,
      "two packets",
    );
    await apply("sip");
    await click(recent("first.pcap"));
    await wait(() => current() === "first.pcap", "switch first");
    await apply("frame.number == 1");
    await click(button("second.pcap"));
    await wait(() => current() === "second.pcap", "switch second again");
    assert.equal(document.querySelector("#packet-filter").value, "sip");
    await click(button("first.pcap"));
    assert.equal(
      document.querySelector("#packet-filter").value,
      "frame.number == 1",
    );
    await click(
      [...document.querySelectorAll(".saved-view-main")].find((b) =>
        b.textContent.includes("收藏单包"),
      ),
    );
    await wait(
      () => document.querySelectorAll('[role="tab"]').length === 3,
      "favorite tab",
    );
    assert.equal(
      document.querySelector('[role="tab"][aria-selected="true"]').textContent,
      "★ 收藏单包",
    );
    await click(button("关闭标签 收藏单包"));
    await wait(
      () => document.querySelectorAll('[role="tab"]').length === 2,
      "close favorite",
    );
    await click(button("重新打开关闭的标签"));
    await wait(
      () => document.querySelectorAll('[role="tab"]').length === 3,
      "reopen favorite",
    );
    assert.equal(
      document.querySelector("#packet-filter").value,
      "frame.number == 1",
    );
    await click(button("工具"));
    await click(button("报文构造器"));
    assert.ok(
      document
        .querySelector('[role="dialog"]')
        .textContent.includes("构造并下载 1 个包"),
    );
  } finally {
    if (root) {
      const React = await import("react");
      await React.act(() => root.unmount());
    }
    globalThis.fetch = realFetch;
    dom?.window.close();
    await server.stop();
    await rm(output, { recursive: true, force: true });
  }
});
