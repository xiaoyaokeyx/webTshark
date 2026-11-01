import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { startTestServer, waitCapture } from "./helpers.mjs";
import { buildSipMultiCallPcap } from "../server/fixtures.mjs";
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
        (b) =>
          b.textContent.trim() === text ||
          b.getAttribute("aria-label") === text ||
          b.getAttribute("title") === text,
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
    assert.ok(button("Time"), "time column uses compact header label");
    assert.equal(button("Seconds Since Beginning of Capture"), undefined);
    assert.equal(
      document.querySelectorAll(".column-resizer").length,
      document.querySelectorAll(".packet-table thead th").length,
    );
    await click(button("TCP"));
    await wait(
      () =>
        document.querySelector("#packet-filter").value === "tcp" &&
        button("TCP").getAttribute("aria-pressed") === "true",
      "TCP preset filter",
    );
    assert.equal(button("TCP").getAttribute("aria-pressed"), "true");
    await click(button("TCP"));
    await wait(
      () =>
        document.querySelector("#packet-filter").value === "" &&
        document.querySelectorAll(".packet-table tbody tr").length === 100,
      "toggle TCP preset off",
    );
    assert.equal(button("TCP").getAttribute("aria-pressed"), "false");
    await click(button("数据包列与时间设置"));
    await select(document.querySelector("#time-format"), "epoch");
    const infoColumn = document.querySelector('[aria-label="显示 信息"]');
    await act(() =>
      infoColumn.dispatchEvent(
        new dom.window.MouseEvent("click", { bubbles: true }),
      ),
    );
    await fill(
      document.querySelector('[aria-label="新增字段列"]'),
      "dns.qry.name",
    );
    await click(button("添加字段列"));
    assert.ok(
      [...document.querySelectorAll(".column-config-row")].some((row) =>
        row.textContent.includes("DNS 查询名"),
      ),
    );
    assert.equal(
      document.querySelector(".column-config-row").getAttribute("draggable"),
      "true",
    );
    await click(button("上移 协议"));
    assert.equal(
      [...document.querySelectorAll(".column-config-row strong")][3].textContent,
      "协议",
    );
    await click(button("完成"));
    assert.ok(
      [...document.querySelectorAll(".packet-table thead th")].some((th) =>
        th.textContent.includes("DNS 查询名"),
      ),
    );
    assert.equal(
      [...document.querySelectorAll(".packet-table thead th")].some((th) =>
        th.textContent.includes("信息"),
      ),
      false,
    );
    await click(button("数据包列与时间设置"));
    await click(button("恢复默认列"));
    await click(button("完成"));
    assert.ok(
      [...document.querySelectorAll(".packet-table thead th")].some((th) =>
        th.textContent.includes("信息"),
      ),
    );
    await click(button("包比较"));
    await click(document.querySelector(".packet-table tbody tr"));
    await click(document.querySelectorAll(".packet-table tbody tr")[1]);
    await click(button("查看差异"));
    assert.match(
      document.querySelector('[role="dialog"]').textContent,
      /比较数据包 #/,
    );
    await click(button("完成", document.querySelector('[role="dialog"]')));
    await click(button("选择中 2/2"));
    await click(button("长度"));
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
    assert.ok(button("应用为列"), "field context menu exposes apply as column");
    assert.ok(button("解码为…"), "transport context menu exposes Decode As");
    await click(button("解码为…"));
    assert.equal(
      document.querySelector('[role="dialog"] #decode-as-protocol').value,
      "rtp",
    );
    await click(button("取消", document.querySelector('[role="dialog"]')));
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
    await click(button("应用为列"));
    assert.match(document.querySelector(".toast").textContent, /源地址/);
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
    await click(button("应用为过滤器"));
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 69,
      "context filter",
    );
    assert.equal(
      document.querySelector("#packet-filter").value,
      "ip.src == 10.10.0.10",
    );
    await click(button("保存当前视图"));
    await fill(document.querySelector("#saved-view-name"), "源地址分析");
    await click(button("保存视图", document.querySelector('[role="dialog"]')));
    assert.equal(document.querySelectorAll(".saved-view-row").length, 1);
    assert.match(
      document.querySelector(".saved-view-row").textContent,
      /源地址分析/,
    );
    await click(button("RTP"));
    await wait(
      () =>
        document.querySelector("#packet-filter").value === "rtp" &&
        !document.querySelector(".packet-panel.is-loading"),
      "RTP saved view filter",
    );
    await click(button("保存当前视图"));
    await fill(document.querySelector("#saved-view-name"), "RTP 媒体");
    await click(button("保存视图", document.querySelector('[role="dialog"]')));
    assert.equal(document.querySelectorAll(".saved-view-row").length, 2);
    await act(() =>
      document
        .querySelectorAll(".saved-view-main")[1]
        .dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })),
    );
    await wait(
      () =>
        document.querySelector("#packet-filter").value ===
        "ip.src == 10.10.0.10",
      "restore saved view",
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
        b.textContent.includes("SIP 时序图"),
      ),
    );
    await wait(
      () => document.querySelectorAll(".sip-sequence-card").length === 1,
      "SIP sequence view",
    );
    assert.match(
      document.querySelector(".sip-sequence-lane code").textContent,
      /192\.168\.1\.108/,
    );
    assert.match(
      document.querySelector(".sip-sequence-delta").textContent,
      /首条消息/,
    );
    assert.match(
      document.querySelectorAll(".sip-sequence-delta")[1].textContent,
      /ms/,
    );
    assert.ok(document.querySelector("#sip-time-format"));
    assert.ok(document.querySelector("#sip-session-gap"));
    await select(document.querySelector("#sip-time-format"), "local");
    assert.match(
      document.querySelector(".sip-sequence-time strong").textContent,
      /^\d{4}-\d{2}-\d{2}/,
    );
    await select(document.querySelector("#sip-session-gap"), "0.5");
    assert.equal(document.querySelector("#sip-session-gap").value, "0.5");
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
    await click(button("取消", document.querySelector('[role="dialog"]')));
    await click(button("关闭文件"));
    await wait(
      () => !document.querySelector(".capture-card"),
      "close current capture",
    );
    assert.match(
      document.querySelector(".empty-state").textContent,
      /当前未打开 pcap 文件/,
    );
    assert.equal(sessionStorage.getItem("webshark-capture"), "closed");
    const recent = [...document.querySelectorAll(".recent-file")].find((b) =>
      b.textContent.includes("webshark-demo.pcap"),
    );
    assert.ok(recent, "closed capture remains in recent files");
    await click(recent);
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 100,
      "reopen closed capture",
    );
    assert.equal(sessionStorage.getItem("webshark-capture"), saved[0].id);
    let multi;
    await act(async () => {
      multi = await realFetch(server.base + "/api/captures", {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-File-Name": "sip-multi-call-demo.pcap",
        },
        body: buildSipMultiCallPcap(),
      }).then((r) => r.json());
      await waitCapture(server.base, multi.id);
    });
    await act(() => root.unmount());
    sessionStorage.setItem("webshark-capture", multi.id);
    root = createRoot(document.getElementById("root"));
    await act(() => root.render(React.createElement(App)));
    await wait(
      () => document.querySelectorAll(".packet-table tbody tr").length === 11,
      "multi-call PCAP loaded",
    );
    await click(
      [...document.querySelectorAll(".nav-item")].find((b) =>
        b.textContent.includes("SIP 时序图"),
      ),
    );
    await wait(
      () => document.querySelectorAll(".voip-message-row").length === 11,
      "all interleaved SIP messages",
    );
    assert.equal(
      document.querySelectorAll(".voip-call-table tbody tr").length,
      2,
    );
    assert.equal(document.querySelectorAll(".voip-endpoint").length, 4);
    assert.equal(document.querySelectorAll(".voip-chart").length, 1);
    assert.match(
      document.querySelector(".voip-selected-legend").textContent,
      /C ↔ D/,
    );
    assert.equal(
      document.querySelectorAll(".voip-idle").length,
      1,
      "long silence is a marker, not a new call",
    );
    await click(button("按会话分组"));
    assert.equal(document.querySelectorAll(".voip-chart").length, 2);
    assert.deepEqual(
      [...document.querySelectorAll(".voip-endpoint-letter")].map(
        (el) => el.textContent,
      ),
      ["A", "B", "C", "D"],
    );
    await click(button("合并时序"));
    await click(button("仅显示会话 2"));
    assert.equal(document.querySelectorAll(".voip-message-row").length, 4);
    assert.equal(document.querySelectorAll(".voip-endpoint").length, 2);
    await click(document.querySelector('[aria-label="显示会话 1"]'));
    assert.equal(document.querySelectorAll(".voip-message-row").length, 11);
    await fill(document.querySelector('[aria-label="搜索 SIP 会话"]'), "carol");
    assert.equal(document.querySelectorAll(".voip-message-row").length, 4);
    await fill(document.querySelector('[aria-label="搜索 SIP 会话"]'), "");
    const lastMessage = [...document.querySelectorAll(".voip-message-row")].at(
      -1,
    );
    await click(lastMessage);
    await wait(
      () =>
        document.querySelector(".voip-inline-raw-sip") &&
        document
          .querySelector(".voip-inline-detail")
          ?.textContent.includes("数据包 #11"),
      "signal expands its inline packet detail",
    );
    assert.ok(document.querySelector(".voip-chart"), "flow remains visible");
    assert.ok(
      document.querySelector(".voip-message-row.is-side-right.is-expanded"),
      "reverse messages use the right-side color",
    );
    assert.ok(
      document.querySelector(".voip-inline-detail.is-align-right"),
      "reverse message details align with the sending side",
    );
    assert.equal(
      document.querySelector(".voip-message-detail"),
      null,
      "flow rows do not duplicate details in a right-side column",
    );
    assert.equal(
      document.querySelector(".voip-comment-heading"),
      null,
      "flow header does not render an unused details column",
    );
    assert.equal(
      document.querySelector(".voip-inline-compact-layers"),
      null,
      "inline detail does not render protocol layer cards",
    );
    assert.match(
      document.querySelector(".voip-inline-raw-sip").textContent,
      /SIP\/2\.0 200 OK/,
      "inline detail renders the raw SIP message",
    );
    await click(lastMessage);
    assert.equal(
      document.querySelector(".voip-inline-detail"),
      null,
      "clicking the same message collapses its detail",
    );
    const sdpMessage = [...document.querySelectorAll(".voip-message-row")].find(
      (message) => message.getAttribute("title")?.includes("#8"),
    );
    await click(sdpMessage);
    await wait(
      () =>
        document
          .querySelector(".voip-inline-raw-sip")
          ?.textContent.includes("m=audio 20000 RTP/AVP 0"),
      "200 OK exposes the raw SDP body",
    );
    assert.ok(
      document.querySelector(".voip-inline-detail.is-align-right"),
      "200 OK details align with the right-side sender",
    );
    assert.match(
      document.querySelector(".voip-inline-raw-sip").textContent,
      /Content-Type: application\/sdp/,
    );
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
