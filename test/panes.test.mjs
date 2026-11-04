import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { JSDOM } from "jsdom";

test("pane dividers support bounded pointer dragging, persistence, reset and keyboard resizing", async () => {
  const output = await mkdtemp(join(process.cwd(), "node_modules/.pane-test-"));
  const dom = new JSDOM('<!doctype html><div id="root"></div>', {
    url: "http://localhost/",
    pretendToBeVisual: true,
  });
  let root;
  try {
    for (const key of [
      "window",
      "document",
      "HTMLElement",
      "MouseEvent",
      "KeyboardEvent",
      "localStorage",
    ])
      globalThis[key] = dom.window[key];
    Object.defineProperty(globalThis, "navigator", {
      value: dom.window.navigator,
      configurable: true,
    });
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    dom.window.HTMLElement.prototype.getBoundingClientRect = () => ({
      width: 1000,
      height: 600,
      top: 0,
      left: 0,
      right: 1000,
      bottom: 600,
    });
    await build({
      entryPoints: ["src/ResizableSplit.jsx"],
      bundle: true,
      platform: "node",
      format: "esm",
      packages: "external",
      outfile: join(output, "panes.mjs"),
      logLevel: "silent",
    });
    const React = await import("react");
    const { createRoot } = await import("react-dom/client");
    const { default: Split } = await import(
      pathToFileURL(join(output, "panes.mjs"))
    );
    const act = React.act;
    root = createRoot(document.getElementById("root"));
    const render = async (key = "columns", direction = "horizontal") =>
      act(() =>
        root.render(
          React.createElement(
            Split,
            {
              key,
              direction,
              storageKey: key,
              label: "调整区域",
              defaultRatio: 0.48,
            },
            React.createElement("p", null, "packet selection stays mounted"),
            React.createElement("p", null, "packet bytes"),
          ),
        ),
      );
    const handle = () => document.querySelector('[role="separator"]');
    const value = () => Number(handle().getAttribute("aria-valuenow"));
    const pointer = async (target, type, x, y, id = 7) =>
      act(() => {
        const event = new MouseEvent(type, {
          bubbles: true,
          clientX: x,
          clientY: y,
          button: 0,
        });
        Object.defineProperties(event, {
          pointerId: { value: id },
          isPrimary: { value: true },
        });
        target.dispatchEvent(event);
      });
    await render();
    const originalChild = document.querySelector(".split-first p");
    const initial = value();
    await pointer(handle(), "pointerdown", 400, 200);
    await pointer(window, "pointermove", 600, 200);
    assert.ok(value() > initial, "drag moves the separator");
    assert.equal(
      document.querySelector(".split-first p"),
      originalChild,
      "resizing retains packet content",
    );
    assert.equal(
      localStorage.getItem("columns"),
      null,
      "drag writes preferences when it finishes",
    );
    await pointer(window, "pointermove", 10000, 200);
    assert.equal(
      value(),
      Number(handle().getAttribute("aria-valuemax")),
      "neither pane can collapse",
    );
    await pointer(window, "pointercancel", 10000, 200);
    assert.ok(!document.body.classList.contains("resizing-pane-columns"));
    const saved = value();
    assert.ok(Number(localStorage.getItem("columns")) > 0);
    await render("temporary");
    await render();
    assert.equal(value(), saved, "saved divider position survives reopening");
    await act(() =>
      handle().dispatchEvent(new MouseEvent("dblclick", { bubbles: true })),
    );
    assert.equal(value(), initial);
    await act(() =>
      handle().dispatchEvent(
        new KeyboardEvent("keydown", { key: "Home", bubbles: true }),
      ),
    );
    const minimum = value();
    await act(() =>
      handle().dispatchEvent(
        new KeyboardEvent("keydown", {
          key: "ArrowRight",
          shiftKey: true,
          bubbles: true,
        }),
      ),
    );
    assert.ok(
      value() > minimum,
      "keyboard resizing follows the divider orientation",
    );
    await act(() =>
      handle().dispatchEvent(
        new KeyboardEvent("keydown", { key: "End", bubbles: true }),
      ),
    );
    assert.equal(value(), Number(handle().getAttribute("aria-valuemax")));

    await render("rows", "vertical");
    const beforeRows = value();
    await pointer(handle(), "pointerdown", 200, 300);
    await pointer(window, "pointermove", 200, 250, 99);
    assert.equal(
      value(),
      beforeRows,
      "unrelated touch pointers do not move the divider",
    );
    await pointer(window, "pointermove", 200, 250);
    assert.ok(value() < beforeRows, "vertical divider responds to Y movement");
    await act(() => root.unmount());
    root = null;
    assert.ok(
      !document.body.classList.contains("resizing-pane-rows"),
      "unmount releases drag state",
    );
    await pointer(window, "pointermove", 200, 100);
  } finally {
    if (root) {
      const React = await import("react");
      await React.act(() => root.unmount());
    }
    dom.window.close();
    await rm(output, { recursive: true, force: true });
  }
});
