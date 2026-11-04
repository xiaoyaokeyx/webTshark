import React, { useEffect, useId, useRef, useState } from "react";

const HANDLE_SIZE = 12;
const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

function readRatio(key, fallback) {
  try {
    const saved = JSON.parse(localStorage.getItem(key));
    return typeof saved === "number" &&
      Number.isFinite(saved) &&
      saved > 0 &&
      saved < 1
      ? saved
      : fallback;
  } catch {
    return fallback;
  }
}

export function useNarrowPanes() {
  const [narrow, setNarrow] = useState(() => window.innerWidth < 768);
  useEffect(() => {
    const update = () => setNarrow(window.innerWidth < 768);
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);
  return narrow;
}

export default function ResizableSplit({
  children,
  direction = "horizontal",
  storageKey,
  defaultRatio = 0.5,
  minFirst = 240,
  minSecond = 240,
  minHeight = 0,
  fitViewport = false,
  label,
  className = "",
}) {
  const horizontal = direction === "horizontal";
  const [ratio, setRatio] = useState(() => readRatio(storageKey, defaultRatio));
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [height, setHeight] = useState(null);
  const container = useRef(null);
  const drag = useRef(null);
  const latestRatio = useRef(ratio);
  const stopDrag = useRef(() => {});
  const id = useId();

  const limits = (extent) => {
    const available = Math.max(1, extent - HANDLE_SIZE);
    // Very small containers still divide their available space without overflow.
    const scale = Math.min(1, available / (minFirst + minSecond));
    return {
      available,
      min: (minFirst * scale) / available,
      max: 1 - (minSecond * scale) / available,
    };
  };
  const bounds = limits(horizontal ? size.width : size.height);
  const visibleRatio =
    size.width && size.height ? clamp(ratio, bounds.min, bounds.max) : ratio;
  const updateRatio = (next, persist = false) => {
    latestRatio.current = next;
    setRatio(next);
    if (persist) {
      try {
        localStorage.setItem(storageKey, JSON.stringify(next));
      } catch {
        // Resizing remains usable when browser storage is unavailable.
      }
    }
  };

  useEffect(() => {
    const el = container.current;
    const measure = () => {
      const rect = el.getBoundingClientRect();
      setSize((old) =>
        old.width === rect.width && old.height === rect.height
          ? old
          : { width: rect.width, height: rect.height },
      );
      if (fitViewport) {
        const documentTop = rect.top + window.scrollY;
        setHeight(
          Math.max(
            minHeight,
            minFirst + minSecond + HANDLE_SIZE,
            window.innerHeight - documentTop - 40,
          ),
        );
      }
    };
    measure();
    const observer = window.ResizeObserver
      ? new window.ResizeObserver(measure)
      : null;
    observer?.observe(el);
    if (fitViewport && el.parentElement) observer?.observe(el.parentElement);
    window.addEventListener("resize", measure);
    return () => {
      observer?.disconnect();
      window.removeEventListener("resize", measure);
      stopDrag.current();
    };
  }, [fitViewport, minFirst, minSecond, minHeight]);

  const beginDrag = (event) => {
    if (event.button !== 0 || event.isPrimary === false) return;
    event.preventDefault();
    stopDrag.current();
    const handle = event.currentTarget;
    const rect = container.current.getBoundingClientRect();
    const currentBounds = limits(horizontal ? rect.width : rect.height);
    const initial = clamp(
      latestRatio.current,
      currentBounds.min,
      currentBounds.max,
    );
    const start = horizontal ? event.clientX : event.clientY;
    const pointerId = event.pointerId;
    const cursorClass = horizontal
      ? "resizing-pane-columns"
      : "resizing-pane-rows";
    drag.current = pointerId;
    handle.focus({ preventScroll: true });
    handle.setPointerCapture?.(pointerId);
    document.body.classList.add(cursorClass);
    const move = (nextEvent) => {
      if (nextEvent.pointerId !== pointerId) return;
      const position = horizontal ? nextEvent.clientX : nextEvent.clientY;
      updateRatio(
        clamp(
          initial + (position - start) / currentBounds.available,
          currentBounds.min,
          currentBounds.max,
        ),
      );
    };
    const finish = (endEvent) => {
      if (endEvent && endEvent.pointerId !== pointerId) return;
      if (drag.current === null) return;
      drag.current = null;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", finish);
      window.removeEventListener("blur", blur);
      handle.removeEventListener("lostpointercapture", finish);
      document.body.classList.remove(cursorClass);
      if (handle.hasPointerCapture?.(pointerId))
        handle.releasePointerCapture(pointerId);
      updateRatio(latestRatio.current, true);
      stopDrag.current = () => {};
    };
    const blur = () => finish();
    stopDrag.current = blur;
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish);
    window.addEventListener("pointercancel", finish);
    window.addEventListener("blur", blur);
    handle.addEventListener("lostpointercapture", finish);
  };

  const onKeyDown = (event) => {
    const previous = horizontal ? "ArrowLeft" : "ArrowUp";
    const next = horizontal ? "ArrowRight" : "ArrowDown";
    if (![previous, next, "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const rect = container.current.getBoundingClientRect();
    const current = limits(horizontal ? rect.width : rect.height);
    const value = clamp(latestRatio.current, current.min, current.max);
    const step = (event.shiftKey ? 40 : 10) / current.available;
    updateRatio(
      event.key === "Home"
        ? current.min
        : event.key === "End"
          ? current.max
          : clamp(
              value + (event.key === next ? step : -step),
              current.min,
              current.max,
            ),
      true,
    );
  };
  const tracks = `${visibleRatio}fr ${HANDLE_SIZE}px ${1 - visibleRatio}fr`;

  return (
    <div
      ref={container}
      className={`resizable-split split-${direction} ${className}`}
      style={{
        ...(horizontal
          ? { gridTemplateColumns: tracks }
          : { gridTemplateRows: tracks }),
        ...(fitViewport ? { height: height ?? minHeight } : {}),
      }}
    >
      <div className="split-pane split-first" id={`${id}-first`}>
        {children[0]}
      </div>
      <div
        role="separator"
        aria-label={label}
        aria-orientation={horizontal ? "vertical" : "horizontal"}
        aria-controls={`${id}-first ${id}-second`}
        aria-valuemin={Math.round(bounds.min * 100)}
        aria-valuemax={Math.round(bounds.max * 100)}
        aria-valuenow={Math.round(visibleRatio * 100)}
        aria-valuetext={`${horizontal ? "左侧" : "上方"}区域 ${Math.round(visibleRatio * 100)}%`}
        tabIndex={0}
        className="pane-divider"
        title={`${horizontal ? "左右拖动调整宽度" : "上下拖动调整高度"}；双击恢复默认；方向键微调`}
        onPointerDown={beginDrag}
        onKeyDown={onKeyDown}
        onDoubleClick={() => updateRatio(defaultRatio, true)}
      >
        <span aria-hidden="true" />
      </div>
      <div className="split-pane split-second" id={`${id}-second`}>
        {children[1]}
      </div>
    </div>
  );
}

export function PacketWorkspace({ children }) {
  const narrow = useNarrowPanes();
  return (
    <ResizableSplit
      key={narrow ? "narrow" : "wide"}
      direction="vertical"
      className="packet-workspace"
      storageKey={`webshark-pane-list-${narrow ? "narrow" : "wide"}`}
      label="调整数据包列表与详情高度"
      defaultRatio={narrow ? 0.4 : 0.62}
      minFirst={narrow ? 300 : 190}
      minSecond={narrow ? 480 : 180}
      minHeight={narrow ? 900 : 560}
      fitViewport
    >
      {children}
    </ResizableSplit>
  );
}
