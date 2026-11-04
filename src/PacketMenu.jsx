import React, { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";

export default function PacketMenu({
  label,
  children,
  className = "",
  width = 340,
}) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({
    left: 12,
    top: 80,
    maxHeight: 500,
    width,
  });
  const anchor = useRef(null);
  const popup = useRef(null);
  const id = useId();
  useEffect(() => {
    if (!open) return;
    const rect = anchor.current.getBoundingClientRect();
    const actualWidth = Math.min(width, window.innerWidth - 24);
    setPosition({
      left: Math.max(
        12,
        Math.min(
          rect.right - actualWidth,
          window.innerWidth - actualWidth - 12,
        ),
      ),
      top: rect.bottom + 5,
      maxHeight: Math.max(100, window.innerHeight - rect.bottom - 17),
      width: actualWidth,
    });
    popup.current
      ?.querySelector("button:not(:disabled), input, select, a[href]")
      ?.focus({ preventScroll: true });
    const outside = (event) => {
      if (
        !anchor.current?.contains(event.target) &&
        !popup.current?.contains(event.target)
      )
        setOpen(false);
    };
    const escape = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setOpen(false);
        anchor.current?.focus();
      }
    };
    const resize = () => setOpen(false);
    document.addEventListener("pointerdown", outside);
    document.addEventListener("focusin", outside);
    document.addEventListener("keydown", escape, true);
    window.addEventListener("resize", resize);
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("focusin", outside);
      document.removeEventListener("keydown", escape, true);
      window.removeEventListener("resize", resize);
    };
  }, [open, width]);
  return (
    <div className={`packet-menu ${className}`}>
      <button
        ref={anchor}
        className="packet-menu-trigger"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        {label}
        <ChevronDown size={12} />
      </button>
      {open &&
        createPortal(
          <div
            ref={popup}
            id={id}
            role="region"
            aria-label={`${label}选项`}
            className="packet-menu-popup"
            style={position}
            onClick={(event) => {
              const button = event.target.closest("button");
              if (
                button &&
                !button.disabled &&
                !button.hasAttribute("data-keep-menu")
              )
                setOpen(false);
            }}
          >
            {children}
          </div>,
          document.body,
        )}
    </div>
  );
}

export function WorkbenchTools({ compact, children }) {
  return compact ? (
    <PacketMenu label="工具" className="compact-workbench-tools">
      {children}
    </PacketMenu>
  ) : (
    <div className="feature-launcher" aria-label="增强分析工具">
      {children}
    </div>
  );
}
