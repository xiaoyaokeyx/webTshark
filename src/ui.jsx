import React, { useEffect, useRef } from "react";
import { X } from "lucide-react";
import { protocolClass } from "./api.js";
export function Logo() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
          <path
            d="M5 24C13 22 10 9 23 5c-3 7-4 12 4 19H5Z"
            fill="currentColor"
          />
          <path
            d="M4 26c4-3 7 3 11 0s7 3 13 0"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      </span>
      <span>
        WebShark<span className="brand-dot">.</span>
      </span>
    </div>
  );
}
export function IconButton({ icon: Icon, label, active = false, ...props }) {
  return (
    <button
      className={`icon-button ${active ? "is-active" : ""}`}
      aria-label={label}
      title={label}
      {...props}
    >
      <Icon size={16} />
    </button>
  );
}
export function Protocol({ name }) {
  return (
    <span className={`protocol protocol-${protocolClass(name)}`}>{name}</span>
  );
}
export function Modal({ title, subtitle, onClose, children, wide = false }) {
  const ref = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    ref.current?.focus();
    const listener = (e) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
      if (e.key === "Tab") {
        const items = [
          ...ref.current.querySelectorAll(
            'button:not(:disabled),input,select,textarea,a[href],audio,[tabindex="0"]',
          ),
        ];
        const first = items[0],
          last = items.at(-1);
        if (
          e.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === ref.current)
        ) {
          e.preventDefault();
          last?.focus();
        } else if (
          !e.shiftKey &&
          (document.activeElement === last ||
            document.activeElement === ref.current)
        ) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", listener);
    return () => {
      document.removeEventListener("keydown", listener);
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <section
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`modal ${wide ? "modal-wide" : ""}`}
      >
        <header className="modal-heading">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <IconButton icon={X} label="关闭弹窗" onClick={onClose} />
        </header>
        {children}
      </section>
    </div>
  );
}
export function Notice({ children }) {
  return (
    <div className="notice">
      <p>{children}</p>
    </div>
  );
}
