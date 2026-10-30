import React, { useEffect, useRef, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Copy,
  Star,
  GitBranch,
  ArrowUpRight,
  Filter,
  Settings2,
} from "lucide-react";
import { IconButton } from "./ui.jsx";
export function packetCondition(p, key) {
  const family = p.ipVersion === 6 ? "ipv6" : p.ipVersion === 4 ? "ip" : "eth";
  switch (key) {
    case "source":
      return `${family}.src == ${p.source}`;
    case "destination":
      return `${family}.dst == ${p.destination}`;
    case "protocol":
      return p.rtp
        ? "rtp"
        : p.transport && ["TCP", "UDP"].includes(p.protocol)
          ? p.protocol.toLowerCase()
          : { TLSv13: "tls", TLSv12: "tls" }[p.protocol.replaceAll(".", "")] ||
            p.protocol.toLowerCase();
    case "time":
      return `frame.time_relative == ${p.time}`;
    case "length":
      return `frame.len == ${p.length}`;
    default:
      return `frame.number == ${p.no}`;
  }
}
export function ContextMenu({
  context,
  onClose,
  onFilter,
  onStream,
  onRtp,
  onCopy,
  onMark,
}) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    el?.querySelector("button")?.focus();
    const close = (e) => {
      if (!el?.contains(e.target)) onClose();
    };
    const key = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
      if (["ArrowDown", "ArrowUp"].includes(e.key)) {
        e.preventDefault();
        const options = [...el.querySelectorAll("button:not(:disabled)")],
          i = options.indexOf(document.activeElement);
        options[
          (i + (e.key === "ArrowDown" ? 1 : -1) + options.length) %
            options.length
        ]?.focus();
      }
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", key);
    window.addEventListener("resize", onClose);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("keydown", key);
      window.removeEventListener("resize", onClose);
    };
  }, []);
  const action = (mode, prepare = false) => {
    onFilter(context.condition, mode, prepare);
    onClose();
  };
  return (
    <div
      ref={ref}
      role="menu"
      aria-label="数据包右键菜单"
      className="context-menu"
      style={{
        left: Math.max(8, Math.min(context.x, window.innerWidth - 300)),
        top: Math.max(8, Math.min(context.y, window.innerHeight - 440)),
      }}
    >
      <div className="context-caption">
        {context.label || "选择的字段"}
        <code>{context.condition || "该字段不能生成过滤表达式"}</code>
      </div>
      {[
        ["replace", "应用为过滤器"],
        ["exclude", "排除此条件"],
        ["and", "与当前条件组合（AND）"],
        ["or", "或当前条件（OR）"],
        ["and-not", "与当前条件组合并排除"],
      ].map(([mode, text]) => (
        <button
          key={mode}
          role="menuitem"
          disabled={!context.condition}
          onClick={() => action(mode)}
        >
          <Filter size={14} />
          {text}
        </button>
      ))}
      <button
        role="menuitem"
        disabled={!context.condition}
        onClick={() => action("replace", true)}
      >
        仅填入过滤栏，暂不应用
      </button>
      <div className="context-divider" />
      {context.packet?.transport && (
        <button
          role="menuitem"
          onClick={() => {
            onStream(context.packet);
            onClose();
          }}
        >
          <GitBranch size={14} />
          追踪 {context.packet.transport} 流
        </button>
      )}
      {context.packet?.transport === "UDP" && (
        <button
          role="menuitem"
          onClick={() => {
            onRtp(context.packet);
            onClose();
          }}
        >
          <Settings2 size={14} />
          {context.packet.rtp
            ? "设置此 RTP 流的 PT 编解码"
            : "将此 UDP 端口解码为 RTP"}
        </button>
      )}
      <button
        role="menuitem"
        onClick={() => {
          onMark(context.packet);
          onClose();
        }}
      >
        <Star size={14} />
        标记 / 取消标记数据包
      </button>
      <button
        role="menuitem"
        onClick={() => {
          onCopy(context.condition || context.label);
          onClose();
        }}
      >
        <Copy size={14} />
        复制过滤表达式
      </button>
    </div>
  );
}
function FieldNode({ field, depth = 0, active, onSelect, onContext }) {
  const [open, setOpen] = useState(
    depth === 0 && ["rtp", "webshark_rtp", "http"].includes(field.name),
  );
  const hasChildren = field.fields?.length > 0;
  return (
    <div className="tree-layer">
      <button
        className={`tree-row ${active === field ? "field-selected" : ""}`}
        style={{ paddingLeft: depth * 12 + 4 }}
        aria-expanded={hasChildren ? open : undefined}
        title={field.label}
        onClick={() => {
          if (hasChildren) setOpen(!open);
          onSelect(field);
        }}
        onContextMenu={(e) => {
          e.preventDefault();
          onSelect(field);
          onContext(e, field);
        }}
      >
        {hasChildren ? (
          open ? (
            <ChevronDown size={12} />
          ) : (
            <ChevronRight size={12} />
          )
        ) : (
          <span className="field-leaf" />
        )}
        <span>{field.label || `${field.name}: ${field.value}`}</span>
      </button>
      {open &&
        field.fields.map((child, i) => (
          <FieldNode
            key={`${child.name}-${i}`}
            field={child}
            depth={depth + 1}
            active={active}
            onSelect={onSelect}
            onContext={onContext}
          />
        ))}
    </div>
  );
}
export default function PacketInspector({
  packet,
  detail,
  loading,
  error,
  captureId,
  onContext,
  onStream,
  onCopy,
  onMark,
  marked,
}) {
  const [tab, setTab] = useState("fields"),
    [mode, setMode] = useState("hex"),
    [active, setActive] = useState(null);
  useEffect(() => setActive(null), [packet?.no, detail]);
  const bytes = detail?.bytes || [];
  return (
    <section className="details-grid">
      <div className="protocol-panel">
        <div className="panel-toolbar detail-toolbar">
          <div className="detail-tabs">
            <button
              className={tab === "fields" ? "active" : ""}
              onClick={() => setTab("fields")}
            >
              协议详情
            </button>
            <button
              className={tab === "notes" ? "active" : ""}
              onClick={() => setTab("notes")}
            >
              数据包备注
            </button>
          </div>
          <div className="panel-tools">
            <span className="selected-packet-label">
              {packet ? `Packet #${packet.no}` : "未选择"}
            </span>
            <IconButton
              icon={Star}
              label="标记当前数据包"
              disabled={!packet}
              active={marked}
              onClick={() => onMark(packet)}
            />
            <IconButton
              icon={Copy}
              label="复制数据包详情"
              disabled={!detail}
              onClick={() => onCopy(JSON.stringify(detail, null, 2))}
            />
          </div>
        </div>
        {tab === "notes" && packet ? (
          <PacketNote
            key={`${captureId}-${packet.no}`}
            captureId={captureId}
            no={packet.no}
          />
        ) : loading ? (
          <div className="details-empty">正在解码协议字段…</div>
        ) : error ? (
          <div className="details-empty error-text">{error}</div>
        ) : (
          <div className="protocol-tree">
            {detail?.layers.map((f, i) => (
              <FieldNode
                key={`${packet.no}-${f.name}-${i}`}
                field={f}
                active={active}
                onSelect={setActive}
                onContext={(e, field) =>
                  onContext({
                    x: e.clientX,
                    y: e.clientY,
                    condition: field.filter,
                    label: field.name,
                    packet,
                  })
                }
              />
            ))}
            {!packet && (
              <div className="details-empty">选择一个数据包查看详情</div>
            )}
          </div>
        )}
      </div>
      <div className="hex-panel">
        <div className="panel-toolbar detail-toolbar">
          <div className="panel-title">
            <h2>数据包字节</h2>
            <span className="bytes-label">{bytes.length} bytes</span>
          </div>
          <div className="panel-tools">
            <div className="segmented">
              <button
                className={mode === "hex" ? "active" : ""}
                onClick={() => setMode("hex")}
              >
                HEX
              </button>
              <button
                className={mode === "ascii" ? "active" : ""}
                onClick={() => setMode("ascii")}
              >
                ASCII
              </button>
            </div>
            <IconButton
              icon={Copy}
              label="复制原始字节"
              disabled={!bytes.length}
              onClick={() =>
                onCopy(
                  bytes.map((b) => b.toString(16).padStart(2, "0")).join(" "),
                )
              }
            />
          </div>
        </div>
        <div className="hex-content">
          {mode === "ascii" ? (
            <pre className="ascii-content">
              {bytes
                .map((b) =>
                  b >= 32 && b <= 126 ? String.fromCharCode(b) : "·",
                )
                .join("")}
            </pre>
          ) : (
            <>
              <div className="hex-heading">
                <span>OFFSET</span>
                <span>
                  00 01 02 03 04 05 06 07&nbsp; 08 09 0A 0B 0C 0D 0E 0F
                </span>
                <span>ASCII</span>
              </div>
              {Array.from({ length: Math.ceil(bytes.length / 16) }, (_, i) => (
                <div className="hex-row" key={i}>
                  <span className="hex-offset">
                    {(i * 16).toString(16).padStart(4, "0")}
                  </span>
                  <span className="hex-bytes">
                    {bytes.slice(i * 16, i * 16 + 16).map((b, j) => (
                      <span
                        key={j}
                        className={
                          active?.pos != null &&
                          i * 16 + j >= active.pos &&
                          i * 16 + j < active.pos + active.size
                            ? "byte-highlight"
                            : ""
                        }
                      >
                        {b.toString(16).padStart(2, "0")}
                        {j === 7 ? "  " : " "}
                      </span>
                    ))}
                  </span>
                  <span className="hex-ascii">
                    {bytes
                      .slice(i * 16, i * 16 + 16)
                      .map((b) =>
                        b >= 32 && b <= 126 ? String.fromCharCode(b) : "·",
                      )
                      .join("")}
                  </span>
                </div>
              ))}
            </>
          )}
        </div>
        <div className="hex-footer">
          <span>
            {active
              ? `${active.name}${active.pos != null ? ` · 字节 ${active.pos}–${active.pos + active.size - 1}` : " · 生成字段或重组数据"}`
              : "右键协议字段，可直接设置过滤器"}
          </span>
          <button
            className="text-button"
            disabled={!packet?.transport}
            onClick={() => onStream(packet)}
          >
            <GitBranch size={13} />
            追踪流
            <ArrowUpRight size={12} />
          </button>
        </div>
      </div>
    </section>
  );
}
function PacketNote({ captureId, no }) {
  const key = `webshark-note-${captureId}-${no}`;
  const [note, setNote] = useState(() => {
      try {
        return localStorage.getItem(key) || "";
      } catch {
        return "";
      }
    }),
    [status, setStatus] = useState("");
  return (
    <div className="packet-note">
      <label htmlFor="packet-note">数据包 #{no} · 备注保存在当前浏览器</label>
      <textarea
        id="packet-note"
        value={note}
        onChange={(e) => {
          setNote(e.target.value);
          setStatus("");
        }}
        placeholder="记录发现…"
      />
      <div className="note-footer">
        <span role="status">{status}</span>
        <button
          className="button secondary"
          onClick={() => {
            try {
              localStorage.setItem(key, note);
              setStatus("已保存");
            } catch {
              setStatus("浏览器存储不可用");
            }
          }}
        >
          保存备注
        </button>
      </div>
    </div>
  );
}
