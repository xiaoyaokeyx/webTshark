import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  AudioLines,
  BookOpen,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  Download,
  FileCode2,
  Filter,
  FolderOpen,
  GitBranch,
  Globe2,
  HardDrive,
  Info,
  Layers3,
  ListFilter,
  LoaderCircle,
  MoreHorizontal,
  Network,
  PanelLeftClose,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Star,
  Trash2,
  TriangleAlert,
  Upload,
  X,
} from "lucide-react";
import {
  api,
  capturePath,
  combineFilter,
  downloadBlob,
  protocolClass,
  sizeLabel,
  uploadCapture,
} from "./api.js";
import { IconButton, Logo, Modal, Notice, Protocol } from "./ui.jsx";
import PacketInspector, {
  ContextMenu,
  packetCondition,
} from "./PacketInspector.jsx";
import RtpPanel, { MappingEditor, RtpDetection } from "./RtpPanel.jsx";
const nav = [
  ["packets", "数据包分析", Layers3],
  ["statistics", "统计概览", Activity],
  ["conversations", "网络会话", GitBranch],
  ["endpoints", "网络端点", Globe2],
  ["rtp", "RTP 媒体流", AudioLines],
  ["expert", "专家信息", ShieldCheck],
];
const presets = [
  ["全部数据包", ""],
  ["TCP", "tcp"],
  ["HTTP", "http"],
  ["DNS", "dns"],
  ["RTP", "rtp"],
  [
    "异常数据包",
    "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.flags.reset == 1 || tcp.analysis.zero_window",
  ],
];
const emptySummary = {
  count: 0,
  bytes: 0,
  duration: 0,
  protocols: [],
  endpoints: [],
  conversations: [],
  media: [],
  issues: [],
  issueCount: 0,
  activity: [],
};
function readStorage(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}
function TrafficChart({ summary, large = false }) {
  const raw = summary.activity || [],
    chunk = Math.max(1, Math.ceil(raw.length / 80)),
    points = [];
  for (let i = 0; i < raw.length; i += chunk)
    points.push({
      time: raw[i].time,
      bytes: raw.slice(i, i + chunk).reduce((s, p) => s + p.bytes, 0),
    });
  const max = Math.max(1, ...points.map((p) => p.bytes));
  return (
    <div className={`traffic-chart ${large ? "large-chart" : ""}`}>
      <div className="chart-axis">
        <span>{sizeLabel(max)}</span>
        <span>0 B</span>
      </div>
      <div className="chart-plot">
        <div className="chart-grid" />
        <div className="chart-bars">
          {points.map((p, i) => (
            <div
              key={i}
              className="chart-bar"
              style={{ height: `${Math.max(2, (p.bytes / max) * 100)}%` }}
              title={`${p.time.toFixed(3)} s · ${sizeLabel(p.bytes)}`}
            />
          ))}
        </div>
        <div className="chart-ticks">
          {Array.from({ length: 7 }, (_, i) => (
            <span key={i}>{((summary.duration * i) / 6).toFixed(2)} s</span>
          ))}
        </div>
      </div>
    </div>
  );
}
function highlighted(text, needle) {
  if (!needle) return text;
  const parts = [],
    lower = text.toLowerCase(),
    q = needle.toLowerCase();
  let from = 0,
    index;
  while ((index = lower.indexOf(q, from)) !== -1) {
    parts.push(
      text.slice(from, index),
      <mark key={index}>{text.slice(index, index + q.length)}</mark>,
    );
    from = index + q.length;
    if (parts.length > 2000) break;
  }
  parts.push(text.slice(from));
  return parts;
}
export default function App() {
  const [health, setHealth] = useState(null),
    [captures, setCaptures] = useState([]),
    [capture, setCapture] = useState(null),
    [bootError, setBootError] = useState("");
  const [view, setView] = useState("packets"),
    [modal, setModal] = useState(null),
    [toast, setToast] = useState(""),
    [context, setContext] = useState(null),
    [mappingTarget, setMappingTarget] = useState(null),
    [detectionPort, setDetectionPort] = useState(null);
  const [expression, setExpression] = useState(""),
    [applied, setApplied] = useState(""),
    [query, setQuery] = useState({ filter: "", page: 0 }),
    [filterError, setFilterError] = useState(""),
    [loading, setLoading] = useState(false),
    [rows, setRows] = useState([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(0),
    [filteredBytes, setFilteredBytes] = useState(0),
    [selectedNo, setSelectedNo] = useState(8),
    [detail, setDetail] = useState(null),
    [detailError, setDetailError] = useState(""),
    [detailLoading, setDetailLoading] = useState(false);
  const [bookmarked, setBookmarked] = useState(new Set()),
    [markedOnly, setMarkedOnly] = useState(false),
    [colors, setColors] = useState(true),
    [compact, setCompact] = useState(false),
    [sidebarOpen, setSidebarOpen] = useState(false),
    [sidebarCollapsed, setSidebarCollapsed] = useState(false),
    [savedFilters, setSavedFilters] = useState(() =>
      readStorage("webshark-filters", ["tcp.port == 443", "rtp.p_type == 96"]),
    ),
    [showSaved, setShowSaved] = useState(false),
    [suggestions, setSuggestions] = useState([]);
  const [importFile, setImportFile] = useState(null),
    [importError, setImportError] = useState(""),
    [uploading, setUploading] = useState(false),
    [progress, setProgress] = useState(0),
    [stream, setStream] = useState(null),
    [streamLoading, setStreamLoading] = useState(false),
    [streamError, setStreamError] = useState(""),
    [streamDirection, setStreamDirection] = useState("both"),
    [streamFormat, setStreamFormat] = useState("UTF-8"),
    [streamSearch, setStreamSearch] = useState(""),
    [exportFormat, setExportFormat] = useState("pcapng"),
    [pendingDelete, setPendingDelete] = useState(null);
  const inputRef = useRef(null),
    fileRef = useRef(null),
    tableRef = useRef(null),
    uploadAbort = useRef(null),
    querySerial = useRef(0),
    streamSerial = useRef(0),
    bootSerial = useRef(0);
  const summary = capture?.summary || emptySummary,
    selected = rows.find((p) => p.no === selectedNo) || rows[0] || null,
    ready = capture?.status === "ready";
  const title = nav.find(([id]) => id === view)?.[1] || "数据包分析";
  async function refreshList() {
    const list = await api("/captures");
    setCaptures(list);
    return list;
  }
  async function boot() {
    const version = ++bootSerial.current;
    setBootError("");
    try {
      const h = await api("/health");
      if (version !== bootSerial.current) return;
      setHealth(h);
      if (!h.ready) throw new Error(h.error);
      const list = await refreshList();
      const saved = sessionStorage.getItem("webshark-capture");
      const c =
        list.find((c) => c.id === saved && c.status === "ready") ||
        list.find((c) => c.status === "ready") ||
        (await api("/demo", { method: "POST" }));
      if (version === bootSerial.current) selectCapture(c);
    } catch (e) {
      if (version === bootSerial.current)
        setBootError(
          e.message.includes("fetch")
            ? "无法连接本地解析服务，请运行 npm run dev 或 npm start。"
            : e.message,
        );
    }
  }
  function selectCapture(c) {
    setCapture(c);
    setRows([]);
    setDetail(null);
    setExpression("");
    setApplied("");
    setQuery({ filter: "", page: 0 });
    setMarkedOnly(false);
    setBookmarked(new Set());
    setSelectedNo(c.demo ? 8 : 1);
    setFilterError("");
    setSidebarOpen(false);
    setContext(null);
    sessionStorage.setItem("webshark-capture", c.id);
  }
  useEffect(() => {
    boot();
    return () => {
      bootSerial.current++;
    };
  }, []);
  useEffect(() => {
    if (!capture || !["indexing", "uploading"].includes(capture.status)) return;
    let cancelled = false,
      timer;
    const poll = async () => {
      try {
        const next = await api(capturePath(capture.id));
        if (cancelled) return;
        setCapture(next);
        if (["indexing", "uploading"].includes(next.status))
          timer = setTimeout(poll, 700);
        else {
          refreshList().catch(() => {});
          if (next.error) setToast(next.error);
        }
      } catch (e) {
        if (!cancelled) {
          setBootError(e.message);
          timer = setTimeout(poll, 2000);
        }
      }
    };
    timer = setTimeout(poll, 400);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [capture?.id, capture?.status]);
  useEffect(() => {
    if (!ready) return;
    const controller = new AbortController(),
      serial = ++querySerial.current;
    setLoading(true);
    setFilterError("");
    let filter = query.filter;
    if (markedOnly) {
      const ids = [...bookmarked];
      const marks = ids.length
        ? `frame.number in {${ids.join(" ")}}`
        : "frame.number == 0";
      filter = combineFilter(filter, marks, "and");
    }
    api(
      capturePath(
        capture.id,
        `/packets?filter=${encodeURIComponent(filter)}&page=${query.page}`,
      ),
      { signal: controller.signal },
    )
      .then((data) => {
        if (serial !== querySerial.current) return;
        setRows(data.packets);
        setTotal(data.total);
        setPage(data.page);
        setFilteredBytes(data.bytes);
        setApplied(query.filter);
        setSelectedNo((current) =>
          data.packets.some((p) => p.no === current)
            ? current
            : data.packets[0]?.no || null,
        );
      })
      .catch((e) => {
        if (e.name !== "AbortError" && serial === querySerial.current)
          setFilterError(e.message);
      })
      .finally(() => {
        if (serial === querySerial.current) setLoading(false);
      });
    return () => controller.abort();
  }, [
    capture?.id,
    capture?.revision,
    ready,
    query,
    markedOnly,
    markedOnly ? [...bookmarked].join(",") : "",
  ]);
  useEffect(() => {
    setDetail(null);
    setDetailError("");
    if (!selected || !ready) return;
    const controller = new AbortController();
    setDetailLoading(true);
    api(capturePath(capture.id, `/packets/${selected.no}`), {
      signal: controller.signal,
    })
      .then(setDetail)
      .catch((e) => {
        if (e.name !== "AbortError") setDetailError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setDetailLoading(false);
      });
    return () => controller.abort();
  }, [capture?.id, capture?.revision, selected?.no, ready]);
  useEffect(() => {
    const row = tableRef.current?.querySelector(".selected-row");
    if (!row) return;
    const bounds = tableRef.current.getBoundingClientRect(),
      rect = row.getBoundingClientRect();
    if (rect.bottom > bounds.bottom)
      tableRef.current.scrollTop += rect.bottom - bounds.bottom + 4;
    else if (rect.top < bounds.top + 30)
      tableRef.current.scrollTop -= bounds.top + 30 - rect.top;
  }, [selected?.no, rows]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 5000);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    const key = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setView("packets");
        requestAnimationFrame(() => inputRef.current?.focus());
      }
      if ((e.metaKey || e.ctrlKey) && e.key === ",") {
        e.preventDefault();
        setModal("settings");
      }
      if (e.key === "Escape") {
        setContext(null);
        setShowSaved(false);
        setSuggestions([]);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  useEffect(() => {
    const token = expression.match(/[a-zA-Z_][\w.]*$/)?.[0];
    if (
      !token ||
      token.length < 3 ||
      document.activeElement !== inputRef.current
    ) {
      setSuggestions([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(
      () =>
        api(`/fields?q=${encodeURIComponent(token)}`)
          .then((data) => {
            if (!cancelled)
              setSuggestions(data.filter((s) => s !== token).slice(0, 6));
          })
          .catch(() => {}),
      200,
    );
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [expression]);
  function apply(value = expression) {
    setExpression(value);
    setQuery({ filter: value, page: 0 });
    setView("packets");
    setMarkedOnly(false);
    setSuggestions([]);
    setShowSaved(false);
    setContext(null);
  }
  function navigate(id) {
    setView(id);
    setSidebarOpen(false);
    setContext(null);
  }
  function mark(packet = selected) {
    if (!packet) return;
    setBookmarked((previous) => {
      const next = new Set(previous);
      next.has(packet.no) ? next.delete(packet.no) : next.add(packet.no);
      return next;
    });
  }
  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      setToast("已复制到剪贴板");
    } catch {
      setToast("浏览器无法访问剪贴板，请手动复制");
    }
  }
  function contextFor(event, p, key = "no") {
    event.preventDefault();
    setSelectedNo(p.no);
    setContext({
      x: event.clientX || 40,
      y: event.clientY || 200,
      packet: p,
      label:
        {
          no: `数据包 #${p.no}`,
          time: "相对时间",
          source: "源地址",
          destination: "目标地址",
          protocol: "协议",
          length: "数据包长度",
          info: "数据包信息",
        }[key] || "数据包字段",
      condition: packetCondition(p, key),
    });
  }
  function filterContext(condition, mode, prepare = false) {
    const value = combineFilter(applied, condition, mode);
    if (prepare) {
      setExpression(value);
      setView("packets");
      requestAnimationFrame(() => inputRef.current?.focus());
    } else apply(value);
  }
  function saveFilter() {
    if (!expression.trim()) return setToast("先输入一个过滤表达式");
    const saved = [...new Set([...savedFilters, expression])].slice(-30);
    setSavedFilters(saved);
    try {
      localStorage.setItem("webshark-filters", JSON.stringify(saved));
    } catch {}
    setToast("过滤表达式已收藏");
  }
  function acceptFile(file) {
    setImportError("");
    if (!file) return;
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
      setImportFile(null);
      return setImportError("请选择 PCAP、PCAPNG 或 CAP 文件");
    }
    if (file.size > (health?.maxUpload || 1024 ** 3)) {
      setImportFile(null);
      return setImportError(
        `文件超过 ${sizeLabel(health?.maxUpload)} 上传限制`,
      );
    }
    setImportFile(file);
  }
  async function importCapture() {
    if (!importFile) return;
    setUploading(true);
    setProgress(0);
    setImportError("");
    uploadAbort.current = new AbortController();
    try {
      const c = await uploadCapture(
        importFile,
        setProgress,
        uploadAbort.current.signal,
      );
      selectCapture(c);
      setModal(null);
      setView("packets");
      refreshList().catch(() => {});
    } catch (e) {
      setImportError(e.message);
    } finally {
      setUploading(false);
    }
  }
  async function updateConfig(config) {
    if (!ready) throw new Error("请等待当前解析完成");
    const next = await api(capturePath(capture.id, "/config"), {
      method: "PUT",
      body: config,
    });
    setCapture(next);
    setRows([]);
    setDetail(null);
    setToast("已保存设置，正在重新解析当前抓包");
  }
  async function saveMapping(mapping, existing) {
    let mappings = capture.config.mappings.filter((m) => m !== existing);
    const key = (m) =>
      [
        m.scope,
        m.pt,
        m.source,
        m.destination,
        m.srcPort,
        m.dstPort,
        m.ssrc,
      ].join("|");
    mappings = mappings.filter((m) => key(m) !== key(mapping));
    await updateConfig({ ...capture.config, mappings: [...mappings, mapping] });
  }
  function editMapping(stream, existing) {
    setMappingTarget({ stream, existing });
    setModal("mapping");
  }
  function rtpContext(packet) {
    if (packet.rtp) {
      const stream = summary.media.find(
        (s) =>
          s.source === packet.source &&
          s.destination === packet.destination &&
          s.srcPort === packet.srcPort &&
          s.dstPort === packet.dstPort &&
          Number(s.ssrc) === Number(packet.rtp.ssrc),
      );
      editMapping(stream, null);
    } else {
      setDetectionPort(packet.dstPort);
      setModal("rtpDetection");
    }
  }
  async function openStream(packet) {
    if (!packet?.transport || packet.stream == null) return;
    const serial = ++streamSerial.current;
    setStream(null);
    setStreamError("");
    setStreamLoading(true);
    setStreamDirection("both");
    setStreamSearch("");
    setModal("stream");
    try {
      const result = await api(
        capturePath(
          capture.id,
          `/stream?transport=${packet.transport.toLowerCase()}&index=${packet.stream}`,
        ),
      );
      if (serial === streamSerial.current) setStream(result);
    } catch (e) {
      if (serial === streamSerial.current) setStreamError(e.message);
    } finally {
      if (serial === streamSerial.current) setStreamLoading(false);
    }
  }
  function exportPage() {
    const keys = [
      "no",
      "time",
      "source",
      "destination",
      "protocol",
      "length",
      "info",
    ];
    const data =
      exportFormat === "json"
        ? JSON.stringify(rows, null, 2)
        : "\ufeff" +
          [
            keys.join(","),
            ...rows.map((p) =>
              keys
                .map((k) => `"${String(p[k] ?? "").replaceAll('"', '""')}"`)
                .join(","),
            ),
          ].join("\n");
    downloadBlob(
      new Blob([data], {
        type: exportFormat === "json" ? "application/json" : "text/csv",
      }),
      `webshark-page-${page + 1}.${exportFormat}`,
    );
    setModal(null);
  }
  async function removeCapture(c) {
    try {
      await api(capturePath(c.id), { method: "DELETE" });
      setPendingDelete(null);
      const list = await refreshList();
      if (c.id === capture?.id) {
        if (list.length) selectCapture(list[0]);
        else {
          setCapture(null);
          setRows([]);
          setDetail(null);
        }
      }
      setToast("抓包及其解析结果已删除");
    } catch (e) {
      setToast(e.message);
    }
  }
  const fullFilter = markedOnly
    ? combineFilter(
        applied,
        bookmarked.size
          ? `frame.number in {${[...bookmarked].join(" ")}}`
          : "frame.number == 0",
        "and",
      )
    : applied;
  return (
    <div
      className={`app ${compact ? "compact" : ""} ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}
    >
      {sidebarOpen && (
        <button
          className="sidebar-scrim"
          aria-label="关闭导航"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <Logo />
        <button className="workspace-switch" onClick={() => setModal("files")}>
          <span className="workspace-icon">
            <Network size={17} />
          </span>
          <span>
            我的工作空间<small>本地离线分析</small>
          </span>
          <ChevronDown size={14} />
        </button>
        <div className="nav-section-label">工作空间</div>
        <nav aria-label="分析导航">
          {nav.map(([id, label, Icon]) => (
            <button
              key={id}
              className={`nav-item ${view === id ? "active" : ""}`}
              onClick={() => navigate(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "packets" && (
                <span className="nav-count">{summary.count}</span>
              )}
              {id === "rtp" && summary.media.length > 0 && (
                <span className="nav-count">{summary.media.length}</span>
              )}
              {id === "expert" && summary.issueCount > 0 && (
                <span className="warning-count">{summary.issueCount}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-divider" />
        <div className="nav-section-label recent-label">
          最近打开
          <IconButton
            icon={Plus}
            label="打开新的抓包文件"
            onClick={() => setModal("import")}
          />
        </div>
        <div className="recent-files">
          {captures.slice(0, 4).map((c) => (
            <button
              key={c.id}
              className={`recent-file ${c.id === capture?.id ? "selected" : ""}`}
              onClick={() => selectCapture(c)}
            >
              <FileCode2 size={17} />
              <span title={c.name}>
                {c.name}
                <small>
                  {c.demo ? "合成演示抓包" : "本地文件"} · {sizeLabel(c.size)}
                </small>
              </span>
              {c.id === capture?.id && <span className="file-active-dot" />}
            </button>
          ))}
        </div>
        <button className="recent-file" onClick={() => setModal("files")}>
          <FolderOpen size={17} />
          <span>
            管理抓包文件<small>{captures.length} 个文件保存在本机</small>
          </span>
        </button>
        <div className="sidebar-bottom">
          <div className="local-card">
            <div className="local-card-icon">
              <HardDrive size={18} />
            </div>
            <strong>专注离线分析</strong>
            <p>
              从每一个数据包，
              <br />
              读懂网络正在发生什么。
            </p>
            <span>
              <span className="status-dot" />
              {health?.ready ? "TShark 解析引擎已连接" : "等待解析服务"}
            </span>
          </div>
          <button
            className="sidebar-setting"
            onClick={() => setModal("settings")}
          >
            <Settings2 size={17} />
            偏好设置<span>⌘ ,</span>
          </button>
          <button className="sidebar-setting" onClick={() => setModal("help")}>
            <CircleHelp size={17} />
            帮助与快捷键
            <ArrowUpRight size={14} />
          </button>
          <div className="sidebar-version">
            WebShark <span>Offline Analyzer v0.2</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <IconButton
              icon={PanelLeftClose}
              label="切换导航"
              onClick={() =>
                window.matchMedia("(min-width:1024px)").matches
                  ? setSidebarCollapsed(!sidebarCollapsed)
                  : setSidebarOpen(!sidebarOpen)
              }
            />
            <span>工作空间</span>
            <ChevronRight size={13} />
            <strong>{title}</strong>
          </div>
          <div className="topbar-right">
            <span className="offline-label">
              <span className="status-dot" />
              离线分析模式
            </span>
            <span className="topbar-divider" />
            <button
              className="text-button docs-link"
              onClick={() => setModal("help")}
            >
              <BookOpen size={15} />
              使用指南
            </button>
            <IconButton
              icon={CircleHelp}
              label="帮助"
              onClick={() => setModal("help")}
            />
            <span className="avatar">Y</span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">PACKET INTELLIGENCE</div>
              <h1>
                {title}
                <span className="preview-badge">
                  {health?.ready ? "TShark 驱动" : "离线工作台"}
                </span>
              </h1>
              <p>
                {view === "rtp"
                  ? "配置动态载荷映射，深入每一条媒体流。"
                  : "洞察每一次连接，让网络问题清晰可见。"}
              </p>
            </div>
            <div className="page-actions">
              <button
                className="button secondary"
                disabled={!ready}
                onClick={() => setModal("export")}
              >
                <Download size={15} />
                导出
                <ChevronDown size={13} />
              </button>
              <button
                className="button primary"
                onClick={() => {
                  setImportFile(null);
                  setImportError("");
                  setModal("import");
                }}
              >
                <Plus size={17} />
                打开抓包文件
              </button>
            </div>
          </div>
          {bootError && (
            <div className="service-error" role="alert">
              <TriangleAlert size={18} />
              <span>{bootError}</span>
              <button className="button secondary" onClick={boot}>
                <RefreshCw size={14} />
                重试连接
              </button>
            </div>
          )}
          {capture && (
            <section className="capture-card" aria-label="当前抓包文件">
              <div className="capture-top">
                <div className="capture-file-icon">
                  <FileCode2 size={20} />
                </div>
                <div className="capture-file-title">
                  <strong>{capture.name}</strong>
                  <span>
                    <span className="status-dot" />
                    {ready
                      ? "已解析"
                      : capture.status === "indexing"
                        ? "解析中"
                        : capture.status === "error"
                          ? "解析失败"
                          : capture.status === "cancelled"
                            ? "已取消"
                            : "上传中"}
                    <span className="meta-dot">·</span>
                    {capture.demo ? "合成演示抓包 · 真实引擎解析" : "本地抓包"}
                    <span className="meta-dot">·</span>
                    {sizeLabel(capture.size)}
                  </span>
                </div>
                <span className="capture-type">
                  {capture.name.split(".").at(-1).toUpperCase()}
                </span>
                <IconButton
                  icon={Info}
                  label="抓包文件详情"
                  onClick={() => setModal("fileInfo")}
                />
              </div>
              {ready && (
                <div className="capture-metrics">
                  <div>
                    <span>数据包总数</span>
                    <strong>
                      {summary.count.toLocaleString()}
                      <small>packets</small>
                    </strong>
                  </div>
                  <div>
                    <span>捕获流量</span>
                    <strong>
                      {sizeLabel(summary.bytes).split(" ")[0]}
                      <small>{sizeLabel(summary.bytes).split(" ")[1]}</small>
                    </strong>
                  </div>
                  <div>
                    <span>捕获时长</span>
                    <strong>
                      {summary.duration.toFixed(3)}
                      <small>秒</small>
                    </strong>
                  </div>
                  <div>
                    <span>协议类型</span>
                    <strong>
                      {summary.protocols.length}
                      <small>protocols</small>
                    </strong>
                  </div>
                  <div className="capture-health">
                    <span className="health-icon">
                      <TriangleAlert size={15} />
                    </span>
                    <span>{summary.issueCount} 个分析提示</span>
                    <button onClick={() => navigate("expert")}>
                      查看详情
                      <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              )}
            </section>
          )}
          {capture?.status === "indexing" && (
            <div className="analysis-progress" role="status">
              <LoaderCircle className="spin" size={25} />
              <div>
                <strong>正在解析抓包</strong>
                <p>
                  已处理 {capture.processed.toLocaleString()}{" "}
                  个数据包。解析结果写入本地索引，完成后即可浏览。
                </p>
              </div>
              <button
                className="button secondary"
                onClick={() =>
                  api(capturePath(capture.id, "/cancel"), { method: "POST" })
                    .then(setCapture)
                    .catch((e) => setToast(e.message))
                }
              >
                取消解析
              </button>
            </div>
          )}
          {capture && ["error", "cancelled"].includes(capture.status) && (
            <div className="service-error" role="alert">
              <TriangleAlert size={18} />
              <span>{capture.error || "解析已取消，可以重新导入文件。"}</span>
            </div>
          )}
          {!capture && !bootError && (
            <div className="empty-state">
              <FolderOpen size={32} />
              <strong>打开一个抓包，开始分析</strong>
              <button
                className="button primary"
                onClick={() => setModal("import")}
              >
                选择 PCAP 文件
              </button>
            </div>
          )}
          {ready && view === "packets" && (
            <>
              <section className="activity-strip">
                <div className="activity-heading">
                  <span>
                    <Activity size={15} />
                    流量时间线
                  </span>
                  <div>
                    <span className="chart-legend">
                      <i />
                      完整抓包 · 捕获字节
                    </span>
                    <span className="timeline-interval">自适应时间分桶</span>
                  </div>
                </div>
                <TrafficChart summary={summary} />
              </section>
              <section className="filter-section" aria-label="显示过滤操作">
                <div
                  className={`filter-input ${filterError ? "filter-invalid" : ""}`}
                >
                  <Filter size={16} />
                  <label htmlFor="packet-filter" className="sr-only">
                    显示过滤器
                  </label>
                  <input
                    id="packet-filter"
                    ref={inputRef}
                    value={expression}
                    placeholder="Wireshark 过滤器，例如 ip.addr == 10.10.0.10 或 rtp.p_type == 96"
                    onChange={(e) => setExpression(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") apply();
                    }}
                    spellCheck={false}
                  />
                  {expression ? (
                    <IconButton
                      icon={X}
                      label="清除过滤器"
                      onClick={() => apply("")}
                    />
                  ) : (
                    <kbd>⌘ K</kbd>
                  )}
                  <div className="filter-action-divider" />
                  <IconButton
                    icon={Star}
                    label="保存当前过滤器"
                    onClick={saveFilter}
                  />
                  <button className="apply-button" onClick={() => apply()}>
                    {loading ? (
                      <LoaderCircle className="spin" size={13} />
                    ) : (
                      <>
                        应用
                        <ArrowRight size={14} />
                      </>
                    )}
                  </button>
                </div>
                {suggestions.length > 0 && (
                  <div
                    className="field-suggestions"
                    role="listbox"
                    aria-label="过滤字段建议"
                  >
                    {suggestions.map((s) => (
                      <button
                        key={s}
                        role="option"
                        onClick={() => {
                          setExpression(
                            expression.replace(/[a-zA-Z_][\w.]*$/, s) + " ",
                          );
                          setSuggestions([]);
                          inputRef.current.focus();
                        }}
                      >
                        <Code2 size={13} />
                        {s}
                      </button>
                    ))}
                  </div>
                )}
                {filterError && (
                  <p className="filter-error" role="alert">
                    <TriangleAlert size={13} />
                    {filterError} · 列表保留上次成功的筛选结果
                  </p>
                )}
                <div className="filter-presets">
                  <div className="preset-list">
                    {presets.map(([label, value]) => (
                      <button
                        key={label}
                        className={`preset ${applied === value ? "selected" : ""}`}
                        onClick={() => apply(value)}
                      >
                        {label === "异常数据包" && <TriangleAlert size={12} />}
                        <span>{label}</span>
                      </button>
                    ))}
                  </div>
                  <div className="saved-filter-wrap">
                    <button
                      className="text-button saved-filter"
                      onClick={() => setShowSaved(!showSaved)}
                    >
                      <Star size={13} />
                      已保存的过滤器
                      <ChevronDown size={12} />
                    </button>
                    {showSaved && (
                      <div className="saved-popover">
                        <strong>收藏的显示过滤器</strong>
                        {savedFilters.map((f) => (
                          <button key={f} onClick={() => apply(f)}>
                            <Code2 size={14} />
                            <code>{f}</code>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </section>
              <section
                className={`packet-panel ${loading ? "is-loading" : ""}`}
              >
                <div className="panel-toolbar">
                  <div className="panel-title">
                    <Layers3 size={16} />
                    <h2>数据包列表</h2>
                    <span className="count-badge">{total}</span>
                    {loading && <span className="filtered-label">筛选中…</span>}
                  </div>
                  <div className="panel-tools">
                    <button
                      className={`text-button ${markedOnly ? "accent-text" : ""}`}
                      onClick={() => {
                        setMarkedOnly(!markedOnly);
                        setQuery((q) => ({ ...q, page: 0 }));
                      }}
                    >
                      <Star
                        size={14}
                        fill={markedOnly ? "currentColor" : "none"}
                      />
                      <span>仅看标记</span>
                      {bookmarked.size > 0 && <small>{bookmarked.size}</small>}
                    </button>
                    <span className="tool-divider" />
                    <IconButton
                      icon={ListFilter}
                      label="切换协议行着色"
                      active={colors}
                      onClick={() => setColors(!colors)}
                    />
                    <IconButton
                      icon={SlidersHorizontal}
                      label="列表显示设置"
                      onClick={() => setModal("settings")}
                    />
                    <IconButton
                      icon={MoreHorizontal}
                      label="当前数据包操作"
                      disabled={!selected}
                      onClick={(e) => contextFor(e, selected)}
                    />
                  </div>
                </div>
                <div
                  ref={tableRef}
                  className={`packet-table-wrap ${colors ? "colored-rows" : ""}`}
                >
                  <table className="packet-table">
                    <thead>
                      <tr>
                        {[
                          ["no", "No."],
                          ["time", "时间 (s)"],
                          ["source", "源地址"],
                          ["destination", "目标地址"],
                          ["protocol", "协议"],
                          ["length", "长度"],
                          ["info", "信息"],
                        ].map(([key, label]) => (
                          <th key={key}>
                            {label}
                            {key === "no" && <ArrowDown size={10} />}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((p) => (
                        <tr
                          key={p.no}
                          tabIndex={0}
                          aria-selected={selected?.no === p.no}
                          className={`packet-row ${protocolClass(p.protocol)}-row ${p.issue ? "issue-row" : ""} ${selected?.no === p.no ? "selected-row" : ""}`}
                          onClick={() => setSelectedNo(p.no)}
                          onDoubleClick={() => openStream(p)}
                          onContextMenu={(e) => {
                            if (e.defaultPrevented) return;
                            contextFor(e, p);
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              setSelectedNo(p.no);
                            }
                            if (
                              e.key === "ContextMenu" ||
                              (e.shiftKey && e.key === "F10")
                            )
                              contextFor(e, p);
                            if (["ArrowDown", "ArrowUp"].includes(e.key)) {
                              e.preventDefault();
                              const next =
                                rows.indexOf(p) +
                                (e.key === "ArrowDown" ? 1 : -1);
                              if (rows[next]) {
                                setSelectedNo(rows[next].no);
                                e.currentTarget.parentElement.children[
                                  next
                                ]?.focus();
                              }
                            }
                          }}
                        >
                          {[
                            "no",
                            "time",
                            "source",
                            "destination",
                            "protocol",
                            "length",
                            "info",
                          ].map((key) => (
                            <td
                              key={key}
                              onContextMenu={(e) => contextFor(e, p, key)}
                              title={String(p[key] ?? "")}
                            >
                              {key === "no" ? (
                                <span className="row-number">
                                  {bookmarked.has(p.no) && (
                                    <Star size={9} fill="currentColor" />
                                  )}
                                  {p.no}
                                </span>
                              ) : key === "time" ? (
                                p.time.toFixed(6)
                              ) : key === "protocol" ? (
                                <Protocol name={p.protocol} />
                              ) : (
                                p[key]
                              )}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!rows.length && !loading && (
                    <div className="empty-state">
                      <Search size={27} />
                      <strong>没有匹配的数据包</strong>
                      <p>调整过滤表达式，或返回全部数据包。</p>
                      <button
                        className="button secondary"
                        onClick={() => apply("")}
                      >
                        清除筛选
                      </button>
                    </div>
                  )}
                </div>
                <div className="table-footer">
                  <span>
                    匹配 <strong>{total.toLocaleString()}</strong> /{" "}
                    {summary.count.toLocaleString()} 个 ·{" "}
                    {sizeLabel(filteredBytes)}
                  </span>
                  <div className="pagination">
                    <button
                      aria-label="上一页"
                      disabled={page === 0 || loading}
                      onClick={() =>
                        setQuery({ filter: applied, page: page - 1 })
                      }
                    >
                      <ChevronRight size={13} className="rotate-180" />
                    </button>
                    <span>
                      {page + 1} / {Math.max(1, Math.ceil(total / 100))}
                    </span>
                    <button
                      aria-label="下一页"
                      disabled={(page + 1) * 100 >= total || loading}
                      onClick={() =>
                        setQuery({ filter: applied, page: page + 1 })
                      }
                    >
                      <ChevronRight size={13} />
                    </button>
                    <span>100 包 / 页</span>
                  </div>
                  <span className="table-hint">右键字段筛选 · 双击追踪流</span>
                </div>
              </section>
              <PacketInspector
                packet={selected}
                detail={detail}
                loading={detailLoading}
                error={detailError}
                captureId={capture.id}
                onContext={setContext}
                onStream={openStream}
                onCopy={copy}
                onMark={mark}
                marked={selected && bookmarked.has(selected.no)}
              />
            </>
          )}
          {ready && view === "rtp" && (
            <RtpPanel
              capture={capture}
              onFilter={apply}
              onEdit={editMapping}
              onDetect={() => {
                setDetectionPort(null);
                setModal("rtpDetection");
              }}
              onRemove={(i) =>
                updateConfig({
                  ...capture.config,
                  mappings: capture.config.mappings.filter(
                    (_, index) => i !== index,
                  ),
                }).catch((e) => setToast(e.message))
              }
              onError={setToast}
            />
          )}
          {ready && view === "statistics" && (
            <section className="analysis-content">
              <div className="analysis-grid">
                <div className="analysis-card">
                  <div className="section-heading">
                    <h2>协议分布</h2>
                    <span>{summary.count} 个数据包</span>
                  </div>
                  <div className="distribution-bar">
                    {summary.protocols.map((s) => (
                      <div
                        key={s.protocol}
                        className={`distribution-${protocolClass(s.protocol)}`}
                        style={{ width: `${s.percentage}%` }}
                        title={`${s.protocol}: ${s.count}`}
                      />
                    ))}
                  </div>
                  {summary.protocols.map((s) => (
                    <button
                      key={s.protocol}
                      className="protocol-stat-row"
                      onClick={() =>
                        apply(
                          s.protocol.startsWith("TLS")
                            ? "tls"
                            : s.protocol.toLowerCase(),
                        )
                      }
                    >
                      <Protocol name={s.protocol} />
                      <div className="stat-progress">
                        <div style={{ width: `${s.percentage}%` }} />
                      </div>
                      <span>{s.count}</span>
                      <strong>{s.percentage.toFixed(1)}%</strong>
                      <ChevronRight size={14} />
                    </button>
                  ))}
                </div>
                <div className="analysis-card">
                  <div className="section-heading">
                    <h2>通信端点 Top 5</h2>
                    <button
                      className="text-button"
                      onClick={() => navigate("endpoints")}
                    >
                      查看全部
                      <ArrowRight size={13} />
                    </button>
                  </div>
                  {summary.endpoints.slice(0, 5).map((e, i) => (
                    <button
                      key={e.address}
                      className="endpoint-stat"
                      onClick={() =>
                        apply(
                          `${e.ipVersion === 6 ? "ipv6" : e.ipVersion === 4 ? "ip" : "eth"}.addr == ${e.address}`,
                        )
                      }
                    >
                      <span className="ranking">0{i + 1}</span>
                      <div>
                        <strong>{e.address}</strong>
                        <span>{e.tx + e.rx} 个收发数据包</span>
                      </div>
                      <b>{sizeLabel(e.bytes)}</b>
                      <ArrowUpRight size={14} />
                    </button>
                  ))}
                </div>
              </div>
              <div className="analysis-card">
                <div className="section-heading">
                  <h2>流量 I/O 图</h2>
                  <span>完整抓包 · 时间分桶汇总</span>
                </div>
                <TrafficChart summary={summary} large />
              </div>
            </section>
          )}
          {ready && view === "conversations" && (
            <section className="analysis-card standalone">
              <div className="section-heading">
                <h2>
                  网络会话{" "}
                  <span className="count-badge">
                    {summary.conversations.length}
                  </span>
                </h2>
                <span>点击会话筛选，或追踪双向载荷</span>
              </div>
              <div className="wide-table">
                <table className="analysis-table">
                  <thead>
                    <tr>
                      <th>协议</th>
                      <th>源端点</th>
                      <th>目标端点</th>
                      <th>数据包</th>
                      <th>流量</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.conversations.map((c) => (
                      <tr key={c.id}>
                        <td>
                          <Protocol name={c.transport} />
                        </td>
                        <td>
                          {c.source}
                          <small>:{c.srcPort}</small>
                        </td>
                        <td>
                          {c.destination}
                          <small>:{c.dstPort}</small>
                        </td>
                        <td>{c.count}</td>
                        <td>{sizeLabel(c.bytes)}</td>
                        <td>
                          <div className="media-actions">
                            <button
                              className="text-button accent-text"
                              onClick={() =>
                                apply(
                                  `${c.transport.toLowerCase()}.stream == ${c.stream}`,
                                )
                              }
                            >
                              查看数据包
                              <ArrowUpRight size={13} />
                            </button>
                            <button
                              className="text-button"
                              onClick={() => openStream(c)}
                            >
                              追踪流
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {ready && view === "endpoints" && (
            <section className="analysis-card standalone">
              <div className="section-heading">
                <h2>
                  网络端点{" "}
                  <span className="count-badge">
                    {summary.endpoints.length}
                  </span>
                </h2>
                <span>按捕获字节排序</span>
              </div>
              <div className="wide-table">
                <table className="analysis-table">
                  <thead>
                    <tr>
                      <th>端点地址</th>
                      <th>发送数据包</th>
                      <th>接收数据包</th>
                      <th>总流量</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.endpoints.map((e) => (
                      <tr key={e.address}>
                        <td>
                          <span className="endpoint-address">
                            <Globe2 size={15} />
                            {e.address}
                          </span>
                        </td>
                        <td>{e.tx}</td>
                        <td>{e.rx}</td>
                        <td>{sizeLabel(e.bytes)}</td>
                        <td>
                          <button
                            className="text-button accent-text"
                            onClick={() =>
                              apply(
                                `${e.ipVersion === 6 ? "ipv6" : e.ipVersion === 4 ? "ip" : "eth"}.addr == ${e.address}`,
                              )
                            }
                          >
                            作为过滤条件
                            <ArrowUpRight size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {ready && view === "expert" && (
            <section className="analysis-card standalone">
              <div className="section-heading">
                <h2>
                  专家信息{" "}
                  <span className="warning-count">{summary.issueCount}</span>
                </h2>
                <span>TShark 诊断 · 最多展示 2000 个事件</span>
              </div>
              <div className="expert-summary">
                <TriangleAlert size={20} />
                <div>
                  <strong>
                    {summary.issueCount
                      ? `发现 ${summary.issueCount} 个分析事件`
                      : "未检测到专家提示"}
                  </strong>
                  <p>提示来自协议分析器，需结合抓包位置与完整会话判断。</p>
                </div>
              </div>
              {summary.issues.map((p) => (
                <button
                  key={p.no}
                  className="expert-event"
                  onClick={() => {
                    apply(`frame.number == ${p.no}`);
                    setSelectedNo(p.no);
                  }}
                >
                  <span className="expert-severity">分析</span>
                  <div>
                    <strong>
                      {p.issue === "retransmission"
                        ? "TCP 重传"
                        : p.issue === "duplicate_ack"
                          ? "TCP 重复确认"
                          : p.issue === "reset"
                            ? "TCP RST"
                            : p.issue === "zero_window"
                              ? "TCP 零窗口"
                              : p.protocol + " 协议提示"}
                    </strong>
                    <span>{p.expert || p.info}</span>
                  </div>
                  <span>#{p.no}</span>
                  <ChevronRight size={15} />
                </button>
              ))}
            </section>
          )}
          {summary.truncatedGroups && (
            <Notice>
              端点和会话统计最多保留 10000
              组；当前抓包超出此范围，请先过滤后导出较小抓包。
            </Notice>
          )}
          <footer className="workspace-footer">
            <span>
              <span className="status-dot" />
              {loading ? "筛选中" : "就绪"}
              <span className="meta-dot">·</span>
              {capture?.demo
                ? "合成演示文件，使用真实 TShark 解析"
                : "数据保存在部署此服务的机器上"}
            </span>
            <span>
              用细节，连接全貌。<span className="footer-brand">WEBSHARK</span>
            </span>
          </footer>
        </main>
      </div>
      {context && (
        <ContextMenu
          context={context}
          onClose={() => setContext(null)}
          onFilter={filterContext}
          onStream={openStream}
          onRtp={rtpContext}
          onCopy={copy}
          onMark={mark}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          {toast}
        </div>
      )}
      {modal === "mapping" && capture && (
        <MappingEditor
          stream={mappingTarget?.stream}
          existing={mappingTarget?.existing}
          codecs={health?.codecs || []}
          onSave={saveMapping}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "rtpDetection" && capture && (
        <RtpDetection
          config={capture.config}
          initialPort={detectionPort}
          onSave={updateConfig}
          onClose={() => setModal(null)}
        />
      )}
      {modal === "import" && (
        <Modal
          title="打开抓包文件"
          subtitle="在部署此服务的机器上解析文件，支持 PCAP、PCAPNG 和 CAP。"
          onClose={() => {
            if (!uploading) setModal(null);
          }}
        >
          <div className="modal-body">
            <button
              className="dropzone"
              disabled={uploading}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (!uploading) acceptFile(e.dataTransfer.files[0]);
              }}
            >
              <span className="upload-icon">
                <Upload size={25} />
              </span>
              <strong>将抓包文件拖到这里</strong>
              <span>或点击选择本地文件</span>
              <small>
                单文件上限 {sizeLabel(health?.maxUpload || 1024 ** 3)}
              </small>
            </button>
            <input
              type="file"
              ref={fileRef}
              className="sr-only"
              accept=".pcap,.pcapng,.cap"
              onChange={(e) => acceptFile(e.target.files[0])}
            />
            {importFile && (
              <div className="selected-import">
                <FileCode2 size={20} />
                <div>
                  <strong>{importFile.name}</strong>
                  <span>{sizeLabel(importFile.size)}</span>
                </div>
                <Check size={16} />
              </div>
            )}
            {uploading && (
              <div className="upload-progress">
                <progress value={progress} max="100" />
                <span>
                  {progress < 100
                    ? `上传 ${progress}%`
                    : "上传完成，正在创建解析任务…"}
                </span>
              </div>
            )}
            {importError && (
              <p className="filter-error" role="alert">
                {importError}
              </p>
            )}
            <Notice>
              解析在后台进行，界面按每页 100
              个数据包加载。没有测试文件时，可以打开内置的 HTTP + 双向 RTP
              示例。
            </Notice>
            <div className="modal-actions">
              <button
                className="button secondary"
                disabled={uploading || !health?.ready}
                onClick={async () => {
                  try {
                    const c = await api("/demo", { method: "POST" });
                    selectCapture(c);
                    setModal(null);
                    setView("packets");
                    refreshList().catch(() => {});
                  } catch (e) {
                    setImportError(e.message);
                  }
                }}
              >
                打开示例
              </button>
              {uploading ? (
                <button
                  className="button secondary"
                  onClick={() => uploadAbort.current?.abort()}
                >
                  取消上传
                </button>
              ) : (
                <button
                  className="button primary"
                  disabled={!importFile || !health?.ready}
                  onClick={importCapture}
                >
                  <Upload size={15} />
                  导入并解析
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
      {modal === "export" && capture && (
        <Modal
          title="导出数据包"
          subtitle="保留当前筛选结果，或保存本页摘要。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body">
            <div className="export-summary">
              <FileCode2 size={24} />
              <div>
                <strong>{total} 个匹配数据包</strong>
                <span>{fullFilter || "全部数据包"}</span>
              </div>
            </div>
            <label className="field-label" htmlFor="export-format">
              文件格式与范围
            </label>
            <select
              className="form-select"
              id="export-format"
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value)}
            >
              <option value="pcapng">PCAPNG · 所有匹配数据包</option>
              <option value="csv">
                CSV · 当前页 {rows.length} 个数据包摘要
              </option>
              <option value="json">
                JSON · 当前页 {rows.length} 个数据包摘要
              </option>
            </select>
            <Notice>
              PCAPNG 导出保留原始数据包，不修改载荷。PT
              映射存储在此分析工作区中，不会写入原始载荷。
            </Notice>
            <div className="modal-actions">
              <button
                className="button secondary"
                onClick={() => setModal(null)}
              >
                取消
              </button>
              {exportFormat === "pcapng" ? (
                <a
                  className="button primary"
                  target="_blank"
                  rel="noreferrer"
                  download
                  href={`/api/captures/${capture.id}/export?filter=${encodeURIComponent(fullFilter)}`}
                  onClick={() => setModal(null)}
                >
                  <Download size={15} />
                  导出 PCAPNG
                </a>
              ) : (
                <button className="button primary" onClick={exportPage}>
                  <Download size={15} />
                  导出当前页
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
      {modal === "stream" && (
        <Modal
          wide
          title={`追踪 ${stream?.transport?.toUpperCase() || "协议"} 流`}
          subtitle={
            stream
              ? `Stream ${stream.number} · 载荷由 TShark 重组`
              : "正在从抓包重组双向载荷"
          }
          onClose={() => {
            streamSerial.current++;
            setModal(null);
          }}
        >
          {streamLoading ? (
            <div className="analysis-progress">
              <LoaderCircle className="spin" size={22} />
              正在重组流…
            </div>
          ) : streamError ? (
            <div className="modal-body">
              <p className="filter-error" role="alert">
                {streamError}
              </p>
            </div>
          ) : (
            stream && (
              <>
                <div className="stream-endpoints">
                  <span>
                    <i className="client-dot" />
                    端点 A <code>{stream.client}</code>
                  </span>
                  <ArrowRight size={16} />
                  <span>
                    <i className="server-dot" />
                    端点 B <code>{stream.server}</code>
                  </span>
                </div>
                <div className="stream-toolbar">
                  <div className="segmented">
                    {[
                      ["both", "双向"],
                      ["client", "A → B"],
                      ["server", "B → A"],
                    ].map(([value, label]) => (
                      <button
                        key={value}
                        className={streamDirection === value ? "active" : ""}
                        onClick={() => setStreamDirection(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                  <div className="stream-search">
                    <Search size={14} />
                    <input
                      aria-label="在流中查找"
                      placeholder="查找文本…"
                      value={streamSearch}
                      onChange={(e) => setStreamSearch(e.target.value)}
                    />
                  </div>
                  <select
                    aria-label="流显示格式"
                    value={streamFormat}
                    onChange={(e) => setStreamFormat(e.target.value)}
                  >
                    <option>UTF-8</option>
                    <option>HEX</option>
                  </select>
                </div>
                <div className="stream-body">
                  {stream.chunks
                    .filter(
                      (c) =>
                        streamDirection === "both" ||
                        c.direction === streamDirection,
                    )
                    .map((chunk, i) => (
                      <div
                        key={i}
                        className={`stream-message stream-${chunk.direction}`}
                      >
                        <span>
                          {chunk.direction === "client" ? "A → B" : "B → A"}
                        </span>
                        <pre>
                          {streamFormat === "HEX"
                            ? chunk.hex
                                .match(/.{1,32}/g)
                                ?.map((row) => row.match(/.{2}/g).join(" "))
                                .join("\n")
                            : highlighted(chunk.text, streamSearch)}
                        </pre>
                      </div>
                    ))}
                  {!stream.chunks.length && <p>此流没有应用载荷。</p>}
                </div>
                <div className="stream-footer">
                  <span>TLS/SRTP 等加密载荷仍为密文</span>
                  <button
                    className="button secondary"
                    onClick={() =>
                      downloadBlob(
                        new Blob(
                          [
                            stream.chunks
                              .map(
                                (c) =>
                                  `[${c.direction === "client" ? "A → B" : "B → A"}]\n${streamFormat === "HEX" ? c.hex : c.text}`,
                              )
                              .join("\n"),
                          ],
                          { type: "text/plain" },
                        ),
                        `stream-${stream.number}.txt`,
                      )
                    }
                  >
                    <Download size={14} />
                    保存流
                  </button>
                  <button
                    className="button primary"
                    onClick={() => {
                      apply(`${stream.transport}.stream == ${stream.number}`);
                      setModal(null);
                    }}
                  >
                    筛选此流
                    <ArrowRight size={14} />
                  </button>
                </div>
              </>
            )
          )}
        </Modal>
      )}
      {modal === "settings" && (
        <Modal
          title="偏好设置"
          subtitle="调整工作台的信息密度。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body">
            <label className="setting-row">
              <div>
                <strong>协议行着色</strong>
                <span>根据协议类型添加浅色背景</span>
              </div>
              <input
                type="checkbox"
                checked={colors}
                onChange={(e) => setColors(e.target.checked)}
              />
            </label>
            <label className="setting-row">
              <div>
                <strong>紧凑列表</strong>
                <span>减少数据包行间距</span>
              </div>
              <input
                type="checkbox"
                checked={compact}
                onChange={(e) => setCompact(e.target.checked)}
              />
            </label>
            <Notice>
              {health?.version || "解析服务未连接"} · 后端运行于{" "}
              {health?.node || "未知 Node 版本"}
              。服务只读取已导入的文件，不进行实时捕获。
            </Notice>
          </div>
        </Modal>
      )}
      {modal === "help" && (
        <Modal
          title="使用指南"
          subtitle="从数据包、协议字段到媒体内容。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body">
            <div className="help-step">
              <span>01</span>
              <div>
                <strong>导入真实抓包</strong>
                <p>
                  选择 PCAP / PCAPNG
                  文件，等待后台索引完成。大文件按页浏览；新的过滤条件需要扫描抓包。
                </p>
              </div>
            </div>
            <div className="help-step">
              <span>02</span>
              <div>
                <strong>右键字段，快速过滤</strong>
                <p>
                  右键源地址、目标地址、协议或协议树字段，选择替换、排除、AND、OR，或仅填入过滤栏。完整表达式交给
                  TShark 校验。
                </p>
              </div>
            </div>
            <div className="help-step">
              <span>03</span>
              <div>
                <strong>为 RTP 设置动态 PT</strong>
                <p>
                  缺少信令时先指定 UDP 端口解码为 RTP，然后按单向媒体流配置 PT
                  96–127、编解码、RTP 时钟及声道。G.711 PCMA / PCMU 支持试听与
                  WAV。
                </p>
              </div>
            </div>
            <div className="keyboard-shortcuts">
              <span>
                聚焦过滤器<kbd>⌘ / Ctrl K</kbd>
              </span>
              <span>
                右键菜单<kbd>Shift F10</kbd>
              </span>
              <span>
                切换数据包<kbd>↑ ↓</kbd>
              </span>
              <span>
                关闭弹窗<kbd>Esc</kbd>
              </span>
            </div>
            <Notice>
              此版本未覆盖 Wireshark 全部功能。其他音视频编码的播放、TLS/SRTP
              解密与多用户权限尚未接入。
            </Notice>
          </div>
        </Modal>
      )}
      {modal === "fileInfo" && capture && (
        <Modal
          title="抓包文件信息"
          subtitle={capture.name}
          onClose={() => setModal(null)}
        >
          <div className="modal-body">
            <dl className="file-info-list">
              {[
                ["数据来源", capture.demo ? "合成演示文件" : "用户导入文件"],
                ["解析引擎", health?.version],
                ["文件大小", sizeLabel(capture.size)],
                ["数据包数", summary.count],
                ["时间跨度", `${summary.duration.toFixed(6)} s`],
                ["分析版本", capture.revision],
                ["RTP 映射", `${capture.config.mappings.length} 条`],
              ].map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </Modal>
      )}
      {modal === "files" && (
        <Modal
          title="抓包文件"
          subtitle="原始抓包、RTP 配置与索引保存在服务的数据目录中。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body file-manager">
            {captures.map((c) => (
              <div key={c.id} className="file-manager-row">
                <FileCode2 size={20} />
                <button
                  onClick={() => {
                    selectCapture(c);
                    setModal(null);
                  }}
                >
                  <strong>{c.name}</strong>
                  <span>
                    {sizeLabel(c.size)} ·{" "}
                    {c.status === "ready"
                      ? `${c.summary?.count || 0} 个数据包`
                      : c.status}
                  </span>
                </button>
                {pendingDelete === c.id ? (
                  <button
                    className="delete-confirm"
                    onClick={() => removeCapture(c)}
                  >
                    确认删除
                  </button>
                ) : (
                  <IconButton
                    icon={Trash2}
                    label={`删除 ${c.name}`}
                    onClick={() => setPendingDelete(c.id)}
                  />
                )}
              </div>
            ))}
            {!captures.length && <p>还没有导入抓包文件。</p>}
          </div>
        </Modal>
      )}
    </div>
  );
}
