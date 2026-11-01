import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowUpRight,
  AudioLines,
  BookOpen,
  Bookmark,
  Check,
  ChevronDown,
  ChevronRight,
  Code2,
  Columns3,
  Download,
  FileCode2,
  Filter,
  FolderOpen,
  GitCompareArrows,
  GitBranch,
  Globe2,
  Info,
  Layers3,
  ListFilter,
  LoaderCircle,
  MoreHorizontal,
  Network,
  PanelLeftClose,
  PhoneCall,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
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
import RtpPanel, {
  DecodeAsEditor,
  MappingEditor,
  RtpDetection,
} from "./RtpPanel.jsx";
import SipFlow from "./SipFlow.jsx";
const nav = [
  ["packets", "数据包分析", Layers3],
  ["sipFlow", "SIP 时序图", PhoneCall],
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
  ["SIP", "sip"],
  ["RTP", "rtp"],
  [
    "异常数据包",
    "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.flags.reset == 1 || tcp.analysis.zero_window",
  ],
];
const sipMrcpFilterSuggestions = [
  "sip_mrcp.port=12345",
  "sip_mrcp.media_port=12345",
  "sip_mrcp.rtp_port=12345",
  "sip_mrcp.port == 12345",
  "sip_mrcp.port eq 12345",
];
function isSipMrcpSuggestion(value) {
  return /^sip_mrcp\./i.test(value);
}
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
// Packet details require two TShark passes (PDML + raw JSON). Avoid starting
// those passes automatically for large captures; users can still load any
// packet on demand by clicking it in the list.
const AUTO_DETAIL_MAX_BYTES = 32 * 1024 * 1024;
function canAutoLoadDetail(capture) {
  if (capture?.demo) return true;
  const size = Number(capture?.size);
  return Number.isFinite(size) && size > 0 && size <= AUTO_DETAIL_MAX_BYTES;
}
const defaultColumnState = [
  "no",
  "time",
  "source",
  "destination",
  "protocol",
  "length",
  "info",
].map((id) => ({ id, hidden: false }));
const columnCatalog = [
  ["no", "No.", "frame.number", "number"],
  ["time", "时间", "frame.time_relative", "time"],
  ["epoch", "Epoch", "frame.time_epoch", "number"],
  ["source", "源地址", "ip.src", "text"],
  ["destination", "目标地址", "ip.dst", "text"],
  ["protocol", "协议", "_ws.col.Protocol", "text"],
  ["length", "长度", "frame.len", "number"],
  ["info", "信息", "_ws.col.Info", "text"],
  ["ip.ttl", "IP TTL", "ip.ttl", "number"],
  ["ip.id", "IP ID", "ip.id", "number"],
  ["ip.flags", "IP Flags", "ip.flags", "text"],
  ["tcp.srcport", "TCP 源端口", "tcp.srcport", "number"],
  ["tcp.dstport", "TCP 目标端口", "tcp.dstport", "number"],
  ["udp.srcport", "UDP 源端口", "udp.srcport", "number"],
  ["udp.dstport", "UDP 目标端口", "udp.dstport", "number"],
  ["stream", "流编号", "tcp.stream", "number"],
  ["tcp.seq", "TCP Seq", "tcp.seq", "number"],
  ["tcp.ack", "TCP Ack", "tcp.ack", "number"],
  ["tcp.flags", "TCP Flags", "tcp.flags", "text"],
  ["tcp.window", "TCP Window", "tcp.window_size_value", "number"],
  ["udp.length", "UDP 长度", "udp.length", "number"],
  ["dns.qry.name", "DNS 查询名", "dns.qry.name", "text"],
  ["http.host", "HTTP Host", "http.host", "text"],
  ["http.uri", "HTTP URI", "http.request.uri", "text"],
  ["rtp.pt", "RTP PT", "rtp.p_type", "number"],
  ["rtp.ssrc", "RTP SSRC", "rtp.ssrc", "text"],
  ["rtp.seq", "RTP Seq", "rtp.seq", "number"],
  ["rtp.timestamp", "RTP 时间戳", "rtp.timestamp", "number"],
  ["expert", "专家信息", "_ws.expert.message", "text"],
];
const columnById = new Map(
  columnCatalog.map(([id, label, field, kind]) => [
    id,
    { id, label, field, kind },
  ]),
);
const timeFormats = [
  ["relative", "Seconds Since Beginning of Capture"],
  ["epoch", "Seconds Since 1970-01-01 (Epoch)"],
  ["local", "Date and Time of Day (Local)"],
  ["utc", "UTC Date and Time"],
];
const timeHeaderLabels = new Map([
  ["relative", "Time"],
  ["epoch", "Epoch"],
  ["local", "Date & Time"],
  ["utc", "UTC Date & Time"],
]);
const columnMinWidths = {
  no: 46,
  time: 78,
  epoch: 92,
  source: 96,
  destination: 96,
  protocol: 68,
  length: 58,
  info: 120,
};
const compareFields = [
  ["no", "数据包编号"],
  ["time", "相对时间"],
  ["epoch", "Epoch 时间"],
  ["source", "源地址"],
  ["destination", "目标地址"],
  ["protocol", "协议"],
  ["length", "长度"],
  ["info", "信息"],
  ["tcp.srcport", "源端口"],
  ["tcp.dstport", "目标端口"],
  ["stream", "流编号"],
  ["rtp.pt", "RTP PT"],
  ["rtp.ssrc", "RTP SSRC"],
  ["expert", "专家信息"],
];
function readStorage(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}
function readSavedViews() {
  const stored = readStorage("webshark-saved-views", []);
  if (!Array.isArray(stored)) return [];
  return stored
    .filter(
      (item) =>
        item &&
        typeof item.id === "string" &&
        typeof item.captureId === "string" &&
        typeof item.filter === "string",
    )
    .slice(0, 20);
}
function readColumnState() {
  const stored = readStorage("webshark-columns", defaultColumnState);
  if (!Array.isArray(stored)) return defaultColumnState;
  const valid = stored
    .map((item) =>
      typeof item === "string" ? { id: item, hidden: false } : item,
    )
    .filter((item) => item && columnById.has(item.id))
    .map((item) => ({ id: item.id, hidden: item.hidden === true }));
  return valid.length ? valid : defaultColumnState;
}
function columnValue(packet, column) {
  if (column.id === "no") return packet.no;
  if (column.id === "time") return packet.time;
  if (column.id === "epoch") return packet.epoch;
  if (column.id === "source") return packet.source;
  if (column.id === "destination") return packet.destination;
  if (column.id === "protocol") return packet.protocol;
  if (column.id === "length") return packet.length;
  if (column.id === "info") return packet.info;
  if (column.id === "stream") return packet.stream;
  if (column.id === "tcp.srcport" || column.id === "udp.srcport")
    return packet.srcPort;
  if (column.id === "tcp.dstport" || column.id === "udp.dstport")
    return packet.dstPort;
  if (column.id === "rtp.pt") return packet.rtp?.pt;
  if (column.id === "rtp.ssrc") return packet.rtp?.ssrc;
  if (column.id === "rtp.seq") return packet.rtp?.seq;
  if (column.id === "rtp.timestamp") return packet.rtp?.timestamp;
  return packet.fields?.[column.field] ?? "";
}
function formatPacketTime(packet, format) {
  if (format === "relative") return Number(packet.time).toFixed(6);
  if (format === "epoch") return Number(packet.epoch).toFixed(6);
  const epoch = Number(packet.epoch);
  if (!Number.isFinite(epoch)) return "—";
  const microseconds = Math.round(epoch * 1e6),
    date = new Date(Math.floor(microseconds / 1e6) * 1000),
    utc = format === "utc",
    part = (value) => String(value).padStart(2, "0"),
    year = utc ? date.getUTCFullYear() : date.getFullYear(),
    month = utc ? date.getUTCMonth() + 1 : date.getMonth() + 1,
    day = utc ? date.getUTCDate() : date.getDate(),
    hours = utc ? date.getUTCHours() : date.getHours(),
    minutes = utc ? date.getUTCMinutes() : date.getMinutes(),
    seconds = utc ? date.getUTCSeconds() : date.getSeconds(),
    fraction = String(((microseconds % 1e6) + 1e6) % 1e6).padStart(
      6,
      "0",
    );
  return `${year}-${part(month)}-${part(day)} ${part(hours)}:${part(minutes)}:${part(seconds)}.${fraction}`;
}
function isSipPacket(packet) {
  return /^sip(?:\/|$)/i.test(String(packet?.protocol || ""));
}
function uniqueRelationChannels(relation) {
  return [
    ...new Set(
      (relation?.matches || []).flatMap((match) => match.channelIds || []),
    ),
  ];
}
function addSipCompareField(target, field, namespace, keyOverride = null) {
  if (!field?.name || field.name.startsWith("sip.call_id_generated")) return;
  const prefix = `${namespace}.`;
  if (!field.name.startsWith(prefix)) return;
  const baseKey = keyOverride || field.name.slice(prefix.length);
  const duplicate = target.filter((item) => item.baseKey === baseKey).length;
  target.push({
    baseKey,
    key: duplicate ? `${baseKey} #${duplicate + 1}` : baseKey,
    value: field.value == null || field.value === "" ? "—" : String(field.value),
  });
}
const sipSdpLinePrefixes = {
  "sdp.version": "v=",
  "sdp.owner": "o=",
  "sdp.session_name": "s=",
  "sdp.session_info": "i=",
  "sdp.uri": "u=",
  "sdp.email": "e=",
  "sdp.phone": "p=",
  "sdp.connection_info": "c=",
  "sdp.bandwidth": "b=",
  "sdp.time": "t=",
  "sdp.repeat_time": "r=",
  "sdp.time_zone": "z=",
  "sdp.encryption_key": "k=",
  "sdp.session_attr": "a=",
  "sdp.media": "m=",
  "sdp.media_title": "i=",
  "sdp.media_connection_info": "c=",
  "sdp.media_bandwidth": "b=",
  "sdp.media_encryption_key": "k=",
  "sdp.media_attr": "a=",
};
function collectSipSdpLines(fields) {
  const target = [];
  const walk = (items) => {
    (items || []).forEach((field) => {
      const name = field?.name || "",
        prefix = sipSdpLinePrefixes[name];
      if (prefix) {
        const value = field.value == null ? "" : String(field.value).trim();
        target.push({
          key: `line[${String(target.length + 1).padStart(2, "0")}]`,
          value: `${prefix}${value}`,
        });
      }
      if (field?.fields?.length) walk(field.fields);
    });
  };
  walk(fields);
  return target;
}
function sipComparisonFields(detail) {
  const layers = detail?.layers || [],
    sip = layers.find((layer) => layer.name === "sip" || layer.id === "sip"),
    sdp = layers.find((layer) => layer.name === "sdp" || layer.id === "sdp"),
    headers = [];
  if (sip) {
    const startLine = (sip.fields || []).find((field) =>
      /sip\.(Request-Line|Status-Line)$/.test(field.name || ""),
    );
    if (startLine)
      headers.push({ baseKey: "Start-Line", key: "Start-Line", value: String(startLine.value) });
    const headerGroup = (sip.fields || []).find((field) => field.name === "sip.msg_hdr");
    (headerGroup?.fields || []).forEach((field) => addSipCompareField(headers, field, "sip"));
  }
  // TShark may expose SDP as a dedicated layer or nest it beneath the SIP
  // layer, depending on the dissector output/version. Walk both locations so
  // the comparison works for real captures as well as the demo capture.
  const dedicatedSdp = collectSipSdpLines(sdp?.fields),
    nestedSdp = dedicatedSdp.length ? dedicatedSdp : collectSipSdpLines(sip?.fields);
  return {
    headers,
    sdp: nestedSdp,
    sdpSummary: { lineCount: nestedSdp.length },
  };
}
function mergeSipCompareRows(left = [], right = []) {
  const leftMap = new Map(left.map((field) => [field.key, field.value])),
    rightMap = new Map(right.map((field) => [field.key, field.value])),
    keys = [...new Set([...left.map((field) => field.key), ...right.map((field) => field.key)])];
  return keys.map((key) => {
    const leftValue = leftMap.get(key) ?? "—",
      rightValue = rightMap.get(key) ?? "—";
    return { key, left: leftValue, right: rightValue, different: leftValue !== rightValue };
  });
}
function mergeSipSdpLines(left = [], right = []) {
  const leftValues = left.map((line) => line.value),
    rightValues = right.map((line) => line.value),
    dp = Array.from({ length: leftValues.length + 1 }, () =>
      Array(rightValues.length + 1).fill(0),
    );
  for (let i = leftValues.length - 1; i >= 0; i -= 1)
    for (let j = rightValues.length - 1; j >= 0; j -= 1)
      dp[i][j] =
        leftValues[i] === rightValues[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const operations = [];
  let i = 0,
    j = 0;
  while (i < leftValues.length || j < rightValues.length) {
    if (
      i < leftValues.length &&
      j < rightValues.length &&
      leftValues[i] === rightValues[j]
    ) {
      operations.push({
        type: "same",
        left: left[i],
        right: right[j],
        leftIndex: i,
        rightIndex: j,
      });
      i += 1;
      j += 1;
    } else if (
      i < leftValues.length &&
      (j >= rightValues.length || dp[i + 1][j] >= dp[i][j + 1])
    ) {
      operations.push({ type: "removed", left: left[i], leftIndex: i });
      i += 1;
    } else {
      operations.push({ type: "added", right: right[j], rightIndex: j });
      j += 1;
    }
  }
  const rows = [];
  for (let index = 0; index < operations.length; ) {
    const operation = operations[index];
    if (operation.type === "same") {
      rows.push({
        key: `sdp-${rows.length + 1}`,
        status: "same",
        left: operation.left.value,
        right: operation.right.value,
        leftLine: operation.leftIndex + 1,
        rightLine: operation.rightIndex + 1,
      });
      index += 1;
      continue;
    }
    const removed = [],
      added = [];
    while (operations[index]?.type === "removed") removed.push(operations[index++]);
    while (operations[index]?.type === "added") added.push(operations[index++]);
    const length = Math.max(removed.length, added.length);
    for (let offset = 0; offset < length; offset += 1) {
      const leftLine = removed[offset]?.left || null,
        rightLine = added[offset]?.right || null;
      rows.push({
        key: `sdp-${rows.length + 1}`,
        status: leftLine && rightLine ? "changed" : leftLine ? "removed" : "added",
        left: leftLine?.value || null,
        right: rightLine?.value || null,
        leftLine: removed[offset]?.leftIndex == null ? null : removed[offset].leftIndex + 1,
        rightLine: added[offset]?.rightIndex == null ? null : added[offset].rightIndex + 1,
      });
    }
  }
  return {
    rows,
    counts: rows.reduce(
      (result, row) => ({ ...result, [row.status]: result[row.status] + 1 }),
      { same: 0, changed: 0, added: 0, removed: 0 },
    ),
  };
}
function SipCompareSection({ title, rows, meta = "", columnTitle = "字段" }) {
  return (
    <section className="sip-compare-section">
      <div className="sip-compare-heading">
        <h3>{title}</h3>
        <span>{meta ? `${meta} · ` : ""}{rows.filter((row) => row.different).length} 项不同</span>
      </div>
      {rows.length ? (
        <div className="compare-table sip-compare-table">
          <div className="sip-compare-grid sip-compare-grid-header">
            <span>{columnTitle}</span>
            <span>报文 A</span>
            <span>报文 B</span>
          </div>
          {rows.map((row) => (
            <div className={`sip-compare-grid ${row.different ? "is-different" : ""}`} key={row.key}>
              <span>{row.key}</span>
              <code>{row.left}</code>
              <code>{row.right}</code>
            </div>
          ))}
        </div>
      ) : (
        <div className="sip-compare-empty">两个报文都没有可比较的 {title}。</div>
      )}
    </section>
  );
}
function SipSdpDiffSection({ diff }) {
  const labels = { same: "相同", changed: "修改", added: "新增", removed: "删除" };
  return (
    <section className="sip-compare-section sip-sdp-diff-section">
      <div className="sip-compare-heading">
        <div>
          <h3>SDP 原始行差异</h3>
          <p>按原始行顺序对齐，不拆解字段</p>
        </div>
        <span>{diff.rows.length} 行 · {diff.counts.changed + diff.counts.added + diff.counts.removed} 项变化</span>
      </div>
      <div className="sip-diff-summary" aria-label="SDP 差异统计">
        {Object.entries(labels).map(([status, label]) => (
          <span className={`sip-diff-stat is-${status}`} key={status}>
            <strong>{diff.counts[status]}</strong>
            {label}
          </span>
        ))}
      </div>
      <div className="sip-diff-table">
        <div className="sip-diff-grid sip-diff-grid-header">
          <span>状态</span>
          <span>报文 A · Offer</span>
          <span>报文 B · Answer</span>
        </div>
        {diff.rows.map((row) => (
          <div className={`sip-diff-grid is-${row.status}`} key={row.key}>
            <span className="sip-diff-status">
              <strong>{labels[row.status]}</strong>
              <small>{row.leftLine ? `A:${row.leftLine}` : "A:—"} · {row.rightLine ? `B:${row.rightLine}` : "B:—"}</small>
            </span>
            <code>{row.left || ""}</code>
            <code>{row.right || ""}</code>
          </div>
        ))}
      </div>
    </section>
  );
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
    [detectionPort, setDetectionPort] = useState(null),
    [decodeTarget, setDecodeTarget] = useState(null);
  const [expression, setExpression] = useState(""),
    [applied, setApplied] = useState(""),
    [query, setQuery] = useState({ filter: "", page: 0 }),
    [filterError, setFilterError] = useState(""),
    [loading, setLoading] = useState(false),
    [rows, setRows] = useState([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(0),
    [pageSize, setPageSize] = useState(() => {
      const saved = Number(readStorage("webshark-page-size", 100));
      return [100, 200, 500, 1000].includes(saved) ? saved : 100;
    }),
    [filteredBytes, setFilteredBytes] = useState(0),
    [relation, setRelation] = useState(null),
    [selectedNo, setSelectedNo] = useState(8),
    [detail, setDetail] = useState(null),
    [detailError, setDetailError] = useState(""),
    [detailLoading, setDetailLoading] = useState(false),
    [sipCompareDetails, setSipCompareDetails] = useState(null),
    [sipCompareLoading, setSipCompareLoading] = useState(false),
    [sipCompareError, setSipCompareError] = useState("");
  const [bookmarked, setBookmarked] = useState(new Set()),
    [markedOnly, setMarkedOnly] = useState(false),
    [colors, setColors] = useState(true),
    [compact, setCompact] = useState(false),
    [columnState, setColumnState] = useState(readColumnState),
    [columnWidths, setColumnWidths] = useState(() =>
      readStorage("webshark-column-widths", {}),
    ),
    [timeFormat, setTimeFormat] = useState(() =>
      readStorage("webshark-time-format", "relative"),
    ),
    [sort, setSort] = useState({ key: "no", direction: "asc" }),
    [compareMode, setCompareMode] = useState(false),
    [compareSelection, setCompareSelection] = useState([]),
    [newColumn, setNewColumn] = useState(""),
    [draggedColumn, setDraggedColumn] = useState(null),
    [sidebarOpen, setSidebarOpen] = useState(false),
    [sidebarCollapsed, setSidebarCollapsed] = useState(false),
    [sidebarViewOpen, setSidebarViewOpen] = useState(true),
    [savedFilters, setSavedFilters] = useState(() =>
      readStorage("webshark-filters", ["tcp.port == 443", "rtp.p_type == 96"]),
    ),
    [savedViews, setSavedViews] = useState(readSavedViews),
    [savedViewName, setSavedViewName] = useState(""),
    [activeSavedViewId, setActiveSavedViewId] = useState(null),
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
    bootSerial = useRef(0),
    columnResize = useRef(null);
  const summary = capture?.summary || emptySummary,
    selected =
      selectedNo == null
        ? null
        : rows.find((p) => p.no === selectedNo) || rows[0] || null,
    visibleColumns = columnState
      .map(({ id }) => columnById.get(id))
      .filter(Boolean)
      .filter((column) => !columnState.find((item) => item.id === column.id)?.hidden),
    comparePackets = compareSelection
      .map((no) => rows.find((p) => p.no === no))
      .filter(Boolean),
    sipCompare = comparePackets.length === 2 && comparePackets.every(isSipPacket),
    ready = capture?.status === "ready";
  const title = nav.find(([id]) => id === view)?.[1] || "数据包分析";
  const displayRows = [...rows].sort((a, b) => {
    const column = columnById.get(sort.key) || columnById.get("no");
    const left = columnValue(a, column),
      right = columnValue(b, column),
      leftNumber = Number(left),
      rightNumber = Number(right),
      bothNumbers = Number.isFinite(leftNumber) && Number.isFinite(rightNumber);
    const result = bothNumbers
      ? leftNumber - rightNumber
      : String(left ?? "").localeCompare(String(right ?? ""), "zh-CN", {
          numeric: true,
        });
    return (sort.direction === "desc" ? -1 : 1) * result;
  });
  useEffect(() => {
    try {
      localStorage.setItem("webshark-columns", JSON.stringify(columnState));
      localStorage.setItem("webshark-column-widths", JSON.stringify(columnWidths));
      localStorage.setItem("webshark-time-format", timeFormat);
      localStorage.setItem("webshark-page-size", String(pageSize));
    } catch {}
  }, [columnState, columnWidths, timeFormat, pageSize]);
  useEffect(() => {
    const move = (event) => {
      const active = columnResize.current;
      if (!active) return;
      const width = Math.max(
        columnMinWidths[active.id] || 72,
        active.startWidth + event.clientX - active.startX,
      );
      setColumnWidths((current) =>
        current[active.id] === width
          ? current
          : { ...current, [active.id]: Math.round(width) },
      );
    };
    const stop = () => {
      columnResize.current = null;
      document.body.classList.remove("resizing-columns");
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", stop);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", stop);
    };
  }, []);
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
        saved === "closed"
          ? null
          : list.find((c) => c.id === saved && c.status === "ready") ||
            list.find((c) => c.status === "ready") ||
            (await api("/demo", { method: "POST" }));
      if (version === bootSerial.current && c) selectCapture(c);
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
    setRelation(null);
    setExpression("");
    setApplied("");
    setQuery({ filter: "", page: 0 });
    setMarkedOnly(false);
    setBookmarked(new Set());
    setCompareSelection([]);
    setCompareMode(false);
    setSipCompareDetails(null);
    setSipCompareError("");
    setSelectedNo(canAutoLoadDetail(c) ? (c.demo ? 8 : 1) : null);
    setFilterError("");
    setSidebarOpen(false);
    setContext(null);
    setDecodeTarget(null);
    setActiveSavedViewId(null);
    sessionStorage.setItem("webshark-capture", c.id);
  }
  function toggleSort(key) {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: "asc" },
    );
  }
  function startColumnResize(event, columnId) {
    event.preventDefault();
    event.stopPropagation();
    const cell = event.currentTarget.parentElement;
    columnResize.current = {
      id: columnId,
      startX: event.clientX,
      startWidth: cell?.getBoundingClientRect().width || 100,
    };
    document.body.classList.add("resizing-columns");
  }
  function resetColumnWidth(columnId) {
    setColumnWidths((current) => {
      if (!(columnId in current)) return current;
      const next = { ...current };
      delete next[columnId];
      return next;
    });
  }
  function toggleCompare(packet) {
    setSelectedNo(packet.no);
    setCompareSelection((current) => {
      if (current.includes(packet.no))
        return current.filter((no) => no !== packet.no);
      return current.length >= 2 ? [current[1], packet.no] : [...current, packet.no];
    });
  }
  function packetClick(event, packet) {
    if (compareMode || event.shiftKey || event.metaKey || event.ctrlKey)
      toggleCompare(packet);
    else setSelectedNo(packet.no);
  }
  function toggleColumnHidden(id) {
    const visible = columnState.filter((item) => !item.hidden);
    if (visible.length === 1 && visible[0].id === id) {
      setToast("至少保留一列用于显示数据包");
      return;
    }
    setColumnState((current) =>
      current.map((item) =>
        item.id === id ? { ...item, hidden: !item.hidden } : item,
      ),
    );
  }
  function moveColumn(id, offset) {
    setColumnState((current) => {
      const index = current.findIndex((item) => item.id === id),
        next = index + offset;
      if (index < 0 || next < 0 || next >= current.length) return current;
      const result = [...current];
      [result[index], result[next]] = [result[next], result[index]];
      return result;
    });
  }
  function reorderColumn(sourceId, targetId) {
    if (!sourceId || !targetId || sourceId === targetId) return;
    setColumnState((current) => {
      const sourceIndex = current.findIndex((item) => item.id === sourceId),
        targetIndex = current.findIndex((item) => item.id === targetId);
      if (sourceIndex < 0 || targetIndex < 0) return current;
      const result = [...current],
        [moved] = result.splice(sourceIndex, 1);
      result.splice(targetIndex, 0, moved);
      return result;
    });
  }
  function addColumn(field, customLabel = "") {
    const normalized = String(field || "").trim();
    if (!/^[a-zA-Z_][\w.-]*$/.test(normalized)) {
      setToast("请输入合法的 Wireshark 字段名，例如 tcp.stream");
      return false;
    }
    const existing =
      columnById.get(normalized) ||
      columnById.get(columnCatalog.find(([, , field]) => field === normalized)?.[0]);
    if (existing) {
      setColumnState((current) =>
        current.some((item) => item.id === existing.id)
          ? current.map((item) =>
              item.id === existing.id ? { ...item, hidden: false } : item,
            )
          : [...current, { id: existing.id, hidden: false }],
      );
      setToast(`已显示“${existing.label}”列`);
      return true;
    }
    const label = customLabel.trim() || normalized;
    const dynamic = { id: normalized, label, field: normalized, kind: "text" };
    columnById.set(dynamic.id, dynamic);
    setColumnState((current) =>
      current.some((item) => item.id === dynamic.id)
        ? current.map((item) =>
            item.id === dynamic.id ? { ...item, hidden: false } : item,
          )
        : [...current, { id: dynamic.id, hidden: false }],
    );
    setToast(`已添加“${dynamic.label}”列`);
    return true;
  }
  function resetColumns() {
    setColumnState(defaultColumnState.map((item) => ({ ...item })));
    setColumnWidths({});
    setTimeFormat("relative");
    setSort({ key: "no", direction: "asc" });
  }
  function closeCapture() {
    streamSerial.current++;
    setCapture(null);
    setRows([]);
    setDetail(null);
    setRelation(null);
    setExpression("");
    setApplied("");
    setQuery({ filter: "", page: 0 });
    setMarkedOnly(false);
    setBookmarked(new Set());
    setCompareSelection([]);
    setCompareMode(false);
    setSipCompareDetails(null);
    setSipCompareError("");
    setSelectedNo(null);
    setFilterError("");
    setContext(null);
    setMappingTarget(null);
    setDetectionPort(null);
    setDecodeTarget(null);
    setStream(null);
    setStreamError("");
    setStreamLoading(false);
    setModal(null);
    setView("packets");
    sessionStorage.setItem("webshark-capture", "closed");
    setToast("已关闭当前抓包文件；文件仍保存在最近打开中");
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
        `/packets?filter=${encodeURIComponent(filter)}&page=${query.page}&size=${pageSize}`,
      ),
      { signal: controller.signal },
    )
      .then((data) => {
        if (serial !== querySerial.current) return;
        setRows(data.packets);
        setTotal(data.total);
        setPage(data.page);
        setFilteredBytes(data.bytes);
        setRelation(data.relation || null);
        setApplied(query.filter);
        const autoSelectDetail = canAutoLoadDetail(capture);
        setSelectedNo((current) => {
          if (current != null && data.packets.some((p) => p.no === current))
            return current;
          return autoSelectDetail ? data.packets[0]?.no || null : null;
        });
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
    capture?.size,
    capture?.demo,
    ready,
    query,
    pageSize,
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
    if (modal !== "compare" || !sipCompare || !capture) {
      setSipCompareDetails(null);
      setSipCompareLoading(false);
      setSipCompareError("");
      return;
    }
    const controller = new AbortController();
    setSipCompareLoading(true);
    setSipCompareError("");
    Promise.all(
      comparePackets.map((packet) =>
        api(capturePath(capture.id, `/packets/${packet.no}`), {
          signal: controller.signal,
        }),
      ),
    )
      .then(([left, right]) => setSipCompareDetails({ left, right }))
      .catch((error) => {
        if (error.name !== "AbortError") setSipCompareError(error.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setSipCompareLoading(false);
      });
    return () => controller.abort();
  }, [modal, capture?.id, capture?.revision, sipCompare, compareSelection.join(",")]);
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
    if (/^sip_mrcp(?:\.[\w]*)?$/i.test(token)) {
      setSuggestions(sipMrcpFilterSuggestions);
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
    setActiveSavedViewId(null);
    setMarkedOnly(false);
    setCompareSelection([]);
    setSuggestions([]);
    setShowSaved(false);
    setContext(null);
    setRelation(null);
  }
  function navigate(id) {
    if (id === "sipFlow") {
      const nextFilter = applied.trim();
      setExpression(nextFilter);
      setQuery({ filter: nextFilter, page: 0 });
      setApplied(nextFilter);
      setMarkedOnly(false);
      setCompareSelection([]);
    }
    setActiveSavedViewId(null);
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
    const column = columnById.get(key);
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
      columnField: column?.field || null,
      columnLabel: column?.label || null,
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
  function persistSavedViews(next) {
    setSavedViews(next);
    try {
      localStorage.setItem("webshark-saved-views", JSON.stringify(next));
    } catch {}
  }
  function saveWorkspaceView() {
    if (!capture || !ready) return setToast("请先打开一个已解析的抓包文件");
    if (expression.trim() !== applied.trim()) {
      return setToast("请先应用当前过滤器，再保存分析视图");
    }
    setSavedViewName("");
    setModal("saveView");
  }
  function confirmSaveWorkspaceView() {
    if (!capture || !ready) return setToast("请先打开一个已解析的抓包文件");
    const filter = applied.trim(),
      label = savedViewName.trim() || filter || "全部数据包",
      existing = savedViews.find(
        (item) =>
          item.captureId === capture.id &&
          item.filter === filter &&
          item.view === view,
      ),
      item = {
        id:
          existing?.id ||
          `saved-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
        captureId: capture.id,
        captureName: capture.name,
        filter,
        view,
        label,
        savedAt: Date.now(),
      },
      next = [
        item,
        ...savedViews.filter(
          (saved) =>
            saved.id !== item.id &&
            !(saved.captureId === capture.id && saved.filter === filter && saved.view === view),
        ),
      ].slice(0, 20);
    persistSavedViews(next);
    setActiveSavedViewId(item.id);
    setSavedViewName("");
    setModal(null);
    setToast(`已保存“${label}”分析视图`);
  }
  function openSavedWorkspace(item) {
    const target = captures.find((candidate) => candidate.id === item.captureId);
    if (!target) {
      persistSavedViews(savedViews.filter((saved) => saved.id !== item.id));
      setToast("对应抓包文件已不存在，已移除这条保存视图");
      return;
    }
    if (target.id !== capture?.id) selectCapture(target);
    const filter = item.filter || "";
    setExpression(filter);
    setApplied(filter);
    setQuery({ filter, page: 0 });
    setMarkedOnly(false);
    setCompareSelection([]);
    setView(item.view || "packets");
    setContext(null);
    setActiveSavedViewId(item.id);
  }
  function removeSavedWorkspace(id) {
    const next = savedViews.filter((item) => item.id !== id);
    persistSavedViews(next);
    if (activeSavedViewId === id) setActiveSavedViewId(null);
    setToast("已移除保存视图");
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
  function openDecodeAs(packet) {
    const transport = packet?.transport?.toLowerCase();
    if (!transport) return;
    const ports = [packet.dstPort, packet.srcPort].filter(
      (port, index, list) => Number.isInteger(port) && list.indexOf(port) === index,
    );
    const existing = (capture?.config?.decodeAs || []).find(
      (rule) => rule.transport === transport && ports.includes(rule.port),
    );
    setDecodeTarget({ packet, existing });
    setModal("decodeAs");
  }
  async function saveDecodeAs(rule) {
    const current = capture.config.decodeAs || [];
    const packet = decodeTarget?.packet;
    const transport = rule?.transport || packet?.transport?.toLowerCase();
    const port = Number(rule?.port ?? packet?.dstPort ?? packet?.srcPort);
    const next = current.filter(
      (item) => !(item.transport === transport && item.port === port),
    );
    if (rule) next.push({ ...rule, transport, port });
    await updateConfig({ ...capture.config, decodeAs: next });
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
    const keys = visibleColumns.map((column) => column.id);
    const data =
      exportFormat === "json"
        ? JSON.stringify(displayRows, null, 2)
        : "\ufeff" +
          [
            visibleColumns.map((column) => column.label).join(","),
            ...displayRows.map((p) =>
              keys
                .map((key) => {
                  const column = columnById.get(key);
                  return `"${String(
                    key === "time"
                      ? formatPacketTime(p, timeFormat)
                      : columnValue(p, column),
                  ).replaceAll('"', '""')}"`;
                })
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
      persistSavedViews(savedViews.filter((item) => item.captureId !== c.id));
      if (activeSavedViewId && savedViews.some((item) => item.id === activeSavedViewId && item.captureId === c.id)) {
        setActiveSavedViewId(null);
      }
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
            数据分析工作区
            <small>{capture?.name || "尚未打开抓包"}</small>
          </span>
          <ChevronDown size={14} />
        </button>
        <div className="nav-section-label">分析</div>
        <nav aria-label="分析导航">
          {nav
            .filter(([id]) => id === "packets")
            .map(([id, label, Icon]) => (
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
            </button>
            ))}
          {nav
            .filter(([id]) => id === "sipFlow")
            .map(([id, label, Icon]) => (
              <button
                key={id}
                className={`nav-item ${view === id ? "active" : ""}`}
                onClick={() => navigate(id)}
              >
                <Icon size={18} />
                <span>{label}</span>
                {summary.protocols.find((item) => /^sip/i.test(String(item.protocol || "")))?.count > 0 && (
                  <span className="nav-count">
                    {summary.protocols.find((item) => /^sip/i.test(String(item.protocol || ""))).count}
                  </span>
                )}
              </button>
            ))}
          <button
            className={`nav-item nav-group-toggle ${
              ["statistics", "conversations", "endpoints", "rtp", "expert"].includes(view)
                ? "is-active"
                : ""
            }`}
            aria-expanded={sidebarViewOpen}
            onClick={() => setSidebarViewOpen((open) => !open)}
          >
            <Activity size={18} />
            <span>分析视图</span>
            <ChevronDown size={14} />
          </button>
          {sidebarViewOpen && (
            <div className="nav-subitems">
              {nav
                .filter(([id]) =>
                  ["statistics", "conversations", "endpoints", "rtp", "expert"].includes(id),
                )
                .map(([id, label, Icon]) => (
                  <button
                    key={id}
                    className={`nav-item nav-subitem ${view === id ? "active" : ""}`}
                    onClick={() => navigate(id)}
                  >
                    <Icon size={15} />
                    <span>{label}</span>
                    {id === "rtp" && summary.media.length > 0 && (
                      <span className="nav-count">{summary.media.length}</span>
                    )}
                    {id === "expert" && summary.issueCount > 0 && (
                      <span className="warning-count">{summary.issueCount}</span>
                    )}
                  </button>
                ))}
            </div>
          )}
        </nav>
        <div className="sidebar-divider" />
        <div className="nav-section-label recent-label saved-view-heading">
          <span>
            <Bookmark size={12} />
            已保存视图
          </span>
          <IconButton
            icon={Plus}
            label="保存当前视图"
            disabled={!ready}
            onClick={saveWorkspaceView}
          />
        </div>
        <div className="saved-view-list">
          {savedViews.map((item) => (
            <div
              key={item.id}
              className={`saved-view-row ${activeSavedViewId === item.id ? "is-active" : ""}`}
            >
              <button
                className="saved-view-main"
                title={`${item.captureName || "抓包文件"} · ${item.filter || "全部数据包"}`}
                onClick={() => openSavedWorkspace(item)}
              >
                <Bookmark size={15} />
                <span>
                  <strong>{item.label || item.filter || "全部数据包"}</strong>
                  <small>
                    {item.captureName || "抓包文件"} · {item.filter ? "筛选视图" : "完整抓包"}
                  </small>
                </span>
              </button>
              <IconButton
                icon={X}
                label={`移除保存视图 ${item.label || item.filter || "全部数据包"}`}
                onClick={() => removeSavedWorkspace(item.id)}
              />
            </div>
          ))}
          {!savedViews.length && (
            <div className="saved-view-empty">
              应用过滤器后，点击这里的加号保存分析视图
            </div>
          )}
        </div>
        <div className="sidebar-divider" />
        <div className="nav-section-label recent-label">
          抓包文件
          <IconButton
            icon={Plus}
            label="打开新的抓包文件"
            onClick={() => setModal("import")}
          />
        </div>
        <div className="recent-files">
          {captures.slice(0, 3).map((c) => (
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
        <button
          className="recent-file recent-file-manage"
          onClick={() => setModal("files")}
        >
          <FolderOpen size={17} />
          <span>
            全部抓包文件<small>{captures.length} 个本地文件</small>
          </span>
          <ChevronRight size={14} />
        </button>
        <div className="sidebar-bottom">
          <button
            className="sidebar-status"
            onClick={() => setModal("settings")}
            aria-label="查看解析服务状态"
          >
            <span className="sidebar-status-icon">
              <span className="status-dot" />
            </span>
            <span className="sidebar-status-copy">
              <strong>离线分析</strong>
              <small>{health?.ready ? "TShark 解析引擎已连接" : "等待解析服务"}</small>
            </span>
            <Settings2 size={16} />
          </button>
          <div className="sidebar-version">
            <span>WebShark</span>
            <span>Offline Analyzer v0.2</span>
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
            <button
              className="text-button docs-link"
              aria-label="打开帮助与快捷键"
              onClick={() => setModal("help")}
            >
              <BookOpen size={15} />
              帮助与快捷键
            </button>
          </div>
        </header>
        <main className={`main-content main-content-${view}`}>
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
                <button
                  className="capture-close-button"
                  aria-label="关闭当前抓包文件"
                  title="关闭当前抓包文件"
                  onClick={closeCapture}
                >
                  <X size={14} />
                  关闭文件
                </button>
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
              <p>当前未打开 pcap 文件，关闭不会删除已保存的抓包。</p>
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
                    placeholder="Wireshark 过滤器，例如 ip.addr == 10.10.0.10、rtp.p_type == 96 或 sip_mrcp.port=12345"
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
                  <IconButton
                    icon={Bookmark}
                    label="保存当前视图"
                    disabled={!ready}
                    onClick={saveWorkspaceView}
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
                        <span>{s}</span>
                        {isSipMrcpSuggestion(s) && (
                          <small>ASR/MRCP 关联</small>
                        )}
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
                {relation && (
                  <div className="filter-relation" role="status">
                    <div>
                      <strong>ASR 关联过滤</strong>
                      <span>
                        {relation.matches.length} 个 SIP 会话 · {relation.matches.reduce((count, item) => count + item.mrcpPackets, 0)} 个 MRCP · {relation.matches.reduce((count, item) => count + item.rtpPackets, 0)} 个 RTP
                      </span>
                    </div>
                    <div className="filter-relation-meta">
                      <code>
                        {uniqueRelationChannels(relation).join(", ") || "未发现 Channel-ID"}
                      </code>
                      {relation.warning && <span>{relation.warning}</span>}
                    </div>
                  </div>
                )}
                <div className="filter-presets">
                  <div className="preset-list">
                    {presets.map(([label, value]) => (
                      <button
                        key={label}
                        className={`preset ${applied === value ? "selected" : ""}`}
                        aria-pressed={applied === value}
                        onClick={() => apply(applied === value ? "" : value)}
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
                      className={`text-button ${compareMode ? "accent-text" : ""}`}
                      aria-label={compareMode ? `选择比较数据包 ${compareSelection.length}/2` : "进入数据包比较模式"}
                      title={compareMode ? "点击两行选择数据包" : "选择两个数据包进行比较"}
                      onClick={() => {
                        setCompareMode(!compareMode);
                        if (compareMode) setCompareSelection([]);
                      }}
                    >
                      <GitCompareArrows size={14} />
                      <span>{compareMode ? `选择中 ${compareSelection.length}/2` : "包比较"}</span>
                    </button>
                    <button
                      className="text-button"
                      aria-label={sipCompare ? "比较选中 SIP 数据包的头域和 SDP" : "比较选中的两个数据包"}
                      title={sipCompare ? "比较 SIP 头域和 SDP 原始行" : "查看两个选中数据包的差异"}
                      disabled={compareSelection.length !== 2}
                      onClick={() => setModal("compare")}
                    >
                      <GitCompareArrows size={14} />
                      <span>{sipCompare ? "SIP 头域/SDP" : "查看差异"}</span>
                    </button>
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
                      icon={Columns3}
                      label="数据包列与时间设置"
                      onClick={() => setModal("columns")}
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
                        {visibleColumns.map((column) => (
                          <th
                            key={column.id}
                            className={`packet-column-th packet-column-${column.id}`}
                            style={
                              columnWidths[column.id]
                                ? {
                                    width: `${columnWidths[column.id]}px`,
                                    minWidth: `${columnWidths[column.id]}px`,
                                  }
                                : undefined
                            }
                            aria-sort={sort.key === column.id ? sort.direction : "none"}
                          >
                            <button
                              className="packet-column-button"
                              onClick={() => toggleSort(column.id)}
                              title={`按${column.id === "time" ? timeFormats.find(([id]) => id === timeFormat)?.[1] || column.label : column.label}排序`}
                            >
                              <span className="packet-column-label">
                                {column.id === "time"
                                  ? timeHeaderLabels.get(timeFormat) || column.label
                                  : column.label}
                              </span>
                              {sort.key === column.id ? (
                                sort.direction === "asc" ? (
                                  <ArrowUp size={10} />
                                ) : (
                                  <ArrowDown size={10} />
                                )
                              ) : (
                                <ArrowDown size={9} className="sort-muted" />
                              )}
                            </button>
                            <span
                              className="column-resizer"
                              role="separator"
                              aria-orientation="vertical"
                              aria-label={`调整 ${column.label} 列宽`}
                              title="拖拽调整列宽，双击恢复默认"
                              onMouseDown={(event) =>
                                startColumnResize(event, column.id)
                              }
                              onDoubleClick={() => resetColumnWidth(column.id)}
                            />
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {displayRows.map((p) => (
                        <tr
                          key={p.no}
                          tabIndex={0}
                          aria-selected={selected?.no === p.no}
                          className={`packet-row ${protocolClass(p.protocol)}-row ${p.issue ? "issue-row" : ""} ${selected?.no === p.no ? "selected-row" : ""} ${compareSelection.includes(p.no) ? "compare-selected-row" : ""}`}
                          onClick={(e) => packetClick(e, p)}
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
                          {visibleColumns.map((column) => (
                            <td
                              key={column.id}
                              className={`packet-column-cell packet-column-${column.id}`}
                              style={
                                columnWidths[column.id]
                                  ? {
                                      width: `${columnWidths[column.id]}px`,
                                      minWidth: `${columnWidths[column.id]}px`,
                                    }
                                  : undefined
                              }
                              onContextMenu={(e) =>
                                contextFor(e, p, column.id)
                              }
                              title={String(
                                column.id === "time"
                                  ? formatPacketTime(p, timeFormat)
                                  : columnValue(p, column) ?? "",
                              )}
                            >
                              {column.id === "no" ? (
                                <span className="row-number">
                                  {bookmarked.has(p.no) && (
                                    <Star size={9} fill="currentColor" />
                                  )}
                                  {p.no}
                                </span>
                              ) : column.id === "time" ? (
                                formatPacketTime(p, timeFormat)
                              ) : column.id === "protocol" ? (
                                <Protocol name={p.protocol} />
                              ) : (
                                columnValue(p, column) ?? ""
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
                      {page + 1} / {Math.max(1, Math.ceil(total / pageSize))}
                    </span>
                    <button
                      aria-label="下一页"
                      disabled={(page + 1) * pageSize >= total || loading}
                      onClick={() =>
                        setQuery({ filter: applied, page: page + 1 })
                      }
                    >
                      <ChevronRight size={13} />
                    </button>
                    <label className="page-size-control">
                      <span>每页</span>
                      <select
                        aria-label="每页数据包数量"
                        value={pageSize}
                        onChange={(event) => {
                          const next = Number(event.target.value);
                          setPageSize(next);
                          setQuery((current) => ({ filter: current.filter, page: 0 }));
                          setSelectedNo(null);
                          setDetail(null);
                        }}
                      >
                        {[100, 200, 500, 1000].map((size) => (
                          <option key={size} value={size}>
                            {size}
                          </option>
                        ))}
                      </select>
                      <span>包</span>
                    </label>
                  </div>
                  <span className="table-hint">
                    {compareMode
                      ? "点击两行选择数据包 · 查看差异"
                      : "右键字段筛选或追踪流 · 点击列头排序"}
                  </span>
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
          {ready && view === "sipFlow" && (
            <SipFlow
              key={capture.id}
              capture={capture}
              filter={applied}
              timeFormat={timeFormat}
              onTimeFormatChange={setTimeFormat}
              formatTime={formatPacketTime}
              onPacket={(packet) => {
                // SIP flow messages expand their packet detail inline; keep the
                // current flow view and only sync the selected packet state.
                setSelectedNo(packet.no);
              }}
              onOpenPackets={() => apply("sip")}
            />
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
          onDecodeAs={openDecodeAs}
          onColumn={(field, label) => addColumn(field, label)}
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
      {modal === "decodeAs" && capture && decodeTarget && (
        <DecodeAsEditor
          packet={decodeTarget.packet}
          existing={decodeTarget.existing}
          onSave={saveDecodeAs}
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
      {modal === "columns" && (
        <Modal
          title="数据包列与时间"
          subtitle="按 Wireshark 的数据包列表习惯，自定义列、顺序和时间显示。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body columns-modal">
            <label className="field-label" htmlFor="time-format">
              时间显示格式
            </label>
            <select
              id="time-format"
              className="form-select"
              value={timeFormat}
              onChange={(e) => setTimeFormat(e.target.value)}
            >
              {timeFormats.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
            <div className="columns-heading">
              <span>当前列</span>
              <small>拖动整行调整顺序 · ↑↓ 微调 · 表头边界可拖拽调整列宽</small>
            </div>
            <div className="columns-display-options" aria-label="列表显示选项">
              <label className="setting-row">
                <div>
                  <strong>协议行着色</strong>
                  <span>根据协议类型添加浅色背景，便于快速扫读</span>
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
                  <span>减少数据包行间距，适合大抓包快速浏览</span>
                </div>
                <input
                  type="checkbox"
                  checked={compact}
                  onChange={(e) => setCompact(e.target.checked)}
                />
              </label>
            </div>
            <div className="column-config-list">
              {columnState.map((item, index) => {
                const column = columnById.get(item.id);
                if (!column) return null;
                return (
                  <div
                    className={`column-config-row ${item.hidden ? "is-hidden" : ""} ${draggedColumn === item.id ? "is-dragging" : ""}`}
                    key={item.id}
                    draggable
                    aria-grabbed={draggedColumn === item.id}
                    onDragStart={(event) => {
                      setDraggedColumn(item.id);
                      event.dataTransfer.effectAllowed = "move";
                      event.dataTransfer.setData("text/plain", item.id);
                    }}
                    onDragOver={(event) => {
                      event.preventDefault();
                      event.dataTransfer.dropEffect = "move";
                    }}
                    onDrop={(event) => {
                      event.preventDefault();
                      reorderColumn(
                        event.dataTransfer.getData("text/plain") || draggedColumn,
                        item.id,
                      );
                      setDraggedColumn(null);
                    }}
                    onDragEnd={() => setDraggedColumn(null)}
                  >
                    <input
                      type="checkbox"
                      checked={!item.hidden}
                      disabled={!item.hidden && columnState.filter((x) => !x.hidden).length === 1}
                      aria-label={`显示 ${column.label}`}
                      onChange={() => toggleColumnHidden(item.id)}
                    />
                    <div>
                      <strong>{column.label}</strong>
                      <span>{column.field}</span>
                    </div>
                    <button
                      className="column-order-button"
                      aria-label={`上移 ${column.label}`}
                      disabled={index === 0}
                      onClick={() => moveColumn(item.id, -1)}
                    >
                      <ArrowUp size={13} />
                    </button>
                    <button
                      className="column-order-button"
                      aria-label={`下移 ${column.label}`}
                      disabled={index === columnState.length - 1}
                      onClick={() => moveColumn(item.id, 1)}
                    >
                      <ArrowDown size={13} />
                    </button>
                    <button
                      className="column-remove-button"
                      aria-label={`删除 ${column.label}`}
                      onClick={() => {
                        if (columnState.filter((x) => !x.hidden).length === 1 && !item.hidden) {
                          setToast("至少保留一列用于显示数据包");
                          return;
                        }
                        setColumnState((current) => current.filter((x) => x.id !== item.id));
                      }}
                    >
                      删除
                    </button>
                  </div>
                );
              })}
            </div>
            <div className="column-add-row">
              <input
                className="form-input"
                list="packet-column-fields"
                aria-label="新增字段列"
                placeholder="选择字段，例如 dns.qry.name"
                value={newColumn}
                onChange={(e) => setNewColumn(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addColumn(newColumn);
                    setNewColumn("");
                  }
                }}
              />
              <datalist id="packet-column-fields">
                {columnCatalog.map(([id, label, field]) => (
                  <option key={id} value={field}>
                    {label}
                  </option>
                ))}
              </datalist>
              <button
                className="button secondary"
                onClick={() => {
                  addColumn(newColumn);
                  setNewColumn("");
                }}
              >
                <Plus size={14} />
                添加字段列
              </button>
            </div>
            <Notice>
              隐藏或删除列只影响当前浏览器的列表布局，不会修改原始 PCAP。字段列来自当前索引采集的常用 Wireshark 字段。
            </Notice>
            <div className="modal-actions">
              <button className="button secondary" onClick={resetColumns}>
                恢复默认列
              </button>
              <button className="button primary" onClick={() => setModal(null)}>
                完成
              </button>
            </div>
          </div>
        </Modal>
      )}
      {modal === "compare" && comparePackets.length === 2 && (
        <Modal
          wide
          title={
            sipCompare
              ? `SIP 对比 · #${comparePackets[0].no} 与 #${comparePackets[1].no}`
              : `比较数据包 #${comparePackets[0].no} 与 #${comparePackets[1].no}`
          }
          subtitle={
            sipCompare
            ? "SIP 头域保留字段对比；SDP 按 Offer/Answer 原始行对齐，新增、删除和修改分开标记。"
              : "逐字段对比当前列表中选中的两个数据包。"
          }
          onClose={() => setModal(null)}
        >
          <div className="modal-body compare-modal">
            {sipCompare ? (
              sipCompareLoading ? (
                <div className="details-empty">正在读取两个 SIP 报文的头域和 SDP…</div>
              ) : sipCompareError ? (
                <p className="filter-error" role="alert">{sipCompareError}</p>
              ) : sipCompareDetails ? (
                (() => {
                  const left = sipComparisonFields(sipCompareDetails.left),
                    right = sipComparisonFields(sipCompareDetails.right),
                    sdpDiff = mergeSipSdpLines(left.sdp, right.sdp);
                  return (
                    <>
                      <div className="sip-compare-packets">
                        <div className="sip-compare-packet-card is-offer">
                          <span className="sip-compare-packet-label">报文 A · Offer</span>
                          <strong>#{comparePackets[0].no}</strong>
                          <code>{comparePackets[0].info}</code>
                        </div>
                        <div className="sip-compare-transition" aria-hidden="true">
                          <ArrowRight size={16} />
                          <span>协商结果</span>
                        </div>
                        <div className="sip-compare-packet-card is-answer">
                          <span className="sip-compare-packet-label">报文 B · Answer</span>
                          <strong>#{comparePackets[1].no}</strong>
                          <code>{comparePackets[1].info}</code>
                        </div>
                      </div>
                      <SipCompareSection
                        title="SIP 头域"
                        rows={mergeSipCompareRows(left.headers, right.headers)}
                      />
                      <SipSdpDiffSection diff={sdpDiff} />
                      <Notice>
                        SDP 只按原始行进行 diff：琥珀色表示修改，绿色表示新增，红色表示删除；行号用于快速定位，不会把 SDP 拆成更细的字段。
                      </Notice>
                    </>
                  );
                })()
              ) : (
                <div className="details-empty">准备 SIP 对比数据…</div>
              )
            ) : (
              <>
                <div className="compare-header-row">
                  <span>字段</span>
                  <strong>#{comparePackets[0].no}</strong>
                  <strong>#{comparePackets[1].no}</strong>
                </div>
                <div className="compare-table">
                  {compareFields.map(([id, label]) => {
                    const column = columnById.get(id),
                      displayLabel =
                        id === "time"
                          ? timeFormats.find(([format]) => format === timeFormat)?.[1] || label
                          : label,
                      left = id === "time"
                        ? formatPacketTime(comparePackets[0], timeFormat)
                        : columnValue(comparePackets[0], column),
                      right = id === "time"
                        ? formatPacketTime(comparePackets[1], timeFormat)
                        : columnValue(comparePackets[1], column),
                      different = String(left ?? "") !== String(right ?? "");
                    return (
                      <div className={`compare-row ${different ? "is-different" : ""}`} key={id}>
                        <span>{displayLabel}</span>
                        <code>{String(left ?? "—")}</code>
                        <code>{String(right ?? "—")}</code>
                      </div>
                    );
                  })}
                </div>
                <Notice>高亮字段表示两个数据包的摘要值不同；右键协议详情仍可继续查看完整字段树。</Notice>
              </>
            )}
            <div className="modal-actions">
              <button className="button secondary" onClick={() => setCompareSelection([])}>
                清空选择
              </button>
              <button className="button primary" onClick={() => setModal(null)}>
                完成
              </button>
            </div>
          </div>
        </Modal>
      )}
      {modal === "settings" && (
        <Modal
          title="解析服务状态"
          subtitle="当前工作区使用本机 TShark 离线解析，不进行实时抓包。"
          onClose={() => setModal(null)}
        >
          <div className="modal-body">
            <Notice>
              {health?.version || "解析服务未连接"} · 后端运行于{" "}
              {health?.node || "未知 Node 版本"}
              。服务只读取已导入的文件，不进行实时捕获。
            </Notice>
          </div>
        </Modal>
      )}
      {modal === "saveView" && (
        <Modal
          title="保存分析视图"
          subtitle="为当前过滤结果设置一个容易回顾的名称。"
          onClose={() => {
            setSavedViewName("");
            setModal(null);
          }}
        >
          <form
            className="modal-body"
            onSubmit={(event) => {
              event.preventDefault();
              confirmSaveWorkspaceView();
            }}
          >
            <label className="field-label" htmlFor="saved-view-name">
              视图名称
            </label>
            <input
              id="saved-view-name"
              className="form-input"
              value={savedViewName}
              onChange={(event) => setSavedViewName(event.target.value)}
              placeholder="例如：呼叫建立流程、10.10.0.10 信令"
              maxLength={80}
              autoFocus
            />
            <p className="form-helper">
              当前过滤器：<code>{applied || "全部数据包"}</code>
              <br />
              名称留空时将使用过滤器文本作为名称。
            </p>
            <div className="modal-actions">
              <button
                type="button"
                className="button secondary"
                onClick={() => {
                  setSavedViewName("");
                  setModal(null);
                }}
              >
                取消
              </button>
              <button className="button primary" type="submit">
                保存视图
              </button>
            </div>
          </form>
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
