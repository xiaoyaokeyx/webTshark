import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  GitBranch,
  Layers3,
  LoaderCircle,
  Network,
  PhoneCall,
  Search,
  TriangleAlert,
} from "lucide-react";
import { api, capturePath } from "./api.js";
import {
  buildSipCalls,
  endpointLetter,
  sipEndpoints,
  sipFlowRows,
} from "./sipFlow.js";
import "./sipFlow.css";

const timeOptions = [
  ["relative", "相对抓包时间"],
  ["local", "本地日期与时间"],
  ["utc", "UTC 日期与时间"],
  ["epoch", "Epoch 时间"],
];
const PAGE_SIZE = 150;

function sipRawText(detail) {
  const sipLayer = (detail?.layers || []).find(
    (layer) => String(layer?.name || "").toLowerCase() === "sip",
  );
  const bytes = Array.isArray(detail?.bytes) ? detail.bytes : [];
  if (!sipLayer || sipLayer.pos == null || !bytes.length) return "";
  const start = Math.max(0, Number(sipLayer.pos));
  const size = Math.max(0, Number(sipLayer.size) || bytes.length - start);
  return bytes
    .slice(start, start + size)
    .map((byte) => {
      const value = Number(byte);
      if (value === 10 || value === 13) return String.fromCharCode(value);
      return value >= 32 && value <= 126 ? String.fromCharCode(value) : "";
    })
    .join("")
    .replace(/\r?\n/g, "\n")
    .trim();
}

function InlinePacketDetail({
  packet,
  detail,
  loading,
  error,
  onClose,
  align = "left",
}) {
  const detailRef = useRef(null);
  const rawSip = sipRawText(detail);
  const rawLineCount = rawSip ? rawSip.split("\n").length : 0;
  useEffect(() => {
    if (
      loading ||
      (!detail && !error) ||
      typeof detailRef.current?.scrollIntoView !== "function"
    )
      return;
    detailRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [detail, error, loading]);
  return (
    <section
      ref={detailRef}
      className={`voip-inline-detail is-align-${align}`}
      aria-label={`数据包 ${packet.no} 详情`}
      aria-live="polite"
    >
      <header className="voip-inline-detail-header">
        <div>
          <span className="voip-inline-kicker">原始 SIP</span>
          <span className="voip-inline-packet-id">数据包 #{packet.no}</span>
          <strong>{packet.protocol || "SIP"}</strong>
          <span className="voip-inline-summary">
            {packet.info || "信令消息"}
          </span>
        </div>
        <button
          className="voip-inline-close"
          aria-label="收起数据包详情"
          title="收起数据包详情"
          onClick={onClose}
        >
          <ChevronUp size={16} />
          <span>收起</span>
        </button>
      </header>
      {loading ? (
        <div className="voip-inline-state" role="status">
          正在读取 SIP 原始报文…
        </div>
      ) : error ? (
        <div className="voip-inline-state is-error" role="alert">
          {error}
        </div>
      ) : detail ? (
        <>
          <div className="voip-inline-body-heading">
            <span>原始报文</span>
            {rawLineCount > 0 && <small>{rawLineCount} 行</small>}
          </div>
          <pre className="voip-inline-raw-sip">
            {rawSip || packet.info || "未解析出 SIP 原始报文"}
          </pre>
        </>
      ) : null}
    </section>
  );
}

function FlowChart({
  calls,
  timeFormat,
  formatTime,
  gap,
  onPacket,
  endpointOrder,
  grouped = false,
  expandedPacketNo,
  packetDetail,
  packetDetailLoading,
  packetDetailError,
  onCloseDetail,
}) {
  const [page, setPage] = useState(0);
  const rows = useMemo(() => sipFlowRows(calls), [calls]);
  const endpoints = useMemo(
    () => sipEndpoints(calls.flatMap((c) => c.packets)),
    [calls],
  );
  const endpointSides = useMemo(() => {
    const sides = new Map();
    calls.forEach((call) => {
      const first = call.packets[0];
      if (!first) return;
      if (!sides.has(first.source)) sides.set(first.source, "left");
      if (!sides.has(first.destination)) sides.set(first.destination, "right");
    });
    endpoints.forEach((ip, index) => {
      if (!sides.has(ip)) sides.set(ip, index % 2 === 0 ? "left" : "right");
    });
    return sides;
  }, [calls, endpoints]);
  const pageCount = Math.ceil(rows.length / PAGE_SIZE);
  const safePage = Math.min(page, Math.max(0, pageCount - 1));
  const visible = rows.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const position = (ip) =>
    ((endpoints.indexOf(ip) + 0.5) / Math.max(1, endpoints.length)) * 100;
  const scopeKey = calls.map((c) => c.key).join("|");
  useEffect(() => setPage(0), [scopeKey]);
  return (
    <article
      className="voip-chart sip-sequence-card"
      aria-label={
        grouped ? `会话 ${calls[0].index + 1} 时序图` : "多会话合并时序图"
      }
    >
      <div className="voip-chart-title">
        <span>
          <GitBranch size={15} />
          {grouped
            ? `会话 ${String(calls[0].index + 1).padStart(2, "0")}`
            : "信令时序"}
          <small>
            {endpoints.length} 个端点 · {rows.length} 条消息
          </small>
        </span>
        <span className="voip-chart-note">自上而下按时间排列</span>
      </div>
      <div
        className="voip-chart-scroll"
        tabIndex={0}
        role="region"
        aria-label="SIP 时序画布，可横向滚动查看所有端点"
      >
        <div
          className="voip-chart-canvas"
          style={{ "--lane-count": Math.max(1, endpoints.length) }}
        >
          <div className="voip-lane-header">
            <div className="voip-time-heading">
              时间 <small>Δ 同会话相邻消息</small>
            </div>
            <div className="voip-endpoints">
              {endpoints.map((ip, index) => (
                <div
                  className={`voip-endpoint sip-sequence-lane is-${endpointSides.get(ip)}`}
                  key={ip}
                >
                  <span className="voip-endpoint-letter">
                    {endpointLetter(
                      endpointOrder ? endpointOrder.indexOf(ip) : index,
                    )}
                  </span>
                  <code title={ip}>{ip}</code>
                </div>
              ))}
            </div>
          </div>
          <div className="voip-chart-body">
            <div className="voip-lifelines" aria-hidden="true">
              {endpoints.map((ip) => (
                <span key={ip} style={{ left: `${position(ip)}%` }} />
              ))}
            </div>
            {visible.map((row, index) => {
              const { packet, call, message, delta } = row;
              const source = position(packet.source),
                destination = position(packet.destination);
              const left = Math.min(source, destination),
                width = Math.abs(destination - source);
              const previous = rows[safePage * PAGE_SIZE + index - 1]?.packet;
              const idle = previous ? packet.time - previous.time : 0;
              const self = packet.source === packet.destination;
              const sourceSide =
                endpointSides.get(packet.source) ||
                (source <= destination ? "left" : "right");
              const detailAlign = self ? "center" : sourceSide;
              return (
                <React.Fragment key={packet.no}>
                  {idle > gap && (
                    <div className="voip-idle">
                      <span>间隔 {idle.toFixed(3)} s</span>
                    </div>
                  )}
                  <div className="voip-message-block">
                    <button
                      className={`voip-message-row voip-call-${call.index % 6} is-side-${sourceSide} ${expandedPacketNo === packet.no ? "is-expanded" : ""}`}
                      onClick={() => onPacket(packet)}
                      title={`展开数据包 #${packet.no} · ${packet.source}:${packet.srcPort} → ${packet.destination}:${packet.dstPort}`}
                      aria-label={`数据包 ${packet.no}，会话 ${call.index + 1}，${packet.source} 到 ${packet.destination}，${message.label}，${delta === null ? "首条消息" : `间隔 ${delta.toFixed(3)} 毫秒`}`}
                      aria-expanded={expandedPacketNo === packet.no}
                    >
                      <span className="voip-message-time sip-sequence-time">
                        <strong>{formatTime(packet, timeFormat)}</strong>
                        <small className="sip-sequence-delta">
                          {delta === null
                            ? "首条消息"
                            : `Δ ${delta.toFixed(3)} ms`}
                        </small>
                      </span>
                      <span className="voip-signal">
                        <span
                          className="voip-signal-label"
                          style={{
                            left: `${self ? source - 15 : left}%`,
                            width: `${self ? 30 : width}%`,
                          }}
                        >
                          <span className="voip-signal-call">
                            {String(call.index + 1).padStart(2, "0")}
                          </span>
                          <strong>{message.label}</strong>
                          {message.hasSdp && <em>SDP</em>}
                        </span>
                        <svg
                          className="voip-signal-line"
                          viewBox="0 0 1000 60"
                          preserveAspectRatio="none"
                          aria-hidden="true"
                        >
                          {self ? (
                            <path
                              d={`M ${source * 10} 29 h 55 v 16 h -55 m 0 0 l 7 -4 m -7 4 l 7 4`}
                            />
                          ) : (
                            <>
                              <path
                                d={`M ${source * 10} 32 H ${destination * 10}`}
                              />
                              <path
                                d={`M ${destination * 10 + (source < destination ? -7 : 7)} 28 L ${destination * 10} 32 L ${destination * 10 + (source < destination ? -7 : 7)} 36`}
                              />
                            </>
                          )}
                        </svg>
                        {!self && (
                          <>
                            <span
                              className="voip-port"
                              style={{ left: `${source}%` }}
                            >
                              {packet.srcPort || ""}
                            </span>
                            <span
                              className="voip-port"
                              style={{ left: `${destination}%` }}
                            >
                              {packet.dstPort || ""}
                            </span>
                          </>
                        )}
                      </span>
                    </button>
                    {expandedPacketNo === packet.no && (
                      <InlinePacketDetail
                        packet={packet}
                        detail={packetDetail}
                        loading={packetDetailLoading}
                        error={packetDetailError}
                        onClose={onCloseDetail}
                        align={detailAlign}
                      />
                    )}
                  </div>
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </div>
      <footer className="voip-chart-footer">
        <span>箭头表示信令方向 · 点击消息在当前时序图下方展开详情</span>
        {pageCount > 1 ? (
          <div className="voip-pagination">
            <button
              aria-label="上一页信令"
              disabled={!safePage}
              onClick={() => setPage(safePage - 1)}
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              {safePage + 1} / {pageCount}
            </span>
            <button
              aria-label="下一页信令"
              disabled={safePage + 1 >= pageCount}
              onClick={() => setPage(safePage + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        ) : (
          <span>Δ 为同一会话的消息间隔</span>
        )}
      </footer>
    </article>
  );
}

export default function SipFlow({
  capture,
  filter = "",
  timeFormat,
  onTimeFormatChange,
  formatTime,
  onPacket,
  onOpenPackets,
}) {
  const [packets, setPackets] = useState([]),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  const [progress, setProgress] = useState(0),
    [retry, setRetry] = useState(0);
  const [hidden, setHidden] = useState(new Set()),
    [search, setSearch] = useState("");
  const [mode, setMode] = useState("merged"),
    [gap, setGap] = useState(2);
  const [expandedPacketNo, setExpandedPacketNo] = useState(null),
    [packetDetail, setPacketDetail] = useState(null),
    [packetDetailLoading, setPacketDetailLoading] = useState(false),
    [packetDetailError, setPacketDetailError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setPackets([]);
    setProgress(0);
    setHidden(new Set());
    const flowFilter = filter.trim() || "sip";
    (async () => {
      const load = (page) =>
        api(
          capturePath(
            capture.id,
            `/packets?filter=${encodeURIComponent(flowFilter)}&page=${page}&size=${PAGE_SIZE}`,
          ),
          {
            signal: controller.signal,
          },
        );
      const first = await load(0),
        all = [...first.packets];
      setProgress(all.length);
      const pages = Math.ceil(first.total / first.pageSize);
      for (let page = 1; page < pages; page += 4) {
        const batch = await Promise.all(
          Array.from({ length: Math.min(4, pages - page) }, (_, i) =>
            load(page + i),
          ),
        );
        all.push(...batch.flatMap((data) => data.packets));
        if (controller.signal.aborted) return;
        setProgress(all.length);
      }
      if (!controller.signal.aborted) setPackets(all);
    })()
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [capture.id, capture.revision, retry, filter]);
  useEffect(() => {
    if (expandedPacketNo == null) {
      setPacketDetail(null);
      setPacketDetailLoading(false);
      setPacketDetailError("");
      return undefined;
    }
    const controller = new AbortController();
    setPacketDetail(null);
    setPacketDetailLoading(true);
    setPacketDetailError("");
    api(capturePath(capture.id, `/packets/${expandedPacketNo}`), {
      signal: controller.signal,
    })
      .then((data) => {
        if (!controller.signal.aborted) setPacketDetail(data);
      })
      .catch((e) => {
        if (!controller.signal.aborted) setPacketDetailError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setPacketDetailLoading(false);
      });
    return () => controller.abort();
  }, [capture.id, capture.revision, expandedPacketNo]);
  const calls = useMemo(() => buildSipCalls(packets), [packets]);
  const matching = useMemo(
    () =>
      calls.filter((call) =>
        `${call.callId} ${call.endpoints.join(" ")} ${call.status}`
          .toLowerCase()
          .includes(search.toLowerCase().trim()),
      ),
    [calls, search],
  );
  const selected = useMemo(
    () => matching.filter((call) => !hidden.has(call.key)),
    [matching, hidden],
  );
  const allSelected =
    matching.length > 0 && selected.length === matching.length;
  const endpoints = useMemo(
    () => sipEndpoints(calls.flatMap((call) => call.packets)),
    [calls],
  );
  function toggle(key) {
    setHidden((current) => {
      const next = new Set(current);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }
  function handlePacketClick(packet) {
    setExpandedPacketNo((current) =>
      current === packet.no ? null : packet.no,
    );
    onPacket?.(packet);
  }
  return (
    <section className="voip-workspace" aria-labelledby="voip-title">
      <header className="voip-heading">
        <div>
          <span className="voip-eyebrow">TELEPHONY / SIP FLOW</span>
          <h1 id="voip-title">VoIP 通话时序</h1>
          <p>
            {filter.trim()
              ? `当前过滤器：${filter} · 仅显示过滤结果中的 SIP 会话。`
              : "未设置过滤器 · 显示抓包中的全部 SIP 会话。"}
          </p>
        </div>
        <button className="voip-packets-button" onClick={onOpenPackets}>
          <Layers3 size={15} />
          查看 SIP 数据包
          <ArrowRight size={14} />
        </button>
      </header>
      <div className="voip-summary">
        <span>
          <PhoneCall size={15} />
          <strong>{calls.length}</strong> 个会话
        </span>
        <span>
          <Network size={15} />
          <strong>{sipEndpoints(packets).length}</strong> 个端点
        </span>
        <span>
          <Layers3 size={15} />
          <strong>{packets.length}</strong> 条信令
        </span>
        <span className="voip-summary-hint">
          按 Call-ID 关联 · 支持交错会话
        </span>
      </div>
      {loading ? (
        <div className="voip-state" role="status">
          <LoaderCircle className="spin" size={23} />
          <strong>正在还原 SIP 会话</strong>
          <span>已读取 {progress} 条信令</span>
        </div>
      ) : error ? (
        <div className="voip-state" role="alert">
          <TriangleAlert size={23} />
          <strong>无法加载 SIP 信令</strong>
          <span>{error}</span>
          <button onClick={() => setRetry((n) => n + 1)}>重新加载</button>
        </div>
      ) : !calls.length ? (
        <div className="voip-state">
          <PhoneCall size={25} />
          <strong>当前抓包没有 SIP 信令</strong>
          <span>打开包含 SIP 的 PCAP 文件后，即可查看多端点通话时序。</span>
          <button onClick={onOpenPackets}>查看数据包</button>
        </div>
      ) : (
        <>
          <div className="voip-call-list">
            <div className="voip-call-list-heading">
              <span>
                通话会话{" "}
                <small>
                  {selected.length} / {calls.length} 已显示
                </small>
              </span>
              <label className="voip-search">
                <Search size={14} />
                <input
                  aria-label="搜索 SIP 会话"
                  placeholder="搜索 IP 或 Call-ID"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </label>
            </div>
            <div className="voip-call-table-wrap">
              <table className="voip-call-table">
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        aria-label="显示全部匹配会话"
                        checked={allSelected}
                        onChange={() =>
                          setHidden((current) => {
                            const next = new Set(current);
                            matching.forEach((c) =>
                              allSelected
                                ? next.add(c.key)
                                : next.delete(c.key),
                            );
                            return next;
                          })
                        }
                      />
                    </th>
                    <th>会话 / Call-ID</th>
                    <th>端点</th>
                    <th>信令</th>
                    <th>时间跨度</th>
                    <th>状态</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {matching.map((call) => (
                    <tr
                      key={call.key}
                      className={`voip-call-${call.index % 6} ${hidden.has(call.key) ? "is-muted" : ""}`}
                    >
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`显示会话 ${call.index + 1}`}
                          checked={!hidden.has(call.key)}
                          onChange={() => toggle(call.key)}
                        />
                      </td>
                      <td>
                        <div className="voip-call-identity">
                          <i className="voip-color-dot" />
                          <strong>
                            会话 {String(call.index + 1).padStart(2, "0")}
                          </strong>
                        </div>
                        <code className="voip-call-id" title={call.callId}>
                          {call.callId}
                        </code>
                      </td>
                      <td>
                        <span className="voip-call-route">
                          {call.endpoints[0]} <ArrowRight size={12} />{" "}
                          {call.endpoints.at(-1)}
                        </span>
                        {call.endpoints.length > 2 && (
                          <small>{call.endpoints.length} 个端点 · 含中继</small>
                        )}
                      </td>
                      <td>{call.packets.length}</td>
                      <td>
                        <code>{call.duration.toFixed(3)} s</code>
                      </td>
                      <td>
                        <span
                          className={`voip-status ${call.status === "呼叫失败" ? "is-error" : ""}`}
                        >
                          {call.status === "已结束" && <Check size={11} />}
                          {call.status}
                        </span>
                      </td>
                      <td>
                        <button
                          className="voip-only"
                          aria-label={`仅显示会话 ${call.index + 1}`}
                          onClick={() =>
                            setHidden(
                              new Set(
                                calls
                                  .filter((c) => c.key !== call.key)
                                  .map((c) => c.key),
                              ),
                            )
                          }
                        >
                          仅此会话
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!matching.length && (
              <p className="voip-no-match">
                没有匹配的会话，请尝试其他 IP 或 Call-ID。
              </p>
            )}
          </div>
          <div className="voip-controls">
            <div
              className="voip-view-toggle"
              role="group"
              aria-label="时序布局"
            >
              <button
                aria-pressed={mode === "merged"}
                onClick={() => setMode("merged")}
              >
                <GitBranch size={14} />
                合并时序
              </button>
              <button
                aria-pressed={mode === "grouped"}
                onClick={() => setMode("grouped")}
              >
                <Layers3 size={14} />
                按会话分组
              </button>
            </div>
            <div className="voip-time-controls">
              <label htmlFor="sip-time-format">
                时间
                <select
                  id="sip-time-format"
                  value={timeFormat}
                  onChange={(e) => onTimeFormatChange(e.target.value)}
                >
                  {timeOptions.map(([id, label]) => (
                    <option key={id} value={id}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label htmlFor="sip-session-gap">
                空闲分段
                <select
                  id="sip-session-gap"
                  value={gap}
                  onChange={(e) => setGap(Number(e.target.value))}
                >
                  <option value="0.5">&gt; 500 ms</option>
                  <option value="1">&gt; 1 s</option>
                  <option value="2">&gt; 2 s</option>
                  <option value="5">&gt; 5 s</option>
                </select>
              </label>
            </div>
          </div>
          <div className="voip-selected-legend" aria-label="已显示的会话">
            <span>正在显示</span>
            {selected.map((call) => (
              <button
                key={call.key}
                className={`voip-call-${call.index % 6}`}
                title={`${call.callId} · 点击隐藏`}
                onClick={() => toggle(call.key)}
              >
                <i className="voip-color-dot" />
                会话 {String(call.index + 1).padStart(2, "0")}
                <span>
                  {call.endpoints
                    .map((ip) => endpointLetter(endpoints.indexOf(ip)))
                    .join(" ↔ ")}
                </span>
              </button>
            ))}
          </div>
          {!selected.length ? (
            <div className="voip-state">
              <Network size={24} />
              <strong>选择会话以查看时序</strong>
              <span>勾选上方会话，可将多路通话放在同一张图中。</span>
              <button
                onClick={() => {
                  setHidden(new Set());
                  setSearch("");
                }}
              >
                显示全部会话
              </button>
            </div>
          ) : mode === "merged" ? (
            <FlowChart
              calls={selected}
              endpointOrder={endpoints}
              timeFormat={timeFormat}
              formatTime={formatTime}
              gap={gap}
              onPacket={handlePacketClick}
              expandedPacketNo={expandedPacketNo}
              packetDetail={packetDetail}
              packetDetailLoading={packetDetailLoading}
              packetDetailError={packetDetailError}
              onCloseDetail={() => setExpandedPacketNo(null)}
            />
          ) : (
            <div className="voip-grouped-charts">
              {selected.map((call) => (
                <FlowChart
                  key={call.key}
                  calls={[call]}
                  endpointOrder={endpoints}
                  timeFormat={timeFormat}
                  formatTime={formatTime}
                  gap={gap}
                  onPacket={handlePacketClick}
                  expandedPacketNo={expandedPacketNo}
                  packetDetail={packetDetail}
                  packetDetailLoading={packetDetailLoading}
                  packetDetailError={packetDetailError}
                  onCloseDetail={() => setExpandedPacketNo(null)}
                  grouped
                />
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}
