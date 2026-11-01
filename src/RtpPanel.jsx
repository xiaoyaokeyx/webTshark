import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowUpRight,
  AudioLines,
  Download,
  Headphones,
  RotateCcw,
  Plus,
  Settings2,
  Trash2,
  TriangleAlert,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { Modal, Notice, IconButton } from "./ui.jsx";
import { sizeLabel, downloadBlob } from "./api.js";
export function MappingEditor({ stream, existing, codecs, onSave, onClose }) {
  const [pt, setPt] = useState(
      existing?.pt ?? stream?.pts?.find((p) => p >= 96) ?? 96,
    ),
    [codec, setCodec] = useState(existing?.codec || "PCMU"),
    [rate, setRate] = useState(existing?.clockRate || 8000),
    [channels, setChannels] = useState(existing?.channels || 1),
    [octetAlign, setOctetAlign] = useState(existing?.octetAlign ?? false),
    [scope, setScope] = useState(
      existing?.scope || (stream ? "stream" : "capture"),
    ),
    [error, setError] = useState("");
  const identity = existing?.scope === "stream" ? existing : stream;
  async function submit(e) {
    e.preventDefault();
    setError("");
    try {
      await onSave(
        {
          pt: Number(pt),
          codec,
          clockRate: Number(rate),
          channels: Number(channels),
          scope,
          ...(codecs.find((c) => c.name === codec)?.amr ? { octetAlign } : {}),
          ...(scope === "stream"
            ? {
                source: identity.source,
                destination: identity.destination,
                srcPort: identity.srcPort,
                dstPort: identity.dstPort,
                ssrc: identity.ssrc,
              }
            : {}),
        },
        existing,
      );
      onClose();
    } catch (e) {
      setError(e.message);
    }
  }
  const selected = codecs.find((c) => c.name === codec);
  return (
    <Modal
      title="RTP 动态 PT 编解码映射"
      subtitle="将载荷类型绑定到明确的编解码格式与 RTP 时钟。"
      onClose={onClose}
    >
      <form className="modal-body" onSubmit={submit}>
        <label className="field-label" htmlFor="mapping-scope">
          作用范围
        </label>
        <select
          id="mapping-scope"
          className="form-select"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
        >
          {identity && <option value="stream">仅当前单向媒体流（推荐）</option>}
          <option value="capture">当前抓包中所有使用此 PT 的媒体流</option>
        </select>
        {scope === "stream" && identity && (
          <div className="flow-identity">
            <code>
              {identity.source}:{identity.srcPort} → {identity.destination}:
              {identity.dstPort}
            </code>
            <span>SSRC {identity.ssrc}</span>
          </div>
        )}
        {scope === "capture" && (
          <Notice>
            同一 PT
            在不同会话中可能代表不同编码。文件级映射会影响所有匹配的媒体流；单流映射优先。
          </Notice>
        )}
        <div className="form-grid">
          <div>
            <label className="field-label" htmlFor="mapping-pt">
              动态 Payload Type
            </label>
            <input
              id="mapping-pt"
              type="number"
              min="96"
              max="127"
              required
              value={pt}
              onChange={(e) => setPt(e.target.value)}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="mapping-codec">
              编解码
            </label>
            <select
              id="mapping-codec"
              value={codec}
              onChange={(e) => {
                const c = codecs.find((c) => c.name === e.target.value);
                setCodec(c.name);
                setRate(c.clockRate);
                setChannels(c.channels);
                setOctetAlign(false);
              }}
            >
              {codecs.map((c) => (
                <option key={c.name} value={c.name}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="field-label" htmlFor="mapping-rate">
              RTP 时钟频率（Hz）
            </label>
            <input
              id="mapping-rate"
              type="number"
              min="1000"
              max="192000"
              required
              value={rate}
              readOnly={selected?.amr === true}
              onChange={(e) => setRate(e.target.value)}
            />
          </div>
          <div>
            <label className="field-label" htmlFor="mapping-channels">
              声道数
            </label>
            <select
              id="mapping-channels"
              value={channels}
              onChange={(e) => setChannels(e.target.value)}
            >
              <option value="1">1 · 单声道 / 视频</option>
              <option value="2">2 · 双声道</option>
            </select>
          </div>
        </div>
        {selected?.amr && (
          <>
            <label className="field-label" htmlFor="mapping-octet-align">
              AMR 载荷封装（octet-align）
            </label>
            <select
              id="mapping-octet-align"
              className="form-select"
              value={octetAlign ? "1" : "0"}
              onChange={(e) => setOctetAlign(e.target.value === "1")}
            >
              <option value="0">Bandwidth-efficient（octet-align=0）</option>
              <option value="1">Octet-aligned（octet-align=1）</option>
            </select>
          </>
        )}
        <Notice>
          {selected?.playback
            ? "此编码支持真实 G.711 解码、音频试听和 WAV 导出。丢失的时间区间填充静音。"
            : selected?.dissector
              ? "此编码会调用 TShark 的对应载荷解析器；当前版本不提供该编码的音视频播放。"
              : "此编码保存映射并用于流标识与时钟统计；当前版本不提供该编码的载荷解码或播放。"}
          {codec === "G722" &&
            " G.722 的 RTP 时间戳时钟是 8000 Hz，与音频采样率不同。"}
          {selected?.amr &&
            " 请按 SDP 中的 octet-align 参数选择封装；未声明时默认 0。"}
        </Notice>
        {error && (
          <p className="filter-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button className="button primary" type="submit">
            保存并重新解析
          </button>
        </div>
      </form>
    </Modal>
  );
}
export function RtpDetection({ config, initialPort, onSave, onClose }) {
  const [ports, setPorts] = useState(
      [
        ...new Set([...config.ports, ...(initialPort ? [initialPort] : [])]),
      ].join(", "),
    ),
    [heuristic, setHeuristic] = useState(config.heuristic),
    [error, setError] = useState("");
  return (
    <Modal
      title="RTP 识别设置"
      subtitle="抓包缺少 SIP/SDP 信令时，可手动指定 RTP 的 UDP 端口。"
      onClose={onClose}
    >
      <form
        className="modal-body"
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            const parsed = ports.trim()
              ? ports
                  .split(/[,，\s]+/)
                  .filter(Boolean)
                  .map(Number)
              : [];
            await onSave({ ...config, ports: parsed, heuristic });
            onClose();
          } catch (e) {
            setError(e.message);
          }
        }}
      >
        <label className="field-label" htmlFor="rtp-ports">
          将 UDP 端口解码为 RTP
        </label>
        <input
          id="rtp-ports"
          className="form-input"
          value={ports}
          onChange={(e) => setPorts(e.target.value)}
          placeholder="例如 20000, 20002"
        />
        <p className="form-helper">
          源端口或目标端口匹配时生效。留空则取消强制解码。
        </p>
        <label className="setting-row">
          <div>
            <strong>启用 RTP 启发式识别</strong>
            <span>
              根据数据包结构识别 RTP；可能将其他 UDP 流量误识别为 RTP。
            </span>
          </div>
          <input
            type="checkbox"
            checked={heuristic}
            onChange={(e) => setHeuristic(e.target.checked)}
          />
        </label>
        <Notice>这些设置仅作用于当前抓包；原始文件内容保持不变。</Notice>
        {error && (
          <p className="filter-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button className="button primary" type="submit">
            应用并重新解析
          </button>
        </div>
      </form>
    </Modal>
  );
}
const decodeAsProtocols = [
  ["rtp", "RTP（实时传输协议）"],
  ["rtcp", "RTCP（RTP 控制协议）"],
  ["sip", "SIP（会话初始化协议）"],
  ["sdp", "SDP（会话描述协议）"],
  ["http", "HTTP"],
  ["mrcpv2", "MRCPv2"],
  ["dns", "DNS"],
  ["tls", "TLS"],
  ["data", "Data（原始数据）"],
];
export function DecodeAsEditor({ packet, existing, onSave, onClose }) {
  const [transport, setTransport] = useState(
      existing?.transport || packet?.transport?.toLowerCase() || "udp",
    ),
    [port, setPort] = useState(
      existing?.port ?? packet?.dstPort ?? packet?.srcPort ?? "",
    ),
    [protocol, setProtocol] = useState(existing?.protocol || "rtp"),
    [error, setError] = useState("");
  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await onSave({ transport, port: Number(port), protocol });
      onClose();
    } catch (e) {
      setError(e.message);
    }
  }
  return (
    <Modal
      title="Decode As · 解码为"
      subtitle="按 Wireshark 的端口规则，将当前 TCP/UDP 流交给指定协议解析器。"
      onClose={onClose}
    >
      <form className="modal-body" onSubmit={submit}>
        <div className="flow-identity">
          <code>
            数据包 #{packet?.no} · {packet?.source}:{packet?.srcPort} → {packet?.destination}:
            {packet?.dstPort}
          </code>
          <span>{packet?.protocol || packet?.transport}</span>
        </div>
        <div className="form-grid">
          <div>
            <label className="field-label" htmlFor="decode-as-transport">
              传输协议
            </label>
            <select
              id="decode-as-transport"
              value={transport}
              onChange={(event) => setTransport(event.target.value)}
            >
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </select>
          </div>
          <div>
            <label className="field-label" htmlFor="decode-as-port">
              端口
            </label>
            <input
              id="decode-as-port"
              type="number"
              min="1"
              max="65535"
              required
              value={port}
              onChange={(event) => setPort(event.target.value)}
            />
          </div>
        </div>
        <label className="field-label" htmlFor="decode-as-protocol">
          解码协议
        </label>
        <select
          id="decode-as-protocol"
          className="form-select"
          value={protocol}
          onChange={(event) => setProtocol(event.target.value)}
        >
          {decodeAsProtocols.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <p className="form-helper">
          规则对当前抓包生效，并同时匹配该端口的两个方向；编辑已有规则时可点击下方“恢复默认”。
        </p>
        {existing && (
          <button
            type="button"
            className="text-button accent-text decode-as-reset"
            onClick={async () => {
              try {
                await onSave(null);
                onClose();
              } catch (e) {
                setError(e.message);
              }
            }}
          >
            恢复该端口的默认解析
          </button>
        )}
        <Notice>原始 PCAP 不会被修改，重新解析只更新当前工作区的协议识别结果。</Notice>
        {error && (
          <p className="filter-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button className="button primary" type="submit">
            应用并重新解析
          </button>
        </div>
      </form>
    </Modal>
  );
}

function formatRelativeClock(seconds) {
  const safe = Math.max(0, Number(seconds) || 0);
  const minutes = Math.floor(safe / 60);
  const wholeSeconds = Math.floor(safe % 60);
  const milliseconds = Math.floor((safe % 1) * 1000);
  return `${minutes}:${String(wholeSeconds).padStart(2, "0")}.${String(milliseconds).padStart(3, "0")}`;
}

function formatLocalClock(epoch) {
  if (!Number.isFinite(Number(epoch))) return "--:--:--.---";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
    hour12: false,
  }).format(new Date(Number(epoch) * 1000));
}

function RtpWaveform({
  data,
  stream,
  audio,
  audioRef,
  playbackTime,
  playbackDuration,
  timeMode,
  onTimeModeChange,
  onTimeUpdate,
  onLoadedMetadata,
  onSeek,
  onRestart,
  onLocatePacket,
  onClose,
}) {
  const [zoom, setZoom] = useState(1);
  const scrollRef = useRef(null);
  const axisScrollRef = useRef(null);
  const [scrollMetrics, setScrollMetrics] = useState({
    left: 0,
    viewport: 0,
    total: 0,
  });
  const packets = data?.packets || [];
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === "Escape") onClose?.();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);
  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return undefined;
    node.scrollLeft = 0;
    if (axisScrollRef.current) axisScrollRef.current.scrollLeft = 0;
    const updateMetrics = () =>
      setScrollMetrics({
        left: node.scrollLeft,
        viewport: node.clientWidth,
        total: node.scrollWidth,
      });
    updateMetrics();
    return undefined;
  }, [zoom, packets.length]);
  if (!packets.length) return null;
  const width = 1000;
  const height = 210;
  const plotLeft = 26;
  const plotRight = 12;
  const plotTop = 18;
  const plotBottom = 28;
  const plotWidth = width - plotLeft - plotRight;
  const plotHeight = height - plotTop - plotBottom;
  const mid = plotTop + plotHeight / 2;
  const maxLevel = Math.max(
    1,
    ...packets.map((packet) => Math.max(Math.abs(packet.min), Math.abs(packet.max))),
  );
  const yFor = (value) => mid - (value / maxLevel) * (plotHeight * 0.44);
  const first = packets[0];
  const last = packets.at(-1);
  const firstTime = Number(data.startTime ?? first.time) || 0;
  const duration = Math.max(
    0,
    Number(data.duration) || (Number(last?.time) || 0) - firstTime,
  );
  const mediaDuration = playbackDuration || duration;
  const startEpoch = Number(data.startEpoch ?? first.epoch);
  const xFor = (packet, index) => {
    const packetOffset = Number(packet?.offset);
    const ratio = Number.isFinite(packetOffset) && mediaDuration > 0
      ? packetOffset / mediaDuration
      : index / Math.max(1, packets.length - 1);
    return plotLeft + Math.min(1, Math.max(0, ratio)) * plotWidth;
  };
  const playheadRatio = mediaDuration
    ? Math.min(1, Math.max(0, playbackTime / mediaDuration))
    : 0;
  const playheadX = plotLeft + playheadRatio * plotWidth;
  const formatAxisTime = (packet) =>
    timeMode === "local" && Number.isFinite(Number(packet?.epoch))
      ? formatLocalClock(packet.epoch)
      : formatRelativeClock((Number(packet?.time) || 0) - firstTime);
  const formatPlaybackTime = () =>
    timeMode === "local" && Number.isFinite(startEpoch)
      ? formatLocalClock(startEpoch + playbackTime)
      : formatRelativeClock(playbackTime);
  const formatTimelineTime = (seconds) =>
    timeMode === "local" && Number.isFinite(startEpoch)
      ? formatLocalClock(startEpoch + seconds)
      : formatRelativeClock(seconds);
  const viewportWidth = scrollMetrics.viewport || width;
  const totalWidth = scrollMetrics.total || width * zoom;
  const visibleRatio = Math.min(1, viewportWidth / Math.max(viewportWidth, totalWidth));
  const visibleDuration = mediaDuration * visibleRatio;
  const maxScroll = Math.max(0, totalWidth - viewportWidth);
  const scrollRatio = maxScroll ? scrollMetrics.left / maxScroll : 0;
  const visibleStart = (mediaDuration - visibleDuration) * scrollRatio;
  const visibleEnd = Math.min(mediaDuration, visibleStart + visibleDuration);
  const targetTickCount = Math.max(5, Math.min(10, Math.round(viewportWidth / 140)));
  const rawTickStep = Math.max(0.001, visibleDuration / targetTickCount);
  const niceTickStep = (value) => {
    const exponent = 10 ** Math.floor(Math.log10(value));
    const fraction = value / exponent;
    const multiplier =
      fraction <= 1.5 ? 1 : fraction <= 3.5 ? 2 : fraction <= 7.5 ? 5 : 10;
    return multiplier * exponent;
  };
  const tickStep = niceTickStep(rawTickStep);
  const tickCount = Math.max(1, Math.ceil(mediaDuration / tickStep));
  const rawTicks = Array.from({ length: tickCount + 1 }, (_, index) => {
    const seconds = Math.min(mediaDuration, index * tickStep);
    const ratio = mediaDuration ? seconds / mediaDuration : 0;
    return {
      ratio,
      x: plotLeft + ratio * plotWidth,
      label: formatTimelineTime(seconds),
    };
  });
  // Keep labels comfortably separated. The final duration marker can land
  // only a few pixels after the previous "nice" tick (for example 7.000 and
  // 7.080 seconds), which makes the two labels overlap at the axis edge.
  const minTickSpacing = timeMode === "local" ? 132 : 72;
  const ticks = rawTicks.reduce((visibleTicks, tick) => {
    const previous = visibleTicks.at(-1);
    if (!previous || tick.x - previous.x >= minTickSpacing) {
      visibleTicks.push(tick);
    }
    return visibleTicks;
  }, []);
  function seek(packet) {
    if (packet?.no == null) return;
    const offset = Number(packet.offset);
    onSeek?.(
      Number.isFinite(offset)
        ? Math.max(0, offset)
        : Math.max(0, (Number(packet.time) || firstTime) - firstTime),
    );
  }
  function locate(packet) {
    if (packet?.no == null) return;
    seek(packet);
    onLocatePacket?.(packet.no, stream?.filter);
  }
  function handleWaveformScroll(event) {
    const node = event.currentTarget;
    if (axisScrollRef.current && axisScrollRef.current.scrollLeft !== node.scrollLeft)
      axisScrollRef.current.scrollLeft = node.scrollLeft;
    setScrollMetrics({
      left: node.scrollLeft,
      viewport: node.clientWidth,
      total: node.scrollWidth,
    });
  }
  function handleAxisScroll(event) {
    const node = event.currentTarget;
    if (scrollRef.current && scrollRef.current.scrollLeft !== node.scrollLeft)
      scrollRef.current.scrollLeft = node.scrollLeft;
  }
  return (
    <div
      className="rtp-media-modal"
      role="dialog"
      aria-modal="true"
      aria-label="RTP 媒体播放窗口"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose?.();
      }}
    >
      <section
        className="rtp-waveform-card rtp-media-dialog"
        aria-label="RTP 音频波形图"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="rtp-waveform-header">
          <div>
            <div className="rtp-waveform-title">
              <AudioLines size={15} />
              <strong>RTP 媒体播放</strong>
              <span>{data.codec} · PT {stream?.pts?.join(", ")}</span>
            </div>
            <p>播放进度与波形同步；单击预览位置，双击定位对应 RTP 数据包。</p>
          </div>
          <div className="rtp-waveform-meta">
            <span>{packets.length}{data.sampled ? ` / ${data.originalPackets}` : ""} 包</span>
            <span>{formatPlaybackTime()} / {timeMode === "local" ? formatLocalClock(startEpoch + mediaDuration) : formatRelativeClock(mediaDuration)}</span>
            {data.sampled && <span>已抽样</span>}
            <button className="text-button" onClick={onClose} aria-label="关闭媒体播放窗口">
              <X size={14} />
              关闭
            </button>
          </div>
        </div>
        <div className="rtp-waveform-toolbar">
          <div className="rtp-time-mode" role="group" aria-label="波形时间显示格式">
            <span>时间</span>
            <button
              className={timeMode === "relative" ? "active" : ""}
              onClick={() => onTimeModeChange?.("relative")}
            >
              相对
            </button>
            <button
              className={timeMode === "local" ? "active" : ""}
              onClick={() => onTimeModeChange?.("local")}
            >
              本地
            </button>
          </div>
          <div className="rtp-waveform-zoom-controls" role="group" aria-label="波形缩放">
            <span>整体</span>
            <button
              className="text-button rtp-zoom-button"
              onClick={() => setZoom((value) => Math.max(1, value / 2))}
              disabled={zoom <= 1}
              aria-label="缩小波形"
            >
              <ZoomOut size={14} />
            </button>
            <strong>{zoom}×</strong>
            <button
              className="text-button rtp-zoom-button"
              onClick={() => setZoom((value) => Math.min(8, value * 2))}
              disabled={zoom >= 8}
              aria-label="放大波形"
            >
              <ZoomIn size={14} />
            </button>
            <button className="text-button" onClick={() => setZoom(1)} disabled={zoom === 1}>
              复位
            </button>
          </div>
        </div>
        <div className="rtp-waveform-zoom-status" aria-live="polite">
          {zoom === 1
            ? "显示完整波形"
            : `整体 ${zoom}×（时间轴与振幅）· 当前视窗 ${formatTimelineTime(visibleStart)} – ${formatTimelineTime(visibleEnd)}，可拖动滚动条查看完整音频`}
        </div>
        <div className="rtp-waveform-legend">
          <span><i className="rtp-waveform-swatch audio" />音频能量</span>
          <span><i className="rtp-waveform-swatch loss" />序列缺口</span>
          <span className="rtp-waveform-hint">蓝色游标 = 当前播放位置 · 单击预览 · 双击定位 frame.number</span>
        </div>
        <div
          className="rtp-waveform-scroll"
          ref={scrollRef}
          onScroll={handleWaveformScroll}
        >
          <svg
            className="rtp-waveform-svg"
            style={{
              width: `${zoom * 100}%`,
              minWidth: `${zoom * 100}%`,
              height: `${260 * zoom}px`,
              minHeight: `${260 * zoom}px`,
              maxWidth: "none",
            }}
            viewBox={`0 0 ${width} ${height}`}
            role="img"
            aria-label={`${data.codec} RTP 音频波形，单击预览，双击节点定位数据包`}
          >
            <rect x="0" y="0" width={width} height={height} className="rtp-waveform-bg" />
            <line x1={plotLeft} x2={width - plotRight} y1={mid} y2={mid} className="rtp-waveform-zero" />
            <line x1={plotLeft} x2={plotLeft} y1={plotTop} y2={height - plotBottom} className="rtp-waveform-axis" />
            {ticks.map((tick) => (
              <g key={`tick-${tick.ratio}`} className="rtp-waveform-tick-group">
                <line
                  x1={tick.x}
                  x2={tick.x}
                  y1={plotTop}
                  y2={height - plotBottom}
                  className="rtp-waveform-gridline"
                />
              </g>
            ))}
            {packets.map((packet, index) => {
              const x = xFor(packet, index);
              const y1 = yFor(packet.max);
              const y2 = yFor(packet.min);
              const lost = packet.lostBefore > 0;
              return (
                <g key={`${packet.no}-${packet.seq}-${index}`}>
                  {lost && (
                    <rect
                      x={Math.max(plotLeft, x - 1.5)}
                      y={plotTop}
                      width="3"
                      height={plotHeight}
                      className="rtp-waveform-loss"
                      aria-label={`丢失 ${packet.lostBefore} 个 RTP 序号`}
                    />
                  )}
                  <line
                    x1={x}
                    x2={x}
                    y1={Math.min(y1, y2)}
                    y2={Math.max(y1, y2)}
                    className={`rtp-waveform-node ${lost ? "has-gap" : ""}`}
                    onClick={() => seek(packet)}
                    onDoubleClick={() => locate(packet)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        locate(packet);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    aria-label={`RTP 包 ${packet.no}，序号 ${packet.seq}，${formatAxisTime(packet)}；双击定位`}
                  />
                </g>
              );
            })}
            <line
              x1={playheadX}
              x2={playheadX}
              y1={plotTop}
              y2={height - plotBottom}
              className="rtp-waveform-playhead"
              aria-hidden="true"
            />
            <circle
              cx={playheadX}
              cy={plotTop}
              r="4"
              className="rtp-waveform-playhead-dot"
              aria-hidden="true"
            />
            <text x={plotLeft - 6} y={plotTop + 4} textAnchor="end" className="rtp-waveform-label">+</text>
            <text x={plotLeft - 6} y={mid + 4} textAnchor="end" className="rtp-waveform-label">0</text>
            <text x={plotLeft - 6} y={height - plotBottom + 4} textAnchor="end" className="rtp-waveform-label">−</text>
          </svg>
        </div>
        <div
          className="rtp-waveform-axis-scroll"
          ref={axisScrollRef}
          onScroll={handleAxisScroll}
          aria-label="固定时间刻度"
        >
          <svg
            className="rtp-waveform-axis-svg"
            style={{
              width: `${zoom * 100}%`,
              minWidth: `${zoom * 100}%`,
              maxWidth: "none",
            }}
            viewBox={`0 0 ${width * zoom} 36`}
            aria-hidden="true"
          >
            <line
              x1={plotLeft * zoom}
              x2={(width - plotRight) * zoom}
              y1="1"
              y2="1"
              className="rtp-waveform-axis-ruler"
            />
            {ticks.map((tick) => (
              <g key={`axis-tick-${tick.ratio}`}>
                <line
                  x1={tick.x * zoom}
                  x2={tick.x * zoom}
                  y1="1"
                  y2="7"
                  className="rtp-waveform-tick"
                />
                <text
                  x={tick.x * zoom}
                  y="27"
                  textAnchor={tick.ratio === 0 ? "start" : tick.ratio === 1 ? "end" : "middle"}
                  className="rtp-waveform-time"
                >
                  {tick.label}
                </text>
              </g>
            ))}
          </svg>
        </div>
        <div className="rtp-stream-summary" aria-label="RTP 媒体流摘要">
          <div className="rtp-stream-summary-title">
            <span>播放流</span>
            <span>与 Wireshark RTP Player 一致，先看完整波形，再查看流信息</span>
          </div>
          <div className="rtp-stream-summary-scroll">
            <table>
              <thead>
                <tr>
                  <th>播放</th>
                  <th>源地址</th>
                  <th>源端口</th>
                  <th>目标地址</th>
                  <th>目标端口</th>
                  <th>SSRC</th>
                  <th>包数</th>
                  <th>时间跨度</th>
                  <th>采样率</th>
                  <th>Payload</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <button
                      className="rtp-stream-play-button"
                      onClick={onRestart}
                      disabled={!audio}
                      title="从头开始播放当前流"
                      aria-label="从头开始播放当前流"
                    >
                      <Headphones size={13} />
                    </button>
                  </td>
                  <td>{stream?.source || "—"}</td>
                  <td>{stream?.srcPort ?? "—"}</td>
                  <td>{stream?.destination || "—"}</td>
                  <td>{stream?.dstPort ?? "—"}</td>
                  <td><code>{stream?.ssrc || "—"}</code></td>
                  <td>{stream?.packets ?? packets.length}</td>
                  <td>{formatRelativeClock(mediaDuration)}</td>
                  <td>{data.clockRate || stream?.clockRate || "—"} Hz</td>
                  <td>{data.codec || "—"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div className="rtp-waveform-player">
          <Headphones size={16} />
          <button
            className="button secondary rtp-restart-button"
            onClick={onRestart}
            disabled={!audio}
            title="从头开始播放"
            aria-label="从头开始播放"
          >
            <RotateCcw size={14} />
          </button>
          <audio
            ref={audioRef}
            controls
            src={audio?.url}
            onTimeUpdate={onTimeUpdate}
            onLoadedMetadata={onLoadedMetadata}
          />
          {audio && (
            <button
              className="button secondary"
              onClick={() => downloadBlob(audio.blob, audio.name)}
            >
              <Download size={14} />
              下载 WAV
            </button>
          )}
        </div>
      </section>
    </div>
  );
}

export default function RtpPanel({
  capture,
  onFilter,
  onEdit,
  onDetect,
  onRemove,
  onError,
  onLocatePacket,
}) {
  const audioRef = useRef(null);
  const [audio, setAudio] = useState(null),
    [waveform, setWaveform] = useState(null),
    [mediaLoading, setMediaLoading] = useState(null),
    [playbackTime, setPlaybackTime] = useState(0),
    [playbackDuration, setPlaybackDuration] = useState(0),
    [timeMode, setTimeMode] = useState("relative");
  useEffect(() => {
    setAudio(null);
    setWaveform(null);
    setMediaLoading(null);
    setPlaybackTime(0);
    setPlaybackDuration(0);
    setTimeMode("relative");
  }, [capture.id, capture.revision]);
  useEffect(
    () => () => {
      if (audio?.url) URL.revokeObjectURL(audio.url);
    },
    [audio],
  );
  const streams = capture.summary?.media || [];
  const closeMedia = useCallback(() => {
    setAudio(null);
    setWaveform(null);
    setPlaybackTime(0);
    setPlaybackDuration(0);
    setTimeMode("relative");
  }, []);
  async function openMedia(index) {
    if (audio?.index === index && waveform?.stream === index) {
      closeMedia();
      return;
    }
    setMediaLoading(index);
    try {
      const [waveformRes, audioRes] = await Promise.all([
        fetch(`/api/captures/${capture.id}/waveform?stream=${index}`),
        fetch(`/api/captures/${capture.id}/audio?stream=${index}`),
      ]);
      const waveformData = await waveformRes.json();
      if (!waveformRes.ok)
        throw new Error(waveformData.error || "波形生成失败");
      if (!audioRes.ok) {
        const data = await audioRes.json();
        throw new Error(data.error || "音频解码失败");
      }
      const blob = await audioRes.blob();
      setAudio({
        index,
        blob,
        url: URL.createObjectURL(blob),
        name: `rtp-${streams[index].ssrc}.wav`,
      });
      setWaveform(waveformData);
      setPlaybackTime(0);
      setPlaybackDuration(0);
    } catch (e) {
      onError(e.message);
    } finally {
      setMediaLoading(null);
    }
  }
  function syncPlayback(event) {
    setPlaybackTime(event.currentTarget.currentTime || 0);
    if (Number.isFinite(event.currentTarget.duration))
      setPlaybackDuration(event.currentTarget.duration);
  }
  function seekPlayback(seconds) {
    if (!audioRef.current) return;
    audioRef.current.currentTime = Math.max(0, seconds);
    setPlaybackTime(Math.max(0, seconds));
  }
  function restartPlayback() {
    if (!audioRef.current) return;
    audioRef.current.currentTime = 0;
    setPlaybackTime(0);
    audioRef.current.play().catch(() => {});
  }
  return (
    <section className="analysis-content">
      <div className="rtp-intro">
        <div className="rtp-intro-icon">
          <AudioLines size={26} />
        </div>
        <div>
          <h2>从载荷类型，还原媒体内容</h2>
          <p>按媒体流配置动态 PT，查看序列与时钟统计，并试听 G.711 音频。</p>
        </div>
        <button className="button secondary" onClick={() => onDetect()}>
          <Settings2 size={15} />
          RTP 识别设置
        </button>
      </div>
      <section className="analysis-card standalone">
        <div className="section-heading">
          <h2>
            RTP 媒体流 <span className="count-badge">{streams.length}</span>
          </h2>
          <span>单向五元组 + SSRC · 丢包数为序列号估算</span>
        </div>
        {!streams.length ? (
          <div className="empty-state">
            <AudioLines size={28} />
            <strong>尚未识别到 RTP 媒体流</strong>
            <p>可导入包含 SIP/SDP 的抓包，或手动指定 UDP 端口。</p>
            <button className="button secondary" onClick={() => onDetect()}>
              设置 RTP 端口
            </button>
          </div>
        ) : (
          <div className="wide-table">
            <table className="analysis-table rtp-table">
              <thead>
                <tr>
                  <th>媒体端点 / SSRC</th>
                  <th>PT / 编解码</th>
                  <th>数据包</th>
                  <th>估算丢包</th>
                  <th>最大抖动</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {streams.map((s, i) => (
                  <tr key={s.key}>
                    <td>
                      <div className="media-address">
                        {s.source}:{s.srcPort}
                        <span>
                          → {s.destination}:{s.dstPort}
                        </span>
                        <small>SSRC {s.ssrc}</small>
                      </div>
                    </td>
                    <td>
                      <div className="media-codec">
                        <span
                          className={`protocol ${s.codecs.some((c) => c.startsWith("Dynamic")) ? "protocol-unmapped" : "protocol-rtp"}`}
                        >
                          {s.codecs.join(" / ")}
                        </span>
                        <small>
                          PT {s.pts.join(", ")} ·{" "}
                          {s.clockRate ? `${s.clockRate} Hz` : "时钟频率未知"}
                        </small>
                      </div>
                    </td>
                    <td>
                      {s.packets}
                      <small className="block-small">
                        {sizeLabel(s.bytes)}
                      </small>
                    </td>
                    <td>
                      <span className={s.lost ? "error-text" : ""}>
                        {s.lost}
                      </span>
                      <small className="block-small">重复 {s.duplicates}</small>
                    </td>
                    <td>
                      {s.maxJitter == null
                        ? "—"
                        : `${s.maxJitter.toFixed(2)} ms`}
                    </td>
                    <td>
                      <div className="media-actions">
                        <button
                          className="text-button accent-text"
                          onClick={() => onEdit(s)}
                          disabled={!s.pts.some((pt) => pt >= 96)}
                        >
                          <Settings2 size={13} />
                          设置 PT
                        </button>
                        <button
                          className="text-button"
                          onClick={() => onFilter(s.filter)}
                        >
                          <ArrowUpRight size={13} />
                          数据包
                        </button>
                        <button
                          className={`text-button ${audio?.index === i ? "accent-text" : ""}`}
                          disabled={
                            mediaLoading !== null ||
                            s.codecs.some((c) => !["PCMA", "PCMU"].includes(c))
                          }
                          onClick={() => openMedia(i)}
                          title="打开独立 RTP 媒体窗口"
                        >
                          <Headphones size={13} />
                          {mediaLoading === i
                            ? "加载试听…"
                            : audio?.index === i
                              ? "收起试听"
                              : "试听"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {waveform && (
        <RtpWaveform
          data={waveform}
          stream={streams[waveform.stream]}
          audio={audio}
          audioRef={audioRef}
          playbackTime={playbackTime}
          playbackDuration={playbackDuration}
          timeMode={timeMode}
          onTimeModeChange={setTimeMode}
          onTimeUpdate={syncPlayback}
          onLoadedMetadata={(event) => {
            if (Number.isFinite(event.currentTarget.duration))
              setPlaybackDuration(event.currentTarget.duration);
          }}
          onSeek={seekPlayback}
          onRestart={restartPlayback}
          onLocatePacket={onLocatePacket}
          onClose={closeMedia}
        />
      )}
      <section className="analysis-card standalone">
        <div className="section-heading">
          <h2>
            动态 PT 映射{" "}
            <span className="count-badge">
              {capture.config.mappings.length}
            </span>
          </h2>
          <button className="button secondary" onClick={() => onEdit(null)}>
            <Plus size={14} />
            添加映射
          </button>
        </div>
        {capture.config.mappings.length ? (
          <div className="mapping-list">
            {capture.config.mappings.map((m, i) => (
              <div key={i} className="mapping-item">
                <span className="pt-badge">{m.pt}</span>
                <div>
                  <strong>
                    {m.codec}{" "}
                    <small>
                      {m.clockRate} Hz · {m.channels} ch
                      {typeof m.octetAlign === "boolean" &&
                        ` · ${m.octetAlign ? "Octet-aligned" : "Bandwidth-efficient"}`}
                    </small>
                  </strong>
                  <span>
                    {m.scope === "stream"
                      ? `${m.source}:${m.srcPort} → ${m.destination}:${m.dstPort} · ${m.ssrc}`
                      : "当前抓包所有媒体流（单流映射优先）"}
                  </span>
                </div>
                <button
                  className="text-button accent-text"
                  onClick={() => onEdit(null, m)}
                >
                  编辑
                </button>
                <IconButton
                  icon={Trash2}
                  label={`删除 PT ${m.pt} 映射 ${i + 1}`}
                  onClick={() => onRemove(i)}
                />
              </div>
            ))}
          </div>
        ) : (
          <div className="mapping-empty">
            <TriangleAlert size={17} />
            <span>
              PT 96–127
              是动态类型，需要信令协商或手动指定。先在上方选择一条媒体流设置映射。
            </span>
          </div>
        )}
      </section>
    </section>
  );
}
