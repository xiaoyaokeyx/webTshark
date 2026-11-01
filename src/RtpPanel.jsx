import React, { useEffect, useState } from "react";
import {
  ArrowUpRight,
  AudioLines,
  Download,
  Headphones,
  Plus,
  Settings2,
  Trash2,
  TriangleAlert,
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
export default function RtpPanel({
  capture,
  onFilter,
  onEdit,
  onDetect,
  onRemove,
  onError,
}) {
  const [audio, setAudio] = useState(null),
    [loading, setLoading] = useState(null);
  useEffect(() => {
    setAudio(null);
  }, [capture.id, capture.revision]);
  useEffect(
    () => () => {
      if (audio?.url) URL.revokeObjectURL(audio.url);
    },
    [audio],
  );
  const streams = capture.summary?.media || [];
  async function play(index) {
    setLoading(index);
    try {
      const res = await fetch(
        `/api/captures/${capture.id}/audio?stream=${index}`,
      );
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error);
      }
      const blob = await res.blob();
      setAudio({
        index,
        blob,
        url: URL.createObjectURL(blob),
        name: `rtp-${streams[index].ssrc}.wav`,
      });
    } catch (e) {
      onError(e.message);
    } finally {
      setLoading(null);
    }
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
                          className="text-button"
                          disabled={
                            loading !== null ||
                            s.codecs.some((c) => !["PCMA", "PCMU"].includes(c))
                          }
                          title="试听支持 PCMA、PCMU"
                          onClick={() => play(i)}
                        >
                          <Headphones size={13} />
                          {loading === i ? "解码中…" : "试听"}
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
      {audio && (
        <div className="audio-preview">
          <Headphones size={20} />
          <div>
            <strong>RTP 音频 · {streams[audio.index]?.ssrc}</strong>
            <span>G.711 → PCM WAV · 捕获缺口填充静音</span>
          </div>
          <audio controls src={audio.url} />
          <button
            className="button secondary"
            onClick={() => downloadBlob(audio.blob, audio.name)}
          >
            <Download size={14} />
            下载 WAV
          </button>
        </div>
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
