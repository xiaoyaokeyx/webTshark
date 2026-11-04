import React, { useEffect, useState } from "react";
import { api, capturePath, downloadBlob, uploadCapture } from "./api.js";
import { Modal, Notice } from "./ui.jsx";
import { buildCapture, buildVoipCalls, composeDefaults } from "./compose.js";
import "./enhancements.css";

export function FeaturePanel({
  kind,
  captures,
  capture,
  filter,
  onClose,
  onOpen,
  onLocate,
  onRefresh,
  onTaskUpdate,
  backendReady,
}) {
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [data, setData] = useState(null);
  const [form, setForm] = useState(composeDefaults),
    [voipCallCount, setVoipCallCount] = useState(6),
    [a, setA] = useState(capture?.id || ""),
    [b, setB] = useState(
      captures.find((c) => c.id !== capture?.id && c.status === "ready")?.id ||
        "",
    );
  const [mode, setMode] = useState("call"),
    [tolerance, setTolerance] = useState(100),
    [tasks, setTasks] = useState([]);
  const [jumpMode, setJumpMode] = useState("number"),
    [target, setTarget] = useState("1");
  async function previewTask(id, page = 0) {
    const result = await api(capturePath(id, `/progress-packets?page=${page}`));
    setData({ ...result, id, page });
  }
  async function updateTask(id, action) {
    const next = await api(capturePath(id, `/${action}`), { method: "POST" });
    setTasks((items) => items.map((item) => item.id === next.id ? next : item));
    onTaskUpdate?.(next);
  }
  async function run(fn) {
    setError("");
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    if (kind === "diagnose" && capture)
      run(async () =>
        setData(
          await api(
            capturePath(
              capture.id,
              `/diagnostics?filter=${encodeURIComponent(filter)}`,
            ),
          ),
        ),
      );
    if (kind !== "tasks" || !backendReady) return;
    let stopped = false;
    const update = () =>
      api("/tasks")
        .then((d) => {
          if (!stopped) setTasks(d.tasks);
        })
        .catch((e) => {
          if (!stopped) setError(e.message);
        });
    update();
    const timer = setInterval(update, 1000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [kind, capture?.id]);
  const set = (key, value) => setForm((f) => ({ ...f, [key]: value }));
  const ready = captures.filter((c) => c.status === "ready");
  const titles = {
    compose: "报文构造器",
    tasks: "抓包任务中心",
    diagnose: "SIP / SDP / RTP / MRCP 诊断",
    compare: "两个 PCAP 对比",
    navigate: "数据包导航与搜索",
  };
  async function report(format) {
    const res = await fetch(
      `/api/captures/${capture.id}/report?filter=${encodeURIComponent(filter)}&format=${format}`,
    );
    if (!res.ok) throw new Error((await res.json()).error);
    downloadBlob(
      await res.blob(),
      `webtshark-report.${format === "html" ? "html" : "json"}`,
    );
  }
  return (
    <Modal
      title={titles[kind]}
      subtitle={
        kind === "compose"
          ? "构造离线合成数据，可下载 PCAP 或交给解析服务打开。"
          : "使用当前工作区抓包与已应用过滤器。"
      }
      onClose={onClose}
      wide={kind !== "navigate"}
      className={`feature-modal feature-modal-${kind}`}
    >
      <div className="modal-body feature-panel">
        {error && (
          <p role="alert" className="filter-error">
            {error}
          </p>
        )}
        {!backendReady && (
          <Notice>
            当前未连接解析服务。报文构造和 PCAP
            下载可直接使用，其余功能需启动完整 Node/TShark 服务。
          </Notice>
        )}
        {kind === "compose" && (
          <>
            <div className="form-grid">
              <label>
                协议
                <select
                  value={form.protocol}
                  onChange={(e) => {
                    const protocol = e.target.value;
                    setForm((f) => ({
                      ...f,
                      protocol,
                      srcPort:
                        protocol === "RTP"
                          ? 20000
                          : protocol === "RTCP"
                            ? 20001
                            : protocol === "MRCPv2"
                              ? 1544
                              : 5060,
                      dstPort:
                        protocol === "RTP"
                          ? 21000
                          : protocol === "RTCP"
                            ? 21001
                            : protocol === "MRCPv2"
                              ? 1544
                              : 5060,
                    }));
                  }}
                >
                  {["SIP", "SDP", "RTP", "RTCP", "MRCPv2"].map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
              {[
                "source",
                "destination",
                "srcPort",
                "dstPort",
                "count",
                "interval",
                ...(form.protocol === "RTP"
                  ? ["pt", "ssrc", "sequence", "clockRate"]
                  : form.protocol === "RTCP"
                    ? ["ssrc"]
                    : form.protocol === "MRCPv2"
                      ? ["method", "channelId"]
                      : ["method", "callId"]),
              ].map((key) => (
                <label
                  key={key}
                  className={
                    ["callId", "channelId"].includes(key)
                      ? "full-width-field"
                      : ""
                  }
                >
                  {
                    {
                      source: "源 IPv4",
                      destination: "目标 IPv4",
                      srcPort: "源端口",
                      dstPort: "目标端口",
                      count: "包数（1–10000）",
                      interval: "包间隔(ms)",
                      pt: "PT",
                      ssrc: "SSRC（十进制）",
                      sequence: "初始序列号",
                      clockRate: "RTP 时钟频率",
                      method: "请求方法",
                      callId: "Call-ID",
                      channelId: "Channel-Identifier",
                    }[key]
                  }
                  <input
                    value={form[key]}
                    onChange={(e) => set(key, e.target.value)}
                  />
                </label>
              ))}
            </div>
            {!["RTP", "RTCP"].includes(form.protocol) && (
              <label className="feature-body-label">
                消息正文 / SDP（留空使用合成模板）
                <textarea
                  value={form.body}
                  onChange={(e) => set("body", e.target.value)}
                  rows={7}
                />
              </label>
            )}
            <Notice>
              自动计算 IP/UDP/TCP 校验和、Content-Length、MRCP 消息长度及 RTP
              序列号。MRCP 使用带应用载荷的 TCP
              包；本功能只生成文件，不发送网络流量。
            </Notice>
            {['SIP', 'SDP'].includes(form.protocol) && (
              <div className="multi-call-builder">
                <label>
                  VoIP 通话数
                  <input
                    type="number"
                    min="2"
                    max="64"
                    value={voipCallCount}
                    onChange={(e) => setVoipCallCount(e.target.value)}
                  />
                </label>
                <span>每组使用独立 Call-ID，包含接通、忙线、振铃和取消等流程。</span>
                <button
                  className="button primary"
                  disabled={busy || !backendReady}
                  onClick={() =>
                    run(async () => {
                      const count = Number(voipCallCount);
                      const file = new File(
                        [buildVoipCalls({ callCount: count })],
                        `synthetic-${count}-voip-calls.pcap`,
                        { type: "application/vnd.tcpdump.pcap" },
                      );
                      const c = await uploadCapture(file, () => {});
                      onOpen(c);
                      onRefresh();
                      onClose();
                    })
                  }
                >
                  构造并打开 {voipCallCount} 个 VoIP 通话
                </button>
              </div>
            )}
            <div className="modal-actions">
              <button
                className="button secondary"
                disabled={busy}
                onClick={() =>
                  run(() =>
                    downloadBlob(
                      new Blob([buildCapture({ ...form, count: 1 })]),
                      "synthetic-one-packet.pcap",
                    ),
                  )
                }
              >
                构造并下载 1 个包
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  run(() =>
                    downloadBlob(
                      new Blob([buildCapture(form)]),
                      "synthetic.pcap",
                    ),
                  )
                }
              >
                下载 PCAP
              </button>
              <button
                className="button secondary"
                disabled={busy || !backendReady}
                onClick={() =>
                  run(async () => {
                    const file = new File(
                      [buildCapture(form)],
                      "synthetic.pcap",
                    );
                    const c = await uploadCapture(file, () => {});
                    onOpen(c);
                    onRefresh();
                    onClose();
                  })
                }
              >
                生成并打开
              </button>
            </div>
          </>
        )}
        {kind === "tasks" && (
          <>
            <Notice>
              并发任务由服务端限制。支持暂停/继续和取消重试；重试会重新扫描原文件，已完成抓包与索引在服务重启后恢复。
            </Notice>
            {tasks.map((c) => (
              <div className="task-item" key={c.id}>
                <strong>{c.name}</strong>
                <span>
                  {c.status} · 已处理 {c.processed || 0} 包 ·{" "}
                  {c.segments?.length || 0} 段
                </span>
                <div className="feature-actions">
                  <button
                    onClick={() => {
                      onOpen(c);
                      onClose();
                    }}
                  >
                    打开
                  </button>
                  {["queued", "paused", "indexing", "uploading"].includes(
                    c.status,
                  ) ? (
                    <button
                      onClick={() =>
                        run(() =>
                          updateTask(c.id, "cancel"),
                        )
                      }
                    >
                      取消
                    </button>
                  ) : (
                    <button
                      disabled={busy}
                      onClick={() =>
                        run(() =>
                          updateTask(c.id, "retry"),
                        )
                      }
                    >
                      重试解析
                    </button>
                  )}
                  {["queued", "indexing", "paused"].includes(c.status) && (
                    <button
                      disabled={busy}
                      onClick={() =>
                        run(() =>
                          updateTask(c.id, c.status === "paused" ? "resume" : "pause"),
                        )
                      }
                    >
                      {c.status === "paused" ? "继续" : "暂停"}
                    </button>
                  )}
                </div>
                {c.error && <p className="filter-error">{c.error}</p>}
                <details>
                  <summary>任务日志与分段</summary>
                  <pre>
                    {(c.logs || [])
                      .map((l) => `${l.time} ${l.message}`)
                      .join("\n")}
                  </pre>
                  <pre>{JSON.stringify(c.segments, null, 2)}</pre>
                </details>
              </div>
            ))}
            {!tasks.length && !error && <p>暂无任务</p>}
          </>
        )}
        {kind === "diagnose" && (
          <>
            {busy && <p>正在扫描索引并关联协议…</p>}
            {data && (
              <>
                <Notice>{data.scope}</Notice>
                <div className="feature-actions">
                  <button
                    className="button secondary"
                    onClick={() => run(() => report("html"))}
                  >
                    导出 HTML / 打印 PDF
                  </button>
                  <button
                    className="button secondary"
                    onClick={() => run(() => report("json"))}
                  >
                    导出 JSON
                  </button>
                  <button
                    className="button secondary"
                    onClick={() =>
                      run(async () => {
                        const frames = [
                          ...new Set(data.findings.flatMap((f) => f.packets)),
                        ];
                        if (!frames.length)
                          throw new Error("没有带包号的诊断证据");
                        const res = await fetch(
                          `/api/captures/${capture.id}/export?filter=${encodeURIComponent(`frame.number in {${frames.join(" ")}}`)}`,
                        );
                        if (!res.ok) throw new Error("导出失败");
                        downloadBlob(
                          await res.blob(),
                          "diagnostic-evidence.pcapng",
                        );
                      })
                    }
                  >
                    导出证据包
                  </button>
                </div>
                <p>
                  {data.calls.length} 个 SIP 呼叫 · {data.mrcp.length} 个 MRCP
                  请求 · {data.findings.length} 条发现
                </p>
                {data.findings.map((f, i) => (
                  <div className={`finding finding-${f.severity}`} key={i}>
                    <strong>{f.severity}</strong>
                    <span>{f.message}</span>
                    <div>
                      {f.packets.map((no) => (
                        <button
                          key={no}
                          onClick={() => {
                            onLocate(no);
                            onClose();
                          }}
                        >
                          #{no}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
                {!data.findings.length && (
                  <p>当前规则未发现异常；可查看原始报文进一步确认。</p>
                )}
                {data.truncated && <p>明细达到上限，请缩小过滤范围。</p>}
                <details>
                  <summary>MRCP 阶段耗时与关联包</summary>
                  <pre>{JSON.stringify(data.mrcp, null, 2)}</pre>
                </details>
              </>
            )}
          </>
        )}
        {kind === "compare" && (
          <>
            <div className="form-grid">
              {[
                ["抓包 A", a, setA],
                ["抓包 B", b, setB],
              ].map(([label, value, setValue]) => (
                <label key={label}>
                  {label}
                  <select
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                  >
                    <option value="">请选择</option>
                    {ready.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <label>
                关联依据
                <select value={mode} onChange={(e) => setMode(e.target.value)}>
                  <option value="call">Call-ID / CSeq / 响应码</option>
                  <option value="flow">五元组 / 包长度</option>
                  <option value="rtp">SSRC / 序列号 / 时间戳</option>
                </select>
              </label>
              <label>
                相对时间容差(ms)
                <input
                  type="number"
                  min="0"
                  value={tolerance}
                  onChange={(e) => setTolerance(e.target.value)}
                />
              </label>
            </div>
            <button
              className="button primary"
              disabled={busy || !a || !b}
              onClick={() =>
                run(async () =>
                  setData(
                    await api("/compare", {
                      method: "POST",
                      body: { a, b, mode, toleranceMs: Number(tolerance) },
                    }),
                  ),
                )
              }
            >
              {busy ? "对比中…" : "开始对比"}
            </button>
            {data && (
              <>
                <p>
                  匹配 {data.matched} · 仅 A {data.missing} · 仅 B {data.extra}
                </p>
                <button
                  className="button secondary"
                  onClick={() =>
                    downloadBlob(
                      new Blob([JSON.stringify(data, null, 2)], {
                        type: "application/json",
                      }),
                      "capture-diff.json",
                    )
                  }
                >
                  下载对比结果
                </button>
                <pre>{JSON.stringify(data.differences, null, 2)}</pre>
                {data.truncated && (
                  <Notice>
                    对比或显示达到保护上限，请缩小抓包范围后重试。
                  </Notice>
                )}
              </>
            )}
          </>
        )}
        {kind === "diagnose" && data && (
          <details>
            <summary>RTP 时间线、突发缺口、时钟漂移与 RTCP 关联</summary>
            {(data.rtpQuality || []).map((s) => (
              <section key={s.key}>
                <p>
                  {s.key} · 最大到达间隔 {s.maxGapMs.toFixed(2)} ms ·
                  最大观测缺口 {s.maxBurstLoss} · 漂移{" "}
                  {s.estimatedClockDriftPpm?.toFixed(1) ?? "未知"} ppm
                </p>
                <svg
                  viewBox="0 0 600 100"
                  role="img"
                  aria-label={`SSRC ${s.ssrc} 包间隔时间线`}
                >
                  <polyline
                    fill="none"
                    stroke="#3670ef"
                    strokeWidth="1.5"
                    points={s.timeline
                      .map(
                        (p, i) =>
                          `${(i / Math.max(1, s.timeline.length - 1)) * 600},${95 - Math.min(90, (p.gapMs / Math.max(1, s.maxGapMs)) * 90)}`,
                      )
                      .join(" ")}
                  />
                </svg>
                <p>RTCP 包：{s.rtcpPackets.join(", ") || "未捕获"}</p>
              </section>
            ))}
            <pre>{JSON.stringify(data.rtcp, null, 2)}</pre>
          </details>
        )}
        {kind === "tasks" && (
          <>
            <div className="feature-actions">
              {tasks
                .filter((t) => t.segments?.length)
                .map((t) => (
                  <button
                    key={t.id}
                    onClick={() => run(() => previewTask(t.id))}
                  >
                    预览已完成分段：{t.name}
                  </button>
                ))}
            </div>
            {data?.packets && (
              <>
                <p>
                  已索引 {data.total} 包 · 第 {data.page + 1} 页 · 每页 100 包
                </p>
                <div className="feature-actions">
                  <button
                    disabled={!data.page}
                    onClick={() =>
                      run(() => previewTask(data.id, data.page - 1))
                    }
                  >
                    上一页
                  </button>
                  <button
                    disabled={(data.page + 1) * 100 >= data.total}
                    onClick={() =>
                      run(() => previewTask(data.id, data.page + 1))
                    }
                  >
                    下一页
                  </button>
                </div>
                <pre>
                  {data.packets
                    .map(
                      (p) =>
                        `${p.no}\t${p.time.toFixed(6)}\t${p.source} → ${p.destination}\t${p.protocol}\t${p.info}`,
                    )
                    .join("\n")}
                </pre>
              </>
            )}
          </>
        )}
        {kind === "navigate" && (
          <>
            <label>
              跳转方式
              <select
                value={jumpMode}
                onChange={(e) => setJumpMode(e.target.value)}
              >
                <option value="number">包号</option>
                <option value="time">相对时间（秒）</option>
                <option value="search">协议字段文本搜索（下一匹配）</option>
                <option value="issue">下一个异常包</option>
              </select>
            </label>
            <input
              className="form-input"
              aria-label="跳转目标"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <button
              className="button primary"
              disabled={busy || !capture}
              onClick={() =>
                run(async () => {
                  const params = new URLSearchParams({
                    mode: jumpMode,
                    no: jumpMode === "number" ? target : "0",
                    time: target,
                    text: target,
                    filter,
                    size: "100",
                  });
                  const result = await api(
                    capturePath(capture.id, `/locate?${params}`),
                  );
                  onLocate(result.no);
                  onClose();
                })
              }
            >
              跳转
            </button>
          </>
        )}
      </div>
    </Modal>
  );
}
