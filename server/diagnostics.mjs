import { indexRecords } from "./index-storage.mjs";
export { indexRecords } from "./index-storage.mjs";
const val = (p, name) => p.fields?.[name] || "";
const bodyText = (value) =>
  /^(?:[0-9a-f]{2}:?)+$/i.test(value)
    ? Buffer.from(value.replaceAll(":", ""), "hex").toString("utf8")
    : value;
export async function diagnose(index) {
  const calls = new Map(),
    requests = new Map(),
    findings = [],
    raw = [];
  const rtpStats = new Map(),
    rtcp = [];
  let truncated = false;
  const add = (kind, severity, message, packets = []) => {
    if (findings.length < 2000)
      findings.push({ kind, severity, message, packets });
    else truncated = true;
  };
  for await (const p of indexRecords(index)) {
    const id = val(p, "sip.Call-ID");
    if (id) {
      if (raw.length < 2000)
        raw.push({
          no: p.no,
          time: p.time,
          source: p.source,
          destination: p.destination,
          info: p.info,
          body: `${val(p, "sip.msg_hdr")}\r\n${bodyText(val(p, "sip.msg_body"))}`,
          callId: id,
        });
      let call = calls.get(id);
      if (!call && calls.size < 10000)
        calls.set(
          id,
          (call = { id, packets: [], transactions: new Map(), sdp: [] }),
        );
      if (!call) {
        truncated = true;
        continue;
      }
      if (call.packets.length < 5000) call.packets.push(p.no);
      else {
        truncated = true;
        continue;
      }
      const method = val(p, "sip.CSeq.method") || val(p, "sip.Method"),
        seq = val(p, "sip.CSeq.seq"),
        status = Number(val(p, "sip.Status-Code"));
      const key = `${seq}:${method}:${val(p, "sip.Via.branch")}`;
      let tx = call.transactions.get(key);
      if (!tx)
        call.transactions.set(
          key,
          (tx = { method, seq, requests: [], responses: [] }),
        );
      if (status) tx.responses.push(p);
      else tx.requests.push(p);
      if (status >= 400)
        add(
          "sip-response",
          "warning",
          `呼叫 ${id} 收到 SIP ${status}（需结合业务判断）`,
          [p.no],
        );
      if (!val(p, "sip.from.tag"))
        add("sip-tag", "warning", `SIP 报文缺少 From tag：${id}`, [p.no]);
      const body = bodyText(val(p, "sip.msg_body"));
      if (body && /m=(audio|video)/.test(body))
        call.sdp.push({
          no: p.no,
          body: body.replace(/\\r\\n|\r\n/g, "\n"),
          source: p.source,
          status,
        });
    }
    const channel = val(p, "mrcpv2.Channel-Identifier"),
      req = val(p, "mrcpv2.reqID");
    if (channel && req) {
      const key = `${channel}:${req}`;
      let r = requests.get(key);
      if (!r && requests.size < 10000)
        requests.set(
          key,
          (r = {
            channel,
            requestId: req,
            packets: [],
            start: p.time,
            end: p.time,
            method: "",
            completed: false,
          }),
        );
      if (r) {
        if (r.packets.length < 100) r.packets.push(p.no);
        r.end = p.time;
        r.method ||= val(p, "mrcpv2.Method");
        r.completed ||= val(p, "mrcpv2.request_state") === "COMPLETE";
        if (val(p, "mrcpv2.status_code"))
          r.responseMs ??= (p.time - r.start) * 1000;
        if (val(p, "mrcpv2.Event")) r.event = val(p, "mrcpv2.Event");
        r.completionCause ||= val(p, "mrcpv2.Completion-Cause");
      }
    }
    if (p.rtp) {
      const key = `${p.source}:${p.srcPort}>${p.destination}:${p.dstPort}:${p.rtp.ssrc}`;
      let stats = rtpStats.get(key);
      if (!stats && rtpStats.size < 10000)
        rtpStats.set(
          key,
          (stats = {
            key,
            ssrc: p.rtp.ssrc,
            source: p.source,
            destination: p.destination,
            srcPort: p.srcPort,
            dstPort: p.dstPort,
            first: p.time,
            last: p.time,
            firstTimestamp: p.rtp.timestamp,
            lastTimestamp: p.rtp.timestamp,
            clockRate: p.rtp.clockRate,
            maxGapMs: 0,
            maxBurstLoss: 0,
            lossBursts: [],
            timeline: [],
            sampleStep: 1,
            anomalies: [],
            jitter: 0,
            previousTransit: null,
            count: 0,
            previousSeq: null,
          }),
        );
      if (stats) {
        const gap = (p.time - stats.last) * 1000,
          seqGap =
            stats.previousSeq == null
              ? 0
              : (p.rtp.seq - stats.previousSeq + 65536) % 65536;
        const transit = stats.clockRate
          ? p.time * stats.clockRate - Number(p.rtp.timestamp)
          : null;
        if (Number.isFinite(transit) && stats.previousTransit != null)
          stats.jitter += (Math.abs(transit - stats.previousTransit) - stats.jitter) / 16;
        if (Number.isFinite(transit)) stats.previousTransit = transit;
        const status = stats.count === 0 ? "start"
          : seqGap === 0 ? "duplicate"
          : seqGap > 32768 ? "reordered"
          : seqGap > 1 && seqGap < 3000 ? `gap:${seqGap - 1}`
          : gap > 100 ? "late" : "ok";
        const observation = {
          no: p.no, time: p.time, gapMs: gap,
          jitterMs: stats.clockRate ? stats.jitter * 1000 / stats.clockRate : null,
          sequence: p.rtp.seq, pt: p.rtp.pt, status,
        };
        if (status !== "ok" && status !== "start" && stats.anomalies.length < 2000)
          stats.anomalies.push(observation);
        stats.maxGapMs = Math.max(stats.maxGapMs, gap);
        if (seqGap > 1 && seqGap < 3000) {
          stats.maxBurstLoss = Math.max(stats.maxBurstLoss, seqGap - 1);
          if (stats.lossBursts.length < 200)
            stats.lossBursts.push({
              no: p.no,
              time: p.time,
              missing: seqGap - 1,
            });
        }
        if (stats.count % stats.sampleStep === 0) {
          stats.timeline.push(observation);
          if (stats.timeline.length > 1000) {
            stats.timeline = stats.timeline.filter((_, i) => i % 2 === 0);
            stats.sampleStep *= 2;
          }
        }
        if (stats.previousSeq == null || seqGap < 3000)
          stats.previousSeq = p.rtp.seq;
        stats.last = p.time;
        stats.lastTimestamp = p.rtp.timestamp;
        stats.count++;
      }
    }
    if (val(p, "rtcp.senderssrc") && rtcp.length < 2000)
      rtcp.push({
        no: p.no,
        source: p.source,
        destination: p.destination,
        senderSsrc: val(p, "rtcp.senderssrc"),
        reportedSsrc: val(p, "rtcp.ssrc.identifier"),
        fractionLost: val(p, "rtcp.ssrc.fraction"),
        cumulativeLost: val(p, "rtcp.ssrc.cum_nr"),
        jitterTimestampUnits: val(p, "rtcp.ssrc.jitter"),
      });
  }
  for (const c of calls.values()) {
    for (const tx of c.transactions.values()) {
      if (tx.requests.length > 1)
        add(
          "sip-retransmission",
          "info",
          `${c.id} ${tx.method} CSeq=${tx.seq} 重复请求 ${tx.requests.length} 次`,
          tx.requests.slice(0, 20).map((p) => p.no),
        );
      if (
        tx.requests.length &&
        tx.method !== "ACK" &&
        !tx.responses.some((p) => Number(val(p, "sip.Status-Code")) >= 200)
      )
        add(
          "sip-unanswered",
          "warning",
          `${c.id} ${tx.method} 在抓包窗口内未见最终响应`,
          tx.requests.slice(0, 20).map((p) => p.no),
        );
      const ok = tx.responses.find(
        (p) =>
          Number(val(p, "sip.Status-Code")) >= 200 &&
          Number(val(p, "sip.Status-Code")) < 300,
      );
      if (
        tx.method === "INVITE" &&
        ok &&
        ![...c.transactions.values()].some(
          (t) => t.method === "ACK" && t.seq === tx.seq,
        )
      )
        add(
          "sip-no-ack",
          "warning",
          `${c.id} INVITE 2xx 后在抓包窗口内未见 ACK`,
          [ok.no],
        );
    }
    const offer = c.sdp.find((s) => !s.status),
      answer = c.sdp.find((s) => s.status >= 200 && s.status < 300);
    if (offer && answer) {
      const media = (text) =>
        [...text.matchAll(/^m=(\w+)\s+(\d+)\s+\S+\s+(.+)$/gm)].map((m) => ({
          type: m[1],
          port: Number(m[2]),
          pts: m[3].trim().split(/\s+/),
        }));
      const a = media(offer.body),
        b = media(answer.body);
      for (let i = 0; i < b.length; i++)
        if (b[i].port && a[i] && !b[i].pts.some((pt) => a[i].pts.includes(pt)))
          add(
            "sdp-codec",
            "error",
            `${c.id} 媒体段 ${i + 1} offer/answer 无共同 PT`,
            [offer.no, answer.no],
          );
      for (const s of [offer, answer])
        if (/c=IN IP4 0\.0\.0\.0|a=inactive/.test(s.body))
          add("sdp-hold", "info", `${c.id} SDP 包含保持或 inactive 媒体`, [
            s.no,
          ]);
      const maps = (text) =>
        new Map(
          [...text.matchAll(/^a=rtpmap:(\d+)\s+([^\n]+)/gm)].map((m) => [
            m[1],
            m[2].trim().toLowerCase(),
          ]),
        );
      const om = maps(offer.body),
        am = maps(answer.body);
      for (const [pt, codec] of am)
        if (om.has(pt) && om.get(pt) !== codec)
          add(
            "sdp-pt",
            "error",
            `${c.id} PT ${pt} 编解码不一致：${om.get(pt)} / ${codec}`,
            [offer.no, answer.no],
          );
      for (const attr of [
        "ptime",
        "sendonly",
        "recvonly",
        "sendrecv",
        "fmtp",
      ]) {
        const attrs = (text) =>
          text
            .split("\n")
            .filter((l) => l.startsWith(`a=${attr}`))
            .join("; ");
        if (attrs(offer.body) !== attrs(answer.body))
          add(
            "sdp-difference",
            "info",
            `${c.id} SDP ${attr} 协商有差异：${attrs(offer.body) || "未声明"} → ${attrs(answer.body) || "未声明"}`,
            [offer.no, answer.no],
          );
      }
    }
  }
  const media = index.summary.media || [];
  for (const m of media) {
    if (m.lost)
      add(
        "rtp-loss",
        "warning",
        `${m.source}:${m.srcPort} → ${m.destination}:${m.dstPort} 估计丢包 ${m.lost}，乱序 ${m.reordered || 0}，重复 ${m.duplicates || 0}`,
      );
    if (m.maxJitter > 30)
      add(
        "rtp-jitter",
        "warning",
        `SSRC ${m.ssrc} 最大抖动 ${m.maxJitter.toFixed(2)} ms`,
      );
    if (
      !media.some(
        (n) =>
          n.source === m.destination &&
          n.destination === m.source &&
          n.srcPort === m.dstPort &&
          n.dstPort === m.srcPort,
      )
    )
      add(
        "rtp-one-way",
        "warning",
        `${m.source}:${m.srcPort} 的媒体流在当前抓包中未发现反向流；抓包位置/单向业务也可能导致该现象`,
      );
  }
  for (const r of requests.values()) {
    r.callIds = [...calls.values()]
      .filter((c) =>
        c.sdp.some((s) => s.body.includes(`a=channel:${r.channel}`)),
      )
      .map((c) => c.id);
    if (!r.completed)
      add(
        "mrcp-incomplete",
        "warning",
        `MRCP Channel ${r.channel} 请求 ${r.requestId} 在窗口内未见完成消息`,
        r.packets,
      );
  }
  const rtpQuality = [...rtpStats.values()].map((s) => ({
    ...s,
    estimatedClockDriftPpm:
      s.clockRate && s.last > s.first && s.lastTimestamp >= s.firstTimestamp
        ? ((s.lastTimestamp - s.firstTimestamp) /
            s.clockRate /
            (s.last - s.first) -
            1) *
          1e6
        : null,
    rtcpPackets: rtcp
      .filter(
        (r) =>
          Number(r.senderSsrc) === Number(s.ssrc) ||
          Number(r.reportedSsrc) === Number(s.ssrc),
      )
      .map((r) => r.no),
  }));
  return {
    generated: new Date().toISOString(),
    summary: index.summary,
    findings,
    rtpQuality,
    rtcp,
    calls: [...calls.values()].map((c) => ({
      id: c.id,
      packets: c.packets,
      sdp: c.sdp.slice(0, 20),
    })),
    mrcp: [...requests.values()].map((r) => ({
      ...r,
      durationMs: 1000 * (r.end - r.start),
    })),
    messages: raw,
    truncated,
    scope:
      "结论限定于当前抓包/过滤窗口；未见报文不等于对端未发送。RTP 突发缺口为到达时观测值，可能被后续乱序补齐；漂移为端点估算，抓包抖动及时间戳重启会影响结果。",
  };
}
export const escapeHtml = (x) =>
  String(x ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
export function reportHtml(report, name = "WebTshark") {
  const e = escapeHtml;
  const endpoints = [
      ...new Set(report.messages.flatMap((m) => [m.source, m.destination])),
    ].slice(0, 8),
    messages = report.messages
      .filter(
        (m) =>
          endpoints.includes(m.source) && endpoints.includes(m.destination),
      )
      .slice(0, 100);
  const x = (address) => 60 + endpoints.indexOf(address) * 160,
    width = Math.max(320, endpoints.length * 160),
    height = 80 + messages.length * 35;
  const diagram = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="SIP 时序图"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#3670ef"/></marker></defs>${endpoints.map((ep) => `<text x="${x(ep)}" y="20" text-anchor="middle">${e(ep)}</text><line x1="${x(ep)}" x2="${x(ep)}" y1="32" y2="${height}" stroke="#c6d2e3"/>`).join("")}${messages.map((m, i) => `<line x1="${x(m.source)}" x2="${x(m.destination)}" y1="${55 + i * 35}" y2="${55 + i * 35}" stroke="#3670ef" marker-end="url(#arrow)"/><text x="${(x(m.source) + x(m.destination)) / 2}" y="${50 + i * 35}" text-anchor="middle">#${m.no} ${m.time.toFixed(3)} ${e(m.info.slice(0, 55))}</text>`).join("")}</svg>`;
  const section = (title, body) => `<h2>${title}</h2>${body}`;
  return (
    `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>${e(name)} 分析报告</title><style>body{font:14px system-ui;margin:36px;color:#25364d}table{border-collapse:collapse;width:100%;margin:20px 0}th,td{border:1px solid #d9e1ea;padding:8px;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}svg{max-width:100%;font-size:10px}.warning{color:#986200}.error{color:#ae2626}@media print{button{display:none}pre,tr{break-inside:avoid}details>pre{display:block!important}}</style><button onclick="window.print()">打印 / 保存 PDF</button><h1>${e(name)} 分析报告</h1><p>${e(report.generated)} · ${e(report.scope)}</p><p>数据包 ${report.summary.count} · ${report.summary.bytes} 字节 · ${report.summary.duration.toFixed(3)} 秒</p>` +
    section(
      "诊断发现",
      `<table><tr><th>级别</th><th>发现</th><th>证据包</th></tr>${report.findings.map((f) => `<tr><td class="${e(f.severity)}">${e(f.severity)}</td><td>${e(f.message)}</td><td>${f.packets.join(", ")}</td></tr>`).join("")}</table>`,
    ) +
    section("SIP 时序图（最多 8 个端点 / 100 条消息）", diagram) +
    section(
      "SIP 原始报文",
      report.messages
        .map(
          (m) =>
            `<details><summary>#${m.no} ${m.time.toFixed(6)} ${e(m.source)} → ${e(m.destination)} ${e(m.info)}</summary><pre>${e(m.body)}</pre></details>`,
        )
        .join(""),
    ) +
    section(
      "SDP 协商",
      report.calls
        .map(
          (c) =>
            `<h3>${e(c.id)}</h3>${c.sdp.map((s) => `<p>#${s.no}</p><pre>${e(s.body)}</pre>`).join("")}`,
        )
        .join(""),
    ) +
    section(
      "RTP 质量",
      `<pre>${e(JSON.stringify(report.summary.media, null, 2))}</pre><pre>${e(JSON.stringify(report.rtpQuality, null, 2))}</pre>`,
    ) +
    section("RTCP", `<pre>${e(JSON.stringify(report.rtcp, null, 2))}</pre>`) +
    section(
      "MRCP 请求/响应",
      `<pre>${e(JSON.stringify(report.mrcp, null, 2))}</pre>`,
    ) +
    (report.truncated
      ? "<p>报告达到保护上限，部分明细未列出。可先过滤再生成。</p>"
      : "") +
    "</html>"
  );
}
export async function compareIndexes(
  a,
  b,
  { mode = "call", toleranceMs = 100 } = {},
) {
  if (!["call", "flow", "rtp"].includes(mode))
    throw new Error("mode 应为 call/flow/rtp");
  if (!Number.isFinite(Number(toleranceMs)) || Number(toleranceMs) < 0)
    throw new Error("时间容差无效");
  const map = new Map(),
    differences = [];
  let count = 0,
    matched = 0,
    missing = 0,
    extra = 0,
    truncated = false;
  const key = (p) =>
    mode === "rtp"
      ? `${p.rtp?.ssrc}:${p.rtp?.seq}:${p.rtp?.timestamp}`
      : mode === "call"
        ? `${val(p, "sip.Call-ID")}:${val(p, "sip.CSeq.seq")}:${val(p, "sip.CSeq.method")}:${val(p, "sip.Status-Code")}`
        : `${p.source}:${p.srcPort}>${p.destination}:${p.dstPort}:${p.transport}:${p.length}`;
  const eligible = (p) =>
    mode === "rtp" ? p.rtp : mode === "call" ? val(p, "sip.Call-ID") : true;
  for await (const p of indexRecords(a)) {
    if (!eligible(p)) continue;
    if (++count > 100000) {
      truncated = true;
      break;
    }
    const k = key(p);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(p);
  }
  for await (const p of indexRecords(b)) {
    if (!eligible(p)) continue;
    const list = map.get(key(p));
    const idx = list?.findIndex(
      (x) => Math.abs(x.time - p.time) * 1000 <= Number(toleranceMs),
    );
    const other = idx >= 0 ? list.splice(idx, 1)[0] : null;
    if (other) {
      matched++;
      if (
        other.info !== p.info ||
        other.length !== p.length ||
        val(other, "sip.msg_body") !== val(p, "sip.msg_body")
      ) {
        if (differences.length < 1000)
          differences.push({
            kind: "changed",
            a: other.no,
            b: p.no,
            infoA: other.info,
            infoB: p.info,
          });
      }
    } else {
      extra++;
      if (differences.length < 1000)
        differences.push({ kind: "only-b", b: p.no, infoB: p.info });
    }
  }
  for (const list of map.values())
    for (const p of list) {
      missing++;
      if (differences.length < 1000)
        differences.push({ kind: "only-a", a: p.no, infoA: p.info });
    }
  return {
    mode,
    toleranceMs,
    matched,
    missing,
    extra,
    differences,
    truncated: truncated || differences.length >= 1000,
  };
}
