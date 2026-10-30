import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { open, writeFile, readFile, mkdir, rm } from "node:fs/promises";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { XMLParser } from "fast-xml-parser";
import {
  mappingLua,
  mappingFor,
  staticCodec,
  streamKey,
  streamFilter,
  makeWave,
} from "./rtp.mjs";

export const tshark = process.env.TSHARK_PATH || "tshark";
const running = new Set();
let active = 0;
const queue = [];
const MAX_PROCESSES = 3;
async function acquire() {
  if (active >= MAX_PROCESSES)
    await new Promise((resolve) => queue.push(resolve));
  active++;
}
function release() {
  active--;
  queue.shift()?.();
}
export async function run(
  args,
  { capture, timeout = 120000, maxBytes = 16 * 1024 * 1024, onLine } = {},
) {
  await acquire();
  if (capture?.cancelled) {
    release();
    throw new Error("分析任务已取消");
  }
  return new Promise((resolve, reject) => {
    const proc = spawn(tshark, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, LC_ALL: "C" },
    });
    running.add(proc);
    capture?.processes?.add(proc);
    let stderr = "",
      stdout = "",
      size = 0,
      problem = null,
      done = false,
      reader;
    const timer = setTimeout(() => {
      problem = new Error("解析超时，请缩小抓包范围后重试");
      proc.kill("SIGKILL");
    }, timeout);
    timer.unref();
    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      running.delete(proc);
      capture?.processes?.delete(proc);
      release();
      err ? reject(err) : resolve(stdout);
    };
    proc.stderr.on("data", (chunk) => {
      if (stderr.length < 16000) stderr += chunk.toString();
    });
    if (onLine) {
      reader = createInterface({ input: proc.stdout, crlfDelay: Infinity });
      (async () => {
        try {
          for await (const line of reader) await onLine(line);
        } catch (e) {
          problem = e;
          proc.kill("SIGKILL");
        }
      })().then(() => {
        reader.finished = true;
      });
    } else
      proc.stdout.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          problem = new Error("结果超出响应限制，请缩小选择范围");
          proc.kill("SIGKILL");
        } else stdout += chunk.toString();
      });
    proc.on("error", (err) =>
      finish(
        new Error(
          err.code === "ENOENT"
            ? "找不到 TShark，请安装 Wireshark 命令行组件或设置 TSHARK_PATH"
            : err.message,
        ),
      ),
    );
    proc.on("close", async (code) => {
      while (reader && !reader.finished)
        await new Promise((r) => setTimeout(r, 2));
      finish(
        problem ||
          (code !== 0
            ? new Error(
                capture?.cancelled
                  ? "分析任务已取消"
                  : stderr.trim() || `TShark 退出码 ${code}`,
              )
            : null),
      );
    });
  });
}
export function stopAll() {
  for (const proc of running) proc.kill("SIGKILL");
}
let fieldTypes = new Map();
let fieldNames = [];
export let engineVersion = "";
export async function initEngine() {
  engineVersion = (await run(["--version"])).split("\n")[0];
  const fields = await run(["-G", "fields"], { maxBytes: 80 * 1024 * 1024 });
  for (const line of fields.split("\n")) {
    const cells = line.split("\t");
    if (cells[0] === "F") fieldTypes.set(cells[2], cells[3]);
  }
  fieldTypes.set("webshark.rtp.codec", "FT_STRING");
  fieldTypes.set("webshark.rtp.clock_rate", "FT_UINT32");
  fieldTypes.set("webshark.rtp.channels", "FT_UINT8");
  fieldTypes.set("webshark.rtp.payload", "FT_BYTES");
  fieldNames = [...fieldTypes.keys()];
  return engineVersion;
}
export function suggestFields(prefix) {
  return fieldNames.filter((s) => s.startsWith(prefix)).slice(0, 30);
}
const baseFields = [
  "frame.number",
  "frame.time_relative",
  "frame.time_epoch",
  "ip.src",
  "ipv6.src",
  "eth.src",
  "ip.dst",
  "ipv6.dst",
  "eth.dst",
  "_ws.col.Protocol",
  "frame.len",
  "_ws.col.Info",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.stream",
  "udp.stream",
  "_ws.expert.message",
  "tcp.analysis.retransmission",
  "tcp.analysis.fast_retransmission",
  "tcp.analysis.duplicate_ack",
  "rtp.p_type",
  "rtp.ssrc",
  "rtp.seq",
  "rtp.timestamp",
  "webshark.rtp.codec",
  "webshark.rtp.clock_rate",
  "webshark.rtp.channels",
  "tcp.flags.reset",
  "tcp.analysis.zero_window",
];
export async function prepare(capture) {
  await writeFile(
    join(capture.dir, `rtp-${capture.revision}.lua`),
    mappingLua(capture.config),
  );
}
export function argsFor(capture) {
  return [
    "-n",
    "-r",
    join(capture.dir, "capture.pcap"),
    "-X",
    `lua_script:${join(capture.dir, `rtp-${capture.revision}.lua`)}`,
    ...(capture.config.heuristic ? ["--enable-heuristic", "rtp_udp"] : []),
    ...capture.config.ports.flatMap((p) => ["-d", `udp.port==${p},rtp`]),
  ];
}
const number = (v) => (v === "" || v == null ? null : Number(v));
const unescapeField = (s) =>
  s.replace(
    /\\([tnr\\])/g,
    (_, c) => ({ t: "\t", n: "\n", r: "\r", "\\": "\\" })[c],
  );
function parsePacket(line, fields, config) {
  const cells = line.split("\t"),
    p = {};
  fields.forEach((f, i) => (p[f] = unescapeField(cells[i] || "")));
  const tcp = p["tcp.srcport"] !== "";
  const udp = p["udp.srcport"] !== "";
  const out = {
    no: Number(p["frame.number"]),
    time: Number(p["frame.time_relative"]),
    epoch: Number(p["frame.time_epoch"]),
    source: p["ip.src"] || p["ipv6.src"] || p["eth.src"],
    destination: p["ip.dst"] || p["ipv6.dst"] || p["eth.dst"],
    ipVersion: p["ipv6.src"] ? 6 : p["ip.src"] ? 4 : null,
    protocol: p["_ws.col.Protocol"] || "DATA",
    length: Number(p["frame.len"]),
    info: p["_ws.col.Info"],
    srcPort: number(p[tcp ? "tcp.srcport" : "udp.srcport"]),
    dstPort: number(p[tcp ? "tcp.dstport" : "udp.dstport"]),
    transport: tcp ? "TCP" : udp ? "UDP" : null,
    stream: number(p[tcp ? "tcp.stream" : "udp.stream"]),
    issue:
      p["tcp.analysis.retransmission"] || p["tcp.analysis.fast_retransmission"]
        ? "retransmission"
        : p["tcp.analysis.duplicate_ack"]
          ? "duplicate_ack"
          : p["tcp.flags.reset"] === "1"
            ? "reset"
            : p["tcp.analysis.zero_window"]
              ? "zero_window"
              : null,
    expert: p["_ws.expert.message"],
  };
  if (p["rtp.p_type"] !== "") {
    out.rtp = {
      pt: Number(p["rtp.p_type"]),
      ssrc: p["rtp.ssrc"],
      seq: Number(p["rtp.seq"]),
      timestamp: Number(p["rtp.timestamp"]),
    };
    const m = mappingFor(out, config) || staticCodec(out.rtp.pt);
    out.rtp.codec = m?.codec || p["webshark.rtp.codec"] || null;
    out.rtp.clockRate = m?.clockRate || number(p["webshark.rtp.clock_rate"]);
    out.rtp.channels = m?.channels || number(p["webshark.rtp.channels"]);
    out.rtp.mapping = m?.scope || (m ? "static" : null);
    out.protocol = "RTP";
    if (out.rtp.codec) out.info += ` · ${out.rtp.codec}/${out.rtp.clockRate}`;
  }
  return out;
}
function createSummary() {
  return {
    count: 0,
    bytes: 0,
    duration: 0,
    start: null,
    protocols: new Map(),
    endpoints: new Map(),
    conversations: new Map(),
    media: new Map(),
    issues: [],
    issueCount: 0,
    activity: new Map(),
    interval: 0.01,
    truncatedGroups: false,
  };
}
function incrementMap(map, key, create, update, summary) {
  let item = map.get(key);
  if (!item) {
    if (map.size >= 10000) {
      summary.truncatedGroups = true;
      return;
    }
    item = create();
    map.set(key, item);
  }
  update(item);
}
function updateSummary(s, p) {
  s.count++;
  s.bytes += p.length;
  s.duration = Math.max(s.duration, p.time);
  s.start = s.start === null ? p.epoch : Math.min(s.start, p.epoch);
  incrementMap(
    s.protocols,
    p.protocol,
    () => ({ protocol: p.protocol, count: 0, bytes: 0 }),
    (x) => {
      x.count++;
      x.bytes += p.length;
    },
    s,
  );
  for (const [address, dir] of [
    [p.source, "tx"],
    [p.destination, "rx"],
  ])
    incrementMap(
      s.endpoints,
      address,
      () => ({ address, tx: 0, rx: 0, bytes: 0, ipVersion: p.ipVersion }),
      (x) => {
        x[dir]++;
        x.bytes += p.length;
      },
      s,
    );
  if (p.transport)
    incrementMap(
      s.conversations,
      `${p.transport}:${p.stream}`,
      () => ({ ...p, count: 0, bytes: 0, id: `${p.transport}:${p.stream}` }),
      (x) => {
        x.count++;
        x.bytes += p.length;
      },
      s,
    );
  if (p.issue || p.expert) {
    s.issueCount++;
    if (s.issues.length < 2000) s.issues.push(p);
  }
  let bucket = Math.floor(p.time / s.interval);
  s.activity.set(bucket, (s.activity.get(bucket) || 0) + p.length);
  while (s.activity.size > 240) {
    s.interval *= 2;
    const next = new Map();
    for (const [k, v] of s.activity)
      next.set(Math.floor(k / 2), (next.get(Math.floor(k / 2)) || 0) + v);
    s.activity = next;
  }
  if (p.rtp)
    incrementMap(
      s.media,
      streamKey(p),
      () => ({
        key: streamKey(p),
        source: p.source,
        destination: p.destination,
        srcPort: p.srcPort,
        dstPort: p.dstPort,
        ssrc: p.rtp.ssrc,
        start: p.time,
        end: p.time,
        packets: 0,
        bytes: 0,
        pts: new Set(),
        codecs: new Set(),
        clockRate: p.rtp.clockRate,
        seqFirst: p.rtp.seq,
        seqMax: p.rtp.seq,
        seqMin: p.rtp.seq,
        unique: 0,
        duplicates: 0,
        ranges: [],
        jitter: 0,
        maxJitter: 0,
        previousTransit: null,
        previousTimestamp: p.rtp.timestamp,
        timestampExtended: p.rtp.timestamp,
        firstNo: p.no,
        stream: p.stream,
      }),
      (m) => {
        m.packets++;
        m.bytes += p.length;
        m.end = p.time;
        m.pts.add(p.rtp.pt);
        m.codecs.add(p.rtp.codec || `Dynamic PT ${p.rtp.pt}`);
        if (m.clockRate !== p.rtp.clockRate) m.clockRate = null;
        let extended = p.rtp.seq + Math.floor(m.seqMax / 65536) * 65536;
        if (extended < m.seqMax - 32768) extended += 65536;
        else if (extended > m.seqMax + 32768) extended -= 65536;
        m.seqMax = Math.max(m.seqMax, extended);
        m.seqMin = Math.min(m.seqMin, extended);
        let i = 0;
        while (i < m.ranges.length && m.ranges[i][1] < extended - 1) i++;
        if (
          m.ranges[i] &&
          m.ranges[i][0] <= extended &&
          m.ranges[i][1] >= extended
        )
          m.duplicates++;
        else {
          m.unique++;
          if (m.ranges[i] && m.ranges[i][0] <= extended + 1) {
            m.ranges[i][0] = Math.min(extended, m.ranges[i][0]);
            m.ranges[i][1] = Math.max(extended, m.ranges[i][1]);
          } else m.ranges.splice(i, 0, [extended, extended]);
          if (m.ranges[i + 1] && m.ranges[i][1] + 1 >= m.ranges[i + 1][0]) {
            m.ranges[i][1] = Math.max(m.ranges[i][1], m.ranges[i + 1][1]);
            m.ranges.splice(i + 1, 1);
          }
          if (m.ranges.length > 50000)
            throw new Error("RTP 序列范围过于分散，请先裁剪抓包");
        }
        if (m.clockRate) {
          const delta = (p.rtp.timestamp - m.previousTimestamp) | 0;
          m.timestampExtended += delta;
          m.previousTimestamp = p.rtp.timestamp;
          const transit = p.time - m.timestampExtended / m.clockRate;
          if (m.previousTransit !== null)
            m.jitter += (Math.abs(transit - m.previousTransit) - m.jitter) / 16;
          m.previousTransit = transit;
          m.maxJitter = Math.max(m.maxJitter, m.jitter);
        }
      },
      s,
    );
}
function finishSummary(s) {
  return {
    ...s,
    protocols: [...s.protocols.values()]
      .sort((a, b) => b.count - a.count)
      .map((p) => ({
        ...p,
        percentage: s.count ? (p.count / s.count) * 100 : 0,
      })),
    endpoints: [...s.endpoints.values()].sort((a, b) => b.bytes - a.bytes),
    conversations: [...s.conversations.values()],
    media: [...s.media.values()].map(
      ({
        ranges,
        previousTransit,
        previousTimestamp,
        timestampExtended,
        pts,
        codecs,
        ...m
      }) => ({
        ...m,
        pts: [...pts],
        codecs: [...codecs],
        lost: Math.max(0, m.seqMax - m.seqMin + 1 - m.unique),
        maxJitter: m.clockRate ? m.maxJitter * 1000 : null,
        jitter: m.clockRate ? m.jitter * 1000 : null,
        filter: streamFilter(m),
      }),
    ),
    activity: [...s.activity]
      .sort((a, b) => a[0] - b[0])
      .map(([i, bytes]) => ({ time: i * s.interval, bytes })),
  };
}
export async function buildIndex(capture, filter = "", progress = false) {
  if (filter.length > 4096) throw new Error("显示过滤器最长 4096 个字符");
  const hash = createHash("sha256")
    .update(`${capture.revision}:${filter}`)
    .digest("hex")
    .slice(0, 20);
  const path = join(capture.dir, `${hash}-${randomUUID()}.jsonl`);
  const offsets = [0];
  let byteOffset = 0;
  const summary = createSummary();
  const out = createWriteStream(path, { flags: "w" });
  let writeError;
  out.on("error", (e) => {
    writeError = e;
  });
  const fields = baseFields.filter(
    (f) => f.startsWith("_ws.col.") || fieldTypes.has(f),
  );
  try {
    await run(
      [
        ...argsFor(capture),
        ...(filter ? ["-Y", filter] : []),
        "-T",
        "fields",
        "-E",
        "occurrence=f",
        "-E",
        "escape=y",
        ...fields.flatMap((f) => ["-e", f]),
      ],
      {
        capture,
        timeout: Number(process.env.PARSE_TIMEOUT_MS) || 600000,
        onLine: async (line) => {
          if (!line.trim()) return;
          const p = parsePacket(line, fields, capture.config);
          if (!p.no) return;
          updateSummary(summary, p);
          const record = JSON.stringify(p) + "\n";
          if (writeError) throw writeError;
          if (!out.write(record)) await once(out, "drain");
          byteOffset += Buffer.byteLength(record);
          if (summary.count % 100 === 0) offsets.push(byteOffset);
          if (progress) capture.processed = summary.count;
        },
      },
    );
    out.end();
    await once(out, "finish");
    return {
      path,
      offsets,
      summary: finishSummary(summary),
      count: summary.count,
      bytes: byteOffset,
    };
  } catch (e) {
    out.destroy();
    await rm(path, { force: true });
    throw e;
  }
}
export async function getIndex(capture, filter = "") {
  if (!filter) return capture.index;
  if (capture.queries.has(filter)) return capture.queries.get(filter);
  // Each query is a bounded disk index, rather than all packet objects held in browser or Node memory.
  if (capture.queries.size >= 4) {
    const [key, value] = capture.queries.entries().next().value;
    capture.queries.delete(key);
    Promise.resolve(value)
      .then((i) => {
        const timer = setTimeout(
          () => rm(i.path, { force: true }).catch(() => {}),
          60000,
        );
        timer.unref();
      })
      .catch(() => {});
  }
  const snapshot = { ...capture };
  const promise = buildIndex(snapshot, filter).catch((e) => {
    if (capture.queries.get(filter) === promise) capture.queries.delete(filter);
    throw e;
  });
  capture.queries.set(filter, promise);
  return promise;
}
export async function pageFromIndex(index, page = 0) {
  page = Math.max(0, Math.floor(page));
  if (page * 100 >= index.count) return [];
  const from = index.offsets[page],
    to = index.offsets[page + 1] ?? index.bytes;
  const file = await open(index.path, "r");
  try {
    const buf = Buffer.alloc(to - from);
    await file.read(buf, 0, buf.length, from);
    return buf.toString().trim().split("\n").filter(Boolean).map(JSON.parse);
  } finally {
    await file.close();
  }
}
export function fieldExpression(name, value, raw = "") {
  if (!/^[\w.-]+$/.test(name)) return null;
  const type = fieldTypes.get(name);
  if (!type) return name.includes(".") ? null : name;
  if (type === "FT_NONE" || type === "FT_PROTOCOL") return name;
  if (type === "FT_BOOLEAN")
    return `${name} == ${/^(true|1|set)$/i.test(value) ? "1" : "0"}`;
  if (/FT_(U?INT|FLOAT|DOUBLE|RELATIVE_TIME|FRAMENUM)/.test(type)) {
    if (/^(?:-?\d+(?:\.\d+)?|0x[0-9a-f]+)$/i.test(value))
      return `${name} == ${value}`;
    return null;
  }
  if (["FT_IPv4", "FT_IPv6", "FT_ETHER", "FT_EUI64"].includes(type))
    return `${name} == ${value}`;
  if (type === "FT_BYTES" || type === "FT_UINT_BYTES") {
    const hex = raw || value.replaceAll(":", "");
    return hex && /^[a-f0-9]+$/i.test(hex)
      ? `${name} == ${hex.match(/.{2}/g).join(":")}`
      : null;
  }
  return `${name} == ${JSON.stringify(String(value))}`;
}
const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@",
  parseTagValue: false,
  parseAttributeValue: false,
  processEntities: true,
});
const list = (value) => (value ? (Array.isArray(value) ? value : [value]) : []);
export async function packetDetail(capture, no) {
  if (!Number.isInteger(no) || no < 1 || no > capture.index.count)
    throw new Error("数据包编号不存在");
  const args = [...argsFor(capture), "-Y", `frame.number == ${no}`];
  const [xml, raw] = await Promise.all([
    run([...args, "-T", "pdml"], { capture }),
    run([...args, "-T", "jsonraw", "-j", "frame"], { capture }),
  ]);
  const bytes = Array.from(
    Buffer.from(
      JSON.parse(raw)[0]?._source?.layers?.frame_raw?.[0] || "",
      "hex",
    ),
  );
  function convert(field, depth = 0, virtual = false) {
    const name = field["@name"] || "",
      value = field["@show"] ?? field["@value"] ?? "",
      label = field["@showname"] || field["@show"] || name || "字段";
    const pos = Number(field["@pos"]),
      size = Number(field["@size"]);
    const isVirtual = virtual || /reassembled|decrypted/i.test(name);
    return {
      id: name,
      name,
      value,
      label,
      filter: fieldExpression(name, value, field["@value"]),
      pos:
        !isVirtual && size > 0 && pos >= 0 && pos + size <= bytes.length
          ? pos
          : null,
      size,
      fields:
        depth < 32
          ? convertFields(
              [...list(field.field), ...list(field.proto)],
              depth + 1,
              isVirtual,
            )
          : [],
    };
  }
  function convertFields(fields, depth = 0, virtual = false) {
    if (depth > 32) return [];
    return fields
      .filter((field) => field["@hide"] !== "yes")
      .flatMap((field) =>
        field["@name"] === "fake-field-wrapper"
          ? convertFields(
              [...list(field.field), ...list(field.proto)],
              depth + 1,
              virtual,
            )
          : [convert(field, depth, virtual)],
      );
  }
  const layers = convertFields(
    list(parser.parse(xml).pdml?.packet?.proto).filter(
      (p) => p["@name"] !== "geninfo",
    ),
  );
  return { no, bytes, layers };
}
export async function followStream(capture, transport, index) {
  if (
    !["tcp", "udp"].includes(transport) ||
    !Number.isInteger(index) ||
    index < 0
  )
    throw new Error("流参数无效");
  const text = await run(
    [...argsFor(capture), "-q", "-z", `follow,${transport},raw,${index}`],
    { capture, maxBytes: 8 * 1024 * 1024 },
  );
  const client = text.match(/^Node 0: (.+)$/m)?.[1] || "",
    server = text.match(/^Node 1: (.+)$/m)?.[1] || "";
  const chunks = [];
  for (const line of text.split("\n"))
    if (/^\t?[0-9a-f]+$/i.test(line) && line.trim().length % 2 === 0)
      chunks.push({
        direction: line.startsWith("\t") ? "server" : "client",
        hex: line.trim(),
        text: Buffer.from(line.trim(), "hex").toString("utf8"),
      });
  return { client, server, number: index, transport, chunks };
}
export async function audioFor(capture, streamIndex) {
  const stream = capture.index.summary.media[streamIndex];
  if (!stream) throw new Error("RTP 媒体流不存在");
  if (stream.pts.length !== 1)
    throw new Error("该流含多个 PT，请先按 PT 导出抓包后播放");
  const mapping =
    mappingFor(
      { ...stream, rtp: { pt: stream.pts[0], ssrc: stream.ssrc } },
      capture.config,
    ) || staticCodec(stream.pts[0]);
  if (!mapping) throw new Error("请先为该流设置 PT 编解码映射");
  if (!["PCMA", "PCMU"].includes(mapping.codec))
    throw new Error(
      "当前音频播放仅支持 PCMA / PCMU；其他编码仍可映射和查看协议解析",
    );
  const frames = [];
  let size = 0;
  await run(
    [
      ...argsFor(capture),
      "-Y",
      stream.filter,
      "-T",
      "fields",
      "-E",
      "occurrence=f",
      "-e",
      "rtp.seq",
      "-e",
      "rtp.timestamp",
      "-e",
      "rtp.payload",
    ],
    {
      capture,
      onLine: (line) => {
        const [seq, timestamp, hex] = line.split("\t");
        if (hex) {
          const payload = Buffer.from(hex.replaceAll(":", ""), "hex");
          size += payload.length;
          if (size > 8000 * 600) throw new Error("音频预览最多 10 分钟");
          frames.push({
            seq: Number(seq),
            timestamp: Number(timestamp),
            payload,
          });
        }
      },
    },
  );
  return makeWave(frames, mapping);
}
export async function exportCapture(capture, filter, path) {
  await run(
    [
      ...argsFor(capture),
      ...(filter ? ["-Y", filter] : []),
      "-F",
      "pcapng",
      "-w",
      path,
    ],
    { capture, timeout: 600000 },
  );
  return path;
}
