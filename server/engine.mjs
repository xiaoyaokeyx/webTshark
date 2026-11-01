import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { open, writeFile, readFile, mkdir, rm } from "node:fs/promises";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { join, dirname } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { XMLParser } from "fast-xml-parser";
import {
  mappingLua,
  mappingFor,
  staticCodec,
  streamKey,
  streamFilter,
  makeWave,
  decodeG711,
} from "./rtp.mjs";

export const tshark = process.env.TSHARK_PATH || "tshark";
const running = new Set();
const DETAIL_CACHE_LIMIT = 32;
const DETAIL_CACHE_BYTES = 32 * 1024 * 1024;
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
  "ip.ttl",
  "ip.id",
  "ip.flags",
  "_ws.col.Protocol",
  "frame.len",
  "_ws.col.Info",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.stream",
  "udp.stream",
  "sip.Method",
  "tcp.seq",
  "tcp.ack",
  "tcp.flags",
  "tcp.window_size_value",
  "udp.length",
  "dns.qry.name",
  "http.host",
  "http.request.uri",
  "sip.Call-ID",
  "sip.from.tag",
  "sip.to.tag",
  "sip.Via.branch",
  "sip.msg_body",
  "sip.CSeq.method",
  "sip.CSeq.seq",
  "sip.Status-Code",
  "sip.Content-Type",
  "_ws.expert.message",
  "tcp.analysis.retransmission",
  "tcp.analysis.fast_retransmission",
  "tcp.analysis.duplicate_ack",
  "rtp.p_type",
  "rtp.ssrc",
  "rtp.seq",
  "rtp.timestamp",
  "mrcpv2.Channel-Identifier",
  "mrcpv2.Method",
  "mrcpv2.Event",
  "mrcpv2.reqID",
  "mrcpv2.Completion-Cause",
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
export function argsFor(capture, extraDecodeAs = []) {
  const args = [
    "-n",
    "-r",
    join(capture.dir, "capture.pcap"),
    "-X",
    `lua_script:${join(capture.dir, `rtp-${capture.revision}.lua`)}`,
    ...(capture.config.heuristic ? ["--enable-heuristic", "rtp_udp"] : []),
    ...capture.config.ports.flatMap((p) => ["-d", `udp.port==${p},rtp`]),
    ...(capture.config.decodeAs || []).flatMap(({ transport, port, protocol }) => [
      "-d",
      `${transport}.port==${port},${protocol}`,
    ]),
  ];
  const existing = new Set(
    (capture.config.decodeAs || []).map(
      ({ transport, port, protocol }) => `${transport}:${port}:${protocol}`,
    ),
  );
  for (const { transport, port, protocol } of extraDecodeAs) {
    const key = `${transport}:${port}:${protocol}`;
    if (existing.has(key)) continue;
    args.push("-d", `${transport}.port==${port},${protocol}`);
    existing.add(key);
  }
  return args;
}

const sipMrcpFilterPattern =
  /^\s*sip_mrcp\.(?:port|media_port|rtp_port)\s*(?:=|==|eq)\s*(\d+)\s*$/i;
const relationFields = [
  "frame.number",
  "frame.time_relative",
  "frame.time_epoch",
  "ip.src",
  "ipv6.src",
  "ip.dst",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.stream",
  "udp.stream",
  "sip.Method",
  "sip.CSeq.method",
  "sip.Call-ID",
  "sip.from.tag",
  "sip.to.tag",
  "sip.Status-Code",
  "sip.msg_body",
  "sdp.media",
  "sdp.media.port",
  "sdp.media.proto",
  "sdp.connection_info.address",
  "sdp.media_attribute.value",
  "sdp.session_attr.value",
  "mrcpv2.Channel-Identifier",
  "mrcpv2.Method",
  "mrcpv2.Event",
  "mrcpv2.reqID",
  "mrcpv2.Completion-Cause",
];

export function parseSipMrcpFilter(expression = "") {
  const match = String(expression).match(sipMrcpFilterPattern);
  if (!match) return null;
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("sip_mrcp 端口必须在 1–65535 之间");
  return { port };
}

const sipMrcpMacroPattern =
  /sip_mrcp\.(?:port|media_port|rtp_port)\s*(?:=|==|eq)\s*\d+/gi;

function splitFieldValues(value) {
  return String(value || "")
    .split("|")
    .map((item) => item.trim())
    .filter(Boolean);
}

function decodeHexField(value) {
  const text = String(value || "").replace(/:/g, "").trim();
  if (!text || !/^[0-9a-f]+$/i.test(text) || text.length % 2) return "";
  try {
    return Buffer.from(text, "hex").toString("utf8");
  } catch {
    return "";
  }
}

export function parseSdpBody(value) {
  const body = decodeHexField(value);
  if (!body || !/\bm=/.test(body)) return null;
  const lines = body.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  let sessionConnection = null;
  let current = null;
  const media = [];
  for (const line of lines) {
    if (line.startsWith("c=")) {
      const address = line.match(/^c=IN\s+IP[46]\s+([^/\s]+)/i)?.[1];
      if (address) {
        if (current) current.connection = address;
        else sessionConnection = address;
      }
      continue;
    }
    if (line.startsWith("m=")) {
      const match = line.match(/^m=([^\s]+)\s+(\d+)(?:\/\d+)?\s+([^\s]+)(?:\s+(.*))?$/i);
      if (!match) {
        current = null;
        continue;
      }
      current = {
        type: match[1].toLowerCase(),
        port: Number(match[2]),
        proto: match[3],
        formats: match[4] ? match[4].split(/\s+/) : [],
        connection: sessionConnection,
        attributes: [],
      };
      media.push(current);
      continue;
    }
    if (line.startsWith("a=") && current) current.attributes.push(line.slice(2));
  }
  return { media, sessionConnection };
}

function mediaAttributes(media) {
  const result = new Map();
  for (const attribute of media?.attributes || []) {
    const index = attribute.indexOf(":");
    const name = (index < 0 ? attribute : attribute.slice(0, index)).toLowerCase();
    const value = index < 0 ? "" : attribute.slice(index + 1).trim();
    const values = result.get(name) || [];
    values.push(value);
    result.set(name, values);
  }
  return result;
}

function unique(values) {
  return [...new Set(values.filter((value) => value !== "" && value != null))];
}

function uniqueDecodeAs(rules = []) {
  return [
    ...new Map(
      rules
        .filter(
          (rule) =>
            rule &&
            ["tcp", "udp"].includes(String(rule.transport).toLowerCase()) &&
            Number.isInteger(Number(rule.port)) &&
            rule.protocol,
        )
        .map((rule) => [
          `${String(rule.transport).toLowerCase()}:${Number(rule.port)}:${rule.protocol}`,
          {
            transport: String(rule.transport).toLowerCase(),
            port: Number(rule.port),
            protocol: String(rule.protocol),
          },
        ]),
    ).values(),
  ];
}

function displayString(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function relationTimeFilter(start, end) {
  const from = Math.max(0, Number(start) - 1);
  const to = Number(end) + 2;
  return `frame.time_relative >= ${from.toFixed(6)} && frame.time_relative <= ${to.toFixed(6)}`;
}

async function scanRelationFields(
  capture,
  filter,
  fields = relationFields,
  extraDecodeAs = [],
) {
  const selectedFields = fields.filter(
    (field) => field.startsWith("_ws.col.") || fieldTypes.has(field),
  );
  const args = [...argsFor(capture)];
  const existingDecodeAs = new Set(
    (capture.config.decodeAs || []).map(
      ({ transport, port, protocol }) => `${transport}:${port}:${protocol}`,
    ),
  );
  for (const { transport, port, protocol } of extraDecodeAs) {
    const key = `${transport}:${port}:${protocol}`;
    if (existingDecodeAs.has(key)) continue;
    args.push("-d", `${transport}.port==${port},${protocol}`);
    existingDecodeAs.add(key);
  }
  args.push(
    "-T",
    "fields",
    "-E",
    "separator=\t",
    "-E",
    "quote=n",
    "-E",
    "occurrence=a",
    "-E",
    "aggregator=|",
    "-E",
    "escape=y",
    ...selectedFields.flatMap((field) => ["-e", field]),
  );
  if (filter) args.splice(argsFor(capture).length, 0, "-Y", filter);
  const rows = [];
  await run(args, {
    capture,
    timeout: Number(process.env.PARSE_TIMEOUT_MS) || 600000,
    onLine: async (line) => {
      if (!line.trim()) return;
      const cells = line.split("\t");
      const row = {};
      selectedFields.forEach((field, index) => {
        row[field] = cells[index] || "";
      });
      row.no = Number(row["frame.number"]);
      row.time = Number(row["frame.time_relative"]);
      row.epoch = Number(row["frame.time_epoch"]);
      row.source = row["ip.src"] || row["ipv6.src"] || "";
      row.destination = row["ip.dst"] || row["ipv6.dst"] || "";
      row.callId = row["sip.Call-ID"] || "";
      row.fromTag = row["sip.from.tag"] || "";
      row.toTag = row["sip.to.tag"] || "";
      row.transport = row["tcp.srcport"] !== "" ? "TCP" : row["udp.srcport"] !== "" ? "UDP" : "";
      row.stream = Number(
        row.transport === "TCP" ? row["tcp.stream"] : row["udp.stream"],
      );
      rows.push(row);
    },
  });
  return rows.filter((row) => Number.isInteger(row.no) && row.no > 0);
}

function mediaFromSipRows(rows) {
  const result = [];
  for (const row of rows) {
    const body = parseSdpBody(row["sip.msg_body"]);
    if (!body) continue;
    for (const media of body.media) {
      const attributes = mediaAttributes(media);
      result.push({
        ...media,
        attributes,
        frame: row.no,
        time: row.time,
        source: row.source,
        destination: row.destination,
      });
    }
  }
  return result;
}

function mediaChannelIds(media) {
  return unique(
    media
      .flatMap((item) => item.attributes.get("channel") || [])
      .filter(Boolean),
  );
}

function mediaResource(media) {
  return unique(
    media.flatMap((item) => item.attributes.get("resource") || []),
  );
}

function mediaPortSet(media, predicate) {
  return new Set(
    media.filter((item) => item.port > 0 && predicate(item)).map((item) => item.port),
  );
}

function mediaEndpointPairs(media) {
  return media
    .map((item) => {
      const addresses = [item.source, item.destination, item.connection].filter(Boolean);
      return addresses.length > 1 ? addresses : null;
    })
    .filter(Boolean);
}

function rowMatchesMediaEndpoints(row, pairs) {
  if (!pairs.length || !row.source || !row.destination) return true;
  const addresses = new Set(pairs.flat());
  return addresses.has(row.source) && addresses.has(row.destination);
}

function rowMrcpChannel(row) {
  return String(
    row["mrcpv2.Channel-Identifier"] ||
      row["mrcpv2.channel_identifier"] ||
      row["mrcpv2.channel-id"] ||
      "",
  );
}

function buildPortExpression(protocol, ports) {
  return [...ports]
    .sort((a, b) => a - b)
    .map((port) => `${protocol}.port == ${port}`)
    .join(" || ");
}

function joinRelationFilters(matches) {
  const terms = unique(
    matches.flatMap((match) => match.expandedFilter.split(" || ")),
  );
  return terms.map((term) => `(${term})`).join(" || ");
}

function storedRelationRow(record) {
  const fields = record.fields || {};
  return {
    ...record,
    ...fields,
    callId: fields["sip.Call-ID"] || "",
    fromTag: fields["sip.from.tag"] || "",
    toTag: fields["sip.to.tag"] || "",
    source: record.source || fields["ip.src"] || fields["ipv6.src"] || "",
    destination:
      record.destination || fields["ip.dst"] || fields["ipv6.dst"] || "",
    transport: record.transport || "",
    stream: record.stream,
  };
}

async function scanStoredIndex(capture, predicate, project = (row) => row) {
  if (
    !capture.index?.path ||
    !capture.index.fields?.includes("sip.msg_body")
  )
    return null;
  const rows = [];
  const input = createReadStream(capture.index.path, { encoding: "utf8" });
  const reader = createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of reader) {
      if (!line.trim()) continue;
      let record;
      try {
        record = storedRelationRow(JSON.parse(line));
      } catch {
        continue;
      }
      if (predicate(record)) {
        const value = project(record);
        if (value != null) rows.push(value);
      }
    }
  } finally {
    input.destroy();
  }
  return rows;
}

function relationMatchFromRows({
  callId,
  sipRows,
  allRows,
  inputPort,
  allCallIds,
}) {
  const media = mediaFromSipRows(sipRows);
  const audioMedia = media.filter((item) => item.type === "audio" && item.port > 0);
  const mrcpMedia = media.filter(
    (item) => item.type === "application" && /MRCPv2/i.test(item.proto),
  );
  const mrcpChannels = mediaChannelIds(mrcpMedia);
  const resources = mediaResource(mrcpMedia);
  const mrcpPairs = mediaEndpointPairs(mrcpMedia);
  const rtpPairs = mediaEndpointPairs(audioMedia);
  const audioPorts = mediaPortSet(audioMedia, () => true);
  const rtcpPorts = new Set();
  for (const item of audioMedia) {
    for (const value of item.attributes.get("rtcp") || []) {
      const rtcpPort = Number(value.match(/^\s*(\d+)/)?.[1]);
      if (rtcpPort > 0) rtcpPorts.add(rtcpPort);
    }
    if ([...(item.attributes.get("rtcp-mux") || [])].length) rtcpPorts.add(item.port);
  }
  const mrcpPorts = mediaPortSet(mrcpMedia, () => true);
  const selectedRows = sipRows.length ? sipRows : [];
  const times = selectedRows.map((row) => row.time).filter(Number.isFinite);
  const start = times.length ? Math.min(...times) : 0;
  const end = times.length ? Math.max(...times) : start;
  const from = Math.max(0, start - 1);
  const to = end + 2;
  const mrcpCandidates = allRows.filter(
    (row) =>
      row.transport === "TCP" &&
      Number.isFinite(row.time) &&
      row.time >= from &&
      row.time <= to &&
      rowMatchesMediaEndpoints(row, mrcpPairs) &&
      [...mrcpPorts].some((port) => row.srcPort === port || row.dstPort === port),
  );
  const channelStreams = unique(
    mrcpCandidates
      .filter((row) => mrcpChannels.some((channel) => rowMrcpChannel(row).includes(channel)))
      .map((row) => row.stream),
  ).filter((stream) => Number.isInteger(stream));
  const mrcpRows = channelStreams.length
    ? mrcpCandidates.filter((row) => channelStreams.includes(row.stream))
    : mrcpCandidates;
  const rtpPorts = new Set([...audioPorts, ...rtcpPorts]);
  const rtpRows = allRows.filter(
    (row) =>
      row.transport === "UDP" &&
      Number.isFinite(row.time) &&
      row.time >= from &&
      row.time <= to &&
      rowMatchesMediaEndpoints(row, rtpPairs) &&
      [...rtpPorts].some((port) => row.srcPort === port || row.dstPort === port),
  );
  const mrcpStreams = unique(mrcpRows.map((row) => row.stream)).sort((a, b) => a - b);
  const rtpStreams = unique(rtpRows.map((row) => row.stream)).sort((a, b) => a - b);
  const sipFrames = unique(sipRows.map((row) => row.no)).sort((a, b) => a - b);
  const terms = [`sip.Call-ID == "${displayString(callId)}"`];
  for (const stream of mrcpStreams) terms.push(`tcp.stream == ${stream}`);
  for (const stream of rtpStreams) terms.push(`udp.stream == ${stream}`);
  for (const mediaPort of [...mrcpPorts].sort((a, b) => a - b))
    if (!mrcpStreams.length) terms.push(`tcp.port == ${mediaPort}`);
  for (const mediaPort of [...rtpPorts].sort((a, b) => a - b))
    if (!rtpStreams.length) terms.push(`udp.port == ${mediaPort}`);
  return {
    callId,
    fromTags: unique(sipRows.map((row) => row.fromTag)),
    toTags: unique(sipRows.map((row) => row.toTag)),
    channelIds: mrcpChannels,
    resources,
    sipFrames,
    mrcpStreams,
    rtpStreams,
    mrcpPorts: [...mrcpPorts].sort((a, b) => a - b),
    rtpPorts: [...rtpPorts].sort((a, b) => a - b),
    mrcpPackets: mrcpRows.length,
    rtpPackets: rtpRows.length,
    start,
    end,
    inputPort,
    allCallIds,
    expandedFilter: terms.join(" || "),
  };
}

async function resolveSipMrcpPortFromIndex(capture, port) {
  const sipRows = await scanStoredIndex(
    capture,
    (row) => row.callId || row["sip.Method"] || row["sip.msg_body"],
  );
  if (!sipRows) return null;
  const invites = sipRows.filter((row) => {
    if (String(row["sip.Method"] || "").toUpperCase() !== "INVITE") return false;
    const media = parseSdpBody(row["sip.msg_body"]);
    return media?.media.some(
      (item) => item.type === "audio" && item.port === port,
    );
  });
  const callIds = unique(invites.map((row) => row.callId));
  if (!callIds.length)
    throw new Error(`没有找到 SDP 音频端口为 ${port} 的 SIP INVITE`);
  const specs = callIds.map((callId) => {
    const rows = sipRows.filter((row) => row.callId === callId);
    const media = mediaFromSipRows(rows);
    const audioMedia = media.filter((item) => item.type === "audio" && item.port > 0);
    const mrcpMedia = media.filter(
      (item) => item.type === "application" && /MRCPv2/i.test(item.proto),
    );
    const audioPorts = mediaPortSet(audioMedia, () => true);
    const rtcpPorts = new Set();
    for (const item of audioMedia) {
      for (const value of item.attributes.get("rtcp") || []) {
        const rtcpPort = Number(value.match(/^\s*(\d+)/)?.[1]);
        if (rtcpPort > 0) rtcpPorts.add(rtcpPort);
      }
      if ([...(item.attributes.get("rtcp-mux") || [])].length) rtcpPorts.add(item.port);
    }
    const times = rows.map((row) => row.time).filter(Number.isFinite);
    return {
      callId,
      rows,
      mrcpPorts: mediaPortSet(mrcpMedia, () => true),
      rtpPorts: new Set([...audioPorts, ...rtcpPorts]),
      start: times.length ? Math.min(...times) : 0,
      end: times.length ? Math.max(...times) : 0,
    };
  });
  const allMrcpPorts = new Set(specs.flatMap((spec) => [...spec.mrcpPorts]));
  const allRtpPorts = new Set(specs.flatMap((spec) => [...spec.rtpPorts]));
  const from = Math.max(0, Math.min(...specs.map((spec) => spec.start)) - 1);
  const to = Math.max(...specs.map((spec) => spec.end)) + 2;
  const allRows = await scanStoredIndex(
    capture,
    (row) =>
      Number.isFinite(row.time) &&
      row.time >= from &&
      row.time <= to &&
      ((row.transport === "TCP" &&
        [...allMrcpPorts].some((mediaPort) => row.srcPort === mediaPort || row.dstPort === mediaPort)) ||
        (row.transport === "UDP" &&
          [...allRtpPorts].some((mediaPort) => row.srcPort === mediaPort || row.dstPort === mediaPort))),
    (row) => ({
      time: row.time,
      transport: row.transport,
      stream: row.stream,
      srcPort: row.srcPort,
      dstPort: row.dstPort,
    }),
  );
  const matches = specs.map((spec) =>
    relationMatchFromRows({
      callId: spec.callId,
      sipRows: spec.rows,
      allRows,
      inputPort: port,
      allCallIds: callIds,
    }),
  );
  const expandedFilter = joinRelationFilters(matches);
  return {
    type: "sip_mrcp",
    port,
    matches,
    decodeAs: [
      ...new Map(
        matches
          .flatMap((match) => [
            ...match.mrcpPorts.map((mediaPort) => ({
              transport: "tcp",
              port: mediaPort,
              protocol: "mrcpv2",
            })),
            ...match.rtpPorts.map((mediaPort) => ({
              transport: "udp",
              port: mediaPort,
              protocol: "rtp",
            })),
          ])
          .map((rule) => [`${rule.transport}:${rule.port}:${rule.protocol}`, rule]),
      ).values(),
    ],
    expandedFilter,
    ambiguous: matches.length > 1,
    warning:
      matches.length > 1
        ? `端口 ${port} 匹配到 ${matches.length} 个 SIP Call-ID，已合并显示`
        : null,
  };
}

async function resolveSipMrcpPort(capture, port) {
  const stored = await resolveSipMrcpPortFromIndex(capture, port);
  if (stored) return stored;
  const candidateFilter =
    `sip.Method == "INVITE" && sdp.media.media == "audio" && sdp.media.port == ${port}`;
  const invites = await scanRelationFields(capture, candidateFilter);
  const callIds = unique(invites.map((row) => row.callId));
  if (!callIds.length)
    throw new Error(`没有找到 SDP 音频端口为 ${port} 的 SIP INVITE`);

  const matches = [];
  for (const callId of callIds) {
    const sipRows = await scanRelationFields(
      capture,
      `sip.Call-ID == "${displayString(callId)}"`,
    );
    const media = mediaFromSipRows(sipRows);
    const audioMedia = media.filter((item) => item.type === "audio" && item.port > 0);
    const mrcpMedia = media.filter(
      (item) => item.type === "application" && /MRCPv2/i.test(item.proto),
    );
    const mrcpChannels = mediaChannelIds(mrcpMedia);
    const resources = mediaResource(mrcpMedia);
    const mrcpPairs = mediaEndpointPairs(mrcpMedia);
    const rtpPairs = mediaEndpointPairs(audioMedia);
    const audioPorts = mediaPortSet(audioMedia, () => true);
    const rtcpPorts = new Set();
    for (const item of audioMedia) {
      for (const value of item.attributes.get("rtcp") || []) {
        const rtcpPort = Number(value.match(/^\s*(\d+)/)?.[1]);
        if (rtcpPort > 0) rtcpPorts.add(rtcpPort);
      }
      if ([...(item.attributes.get("rtcp-mux") || [])].length) rtcpPorts.add(item.port);
    }
    const mrcpPorts = mediaPortSet(mrcpMedia, () => true);
    const selectedRows = sipRows.length ? sipRows : invites.filter((row) => row.callId === callId);
    const start = Math.min(...selectedRows.map((row) => row.time).filter(Number.isFinite));
    const end = Math.max(...selectedRows.map((row) => row.time).filter(Number.isFinite));
    const timeFilter = relationTimeFilter(start, end);
    const mrcpStreams = new Set();
    let mrcpRows = [];
    if (mrcpPorts.size) {
      const mrcpFilter = `(${buildPortExpression("tcp", mrcpPorts)}) && ${timeFilter}`;
      mrcpRows = await scanRelationFields(
        capture,
        mrcpFilter,
        relationFields,
        [...mrcpPorts].map((mrcpPort) => ({
          transport: "tcp",
          port: mrcpPort,
          protocol: "mrcpv2",
        })),
      );
      mrcpRows = mrcpRows.filter((row) => rowMatchesMediaEndpoints(row, mrcpPairs));
      const channelStreams = unique(
        mrcpRows
          .filter((row) => mrcpChannels.some((channel) => rowMrcpChannel(row).includes(channel)))
          .map((row) => row.stream),
      ).filter((stream) => Number.isInteger(stream));
      if (channelStreams.length)
        mrcpRows = mrcpRows.filter((row) => channelStreams.includes(row.stream));
      for (const row of mrcpRows) if (Number.isInteger(row.stream)) mrcpStreams.add(row.stream);
    }
    const rtpPorts = new Set([...audioPorts, ...rtcpPorts]);
    const rtpStreams = new Set();
    let rtpRows = [];
    if (rtpPorts.size) {
      const rtpFilter = `(${buildPortExpression("udp", rtpPorts)}) && ${timeFilter}`;
      rtpRows = await scanRelationFields(
        capture,
        rtpFilter,
        relationFields,
        [...audioPorts].map((rtpPort) => ({
          transport: "udp",
          port: rtpPort,
          protocol: "rtp",
        })),
      );
      rtpRows = rtpRows.filter((row) => rowMatchesMediaEndpoints(row, rtpPairs));
      for (const row of rtpRows) if (Number.isInteger(row.stream)) rtpStreams.add(row.stream);
    }
    const sipFrames = unique(sipRows.map((row) => row.no)).sort((a, b) => a - b);
    const terms = [`sip.Call-ID == "${displayString(callId)}"`];
    for (const stream of [...mrcpStreams].sort((a, b) => a - b)) terms.push(`tcp.stream == ${stream}`);
    for (const stream of [...rtpStreams].sort((a, b) => a - b)) terms.push(`udp.stream == ${stream}`);
    for (const mediaPort of [...mrcpPorts].sort((a, b) => a - b))
      if (!mrcpStreams.size) terms.push(`tcp.port == ${mediaPort}`);
    for (const mediaPort of [...rtpPorts].sort((a, b) => a - b))
      if (!rtpStreams.size) terms.push(`udp.port == ${mediaPort}`);
    matches.push({
      callId,
      fromTags: unique(sipRows.map((row) => row.fromTag)),
      toTags: unique(sipRows.map((row) => row.toTag)),
      channelIds: mrcpChannels,
      resources,
      sipFrames,
      mrcpStreams: [...mrcpStreams].sort((a, b) => a - b),
      rtpStreams: [...rtpStreams].sort((a, b) => a - b),
      mrcpPorts: [...mrcpPorts].sort((a, b) => a - b),
      rtpPorts: [...rtpPorts].sort((a, b) => a - b),
      mrcpPackets: mrcpRows.length,
      rtpPackets: rtpRows.length,
      start,
      end,
      expandedFilter: terms.join(" || "),
    });
  }
  const expandedFilter = joinRelationFilters(matches);
  if (!expandedFilter) throw new Error(`端口 ${port} 找到了 SIP，但没有可关联的 MRCP/RTP 流`);
  return {
    type: "sip_mrcp",
    port,
    matches,
    decodeAs: [
      ...new Map(
        matches
          .flatMap((match) => [
            ...match.mrcpPorts.map((mediaPort) => ({
              transport: "tcp",
              port: mediaPort,
              protocol: "mrcpv2",
            })),
            ...match.rtpPorts.map((mediaPort) => ({
              transport: "udp",
              port: mediaPort,
              protocol: "rtp",
            })),
          ])
          .map((rule) => [`${rule.transport}:${rule.port}:${rule.protocol}`, rule]),
      ).values(),
    ],
    expandedFilter,
    ambiguous: matches.length > 1,
    warning:
      matches.length > 1
        ? `端口 ${port} 匹配到 ${matches.length} 个 SIP Call-ID，已合并显示`
        : null,
  };
}

export async function resolveFilter(capture, filter = "", requestedFields = []) {
  return resolveFilterWithFields(capture, filter, requestedFields);
}

async function resolveFilterWithFields(capture, filter = "", requestedFields = []) {
  const macros = [...String(filter).matchAll(sipMrcpMacroPattern)].map((match) => {
    const expression = match[0];
    return { expression, macro: parseSipMrcpFilter(expression) };
  });
  if (!macros.length)
    return {
      index: await getIndex(capture, filter, [], requestedFields),
      relation: null,
    };
  capture.relationQueries ||= new Map();
  const relations = [];
  for (const { macro } of macros) {
    const key = `port:${macro.port}`;
    let relation = capture.relationQueries.get(key);
    if (!relation) {
      relation = resolveSipMrcpPort(capture, macro.port).catch((error) => {
        capture.relationQueries.delete(key);
        throw error;
      });
      capture.relationQueries.set(key, relation);
    }
    relations.push(await relation);
  }
  const byExpression = new Map(
    macros.map(({ expression }, index) => [expression.toLowerCase(), relations[index]]),
  );
  const expandedFilter = String(filter).replace(
    sipMrcpMacroPattern,
    (expression) => `(${byExpression.get(expression.toLowerCase()).expandedFilter})`,
  );
  const mergedRelation =
    relations.length === 1
      ? { ...relations[0], expandedFilter }
      : {
          type: "sip_mrcp",
          ports: unique(relations.map((item) => item.port)),
          matches: relations.flatMap((item) => item.matches || []),
          decodeAs: uniqueDecodeAs(relations.flatMap((item) => item.decodeAs || [])),
          expandedFilter,
          ambiguous: relations.some((item) => item.ambiguous),
          warning: relations.map((item) => item.warning).filter(Boolean).join("；") || null,
        };
  const decodeAs = uniqueDecodeAs(relations.flatMap((item) => item.decodeAs || []));
  return {
    index: await getIndex(capture, expandedFilter, decodeAs, requestedFields),
    relation: mergedRelation,
  };
}
function argsForSource(capture, source) {
  const args = [...argsFor(capture)],
    readIndex = args.indexOf("-r");
  if (readIndex >= 0) args[readIndex + 1] = source;
  return args;
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
    fields: Object.fromEntries(
      Object.entries(p).filter(([, value]) => value !== "" && value != null),
    ),
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
export async function buildIndex(
  capture,
  filter = "",
  progress = false,
  extraDecodeAs = [],
  requestedFields = [],
) {
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
  const fields = [...new Set([...baseFields, ...requestedFields])].filter(
    (f) => f.startsWith("_ws.col.") || fieldTypes.has(f),
  );
  try {
    await run(
      [
        ...argsFor(capture, extraDecodeAs),
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
      fields,
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
export async function getIndex(
  capture,
  filter = "",
  extraDecodeAs = [],
  requestedFields = [],
) {
  const macro = parseSipMrcpFilter(filter);
  if (macro) {
    const resolved = await resolveFilter(capture, filter, requestedFields);
    return resolved.index;
  }
  if (
    !filter &&
    requestedFields.every((field) => capture.index?.fields?.includes(field))
  )
    return capture.index;
  const fieldKey = requestedFields.length
    ? `\nfields:${[...new Set(requestedFields)].sort().join(",")}`
    : "";
  const queryKey = extraDecodeAs.length
    ? `${filter}\n${extraDecodeAs
        .map(({ transport, port, protocol }) => `${transport}:${port}:${protocol}`)
        .sort()
        .join(",")}${fieldKey}`
    : `${filter}${fieldKey}`;
  if (capture.queries.has(queryKey)) return capture.queries.get(queryKey);
  // Each query is a bounded disk index, rather than all packet objects held in browser or Node memory.
  if (capture.queries.size >= 4) {
    const [key, value] = capture.queries.entries().next().value;
    capture.queries.delete(key);
    Promise.resolve(value)
      .then((i) => {
        const timer = setTimeout(
          () => {
            rm(i.path, { force: true }).catch(() => {});
            for (const sorted of i.sorted?.values?.() || [])
              Promise.resolve(sorted)
                .then((item) => rm(item.path, { force: true }))
                .catch(() => {});
          },
          60000,
        );
        timer.unref();
      })
      .catch(() => {});
  }
  const snapshot = { ...capture };
  const promise = buildIndex(snapshot, filter, false, extraDecodeAs, requestedFields).catch((e) => {
    if (capture.queries.get(queryKey) === promise) capture.queries.delete(queryKey);
    throw e;
  });
  capture.queries.set(queryKey, promise);
  return promise;
}
function sortFieldValue(record, field) {
  if (field === "frame.number") return record.no;
  if (field === "frame.time_relative") return record.time;
  if (field === "frame.time_epoch") return record.epoch;
  if (field === "ip.src") return record.source;
  if (field === "ip.dst") return record.destination;
  if (field === "_ws.col.Protocol") return record.protocol;
  if (field === "frame.len") return record.length;
  if (field === "_ws.col.Info") return record.info;
  if (field === "tcp.srcport") return record.transport === "TCP" ? record.srcPort : null;
  if (field === "tcp.dstport") return record.transport === "TCP" ? record.dstPort : null;
  if (field === "udp.srcport") return record.transport === "UDP" ? record.srcPort : null;
  if (field === "udp.dstport") return record.transport === "UDP" ? record.dstPort : null;
  if (field === "tcp.stream") return record.transport === "TCP" ? record.stream : null;
  if (field === "udp.stream") return record.transport === "UDP" ? record.stream : null;
  if (field === "rtp.p_type") return record.rtp?.pt ?? null;
  if (field === "rtp.ssrc") return record.rtp?.ssrc ?? null;
  if (field === "rtp.seq") return record.rtp?.seq ?? null;
  if (field === "rtp.timestamp") return record.rtp?.timestamp ?? null;
  return record.fields?.[field] ?? null;
}

function compareSortEntries(left, right, direction) {
  const a = left.value,
    b = right.value,
    aEmpty = a == null || a === "",
    bEmpty = b == null || b === "";
  if (aEmpty !== bEmpty) return aEmpty ? 1 : -1;
  if (aEmpty) return left.record.no - right.record.no;
  const aNumber = Number(a),
    bNumber = Number(b);
  let result;
  if (Number.isFinite(aNumber) && Number.isFinite(bNumber)) result = aNumber - bNumber;
  else
    result = String(a).localeCompare(String(b), "zh-CN", {
      numeric: true,
      sensitivity: "base",
    });
  return result === 0
    ? left.record.no - right.record.no
    : (direction === "desc" ? -1 : 1) * result;
}

async function buildSortedIndex(index, field, direction) {
  const chunkSize = 20000;
  const chunks = [];
  let chunk = [];
  const input = createReadStream(index.path, { encoding: "utf8" });
  const reader = createInterface({ input, crlfDelay: Infinity });
  const flushChunk = async () => {
    if (!chunk.length) return;
    chunk.sort((a, b) => compareSortEntries(a, b, direction));
    const path = join(dirname(index.path), `.sort-${randomUUID()}.jsonl`);
    await writeFile(path, chunk.map((item) => JSON.stringify(item.record)).join("\n") + "\n");
    chunks.push(path);
    chunk = [];
  };
  try {
    for await (const line of reader) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        chunk.push({ record, value: sortFieldValue(record, field) });
        if (chunk.length >= chunkSize) await flushChunk();
      } catch {
        // Ignore a partially written/corrupt index record; the normal reader does the same.
      }
    }
    await flushChunk();
  } finally {
    input.destroy();
  }
  const outputPath = join(dirname(index.path), `.sorted-${randomUUID()}.jsonl`);
  const output = createWriteStream(outputPath, { flags: "w" });
  const iterators = [];
  const current = [];
  try {
    for (const path of chunks) {
      const stream = createReadStream(path, { encoding: "utf8" });
      const lineReader = createInterface({ input: stream, crlfDelay: Infinity });
      const iterator = lineReader[Symbol.asyncIterator]();
      iterators.push({ stream, lineReader, iterator });
      const next = await iterator.next();
      current.push(next.done ? null : JSON.parse(next.value));
    }
    const offsets = [0];
    let bytes = 0,
      count = 0;
    while (current.some(Boolean)) {
      let winner = -1;
      for (let i = 0; i < current.length; i++) {
        if (!current[i]) continue;
        const candidate = { record: current[i], value: sortFieldValue(current[i], field) };
        if (
          winner < 0 ||
          compareSortEntries(
            candidate,
            { record: current[winner], value: sortFieldValue(current[winner], field) },
            direction,
          ) < 0
        )
          winner = i;
      }
      const record = JSON.stringify(current[winner]) + "\n";
      if (!output.write(record)) await once(output, "drain");
      bytes += Buffer.byteLength(record);
      count++;
      if (count % 100 === 0) offsets.push(bytes);
      const next = await iterators[winner].iterator.next();
      current[winner] = next.done ? null : JSON.parse(next.value);
    }
    output.end();
    await once(output, "finish");
    return {
      ...index,
      path: outputPath,
      offsets,
      bytes,
      count,
      sortKey: field,
      sortDirection: direction,
      sortedPaths: [outputPath],
    };
  } catch (error) {
    output.destroy();
    await rm(outputPath, { force: true });
    throw error;
  } finally {
    for (const item of iterators) {
      item.lineReader.close();
      item.stream.destroy();
    }
    await Promise.all(chunks.map((path) => rm(path, { force: true })));
  }
}

async function sortedIndexFor(index, field, direction) {
  index.sorted ||= new Map();
  const key = `${field}:${direction}`;
  if (!index.sorted.has(key))
    index.sorted.set(key, buildSortedIndex(index, field, direction));
  return index.sorted.get(key);
}

export async function pageFromIndex(index, page = 0, pageSize = 100, sort = null) {
  if (sort?.field) {
    const sorted = await sortedIndexFor(
      index,
      sort.field,
      sort.direction === "desc" ? "desc" : "asc",
    );
    return pageFromIndex(sorted, page, pageSize);
  }
  page = Math.max(0, Math.floor(page));
  pageSize = Math.max(1, Math.floor(Number(pageSize) || 100));
  const start = page * pageSize;
  if (start >= index.count) return [];
  const end = Math.min(index.count, start + pageSize);
  // The JSONL index stores byte offsets every 100 records. For larger or
  // custom page sizes, read the smallest enclosing 100-record range and
  // slice by record position so filtered captures remain correctly paged.
  const blockStart = Math.floor(start / 100),
    blockEnd = Math.ceil(end / 100),
    from = index.offsets[blockStart] ?? 0,
    to = index.offsets[blockEnd] ?? index.bytes;
  const file = await open(index.path, "r");
  try {
    const buf = Buffer.alloc(to - from);
    await file.read(buf, 0, buf.length, from);
    const records = buf
      .toString()
      .trim()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse);
    return records.slice(start - blockStart * 100, end - blockStart * 100);
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
async function packetDetailFromPdml(capture, no, source = null) {
  const frameNo = source ? 1 : no,
    args = [
      ...(source ? argsForSource(capture, source) : argsFor(capture)),
      "-Y",
      `frame.number == ${frameNo}`,
    ];
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
function jsonRawMeta(value) {
  if (!Array.isArray(value) || typeof value[0] !== "string") return null;
  const pos = Number(value[1]),
    size = Number(value[2]);
  return {
    raw: value[0],
    pos: Number.isFinite(pos) ? pos : -1,
    size: Number.isFinite(size) ? size : 0,
  };
}
function jsonFieldLabel(name, value) {
  const text = String(value ?? "");
  if (!text) return name || "字段";
  if (
    /(?:^|\.)(?:request|response|Request-Line|Status-Line)$/.test(name)
  )
    return text;
  const shortName = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : name;
  return `${shortName}: ${text}`;
}
function jsonFieldNodes(container, bytes, depth = 0, virtual = false) {
  if (!container || typeof container !== "object" || depth > 32) return [];
  return Object.entries(container)
    .filter(([name]) => !name.endsWith("_raw") && !name.endsWith("_tree"))
    .map(([name, value]) => {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        return {
          id: name,
          name,
          value: "",
          label: name,
          filter: fieldExpression(name, ""),
          pos: null,
          size: 0,
          fields: jsonFieldNodes(value, bytes, depth + 1, virtual),
        };
      }
      const meta = jsonRawMeta(container[`${name}_raw`]),
        raw = meta?.raw || "",
        fieldValue = Array.isArray(value)
          ? value.join(", ")
          : value == null
            ? ""
            : String(value),
        isVirtual = virtual || /reassembled|decrypted/i.test(name),
        tree = container[`${name}_tree`],
        pos = meta?.pos ?? -1,
        size = meta?.size ?? 0;
      return {
        id: name,
        name,
        value: fieldValue,
        label: jsonFieldLabel(name, fieldValue),
        filter: fieldExpression(name, fieldValue, raw),
        pos:
          !isVirtual && size > 0 && pos >= 0 && pos + size <= bytes.length
            ? pos
            : null,
        size,
        fields:
          tree && typeof tree === "object"
            ? jsonFieldNodes(tree, bytes, depth + 1, isVirtual)
            : [],
      };
    });
}
function findJsonField(nodes, name) {
  for (const node of nodes) {
    if (node.name === name) return node;
    const nested = findJsonField(node.fields || [], name);
    if (nested) return nested;
  }
  return null;
}
function jsonLayerLabel(name, fields, no, bytes) {
  const source = findJsonField(fields, `${name}.src`)?.value,
    destination = findJsonField(fields, `${name}.dst`)?.value,
    srcPort = findJsonField(fields, `${name}.srcport`)?.value,
    dstPort = findJsonField(fields, `${name}.dstport`)?.value;
  if (name === "frame")
    return `Frame ${no}: Packet, ${bytes.length} bytes on wire (${bytes.length * 8} bits), ${bytes.length} bytes captured (${bytes.length * 8} bits)`;
  if (name === "eth") return "Ethernet II";
  if (name === "ip")
    return `Internet Protocol Version 4${source ? `, Src: ${source}` : ""}${destination ? `, Dst: ${destination}` : ""}`;
  if (name === "ipv6")
    return `Internet Protocol Version 6${source ? `, Src: ${source}` : ""}${destination ? `, Dst: ${destination}` : ""}`;
  if (name === "tcp")
    return `Transmission Control Protocol${srcPort ? `, Src Port: ${srcPort}` : ""}${dstPort ? `, Dst Port: ${dstPort}` : ""}`;
  if (name === "udp")
    return `User Datagram Protocol${srcPort ? `, Src Port: ${srcPort}` : ""}${dstPort ? `, Dst Port: ${dstPort}` : ""}`;
  return {
    http: "Hypertext Transfer Protocol",
    sip: "Session Initiation Protocol",
    sdp: "Session Description Protocol",
    rtp: "Real-time Transport Protocol",
    data: `Data (${bytes.length} bytes)`,
  }[name] || name;
}
async function packetDetailFromJson(capture, no, source = null) {
  const frameNo = source ? 1 : no;
  const args = [
    ...(source ? argsForSource(capture, source) : argsFor(capture)),
    "-Y",
    `frame.number == ${frameNo}`,
    "-T",
    "json",
    "-x",
  ];
  const output = await run(args, { capture, maxBytes: 32 * 1024 * 1024 }),
    packet = JSON.parse(output)[0]?._source,
    sourceLayers = packet?.layers || {},
    bytes = Array.from(
      Buffer.from(sourceLayers.frame_raw?.[0] || "", "hex"),
    );
  if (!bytes.length || !Object.keys(sourceLayers).length)
    throw new Error("TShark 未返回数据包详情");
  const layers = Object.entries(sourceLayers)
    .filter(
      ([name, value]) =>
        !name.endsWith("_raw") &&
        value &&
        typeof value === "object" &&
        !Array.isArray(value),
    )
    .map(([name, value]) => {
      const fields = jsonFieldNodes(value, bytes);
      return {
        id: name,
        name,
        value: "",
        label: jsonLayerLabel(name, fields, no, bytes),
        filter: fieldExpression(name, ""),
        pos: null,
        size: 0,
        fields,
      };
    });
  return { no, bytes, layers };
}
async function singleClassicPcap(capture, no) {
  const source = join(capture.dir, "capture.pcap"),
    file = await open(source, "r");
  try {
    const stat = await file.stat(),
      global = Buffer.alloc(24);
    await file.read(global, 0, global.length, 0);
    const magic = global.subarray(0, 4).toString("hex"),
      little = magic === "d4c3b2a1" || magic === "4d3cb2a1",
      big = magic === "a1b2c3d4" || magic === "a1b23c4d";
    if (!little && !big) return null;
    const readLength = (buffer, offset) =>
      little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
    let state = capture.pcapOffsetState;
    if (!state || state.source !== source || state.little !== little) {
      state = {
        source,
        little,
        nextNo: 1,
        nextOffset: 24,
        packets: [],
      };
      capture.pcapOffsetState = state;
    }
    const header = Buffer.alloc(16);
    while (state.packets.length < no) {
      if (state.nextOffset + 16 > stat.size) return null;
      await file.read(header, 0, header.length, state.nextOffset);
      const length = readLength(header, 8),
        recordOffset = state.nextOffset;
      if (!length || recordOffset + 16 + length > stat.size) return null;
      state.packets.push({ recordOffset, length });
      state.nextOffset += 16 + length;
      state.nextNo++;
    }
    const packet = state.packets[no - 1],
      record = Buffer.alloc(16 + packet.length);
    await file.read(record, 0, record.length, packet.recordOffset);
    const target = join(
      capture.dir,
      `.detail-${capture.revision}-${no}-${randomUUID()}.pcap`,
    );
    await writeFile(target, Buffer.concat([global, record]));
    return target;
  } finally {
    await file.close();
  }
}
async function withSinglePacketPcap(capture, no, callback) {
  const previous = capture.pcapOffsetTask || Promise.resolve();
  let release;
  const current = new Promise((resolve) => {
    release = resolve;
  });
  capture.pcapOffsetTask = current;
  await previous;
  let target = null;
  try {
    target = await singleClassicPcap(capture, no);
    return await callback(target);
  } finally {
    if (target) await rm(target, { force: true });
    release();
    if (capture.pcapOffsetTask === current) capture.pcapOffsetTask = null;
  }
}
async function packetDetailDecoder(capture, no) {
  const page = await pageFromIndex(capture.index, Math.floor((no - 1) / 100)),
    packet = page.find((item) => item.no === no),
    sipPacket = /sip/i.test(packet?.protocol || ""),
    needsNativeDissector = capture.config.mappings.some(
      (mapping) => mapping.codec === "OPUS",
    ),
    canIsolate = packet?.transport === "UDP";
  // JSON output is faster and contains raw bytes, but TShark's JSON object
  // shape collapses repeated SDP fields and can omit custom Opus dissector
  // fields. Keep PDML for those protocol cases so the detail tree stays exact.
  const decoder = sipPacket || needsNativeDissector
    ? packetDetailFromPdml
    : packetDetailFromJson;
  if (!canIsolate) return decoder(capture, no);
  return withSinglePacketPcap(capture, no, (source) =>
    decoder(capture, no, source),
  );
}
async function cachedPacketDetail(capture, no) {
  if (!capture.detailCache) capture.detailCache = new Map();
  if (!capture.detailPending) capture.detailPending = new Map();
  if (!Number.isFinite(capture.detailCacheBytes)) capture.detailCacheBytes = 0;
  const cacheKey = `${capture.revision || 0}:${no}`,
    cached = capture.detailCache.get(cacheKey);
  if (cached) {
    capture.detailCache.delete(cacheKey);
    capture.detailCache.set(cacheKey, cached);
    return cached;
  }
  if (capture.detailPending.has(cacheKey))
    return capture.detailPending.get(cacheKey);
  const pending = packetDetailDecoder(capture, no);
  capture.detailPending.set(cacheKey, pending);
  try {
    const detail = await pending;
    const bytes = detail.bytes?.length || 0;
    if (bytes <= DETAIL_CACHE_BYTES) {
      capture.detailCache.set(cacheKey, detail);
      capture.detailCacheBytes += bytes;
      while (
        capture.detailCache.size > DETAIL_CACHE_LIMIT ||
        capture.detailCacheBytes > DETAIL_CACHE_BYTES
      ) {
        const oldestKey = capture.detailCache.keys().next().value,
          oldest = capture.detailCache.get(oldestKey);
        capture.detailCache.delete(oldestKey);
        capture.detailCacheBytes -= oldest?.bytes?.length || 0;
      }
    }
    return detail;
  } finally {
    capture.detailPending.delete(cacheKey);
  }
}
export async function packetDetail(capture, no) {
  if (!Number.isInteger(no) || no < 1 || no > capture.index.count)
    throw new Error("数据包编号不存在");
  return cachedPacketDetail(capture, no);
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

export async function waveformFor(capture, streamIndex, maxPoints = 2400) {
  const stream = capture.index.summary.media[streamIndex];
  if (!stream) throw new Error("RTP 媒体流不存在");
  if (stream.pts.length !== 1)
    throw new Error("该流含多个 PT，请先按 PT 导出抓包后绘制波形");
  const mapping =
    mappingFor(
      { ...stream, rtp: { pt: stream.pts[0], ssrc: stream.ssrc } },
      capture.config,
    ) || staticCodec(stream.pts[0]);
  if (!mapping || !["PCMA", "PCMU"].includes(mapping.codec))
    throw new Error("当前波形图仅支持 PCMA / PCMU 音频流");
  const frames = [];
  let previousSequence = null;
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
      "frame.number",
      "-e",
      "frame.time_relative",
      "-e",
      "frame.time_epoch",
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
        const [no, time, epoch, seq, timestamp, hex] = line.split("\t");
        if (!hex) return;
        const payload = Buffer.from(hex.replaceAll(":", ""), "hex");
        const samples = [...payload].map((byte) => decodeG711(byte, mapping.codec));
        if (!samples.length) return;
        const min = Math.min(...samples);
        const max = Math.max(...samples);
        const rms = Math.sqrt(
          samples.reduce((sum, sample) => sum + sample * sample, 0) /
            samples.length,
        );
        const sequence = Number(seq);
        frames.push({
          no: Number(no),
          time: Number(time),
          epoch: Number(epoch),
          seq: sequence,
          timestamp: Number(timestamp),
          span: payload.length / mapping.clockRate,
          min,
          max,
          level: rms,
          lostBefore:
            previousSequence == null
              ? 0
              : Math.max(0, sequence - previousSequence - 1),
        });
        previousSequence = sequence;
      },
    },
  );
  const firstTimestamp = frames.find((frame) => Number.isFinite(frame.timestamp))?.timestamp;
  const firstTime = frames.find((frame) => Number.isFinite(frame.time))?.time ?? 0;
  const firstEpoch = frames.find((frame) => Number.isFinite(frame.epoch))?.epoch ?? null;
  for (const frame of frames) {
    frame.offset =
      Number.isFinite(firstTimestamp) && Number.isFinite(frame.timestamp)
        ? (frame.timestamp - firstTimestamp) / mapping.clockRate
        : Math.max(0, (frame.time || 0) - firstTime);
  }
  const duration = Math.max(
    0,
    ...frames.map((frame) => (frame.offset || 0) + (frame.span || 0)),
  );
  if (frames.length <= maxPoints) {
    return {
      stream: streamIndex,
      codec: mapping.codec,
      clockRate: mapping.clockRate,
      packets: frames,
      duration,
      startTime: firstTime,
      startEpoch: firstEpoch,
      sampled: false,
    };
  }
  const step = frames.length / maxPoints;
  const packets = [];
  for (let index = 0; index < maxPoints; index += 1) {
    const start = Math.floor(index * step);
    const end = Math.min(frames.length, Math.floor((index + 1) * step));
    const bucket = frames.slice(start, Math.max(start + 1, end));
    packets.push(
      bucket.reduce((best, frame) =>
        frame.level > best.level ? frame : best,
      ),
    );
  }
  return {
    stream: streamIndex,
    codec: mapping.codec,
    clockRate: mapping.clockRate,
    packets,
    duration,
    startTime: firstTime,
    startEpoch: firstEpoch,
    sampled: true,
    originalPackets: frames.length,
  };
}
export async function exportCapture(capture, filter, path, extraDecodeAs = []) {
  await run(
    [
      ...argsFor(capture, extraDecodeAs),
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
