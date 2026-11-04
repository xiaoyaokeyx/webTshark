// Synthetic traffic only. The returned PCAP can be generated without a server.
const enc = new TextEncoder();
const u16 = (n) => [(n >>> 8) & 255, n & 255];
const u32 = (n) => [
  (n >>> 24) & 255,
  (n >>> 16) & 255,
  (n >>> 8) & 255,
  n & 255,
];
export function checksum(bytes) {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2)
    sum += (bytes[i] << 8) | (bytes[i + 1] || 0);
  while (sum > 65535) sum = (sum & 65535) + (sum >>> 16);
  return ~sum & 65535;
}
export const composeDefaults = {
  protocol: "SIP",
  source: "192.0.2.10",
  destination: "198.51.100.20",
  srcPort: 5060,
  dstPort: 5060,
  count: 1,
  interval: 20,
  pt: 96,
  ssrc: 305419896,
  sequence: 1000,
  clockRate: 8000,
  payloadSize: 160,
  method: "INVITE",
  callId: "synthetic-call@webtshark.example",
  callCount: 1,
  channelId: "synthetic@speechrecog",
  body: "",
};
function ip(value) {
  if (
    !/^\d+\.\d+\.\d+\.\d+$/.test(value) ||
    value.split(".").some((v) => Number(v) > 255)
  )
    throw new Error("请输入有效 IPv4 地址");
  return value.split(".").map(Number);
}
function integer(value, min, max, name) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max)
    throw new Error(`${name} 应为 ${min}–${max} 的整数`);
  return n;
}

function pcapFromFrames(frames, epoch = 1793664000) {
  const ordered = [...frames].sort((a, b) => a.time - b.time || a.order - b.order);
  const output = new Uint8Array(
    24 + ordered.reduce((sum, frame) => sum + frame.bytes.length + 16, 0),
  );
  const view = new DataView(output.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 262144, true);
  view.setUint32(20, 1, true);
  let offset = 24;
  for (const frame of ordered) {
    const seconds = Math.max(0, Number(frame.time) || 0);
    view.setUint32(offset, Math.floor(epoch + seconds), true);
    view.setUint32(offset + 4, Math.round((seconds % 1) * 1e6), true);
    view.setUint32(offset + 8, frame.bytes.length, true);
    view.setUint32(offset + 12, frame.bytes.length, true);
    output.set(frame.bytes, offset + 16);
    offset += frame.bytes.length + 16;
  }
  return output;
}

function sipUdpFrame(source, destination, payload, identification, sourcePort = 5060) {
  const src = ip(source),
    dst = ip(destination),
    udp = [
      ...u16(sourcePort),
      ...u16(5060),
      ...u16(8 + payload.length),
      0,
      0,
      ...payload,
    ];
  const pseudo = [...src, ...dst, 0, 17, ...u16(udp.length), ...udp];
  udp.splice(6, 2, ...u16(checksum(pseudo) || 0xffff));
  const header = [
    0x45,
    0,
    ...u16(20 + udp.length),
    ...u16(identification & 0xffff),
    0x40,
    0,
    64,
    17,
    0,
    0,
    ...src,
    ...dst,
  ];
  header.splice(10, 2, ...u16(checksum(header)));
  return new Uint8Array([
    0,
    17,
    34,
    51,
    68,
    85,
    102,
    119,
    136,
    153,
    170,
    187,
    8,
    0,
    ...header,
    ...udp,
  ]);
}

function sipDialogMessage({
  source,
  destination,
  callId,
  branch,
  fromTag,
  toTag,
  event,
}) {
  const response = event.code != null;
  const method = event.method || "INVITE";
  const cseqMethod = event.cseqMethod || method;
  const cseq = event.cseq || (cseqMethod === "BYE" ? 2 : 1);
  const body = event.body || "";
  const start = response
    ? `SIP/2.0 ${event.code} ${event.reason}`
    : `${method} sip:bob@${destination} SIP/2.0`;
  const headers = [
    `Via: SIP/2.0/UDP ${source}:5060;branch=${branch}`,
    "Max-Forwards: 70",
    `From: <sip:alice@${source}>;tag=${fromTag}`,
    `To: <sip:bob@${destination}>${toTag ? `;tag=${toTag}` : ""}`,
    `Call-ID: ${callId}`,
    `CSeq: ${cseq} ${cseqMethod}`,
    ...(event.contact
      ? [`Contact: <sip:bob@${destination}:5060>`]
      : !response && method !== "CANCEL"
        ? [`Contact: <sip:alice@${source}:5060>`]
        : []),
    ...(body ? ["Content-Type: application/sdp"] : []),
    `Content-Length: ${enc.encode(body).length}`,
  ];
  return enc.encode(`${start}\r\n${headers.join("\r\n")}\r\n\r\n${body}`);
}

function demoSdp(address, role) {
  return [
    "v=0",
    `o=${role} 1 1 IN IP4 ${address}`,
    "s=WebShark multi-call demo",
    `c=IN IP4 ${address}`,
    "t=0 0",
    "m=audio 20000 RTP/AVP 0 96",
    "a=rtpmap:0 PCMU/8000",
    "a=rtpmap:96 AMR-WB/16000",
    "a=ptime:20",
    "a=sendrecv",
  ].join("\r\n") + "\r\n";
}

/**
 * Build several independent SIP dialogs for exercising the VoIP call list.
 * The generated traffic is offline and deterministic; no packets are sent.
 */
export function buildVoipCalls(input = {}) {
  const callCount = integer(input.callCount ?? 6, 2, 64, "通话数");
  const spacing = Number(input.spacing ?? 0.12);
  if (!Number.isFinite(spacing) || spacing < 0.01 || spacing > 60)
    throw new Error("通话间隔应为 0.01–60 秒");
  const frames = [];
  let order = 0;
  for (let index = 0; index < callCount; index += 1) {
    const source = `192.0.2.${10 + index}`;
    const destination = `198.51.100.${20 + index}`;
    const number = String(index + 1).padStart(2, "0");
    const callId = `webtshark-call-${number}@demo.local`;
    const branch = `z9hG4bK-webtshark-${number}`;
    const fromTag = `caller-${number}`;
    const toTag = `callee-${number}`;
    const mode = index % 4;
    const offer = demoSdp(source, "alice");
    const answer = demoSdp(destination, "bob");
    const events = [
      { at: 0, method: "INVITE", body: offer },
      { at: 0.018, code: 100, reason: "Trying" },
      ...(mode === 1
        ? [
            { at: 0.08, code: 486, reason: "Busy Here", toTag },
            { at: 0.1, method: "ACK", cseqMethod: "ACK", toTag },
          ]
        : mode === 2
          ? [{ at: 0.08, code: 180, reason: "Ringing", toTag }]
          : mode === 3
            ? [
                { at: 0.08, code: 180, reason: "Ringing", toTag },
                { at: 0.11, method: "CANCEL", toTag },
                { at: 0.13, code: 200, reason: "OK", cseqMethod: "CANCEL", toTag },
                { at: 0.16, code: 487, reason: "Request Terminated", toTag },
              ]
            : [
                { at: 0.08, code: 180, reason: "Ringing", toTag },
                { at: 0.18, code: 200, reason: "OK", toTag, body: answer, contact: true },
                { at: 0.2, method: "ACK", cseqMethod: "ACK", toTag },
                { at: 0.55, method: "BYE", cseq: 2, toTag },
                { at: 0.58, code: 200, reason: "OK", cseqMethod: "BYE", cseq: 2, toTag },
              ]),
    ];
    const start = index * spacing;
    for (const event of events) {
      const response = event.code != null;
      const payload = sipDialogMessage({
        source: response ? destination : source,
        destination: response ? source : destination,
        callId,
        branch: `${branch}-${event.method || event.cseqMethod || "response"}`,
        fromTag,
        toTag: response || event.toTag ? toTag : "",
        event,
      });
      frames.push({
        time: start + event.at,
        order: order++,
        bytes: sipUdpFrame(
          response ? destination : source,
          response ? source : destination,
          payload,
          order,
          response ? 5060 : 5062,
        ),
      });
    }
  }
  return pcapFromFrames(frames);
}
export function buildCapture(input = {}) {
  const c = { ...composeDefaults, ...input },
    src = ip(c.source),
    dst = ip(c.destination);
  const count = integer(c.count, 1, 10000, "包数"),
    interval = integer(c.interval, 1, 60000, "间隔(ms)");
  const srcPort = integer(c.srcPort, 1, 65535, "源端口"),
    dstPort = integer(c.dstPort, 1, 65535, "目标端口");
  const estimatedPacket =
    String(c.body || "").length * 4 +
    (c.protocol === "RTP" ? Number(c.payloadSize) : 1500) +
    128;
  if (estimatedPacket * count > 32 * 1024 * 1024)
    throw new Error("合成文件超过 32 MiB 保护上限，请减少包数或正文长度");
  if (!["SIP", "SDP", "RTP", "RTCP", "MRCPv2"].includes(c.protocol))
    throw new Error("不支持的协议");
  for (const v of [c.method, c.callId, c.channelId])
    if (/[\r\n]/.test(v)) throw new Error("标识字段不能包含换行");
  const frames = [];
  let tcpSeq = 1;
  const epoch = Number.isFinite(Number(c.epoch)) ? Number(c.epoch) : 1793664000;
  for (let i = 0; i < count; i++) {
    let payload;
    if (c.protocol === "RTP") {
      const pt = integer(c.pt, 0, 127, "PT"),
        seq = integer(c.sequence, 0, 65535, "序列号");
      const clock = integer(c.clockRate, 1, 192000, "时钟频率"),
        ssrc = integer(c.ssrc, 0, 0xffffffff, "SSRC");
      payload = [
        0x80,
        pt,
        ...u16((seq + i) & 65535),
        ...u32(Math.round((i * interval * clock) / 1000) >>> 0),
        ...u32(ssrc),
        ...Array(integer(c.payloadSize, 1, 60000, "RTP 载荷字节数")).fill(0xff),
      ];
    } else if (c.protocol === "RTCP") {
      const ssrc = integer(c.ssrc, 0, 0xffffffff, "SSRC");
      payload = [
        0x80,
        200,
        0,
        6,
        ...u32(ssrc),
        ...u32(epoch + 2208988800),
        ...u32(0),
        ...u32(i * 160),
        ...u32(i + 1),
        ...u32((i + 1) * 160),
      ];
    } else if (c.protocol === "MRCPv2") {
      const body = String(c.body || ""),
        method = String(c.method === "INVITE" ? "RECOGNIZE" : c.method);
      const tail = `${method} ${i + 1}\r\nChannel-Identifier: ${c.channelId}\r\nContent-Type: text/uri-list\r\nContent-Length: ${enc.encode(body).length}\r\n\r\n${body}`;
      let length = 0,
        text;
      do {
        text = `MRCP/2.0 ${length} ${tail}`;
        if (enc.encode(text).length === length) break;
        length = enc.encode(text).length;
      } while (true);
      payload = [...enc.encode(text)];
    } else {
      const sdp = String(
        c.body ||
          `v=0\r\no=demo 1 1 IN IP4 ${c.source}\r\ns=WebTshark synthetic\r\nc=IN IP4 ${c.source}\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0 96\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\na=sendrecv\r\n`,
      );
      const body =
        c.protocol === "SDP" || c.method === "INVITE"
          ? sdp
          : String(c.body || "");
      payload = [
        ...enc.encode(
          `${c.method} sip:bob@${c.destination} SIP/2.0\r\nVia: SIP/2.0/UDP ${c.source}:${srcPort};branch=z9hG4bK-synthetic-${i}\r\nMax-Forwards: 70\r\nFrom: <sip:alice@${c.source}>;tag=demo\r\nTo: <sip:bob@${c.destination}>\r\nCall-ID: ${c.callId}\r\nCSeq: ${i + 1} ${c.method}\r\nContact: <sip:alice@${c.source}:${srcPort}>\r\n${body ? "Content-Type: application/sdp\r\n" : ""}Content-Length: ${enc.encode(body).length}\r\n\r\n${body}`,
        ),
      ];
    }
    const tcp = c.protocol === "MRCPv2",
      protocol = tcp ? 6 : 17;
    let transport = tcp
      ? [
          ...u16(srcPort),
          ...u16(dstPort),
          ...u32(tcpSeq),
          ...u32(1),
          0x50,
          0x18,
          ...u16(65535),
          0,
          0,
          0,
          0,
          ...payload,
        ]
      : [
          ...u16(srcPort),
          ...u16(dstPort),
          ...u16(payload.length + 8),
          0,
          0,
          ...payload,
        ];
    if (transport.length + 20 > 65535)
      throw new Error("单包超出 IPv4 长度限制");
    const check =
      checksum([
        ...src,
        ...dst,
        0,
        protocol,
        ...u16(transport.length),
        ...transport,
      ]) || 65535;
    transport.splice(tcp ? 16 : 6, 2, ...u16(check));
    tcpSeq += payload.length;
    const header = [
      0x45,
      0,
      ...u16(20 + transport.length),
      ...u16(i & 65535),
      0x40,
      0,
      64,
      protocol,
      0,
      0,
      ...src,
      ...dst,
    ];
    header.splice(10, 2, ...u16(checksum(header)));
    const bytes = new Uint8Array([
      0,
      17,
      34,
      51,
      68,
      85,
      102,
      119,
      136,
      153,
      170,
      187,
      8,
      0,
      ...header,
      ...transport,
    ]);
    frames.push({ bytes, time: (i * interval) / 1000 });
  }
  const output = new Uint8Array(
    24 + frames.reduce((s, f) => s + f.bytes.length + 16, 0),
  );
  const view = new DataView(output.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 262144, true);
  view.setUint32(20, 1, true);
  let offset = 24;
  for (const frame of frames) {
    view.setUint32(offset, Math.floor(epoch + frame.time), true);
    view.setUint32(
      offset + 4,
      Math.round(((epoch + frame.time) % 1) * 1e6),
      true,
    );
    view.setUint32(offset + 8, frame.bytes.length, true);
    view.setUint32(offset + 12, frame.bytes.length, true);
    output.set(frame.bytes, offset + 16);
    offset += frame.bytes.length + 16;
  }
  return output;
}
