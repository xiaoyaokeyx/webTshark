import { isIP } from "node:net";
export const codecs = [
  {
    name: "PCMU",
    label: "G.711 μ-law (PCMU)",
    clockRate: 8000,
    channels: 1,
    playback: true,
  },
  {
    name: "PCMA",
    label: "G.711 A-law (PCMA)",
    clockRate: 8000,
    channels: 1,
    playback: true,
  },
  {
    name: "OPUS",
    label: "Opus",
    clockRate: 48000,
    channels: 2,
    dissector: "opus",
  },
  {
    name: "AMR",
    label: "AMR / AMR-NB",
    clockRate: 8000,
    channels: 1,
    dissector: "amr",
    amr: true,
  },
  {
    name: "AMR-WB",
    label: "AMR-WB",
    clockRate: 16000,
    channels: 1,
    dissector: "amr-wb",
    amr: true,
  },
  {
    name: "G722",
    label: "G.722 · RTP 时钟 8 kHz",
    clockRate: 8000,
    channels: 1,
  },
  { name: "G729", label: "G.729", clockRate: 8000, channels: 1 },
  {
    name: "H264",
    label: "H.264 / AVC",
    clockRate: 90000,
    channels: 1,
    dissector: "h264",
  },
  {
    name: "H265",
    label: "H.265 / HEVC",
    clockRate: 90000,
    channels: 1,
    dissector: "h265",
  },
  {
    name: "VP8",
    label: "VP8",
    clockRate: 90000,
    channels: 1,
    dissector: "vp8",
  },
  {
    name: "telephone-event",
    label: "DTMF / telephone-event",
    clockRate: 8000,
    channels: 1,
    dissector: "rtpevent",
  },
];
export const decodeAsProtocols = [
  { name: "rtp", label: "RTP（实时传输协议）" },
  { name: "rtcp", label: "RTCP（RTP 控制协议）" },
  { name: "sip", label: "SIP（会话初始化协议）" },
  { name: "sdp", label: "SDP（会话描述协议）" },
  { name: "http", label: "HTTP" },
  { name: "mrcpv2", label: "MRCPv2" },
  { name: "dns", label: "DNS" },
  { name: "tls", label: "TLS" },
  { name: "data", label: "Data（原始数据）" },
];
export function validateConfig(input = {}) {
  if (!Array.isArray(input.mappings) || input.mappings.length > 128)
    throw new Error("RTP 映射必须为数组，最多 128 条");
  if (!Array.isArray(input.ports) || input.ports.length > 64)
    throw new Error("最多设置 64 个 RTP UDP 端口");
  const ports = [...new Set(input.ports.map(Number))];
  if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535))
    throw new Error("UDP 端口范围为 1–65535");
  const decodeAsInput = input.decodeAs == null ? [] : input.decodeAs;
  if (!Array.isArray(decodeAsInput) || decodeAsInput.length > 128)
    throw new Error("Decode As 规则必须为数组，最多 128 条");
  const decodeKeys = new Set();
  const decodeAs = decodeAsInput.map((rule) => {
    const transport = String(rule.transport || "").toLowerCase(),
      port = Number(rule.port),
      protocol = String(rule.protocol || "").toLowerCase();
    if (!["tcp", "udp"].includes(transport))
      throw new Error("Decode As 仅支持 TCP 或 UDP");
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new Error("Decode As 端口范围为 1–65535");
    if (!decodeAsProtocols.some((item) => item.name === protocol))
      throw new Error("不支持的 Decode As 协议");
    const key = `${transport}|${port}`;
    if (decodeKeys.has(key))
      throw new Error("相同传输协议和端口只能设置一条 Decode As 规则");
    decodeKeys.add(key);
    return { transport, port, protocol };
  });
  const keys = new Set();
  const mappings = input.mappings.map((m) => {
    const pt = Number(m.pt),
      clockRate = Number(m.clockRate),
      channels = Number(m.channels);
    if (!Number.isInteger(pt) || pt < 96 || pt > 127)
      throw new Error("动态 PT 必须为 96–127 的整数");
    if (!["stream", "capture"].includes(m.scope))
      throw new Error("必须明确选择单流或当前抓包作用范围");
    const codec = codecs.find((c) => c.name === m.codec);
    if (!codec) throw new Error("不支持的编解码名称");
    if (!Number.isInteger(clockRate) || clockRate < 1000 || clockRate > 192000)
      throw new Error("RTP 时钟频率范围为 1000–192000 Hz");
    if (![1, 2].includes(channels)) throw new Error("声道必须为 1 或 2");
    if (
      ["PCMU", "PCMA"].includes(m.codec) &&
      (clockRate !== 8000 || channels !== 1)
    )
      throw new Error("当前 G.711 播放支持 8000 Hz 单声道");
    const out = {
      pt,
      codec: m.codec,
      clockRate,
      channels,
      scope: m.scope === "stream" ? "stream" : "capture",
    };
    if (codec.amr) {
      if (clockRate !== codec.clockRate)
        throw new Error(
          `${codec.name} 的 RTP 时钟频率必须为 ${codec.clockRate} Hz`,
        );
      if (m.octetAlign !== undefined && typeof m.octetAlign !== "boolean")
        throw new Error("AMR octet-align 必须为布尔值");
      out.octetAlign = m.octetAlign ?? false;
    }
    if (out.scope === "stream") {
      if (!isIP(m.source) || !isIP(m.destination))
        throw new Error("媒体流需要有效源/目标 IP");
      for (const key of ["srcPort", "dstPort"])
        if (
          !Number.isInteger(Number(m[key])) ||
          Number(m[key]) < 1 ||
          Number(m[key]) > 65535
        )
          throw new Error("媒体流端口无效");
      if (!/^0x[0-9a-f]{1,8}$/i.test(m.ssrc))
        throw new Error("SSRC 必须为 32 位十六进制值");
      Object.assign(out, {
        source: m.source,
        destination: m.destination,
        srcPort: Number(m.srcPort),
        dstPort: Number(m.dstPort),
        ssrc: `0x${Number(m.ssrc).toString(16)}`,
      });
    }
    const key = [
      out.scope,
      out.pt,
      out.source,
      out.destination,
      out.srcPort,
      out.dstPort,
      out.ssrc,
    ].join("|");
    if (keys.has(key)) throw new Error("相同作用域和 PT 不能重复设置");
    keys.add(key);
    return out;
  });
  return { ports, heuristic: input.heuristic === true, mappings, decodeAs };
}
export function mappingFor(packet, config) {
  const list = config?.mappings || [];
  return (
    list.find(
      (m) =>
        m.scope === "stream" &&
        m.pt === packet.rtp?.pt &&
        m.source === packet.source &&
        m.destination === packet.destination &&
        m.srcPort === packet.srcPort &&
        m.dstPort === packet.dstPort &&
        Number(m.ssrc) === Number(packet.rtp?.ssrc),
    ) ||
    list.find((m) => m.scope === "capture" && m.pt === packet.rtp?.pt) ||
    null
  );
}
export function staticCodec(pt) {
  return (
    {
      0: { codec: "PCMU", clockRate: 8000, channels: 1 },
      8: { codec: "PCMA", clockRate: 8000, channels: 1 },
      9: { codec: "G722", clockRate: 8000, channels: 1 },
      18: { codec: "G729", clockRate: 8000, channels: 1 },
    }[pt] || null
  );
}
const luaString = (s) =>
  `"${String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
export function mappingLua(config) {
  // Only validated structured values are emitted. No uploaded/user-provided Lua is executed.
  const maps = [...config.mappings].sort(
    (a, b) => (a.scope === "stream" ? -1 : 1) - (b.scope === "stream" ? -1 : 1),
  );
  const rules = maps
    .map(
      (m) =>
        `{pt=${m.pt}, codec=${luaString(m.codec)}, rate=${m.clockRate}, channels=${m.channels}, decoder=${luaString(codecs.find((c) => c.name === m.codec)?.dissector || "")}${codecs.find((c) => c.name === m.codec)?.amr ? `, amr_mode=${luaString(m.codec === "AMR" ? "AMR-NB" : "AMR-WB")}, amr_encoding=${luaString(m.octetAlign ? "octet_aligned" : "bw_efficient")}` : ""}${m.scope === "stream" ? `, src=${luaString(m.source)}, dst=${luaString(m.destination)}, sp=${m.srcPort}, dp=${m.dstPort}, ssrc=${Number(m.ssrc)}` : ""}}`,
    )
    .join(",\n");
  return `local p=Proto("webshark_rtp","WebShark RTP payload mapping")
local codec=ProtoField.string("webshark.rtp.codec","Codec")
local rate=ProtoField.uint32("webshark.rtp.clock_rate","RTP clock rate",base.DEC)
local channels=ProtoField.uint8("webshark.rtp.channels","Channels",base.DEC)
local payload=ProtoField.bytes("webshark.rtp.payload","Mapped payload")
p.fields={codec,rate,channels,payload}
local get_pt=Field.new("rtp.p_type")
local get_ssrc=Field.new("rtp.ssrc")
local get_payload=Field.new("rtp.payload")
local rules={${rules}}
function p.dissector(tvb,pinfo,tree)
  local pt,ssrc,body=get_pt(),get_ssrc(),get_payload()
  if not pt or not ssrc then return end
  for _,r in ipairs(rules) do
    if tonumber(pt.value)==r.pt and (not r.src or (tostring(pinfo.src)==r.src and tostring(pinfo.dst)==r.dst and pinfo.src_port==r.sp and pinfo.dst_port==r.dp and tonumber(ssrc.value)==r.ssrc)) then
      local sub=tree:add(p,"RTP PT "..r.pt.." → "..r.codec.." / "..r.rate.." Hz / "..r.channels.." ch")
      sub:add(codec,r.codec):set_generated();sub:add(rate,r.rate):set_generated();sub:add(channels,r.channels):set_generated()
      if body and body.len>0 then
        sub:add(payload,body.range)
        if r.decoder~="" then
          local ok,d=pcall(Dissector.get,r.decoder)
          if ok and d then
            local previous=tostring(pinfo.cols.protocol)
            local previous_mode,previous_encoding
            if r.amr_mode then
              -- Limit these in-memory preferences to this payload; never save them.
              previous_mode=get_preference("amr.mode")
              previous_encoding=get_preference("amr.encoding.version")
              set_preference("amr.mode",r.amr_mode)
              set_preference("amr.encoding.version",r.amr_encoding)
            end
            pcall(function() d:call(body.range:tvb(),pinfo,sub) end)
            if previous_mode then set_preference("amr.mode",previous_mode) end
            if previous_encoding then set_preference("amr.encoding.version",previous_encoding) end
            pinfo.cols.protocol=previous
          end
        end
      end
      pinfo.cols.info:append(" [PT "..r.pt.." → "..r.codec.."]")
      return
    end
  end
end
register_postdissector(p,true)
`;
}
export function streamKey(p) {
  return `${p.source}|${p.srcPort}|${p.destination}|${p.dstPort}|${p.rtp.ssrc}`;
}
export function streamFilter(s) {
  const family = isIP(s.source) === 6 ? "ipv6" : "ip";
  return `${family}.src == ${s.source} && ${family}.dst == ${s.destination} && udp.srcport == ${s.srcPort} && udp.dstport == ${s.dstPort} && rtp.ssrc == ${s.ssrc}`;
}
export function decodeG711(byte, codec) {
  if (codec === "PCMU") {
    const b = ~byte & 255;
    let n = ((b & 15) << 3) + 132;
    n <<= (b & 112) >> 4;
    return b & 128 ? 132 - n : n - 132;
  }
  const b = byte ^ 0x55;
  let n = (b & 15) << 4;
  const seg = (b & 112) >> 4;
  n += seg ? 264 : 8;
  if (seg > 1) n <<= seg - 1;
  return b & 128 ? n : -n;
}
export function makeWave(frames, mapping) {
  if (
    !["PCMU", "PCMA"].includes(mapping.codec) ||
    mapping.clockRate !== 8000 ||
    mapping.channels !== 1
  )
    throw new Error(
      "音频播放当前支持 PCMU/PCMA、8000 Hz、单声道；其他编码可查看解析结果或导出 RTP 载荷",
    );
  if (!frames.length) throw new Error("该流没有可解码的 RTP 载荷");
  const start = frames[0].timestamp;
  const ordered = frames
    .map((f) => ({ ...f, offset: (f.timestamp - start) | 0 }))
    .sort((a, b) => a.offset - b.offset);
  const first = ordered[0].offset;
  for (const f of ordered) f.offset -= first;
  const length = ordered.reduce(
    (max, f) => Math.max(max, f.offset + f.payload.length),
    0,
  );
  if (length > 8000 * 600)
    throw new Error("音频预览最多 10 分钟，请先裁剪抓包");
  const samples = Buffer.alloc(length * 2);
  const seen = new Set();
  for (const frame of ordered) {
    const key = `${frame.seq}:${frame.timestamp}`;
    if (seen.has(key)) continue;
    seen.add(key);
    for (let i = 0; i < frame.payload.length; i++)
      samples.writeInt16LE(
        decodeG711(frame.payload[i], mapping.codec),
        (frame.offset + i) * 2,
      );
  }
  const header = Buffer.alloc(44);
  header.write("RIFF");
  header.writeUInt32LE(36 + samples.length, 4);
  header.write("WAVEfmt ", 8);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(8000, 24);
  header.writeUInt32LE(16000, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write("data", 36);
  header.writeUInt32LE(samples.length, 40);
  return Buffer.concat([header, samples]);
}
