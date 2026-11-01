import { packets } from "../src/packetData.js";

// Two overlapping dialogs on four endpoints, for call-flow previews and regression tests.
export function buildSipMultiCallPcap() {
  const frames = [];
  function call({ source, destination, id, start, busy = false }) {
    const events = busy
      ? [
          [0, "INVITE"],
          [0.045, "100 Trying"],
          [0.19, "486 Busy Here"],
          [0.21, "ACK"],
        ]
      : [
          [0, "INVITE"],
          [0.032, "100 Trying"],
          [0.12, "180 Ringing"],
          [0.42, "200 OK"],
          [0.45, "ACK"],
          [8.2, "BYE"],
          [8.24, "200 OK"],
        ];
    events.forEach(([offset, event], index) => {
      const response = /^\d/.test(event);
      const from = response ? destination : source,
        to = response ? source : destination;
      const method = index >= 5 ? "BYE" : event === "ACK" ? "ACK" : "INVITE";
      const sdp =
        event === "INVITE" || (event === "200 OK" && method === "INVITE");
      const body = sdp
        ? `v=0\r\no=demo 1 1 IN IP4 ${from}\r\ns=Multi-call demo\r\nc=IN IP4 ${from}\r\nt=0 0\r\nm=audio 20000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n`
        : "";
      const text = [
        response
          ? `SIP/2.0 ${event}`
          : `${event} sip:bob@${destination} SIP/2.0`,
        `Via: SIP/2.0/UDP ${source}:5060;branch=z9hG4bK-${id}-${method}`,
        `From: <sip:alice@${source}>;tag=${id}`,
        `To: <sip:bob@${destination}>${response ? ";tag=callee" : ""}`,
        `Call-ID: ${id}@webshark.demo`,
        `CSeq: ${method === "BYE" ? 2 : 1} ${method}`,
        "Max-Forwards: 70",
        ...(sdp ? ["Content-Type: application/sdp"] : []),
        `Content-Length: ${Buffer.byteLength(body)}`,
        "",
        body,
      ].join("\r\n");
      const payload = Buffer.from(text),
        udp = Buffer.alloc(8),
        ip = Buffer.alloc(20);
      udp.writeUInt16BE(5060, 0);
      udp.writeUInt16BE(5060, 2);
      udp.writeUInt16BE(8 + payload.length, 4);
      ip[0] = 0x45;
      ip[8] = 64;
      ip[9] = 17;
      ip.writeUInt16BE(28 + payload.length, 2);
      Buffer.from(from.split(".").map(Number)).copy(ip, 12);
      Buffer.from(to.split(".").map(Number)).copy(ip, 16);
      let checksum = 0;
      for (let i = 0; i < 20; i += 2) checksum += ip.readUInt16BE(i);
      while (checksum > 65535)
        checksum = (checksum & 65535) + (checksum >>> 16);
      ip.writeUInt16BE(~checksum & 65535, 10);
      frames.push({
        time: start + offset,
        bytes: Buffer.concat([
          Buffer.from("00112233445566778899aabb0800", "hex"),
          ip,
          udp,
          payload,
        ]),
      });
    });
  }
  call({
    source: "192.168.1.108",
    destination: "198.51.100.40",
    id: "call-alice-bob",
    start: 0,
  });
  call({
    source: "10.10.0.21",
    destination: "203.0.113.80",
    id: "call-carol-dave",
    start: 0.075,
    busy: true,
  });
  frames.sort((a, b) => a.time - b.time);
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(262144, 16);
  header.writeUInt32LE(1, 20);
  return Buffer.concat([
    header,
    ...frames.flatMap(({ time, bytes }) => {
      const h = Buffer.alloc(16);
      h.writeUInt32LE(1793341934 + Math.floor(time));
      h.writeUInt32LE(Math.round((time % 1) * 1e6), 4);
      h.writeUInt32LE(bytes.length, 8);
      h.writeUInt32LE(bytes.length, 12);
      return [h, bytes];
    }),
  ]);
}

function udpPacket({ seq, ssrc, pt, port, reverse = false }) {
  const payload = Buffer.alloc(160);
  for (let i = 0; i < payload.length; i++)
    payload[i] = (i + seq) % 32 < 16 ? 0xb0 : 0x30; // synthetic G.711 tone bytes
  const rtp = Buffer.alloc(12);
  rtp[0] = 0x80;
  rtp[1] = pt;
  rtp.writeUInt16BE(seq, 2);
  rtp.writeUInt32BE(seq * 160, 4);
  rtp.writeUInt32BE(ssrc, 8);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(reverse ? port + 2 : port, 0);
  udp.writeUInt16BE(reverse ? port : port + 2, 2);
  udp.writeUInt16BE(8 + rtp.length + payload.length, 4);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + udp.length + rtp.length + payload.length, 2);
  ip.writeUInt16BE(seq, 4);
  ip[8] = 64;
  ip[9] = 17;
  Buffer.from(reverse ? [10, 10, 0, 20] : [10, 10, 0, 10]).copy(ip, 12);
  Buffer.from(reverse ? [10, 10, 0, 10] : [10, 10, 0, 20]).copy(ip, 16);
  let sum = 0;
  for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
  while (sum > 65535) sum = (sum & 65535) + (sum >>> 16);
  ip.writeUInt16BE(~sum & 65535, 10);
  const eth = Buffer.from("00112233445566778899aabb0800", "hex");
  return Buffer.concat([eth, ip, udp, rtp, payload]);
}
export function buildDemoPcap({ rtpOnly = false } = {}) {
  const frames = rtpOnly
    ? []
    : packets.map((p) => ({ time: p.time, bytes: Buffer.from(p.bytes) }));
  for (let i = 0; i < 70; i++) {
    if (i !== 25)
      frames.push({
        time: 2 + i * 0.02,
        bytes: udpPacket({
          seq: 65000 + i,
          ssrc: 0x12345678,
          pt: 96,
          port: 20000,
        }),
      });
    frames.push({
      time: 2.005 + i * 0.02,
      bytes: udpPacket({
        seq: 1000 + i,
        ssrc: 0x87654321,
        pt: 96,
        port: 20000,
        reverse: true,
      }),
    });
  }
  frames.sort((a, b) => a.time - b.time);
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(262144, 16);
  header.writeUInt32LE(1, 20);
  return Buffer.concat([
    header,
    ...frames.flatMap((f) => {
      const h = Buffer.alloc(16);
      h.writeUInt32LE(1793341934 + Math.floor(f.time));
      h.writeUInt32LE(Math.round((f.time % 1) * 1e6), 4);
      h.writeUInt32LE(f.bytes.length, 8);
      h.writeUInt32LE(f.bytes.length, 12);
      return [h, f.bytes];
    }),
  ]);
}
