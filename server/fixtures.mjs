import { packets } from "../src/packetData.js";

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
