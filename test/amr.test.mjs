import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildDemoPcap } from "../server/fixtures.mjs";
import { codecs, validateConfig } from "../server/rtp.mjs";
import {
  initEngine,
  prepare,
  buildIndex,
  packetDetail,
  getIndex,
  audioFor,
  stopAll,
} from "../server/engine.mjs";

const flows = [
  { codec: "AMR", clockRate: 8000, octetAlign: false, speechBits: 95 },
  { codec: "AMR-WB", clockRate: 16000, octetAlign: true, speechBits: 132 },
  { codec: "AMR", clockRate: 8000, octetAlign: true, speechBits: 95 },
  { codec: "AMR-WB", clockRate: 16000, octetAlign: false, speechBits: 132 },
];
const identity = {
  pt: 96,
  channels: 1,
  scope: "stream",
  source: "10.10.0.10",
  destination: "10.10.0.20",
  srcPort: 20000,
  dstPort: 20002,
};

// RFC 4867: CMR=15, F=0, FT=0, Q=1, one speech frame.
function payloadFor(flow) {
  if (flow.octetAlign)
    return Buffer.concat([
      Buffer.from([0xf0, 0x04]),
      Buffer.alloc(Math.ceil(flow.speechBits / 8)),
    ]);
  const bits = "1111000001" + "0".repeat(flow.speechBits);
  return Buffer.from(
    bits
      .padEnd(Math.ceil(bits.length / 8) * 8, "0")
      .match(/.{8}/g)
      .map((byte) => parseInt(byte, 2)),
  );
}

function amrPcap() {
  const base = buildDemoPcap({ rtpOnly: true });
  const records = [];
  for (let frame = 0; frame < 2; frame++) {
    flows.forEach((flow, i) => {
      const packet = Buffer.concat([base.subarray(40, 94), payloadFor(flow)]);
      packet.writeUInt16BE(packet.length - 14, 16);
      packet.writeUInt16BE(0, 24);
      let sum = 0;
      for (let offset = 14; offset < 34; offset += 2)
        sum += packet.readUInt16BE(offset);
      while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
      packet.writeUInt16BE(~sum & 0xffff, 24);
      packet.writeUInt16BE(packet.length - 34, 38);
      packet.writeUInt16BE(frame + 1, 44);
      packet.writeUInt32BE((frame * flow.clockRate) / 50, 46);
      packet.writeUInt32BE(i + 1, 50);
      const record = Buffer.alloc(16);
      record.writeUInt32LE(1700000000);
      record.writeUInt32LE(frame * 20000 + i * 1000, 4);
      record.writeUInt32LE(packet.length, 8);
      record.writeUInt32LE(packet.length, 12);
      records.push(record, packet);
    });
  }
  return Buffer.concat([base.subarray(0, 24), ...records]);
}

function find(nodes, name) {
  for (const node of nodes) {
    if (node.name === name) return node;
    const child = find(node.fields || [], name);
    if (child) return child;
  }
}

let dir;
before(async () => {
  await initEngine();
  dir = await mkdtemp(join(tmpdir(), "webshark-amr-"));
});
after(async () => {
  stopAll();
  await rm(dir, { recursive: true, force: true });
});

test("AMR mappings enforce codec clocks and validate octet-align", () => {
  for (const flow of flows) {
    const entry = { ...identity, ...flow, ssrc: "0x1" };
    const config = validateConfig({ ports: [], mappings: [entry] });
    assert.equal(config.mappings[0].octetAlign, flow.octetAlign);
    assert.ok(codecs.find((c) => c.name === flow.codec)?.dissector);
    assert.throws(
      () =>
        validateConfig({
          ports: [],
          mappings: [{ ...entry, clockRate: 48000 }],
        }),
      /RTP 时钟/,
    );
    assert.throws(
      () =>
        validateConfig({
          ports: [],
          mappings: [{ ...entry, octetAlign: "1" }],
        }),
      /octet-align/,
    );
  }
  const { octetAlign, ...entry } = { ...identity, ...flows[0], ssrc: "0x1" };
  assert.equal(
    validateConfig({ ports: [], mappings: [entry] }).mappings[0].octetAlign,
    false,
  );
});

test("same PT supports AMR and AMR-WB with both payload formats in separate SSRC streams", async () => {
  const capture = {
    dir,
    config: validateConfig({
      ports: [20000],
      mappings: flows.map((flow, i) => ({
        ...identity,
        ...flow,
        ssrc: `0x${i + 1}`,
      })),
    }),
    revision: 1,
    processes: new Set(),
    queries: new Map(),
  };
  await writeFile(join(dir, "capture.pcap"), amrPcap());
  await prepare(capture);
  capture.index = await buildIndex(capture);
  assert.equal(capture.index.count, 8);
  assert.equal(capture.index.summary.media.length, 4);
  for (const [i, flow] of flows.entries()) {
    const media = capture.index.summary.media.find(
      (s) => Number(s.ssrc) === i + 1,
    );
    assert.deepEqual(media.codecs, [flow.codec]);
    assert.ok(Math.abs(media.maxJitter) < 1e-9);
    const detail = await packetDetail(capture, media.firstNo);
    const band = flow.codec === "AMR" ? "nb" : "wb";
    assert.equal(find(detail.layers, "webshark.rtp.codec").value, flow.codec);
    assert.equal(
      Number(find(detail.layers, "webshark.rtp.clock_rate").value),
      flow.clockRate,
    );
    assert.equal(Number(find(detail.layers, `amr.${band}.cmr`).value), 15);
    assert.equal(Number(find(detail.layers, `amr.${band}.toc.ft`).value), 0);
    assert.ok(
      find(detail.layers, "amr.frame_data"),
      "native AMR speech payload fields",
    );
    assert.equal(
      Number(find(detail.layers, "amr.payload_decoded_as").value),
      flow.octetAlign ? 0 : 1,
    );
    assert.equal(find(detail.layers, "_ws.lua.error"), undefined);
    assert.equal(find(detail.layers, "_ws.malformed"), undefined);
  }
  const filtered = await getIndex(
    capture,
    'webshark.rtp.codec == "AMR-WB" && amr.payload_decoded_as == 1',
  );
  assert.equal(filtered.count, 2);
  await assert.rejects(audioFor(capture, 0), /PCMA/);
});
