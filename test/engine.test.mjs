import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildDemoPcap } from "../server/fixtures.mjs";
import {
  codecs,
  validateConfig,
  mappingFor,
  decodeG711,
  makeWave,
} from "../server/rtp.mjs";
import {
  initEngine,
  prepare,
  buildIndex,
  pageFromIndex,
  packetDetail,
  getIndex,
  followStream,
  audioFor,
  exportCapture,
  run,
  stopAll,
} from "../server/engine.mjs";
import { combineFilter } from "../src/api.js";
let dir, capture;
before(async () => {
  await initEngine();
  dir = await mkdtemp(join(tmpdir(), "webshark-test-"));
  capture = {
    dir,
    config: { ports: [20000], heuristic: false, mappings: [] },
    revision: 1,
    processes: new Set(),
    queries: new Map(),
  };
  await writeFile(join(dir, "capture.pcap"), buildDemoPcap());
  await prepare(capture);
  capture.index = await buildIndex(capture);
});
after(async () => {
  stopAll();
  await rm(dir, { recursive: true, force: true });
});
function find(nodes, name) {
  for (const node of nodes) {
    if (node.name === name) return node;
    const result = find(node.fields || [], name);
    if (result) return result;
  }
}
const mapping = {
  pt: 96,
  codec: "PCMU",
  clockRate: 8000,
  channels: 1,
  scope: "stream",
  source: "10.10.0.10",
  destination: "10.10.0.20",
  srcPort: 20000,
  dstPort: 20002,
  ssrc: "0x12345678",
};
test("real PCAP index uses bounded pages and keeps original frame numbers", async () => {
  assert.equal(capture.index.count, 187);
  assert.equal((await pageFromIndex(capture.index, 0)).length, 100);
  const page = await pageFromIndex(capture.index, 1);
  assert.equal(page.length, 87);
  assert.equal(page[0].no, 101);
  assert.equal(capture.index.summary.media.length, 2);
  assert.equal(
    capture.index.summary.media.find((s) => s.ssrc === "0x12345678").lost,
    1,
  );
});
test("PDML fields have real filter expressions and exact byte offsets", async () => {
  const d = await packetDetail(capture, 8);
  assert.equal(d.bytes.length, 190);
  assert.equal(find(d.layers, "ip.src").filter, "ip.src == 192.168.1.108");
  assert.equal(find(d.layers, "ip.src").pos, 26);
  assert.deepEqual(d.bytes.slice(26, 30), [192, 168, 1, 108]);
  assert.equal(
    find(d.layers, "http.request.uri").filter,
    'http.request.uri == "/api/v1/dashboard"',
  );
  assert.ok(
    find(d.layers, "http").fields.some((f) =>
      f.label.startsWith("GET /api/v1/dashboard HTTP/1.1"),
    ),
  );
  assert.equal(find(d.layers, "fake-field-wrapper"), undefined);
});
test("right-click combinations preserve Boolean precedence and invalid syntax fails", async () => {
  const expression = combineFilter(
    "tcp || udp",
    "ip.src == 192.168.1.108",
    "and",
  );
  assert.equal(expression, "(tcp || udp) && (ip.src == 192.168.1.108)");
  const idx = await getIndex(capture, expression);
  const rows = await pageFromIndex(idx);
  assert.ok(rows.length > 0);
  assert.ok(rows.every((p) => p.source === "192.168.1.108"));
  const excluded = await getIndex(
    capture,
    combineFilter("", "ip.src == 192.168.1.108", "exclude"),
  );
  assert.ok(
    (await pageFromIndex(excluded)).every((p) => p.source !== "192.168.1.108"),
  );
  await assert.rejects(getIndex(capture, "this is invalid"));
  assert.equal(capture.queries.has("this is invalid"), false);
});
test("TCP and UDP following returns real bidirectional payloads", async () => {
  const tcp = await followStream(capture, "tcp", 0);
  assert.ok(tcp.chunks.some((c) => c.text.includes("GET /api/v1/dashboard")));
  assert.ok(tcp.chunks.some((c) => c.text.includes("HTTP/1.1 200 OK")));
  const udp = await followStream(
    capture,
    "udp",
    capture.index.summary.media[0].stream,
  );
  assert.ok(udp.chunks.length > 0);
});
test("PT settings validate ranges, codec allowlist, scope identity, duplicates and G.711 rate", () => {
  for (const m of [
    { ...mapping, pt: 95 },
    { ...mapping, pt: 128 },
    { ...mapping, codec: 'bad";os.execute()' },
    { ...mapping, ssrc: "oops" },
    { ...mapping, source: "wrong" },
    { ...mapping, clockRate: 16000 },
  ])
    assert.throws(() => validateConfig({ ports: [], mappings: [m] }));
  assert.throws(() => validateConfig({ ports: [70000], mappings: [] }));
  assert.throws(() =>
    validateConfig({ ports: [], mappings: [mapping, mapping] }),
  );
  assert.ok(codecs.find((c) => c.name === "OPUS"));
  const config = validateConfig({
    ports: [20000],
    mappings: [{ ...mapping, scope: "capture", codec: "PCMA" }, mapping],
  });
  assert.equal(
    mappingFor({ ...mapping, rtp: { pt: 96, ssrc: mapping.ssrc } }, config)
      .codec,
    "PCMU",
  );
});
test("same PT in opposite RTP streams is isolated; mapping affects filters, fields, jitter and WAV", async () => {
  capture.config = validateConfig({ ports: [20000], mappings: [mapping] });
  capture.revision++;
  capture.queries.clear();
  await prepare(capture);
  capture.index = await buildIndex(capture);
  const media = capture.index.summary.media;
  const a = media.find((s) => s.ssrc === "0x12345678"),
    b = media.find((s) => s.ssrc === "0x87654321");
  assert.deepEqual(a.codecs, ["PCMU"]);
  assert.deepEqual(b.codecs, ["Dynamic PT 96"]);
  assert.ok(a.maxJitter !== null);
  assert.equal(b.maxJitter, null);
  const idx = await getIndex(capture, 'webshark.rtp.codec == "PCMU"');
  assert.equal(idx.count, 69);
  const detail = await packetDetail(capture, a.firstNo);
  assert.equal(find(detail.layers, "webshark.rtp.codec").value, "PCMU");
  const wave = await audioFor(capture, media.indexOf(a));
  assert.equal(wave.toString("ascii", 0, 4), "RIFF");
  assert.equal(wave.readUInt32LE(24), 8000);
  assert.equal(wave.length, 44 + 70 * 160 * 2);
  assert.ok(
    wave
      .subarray(44 + 25 * 160 * 2, 44 + 26 * 160 * 2)
      .every((byte) => byte === 0),
  );
  await assert.rejects(audioFor(capture, media.indexOf(b)), /映射/);
});
test("Opus mapping invokes the real payload dissector rather than only changing a label", async () => {
  capture.config = validateConfig({
    ports: [20000],
    mappings: [{ ...mapping, codec: "OPUS", clockRate: 48000, channels: 2 }],
  });
  capture.revision++;
  capture.queries.clear();
  await prepare(capture);
  capture.index = await buildIndex(capture);
  const d = await packetDetail(capture, 49);
  assert.equal(find(d.layers, "webshark.rtp.codec").value, "OPUS");
  assert.ok(
    find(d.layers, "opus") || find(d.layers, "opus.toc"),
    "TShark Opus payload fields must be present",
  );
  await assert.rejects(audioFor(capture, 0), /PCMA/);
});
test("filtered export produces a readable PCAPNG with only selected packets", async () => {
  const out = join(dir, "export.pcapng");
  await exportCapture(capture, "http", out);
  const counts = await run([
    "-n",
    "-r",
    out,
    "-T",
    "fields",
    "-e",
    "frame.number",
  ]);
  assert.equal(counts.trim().split("\n").length, 6);
  assert.equal((await readFile(out)).readUInt32LE(0), 0x0a0d0d0a);
});
test("G.711 samples and timestamp wrap are decoded correctly", () => {
  assert.equal(decodeG711(0xff, "PCMU"), 0);
  assert.equal(decodeG711(0x7f, "PCMU"), 0);
  assert.equal(decodeG711(0xd5, "PCMA"), 8);
  assert.equal(decodeG711(0x55, "PCMA"), -8);
  const wave = makeWave(
    [
      { seq: 65535, timestamp: 0xffffffff, payload: Buffer.from([0xff]) },
      { seq: 0, timestamp: 0, payload: Buffer.from([0xff]) },
    ],
    mapping,
  );
  assert.equal(wave.length, 48);
});
