import { mkdir, open, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { buildCapture } from "../src/compose.js";
import {
  initEngine,
  prepare,
  buildIndex,
  pageFromIndex,
  engineVersion,
} from "../server/engine.mjs";
const mb = Number(process.argv[2] || 200);
if (!Number.isFinite(mb) || mb < 1 || mb > 2048)
  throw new Error("size MiB must be 1–2048");
const dir = resolve("artifacts", `large-${Date.now()}`);
await mkdir(dir, { recursive: true });
const chunk = Buffer.from(
  buildCapture({
    protocol: "RTP",
    pt: 0,
    srcPort: 20000,
    dstPort: 21000,
    count: 1000,
    payloadSize: 1200,
  }),
);
const file = await open(join(dir, "capture.pcap"), "w");
let bytes = 24,
  packets = 0;
try {
  await file.write(chunk.subarray(0, 24));
  while (bytes < mb * 1024 * 1024) {
    await file.write(chunk.subarray(24));
    bytes += chunk.length - 24;
    packets += 1000;
  }
} finally {
  await file.close();
}
await initEngine();
const c = {
  dir,
  revision: 1,
  size: bytes,
  config: { ports: [20000], mappings: [], decodeAs: [] },
  processes: new Set(),
  queries: new Map(),
};
await prepare(c);
let peak = process.memoryUsage().rss;
const sampler = setInterval(() => {
  peak = Math.max(peak, process.memoryUsage().rss);
}, 50);
const started = performance.now();
let index;
try {
  index = await buildIndex(c, "", true);
} finally {
  clearInterval(sampler);
}
const elapsedMs = performance.now() - started,
  pageStart = performance.now(),
  page = await pageFromIndex(index, Math.floor((index.count - 1) / 100), 100);
if (index.count !== packets)
  throw new Error(`packet count ${index.count} != ${packets}`);
const result = {
  tshark: engineVersion,
  inputBytes: bytes,
  packets,
  elapsedMs,
  lastPageMs: performance.now() - pageStart,
  lastPageCount: page.length,
  indexBytes: index.bytes,
  segments: c.segments.length,
  nodePeakRss: peak,
  note: "重复的合成 RTP 数据，仅测流式索引/分页；不代表真实 SIP/TCP 重组性能。RSS 不包括 TShark 子进程。",
};
await writeFile(join(dir, "benchmark.json"), JSON.stringify(result, null, 2));
console.log(JSON.stringify({ ...result, directory: dir }, null, 2));
