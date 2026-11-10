import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCapture } from "../src/compose.js";
import { initEngine, prepare, buildIndex, pageFromIndex, stopAll, run, argsFor } from "../server/engine.mjs";
import { canUseFilterSession, closeFilterSession, filterSessionStatus, initFilterSession } from "../server/filter-session.mjs";

test("first page is readable before the first 50 MiB index segment completes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webtshark-progress-"));
  try {
    await initEngine();
    const capture = { dir, revision: 1, config: { ports: [], mappings: [], decodeAs: [], heuristic: false }, processes: new Set() };
    await writeFile(join(dir, "capture.pcap"), buildCapture({ protocol: "RTP", count: 10000 }));
    await prepare(capture);
    const publications = [], reads = [];
    Object.defineProperty(capture, "partialIndex", { set(value) {
      if (!value) return;
      publications.push({ count: value.count, segments: capture.segments?.length || 0 });
      reads.push(pageFromIndex(value).then((rows) => {
        assert.equal(rows.length, 100);
        assert.equal(rows[0].no, 1);
        assert.equal(rows[99].no, 100);
      }));
    } });
    const index = await buildIndex(capture, "", true);
    await Promise.all(reads);
    assert.equal(publications[0].count, 100);
    assert.equal(publications[0].segments, 0);
    assert.ok(capture.firstPageMs < index.buildMs);
    assert.equal(index.count, 10000);
    assert.equal((await pageFromIndex(index, 99))[99].no, 10000);
  } finally { stopAll(); await rm(dir, { recursive: true, force: true }); }
});

test("optional persistent tcp contains filtering agrees with TShark and respects decoding settings", { skip: !process.env.SHARKD_PATH }, async () => {
  const dir = await mkdtemp(join(tmpdir(), "webtshark-filter-session-"));
  try {
    await initEngine();
    assert.equal(filterSessionStatus().ready, true, filterSessionStatus().error);
    const capture = { dir, revision: 1, config: { ports: [], mappings: [], decodeAs: [], heuristic: false }, processes: new Set() };
    await writeFile(join(dir, "capture.pcap"), buildCapture({ protocol: "MRCPv2", count: 6000, body: "INVITE example", srcPort: 19001, dstPort: 80 }));
    await prepare(capture);
    capture.index = await buildIndex(capture);
    for (const filter of ['tcp contains "INVITE"', 'tcp contains "absent-marker"', 'tcp contains 00:50']) {
      const index = await buildIndex(capture, filter);
      const expected = (await run([...argsFor(capture), "-Y", filter, "-T", "fields", "-e", "frame.number"], { maxBytes: 4 * 1024 * 1024 })).trim().split("\n").filter(Boolean).map(Number);
      assert.equal(index.filterEngine, "sharkd", filterSessionStatus().error);
      const actual = [];
      for (let page = 0; page * 1000 < index.count; page++)
        actual.push(...(await pageFromIndex(index, page, 1000)).map((p) => p.no));
      assert.deepEqual(actual, expected, filter);
    }
    assert.equal(canUseFilterSession(capture, 'tcp.reassembled.data contains "INVITE"'), false);
    assert.equal(canUseFilterSession(capture, 'tcp contains "INVITE" && http'), false);
    for (const config of [{ ports: [80] }, { mappings: [{ pt: 96 }] }, { heuristic: true }, { decodeAs: [{ port: 80 }] }])
      assert.equal(canUseFilterSession({ ...capture, config: { ...capture.config, ...config } }, 'tcp contains "INVITE"'), false);
    closeFilterSession();
    const again = await buildIndex(capture, 'tcp contains "example"');
    assert.equal(again.count, 6000);
    assert.equal(again.filterEngine, "sharkd");
    await initFilterSession("TShark 0.0.0");
    assert.equal(filterSessionStatus().ready, false);
    assert.equal((await buildIndex(capture, 'tcp contains "INVITE"')).filterEngine, "tshark");
  } finally { stopAll(); await rm(dir, { recursive: true, force: true }); }
});

test("streamed extraction waits for slow consumers and propagates consumer failures", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webtshark-stream-"));
  try {
    await initEngine();
    const capture = {dir, revision:1, config:{ports:[],mappings:[],decodeAs:[]},processes:new Set()};
    await writeFile(join(dir,"capture.pcap"),buildCapture({protocol:"RTP",count:2000}));
    await prepare(capture);
    const args=[...argsFor(capture),"-T","fields","-e","frame.number"];
    let count=0;
    await run(args,{onLine:async line=>{
      assert.equal(Number(line),++count);
      if(count%100===0) await new Promise(resolve=>setTimeout(resolve,2));
    }});
    assert.equal(count,2000);
    await assert.rejects(run(args,{onLine:()=>{throw new Error("consumer failed");}}),/consumer failed/);
    assert.equal(capture.processes.size,0);
  } finally {stopAll();await rm(dir,{recursive:true,force:true});}
});
