import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { diagnose } from "../server/diagnostics.mjs";

test("RTP quality keeps late anomalies and samples the full stream", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webshark-quality-"));
  try {
    const path = join(dir, "rows.jsonl");
    const rows = Array.from({ length: 2400 }, (_, i) => ({
      no: i + 1,
      time: i * .02 + (i >= 1900 ? .2 : 0),
      source: "10.0.0.1", destination: "10.0.0.2",
      srcPort: 5000, dstPort: 5002, fields: {},
      rtp: { seq: i + (i >= 1900 ? 2 : 0), timestamp: i * 160, ssrc: 123, pt: 8, clockRate: 8000 },
    }));
    await writeFile(path, rows.map((row) => JSON.stringify(row)).join("\n") + "\n");
    const result = await diagnose({ path, summary: { media: [] } });
    const quality = result.rtpQuality[0];
    assert.ok(quality.timeline.length <= 1000);
    assert.ok(quality.timeline.at(-1).time > 40);
    assert.ok(quality.anomalies.some((row) => row.no === 1901 && row.status === "gap:2"));
    assert.ok(quality.anomalies.some((row) => row.no === 1901 && row.gapMs > 100));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
