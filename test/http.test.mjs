import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { startTestServer, waitCapture } from "./helpers.mjs";
import { buildDemoPcap } from "../server/fixtures.mjs";
let server, capture;
before(async () => {
  server = await startTestServer();
});
after(async () => await server?.stop());
test("raw upload, status polling, real packet detail and pagination API", async () => {
  const res = await fetch(server.base + "/api/captures", {
    method: "POST",
    headers: {
      "X-File-Name": encodeURIComponent("测试抓包.pcap"),
      "Content-Type": "application/octet-stream",
    },
    body: buildDemoPcap(),
  });
  assert.equal(res.status, 202);
  capture = await waitCapture(server.base, (await res.json()).id);
  assert.equal(capture.status, "ready");
  assert.equal(capture.name, "测试抓包.pcap");
  const details = await fetch(
    `${server.base}/api/captures/${capture.id}/packets/8`,
  ).then((r) => r.json());
  assert.equal(details.no, 8);
  assert.equal(details.bytes.length, 190);
  const page = await fetch(
    `${server.base}/api/captures/${capture.id}/packets?page=1`,
  ).then((r) => r.json());
  assert.equal(page.packets[0].no, 101);
  assert.equal(page.total, 187);
});
test("configuration reanalysis persists scoped mapping and makes WAV playable", async () => {
  const config = {
    ports: [20000],
    heuristic: false,
    mappings: [
      {
        pt: 96,
        codec: "PCMA",
        clockRate: 8000,
        channels: 1,
        scope: "stream",
        source: "10.10.0.10",
        destination: "10.10.0.20",
        srcPort: 20000,
        dstPort: 20002,
        ssrc: "0x12345678",
      },
    ],
  };
  const res = await fetch(`${server.base}/api/captures/${capture.id}/config`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  assert.equal(res.status, 202);
  capture = await waitCapture(server.base, capture.id);
  assert.equal(capture.revision, 2);
  assert.deepEqual(capture.summary.media[0].codecs, ["PCMA"]);
  assert.deepEqual(capture.summary.media[1].codecs, ["Dynamic PT 96"]);
  const audio = await fetch(
    `${server.base}/api/captures/${capture.id}/audio?stream=0`,
  );
  assert.equal(audio.status, 200);
  assert.equal(audio.headers.get("content-type"), "audio/wav");
  assert.equal(
    Buffer.from(await audio.arrayBuffer()).toString("ascii", 0, 4),
    "RIFF",
  );
});
test("bad filter and invalid config return errors without destroying last valid result", async () => {
  const before = await fetch(`${server.base}/api/captures/${capture.id}`).then(
    (r) => r.json(),
  );
  const filter = await fetch(
    `${server.base}/api/captures/${capture.id}/packets?filter=this%20is%20invalid`,
  );
  assert.equal(filter.status, 400);
  const invalid = await fetch(
    `${server.base}/api/captures/${capture.id}/config`,
    { method: "PUT", body: JSON.stringify({ ports: [-1], mappings: [] }) },
  );
  assert.equal(invalid.status, 400);
  const after = await fetch(`${server.base}/api/captures/${capture.id}`).then(
    (r) => r.json(),
  );
  assert.equal(after.revision, before.revision);
  assert.equal(after.status, "ready");
});
test("cross-site requests are denied and invalid PCAP reports parse error", async () => {
  const denied = await fetch(server.base + "/api/demo", {
    method: "POST",
    headers: { Origin: "https://untrusted.example" },
  });
  assert.equal(denied.status, 403);
  const res = await fetch(server.base + "/api/captures", {
    method: "POST",
    headers: { "X-File-Name": "invalid.pcap" },
    body: Buffer.alloc(100, 42),
  });
  const c = await waitCapture(server.base, (await res.json()).id);
  assert.equal(c.status, "error");
  assert.ok(c.error);
});
