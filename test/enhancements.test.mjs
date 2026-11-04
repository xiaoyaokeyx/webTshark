import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildCapture, buildVoipCalls, checksum } from "../src/compose.js";
import {
  diagnose,
  compareIndexes,
  reportHtml,
} from "../server/diagnostics.mjs";
import { startTestServer, waitCapture } from "./helpers.mjs";
import { buildDemoPcap } from "../server/fixtures.mjs";
import { run as tsharkRun } from "../server/engine.mjs";

test("all constructor protocol templates are decoded by real TShark", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webshark-compose-"));
  try {
    for (const [protocol, transport, port, field] of [
      ["SIP", "udp", 5060, "sip.Method"],
      ["SDP", "udp", 5060, "sdp.media.port"],
      ["RTP", "udp", 20000, "rtp.seq"],
      ["RTCP", "udp", 20001, "rtcp.senderssrc"],
      ["MRCPv2", "tcp", 1544, "mrcpv2.Method"],
    ]) {
      const path = join(dir, `${protocol}.pcap`);
      await writeFile(
        path,
        buildCapture({ protocol, count: 3, srcPort: port, dstPort: port }),
      );
      const decoder = {
        SIP: "sip",
        SDP: "sip",
        RTP: "rtp",
        RTCP: "rtcp",
        MRCPv2: "mrcpv2",
      }[protocol];
      const output = await tsharkRun([
        "-n",
        "-r",
        path,
        "-d",
        `${transport}.port==${port},${decoder}`,
        "-T",
        "fields",
        "-e",
        field,
      ]);
      assert.equal(
        output.trim().split("\n").filter(Boolean).length,
        3,
        `${protocol} native fields`,
      );
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("constructed packets have exact counts, valid IP/transport checksums and MRCP lengths", () => {
  for (const protocol of ["SIP", "SDP", "RTP", "RTCP", "MRCPv2"]) {
    const bytes = buildCapture({ protocol, count: 3, sequence: 65535 }),
      b = Buffer.from(bytes);
    let offset = 24,
      count = 0;
    while (offset < b.length) {
      const length = b.readUInt32LE(offset + 8),
        packet = [...b.subarray(offset + 16, offset + 16 + length)];
      assert.equal(
        checksum(packet.slice(14, 34)),
        0,
        `${protocol} IP checksum`,
      );
      const transport = packet.slice(34),
        pseudo = [
          ...packet.slice(26, 34),
          0,
          packet[23],
          transport.length >> 8,
          transport.length & 255,
          ...transport,
        ];
      assert.equal(checksum(pseudo), 0, `${protocol} transport checksum`);
      if (protocol === "MRCPv2") {
        const payload = Buffer.from(transport.slice(20)).toString();
        assert.equal(Number(payload.split(" ")[1]), Buffer.byteLength(payload));
      }
      if (protocol === "RTP")
        assert.equal(
          (transport[10] << 8) | transport[11],
          (65535 + count) & 65535,
        );
      offset += 16 + length;
      count++;
    }
    assert.equal(count, 3);
    assert.equal(offset, b.length);
  }
  assert.throws(() => buildCapture({ count: 10001 }));
  assert.throws(() => buildCapture({ source: "1.2.3.256" }));
  assert.throws(() => buildCapture({ callId: "x\r\nX: bad" }));
});

test("multi-call VoIP constructor keeps each SIP dialog independent", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webshark-voip-calls-"));
  try {
    const path = join(dir, "multi-call.pcap");
    await writeFile(path, buildVoipCalls({ callCount: 6 }));
    const output = await tsharkRun([
      "-n",
      "-r",
      path,
      "-Y",
      "sip.Call-ID",
      "-T",
      "fields",
      "-e",
      "sip.Call-ID",
    ]);
    const callIds = new Set(
      output
        .split("\n")
        .map((value) => value.trim())
        .filter(Boolean),
    );
    assert.equal(callIds.size, 6);
    assert.equal(output.trim().split("\n").filter(Boolean).length, 31);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diagnostics distinguish capture-limited SIP evidence and escape report data", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webshark-diagnosis-"));
  try {
    const fields = {
      "sip.Call-ID": "<test>",
      "sip.CSeq.seq": "1",
      "sip.CSeq.method": "INVITE",
      "sip.Via.branch": "x",
      "sip.from.tag": "a",
    };
    const rows = [
      {
        no: 1,
        time: 0,
        source: "a",
        destination: "b",
        length: 50,
        info: "INVITE",
        fields,
      },
      {
        no: 2,
        time: 0.1,
        source: "b",
        destination: "a",
        length: 50,
        info: "200 OK",
        fields: { ...fields, "sip.Status-Code": "200" },
      },
    ];
    const path = join(dir, "index.jsonl");
    await writeFile(path, rows.map(JSON.stringify).join("\n") + "\n");
    const index = {
      path,
      summary: { count: 2, bytes: 100, duration: 0.1, media: [] },
    };
    const d = await diagnose(index);
    assert.ok(
      d.findings.some((f) => f.kind === "sip-no-ack" && f.packets.includes(2)),
    );
    assert.ok(
      !reportHtml(d, "<script>x</script>").includes("<script>x</script>"),
    );
    const diff = await compareIndexes(index, index, {
      mode: "call",
      toleranceMs: 0,
    });
    assert.equal(diff.matched, 2);
    assert.equal(diff.missing, 0);
    assert.equal(diff.extra, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("task, compose, diagnosis, compare, navigation and report APIs use actual capture data", async () => {
  const server = await startTestServer();
  try {
    const request = async (path, options) => {
      const r = await fetch(server.base + "/api" + path, options);
      assert.ok(r.ok, await (!r.ok ? r.text() : Promise.resolve("")));
      return r;
    };
    const upload = async (name, data) => {
      const c = await (
        await request("/captures", {
          method: "POST",
          headers: { "X-File-Name": name },
          body: data,
        })
      ).json();
      const ready = await waitCapture(server.base, c.id);
      assert.equal(ready.status, "ready", ready.error);
      return ready;
    };
    const a = await upload("first.pcap", buildDemoPcap()),
      b = await upload("second.pcap", buildDemoPcap());
    for (const c of [a, b]) {
      await request(`/captures/${c.id}/config`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ports: [20000],
          mappings: [],
          decodeAs: [],
          heuristic: false,
        }),
      });
      assert.equal((await waitCapture(server.base, c.id)).status, "ready");
    }
    const d = await (await request(`/captures/${a.id}/diagnostics`)).json();
    assert.equal(d.calls.length, 1);
    assert.ok(d.calls[0].sdp.length >= 2);
    assert.equal(d.rtpQuality.length, 2);
    assert.ok(d.messages.some((m) => m.body.includes("Content-Length")));
    const diff = await (
      await request("/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          a: a.id,
          b: b.id,
          mode: "call",
          toleranceMs: 0,
        }),
      })
    ).json();
    assert.equal(diff.matched, 7);
    assert.equal(diff.missing, 0);
    const located = await (
      await request(`/captures/${a.id}/locate?no=150&size=100`)
    ).json();
    assert.equal(located.no, 150);
    assert.equal(located.page, 1);
    const tasks = await (await request("/tasks")).json();
    assert.equal(tasks.tasks.length, 2);
    assert.ok(tasks.tasks.every((t) => t.logs.length >= 2));
    assert.ok(tasks.tasks.every((t) => t.segments.length));
    const html = await (
      await request(`/captures/${a.id}/report?format=html`)
    ).text();
    assert.ok(html.startsWith("<!doctype html>"));
    assert.ok(html.includes("SIP"));
    const single = await (
      await request("/compose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ protocol: "SIP", count: 1 }),
      })
    ).arrayBuffer();
    const c = await upload("single.pcap", single);
    assert.equal(c.summary.count, 1);
    const retry = await (
      await request(`/captures/${c.id}/retry`, { method: "POST" })
    ).json();
    assert.ok(["queued", "indexing"].includes(retry.status));
    assert.equal((await waitCapture(server.base, c.id)).status, "ready");
  } finally {
    await server.stop();
  }
});

test(
  "running parse can pause, resume and return complete packet counts",
  { skip: process.platform === "win32" },
  async () => {
    const server = await startTestServer();
    try {
      const data = buildCapture({
        protocol: "RTP",
        count: 10000,
        payloadSize: 1200,
        srcPort: 20000,
        dstPort: 21000,
      });
      const c = await (
        await fetch(server.base + "/api/captures", {
          method: "POST",
          headers: { "X-File-Name": "pause.pcap" },
          body: data,
        })
      ).json();
      const pausedResponse = await fetch(
        `${server.base}/api/captures/${c.id}/pause`,
        { method: "POST" },
      );
      assert.equal(pausedResponse.status, 200);
      assert.equal((await pausedResponse.json()).status, "paused");
      await new Promise((r) => setTimeout(r, 100));
      const paused = await (
        await fetch(`${server.base}/api/captures/${c.id}`)
      ).json();
      assert.equal(paused.status, "paused");
      assert.equal(
        (
          await fetch(`${server.base}/api/captures/${c.id}/resume`, {
            method: "POST",
          })
        ).status,
        200,
      );
      const ready = await waitCapture(server.base, c.id);
      assert.equal(ready.status, "ready", ready.error);
      assert.equal(ready.summary.count, 10000);
      const page = await (
        await fetch(`${server.base}/api/captures/${c.id}/progress-packets`)
      ).json();
      assert.equal(page.packets.length, 100);
    } finally {
      await server.stop();
    }
  },
);
