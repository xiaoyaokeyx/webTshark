import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSipCalls,
  sipFlowRows,
  sipEndpoints,
  sipMessage,
} from "../src/sipFlow.js";

const packet = (
  no,
  time,
  id,
  source,
  destination,
  info,
  method = "INVITE",
  stream = 0,
) => ({
  no,
  time,
  protocol: "SIP",
  info,
  source,
  destination,
  transport: "UDP",
  stream,
  fields: { "sip.Call-ID": id, "sip.CSeq.method": method },
});
test("interleaved SIP dialogs keep identity, endpoints and per-call delta on a merged timeline", () => {
  const packets = [
    packet(1, 0, "ab", "A", "B", "INVITE sip:b"),
    packet(2, 0.01, "cd", "C", "D", "INVITE sip:d"),
    packet(3, 0.05, "ab", "B", "A", "100 Trying"),
    packet(4, 0.08, "cd", "D", "C", "486 Busy Here"),
    packet(5, 9, "ab", "A", "B", "BYE sip:b", "BYE"),
  ];
  const calls = buildSipCalls(packets);
  assert.equal(calls.length, 2);
  assert.deepEqual(
    calls.map((c) => c.packets.map((p) => p.no)),
    [
      [1, 3, 5],
      [2, 4],
    ],
  );
  assert.deepEqual(sipEndpoints(calls.flatMap((c) => c.packets)), [
    "A",
    "B",
    "C",
    "D",
  ]);
  assert.deepEqual(
    sipFlowRows(calls).map((r) => r.delta),
    [null, null, 50, 70, 8950],
  );
  assert.equal(calls[0].status, "已结束");
  assert.equal(calls[1].status, "呼叫失败");
});
test("Call-ID separates calls sharing one UDP stream and retains proxy hops", () => {
  const calls = buildSipCalls([
    packet(1, 0, "one", "A", "B", "INVITE sip:b"),
    packet(2, 1, "two", "A", "B", "INVITE sip:b"),
    packet(3, 2, "one", "B", "C", "INVITE sip:c"),
  ]);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0].endpoints, ["A", "B", "C"]);
  assert.equal(
    sipMessage(packet(4, 3, "one", "C", "B", "500 Server Internal Error")).code,
    500,
  );
});
