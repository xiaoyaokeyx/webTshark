import test from "node:test";
import assert from "node:assert/strict";
import {
  createSequenceTracker,
  observeSequence,
  finishSequenceTracker,
  extendTimestamp,
} from "../server/rtp.mjs";

test("RTP sequence analysis ignores reordering and identifies real gaps", () => {
  const reordered = createSequenceTracker();
  for (const sequence of [100, 102, 101, 103]) observeSequence(reordered, sequence);
  const result = finishSequenceTracker(reordered);
  assert.equal(result.lost, 0);
  assert.deepEqual(result.observations.map((item) => item.lostBefore), [0, 0, 0, 0]);

  const gap = createSequenceTracker();
  for (const sequence of [100, 102]) observeSequence(gap, sequence);
  assert.equal(finishSequenceTracker(gap).lost, 1);
});

test("RTP sender restart does not become thousands of phantom lost packets", () => {
  const tracker = createSequenceTracker();
  for (const sequence of [10000, 10001, 1, 2]) observeSequence(tracker, sequence);
  const result = finishSequenceTracker(tracker);
  assert.equal(result.lost, 0);
  assert.equal(new Set(result.observations.map((item) => item.segment)).size, 2);
});

test("RTP timestamp wrap stays monotonic while a large jump starts a new timeline", () => {
  const wrapped = extendTimestamp(0xffffff80, 0xffffff80, 32);
  assert.equal(wrapped.restarted, false);
  assert.equal(wrapped.extended, 0x100000020);
  const restarted = extendTimestamp(100000, 100000, 100);
  assert.equal(restarted.restarted, true);
});
