import test from "node:test";
import assert from "node:assert/strict";
import { detectCaptureFormat } from "../src/captureFormat.js";

test("capture format detection uses PCAP and PCAPNG header magic", () => {
  const pcap = new Uint8Array(24);
  pcap.set([0xd4, 0xc3, 0xb2, 0xa1]);
  assert.equal(detectCaptureFormat(pcap), "pcap");

  const pcapng = new Uint8Array(28);
  pcapng.set([0x0a, 0x0d, 0x0d, 0x0a]);
  pcapng.set([0x1a, 0x2b, 0x3c, 0x4d], 8);
  assert.equal(detectCaptureFormat(pcapng), "pcapng");

  const renamedText = new Uint8Array(100).fill(0x42);
  assert.equal(detectCaptureFormat(renamedText), null);
});
