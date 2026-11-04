const PCAP_MAGICS = new Set([
  "a1b2c3d4",
  "d4c3b2a1",
  "a1b23c4d",
  "4d3cb2a1",
]);
const PCAPNG_MAGIC = "0a0d0d0a";
const PCAPNG_BYTE_ORDER_MAGICS = new Set(["1a2b3c4d", "4d3c2b1a"]);

function bytesOf(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer)
    return new Uint8Array(input);
  if (ArrayBuffer.isView(input))
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  return new Uint8Array(input || []);
}

function hex(bytes, start, length) {
  return Array.from(bytes.subarray(start, start + length), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * Identify a capture from its binary header, not from the file name.
 * Returns "pcap", "pcapng", or null when the header is unknown/incomplete.
 */
export function detectCaptureFormat(input) {
  const bytes = bytesOf(input);
  if (bytes.length < 4) return null;
  const magic = hex(bytes, 0, 4);
  if (PCAP_MAGICS.has(magic))
    return bytes.length >= 24 ? "pcap" : null;
  if (magic !== PCAPNG_MAGIC || bytes.length < 12) return null;
  return PCAPNG_BYTE_ORDER_MAGICS.has(hex(bytes, 8, 4)) ? "pcapng" : null;
}

export function captureFormatLabel(format) {
  return format === "pcapng" ? "PCAPNG" : format === "pcap" ? "PCAP" : "";
}

export function captureHeaderError(input) {
  const format = detectCaptureFormat(input);
  return format
    ? null
    : "文件头不是受支持的 PCAP 或 PCAPNG 抓包文件";
}
