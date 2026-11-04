import { open } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

// Selection files reference immutable JSONL rows: byte offset, length, frame number.
export const REFERENCE_BYTES = 16;
export function encodeReference({ offset, length, no }) {
  const buffer = Buffer.allocUnsafe(REFERENCE_BYTES);
  buffer.writeDoubleLE(offset, 0);
  buffer.writeUInt32LE(length, 8);
  buffer.writeUInt32LE(no, 12);
  return buffer;
}
async function readRange(file, from, length) {
  const buffer = Buffer.allocUnsafe(length);
  let position = 0;
  while (position < length) {
    const { bytesRead } = await file.read(buffer, position, length - position, from + position);
    if (!bytesRead) throw new Error("索引不完整，请重新解析抓包");
    position += bytesRead;
  }
  return buffer;
}

// The unfiltered base index has one row per frame and offsets every 100 rows.
// Keep only the last block in memory, so sparse matches do not scan the whole file.
export async function frameReader(index) {
  const file = await open(index.path, "r");
  let block = -1, rows = [];
  return {
    async get(no) {
      if (!Number.isInteger(no) || no < 1 || no > index.count)
        throw new Error("过滤结果与原始索引不一致");
      const nextBlock = Math.floor((no - 1) / 100);
      if (nextBlock !== block) {
        block = nextBlock;
        const from = index.offsets[block], to = index.offsets[block + 1] ?? index.bytes;
        const data = await readRange(file, from, to - from);
        rows = [];
        let start = 0, end;
        while ((end = data.indexOf(10, start)) >= 0) {
          rows.push({ offset: from + start, length: end + 1 - start, data: data.subarray(start, end) });
          start = end + 1;
        }
      }
      const row = rows[(no - 1) % 100];
      if (!row) throw new Error("过滤结果与原始索引不一致");
      const record = JSON.parse(row.data.toString());
      if (record.no !== no) throw new Error("过滤结果与原始索引不一致");
      return { record, offset: row.offset, length: row.length, no };
    },
    close: () => file.close(),
  };
}

export async function selectionPage(index, start, count) {
  if (!count) return [];
  const refs = await open(index.path, "r");
  let source;
  try {
    source = await open(index.sourcePath, "r");
    const buffer = await readRange(refs, start * REFERENCE_BYTES, count * REFERENCE_BYTES);
    const rows = [];
    for (let i = 0; i < buffer.length; i += REFERENCE_BYTES)
      rows.push({ offset: buffer.readDoubleLE(i), length: buffer.readUInt32LE(i + 8), no: buffer.readUInt32LE(i + 12) });
    const result = [];
    for (let i = 0; i < rows.length;) {
      let j = i + 1, length = rows[i].length;
      while (j < rows.length && rows[j].offset === rows[i].offset + length && length + rows[j].length <= 4 * 1024 * 1024)
        length += rows[j++].length;
      const data = await readRange(source, rows[i].offset, length);
      let offset = 0;
      for (; i < j; i++) {
        const record = JSON.parse(data.subarray(offset, offset + rows[i].length).toString());
        if (record.no !== rows[i].no) throw new Error("过滤结果与原始索引不一致");
        result.push(record);
        offset += rows[i].length;
      }
    }
    return result;
  } finally {
    await refs.close();
    await source?.close();
  }
}

export async function* indexRecords(index) {
  if (index.kind === "selection") {
    for (let start = 0; start < index.count; start += 1000)
      yield* await selectionPage(index, start, Math.min(1000, index.count - start));
    return;
  }
  const stream = createReadStream(index.path, { encoding: "utf8" });
  const reader = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of reader) if (line) yield JSON.parse(line);
  } finally {
    reader.close();
    stream.destroy();
  }
}
