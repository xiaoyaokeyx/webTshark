import { writeFile, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { basename } from "node:path";
const [file, output = "webtshark-report.json", base = "http://127.0.0.1:3001"] =
  process.argv.slice(2);
if (!file)
  throw new Error(
    "用法: node scripts/analyze.mjs capture.pcap report.json [http://127.0.0.1:3001]",
  );
async function request(path, options) {
  const res = await fetch(new URL(path, base), options);
  if (!res.ok) throw new Error(await res.text());
  return res;
}
let c = await (
  await request("/api/captures", {
    method: "POST",
    headers: {
      "X-File-Name": encodeURIComponent(basename(file)),
      "Content-Length": String((await stat(file)).size),
    },
    body: createReadStream(file),
    duplex: "half",
  })
).json();
const deadline = Date.now() + 30 * 60 * 1000;
while (!["ready", "error", "cancelled"].includes(c.status)) {
  if (Date.now() > deadline)
    throw new Error("等待解析超时，任务仍可在任务中心查看");
  await new Promise((r) => setTimeout(r, 500));
  c = await (await request(`/api/captures/${c.id}`)).json();
}
if (c.status !== "ready") throw new Error(c.error || c.status);
const res = await request(
  `/api/captures/${c.id}/report${output.endsWith(".html") ? "?format=html" : ""}`,
);
await writeFile(output, await res.text());
console.log(output);
