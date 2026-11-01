import http from "node:http";
import { createReadStream, createWriteStream } from "node:fs";
import {
  mkdir,
  readFile,
  writeFile,
  readdir,
  rm,
  stat,
} from "node:fs/promises";
import { join, resolve, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import {
  initEngine,
  engineVersion,
  prepare,
  buildIndex,
  getIndex,
  pageFromIndex,
  packetDetail,
  followStream,
  audioFor,
  waveformFor,
  exportCapture,
  suggestFields,
  resolveFilter,
  stopAll,
} from "./engine.mjs";
import { validateConfig, codecs } from "./rtp.mjs";
import { buildDemoPcap } from "./fixtures.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
function flagValue(name) {
  const args = process.argv.slice(2);
  const index = args.indexOf(name);
  if (index !== -1) return args[index + 1] || "";
  const inline = args.find((arg) => arg.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : "";
}
const listenHost =
  flagValue("--host") || flagValue("--bind") || process.env.HOST || "0.0.0.0";
const listenPort =
  Number(flagValue("--port") || process.env.PORT) || 3001;
const dataRoot = resolve(process.env.DATA_DIR || join(root, ".webshark"));
const DEMO_VERSION = 3;
await mkdir(dataRoot, { recursive: true, mode: 0o700 });
const captures = new Map();
const maxUpload = Number(process.env.MAX_UPLOAD_BYTES) || 1024 ** 3;
let engineError = null;
await initEngine().catch((e) => (engineError = e.message));
function snapshot(c) {
  return {
    id: c.id,
    name: c.name,
    size: c.size,
    status: c.status,
    error: c.error,
    processed: c.processed,
    revision: c.revision,
    config: c.config,
    summary: c.status === "ready" ? c.index?.summary : null,
    created: c.created,
    demo: c.demo,
    demoVersion: c.demoVersion || null,
  };
}
async function save(c) {
  const data = snapshot(c);
  if (c.index) data.index = { ...c.index };
  await writeFile(join(c.dir, "manifest.json"), JSON.stringify(data));
}
for (const name of await readdir(dataRoot)) {
  if (!/^[a-f0-9-]{36}$/.test(name)) continue;
  try {
    const stored = JSON.parse(
      await readFile(join(dataRoot, name, "manifest.json"), "utf8"),
    );
    if (stored.status !== "ready") continue;
    const c = {
      ...stored,
      dir: join(dataRoot, name),
      queries: new Map(),
      relationQueries: new Map(),
      processes: new Set(),
      cancelled: false,
    };
    await stat(c.index.path);
    captures.set(c.id, c);
  } catch {
    /* An incomplete upload is not an analysis session. */
  }
}
function requireEngine() {
  if (engineError) throw Object.assign(new Error(engineError), { status: 503 });
}
function getCapture(id, ready = true) {
  const c = captures.get(id);
  if (!c) throw Object.assign(new Error("抓包不存在"), { status: 404 });
  if (ready && c.status !== "ready")
    throw Object.assign(new Error(c.error || "抓包仍在解析，请稍候"), {
      status: 409,
    });
  return c;
}
async function analyze(c, config = c.config) {
  const previous = { config: c.config, index: c.index, revision: c.revision };
  c.status = "indexing";
  c.error = null;
  c.cancelled = false;
  c.processed = 0;
  c.config = config;
  c.revision++;
  c.queries.clear();
  c.relationQueries?.clear();
  try {
    await prepare(c);
    const index = await buildIndex(c, "", true);
    c.index = index;
    c.status = "ready";
    await save(c);
  } catch (e) {
    if (previous.index && !c.cancelled) {
      Object.assign(c, previous);
      c.status = "ready";
      c.error = `设置未生效，已恢复上次结果：${e.message}`;
    } else {
      c.status = c.cancelled ? "cancelled" : "error";
      c.error = e.message;
    }
    await save(c).catch(() => {});
  }
}
async function newCapture(name, demo = false) {
  if (captures.size >= 30)
    throw Object.assign(new Error("最多保留 30 个抓包，请先删除不需要的文件"), {
      status: 409,
    });
  if (
    [...captures.values()].filter((c) =>
      ["uploading", "indexing"].includes(c.status),
    ).length >= 2
  )
    throw Object.assign(new Error("已有 2 个导入任务，请稍后重试"), {
      status: 429,
    });
  const id = randomUUID(),
    dir = join(dataRoot, id);
  await mkdir(dir, { mode: 0o700 });
  const c = {
    id,
    dir,
    name: name.slice(0, 200),
    demo,
    size: 0,
    created: new Date().toISOString(),
    status: "uploading",
    processed: 0,
    revision: 0,
    demoVersion: demo ? DEMO_VERSION : null,
    config: { ports: [], heuristic: false, mappings: [], decodeAs: [] },
    queries: new Map(),
    relationQueries: new Map(),
    processes: new Set(),
  };
  captures.set(id, c);
  return c;
}
function json(res, value, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(value));
}
async function readJson(req) {
  let text = "";
  for await (const chunk of req) {
    text += chunk;
    if (text.length > 64 * 1024)
      throw Object.assign(new Error("请求过大"), { status: 413 });
  }
  try {
    return JSON.parse(text || "{}");
  } catch {
    throw new Error("JSON 格式不正确");
  }
}
function requestGuard(req) {
  const host = req.headers.host || "";
  const allowed = (process.env.ALLOWED_HOSTS
    ? process.env.ALLOWED_HOSTS.split(",")
    : [
        "127.0.0.1",
        "localhost",
        "[::1]",
        listenHost,
        ...(listenHost === "0.0.0.0" || listenHost === "::" ? ["*"] : []),
      ]
  )
    .map((value) => value.trim())
    .filter(Boolean);
  const hostname = host.replace(/:\d+$/, "");
  if (!allowed.includes("*") && !allowed.includes(hostname))
    throw Object.assign(
      new Error("不允许的 Host；外部部署需配置 ALLOWED_HOSTS"),
      { status: 403 },
    );
  if (req.headers.origin) {
    const origin = new URL(req.headers.origin);
    const same = origin.host === host;
    const originHostname = origin.hostname.includes(":")
      ? `[${origin.hostname}]`
      : origin.hostname;
    const originAllowed =
      allowed.includes("*") || allowed.includes(originHostname);
    const development =
      originAllowed &&
      ["5173", "5174"].includes(origin.port);
    if (!same && !development)
      throw Object.assign(new Error("不允许的跨站请求"), { status: 403 });
  }
}
const server = http.createServer(async (req, res) => {
  try {
    requestGuard(req);
    const url = new URL(req.url, "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean);
    const method = req.method;
    if (url.pathname === "/api/health")
      return json(res, {
        ready: !engineError,
        version: engineVersion,
        error: engineError,
        node: process.version,
        maxUpload,
        codecs,
      });
    if (parts[0] === "api") {
      if (url.pathname === "/api/fields")
        return json(
          res,
          suggestFields((url.searchParams.get("q") || "").slice(0, 100)),
        );
      if (url.pathname === "/api/captures" && method === "GET")
        return json(
          res,
          [...captures.values()]
            .sort((a, b) => b.created.localeCompare(a.created))
            .map(snapshot),
        );
      if (url.pathname === "/api/demo" && method === "POST") {
        requireEngine();
        const existing = [...captures.values()].find(
          (c) => c.demo && c.status === "ready",
        );
        if (existing && existing.demoVersion === DEMO_VERSION)
          return json(res, snapshot(existing));
        if (existing) {
          const data = buildDemoPcap();
          existing.demoVersion = DEMO_VERSION;
          existing.status = "indexing";
          existing.error = null;
          existing.processed = 0;
          existing.config = {
            ports: [20000],
            heuristic: false,
            mappings: [],
            decodeAs: [],
          };
          existing.revision = (existing.revision || 0) + 1;
          existing.size = data.length;
          await writeFile(join(existing.dir, "capture.pcap"), data);
          void analyze(existing);
          return json(res, snapshot(existing), 202);
        }
        const c = await newCapture("webshark-demo.pcap", true);
        const data = buildDemoPcap();
        c.size = data.length;
        c.config.ports = [20000];
        await writeFile(join(c.dir, "capture.pcap"), data);
        void analyze(c);
        return json(res, snapshot(c), 202);
      }
      if (url.pathname === "/api/captures" && method === "POST") {
        requireEngine();
        const name = decodeURIComponent(
          req.headers["x-file-name"] || "capture.pcap",
        );
        if (!/\.(pcapng|pcap|cap)$/i.test(name))
          throw new Error("支持 PCAP、PCAPNG、CAP 文件");
        if (Number(req.headers["content-length"]) > maxUpload)
          throw Object.assign(new Error(`文件超过上限 ${maxUpload} 字节`), {
            status: 413,
          });
        const c = await newCapture(name);
        try {
          let size = 0;
          const meter = new Transform({
            transform(chunk, enc, cb) {
              size += chunk.length;
              c.size = size;
              cb(
                size > maxUpload ? new Error("文件超过上传限制") : null,
                chunk,
              );
            },
          });
          await pipeline(
            req,
            meter,
            createWriteStream(join(c.dir, "capture.pcap"), { mode: 0o600 }),
          );
          if (size < 24) throw new Error("文件过短，不是有效抓包");
          void analyze(c);
          return json(res, snapshot(c), 202);
        } catch (e) {
          captures.delete(c.id);
          await rm(c.dir, { recursive: true, force: true });
          throw e;
        }
      }
      if (parts[1] === "captures" && parts[2]) {
        const c = getCapture(parts[2], false);
        const action = parts[3];
        if (!action && method === "GET") return json(res, snapshot(c));
        if (!action && method === "DELETE") {
          c.cancelled = true;
          for (const p of c.processes) p.kill("SIGKILL");
          captures.delete(c.id);
          await rm(c.dir, { recursive: true, force: true });
          return json(res, { ok: true });
        }
        if (action === "cancel" && method === "POST") {
          c.cancelled = true;
          for (const p of c.processes) p.kill("SIGKILL");
          c.status = "cancelled";
          return json(res, snapshot(c));
        }
        getCapture(c.id, true);
        requireEngine();
        if (action === "config" && method === "PUT") {
          const config = validateConfig(await readJson(req));
          void analyze(c, config);
          return json(res, snapshot(c), 202);
        }
        if (action === "packets" && !parts[4] && method === "GET") {
          const requestedFilter = url.searchParams.get("filter") || "";
          const requestedFields = url.searchParams
            .getAll("field")
            .flatMap((value) => value.split(","))
            .map((value) => value.trim())
            .filter(Boolean);
          const resolved = await resolveFilter(c, requestedFilter, requestedFields);
          const index = resolved.index;
          const page = Math.max(0, Number(url.searchParams.get("page")) || 0);
          const rawSize = url.searchParams.get("size");
          const requestedSize = rawSize?.trim() ? Number(rawSize) : NaN;
          const pageSize = Number.isFinite(requestedSize)
            ? Math.min(1000, Math.max(1, Math.floor(requestedSize)))
            : 100;
          const sortField = url.searchParams.get("sort") || "";
          const sortDirection = url.searchParams.get("direction") === "desc" ? "desc" : "asc";
          const sort =
            sortField && !(sortField === "frame.number" && sortDirection === "asc")
              ? { field: sortField, direction: sortDirection }
              : null;
          return json(res, {
            packets: await pageFromIndex(index, page, pageSize, sort),
            total: index.count,
            bytes: index.summary.bytes,
            page,
            pageSize,
            relation: resolved.relation,
          });
        }
        if (action === "packets" && parts[4])
          return json(res, await packetDetail(c, Number(parts[4])));
        if (action === "stream")
          return json(
            res,
            await followStream(
              c,
              url.searchParams.get("transport"),
              Number(url.searchParams.get("index")),
            ),
          );
        if (action === "audio") {
          const wave = await audioFor(
            c,
            Number(url.searchParams.get("stream")),
          );
          res.writeHead(200, {
            "Content-Type": "audio/wav",
            "Content-Length": wave.length,
            "Content-Disposition": `inline; filename="rtp-stream-${url.searchParams.get("stream")}.wav"`,
            "Cache-Control": "no-store",
          });
          return res.end(wave);
        }
        if (action === "waveform" && method === "GET")
          return json(
            res,
            await waveformFor(
              c,
              Number(url.searchParams.get("stream")),
            ),
          );
        if (action === "export") {
          const filter = url.searchParams.get("filter") || "";
          if (filter.length > 4096) throw new Error("过滤表达式过长");
          const resolved = await resolveFilter(c, filter);
          const path = join(c.dir, `${randomUUID()}.pcapng`);
          try {
            await exportCapture(
              c,
              resolved.relation ? resolved.relation.expandedFilter : filter,
              path,
              resolved.relation?.decodeAs || [],
            );
            res.writeHead(200, {
              "Content-Type": "application/vnd.tcpdump.pcap",
              "Content-Disposition":
                'attachment; filename="webshark-filtered.pcapng"',
            });
            await pipeline(createReadStream(path), res);
          } finally {
            await rm(path, { force: true });
          }
          return;
        }
      }
      return json(res, { error: "接口不存在" }, 404);
    }
    const dist = join(root, "dist");
    const path = resolve(dist, "." + decodeURIComponent(url.pathname));
    if (path !== dist && !path.startsWith(dist + "/"))
      throw Object.assign(new Error("路径无效"), { status: 403 });
    let target = path;
    try {
      if ((await stat(target)).isDirectory())
        target = join(target, "index.html");
    } catch {
      target = join(dist, "index.html");
    }
    const types = {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript",
      ".css": "text/css",
      ".svg": "image/svg+xml",
      ".woff2": "font/woff2",
      ".png": "image/png",
    };
    res.writeHead(200, {
      "Content-Type": types[extname(target)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    await pipeline(createReadStream(target), res);
  } catch (e) {
    if (!res.headersSent) json(res, { error: e.message }, e.status || 400);
    else res.destroy();
  }
});
server.requestTimeout = 15 * 60 * 1000;
server.headersTimeout = 30000;
server.listen(listenPort, listenHost, () => {
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : listenPort;
  console.log(
    `WebShark API: http://${listenHost}:${port} · ${engineError || engineVersion}`,
  );
  if (listenHost === "0.0.0.0" || listenHost === "::")
    console.warn(
      "WebShark API is reachable on all network interfaces; set ALLOWED_HOSTS or use --host to restrict access.",
    );
});
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    stopAll();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
  });
