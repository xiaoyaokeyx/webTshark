import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { createInterface } from "node:readline";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { luaScriptNames } from "./lua.mjs";

let executable = "", session = null, gate = Promise.resolve(), pending = 0;
let status = { enabled: false, ready: false, error: null };
const versionNumber = (text) => text.match(/\b(\d+\.\d+\.\d+)\b/)?.[1];
export const filterSessionStatus = () => ({ ...status });
export async function initFilterSession(tsharkVersion) {
  closeFilterSession();
  executable = process.env.SHARKD_PATH || "";
  status = { enabled: Boolean(executable), ready: false, error: null };
  if (!executable) return;
  try {
    const { stdout } = await promisify(execFile)(executable, ["--version"], { timeout: 5000, maxBuffer: 128 * 1024 });
    if (!versionNumber(stdout) || versionNumber(stdout) !== versionNumber(tsharkVersion))
      throw new Error("sharkd 与 TShark 版本不一致，使用 TShark 过滤");
    status.ready = true;
  } catch (error) { status.error = error.message; }
}

export function canUseFilterSession(capture, filter) {
  // Redissection can change stateful/application fields. Restrict this adapter
  // to a packet-local byte predicate; all compound/other filters use TShark.
  return status.ready && !luaScriptNames().length &&
    !capture.config.heuristic && !capture.config.ports?.length &&
    !capture.config.mappings?.length && !capture.config.decodeAs?.length &&
    capture.index?.count <= 500000 &&
    /^\s*tcp\s+contains\s+(?:"(?:[^"\\\r\n]|\\[^\r\n])*"|[\da-fA-F]{2}(?::[\da-fA-F]{2})+)\s*$/.test(filter);
}

function startSession(capture) {
  const proc = spawn(executable, ["-"], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, LC_ALL: "C" } });
  capture.processes?.add(proc);
  let sequence = 0, request = null, dead = false, bytes = 0;
  const reader = createInterface({ input: proc.stdout, crlfDelay: Infinity });
  const state = { key: `${capture.dir}:${capture.revision}:${capture.engineSignature}`, idle: null, call, close };
  function close(error = new Error("常驻过滤进程已关闭")) {
    if (dead) return;
    dead = true;
    clearTimeout(state.idle);
    if (request) { clearTimeout(request.timer); request.reject(error); request = null; }
    capture.processes?.delete(proc);
    reader.close();
    proc.kill("SIGKILL");
    if (session === state) session = null;
  }
  proc.stderr.resume();
  proc.stdin.on("error", close);
  proc.on("error", close);
  proc.on("exit", () => close());
  proc.stdout.on("data", (data) => {
    bytes += data.length;
    if (bytes > 16 * 1024 * 1024) close(new Error("常驻过滤响应超限"));
  });
  reader.on("line", (line) => {
    if (!request) return;
    try {
      const response = JSON.parse(line);
      if (response.id !== request.id) throw new Error("常驻过滤响应不匹配");
      const current = request; request = null;
      clearTimeout(current.timer);
      response.error ? current.reject(new Error(response.error.message || "常驻过滤失败")) : current.resolve(response.result);
    } catch (error) { close(error); }
  });
  function call(method, params = {}) {
    if (dead) return Promise.reject(new Error("常驻过滤进程已退出"));
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      bytes = 0;
      const timer = setTimeout(() => close(new Error("常驻过滤超时，回退 TShark")), 30000);
      timer.unref();
      request = { id, resolve, reject, timer };
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  return state;
}

export function closeFilterSession() { session?.close(); }

// One bounded session, serialized requests, and a short idle lifetime. The
// private stdin/stdout transport is never exposed as an HTTP RPC endpoint.
export async function fastFrameNumbers(capture, filter) {
  if (!canUseFilterSession(capture, filter) || pending >= 4) return null;
  const file = join(capture.dir, "capture.pcap");
  if ((await stat(file)).size > 256 * 1024 * 1024) return null;
  pending++;
  const previous = gate;
  let release;
  gate = new Promise((resolve) => { release = resolve; });
  await previous;
  let current;
  try {
    if (capture.cancelled) return null;
    const key = `${capture.dir}:${capture.revision}:${capture.engineSignature}`;
    if (session?.key !== key) {
      closeFilterSession();
      session = startSession(capture);
      current = session;
      const loaded = await current.call("load", { file });
      if (loaded?.status !== "OK") throw new Error("常驻过滤无法加载抓包");
      const info = await current.call("status");
      if (info?.frames !== capture.index.count) throw new Error("常驻过滤包数不一致");
    } else current = session;
    clearTimeout(current.idle);
    const numbers = [];
    for (let skip = 0;;) {
      const frames = await current.call("frames", { filter, limit: 5000, ...(skip ? { skip } : {}) });
      if (!Array.isArray(frames)) throw new Error("常驻过滤返回格式错误");
      for (const frame of frames) {
        if (!Number.isInteger(frame.num) || frame.num <= (numbers.at(-1) || 0) || frame.num > capture.index.count)
          throw new Error("常驻过滤返回包号错误");
        numbers.push(frame.num);
      }
      if (frames.length < 5000) break;
      skip += frames.length;
    }
    status.error = null;
    return numbers;
  } catch (error) {
    status.error = error.message;
    current?.close();
    return null;
  } finally {
    if (current && session === current) {
      current.idle = setTimeout(() => current.close(), 60000);
      current.idle.unref();
    }
    pending--;
    release();
  }
}
