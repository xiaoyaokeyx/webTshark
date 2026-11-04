import { readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, basename } from "node:path";
import { createHash } from "node:crypto";

let scripts = [];
let stamps = [];
export let luaSignature = "";

// Executable server configuration, never populated from a capture upload/request.
export async function initLuaScripts(value = process.env.TSHARK_LUA_SCRIPTS || "[]") {
  let paths;
  try {
    paths = JSON.parse(value);
  } catch {
    throw new Error("TSHARK_LUA_SCRIPTS 必须是 Lua 文件绝对路径的 JSON 数组");
  }
  if (!Array.isArray(paths) || paths.some((p) => typeof p !== "string" || !isAbsolute(p)))
    throw new Error("TSHARK_LUA_SCRIPTS 必须是 Lua 文件绝对路径的 JSON 数组");
  const next = [], nextStamps = [], hash = createHash("sha256");
  for (const path of paths) {
    const resolved = await realpath(path);
    if (next.includes(resolved)) continue;
    const info = await stat(resolved);
    if (!info.isFile()) throw new Error(`Lua 脚本不是文件：${path}`);
    hash.update(resolved).update("\0").update(await readFile(resolved)).update("\0");
    next.push(resolved);
    nextStamps.push({ size: info.size, mtimeMs: info.mtimeMs });
  }
  scripts = next;
  stamps = nextStamps;
  luaSignature = hash.digest("hex");
}

export const luaArgs = () => scripts.flatMap((path) => ["-X", `lua_script:${path}`]);
export const luaScriptNames = () => scripts.map((path) => basename(path));

export async function assertLuaScriptsUnchanged() {
  for (let i = 0; i < scripts.length; i++) {
    const info = await stat(scripts[i]);
    if (info.size !== stamps[i].size || info.mtimeMs !== stamps[i].mtimeMs)
      throw new Error(`Lua 脚本 ${basename(scripts[i])} 已变更，请重启服务重新解析抓包`);
  }
}
