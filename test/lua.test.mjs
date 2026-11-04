import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildCapture } from "../src/compose.js";
import { initEngine, prepare, buildIndex, getIndex, pageFromIndex, packetDetail,
  suggestFields, exportCapture, run, stopAll, engineSignature } from "../server/engine.mjs";
import { initLuaScripts, luaScriptNames } from "../server/lua.mjs";
import { canUseFilterSession } from "../server/filter-session.mjs";
import { startTestServer, waitCapture } from "./helpers.mjs";

test("configured Lua fields work across list, filter, autocomplete, detail and export", async () => {
  const dir = await mkdtemp(join(tmpdir(), "webtshark-lua-"));
  const previous = process.env.TSHARK_LUA_SCRIPTS;
  let server;
  try {
    const script = join(dir, "custom.lua");
    const stateScript = join(dir, "state.lua");
    await writeFile(script, await readFile(resolve("examples/lua/webdemo.lua")));
    await writeFile(stateScript, `local p=Proto("webdemo_state","Stateful Lua test")
local field=ProtoField.uint32("webdemo_state.previous","Previous frame",base.DEC)
p.fields={field}
local previous=0
function p.init() previous=0 end
function p.dissector(tvb,pinfo,tree)
  tree:add(p):add(field,previous):set_generated()
  previous=pinfo.number
end
register_postdissector(p,true)
`);
    process.env.TSHARK_LUA_SCRIPTS = JSON.stringify([script, stateScript, script]);
    await initEngine();
    assert.deepEqual(luaScriptNames(), ["custom.lua", "state.lua"]);
    assert.ok(suggestFields("webdemo.").includes("webdemo.kind"));
    const capture = { dir, revision: 1, config: { ports: [], mappings: [], decodeAs: [], heuristic: false }, queries: new Map(), processes: new Set() };
    await writeFile(join(dir, "capture.pcap"), buildCapture({ protocol: "SIP", count: 3, srcPort: 12345, dstPort: 19000, body: "INVITE Lua" }));
    await prepare(capture);
    capture.index = await buildIndex(capture);
    assert.equal((await pageFromIndex(capture.index))[0].protocol, "WEBDEMO");
    const index = await getIndex(capture, 'webdemo.kind == 73', [], ["webdemo.kind", "webdemo.body"]);
    assert.equal(index.count, 3);
    const packets = await pageFromIndex(index);
    assert.equal(packets[0].fields["webdemo.kind"], "73");
    assert.match(packets[0].fields["webdemo.body"], /^NVITE sip:/);
    assert.ok(packets[0].fields["webdemo.body"].includes("INVITE Lua"));
    const detail = await packetDetail(capture, 2);
    const visit = (fields) => fields.flatMap((f) => [f, ...visit(f.fields || [])]);
    const kind = visit(detail.layers).find((f) => f.name === "webdemo.kind");
    assert.equal(kind.filter, "webdemo.kind == 73");
    assert.equal(visit(detail.layers).find((f) => f.name === "webdemo_state.previous").filter, "webdemo_state.previous == 1");
    assert.equal(canUseFilterSession(capture, 'tcp contains "INVITE"'), false);
    const out = join(dir, "custom.pcapng");
    await exportCapture(capture, "webdemo.kind == 73 && frame.number == 2", out);
    assert.equal((await run(["-r", out, "-T", "fields", "-e", "frame.number"])).trim(), "1");
    const signature = engineSignature;
    await writeFile(script, (await readFile(script, "utf8")) + "\n-- revision 2\n");
    await initEngine();
    assert.notEqual(engineSignature, signature);
    server = await startTestServer({ TSHARK_LUA_SCRIPTS: JSON.stringify([script]) });
    const health = await fetch(server.base + "/api/health").then((r) => r.json());
    assert.deepEqual(health.luaScripts, ["custom.lua"]);
    assert.ok((await fetch(server.base + "/api/fields?q=webdemo.").then((r) => r.json())).includes("webdemo.kind"));
    const created = await fetch(server.base + "/api/captures", { method: "POST", body: await readFile(join(dir, "capture.pcap")) }).then((r) => r.json());
    assert.equal((await waitCapture(server.base, created.id)).status, "ready");
    await writeFile(script, "this is not valid lua!");
    await assert.rejects(initEngine(), /Lua/);
  } finally {
    await server?.stop();
    stopAll();
    if (previous == null) delete process.env.TSHARK_LUA_SCRIPTS; else process.env.TSHARK_LUA_SCRIPTS = previous;
    await initLuaScripts("[]");
    await rm(dir, { recursive: true, force: true });
  }
});

test("Lua configuration rejects relative paths and malformed lists", async () => {
  await assert.rejects(initLuaScripts("not JSON"), /JSON/);
  await assert.rejects(initLuaScripts('["relative.lua"]'), /绝对路径/);
  await assert.rejects(initLuaScripts('{}'), /JSON/);
});
