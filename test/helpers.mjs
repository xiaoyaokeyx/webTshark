import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
export async function startTestServer() {
  const dir = await mkdtemp(join(tmpdir(), "webshark-http-"));
  const probe = createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const child = spawn(process.execPath, ["server/index.mjs"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), DATA_DIR: dir },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  const base = `http://127.0.0.1:${port}`;
  const stop = async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await new Promise((r) => child.once("exit", r));
    }
    await rm(dir, { recursive: true, force: true });
  };
  try {
    for (let i = 0; i < 150; i++) {
      try {
        const res = await fetch(base + "/api/health");
        if (res.ok) {
          const health = await res.json();
          if (health.ready) return { base, dir, child, stop };
        }
      } catch {}
      if (child.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error("API did not start: " + log);
  } catch (e) {
    await stop();
    throw e;
  }
}
export async function waitCapture(base, id) {
  for (let i = 0; i < 150; i++) {
    const c = await fetch(`${base}/api/captures/${id}`).then((r) => r.json());
    if (["ready", "error", "cancelled"].includes(c.status)) return c;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("Capture analysis timed out");
}
