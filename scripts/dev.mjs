import { spawn } from "node:child_process";
const processes = [
  spawn(process.execPath, ["server/index.mjs"], { stdio: "inherit" }),
  spawn(
    process.execPath,
    [
      "node_modules/vite/bin/vite.js",
      "--host",
      "127.0.0.1",
      "--port",
      "5173",
      ...process.argv.slice(2),
    ],
    { stdio: "inherit" },
  ),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  processes.forEach((p) => p.kill("SIGTERM"));
  setTimeout(() => process.exit(code), 500).unref();
}
processes.forEach((p) => {
  p.on("error", () => stop(1));
  p.on("exit", (code) => stop(code || 0));
});
process.on("SIGINT", () => stop());
process.on("SIGTERM", () => stop());
