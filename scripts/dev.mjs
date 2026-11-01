import { spawn } from "node:child_process";
function flagValue(name) {
  const args = process.argv.slice(2);
  const index = args.indexOf(name);
  if (index !== -1) return args[index + 1] || "";
  const inline = args.find((arg) => arg.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : "";
}
const host = flagValue("--host") || process.env.HOST || "0.0.0.0";
const apiPort = flagValue("--api-port") || process.env.PORT || "3001";
const uiPort = flagValue("--ui-port") || process.env.UI_PORT || "5173";
const viteArgs = process.argv.slice(2).filter((arg, index, args) => {
  if (["--host", "--api-port", "--ui-port"].includes(arg)) return false;
  if (index > 0 && ["--host", "--api-port", "--ui-port"].includes(args[index - 1]))
    return false;
  if (arg.startsWith("--host=") || arg.startsWith("--api-port=") || arg.startsWith("--ui-port="))
    return false;
  return true;
});
const processes = [
  spawn(
    process.execPath,
    ["server/index.mjs", "--host", host, "--port", apiPort],
    {
      stdio: "inherit",
      env: {
        ...process.env,
        HOST: host,
        PORT: apiPort,
        WEBSHARK_API_HOST: host,
        WEBSHARK_API_PORT: apiPort,
      },
    },
  ),
  spawn(
    process.execPath,
    [
      "node_modules/vite/bin/vite.js",
      "--host",
      host,
      "--port",
      uiPort,
      ...viteArgs,
    ],
    {
      stdio: "inherit",
      env: {
        ...process.env,
        HOST: host,
        WEBSHARK_API_HOST: host,
        WEBSHARK_API_PORT: apiPort,
      },
    },
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
