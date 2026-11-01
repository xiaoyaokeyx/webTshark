import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
const apiHost = process.env.WEBSHARK_API_HOST || process.env.HOST || "127.0.0.1";
const proxyHost = apiHost === "0.0.0.0" ? "127.0.0.1" : apiHost === "::" ? "::1" : apiHost;
const apiHostUrl = proxyHost.includes(":") && !proxyHost.startsWith("[")
  ? `[${proxyHost}]`
  : proxyHost;
const apiPort = Number(process.env.WEBSHARK_API_PORT || process.env.PORT) || 3001;
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": `http://${apiHostUrl}:${apiPort}` } },
});
