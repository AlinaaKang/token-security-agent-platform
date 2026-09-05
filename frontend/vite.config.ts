import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const apiTarget = env.TOKEN_SECURITY_REMOTE_API_TARGET || "http://127.0.0.1:18001";
  const pcapApiTarget = env.TOKEN_SECURITY_PCAP_API_TARGET || "http://127.0.0.1:18000";
  const proxy = {
    "/pcap-api": {
      target: pcapApiTarget,
      changeOrigin: false,
      rewrite: (path: string) => path.replace(/^\/pcap-api/, "/api"),
    },
    "/health": { target: apiTarget, changeOrigin: false },
    "/api": { target: apiTarget, changeOrigin: false },
  };

  return {
    plugins: [react()],
    server: { proxy },
    preview: { proxy },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.ts",
    },
  };
});
