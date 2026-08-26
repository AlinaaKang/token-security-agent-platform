import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const apiTarget = "http://127.0.0.1:18000";
const proxy = {
  "/health": { target: apiTarget, changeOrigin: false },
  "/api": { target: apiTarget, changeOrigin: false },
};

export default defineConfig({
  plugins: [react()],
  server: { proxy },
  preview: { proxy },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
  },
});
