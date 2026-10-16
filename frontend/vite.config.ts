import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// En développement, l'API est celle de `uv run cti-dashboard --port 8080`
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://localhost:8080" } },
  build: { outDir: "dist", sourcemap: false },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
