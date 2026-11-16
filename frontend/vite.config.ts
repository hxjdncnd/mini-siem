import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In development the browser talks to Vite, and Vite forwards API calls to the backend,
// so no CORS setup is needed. In Docker, nginx does the same job (see nginx.conf).
const backend = process.env.VITE_BACKEND_URL ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": backend,
      "/health": backend,
    },
  },
  test: {
    environment: "node",
  },
});
