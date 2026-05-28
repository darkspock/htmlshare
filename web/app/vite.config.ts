import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/app/",
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:4545",
      "/auth": "http://localhost:4545",
      "/r": "http://localhost:4545"
    }
  }
});
