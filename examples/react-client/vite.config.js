import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The redirect URL registered for this app is http://localhost:5173/callback,
// so the port must not silently change if 5173 is busy.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true },
  preview: { port: 5173, strictPort: true },
});
