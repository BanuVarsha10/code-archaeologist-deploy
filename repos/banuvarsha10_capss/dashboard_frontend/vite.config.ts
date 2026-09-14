import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Vite defaults to binding on "localhost", which Node resolves to the
    // IPv6 loopback (::1) in most environments. When this dev server runs
    // inside WSL2, WSL2's automatic localhost port-forwarding to Windows
    // only reliably forwards IPv4 — so a Windows browser gets a 404/
    // connection-refused against ::1 even though the server is up and
    // fine from inside WSL. Binding explicitly to all IPv4 interfaces
    // fixes that.
    host: true,
    // TEMPORARY dev-only: allow any Host header (e.g. *.ngrok-free.dev)
    // so the dev server is reachable through an ngrok tunnel. Vite
    // rejects unrecognized Host headers by default as an anti-DNS-
    // rebinding measure; this disables that check entirely. Fine for a
    // local dev server temporarily shared with teammates — do NOT carry
    // this into any production server config.
    allowedHosts: true,
    // TEMPORARY dev-only: proxy API calls to the backend through this
    // same dev server instead of requiring a second public tunnel. This
    // is what lets one ngrok tunnel (this port) serve both frontend and
    // backend — the free ngrok plan only allows one endpoint online at a
    // time, so a separate tunnel for :8000 isn't viable anyway. Requests
    // to /api/* from the browser hit this same origin and Vite forwards
    // them to the real backend server-side (no CORS involved either way).
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
    // The project root is served from a `subst`-mapped drive letter
    // pointing at a UNC (\\wsl.localhost\...) path. Windows' native
    // fs.watch() throws EISDIR against files on subst'd drives, so file
    // watching falls back to polling here instead.
    watch: {
      usePolling: true,
      interval: 300,
    },
  },
})
