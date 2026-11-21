import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Same as DEFAULT_PORT in backend/server/src/config.js. Change both if you change one.
const SERVER_PORT = 3001

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // In dev, /api/* goes to the local backend server, so the browser sees one origin.
    proxy: {
      '/api': `http://localhost:${SERVER_PORT}`,
    },
  },
  test: {
    environment: 'node',
  },
})
