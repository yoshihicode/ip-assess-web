import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `npm run dev`（ルート）で wrangler が 8787 番で動いている前提で、/api をそこへ転送する
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': 'http://localhost:8787' },
  },
});
