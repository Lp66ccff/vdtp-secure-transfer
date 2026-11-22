import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发期把 /ws 与 /api 转到本机 8000 的服务端，浏览器只认同源地址。
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/ws': { target: 'ws://127.0.0.1:8000', ws: true },
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})
