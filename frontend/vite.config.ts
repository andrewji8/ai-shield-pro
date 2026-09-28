import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // 使用 import.meta.url 替代 __dirname，避免 Vite 警告
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})