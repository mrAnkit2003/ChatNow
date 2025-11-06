import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // This tells Vite to build for modern browsers
    // and fixes the "import.meta" error.
    target: 'esnext' 
  }
})
