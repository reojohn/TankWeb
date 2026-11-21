import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/app/',
  build: {
    // Keep source-validation builds away from public/app/. The deployed v3
    // runtime contains a PHP auth gate, vendored runtime files, and the tested
    // parity bundle; emptying public/app would remove those protected files.
    outDir: '../react-build',
    emptyOutDir: true,
    sourcemap: false,
  },
});
