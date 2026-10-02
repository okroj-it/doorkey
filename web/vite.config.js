import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { viteSingleFile } from 'vite-plugin-singlefile';

// One self-contained file: the keypad is served from a route that only exists
// for a few minutes after a tap, so there is nowhere to serve assets from.
export default defineConfig({
  plugins: [svelte(), viteSingleFile()],
  build: { target: 'es2020', cssCodeSplit: false, assetsInlineLimit: 100000000 },
});
