<script>
  import { qrPath } from './qr.js';

  let { text, label = 'QR code' } = $props();
  const qr = $derived(qrPath(text));
</script>

<!-- Dark on white whatever the theme: cameras want the classic contrast. -->
<svg class="qr" viewBox="0 0 {qr.size} {qr.size}" role="img" aria-label={label}
     shape-rendering="crispEdges">
  <rect width={qr.size} height={qr.size} fill="#fff" />
  <path d={qr.d} fill="#000" />
</svg>

<style>
  .qr { display: block; width: min(16rem, 70vw); height: auto; border-radius: .25rem; }
</style>
