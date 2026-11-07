import { encode } from 'uqr';

/**
 * A URL as a QR code: one SVG path of the dark modules, in a square of
 * `size` units that already includes the quiet zone scanners need. Medium
 * error correction: a phone camera on a screen, nothing printed or worn.
 */
export function qrPath(text) {
  const { size, data } = encode(text, { ecc: 'M', border: 4 });
  let d = '';
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++)
      if (data[y][x]) d += `M${x} ${y}h1v1h-1z`;
  return { size, d };
}
