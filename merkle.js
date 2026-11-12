// RFC 6962 Merkle tree helpers (browser + node). SHA-256 via WebCrypto.
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out;
}
async function leafHash(line) { return sha256(concat(new Uint8Array([0]), new TextEncoder().encode(line))); }
async function mth(leaves, lo, hi) {
  const n = hi - lo;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leaves[lo];
  let k = 1; while (k * 2 < n) k *= 2;
  const l = await mth(leaves, lo, lo + k), r = await mth(leaves, lo + k, hi);
  return sha256(concat(new Uint8Array([1]), l, r));
}
const toHex = u8 => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
if (typeof module !== 'undefined') module.exports = { sha256, leafHash, mth, toHex };
