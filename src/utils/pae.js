/**
 * Implement PASETO Pre-Authentication Encoding (PAE) logic.
 */

// Implementation to safely encode a 64-bit integer into a little-endian buffer.
// The input is a safe JavaScript integer (<= 2^53 - 1).
function le64(n) {
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) {
    throw new TypeError('le64 requires a safe non-negative integer');
  }

  const buf = Buffer.alloc(8);
  // Write the low 32 bits
  buf.writeUInt32LE(n >>> 0, 0);

  // Write the high 32 bits (if any)
  // JavaScript bitwise operations are limited to 32 bits.
  // To get the high bits of a 64-bit number, use division.
  const high = Math.floor(n / 0x100000000);
  buf.writeUInt32LE(high, 4);

  return buf;
}

/**
 * PAE (...pieces)
 *
 * PAE(p1, p2, ...) = LE64(n) || LE64(|p1|) || p1 || LE64(|p2|) || p2 || ...
 *
 * @param  {...(Buffer|Uint8Array|string|undefined|null)} pieces
 * @returns {Buffer} The concatenated PAE buffer.
 */
function pae(...pieces) {
  // Spec: If we receive null/undefined, we probably shouldn't encode them as strings.
  // We'll treat all undefined/null as empty, or strictly enforce Buffer/string.
  // But wait, the spec says to format things as LE64(count). We strictly use strings or Buffers.

  const n = pieces.length;
  const bufs = [le64(n)];

  for (const piece of pieces) {
    let buf;
    if (Buffer.isBuffer(piece)) {
      buf = piece;
    } else if (piece instanceof Uint8Array) {
      buf = Buffer.from(piece);
    } else if (typeof piece === 'string') {
      buf = Buffer.from(piece, 'utf8');
    } else {
      throw new TypeError(`PAE pieces must be Buffer, Uint8Array or string. Got ${typeof piece}`);
    }

    bufs.push(le64(buf.length));
    bufs.push(buf);
  }

  return Buffer.concat(bufs);
}

module.exports = {
  le64,
  pae,
};
