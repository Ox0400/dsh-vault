/**
 * Blake2b hash (RFC 7693) for dsh-vault — used by the Argon2 KDF (RFC 9106).
 *
 * Pure-JS implementation. 64-bit words are represented as lo/hi 32-bit halves
 * to avoid BigInt overhead. Supports digest lengths 1–64 and optional key.
 *
 * @module dsh-vault/blake2b
 */

const IV = [
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, // lo, hi
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

/** 64-bit rotate right of a lo/hi word pair. */
function rotr64(lo: number, hi: number, n: number): [number, number] {
  n &= 63
  if (n === 0) return [lo >>> 0, hi >>> 0]
  if (n === 32) return [hi >>> 0, lo >>> 0]
  if (n < 32) {
    return [
      ((lo >>> n) | (hi << (32 - n))) >>> 0,
      ((hi >>> n) | (lo << (32 - n))) >>> 0,
    ]
  }
  const shift = n - 32
  return [
    ((hi >>> shift) | (lo << (32 - shift))) >>> 0,
    ((lo >>> shift) | (hi << (32 - shift))) >>> 0,
  ]
}

/** 64-bit add of (a,b) + (c,d), returns lo/hi. */
function add64(a: number, b: number, c: number, d: number): [number, number] {
  const sumLo = (a >>> 0) + (c >>> 0)
  const carry = Math.floor(sumLo / 0x100000000)
  return [sumLo >>> 0, (b + d + carry) >>> 0]
}

/** G mixing function operating on 64-bit words in `v` (lo at even index). */
function g(v: number[], a: number, b: number, c: number, d: number, xLo: number, xHi: number, yLo: number, yHi: number): void {
  // a = a + b + x
  const a1 = add64(v[a]!, v[a + 1]!, v[b]!, v[b + 1]!);
  const a2 = add64(a1[0], a1[1], xLo, xHi);
  v[a] = a2[0]; v[a + 1] = a2[1]
  // d = rotr64(d ^ a, 32)
  let lo = v[d]! ^ v[a]!
  let hi = v[d + 1]! ^ v[a + 1]!
  let r = rotr64(lo, hi, 32)
  v[d] = r[0]; v[d + 1] = r[1]
  // c = c + d
  const c1 = add64(v[c]!, v[c + 1]!, v[d]!, v[d + 1]!)
  v[c] = c1[0]; v[c + 1] = c1[1]
  // b = rotr64(b ^ c, 24)
  lo = v[b]! ^ v[c]!
  hi = v[b + 1]! ^ v[c + 1]!
  r = rotr64(lo, hi, 24)
  v[b] = r[0]; v[b + 1] = r[1]
  // a = a + b + y
  const a3 = add64(v[a]!, v[a + 1]!, v[b]!, v[b + 1]!);
  const a4 = add64(a3[0], a3[1], yLo, yHi);
  v[a] = a4[0]; v[a + 1] = a4[1]
  // d = rotr64(d ^ a, 16)
  lo = v[d]! ^ v[a]!
  hi = v[d + 1]! ^ v[a + 1]!
  r = rotr64(lo, hi, 16)
  v[d] = r[0]; v[d + 1] = r[1]
  // c = c + d
  const c2 = add64(v[c]!, v[c + 1]!, v[d]!, v[d + 1]!)
  v[c] = c2[0]; v[c + 1] = c2[1]
  // b = rotr64(b ^ c, 63)
  lo = v[b]! ^ v[c]!
  hi = v[b + 1]! ^ v[c + 1]!
  r = rotr64(lo, hi, 63)
  v[b] = r[0]; v[b + 1] = r[1]
}

export interface Blake2bState {
  h: number[]
  t0: number
  t1: number
  buf: Buffer
  buflen: number
  outlen: number
}

/** Create a Blake2b state (supports keying and custom digest length). */
export function blake2bInit(outlen: number, key?: Buffer): Blake2bState {
  if (outlen < 1 || outlen > 64) throw new Error('blake2b: digest length must be 1–64')
  // Parameter block (little-endian 64-bit): digest_length | key_length<<8 |
  // fanout<<16 | depth<<24; the rest of the block is zero.
  const paramLo = (outlen & 0xff) | ((key?.length ?? 0) << 8) | 0x01010000
  const h = [...IV]
  h[0] = (h[0]! ^ paramLo) >>> 0
  const st: Blake2bState = { h, t0: 0, t1: 0, buf: Buffer.alloc(128), buflen: 0, outlen }
  if (key !== undefined && key.length > 0) {
    if (key.length > 128) throw new Error('blake2b: key too long')
    // RFC 7693 §3.4: the key is padded to the block size and processed as a
    // block. Buffer it (buflen=128) so an empty message compresses it as the
    // final block, while any following message flushes it first.
    const block = Buffer.alloc(128)
    key.copy(block)
    block.copy(st.buf)
    st.buflen = 128
  }
  return st
}

/** Incremental update with `data`. */
export function blake2bUpdate(st: Blake2bState, data: Buffer): void {
  if (data.length === 0) return
  let pos = 0
  // A full buffered block (e.g. the padded key block) must be flushed first.
  if (st.buflen === 128) {
    incrementCounter(st, 128)
    compress(st, st.buf, false)
    st.buflen = 0
  }
  if (st.buflen > 0) {
    const take = Math.min(128 - st.buflen, data.length)
    data.copy(st.buf, st.buflen, 0, take)
    st.buflen += take
    pos += take
    if (st.buflen === 128) {
      incrementCounter(st, 128)
      compress(st, st.buf, false)
      st.buflen = 0
    }
  }
  while (pos + 128 <= data.length) {
    incrementCounter(st, 128)
    compress(st, data.subarray(pos, pos + 128), false)
    pos += 128
  }
  if (pos < data.length) {
    data.copy(st.buf, 0, pos)
    st.buflen = data.length - pos
  }
}

/** Finalize and return the digest. */
export function blake2bFinal(st: Blake2bState): Buffer {
  incrementCounter(st, st.buflen)
  const block = Buffer.alloc(128)
  st.buf.copy(block, 0, 0, st.buflen)
  compress(st, block, true)
  const out = Buffer.alloc(st.outlen)
  for (let i = 0; i < st.outlen; i++) {
    // The state is 16 words of 64 bits stored as [lo, hi]; little-endian
    // byte order is lo's 4 bytes then hi's 4 bytes per word.
    const word = i >>> 3
    const isLo = (i & 4) === 0
    const shift = (i & 3) * 8
    out[i] = ((isLo ? st.h[word * 2]! : st.h[word * 2 + 1]!) >>> shift) & 0xff
  }
  return out
}

/** One-shot Blake2b digest. */
export function blake2b(data: Buffer, outlen = 64, key?: Buffer): Buffer {
  const st = blake2bInit(outlen, key)
  blake2bUpdate(st, data)
  return blake2bFinal(st)
}

function incrementCounter(st: Blake2bState, amount: number): void {
  st.t0 = (st.t0 + amount) >>> 0
  if (st.t0 < amount) st.t1 = (st.t1 + 1) >>> 0
}

/** Compress one 128-byte block (mix the state). */
function compress(st: Blake2bState, block: Buffer, last: boolean): void {
  const v = new Array<number>(32)
  for (let i = 0; i < 16; i++) {
    v[i] = st.h[i]!
    v[16 + i] = IV[i]!
  }
  v[24] = (v[24]! ^ st.t0) >>> 0
  v[25] = (v[25]! ^ st.t1) >>> 0
  if (last) {
    v[28] = (v[28]! ^ 0xffffffff) >>> 0
    v[29] = (v[29]! ^ 0xffffffff) >>> 0
  }
  const m = new Array<number>(32)
  for (let i = 0; i < 16; i++) {
    m[i * 2] = block.readUInt32LE(i * 8)
    m[i * 2 + 1] = block.readUInt32LE(i * 8 + 4)
  }
  for (let round = 0; round < 12; round++) {
    const s = SIGMA[round % 10]!
    g(v, 0, 8, 16, 24, m[s[0]! * 2]!, m[s[0]! * 2 + 1]!, m[s[1]! * 2]!, m[s[1]! * 2 + 1]!)
    g(v, 2, 10, 18, 26, m[s[2]! * 2]!, m[s[2]! * 2 + 1]!, m[s[3]! * 2]!, m[s[3]! * 2 + 1]!)
    g(v, 4, 12, 20, 28, m[s[4]! * 2]!, m[s[4]! * 2 + 1]!, m[s[5]! * 2]!, m[s[5]! * 2 + 1]!)
    g(v, 6, 14, 22, 30, m[s[6]! * 2]!, m[s[6]! * 2 + 1]!, m[s[7]! * 2]!, m[s[7]! * 2 + 1]!)
    g(v, 0, 10, 20, 30, m[s[8]! * 2]!, m[s[8]! * 2 + 1]!, m[s[9]! * 2]!, m[s[9]! * 2 + 1]!)
    g(v, 2, 12, 22, 24, m[s[10]! * 2]!, m[s[10]! * 2 + 1]!, m[s[11]! * 2]!, m[s[11]! * 2 + 1]!)
    g(v, 4, 14, 16, 26, m[s[12]! * 2]!, m[s[12]! * 2 + 1]!, m[s[13]! * 2]!, m[s[13]! * 2 + 1]!)
    g(v, 6, 8, 18, 28, m[s[14]! * 2]!, m[s[14]! * 2 + 1]!, m[s[15]! * 2]!, m[s[15]! * 2 + 1]!)
  }
  for (let i = 0; i < 16; i++) {
    st.h[i] = (st.h[i]! ^ v[i]! ^ v[16 + i]!) >>> 0
  }
}
