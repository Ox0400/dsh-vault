/**
 * Salsa20 stream cipher for dsh-vault (KeePass KDBX4 inner random stream id 3).
 *
 * KeePass derives the Salsa20 key as SHA-256 of the protected stream key and
 * uses the fixed 8-byte nonce E8 30 09 4B 97 20 5D 2A. The state layout matches
 * the original dchest Salsa20 implementation used by kdbxweb/KeePassXC:
 * sigma at 0,5,10,15; key at 1-4 and 11-14; nonce at 6-7; counter at 8-9.
 *
 * @module dsh-vault/salsa20
 */

const ROUNDS = 20

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

/** One Salsa20 double-round on a column (or row) of 4 words. */
function quarterRound(s: number[], a: number, b: number, c: number, d: number): void {
  let u = (s[a]! + s[d]!) >>> 0
  s[b] = (s[b]! ^ rotl(u, 7)) >>> 0
  u = (s[a]! + s[b]!) >>> 0
  s[c] = (s[c]! ^ rotl(u, 9)) >>> 0
  u = (s[b]! + s[c]!) >>> 0
  s[d] = (s[d]! ^ rotl(u, 13)) >>> 0
  u = (s[c]! + s[d]!) >>> 0
  s[a] = (s[a]! ^ rotl(u, 18)) >>> 0
}

/** Little-endian read of 4 bytes. */
function le32(buf: Buffer, offset: number): number {
  return (buf[offset]! |
    (buf[offset + 1]! << 8) |
    (buf[offset + 2]! << 16) |
    (buf[offset + 3]! << 24)) >>> 0
}

/** Little-endian write of a 32-bit word. */
function toBytes(word: number, out: Buffer, offset: number): void {
  out[offset] = word & 0xff
  out[offset + 1] = (word >>> 8) & 0xff
  out[offset + 2] = (word >>> 16) & 0xff
  out[offset + 3] = (word >>> 24) & 0xff
}

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] // "expand 32-byte k"

/**
 * XOR `input` with the Salsa20 keystream. `key` is 32 bytes; `nonce` is 8
 * bytes (KeePass uses the fixed E8 30 09 4B 97 20 5D 2A with counter 0).
 */
export function salsa20Xor(input: Buffer, key: Buffer, nonce: Buffer, counter = 0): Buffer {
  if (key.length !== 32) throw new Error('salsa20: key must be 32 bytes')
  if (nonce.length !== 8) throw new Error('salsa20: nonce must be 8 bytes')
  const out = Buffer.alloc(input.length)
  const k = [
    le32(key, 0), le32(key, 4), le32(key, 8), le32(key, 12),
    le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28),
  ]
  const n0 = le32(nonce, 0)
  const n1 = le32(nonce, 4)
  const block = Buffer.alloc(64)
  let pos = 0
  let counterLo = counter >>> 0
  let counterHi = 0
  while (pos < input.length) {
    const state = [
      SIGMA[0]!, k[0]!, k[1]!, k[2]!,
      k[3]!, SIGMA[1]!, n0, n1,
      counterLo, counterHi, SIGMA[2]!, k[4]!,
      k[5]!, k[6]!, k[7]!, SIGMA[3]!,
    ]
    const working = [...state]
    for (let i = 0; i < ROUNDS; i += 2) {
      quarterRound(working, 0, 4, 8, 12)
      quarterRound(working, 5, 9, 13, 1)
      quarterRound(working, 10, 14, 2, 6)
      quarterRound(working, 15, 3, 7, 11)
      quarterRound(working, 0, 1, 2, 3)
      quarterRound(working, 5, 6, 7, 4)
      quarterRound(working, 10, 11, 8, 9)
      quarterRound(working, 15, 12, 13, 14)
    }
    for (let i = 0; i < 16; i++) {
      toBytes((working[i]! + state[i]!) >>> 0, block, i * 4)
    }
    const take = Math.min(64, input.length - pos)
    for (let i = 0; i < take; i++) out[pos + i] = input[pos + i]! ^ block[i]!
    pos += take
    counterLo = (counterLo + 1) >>> 0
    if (counterLo === 0) counterHi = (counterHi + 1) >>> 0
  }
  return out
}
