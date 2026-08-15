/**
 * ChaCha20 stream cipher (IETF variant, 96-bit nonce) for dsh-vault.
 *
 * Node's crypto module has no ChaCha20 primitive, so this implements the
 * standard 20-round construction needed to decrypt KeePass KDBX protected
 * fields (inner random stream id 2) and other plaintext streams.
 *
 * @module dsh-vault/chacha20
 */

const ROUNDS = 20
const STATE_SIZE = 16

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

function quarterRound(state: number[], a: number, b: number, c: number, d: number): void {
  state[a] = (state[a]! + state[b]!) >>> 0
  state[d] = rotl(state[d]! ^ state[a]!, 16)
  state[c] = (state[c]! + state[d]!) >>> 0
  state[b] = rotl(state[b]! ^ state[c]!, 12)
  state[a] = (state[a]! + state[b]!) >>> 0
  state[d] = rotl(state[d]! ^ state[a]!, 8)
  state[c] = (state[c]! + state[d]!) >>> 0
  state[b] = rotl(state[b]! ^ state[c]!, 7)
}

function littleEndian(buf: Buffer, offset: number): number {
  return (buf[offset]! |
    (buf[offset + 1]! << 8) |
    (buf[offset + 2]! << 16) |
    (buf[offset + 3]! << 24)) >>> 0
}

function toBytes(word: number, out: Buffer, offset: number): void {
  out[offset] = word & 0xff
  out[offset + 1] = (word >>> 8) & 0xff
  out[offset + 2] = (word >>> 16) & 0xff
  out[offset + 3] = (word >>> 24) & 0xff
}

const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

/** XOR `input` with the ChaCha20 keystream. `key` is 32 bytes, `nonce` 12 bytes. */
export function chacha20Xor(input: Buffer, key: Buffer, nonce: Buffer, counter = 0): Buffer {
  if (key.length !== 32) throw new Error('chacha20: key must be 32 bytes')
  if (nonce.length !== 12) throw new Error('chacha20: nonce must be 12 bytes')
  const out = Buffer.alloc(input.length)
  const keyWords = [
    littleEndian(key, 0), littleEndian(key, 4), littleEndian(key, 8), littleEndian(key, 12),
    littleEndian(key, 16), littleEndian(key, 20), littleEndian(key, 24), littleEndian(key, 28),
  ]
  const nonceWords = [
    littleEndian(nonce, 0), littleEndian(nonce, 4), littleEndian(nonce, 8),
  ]
  const block = Buffer.alloc(64)
  let pos = 0
  let blockCounter = counter
  while (pos < input.length) {
    const state = [...CONSTANTS, ...keyWords, blockCounter >>> 0, ...nonceWords]
    const working = [...state]
    for (let i = 0; i < ROUNDS / 2; i++) {
      quarterRound(working, 0, 4, 8, 12)
      quarterRound(working, 1, 5, 9, 13)
      quarterRound(working, 2, 6, 10, 14)
      quarterRound(working, 3, 7, 11, 15)
      quarterRound(working, 0, 5, 10, 15)
      quarterRound(working, 1, 6, 11, 12)
      quarterRound(working, 2, 7, 8, 13)
      quarterRound(working, 3, 4, 9, 14)
    }
    for (let i = 0; i < STATE_SIZE; i++) {
      toBytes((working[i]! + state[i]!) >>> 0, block, i * 4)
    }
    const chunk = input.length - pos
    const take = Math.min(64, chunk)
    for (let i = 0; i < take; i++) out[pos + i] = input[pos + i]! ^ block[i]!
    pos += take
    blockCounter = (blockCounter + 1) >>> 0
  }
  return out
}
