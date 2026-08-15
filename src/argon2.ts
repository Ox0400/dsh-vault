/**
 * Argon2 key derivation (RFC 9106) for dsh-vault — used by KDBX4 Argon2-KDF
 * databases (KeePassXC / KeePass 2.55+ default).
 *
 * Pure-JS implementation of Argon2d / Argon2id (version 0x13), closely
 * following the reference implementation (P-H-C/phc-winner-argon2):
 * - fill_block / fill_segment / next_addresses
 * - index_alpha reference-block selection
 * - fBlaMka mixing with 64-bit multiply via 16-bit limbs
 * Memory blocks are 1024-byte buffers of 128 little-endian 64-bit words.
 *
 * References: RFC 9106; phc-winner-argon2 core.c / blamka-round-ref.h;
 * KeePassXC src/crypto/kdf/Argon2Kdf.cpp for the KDBX parameter mapping.
 *
 * @module dsh-vault/argon2
 */

import { blake2b } from './blake2b.ts'

const BLOCK_SIZE = 1024
const SYNC_POINTS = 4
const ADDRESSES_IN_BLOCK = 128

/** Argon2 type: d = 0, i = 1, id = 2 (RFC 9106 §4.1). */
export type Argon2Type = 0 | 1 | 2

export interface Argon2Options {
  password: Buffer
  salt: Buffer
  parallelism?: number
  iterations?: number
  memoryKiB?: number
  hashLength?: number
  secret?: Buffer
  associatedData?: Buffer
  type?: Argon2Type
  version?: number
}

function le32(buf: Buffer, offset: number): number {
  return (buf[offset]! | (buf[offset + 1]! << 8) | (buf[offset + 2]! << 16) | (buf[offset + 3]! << 24)) >>> 0
}

function writeLe32(buf: Buffer, offset: number, value: number): void {
  buf.writeUInt32LE(value >>> 0, offset)
}

/** 32-bit rotate right. */
function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0
}

/** 64-bit rotate right of a lo/hi pair. */
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
  const s = n - 32
  return [
    ((hi >>> s) | (lo << (32 - s))) >>> 0,
    ((lo >>> s) | (hi << (32 - s))) >>> 0,
  ]
}

/** 64-bit add of (a,b) + (c,d), returns lo/hi. */
function add64(a: number, b: number, c: number, d: number): [number, number] {
  const sumLo = (a >>> 0) + (c >>> 0)
  return [sumLo >>> 0, (b + d + Math.floor(sumLo / 0x100000000)) >>> 0]
}

/** 64-bit product of two 32-bit words as [lo, hi] (16-bit limbs). */
function mul64(a: number, b: number): [number, number] {
  const a0 = a & 0xffff, a1 = a >>> 16
  const b0 = b & 0xffff, b1 = b >>> 16
  // a*b = P2*2^32 + P1*2^16 + P0, with P0 = a0b0, P1 = a1b0 + a0b1, P2 = a1b1
  const p0 = a0 * b0
  const p1 = a1 * b0 + a0 * b1
  const p2 = a1 * b1
  const s1 = Math.floor(p0 / 0x10000) + p1      // carry into bits 32..47
  const lo = (p0 & 0xffff) | ((s1 & 0xffff) << 16)
  const s2 = Math.floor(s1 / 0x10000) + p2      // carry into bits 48..63
  const hi = (s2 & 0xffff) | ((Math.floor(s2 / 0x10000) & 0xffff) << 16)
  return [lo >>> 0, hi >>> 0]
}

/** Low 64 bits of a*b where a,b are 32-bit words. */
function mulLo64(a: number, b: number): [number, number] {
  return mul64(a, b)
}

/** High 32 bits of a*b (a,b 32-bit), i.e. (a*b) >>> 32 exactly. */
function mulHigh32(a: number, b: number): number {
  const a0 = a & 0xffff, a1 = a >>> 16
  const b0 = b & 0xffff, b1 = b >>> 16
  const p0 = a0 * b0
  const p1 = a1 * b0 + a0 * b1
  const p2 = a1 * b1
  const s1 = Math.floor(p0 / 0x10000) + p1      // bits 16..47 carry
  const s2 = Math.floor(s1 / 0x10000) + p2      // bits 32..63
  return s2 >>> 0
}

/** fBlaMka (Lyra PHC team): x + y + 2*((x&0xffffffff)*(y&0xffffffff)) low 64. */
function fBlaMka(xLo: number, xHi: number, yLo: number, yHi: number): [number, number] {
  const [pLo, pHi] = mulLo64(xLo, yLo)
  // x + y
  const [s1Lo, s1Hi] = add64(xLo, xHi, yLo, yHi)
  // + product
  const [s2Lo, s2Hi] = add64(s1Lo, s1Hi, pLo, pHi)
  // + product again (2× product)
  return add64(s2Lo, s2Hi, pLo, pHi)
}

/** H' — variable-length hash (RFC 9106 §3.3). */
function variableHash(data: Buffer, length: number): Buffer {
  const prefix = Buffer.alloc(4)
  prefix.writeUInt32LE(length >>> 0, 0)
  const prefixed = Buffer.concat([prefix, data])
  if (length <= 64) return blake2b(prefixed, length)
  const r = Math.ceil(length / 32) - 2
  const out = Buffer.alloc(length)
  let current = blake2b(prefixed, 64) // V_1
  current.copy(out, 0, 0, 32)
  let position = 32
  for (let i = 2; i <= r; i++) {
    current = blake2b(current, 64)
    current.copy(out, position, 0, 32)
    position += 32
  }
  const last = blake2b(current, length - 32 * r)
  last.copy(out, position)
  return out
}

/** Initial hash H0 (RFC 9106 §3.2): interleaved length-then-data fields. */
function initialHash(opts: Required<Pick<Argon2Options, 'password' | 'salt' | 'parallelism' | 'iterations' | 'memoryKiB' | 'hashLength' | 'type' | 'version'>> & Pick<Argon2Options, 'secret' | 'associatedData'>): Buffer {
  const parts: Buffer[] = []
  const u32 = (v: number): Buffer => {
    const b = Buffer.alloc(4)
    b.writeUInt32LE(v >>> 0, 0)
    return b
  }
  parts.push(
    u32(opts.parallelism), u32(opts.hashLength), u32(opts.memoryKiB), u32(opts.iterations),
    u32(opts.version), u32(opts.type),
    u32(opts.password.length), opts.password,
    u32(opts.salt.length), opts.salt,
    u32(opts.secret?.length ?? 0), ...(opts.secret !== undefined ? [opts.secret] : []),
    u32(opts.associatedData?.length ?? 0), ...(opts.associatedData !== undefined ? [opts.associatedData] : []),
  )
  return blake2b(Buffer.concat(parts), 64)
}

/** G mixing on four 64-bit words (lo/hi pairs at indices 2a..2d+1). */
function gMix(v: number[], a: number, b: number, c: number, d: number): void {
  // a = fBlaMka(a, b)
  const fa = fBlaMka(v[a]!, v[a + 1]!, v[b]!, v[b + 1]!)
  v[a] = fa[0]; v[a + 1] = fa[1]
  // d = rotr64(d ^ a, 32)
  let lo = v[d]! ^ v[a]!
  let hi = v[d + 1]! ^ v[a + 1]!
  let r = rotr64(lo, hi, 32)
  v[d] = r[0]; v[d + 1] = r[1]
  // c = fBlaMka(c, d)
  const fc = fBlaMka(v[c]!, v[c + 1]!, v[d]!, v[d + 1]!)
  v[c] = fc[0]; v[c + 1] = fc[1]
  // b = rotr64(b ^ c, 24)
  lo = v[b]! ^ v[c]!
  hi = v[b + 1]! ^ v[c + 1]!
  r = rotr64(lo, hi, 24)
  v[b] = r[0]; v[b + 1] = r[1]
  // a = fBlaMka(a, b)
  const fa2 = fBlaMka(v[a]!, v[a + 1]!, v[b]!, v[b + 1]!)
  v[a] = fa2[0]; v[a + 1] = fa2[1]
  // d = rotr64(d ^ a, 16)
  lo = v[d]! ^ v[a]!
  hi = v[d + 1]! ^ v[a + 1]!
  r = rotr64(lo, hi, 16)
  v[d] = r[0]; v[d + 1] = r[1]
  // c = fBlaMka(c, d)
  const fc2 = fBlaMka(v[c]!, v[c + 1]!, v[d]!, v[d + 1]!)
  v[c] = fc2[0]; v[c + 1] = fc2[1]
  // b = rotr64(b ^ c, 63)
  lo = v[b]! ^ v[c]!
  hi = v[b + 1]! ^ v[c + 1]!
  r = rotr64(lo, hi, 63)
  v[b] = r[0]; v[b + 1] = r[1]
}

/** One BLAKE2_ROUND_NOMSG on 16 64-bit words (lo/hi entries). */
function blake2RoundNoMsg(v: number[], base: number): void {
  gMix(v, base + 0, base + 8, base + 16, base + 24)
  gMix(v, base + 2, base + 10, base + 18, base + 26)
  gMix(v, base + 4, base + 12, base + 20, base + 28)
  gMix(v, base + 6, base + 14, base + 22, base + 30)
  gMix(v, base + 0, base + 10, base + 20, base + 30)
  gMix(v, base + 2, base + 12, base + 22, base + 24)
  gMix(v, base + 4, base + 14, base + 16, base + 26)
  gMix(v, base + 6, base + 8, base + 18, base + 28)
}

/** One BLAKE2_ROUND_NOMSG over 16 explicit word indices (lo/hi = 2×word). */
function blake2RoundNoMsgWords(v: number[], w: number[]): void {
  const e = w.map(x => x * 2)
  gMix(v, e[0]!, e[4]!, e[8]!, e[12]!)
  gMix(v, e[1]!, e[5]!, e[9]!, e[13]!)
  gMix(v, e[2]!, e[6]!, e[10]!, e[14]!)
  gMix(v, e[3]!, e[7]!, e[11]!, e[15]!)
  gMix(v, e[0]!, e[5]!, e[10]!, e[15]!)
  gMix(v, e[1]!, e[6]!, e[11]!, e[12]!)
  gMix(v, e[2]!, e[7]!, e[8]!, e[13]!)
  gMix(v, e[3]!, e[4]!, e[9]!, e[14]!)
}

/** A 1024-byte block viewed as 128 little-endian 64-bit words (lo/hi). */
class Block {
  readonly v = new Array<number>(256)
  private readonly raw: Buffer

  constructor(raw?: Buffer) {
    this.raw = raw ?? Buffer.alloc(BLOCK_SIZE)
    this.load()
  }

  private load(): void {
    for (let i = 0; i < 128; i++) {
      this.v[i * 2] = le32(this.raw, i * 8)
      this.v[i * 2 + 1] = le32(this.raw, i * 8 + 4)
    }
  }

  toBuffer(): Buffer {
    for (let i = 0; i < 128; i++) {
      this.raw.writeUInt32LE(this.v[i * 2]! >>> 0, i * 8)
      this.raw.writeUInt32LE(this.v[i * 2 + 1]! >>> 0, i * 8 + 4)
    }
    return this.raw
  }

  clear(): void {
    this.v.fill(0)
  }

  copyFrom(other: Block): void {
    for (let i = 0; i < 256; i++) this.v[i] = other.v[i]!
  }

  xorAssign(other: Block): void {
    for (let i = 0; i < 256; i++) this.v[i] = (this.v[i]! ^ other.v[i]!) >>> 0
  }

  /** Permutation P: column rounds then row rounds (reference fill_block). */
  permute(): void {
    for (let i = 0; i < 8; i++) blake2RoundNoMsg(this.v, 32 * i)
    for (let i = 0; i < 8; i++) {
      const b = 2 * i
      blake2RoundNoMsgWords(this.v, [
        b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
        b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113,
      ])
    }
  }
}

/** Reference fill_block: next = (prev XOR ref) after P, XORed with next if withXor. */
function fillBlock(prev: Block, ref: Block, next: Block, withXor: boolean): void {
  const blockR = new Block()
  blockR.copyFrom(ref)
  blockR.xorAssign(prev)
  const blockTmp = new Block()
  blockTmp.copyFrom(blockR)
  if (withXor) blockTmp.xorAssign(next)
  blockR.permute()
  // next = blockTmp XOR blockR
  blockTmp.xorAssign(blockR)
  next.copyFrom(blockTmp)
}

/** next_addresses: generate the next 128 address words. */
function nextAddresses(address: Block, input: Block, zero: Block): void {
  input.v[12] = (input.v[12]! + 1) >>> 0 // v[6] is the 7th 64-bit word
  fillBlock(zero, input, address, false)
  fillBlock(zero, address, address, false)
}

/** Reference index_alpha (RFC 9106 §3.4.1.3). */
function indexAlpha(pass: number, slice: number, index: number, sameLane: boolean, segmentLength: number, laneLength: number, pseudoRand: number): number {
  let referenceAreaSize: number
  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1
    } else if (sameLane) {
      referenceAreaSize = slice * segmentLength + index - 1
    } else {
      referenceAreaSize = slice * segmentLength + (index === 0 ? -1 : 0)
    }
  } else if (sameLane) {
    referenceAreaSize = laneLength - segmentLength + index - 1
  } else {
    referenceAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0)
  }
  let relativePosition = pseudoRand >>> 0
  relativePosition = mulHigh32(relativePosition, relativePosition)
  relativePosition = referenceAreaSize - 1 - mulHigh32(referenceAreaSize, relativePosition)
  let startPosition = 0
  if (pass !== 0) {
    startPosition = slice === SYNC_POINTS - 1 ? 0 : (slice + 1) * segmentLength
  }
  return (startPosition + relativePosition) % laneLength
}

/**
 * Argon2 (RFC 9106). `type` 0 = Argon2d, 2 = Argon2id. Returns the tag.
 */
export function argon2(opts: Argon2Options): Buffer {
  const lanes = opts.parallelism ?? 1
  const passes = opts.iterations ?? 3
  const memoryKiB = opts.memoryKiB ?? 32
  const hashLen = opts.hashLength ?? 32
  const type = opts.type ?? 0
  const version = opts.version ?? 0x13
  if (lanes < 1 || passes < 1) throw new Error('argon2: parallelism and iterations must be >= 1')
  if (memoryKiB < 8 * lanes) throw new Error(`argon2: memory (${memoryKiB} KiB) too small for ${lanes} lanes (min ${8 * lanes})`)

  const segmentLength = Math.floor(memoryKiB / (lanes * SYNC_POINTS))
  const laneLength = segmentLength * SYNC_POINTS
  const memoryBlocks = laneLength * lanes

  const h0 = initialHash({
    password: opts.password, salt: opts.salt, parallelism: lanes, iterations: passes,
    memoryKiB, hashLength: hashLen, type, version,
    ...(opts.secret !== undefined ? { secret: opts.secret } : {}),
    ...(opts.associatedData !== undefined ? { associatedData: opts.associatedData } : {}),
  })

  // Memory blocks (all allocated), initialized with H'(H0 || le32(idx) || le32(lane)).
  const blocks: Block[] = []
  for (let i = 0; i < memoryBlocks; i++) blocks.push(new Block())
  for (let lane = 0; lane < lanes; lane++) {
    for (let b = 0; b < 2; b++) {
      const input = Buffer.alloc(72)
      h0.copy(input, 0, 0, 64)
      writeLe32(input, 64, b)
      writeLe32(input, 68, lane)
      const blk = blocks[lane * laneLength + b]!
      blk.clear()
      const h = variableHash(input, BLOCK_SIZE)
      for (let i = 0; i < 128; i++) {
        blk.v[i * 2] = le32(h, i * 8)
        blk.v[i * 2 + 1] = le32(h, i * 8 + 4)
      }
    }
  }

  const zero = new Block()
  zero.clear()
  const input = new Block()
  input.clear()
  const address = new Block()
  address.clear()

  const dataIndependentAddressing = (pass: number, slice: number): boolean =>
    type === 1 || (type === 2 && pass === 0 && slice < SYNC_POINTS / 2)

  for (let pass = 0; pass < passes; pass++) {
    for (let slice = 0; slice < SYNC_POINTS; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        const dataIndependent = dataIndependentAddressing(pass, slice)
        if (dataIndependent) {
          // input_block.v[0..5] = pass, lane, slice, memory_blocks, passes, type
          input.clear()
          input.v[0] = pass >>> 0
          input.v[2] = lane >>> 0
          input.v[4] = slice >>> 0
          input.v[6] = memoryBlocks >>> 0
          input.v[8] = passes >>> 0
          input.v[10] = type >>> 0
        }
        let startingIndex = 0
        if (pass === 0 && slice === 0) {
          startingIndex = 2
          if (dataIndependent) nextAddresses(address, input, zero)
        }
        // current/previous offsets within the lane (wrap at lane boundary)
        for (let i = startingIndex; i < segmentLength; i++) {
          const currPos = lane * laneLength + slice * segmentLength + i
          let prevPos: number
          if (currPos % laneLength === 0) prevPos = currPos + laneLength - 1
          else prevPos = currPos - 1
          if (currPos % laneLength === 1) prevPos = currPos - 1
          // pseudo-random 64-bit word from previous block or address block
          let pseudoLo: number
          let pseudoHi: number
          if (dataIndependent) {
            if (i % ADDRESSES_IN_BLOCK === 0) nextAddresses(address, input, zero)
            const w = (i % ADDRESSES_IN_BLOCK) * 2
            pseudoLo = address.v[w]!
            pseudoHi = address.v[w + 1]!
          } else {
            pseudoLo = blocks[prevPos]!.v[0]!
            pseudoHi = blocks[prevPos]!.v[1]!
          }
          const refLane = pass === 0 && slice === 0
            ? lane
            : (pseudoHi % lanes)
          const sameLane = refLane === lane
          const refIndex = indexAlpha(pass, slice, i, sameLane, segmentLength, laneLength, pseudoLo)
          const refPos = refLane * laneLength + refIndex
          if (blocks[prevPos] === undefined || blocks[refPos] === undefined || blocks[currPos] === undefined) {
            throw new Error(`argon2: OOB pass=${pass} slice=${slice} lane=${lane} i=${i} curr=${currPos} prev=${prevPos} ref=${refPos} (mem=${memoryBlocks})`)
          }
          const refBlock = blocks[refPos]!
          const currBlock = blocks[currPos]!
          fillBlock(blocks[prevPos]!, refBlock, currBlock, pass > 0)
        }
      }
    }
  }

  // Final block: XOR of each lane's last block, then H'.
  const final = new Block()
  final.clear()
  for (let lane = 0; lane < lanes; lane++) {
    final.xorAssign(blocks[lane * laneLength + laneLength - 1]!)
  }
  return variableHash(final.toBuffer(), hashLen)
}
