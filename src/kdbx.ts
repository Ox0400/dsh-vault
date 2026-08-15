/**
 * KeePass KDBX4 importer for dsh-vault.
 *
 * Implements the KDBX 4 file format per the open-source
 * [keepassxc-specs](https://github.com/Evidlo/keepassxc-specs/blob/master/kdbx-binary/kdbx4_overview.md)
 * and KeePass docs: AES-KDF and Argon2 (RFC 9106) key transformation,
 * AES-256-CBC payload decryption, HMAC-SHA256 block verification, gzip
 * payload decompression, and ChaCha20/Salsa20 protected-field stream
 * decryption.
 *
 * @module dsh-vault/kdbx
 */

import { createCipheriv, createDecipheriv, createHash, createHmac } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { chacha20Xor } from './chacha20.ts'
import { salsa20Xor } from './salsa20.ts'
import { argon2 } from './argon2.ts'

export interface KdbxCredential {
  title: string
  username: string
  password: string
  url: string
  notes: string
}

const AES_CIPHER_ID = Buffer.from('31c1f2e6bf714350be5805216afc5aff', 'hex')
const AES_KDF_UUID = Buffer.from('c9d9f39a628a4460bf740d08c18a4fea', 'hex')
const ARGON2_UUID = Buffer.from('ef636ddf8c29444b91f7a9a403e30a0c', 'hex')

/** Read a LE uint32. */
function le32(buf: Buffer, offset: number): number {
  return (buf[offset]! | (buf[offset + 1]! << 8) | (buf[offset + 2]! << 16) | (buf[offset + 3]! << 24)) >>> 0
}

/** Read a LE uint64 as a Number (safe for the ranges used here). */
function le64(buf: Buffer, offset: number): number {
  return le32(buf, offset) + le32(buf, offset + 4) * 0x100000000
}

/** Parse a KDBX VariantDictionary into a plain object. */
function parseVariantDictionary(buf: Buffer): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  let p = 2 // skip version
  while (p < buf.length && buf[p] !== 0) {
    const type = buf[p]!
    const keyLen = le32(buf, p + 1)
    const key = buf.subarray(p + 5, p + 5 + keyLen).toString('utf8')
    p += 5 + keyLen
    const valLen = le32(buf, p)
    const value = buf.subarray(p + 4, p + 4 + valLen)
    p += 4 + valLen
    switch (type) {
      case 0x04: out[key] = le32(value, 0); break
      case 0x05: out[key] = le64(value, 0); break
      case 0x08: out[key] = Buffer.from(value); break
      case 0x0c: out[key] = value[0] !== 0; break
      default: out[key] = Buffer.from(value); break
    }
  }
  return out
}

/** Parse the KDBX dynamic header. */
function parseDynamicHeader(buf: Buffer): { fields: Record<number, Buffer>; end: number } {
  const fields: Record<number, Buffer> = {}
  let p = 0
  while (p < buf.length) {
    const type = buf[p]!
    const len = le32(buf, p + 1)
    const data = buf.subarray(p + 5, p + 5 + len)
    p += 5 + len
    if (type === 0) break // end
    fields[type] = Buffer.from(data)
  }
  return { fields, end: p }
}

/** AES-ECB single-block encrypt (AES-KDF transform). */
function aesEcbEncrypt(key: Buffer, block: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-ecb', key as Buffer<ArrayBuffer>, null)
  cipher.setAutoPadding(false)
  return Buffer.from(Buffer.concat([cipher.update(block), cipher.final()]))
}

/** KeePass fixed Salsa20 nonce (E8 30 09 4B 97 20 5D 2A). */
const SALSA20_NONCE = Buffer.from('e830094b97205d2a', 'hex')

/**
 * Unprotect a base64 protected value with the KDBX inner random stream.
 * KDBX4 inner random stream ids: 2 = Salsa20 (key = SHA256(streamKey),
 * fixed nonce), 3 = ChaCha20 (key = SHA512(streamKey)[0:32], nonce = [32:44]).
 */
function unprotect(value: Buffer, streamId: number, streamKey: Buffer): string {
  let plain: Buffer
  if (streamId === 3) {
    const h = createHash('sha512').update(streamKey).digest()
    plain = chacha20Xor(value, h.subarray(0, 32), h.subarray(32, 44), 0)
  } else if (streamId === 2) {
    const key = createHash('sha256').update(streamKey).digest()
    plain = salsa20Xor(value, key, SALSA20_NONCE, 0)
  } else {
    throw new Error(`kdbx: unsupported inner random stream id ${streamId}`)
  }
  return plain.toString('utf8')
}

/**
 * Extract entry fields from a KeePass XML group/entry (lightweight parser).
 * Each entry is a list of [fieldName, value, protected] in document order,
 * because the protected stream must be consumed sequentially.
 */
function extractEntries(xml: string): Array<Array<[string, string, boolean]>> {
  const entries: Array<Array<[string, string, boolean]>> = []
  const entryRe = /<Entry>([\s\S]*?)<\/Entry>/g
  // Each field is <String><Key>Name</Key><Value [Protected="True"]>data</Value></String>.
  const stringRe = /<String>([\s\S]*?)<\/String>/g
  const kvRe = /<Key>([\s\S]*?)<\/Key>\s*<Value([^>]*)>([\s\S]*?)<\/Value>/
  let m: RegExpExecArray | null
  while ((m = entryRe.exec(xml)) !== null) {
    const body = m[1]!
    const fields: Array<[string, string, boolean]> = []
    let sm: RegExpExecArray | null
    stringRe.lastIndex = 0
    while ((sm = stringRe.exec(body)) !== null) {
      const kv = kvRe.exec(sm[1]!)
      if (!kv) continue
      const name = kv[1]!.trim()
      const protectedFlag = /\bProtected="True"/.test(kv[2] ?? '')
      fields.push([name, kv[3]!.trim(), protectedFlag])
    }
    entries.push(fields)
  }
  return entries
}

/**
 * Read KeePass KDBX4 entries from a file buffer.
 * @param data - raw .kdbx bytes.
 * @param password - database password (empty allowed).
 * @param keyfileData - optional keyfile bytes (SHA-256 used).
 * @returns decrypted entries (protected values already decrypted).
 */
export function readKdbx(data: Buffer, password: string, keyfileData?: Buffer): KdbxCredential[] {
  if (data.length < 12) throw new Error('kdbx: file too short')
  const sig1 = data.readUInt32LE(0)
  const sig2 = data.readUInt32LE(4)
  const version = data.readUInt32LE(8)
  if (sig1 !== 0x9aa2d903 || sig2 !== 0xb54bfb67) throw new Error('kdbx: not a KeePass database (bad signature)')
  if ((version & 0xffff0000) !== 0x00040000) {
    throw new Error(`kdbx: unsupported KDBX version 0x${version.toString(16)} (only KDBX 4.x is supported)`)
  }
  const headerEnd = 12
  const { fields, end } = parseDynamicHeader(data.subarray(headerEnd))
  const headerForHash = data.subarray(0, headerEnd + end)

  const cipherId = fields[2]
  const compression = fields[3]
  const masterSeed = fields[4]
  const encryptionIv = fields[7]
  const kdf = fields[0x0b]
  if (!cipherId || !masterSeed || !encryptionIv || !kdf) throw new Error('kdbx: missing required header fields')
  if (!cipherId.equals(AES_CIPHER_ID)) throw new Error('kdbx: only AES-256 cipher is supported')
  const kdfParams = parseVariantDictionary(kdf)
  const kdfUuid = kdfParams.$UUID as Buffer | undefined
  if (!kdfUuid) throw new Error('kdbx: KDF parameters missing $UUID')

  // key_composite = SHA256(SHA256(password) || SHA256(keyfile)); empty keyfile contributes zero bytes.
  const pwHash = createHash('sha256').update(Buffer.from(password, 'utf8')).digest()
  const keyfileHash = keyfileData !== undefined ? createHash('sha256').update(keyfileData).digest() : Buffer.alloc(0)
  const composite = createHash('sha256').update(Buffer.from(Buffer.concat([pwHash, keyfileHash]))).digest()

  let transformedKey: Buffer
  if (kdfUuid.equals(ARGON2_UUID)) {
    // Argon2 (RFC 9106) — the KeePassXC/KeePass default since 2.55/2.7.
    // Params: S (salt), P (parallelism), I (iterations), M (memory KiB), V
    // (version), optional K (secret) and A (associated data).
    const salt = kdfParams.S as Buffer | undefined
    const iterations = typeof kdfParams.I === 'number' ? kdfParams.I : 0
    const parallelism = typeof kdfParams.P === 'number' ? kdfParams.P : 0
    const memoryKiB = typeof kdfParams.M === 'number' ? kdfParams.M : 0
    const version = typeof kdfParams.V === 'number' ? kdfParams.V : 0x13
    const secret = kdfParams.K as Buffer | undefined
    const assocData = kdfParams.A as Buffer | undefined
    if (!salt) throw new Error('kdbx: Argon2 KDF missing salt')
    transformedKey = argon2({
      password: composite,
      salt,
      parallelism,
      iterations,
      memoryKiB,
      hashLength: 32,
      type: 2, // KDBX uses Argon2id
      version,
      ...(secret !== undefined ? { secret } : {}),
      ...(assocData !== undefined ? { associatedData: assocData } : {}),
    })
  } else if (kdfUuid.equals(AES_KDF_UUID)) {
    // AES-KDF: transform R rounds of AES-ECB (key = S) over the 32-byte
    // composite, then SHA-256 the result (matches KeePassXC/KeePass KDBX4).
    const rounds = typeof kdfParams.R === 'number' ? kdfParams.R : 0
    const transformKey = kdfParams.S as Buffer
    let transformed: Buffer = composite
    for (let i = 0; i < rounds; i++) transformed = aesEcbEncrypt(transformKey, transformed)
    transformedKey = createHash('sha256').update(transformed).digest()
  } else {
    throw new Error('kdbx: unsupported KDF')
  }

  const masterKey = createHash('sha256').update(Buffer.concat([masterSeed as Buffer<ArrayBuffer>, transformedKey as Buffer<ArrayBuffer>])).digest()

  // Header HMAC key: getHmacKey(UINT64_MAX, SHA512(masterSeed || transformedKey || 0x01)).
  const hmacBase = createHash('sha512').update(Buffer.from(Buffer.concat([masterSeed, transformedKey, Buffer.from([0x01])]))).digest()
  const headerHmacKey = createHash('sha512').update(Buffer.from(Buffer.concat([Buffer.alloc(8, 0xff), hmacBase]))).digest()
  const headerHash = createHash('sha256').update(headerForHash).digest()
  const fileHash = data.subarray(headerEnd + end, headerEnd + end + 32)
  const fileHmac = data.subarray(headerEnd + end + 32, headerEnd + end + 64)
  if (!fileHash.equals(headerHash)) throw new Error('kdbx: header SHA-256 mismatch (corrupt or wrong file)')
  const expectedHmac = createHmac('sha256', headerHmacKey).update(headerForHash).digest()
  if (!fileHmac.equals(expectedHmac)) throw new Error('kdbx: header HMAC mismatch')

  // Concatenate encrypted blocks (with HMAC verification).
  // Block HMAC key for index i: SHA512(le64(i) || hmacKey), hmacKey = SHA512(masterSeed || transformedKey || 0x01).
  let p = headerEnd + end + 64
  const hmacKey = createHash('sha512').update(Buffer.from(Buffer.concat([masterSeed, transformedKey, Buffer.from([0x01])]))).digest()
  const encrypted = Buffer.alloc(data.length - p)
  let outLen = 0
  let index = 0
  while (p < data.length) {
    const blkHmac = data.subarray(p, p + 32)
    const blkLen = le32(data, p + 32)
    const blk = data.subarray(p + 36, p + 36 + blkLen)
    p += 36 + blkLen
    if (blkLen === 0) break
    const indexBuf = Buffer.alloc(8)
    indexBuf.writeBigUInt64LE(BigInt(index))
    const blockHmacKey = createHash('sha512').update(Buffer.from(Buffer.concat([indexBuf, hmacKey]))).digest()
    const lenBuf = Buffer.alloc(4)
    lenBuf.writeUInt32LE(blkLen, 0)
    const expected = createHmac('sha256', blockHmacKey).update(Buffer.from(Buffer.concat([indexBuf, lenBuf, blk]))).digest()
    if (!blkHmac.equals(expected)) throw new Error(`kdbx: block ${index} HMAC mismatch`)
    blk.copy(encrypted, outLen)
    outLen += blkLen
    index++
  }
  const payload = encrypted.subarray(0, outLen)

  // Decrypt AES-256-CBC.
  const decipher = createDecipheriv('aes-256-cbc', masterKey as Buffer<ArrayBuffer>, encryptionIv as Buffer<ArrayBuffer>)
  decipher.setAutoPadding(true)
  const decryptedRaw = Buffer.concat([decipher.update(payload), decipher.final()])

  // Decompress (compression flag 1 = gzip).
  let decrypted: Buffer
  if (compression !== undefined && compression[0] === 1) {
    decrypted = gunzipSync(decryptedRaw)
  } else {
    decrypted = decryptedRaw
  }

  // Inner header (protected stream) + XML.
  const inner = parseDynamicHeader(decrypted)
  const xml = decrypted.subarray(inner.end).toString('utf8')
  const streamId = inner.fields[1] ? le32(inner.fields[1], 0) : 0
  const streamKey = inner.fields[2]

  const entries = extractEntries(xml)
  if (streamId !== 2 && streamId !== 3) {
    // Without a supported protected stream we cannot decrypt protected values.
    if (streamKey && streamId !== 2 && streamId !== 3) throw new Error(`kdbx: unsupported inner random stream id ${streamId} (only Salsa20 and ChaCha20 are supported)`)
    return entries.map((fields) => fieldListToCredential(fields, (_v) => ''))
  }
  // Decrypt protected values with one continuous keystream in document order.
  const decryptedEntries: KdbxCredential[] = []
  const protectedValues: Array<[number, number, string]> = [] // [entryIdx, fieldIdx, base64]
  entries.forEach((fields, ei) => {
    fields.forEach(([name, value, isProtected], fi) => {
      if (isProtected && value.length > 0) protectedValues.push([ei, fi, value])
    })
  })
  // Build the whole keystream lazily: Salsa20/ChaCha20 blocks are 64 bytes,
  // so a value may span block boundaries. We track a running byte offset and
  // XOR each protected ciphertext with keystream bytes at the same offset.
  let makeBlock: (counter: number) => Buffer
  if (streamId === 3) {
    // ChaCha20: key = SHA512(streamKey)[0:32], nonce = [32:44].
    const h = createHash('sha512').update(streamKey!).digest()
    const key = h.subarray(0, 32)
    const nonce = h.subarray(32, 44)
    makeBlock = (c) => chacha20Xor(Buffer.alloc(64), key, nonce, c)
  } else if (streamId === 2) {
    // Salsa20: key = SHA256(streamKey), fixed nonce.
    const key = createHash('sha256').update(streamKey!).digest()
    makeBlock = (c) => salsa20Xor(Buffer.alloc(64), key, SALSA20_NONCE, c)
  } else {
    makeBlock = () => Buffer.alloc(0)
  }
  const valuesByIdx = new Map<string, string>()
  let streamOffset = 0
  const keystreamCache = new Map<number, Buffer>()
  for (const [ei, fi, b64] of protectedValues) {
    try {
      const enc = Buffer.from(b64, 'base64')
      const plain = Buffer.alloc(enc.length)
      let pos = 0
      while (pos < enc.length) {
        const blockIndex = Math.floor((streamOffset + pos) / 64)
        const inBlock = (streamOffset + pos) % 64
        let block = keystreamCache.get(blockIndex)
        if (!block) {
          block = makeBlock(blockIndex)
          keystreamCache.set(blockIndex, block)
        }
        const take = Math.min(64 - inBlock, enc.length - pos)
        for (let i = 0; i < take; i++) plain[pos + i] = enc[pos + i]! ^ block[inBlock + i]!
        pos += take
      }
      streamOffset += enc.length
      valuesByIdx.set(`${ei}:${fi}`, plain.toString('utf8'))
    } catch {
      valuesByIdx.set(`${ei}:${fi}`, '')
    }
  }
  entries.forEach((fields, ei) => {
    const out: Record<string, string> = {}
    fields.forEach(([name, value, isProtected], fi) => {
      out[name] = isProtected ? (valuesByIdx.get(`${ei}:${fi}`) ?? '') : value
    })
    decryptedEntries.push({
      title: out.Title ?? '',
      username: out.UserName ?? '',
      password: out.Password ?? '',
      url: out.URL ?? '',
      notes: out.Notes ?? '',
    })
  })
  return decryptedEntries
}

/** Build a KdbxCredential from ordered field triples (no stream decryption). */
function fieldListToCredential(fields: Array<[string, string, boolean]>, unprotect: (v: string) => string): KdbxCredential {
  const out: Record<string, string> = {}
  for (const [name, value, isProtected] of fields) {
    out[name] = isProtected ? unprotect(value) : value
  }
  return {
    title: out.Title ?? '',
    username: out.UserName ?? '',
    password: out.Password ?? '',
    url: out.URL ?? '',
    notes: out.Notes ?? '',
  }
}
