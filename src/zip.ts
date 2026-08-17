/**
 * Minimal read-only ZIP archive parser for dsh-vault.
 *
 * Implements just enough of the ZIP spec (APPNOTE.TXT) to read a 1Password
 * 1PUX export: End Of Central Directory + Central Directory entries + Local
 * File Headers, with stored (0) and deflate (8) compression via node:zlib.
 * Kept intentionally small, mirroring the style of src/sqlite.ts.
 *
 * @module dsh-vault/zip
 */

import { inflateRawSync } from 'node:zlib'

const EOCD_SIG = 0x06054b50
const CENTRAL_SIG = 0x02014b50
const LOCAL_SIG = 0x04034b50

/** Read a LE uint16. */
function le16(buf: Buffer, offset: number): number {
  return buf[offset]! | (buf[offset + 1]! << 8)
}

/** Read a LE uint32. */
function le32(buf: Buffer, offset: number): number {
  return (buf[offset]! | (buf[offset + 1]! << 8) | (buf[offset + 2]! << 16) | (buf[offset + 3]! << 24)) >>> 0
}

/** Locate the End Of Central Directory record by scanning backwards. */
function findEocd(data: Buffer): number {
  const min = data.length - 65557 // EOCD (22) + max comment (65535)
  for (let p = data.length - 22; p >= Math.max(0, min); p--) {
    if (le32(data, p) === EOCD_SIG) return p
  }
  throw new Error('zip: end of central directory not found (not a zip file)')
}

export interface ZipEntry {
  name: string
  /** Raw (uncompressed) file content. */
  data: Buffer
  size: number
}

/**
 * Read all entries from a ZIP archive buffer. Only stored (0) and deflate (8)
 * methods are supported; other methods are rejected with a clear error.
 */
export function readZip(data: Buffer): ZipEntry[] {
  if (data.length < 22) throw new Error('zip: file too short')
  const eocd = findEocd(data)
  const centralOffset = le32(data, eocd + 16)
  const centralCount = le16(data, eocd + 10)
  const entries: ZipEntry[] = []
  let p = centralOffset
  for (let i = 0; i < centralCount; i++) {
    if (le32(data, p) !== CENTRAL_SIG) throw new Error('zip: bad central directory entry')
    const method = le16(data, p + 10)
    const compSize = le32(data, p + 20)
    const nameLen = le16(data, p + 28)
    const extraLen = le16(data, p + 30)
    const commentLen = le16(data, p + 32)
    const localOffset = le32(data, p + 42)
    const name = data.subarray(p + 46, p + 46 + nameLen).toString('utf8')
    p += 46 + nameLen + extraLen + commentLen
    if (name.endsWith('/')) continue // directory entry

    // Walk the local file header to find the payload offset (skips its extra field).
    if (le32(data, localOffset) !== LOCAL_SIG) throw new Error(`zip: bad local header for ${name}`)
    const localNameLen = le16(data, localOffset + 26)
    const localExtraLen = le16(data, localOffset + 28)
    const payload = localOffset + 30 + localNameLen + localExtraLen

    let raw = data.subarray(payload, payload + compSize)
    if (method === 8) {
      raw = inflateRawSync(raw)
    } else if (method !== 0) {
      throw new Error(`zip: unsupported compression method ${method} for ${name}`)
    }
    entries.push({ name, data: Buffer.from(raw), size: raw.length })
  }
  return entries
}

/** Convenience: find one entry by exact name. */
export function zipEntry(entries: ZipEntry[], name: string): Buffer | undefined {
  const found = entries.find(e => e.name === name || e.name.endsWith(`/${name}`))
  return found?.data
}

/** Write a minimal ZIP archive (stored, no compression) from named buffers.
 * Enough for 1PUX exports and other tools that accept plain ZIP containers. */
export function createZip(entries: Array<{ name: string; data: Buffer }>): Buffer {
  const chunks: Buffer[] = []
  const central: Buffer[] = []
  let offset = 0
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8')
    // Local file header.
    const local = Buffer.alloc(30)
    local.writeUInt32LE(LOCAL_SIG, 0)
    local.writeUInt16LE(20, 4) // version needed
    local.writeUInt16LE(0x0800, 6) // UTF-8 flag
    local.writeUInt16LE(0, 8) // method: stored
    local.writeUInt32LE(0, 10) // crc (0; stored readers ignore for our data)
    local.writeUInt32LE(data.length, 14) // compressed size
    local.writeUInt32LE(data.length, 18) // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26)
    local.writeUInt16LE(0, 28) // extra len
    chunks.push(Buffer.concat([local, nameBuf, data]))
    // Central directory entry.
    const cd = Buffer.alloc(46)
    cd.writeUInt32LE(CENTRAL_SIG, 0)
    cd.writeUInt16LE(20, 4)
    cd.writeUInt16LE(20, 6)
    cd.writeUInt16LE(0x0800, 8)
    cd.writeUInt16LE(0, 10) // method
    cd.writeUInt32LE(0, 12) // crc
    cd.writeUInt32LE(data.length, 16)
    cd.writeUInt32LE(data.length, 20)
    cd.writeUInt16LE(nameBuf.length, 28)
    cd.writeUInt16LE(0, 30) // extra
    cd.writeUInt16LE(0, 32) // comment
    cd.writeUInt16LE(0, 34) // disk
    cd.writeUInt16LE(0, 36) // internal attrs
    cd.writeUInt32LE(0, 38) // external attrs
    cd.writeUInt32LE(offset, 42) // local header offset
    central.push(Buffer.concat([cd, nameBuf]))
    offset += 30 + nameBuf.length + data.length
  }
  const centralStart = offset
  const centralBuf = Buffer.concat(central)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(EOCD_SIG, 0)
  eocd.writeUInt16LE(0, 4) // disk
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(centralBuf.length, 12)
  eocd.writeUInt32LE(centralStart, 16)
  eocd.writeUInt16LE(0, 20) // comment len
  return Buffer.concat([...chunks, centralBuf, eocd])
}
