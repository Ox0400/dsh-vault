/**
 * Minimal read-only SQLite parser for dsh-vault.
 *
 * Implements just enough of the SQLite file format to enumerate the rows of a
 * single table: the 100-byte header, the table b-tree (leaf + interior
 * pages), and the record format (serial-type varints). Used to read Chrome's
 * `Login Data` database without any native dependency. The database must be
 * quiescent (no active WAL) — callers should copy the file first.
 *
 * @module dsh-vault/sqlite
 */

import { readFileSync } from 'node:fs'

/** Read a 16-bit big-endian integer. */
function readU16(buf: Buffer, offset: number): number {
  return (buf[offset]! << 8) | buf[offset + 1]!
}

/** Read a 32-bit big-endian integer. */
function readU32(buf: Buffer, offset: number): number {
  return ((buf[offset]! << 24) | (buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!) >>> 0
}

/** Decode a SQLite varint. */
function readVarint(buf: Buffer, offset: number): { value: number; size: number } {
  let value = 0
  for (let i = 0; i < 8; i++) {
    const b = buf[offset + i]!
    value = value * 128 + (b & 0x7f)
    if ((b & 0x80) === 0) return { value, size: i + 1 }
  }
  const b = buf[offset + 8]!
  value = value * 256 + b
  return { value, size: 9 }
}

/** Decode a record payload into typed column values. */
function parseRecord(payload: Buffer): unknown[] {
  // Header size varint, then serial-type varints.
  const headerSize = readVarint(payload, 0)
  const types: number[] = []
  let p = headerSize.size
  const headerEnd = headerSize.value
  while (p < headerEnd) {
    const vt = readVarint(payload, p)
    types.push(vt.value)
    p += vt.size
  }
  const values: unknown[] = []
  let data = headerEnd
  for (const t of types) {
    if (t === 0) { values.push(null); continue }
    if (t === 1) { values.push(payload.readInt8(data)); data += 1; continue }
    if (t === 2) { values.push(payload.readInt16BE(data)); data += 2; continue }
    if (t === 3) {
      // 24-bit signed integer.
      let v = (payload[data]! << 16) | (payload[data + 1]! << 8) | payload[data + 2]!
      if (v & 0x800000) v -= 0x1000000
      values.push(v); data += 3; continue
    }
    if (t === 4) { values.push(payload.readInt32BE(data)); data += 4; continue }
    if (t === 5) {
      const hi = payload.readInt16BE(data)
      const lo = payload.readUInt32BE(data + 2)
      values.push(hi * 0x100000000 + lo); data += 6; continue
    }
    if (t === 6) { values.push(payload.readBigInt64BE(data) as unknown); data += 8; continue }
    if (t === 7) { values.push(payload.readDoubleBE(data)); data += 8; continue }
    if (t === 8) { values.push(0); continue }
    if (t === 9) { values.push(1); continue }
    if (t >= 13) {
      const len = (t - 13) >> 1
      if (t % 2 === 0) {
        // Text (UTF-8).
        const text = payload.toString('utf8', data, data + len)
        values.push(text); data += len
      } else {
        // Blob.
        values.push(Buffer.from(payload.subarray(data, data + len))); data += len
      }
      continue
    }
    // t in 10..12 are reserved; treat as blob of (t-12)/2.
    const len = (t - 12) >> 1
    values.push(Buffer.from(payload.subarray(data, data + len))); data += len
  }
  return values
}

/** One decoded row: a map of column name → value (string | Buffer | number | null). */
export type SqliteRow = Record<string, unknown>

/**
 * Read every row of one table from a SQLite file. Only the columns listed in
 * `columns` are returned. Supports leaf and interior b-tree pages.
 * @throws when the file is not a SQLite database or the table is missing.
 */
export function readTableRows(dbPath: string, table: string, columns: string[]): SqliteRow[] {
  const buf = readFileSync(dbPath)
  if (buf.length < 100 || buf.toString('latin1', 0, 16) !== 'SQLite format 3\u0000') {
    throw new Error('not a SQLite database file')
  }
  const pageSize = readU16(buf, 16) || 65536
  const pages = Math.ceil(buf.length / pageSize)

  const readPage = (num: number): Buffer => {
    if (num < 1 || num > pages) throw new Error(`page ${num} out of range`)
    // Page 1 begins after the 100-byte file header; every other page starts
    // at its own offset. The b-tree offsets below are relative to the page
    // content (page 1: type at 100, cell pointers at 108).
    const off = num === 1 ? 100 : (num - 1) * pageSize
    return buf.subarray(off, Math.min(off + pageSize, buf.length))
  }

  // Walk the sqlite_master table (root page 1) to find the target table root.
  let rootPage = -1
  const walkMaster = (pageNum: number): void => {
    const page = readPage(pageNum)
    const type = page[0]!
    if (type === 13) {
      // Leaf table page: cell pointer array after the header.
      const cellCount = readU16(page, 3)
      for (let i = 0; i < cellCount; i++) {
        const cellPtr = readU16(page, 8 + i * 2)
        // payload length varint + rowid varint + payload
        const plen = readVarint(page, cellPtr)
        const rowid = readVarint(page, cellPtr + plen.size)
        const payloadStart = cellPtr + plen.size + rowid.size
        const payload = page.subarray(payloadStart, payloadStart + plen.value)
        const record = parseRecord(payload)
        // sqlite_master: type, name, tbl_name, rootpage, sql
        if (record[1] === table && typeof record[3] === 'number') rootPage = record[3]
      }
    } else if (type === 5) {
      const cellCount = readU16(page, 3)
      const rightmost = readU32(page, 8)
      for (let i = 0; i < cellCount; i++) {
        const cellPtr = readU16(page, 12 + i * 2)
        const child = readU32(page, cellPtr)
        walkMaster(child)
      }
      walkMaster(rightmost)
    }
  }
  walkMaster(1)
  if (rootPage < 0) throw new Error(`table "${table}" not found`)

  const rows: SqliteRow[] = []
  const walkTable = (pageNum: number): void => {
    const page = readPage(pageNum)
    const type = page[0]!
    if (type === 13) {
      const cellCount = readU16(page, 3)
      for (let i = 0; i < cellCount; i++) {
        const cellPtr = readU16(page, 8 + i * 2)
        const plen = readVarint(page, cellPtr)
        const rowid = readVarint(page, cellPtr + plen.size)
        void rowid
        const payloadStart = cellPtr + plen.size + rowid.size
        const payload = page.subarray(payloadStart, payloadStart + plen.value)
        const record = parseRecord(payload)
        const row: SqliteRow = {}
        columns.forEach((name, idx) => { row[name] = record[idx] })
        rows.push(row)
      }
    } else if (type === 5) {
      const cellCount = readU16(page, 3)
      const rightmost = readU32(page, 8)
      for (let i = 0; i < cellCount; i++) {
        const cellPtr = readU16(page, 12 + i * 2)
        const child = readU32(page, cellPtr)
        walkTable(child)
      }
      walkTable(rightmost)
    }
  }
  walkTable(rootPage)
  return rows
}
