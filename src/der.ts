/**
 * Minimal ASN.1 DER parser for dsh-vault (Firefox/NSS credential decryption).
 *
 * Implements the subset of DER needed to parse Firefox's password-check and
 * master-key blobs: SEQUENCE/INTEGER/OCTET STRING/OBJECT IDENTIFIER tags plus
 * the `pbeWithSha1AndTripleDES-CBC` and `aes256-CBC` algorithm identifiers.
 *
 * @module dsh-vault/der
 */

export interface DerNode {
  tag: number
  value: Buffer // raw value bytes (no tag/length)
  children: DerNode[]
}

/** DER universal tag numbers used by NSS blobs. */
export const TAG_INTEGER = 0x02
export const TAG_OCTET_STRING = 0x04
export const TAG_NULL = 0x05
export const TAG_OID = 0x06
export const TAG_SEQUENCE = 0x30

function readLength(buf: Buffer, offset: number): { length: number; size: number } {
  const first = buf[offset]!
  if (first < 0x80) return { length: first, size: 1 }
  const n = first & 0x7f
  let length = 0
  for (let i = 1; i <= n; i++) length = length * 256 + buf[offset + i]!
  return { length, size: 1 + n }
}

/** Parse one DER value; returns the node and the byte offset after it. */
export function parseDer(buf: Buffer, offset = 0): { node: DerNode; next: number } {
  const tag = buf[offset]!
  const { length, size: lenSize } = readLength(buf, offset + 1)
  const valueStart = offset + 1 + lenSize
  const value = buf.subarray(valueStart, valueStart + length)
  const node: DerNode = { tag, value, children: [] }
  let next = valueStart + length
  if (tag === TAG_SEQUENCE) {
    let p = 0
    while (p < value.length) {
      const child = parseDer(value, p)
      node.children.push(child.node)
      p = child.next
    }
  }
  return { node, next }
}

/** Find the first child with the given tag. */
export function findChild(node: DerNode, tag: number): DerNode | undefined {
  return node.children.find(c => c.tag === tag)
}

/** Read a big-endian integer value (can be negative; we want unsigned). */
export function readInteger(node: DerNode): number {
  let v = 0
  for (const b of node.value) v = v * 256 + b
  return v
}
