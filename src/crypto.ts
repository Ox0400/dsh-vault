/**
 * Cryptographic core for dsh-vault: scrypt key derivation, AES-256-GCM
 * authenticated encryption, and helper constants.
 *
 * Zero external dependencies — everything comes from `node:crypto`, so the
 * vault's security posture is limited to Node's FIPS-capable primitives and
 * the master password's strength.
 *
 * @module dsh-vault/crypto
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>

/** AES-256 key length in bytes. */
export const KEY_LENGTH = 32

/** GCM nonce length in bytes (the recommended 96-bit default). */
export const IV_LENGTH = 12

/** GCM authentication tag length in bytes. */
export const TAG_LENGTH = 16

/** scrypt CPU/memory cost (2^15). Chosen to make offline brute force of a
 * master password expensive while staying snappy on laptops. */
export const SCRYPT_N = 2 ** 15

/** scrypt block size. */
export const SCRYPT_R = 8

/** scrypt parallelization. */
export const SCRYPT_P = 1

/** 1 GiB cap for the scrypt worker (N=32768, r=8 needs ~32 MiB; the cap is
 * generous headroom for future cost bumps). */
const SCRYPT_MAXMEM = 1024 * 1024 * 1024

/** Version tag stamped into every encrypted vault header. */
export const VAULT_FORMAT_VERSION = 1

/** KDF parameters persisted with the ciphertext so they can be raised later
 * without breaking existing vaults. */
export interface KdfParams {
  algo: 'scrypt'
  /** scrypt cost parameter N. */
  n: number
  /** scrypt block size. */
  r: number
  /** scrypt parallelization. */
  p: number
  /** Per-vault random salt, hex. */
  saltHex: string
}

/**
 * Derive the 256-bit vault key from the master password with scrypt.
 * The same salt must be used for every derivation of one vault.
 */
export async function deriveKey(masterPassword: string, params: KdfParams): Promise<Buffer> {
  const salt = Buffer.from(params.saltHex, 'hex')
  return scrypt(masterPassword, salt, KEY_LENGTH, {
    N: params.n,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  })
}

/** Generate fresh random KDF parameters (a new salt for a new vault). */
export function newKdfParams(): KdfParams {
  return {
    algo: 'scrypt',
    n: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    saltHex: randomBytes(16).toString('hex'),
  }
}

/** One authenticated-encryption envelope: ciphertext plus its nonce and tag. */
export interface EncryptedBlob {
  /** GCM nonce, hex. */
  ivHex: string
  /** GCM authentication tag, hex. */
  tagHex: string
  /** Ciphertext, hex. */
  dataHex: string
}

/**
 * Encrypt `plaintext` with AES-256-GCM under `key`. A fresh random nonce is
 * drawn per call, so encrypting the same plaintext twice yields different
 * blobs — no IV reuse across entries.
 */
export function encrypt(plaintext: Buffer, key: Buffer): EncryptedBlob {
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return { ivHex: iv.toString('hex'), tagHex: tag.toString('hex'), dataHex: data.toString('hex') }
}

/**
 * Decrypt an {@link EncryptedBlob}. GCM authenticates the ciphertext: a wrong
 * key, tampered nonce, or modified data throws instead of returning garbage.
 * @throws when authentication fails (wrong master password or corruption).
 */
export function decrypt(blob: EncryptedBlob, key: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(blob.ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(blob.tagHex, 'hex'))
  return Buffer.concat([
    decipher.update(Buffer.from(blob.dataHex, 'hex')),
    decipher.final(),
  ])
}

/** Constant-time comparison of two Buffers of equal length. */
export function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b)
}

/** Generate `bytes` cryptographically strong random bytes as hex. */
export function randomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex')
}
