/**
 * RFC 6238 TOTP (Time-based One-Time Password) with RFC 4648 Base32 secrets,
 * implemented directly on `node:crypto` (HMAC-SHA1) with zero dependencies.
 *
 * Supports both raw Base32 secrets and `otpauth://totp/...?secret=...` URIs
 * so users can paste either the secret their 2FA setup page shows or the full
 * provisioning URI a QR code encodes.
 *
 * @module dsh-vault/totp
 */

import { createHmac, randomBytes } from 'node:crypto'

/** Default time step in seconds (RFC 6238 default, used by Google Authenticator etc.). */
export const DEFAULT_PERIOD_SECONDS = 30

/** Default number of digits (RFC 6238 default). */
export const DEFAULT_DIGITS = 6

/** Characters used by RFC 4648 Base32 (no padding in secrets). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decode an RFC 4648 Base32 string (case-insensitive, optional padding and
 * whitespace tolerated) into bytes.
 * @throws on characters outside the Base32 alphabet.
 */
export function base32Decode(input: string): Buffer {
  const cleaned = input.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase()
  if (cleaned.length === 0) {
    throw new Error('invalid Base32 secret: secret is empty')
  }
  if (cleaned.length < 8) {
    throw new Error('invalid Base32 secret: too short (expected at least 8 characters)')
  }
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error('invalid Base32 secret: contains characters outside A-Z2-7')
  }
  let bits = 0
  let value = 0
  const bytes: number[] = []
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char)
    if (index < 0) throw new Error(`invalid Base32 character: ${char}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

/** A parsed `otpauth://totp/...` URI or a bare secret. */
export interface TotpSecret {
  /** Raw secret string (Base32, no padding). */
  secret: string
  /** Time step in seconds. */
  periodSeconds: number
  /** Number of digits. */
  digits: number
  /** Optional issuer label from the URI. */
  issuer?: string
  /** Optional account label from the URI. */
  account?: string
}

/** RFC 3986 query-string parser sufficient for otpauth URIs. */
function parseQuery(query: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const pair of query.split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    if (eq < 0) {
      result[decodeURIComponent(pair)] = ''
    } else {
      result[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1))
    }
  }
  return result
}

/** Extract the numeric `digits` query parameter when present and valid. */
function digitsOf(raw?: string): number {
  if (raw === undefined) return DEFAULT_DIGITS
  const parsed = Number.parseInt(raw, 10)
  if (Number.isInteger(parsed) && parsed >= 6 && parsed <= 10) return parsed
  return DEFAULT_DIGITS
}

/** Extract the numeric `period` query parameter when present and valid. */
function periodOf(raw?: string): number {
  if (raw === undefined) return DEFAULT_PERIOD_SECONDS
  const parsed = Number.parseInt(raw, 10)
  if (Number.isInteger(parsed) && parsed >= 5) return parsed
  return DEFAULT_PERIOD_SECONDS
}

/**
 * Parse a TOTP secret from either a bare Base32 string or a full
 * `otpauth://totp/...` provisioning URI. If a bare string has an explicit
 * trailing `?digits=` or `?period=` (unusual), it is ignored; use a URI for
 * non-default parameters.
 */
export function parseTotpSecret(input: string): TotpSecret {
  const trimmed = input.trim()
  if (trimmed.startsWith('otpauth://')) {
    const url = new URL(trimmed)
    if (url.protocol !== 'otpauth:' || url.host !== 'totp') {
      throw new Error('unsupported otpauth URI: only otpauth://totp is supported')
    }
    const secret = url.searchParams.get('secret')
    if (!secret) throw new Error('otpauth URI is missing the secret parameter')
    // Labels: "issuer:account" for otpauth://totp/Issuer:account
    const label = decodeURIComponent(url.pathname.replace(/^\//, ''))
    const colon = label.indexOf(':')
    const issuer = url.searchParams.get('issuer') ?? (colon >= 0 ? label.slice(0, colon) : undefined)
    const account = colon >= 0 ? label.slice(colon + 1) : label
    return {
      secret,
      periodSeconds: periodOf(url.searchParams.get('period') ?? undefined),
      digits: digitsOf(url.searchParams.get('digits') ?? undefined),
      ...(issuer !== undefined ? { issuer } : {}),
      ...(account !== undefined && account.length > 0 ? { account } : {}),
    }
  }
  return {
    secret: trimmed,
    periodSeconds: DEFAULT_PERIOD_SECONDS,
    digits: DEFAULT_DIGITS,
  }
}

/** HOTP (RFC 4226) — the building block TOTP is defined on. */
export function hotp(secret: Buffer, counter: number, digits: number): string {
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeBigUInt64BE(BigInt(Math.floor(counter)))
  const hmac = createHmac('sha1', secret).update(counterBuffer).digest()
  const offset = hmac[hmac.length - 1]! & 0x0f
  const binary =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff)
  return (binary % 10 ** digits).toString().padStart(digits, '0')
}

/**
 * Compute the current TOTP code for `input` (bare Base32 secret or otpauth
 * URI). `nowMs` defaults to the current time; pass it explicitly for tests.
 */
export function totp(input: string, nowMs: number = Date.now()): string {
  const parsed = parseTotpSecret(input)
  const key = base32Decode(parsed.secret)
  const counter = Math.floor(nowMs / 1000 / parsed.periodSeconds)
  return hotp(key, counter, parsed.digits)
}

/**
 * Build a Base32 string from raw bytes (RFC 4648), no padding.
 */
export function bytesToBase32(bytes: Buffer): string {
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f]!
      bits -= 5
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f]!
  }
  return output
}

/**
 * Generate a fresh random TOTP secret (160-bit Base32, the RFC 4226
 * recommended length), e.g. for enrolling a new 2FA account.
 */
export function generateTotpSecret(): string {
  return bytesToBase32(randomBytes(20))
}
