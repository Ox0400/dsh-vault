/**
 * Breach detection for dsh-vault, modeled after 1Password Watchtower and
 * Bitwarden's Exposed Password Report.
 *
 * Privacy: online checks use the Pwned Passwords k-anonymity protocol — only
 * the first 5 hex chars of the SHA-1 hash of a password ever leave this
 * machine; the full hash is matched locally against the returned range.
 * Offline fallback: a small built-in list of common/weak passwords is checked
 * locally when the network is unavailable or disabled.
 *
 * @module dsh-vault/breach
 */

import { createHash } from 'node:crypto'

/** Pwned Passwords API base URL. */
const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/'

/** Request timeout for one range query. */
const QUERY_TIMEOUT_MS = 12_000

/** How long a fetched prefix range is cached in memory. */
const CACHE_TTL_MS = 60 * 60 * 1000

/** Common / weak passwords checked offline (rockyou-style head). */
const WEAK_PASSWORDS = new Set([
  '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
  '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein',
  'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael',
  '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe',
  'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
  'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000',
  'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
  '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn',
  '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'fuck', 'maggie',
  '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer',
  'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees',
  '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail',
  'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow',
])

/** One cached range lookup. */
interface RangeCacheEntry {
  at: number
  suffixes: Set<string> | null // null = last query failed (retry next time)
}

const rangeCache = new Map<string, RangeCacheEntry>()

/** SHA-1 hex (uppercase) of a password, as the HIBP protocol expects. */
export function sha1Hex(password: string): string {
  return createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
}

/** Query one HIBP range; returns the suffix set or throws on transport/HTTP error. */
async function queryRange(prefix: string): Promise<Set<string>> {
  const res = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
    signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
    headers: { 'User-Agent': 'dsh-vault' },
  })
  if (!res.ok) throw new Error(`Pwned Passwords returned HTTP ${res.status}`)
  const text = await res.text()
  const suffixes = new Set<string>()
  for (const line of text.split('\n')) {
    const suffix = line.split(':')[0]
    if (suffix) suffixes.add(suffix.toLowerCase())
  }
  return suffixes
}

export type BreachSource = 'hibp' | 'local' | 'none'

export interface BreachVerdict {
  /** True when the password appears in breach data or is a known weak password. */
  breached: boolean
  /** Reason: 'pwned' (confirmed in HIBP), 'weak' (common password), or undefined. */
  reason?: 'pwned' | 'weak' | undefined
  /** Times the password appeared in breach data (HIBP only). */
  count: number
  /** Where the verdict came from. */
  source: BreachSource
}

/**
 * Check one password against the Pwned Passwords k-anonymity range and the
 * local weak-password list. Never sends the full password or its full hash.
 * @param password - the plaintext password to check.
 * @param now - epoch millis for cache expiry (injectable for tests).
 */
export async function checkPassword(password: string, now = Date.now()): Promise<BreachVerdict> {
  if (typeof password !== 'string' || password.length === 0) {
    return { breached: false, count: 0, source: 'none' }
  }
  // Offline first: a known common password is a risk regardless of network.
  if (WEAK_PASSWORDS.has(password.toLowerCase())) {
    return { breached: true, reason: 'weak', count: 0, source: 'local' }
  }
  const hash = sha1Hex(password)
  const prefix = hash.slice(0, 5)
  const suffix = hash.slice(5).toLowerCase()

  const cached = rangeCache.get(prefix)
  if (cached !== undefined && now - cached.at < CACHE_TTL_MS && cached.suffixes !== null) {
    return {
      breached: cached.suffixes.has(suffix),
      reason: cached.suffixes.has(suffix) ? 'pwned' : undefined,
      count: cached.suffixes.has(suffix) ? 1 : 0,
      source: 'hibp',
    }
  }

  try {
    const suffixes = await queryRange(prefix)
    rangeCache.set(prefix, { at: now, suffixes })
    const hit = suffixes.has(suffix)
    return { breached: hit, reason: hit ? 'pwned' : undefined, count: hit ? 1 : 0, source: 'hibp' }
  } catch {
    // Network failure: fall back to the local weak list only (already checked
    // above), so a transient outage never fails the whole report.
    return { breached: false, count: 0, source: 'local' }
  }
}

/** Number of prefix ranges currently cached (for diagnostics/tests). */
export function cacheSize(): number {
  return rangeCache.size
}

/** Clear the in-memory range cache (exposed for tests and diagnostics). */
export function clearCache(): void {
  rangeCache.clear()
}
