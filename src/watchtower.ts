/**
 * Watchtower-style per-entry risk analysis for dsh-vault.
 *
 * Inspired by 1Password Watchtower and Bitwarden's security reports: instead
 * of a single overall health scan, each credential is rated for concrete
 * risks — weak password (heuristics beyond length), reused password, HTTP
 * site, missing 2FA, and expired. The rating powers per-entry badges in the
 * UI and a machine-readable report for the model tools.
 *
 * @module dsh-vault/watchtower
 */

/** Per-entry watchtower verdict: a list of concrete risk flags. */
export interface WatchtowerEntry {
  id: string
  title: string
  kind: string
  /** Risk flags found on this entry. */
  flags: string[]
  /** 0–100 score (100 = no risks). */
  score: number
  /** `good` | `warn` | `poor` */
  verdict: 'good' | 'warn' | 'poor'
  /** Password strength bits (estimate) when a password exists. */
  bits?: number
}

/** Common keyboard rows used for sequence detection. */
const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '0987654321', '!@#$%^&*()']

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '1234567', '12345678', '123456789',
  '1234567890', 'qwerty', 'qwerty123', 'abc123', '111111', '123123', 'admin', 'letmein',
  'welcome', 'monkey', 'dragon', 'iloveyou', 'sunshine', 'princess', 'football', 'shadow',
  'superman', 'batman', 'trustno1', 'master', 'hello', 'charlie', 'aa123456', '000000',
])

/** Estimate password entropy in bits (character-set + length based). */
export function estimatePasswordBits(password: string): number {
  if (password.length === 0) return 0
  let pool = 0
  if (/[a-z]/.test(password)) pool += 26
  if (/[A-Z]/.test(password)) pool += 26
  if (/[0-9]/.test(password)) pool += 10
  if (/[^A-Za-z0-9]/.test(password)) pool += 33
  if (pool === 0) pool = 1
  return Math.floor(password.length * Math.log2(pool) * 10) / 10
}

/** Detect a repeated character run (3+ identical), e.g. `aaa`, `1111`. */
function hasRepeatedRun(password: string): boolean {
  return /(.)\1{2,}/.test(password)
}

/** Detect a keyboard-row sequence of 4+, e.g. `qwer`, `1234`, `asdf`. */
function hasKeyboardSequence(password: string): boolean {
  const lower = password.toLowerCase()
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - 4; i++) {
      const seq = row.slice(i, i + 4)
      if (lower.includes(seq)) return true
    }
  }
  return false
}

/** Detect a 4-digit year (e.g. 1990–2035) inside the password. */
function hasYear(password: string): boolean {
  return /(19[89]\d|20[0-3]\d)/.test(password)
}

/** Detect a common password or a trivial variation (prefix/suffix digits). */
function isCommonPassword(password: string): boolean {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return true
  const base = password.toLowerCase().replace(/[0-9!@#$%^&*]+$/g, '').replace(/^[0-9!@#$%^&*]+/g, '')
  return base.length >= 3 && COMMON_PASSWORDS.has(base)
}

/** Score a password with the watchtower heuristics. Returns risk flags + bits. */
export function analyzePassword(password: string): { flags: string[]; bits: number } {
  const flags: string[] = []
  if (password.length === 0) return { flags, bits: 0 }
  if (password.length < 8) flags.push('short-password')
  else if (password.length < 12) flags.push('weak-password')
  if (hasRepeatedRun(password)) flags.push('repeated-chars')
  if (hasKeyboardSequence(password)) flags.push('keyboard-sequence')
  if (hasYear(password)) flags.push('contains-year')
  if (isCommonPassword(password)) flags.push('common-password')
  return { flags, bits: estimatePasswordBits(password) }
}

/** A usable score for the entry: start at 100, deduct per risk flag. */
function scoreFor(flags: string[], bits?: number): number {
  let score = 100
  score -= flags.length * 12
  if (bits !== undefined && bits < 40) score -= 15
  score = Math.max(0, score)
  return score
}

/**
 * Analyze one entry against the watchtower rules. Needs the full entry
 * (password, url, otpSecret) and, for reuse detection, the map of
 * password→count across the vault.
 */
export function analyzeEntry(
  entry: { id: string; title: string; kind?: string; password?: string; url?: string; otpSecret?: string; expiresAt?: number },
  passwordCounts: Map<string, number>,
): WatchtowerEntry {
  const flags: string[] = []
  let bits: number | undefined
  const kind = entry.kind ?? 'login'
  if (entry.password !== undefined && entry.password.length > 0) {
    const pw = analyzePassword(entry.password)
    flags.push(...pw.flags)
    bits = pw.bits
    const count = passwordCounts.get(entry.password) ?? 0
    if (count > 1) flags.push('reused-password')
  }
  if (typeof entry.url === 'string' && /^http:\/\//i.test(entry.url)) flags.push('http-site')
  if (entry.password !== undefined && entry.password.length > 0 && (kind === 'login' || kind === 'ssh') && (entry.otpSecret === undefined || entry.otpSecret.length === 0)) {
    flags.push('no-2fa')
  }
  if (entry.expiresAt !== undefined && entry.expiresAt < Date.now()) flags.push('expired')
  const score = scoreFor(flags, bits)
  const verdict: WatchtowerEntry['verdict'] = score >= 80 ? 'good' : score >= 50 ? 'warn' : 'poor'
  return {
    id: entry.id,
    title: entry.title,
    kind,
    flags,
    score,
    verdict,
    ...(bits !== undefined ? { bits } : {}),
  }
}

/** Analyze every active entry in a vault, computing reuse counts internally. */
export function analyzeVault(
  entries: Array<{ id: string; title: string; kind?: string; password?: string; url?: string; otpSecret?: string; expiresAt?: number }>,
): WatchtowerEntry[] {
  const counts = new Map<string, number>()
  for (const e of entries) {
    if (e.password !== undefined && e.password.length > 0) {
      counts.set(e.password, (counts.get(e.password) ?? 0) + 1)
    }
  }
  return entries.map(e => analyzeEntry(e, counts))
}
