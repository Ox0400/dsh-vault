/**
 * Password strength, dependency-free.
 *
 * Two layers:
 *
 * 1. **Composition** — length, character classes and diversity, the cheap
 *    signals every meter uses.
 * 2. **Patterns** — what a cracker actually exploits: a known-common password
 *    (including l33t and trailing-digit variants), a keyboard walk, a sequence,
 *    a date, a repeated block, or "one word plus digits" (`Sunflower22`).
 *
 * A pattern does not just shave points: it **caps** the score, because a
 * dictionary word with a capital and a couple of digits is not 67/100 material
 * no matter how long it is. Composition alone rated exactly that kind of
 * password "strong", which is the bug this module exists to fix.
 *
 * It is deliberately not zxcvbn: no bundled dictionary, no frequency ranking.
 * The one wordlist it consults is the offline common-password set from
 * `breach.ts`, so the strength meter and the breach report agree on what
 * "known-common" means.
 */
import { WEAK_PASSWORDS } from './breach.ts'

export type StrengthVerdict = 'weak' | 'fair' | 'strong' | 'very strong'

export interface StrengthResult {
  /** 0–100, capped by any pattern that was detected. */
  score: number
  verdict: StrengthVerdict
  /** Human-readable reasons, most important first. */
  feedback: string[]
  /** Entropy estimate in bits (naive, ignores patterns — its own caveat). */
  bits: number
  /** Detected pattern kinds, e.g. `common`, `word+digits`, `keyboard`. */
  patterns: string[]
}

/** Substitute the usual l33t characters so `P@ssw0rd` matches `password`. */
function deLeet(password: string): string {
  return password
    .toLowerCase()
    .replace(/[4@]/g, 'a')
    .replace(/[3€]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/7\+/g, 't')
}

/** The password with digits/symbols trimmed off both ends (for dictionary hits). */
function coreLetters(password: string): string {
  return password.toLowerCase().replace(/^[^a-z]+|[^a-z]+$/g, '')
}

const KEYBOARD_RUNS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qazwsx', '1qaz2wsx']
const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '01234567890']

/** True when the text contains a straight run of ≥4 characters from `source`. */
function hasRun(text: string, source: string): boolean {
  for (let i = 0; i + 4 <= text.length; i++) {
    const chunk = text.slice(i, i + 4)
    if (source.includes(chunk)) return true
    if (source.includes([...chunk].reverse().join(''))) return true
  }
  return false
}

/** True for a repeated block: `abcabcabc`, `121212`. */
function isRepeatedBlock(password: string): boolean {
  for (let size = 1; size <= Math.floor(password.length / 3); size++) {
    const block = password.slice(0, size)
    if (block.repeat(Math.ceil(password.length / size)).slice(0, password.length) === password) return true
  }
  return false
}

/**
 * True for a plausible date or year. Deliberately strict about separators: a
 * bare four-digit run is a PIN or a sequence (`1111`), not a date, and calling it
 * one used to add noise to the feedback.
 */
function hasDate(text: string): boolean {
  if (/(19|20)\d{2}/.test(text)) return true
  return /\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}/.test(text)
}

/** Score one password; `common` defaults to the bundled offline list. */
export function estimateStrength(password: string, common: Set<string> = WEAK_PASSWORDS): StrengthResult {
  const feedback: string[] = []
  const patterns: string[] = []
  const lower = password.toLowerCase()
  const deLeeted = deLeet(password)
  const letters = coreLetters(password)

  // ---- layer 1: composition ------------------------------------------------
  let score = Math.min(45, password.length * 3)
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(re => re.test(password)).length
  score += classes * 8
  score += Math.min(15, new Set(password).size)

  if (password.length < 8) feedback.push('too short (aim ≥ 12)')
  if (/^\d+$/.test(password)) { score -= 15; feedback.push('digits only') }
  else if (/^[a-z]+$/i.test(password)) { score -= 10; feedback.push('letters only') }
  if (/(.)\1{2,}/.test(password)) { score -= 8; patterns.push('repeats'); feedback.push('repeated characters') }

  // ---- layer 2: patterns, each of which caps the score ---------------------
  //
  // The caps are length-aware for the *soft* patterns. A year inside a 30
  // character passphrase (`CorrectHorseBatteryStaple!2024`) is not what makes it
  // guessable, but the same year in an 8 character password is. A known-common
  // password and a repeated block stay capped no matter how long they are: those
  // are weak at any length.
  const long = password.length >= 20
  let cap = 100
  const isCommon = (value: string): boolean => common.has(value) || common.has(deLeet(value))
  if (isCommon(lower) || isCommon(deLeeted)) {
    cap = Math.min(cap, 5)
    patterns.push('common')
    feedback.push('found in common-password lists')
  } else if (letters.length >= 4 && isCommon(letters)) {
    // a known word plus a suffix/prefix: `sunshine2024`, `Passw0rd!`
    cap = Math.min(cap, long ? 50 : 25)
    patterns.push('common-word')
    feedback.push('a common password with numbers or symbols around it')
  } else if (/^[a-z]{5,}\d{1,4}!?$/i.test(password) || /^\d{1,4}[a-z]{5,}!?$/i.test(password)) {
    // one dictionary-looking word plus a short number: `Sunflower22`
    cap = Math.min(cap, long ? 65 : 45)
    patterns.push('word+digits')
    feedback.push('looks like a word plus digits — a dictionary attack covers it')
  }

  if (KEYBOARD_RUNS.some(run => hasRun(lower, run))) {
    cap = Math.min(cap, long ? 50 : 30)
    patterns.push('keyboard')
    feedback.push('keyboard pattern (qwerty / asdf / 1234)')
  }
  if (SEQUENCES.some(seq => hasRun(lower, seq))) {
    cap = Math.min(cap, long ? 50 : 35)
    patterns.push('sequence')
    feedback.push('sequential characters (abcd / 4321)')
  }
  if (hasDate(password)) {
    cap = Math.min(cap, long ? 70 : 45)
    patterns.push('date')
    feedback.push('contains a date or year')
  }
  if (isRepeatedBlock(password)) {
    cap = Math.min(cap, 30)
    patterns.push('repeat-block')
    feedback.push('a short block repeated over and over')
  }
  if (new Set(password).size <= Math.max(3, Math.floor(password.length / 2))) {
    patterns.push('low-diversity')
    feedback.push('low character diversity')
  }

  score = Math.max(0, Math.min(100, Math.round(Math.min(score, cap))))
  const verdict: StrengthVerdict = score >= 80 ? 'very strong' : score >= 60 ? 'strong' : score >= 40 ? 'fair' : 'weak'

  // Naive entropy: pool size per character. Reported next to the score, not
  // used to derive it — a 20-character `qwertyqwertyqwertyq` has plenty of bits
  // and is still terrible.
  let pool = 0
  if (/[a-z]/.test(password)) pool += 26
  if (/[A-Z]/.test(password)) pool += 26
  if (/[0-9]/.test(password)) pool += 10
  if (/[^A-Za-z0-9]/.test(password)) pool += 33
  const bits = password.length > 0 && pool > 0 ? Math.round(password.length * Math.log2(pool)) : 0

  return {
    score,
    verdict,
    feedback: feedback.length > 0 ? feedback : ['no obvious weaknesses'],
    bits,
    patterns,
  }
}
