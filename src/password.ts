/**
 * Cryptographically strong random password generator with character-class
 * guarantees (at least one of each selected class) and optional separator
 * grouping (e.g. `XKCD`-style word-free random groups like `vK7-mQ2-zt9`).
 *
 * Zero dependencies — randomness comes from `node:crypto`.
 *
 * @module dsh-vault/password
 */

import { randomInt } from 'node:crypto'

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const DIGITS = '0123456789'
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?/~'

/** Options controlling the generated password's composition. */
export interface PasswordOptions {
  /** Total length. Default 20. */
  length?: number
  /** Include lowercase letters. Default true. */
  lowercase?: boolean
  /** Include uppercase letters. Default true. */
  uppercase?: boolean
  /** Include digits. Default true. */
  digits?: boolean
  /** Include symbols. Default true. */
  symbols?: boolean
  /** Exclude visually ambiguous characters (0/O/1/l/I). Default false. */
  excludeAmbiguous?: boolean
  /** Group the output with `-` separators every `group` characters (e.g. 3
   * for `vK7-mQ2-zt9`). Default ungrouped. */
  group?: number
  /** Fixed prefix prepended to the generated random core. */
  prefix?: string
  /** Fixed suffix appended to the generated random core. */
  suffix?: string
}

function filterPool(options: Required<Omit<PasswordOptions, 'length' | 'group' | 'prefix' | 'suffix'>>): { merged: string; classes: string[] } {
  const pools: string[] = []
  if (options.lowercase) pools.push(LOWERCASE)
  if (options.uppercase) pools.push(UPPERCASE)
  if (options.digits) pools.push(DIGITS)
  if (options.symbols) pools.push(SYMBOLS)
  // Filter each class independently so the per-class guarantee below never
  // draws an ambiguous character when excludeAmbiguous is on: the guarantee
  // samples from `classes`, and `merged` only feeds the fill.
  const classes = options.excludeAmbiguous
    ? pools.map(pool => [...pool].filter(char => !AMBIGUOUS_CHARS.has(char)).join(''))
    : pools
  return { merged: classes.join(''), classes }
}

/** Visually ambiguous characters excluded when `excludeAmbiguous` is set. */
const AMBIGUOUS_CHARS = new Set('0O1lI')

/**
 * Generate a random password. At least one character from every selected class
 * is guaranteed; the rest are drawn uniformly from the merged pool. Uses
 * rejection sampling against `node:crypto`'s `randomInt` (no modulo bias).
 * @throws when no character class is selected, or when the requested length is
 * shorter than the number of selected classes.
 */
export function generatePassword(options: PasswordOptions = {}): string {
  const length = options.length ?? 20
  const config = {
    lowercase: options.lowercase ?? true,
    uppercase: options.uppercase ?? true,
    digits: options.digits ?? true,
    symbols: options.symbols ?? true,
    excludeAmbiguous: options.excludeAmbiguous ?? false,
  }
  const { merged, classes } = filterPool(config)
  const selected = classes.filter(pool => pool.length > 0)
  if (selected.length === 0) throw new Error('password generation requires at least one character class')
  if (!Number.isInteger(length) || length < 1) throw new Error('password length must be a positive integer')
  if (length < selected.length) {
    throw new Error(`password length ${length} is shorter than the ${selected.length} selected character classes`)
  }
  if (options.group !== undefined && (!Number.isInteger(options.group) || options.group < 2)) {
    throw new Error('password group must be an integer >= 2 when provided')
  }

  // Guarantee one of each class first.
  const chars: string[] = selected.map(pool => pool[randomInt(pool.length)]!)
  // Fill the rest from the merged pool (or the only class, if one was selected).
  const source: string = merged.length > 0 ? merged : selected[0]!
  while (chars.length < length) {
    chars.push(source[randomInt(source.length)]!)
  }
  // Fisher-Yates shuffle so the guaranteed classes land anywhere.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    ;[chars[i], chars[j]] = [chars[j]!, chars[i]!]
  }

  let password = chars.join('')
  const coreLength = length
  void coreLength
  if (options.prefix !== undefined && options.prefix.length > 0) {
    password = options.prefix + password
  }
  if (options.suffix !== undefined && options.suffix.length > 0) {
    password = password + options.suffix
  }
  if (options.group !== undefined && options.group > 1 && password.length > options.group) {
    password = password.match(new RegExp(`.{1,${options.group}}`, 'g'))!.join('-')
  }
  return password
}

/** Small EFF-style word list for passphrases (128 common, memorable words). */
const PASSPHRASE_WORDS = [
  'abacus', 'acorn', 'alpine', 'anchor', 'apricot', 'archer', 'aspen', 'autumn',
  'bamboo', 'banyan', 'beacon', 'birch', 'biscuit', 'blossom', 'bravo', 'breeze',
  'cactus', 'canyon', 'cascade', 'cedar', 'charm', 'cherry', 'cinder', 'cobalt',
  'coral', 'cricket', 'crimson', 'crystal', 'cypress', 'dahlia', 'dandelion', 'delta',
  'denim', 'diamond', 'dolphin', 'drift', 'eagle', 'ember', 'falcon', 'fennel',
  'ferret', 'fjord', 'flint', 'foxtrot', 'garden', 'garnet', 'gecko', 'ginkgo',
  'glacier', 'granite', 'gull', 'harbor', 'hazel', 'heron', 'honey', 'horizon',
  'iris', 'island', 'ivory', 'jaguar', 'jasmine', 'juniper', 'kayak', 'kestrel',
  'lagoon', 'larch', 'lilac', 'lotus', 'magpie', 'maple', 'marble', 'meadow',
  'mentor', 'mosaic', 'nectar', 'nimbus', 'oak', 'obsidian', 'olive', 'onyx',
  'orchid', 'otter', 'panda', 'papaya', 'pebble', 'pepper', 'phoenix', 'pine',
  'plum', 'quartz', 'quill', 'raven', 'reed', 'river', 'robin', 'ruby',
  'saffron', 'sage', 'salamander', 'sand', 'sapphire', 'sequoia', 'shale', 'silver',
  'snow', 'sparrow', 'spruce', 'starling', 'stone', 'sunset', 'tiger', 'topaz',
  'tulip', 'umber', 'velvet', 'violet', 'walnut', 'willow', 'winter', 'xenon',
  'yarrow', 'zephyr', 'zinnia',
] as const

/** Options controlling generated passphrase composition. */
export interface PassphraseOptions {
  /** Number of words. Default 4. */
  words?: number
  /** Separator between words. Default "-". */
  separator?: string
  /** Append two random digits after the last word. Default true. */
  wordDigits?: boolean
}

/**
 * Generate a memorable passphrase ("correct-horse-battery-staple" style) from
 * a 128-word list. Optionally appends two random digits for sites that require
 * a number. Zero dependencies; entropy comes from `node:crypto`.
 * @throws when `words` is not an integer in 2–12, or separator is empty.
 */
export function generatePassphrase(options: PassphraseOptions = {}): string {
  const words = options.words ?? 4
  const separator = options.separator ?? '-'
  const withDigits = options.wordDigits ?? true
  if (!Number.isInteger(words) || words < 2 || words > 12) {
    throw new Error('passphrase: words must be an integer 2–12')
  }
  if (separator.length === 0) throw new Error('passphrase: separator must not be empty')
  const parts: string[] = []
  for (let i = 0; i < words; i++) {
    parts.push(PASSPHRASE_WORDS[randomInt(PASSPHRASE_WORDS.length)]!)
  }
  let phrase = parts.join(separator)
  if (withDigits) phrase += separator + String(randomInt(10)) + String(randomInt(10))
  return phrase
}
