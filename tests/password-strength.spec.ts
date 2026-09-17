/**
 * Password strength. The old estimator was composition-only, which rated
 * `Sunflower22` 67/100 ("strong") and `P@ssw0rd` 63/100 — a dictionary word with
 * a capital and digits is not strong, and the offline common-password list was
 * never consulted. These cases pin the correction.
 */
import { test, expect } from 'vitest'
import { estimateStrength } from '../src/password-strength.ts'
import { WEAK_PASSWORDS } from '../src/breach.ts'

const score = (pw: string): number => estimateStrength(pw).score
const patterns = (pw: string): string[] => estimateStrength(pw).patterns

test('known-common passwords score at the bottom, however they are dressed up', () => {
  for (const pw of ['123456', 'password', 'qwerty', '1111', 'letmein', 'iloveyou']) {
    expect(WEAK_PASSWORDS.has(pw), `${pw} is in the offline list`).toBe(true)
    expect(score(pw), pw).toBeLessThanOrEqual(10)
    expect(estimateStrength(pw).verdict).toBe('weak')
  }
  // l33t and case do not save it
  expect(score('P@ssw0rd')).toBeLessThanOrEqual(10)
  expect(patterns('P@ssw0rd')).toContain('common')
  expect(score('Passw0rd!')).toBeLessThanOrEqual(25)
})

test('word + digits is capped at fair, not strong', () => {
  // the case that prompted this: 67/100 before
  const sunflower = estimateStrength('Sunflower22')
  expect(sunflower.score).toBeLessThanOrEqual(45)
  expect(sunflower.verdict).toBe('fair')
  expect(sunflower.patterns).toContain('word+digits')
  expect(sunflower.feedback.join(' ')).toMatch(/dictionary attack/i)
  // a common word with a year is weaker still
  expect(score('iloveyou2024')).toBeLessThanOrEqual(25)
})

test('keyboard walks, sequences and dates are recognised', () => {
  expect(patterns('qwerty123')).toContain('keyboard')
  expect(score('qwerty123')).toBeLessThanOrEqual(30)
  expect(patterns('abcd1234')).toContain('sequence')
  expect(score('abcd1234')).toBeLessThanOrEqual(35)
  expect(patterns('Summer1990!')).toContain('date')
  expect(score('Summer1990!')).toBeLessThanOrEqual(45)
  expect(patterns('abcabcabc')).toContain('repeat-block')
  // a bare digit run is not a date
  expect(patterns('1111')).not.toContain('date')
})

test('genuinely strong passwords still score well', () => {
  const random = estimateStrength('Xk9#mQ2!vT7@pL4z')
  expect(random.score).toBeGreaterThanOrEqual(80)
  expect(random.verdict).toBe('very strong')
  expect(random.patterns).toEqual([])
  // a long passphrase is fine even though letters repeat
  const phrase = estimateStrength('correct horse battery staple')
  expect(phrase.score).toBeGreaterThanOrEqual(60)
})

test('the score never lies about a short secret', () => {
  // a 4-digit PIN cannot be strong, whatever the digits are
  for (const pin of ['1234', '9876', '0000', '2580']) {
    expect(score(pin), pin).toBeLessThanOrEqual(30)
  }
  expect(estimateStrength('').score).toBe(0)
})

test('feedback is ordered and always present', () => {
  const weak = estimateStrength('password123')
  expect(weak.feedback.length).toBeGreaterThan(0)
  expect(weak.feedback.join('; ')).not.toContain('undefined')
  const strong = estimateStrength('Xk9#mQ2!vT7@pL4z')
  expect(strong.feedback).toEqual(['no obvious weaknesses'])
  // entropy is still reported alongside the score
  expect(estimateStrength('Xk9#mQ2!vT7@pL4z').bits).toBeGreaterThan(80)
})
