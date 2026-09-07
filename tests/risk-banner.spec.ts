/** Editor password-risk banner logic. */
import { test, expect } from 'vitest'
import { judgePasswordRisk } from '../src/client/password-risk.ts'

// one reused group: `pw` shared across `n` entries
const group = (pw: string, n: number) => [{ value: pw, entries: Array.from({ length: n }, () => ({})) }]

test('weak only: short password below threshold', () => {
  const r = judgePasswordRisk('abc', 10, [], false)
  expect(r.weak).toBe(true)
  expect(r.reusedOther).toBe(0)
})
test('empty password: no risks', () => {
  expect(judgePasswordRisk('', 0, [], false)).toEqual({ weak: false, reusedOther: 0 })
  expect(judgePasswordRisk('   ', 0, [], false)).toEqual({ weak: false, reusedOther: 0 })
})
test('strong unique password: no banner', () => {
  const r = judgePasswordRisk('k3v$eH9!xqR2#pL', 92, [], false)
  expect(r.weak).toBe(false)
  expect(r.reusedOther).toBe(0)
})
test('strong but shared password still flags the reuse', () => {
  const r = judgePasswordRisk('k3v$eH9!xqR2#pL', 92, group('k3v$eH9!xqR2#pL', 2), true)
  expect(r.weak).toBe(false)
  expect(r.reusedOther).toBe(1)
})
test('reuse counts other entries, excludes the edited one', () => {
  // editing an entry whose stored password equals the typed one → 2 total − 1 self
  expect(judgePasswordRisk('shared1', 80, group('shared1', 2), true).reusedOther).toBe(1)
  // creating new (not editing) with a password that one existing entry has
  expect(judgePasswordRisk('shared1', 80, group('shared1', 1), false).reusedOther).toBe(1)
  // brand-new unique password
  expect(judgePasswordRisk('unique-new-99', 88, group('shared1', 1), false).reusedOther).toBe(0)
})
test('weak + reused both surface', () => {
  const r = judgePasswordRisk('abc', 5, group('abc', 3), false)
  expect(r.weak).toBe(true)
  expect(r.reusedOther).toBe(3)
})
