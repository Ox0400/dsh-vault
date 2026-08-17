import { test, expect } from 'vitest'
import { analyzePassword, analyzeEntry, analyzeVault, estimatePasswordBits } from '../src/watchtower'

test('watchtower: analyzePassword flags weak, keyboard, repeated, year, common', () => {
  expect(analyzePassword('')).toEqual({ flags: [], bits: 0 })
  expect(analyzePassword('short')).toEqual({ flags: ['short-password'], bits: expect.any(Number) })
  expect(analyzePassword('qwerty123')).toEqual(expect.objectContaining({ flags: expect.arrayContaining(['keyboard-sequence', 'common-password']) }))
  expect(analyzePassword('pass111word')).toEqual(expect.objectContaining({ flags: expect.arrayContaining(['repeated-chars']) }))
  expect(analyzePassword('MyPass1990!')).toEqual(expect.objectContaining({ flags: expect.arrayContaining(['contains-year']) }))
  expect(analyzePassword('Tr0ub4dor&3!Long')).toEqual(expect.objectContaining({ flags: [] }))
})

test('watchtower: estimatePasswordBits grows with length and pools', () => {
  expect(estimatePasswordBits('a')).toBeLessThan(estimatePasswordBits('aA1!'))
  expect(estimatePasswordBits('abcdefgh')).toBeLessThan(estimatePasswordBits('abcdefghA1!'))
})

test('watchtower: analyzeEntry flags reuse, http, no-2fa, expired', () => {
  const counts = new Map([['pw1', 2]])
  const entry = analyzeEntry({ id: '1', title: 'T', password: 'pw1', url: 'http://x.io' }, counts)
  expect(entry.flags).toEqual(expect.arrayContaining(['reused-password', 'http-site']))
  expect(entry.verdict).not.toBe('good')
  const ok = analyzeEntry({ id: '2', title: 'O', password: 'Str0ng-Pass!2024', url: 'https://x.io', otpSecret: 'x' }, counts)
  expect(ok.verdict).toBe('good')
})

test('watchtower: analyzeVault computes reuse counts across entries', () => {
  const res = analyzeVault([
    { id: '1', title: 'A', password: 'shared-pass' },
    { id: '2', title: 'B', password: 'shared-pass' },
    { id: '3', title: 'C', password: 'Unique-Pass-42!' },
  ])
  const a = res.find(r => r.id === '1')!
  expect(a.flags).toContain('reused-password')
  const c = res.find(r => r.id === '3')!
  expect(c.flags).not.toContain('reused-password')
})
