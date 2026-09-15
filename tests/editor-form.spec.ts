/**
 * Editor conversion helpers. The OAuth catalog template ships
 * `expiresAt: 'expiry epoch millis'` as a *hint*; a build that copied hints
 * into the form crashed the whole settings slot with
 * `RangeError: Invalid time value`, so these conversions are pinned here.
 */
import { test, expect } from 'vitest'
import { localDateTimeValue, templateHints, templateKind } from '../src/client/editor-form.ts'
import { envPairsForEntry } from '../src/env-export.ts'

test('localDateTimeValue never throws on unusable input', () => {
  // the exact strings that used to take the page down
  for (const bad of ['expiry epoch millis', 'expiry (MM/YY)', 'what it is for', 'account username', 'not a date']) {
    expect(() => localDateTimeValue(bad)).not.toThrow()
    expect(localDateTimeValue(bad)).toBe('')
  }
  for (const bad of [undefined, null, '', '   ', Number.NaN, Number.POSITIVE_INFINITY, 0, -1, {}, []]) {
    expect(() => localDateTimeValue(bad)).not.toThrow()
    expect(localDateTimeValue(bad)).toBe('')
  }
})

test('localDateTimeValue renders a valid epoch as local wall-clock time', () => {
  const epoch = Date.UTC(2026, 8, 15, 12, 30) // 2026-09-15T12:30Z
  const value = localDateTimeValue(epoch)
  expect(value).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/)
  // the shown value must be the LOCAL time, so parsing it back gives the epoch
  expect(Date.parse(value)).toBe(epoch)
})

test('localDateTimeValue accepts a parseable date string', () => {
  expect(localDateTimeValue('2026-09-15T12:30:00.000Z')).toBe(localDateTimeValue(Date.parse('2026-09-15T12:30:00.000Z')))
})

test('templateKind maps catalog templates onto store kinds', () => {
  expect(templateKind('oauth')).toBe('oauth')
  expect(templateKind('api-key')).toBe('api-key')
  // catalog-only kinds have no store equivalent
  expect(templateKind('wifi')).toBe('login')
  expect(templateKind('server')).toBe('ssh')
  expect(templateKind('database')).toBe('ssh')
  expect(templateKind('identity')).toBe('login')
  expect(templateKind('bank')).toBe('card')
  expect(templateKind('something-new')).toBe('something-new')
})

test('templateHints keeps descriptions and drops non-hint entries', () => {
  const hints = templateHints({
    accessToken: 'access token',
    expiresAt: 'expiry epoch millis',
    fields: 'arbitrary key/value pairs', // the key/value map itself, not a hint
    empty: '',
    blank: '   ',
    weird: 42 as unknown as string,
  })
  expect(hints).toEqual({ accessToken: 'access token', expiresAt: 'expiry epoch millis' })
})

test('env names are positional and tolerate the legacy single-name field', () => {
  // no configuration → every name derives from the title
  expect(envPairsForEntry({ id: '1', title: 'DASHSCOPE', apiKey: 'k' }).map(p => p.key)).toEqual(['DASHSCOPE_API_KEY'])
  // one name → names the primary secret
  expect(envPairsForEntry({ id: '1', title: 'x', envKeys: ['MY_KEY'], apiKey: 'k' }).map(p => p.key)).toEqual(['MY_KEY'])
  // several → positional, with derived names for anything beyond the list
  const pairs = envPairsForEntry({
    id: '1', title: 'x', envKeys: ['GOOGLE_ACCESS', 'GOOGLE_REFRESH'],
    accessToken: 'at', refreshToken: 'rt', fields: { scope: 'openid' },
  })
  expect(pairs.map(p => p.key)).toEqual(['GOOGLE_ACCESS', 'GOOGLE_REFRESH', 'GOOGLE_ACCESS_SCOPE'])
  expect(pairs.map(p => p.field)).toEqual(['accessToken', 'refreshToken', 'fields.scope'])
  // the legacy field still works and is read as a one-element list
  expect(envPairsForEntry({ id: '1', title: 'x', envKey: 'LEGACY', apiKey: 'k' }).map(p => p.key)).toEqual(['LEGACY'])
  // an explicit name beats the prefix; derived names take it
  expect(envPairsForEntry({ id: '1', title: 'x', envKeys: ['MINE'], apiKey: 'k' }, 'APP_').map(p => p.key)).toEqual(['MINE'])
  expect(envPairsForEntry({ id: '1', title: 'x', apiKey: 'k' }, 'APP_').map(p => p.key)).toEqual(['APP_X_API_KEY'])
})
