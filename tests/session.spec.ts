import { test, assert } from 'vitest'
import { cookieHeader, netscapeJar, toCookieData } from '../src/session.ts'
import type { CookieData } from '../src/store.ts'

const COOKIES: CookieData[] = [
  { name: 'sid', value: 'abc123', domain: 'example.com', path: '/', expires: -1, httpOnly: true, secure: false },
  { name: 'theme', value: 'dark', domain: '.example.com', path: '/', expires: 1767225600, httpOnly: false, secure: true, sameSite: 'Lax' },
]

test('session: toCookieData normalizes a Playwright cookie', () => {
  const out = toCookieData({
    name: 'sid', value: 'abc123', domain: '.example.com', path: '/', expires: -1,
    httpOnly: true, secure: false, sameSite: 'Lax',
  })
  assert.equal(out.name, 'sid')
  assert.equal(out.value, 'abc123')
  assert.equal(out.sameSite, 'Lax')
})

test('session: cookieHeader joins name=value pairs', () => {
  assert.equal(cookieHeader(COOKIES), 'sid=abc123; theme=dark')
  assert.equal(cookieHeader([]), '')
})

test('session: netscapeJar produces curl-compatible lines', () => {
  const jar = netscapeJar(COOKIES)
  assert.ok(jar.startsWith('# Netscape HTTP Cookie File'))
  assert.ok(jar.includes('.example.com\tTRUE\t/\tTRUE\t1767225600\ttheme\tdark'))
  // session cookie: expires 0
  assert.ok(jar.includes('example.com\tTRUE\t/\tFALSE\t0\tsid\tabc123'))
})

test('session: netscapeJar prefixes bare domains with a dot', () => {
  const jar = netscapeJar([{ name: 'a', value: 'b', domain: 'x.io', path: '/', expires: -1, httpOnly: false, secure: false }])
  assert.ok(jar.includes('.x.io\tTRUE\t/\tFALSE\t0\ta\tb'))
})

test('session: netscapeJar skips cookies without a domain', () => {
  const jar = netscapeJar([
    { name: 'a', value: 'b', domain: 'x.io', path: '/', expires: -1, httpOnly: false, secure: false },
    { name: 'noDomain', value: 'v', domain: '', path: '/', expires: -1, httpOnly: false, secure: false },
  ])
  assert.ok(jar.includes('.x.io\tTRUE\t/\tFALSE\t0\ta\tb'))
  assert.ok(!jar.includes('noDomain'), 'empty-domain cookie omitted from jar')
})

test('session: parseNetscapeJar parses a curl-format jar', () => {
  const { parseNetscapeJar } = awaitImport()
  const jar = [
    '# Netscape HTTP Cookie File',
    '.example.com\tTRUE\t/\tFALSE\t1767225600\tsid\tabc123',
    '#HttpOnly_.github.com\tTRUE\t/\tTRUE\t0\tauth_token\txyz',
    '.github.com\tTRUE\t/\tFALSE\t0\ttheme\tdark',
    'garbage line without tabs',
    '',
  ].join('\n')
  const cookies = parseNetscapeJar(jar)
  assert.equal(cookies.length, 3)
  assert.deepEqual(cookies[0], { name: 'sid', value: 'abc123', domain: '.example.com', path: '/', expires: 1767225600, httpOnly: false, secure: false })
  const auth = cookies.find(c => c.name === 'auth_token')!
  assert.equal(auth.domain, '.github.com')
  assert.equal(auth.httpOnly, true)
  assert.equal(auth.secure, true)
  assert.equal(auth.expires, 0)
})

function awaitImport(): { parseNetscapeJar: (t: string) => CookieData[] } {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const m = require('../src/session.ts') as { parseNetscapeJar: (t: string) => CookieData[] }
  return m
}
