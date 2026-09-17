/**
 * The breach check must leak as little as possible. k-anonymity means only the
 * first five hex characters of the SHA-1 hash are sent, and HIBP's `Add-Padding`
 * header keeps the response size from correlating with how common a password is.
 * These assertions pin both, because a regression here is invisible in normal use.
 */
import { test, expect, afterEach, vi } from 'vitest'
import { checkPassword, clearCache, sha1Hex } from '../src/breach.ts'

const realFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = realFetch
  clearCache()
  vi.restoreAllMocks()
})

/** Stub the range endpoint and capture what was actually requested. */
function stubFetch(body = '0000000000000000000000000000000000:1\r\n'): Array<{ url: string; headers: Record<string, string> }> {
  const seen: Array<{ url: string; headers: Record<string, string> }> = []
  globalThis.fetch = (async (url: string, init?: { headers?: Record<string, string> }) => {
    seen.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string> })
    return { ok: true, status: 200, text: async () => body }
  }) as unknown as typeof fetch
  return seen
}

test('only the five-character hash prefix is sent', async () => {
  const seen = stubFetch()
  const password = 'Xk9#mQ2!vT7@pL4z'
  const full = sha1Hex(password)
  await checkPassword(password)
  expect(seen).toHaveLength(1)
  const { url } = seen[0]!
  // exactly the prefix, nothing longer
  expect(url).toBe(`https://api.pwnedpasswords.com/range/${full.slice(0, 5)}`)
  expect(url).not.toContain(full.slice(5))
  expect(url).not.toContain(password)
  expect(url).not.toContain(encodeURIComponent(password))
})

test('the request asks HIBP to pad the response', async () => {
  const seen = stubFetch()
  await checkPassword('Xk9#mQ2!vT7@pL4z')
  const headers = seen[0]!.headers
  const padding = headers['Add-Padding'] ?? headers['add-padding']
  expect(padding).toBe('true')
})

test('a password already in the offline list never leaves the machine', async () => {
  const seen = stubFetch()
  const verdict = await checkPassword('123456')
  expect(verdict).toMatchObject({ breached: true, reason: 'weak', source: 'local' })
  expect(seen).toHaveLength(0)
})

test('an identical prefix is looked up once and cached', async () => {
  const seen = stubFetch()
  await checkPassword('Xk9#mQ2!vT7@pL4z')
  await checkPassword('Xk9#mQ2!vT7@pL4z')
  expect(seen).toHaveLength(1)
})
