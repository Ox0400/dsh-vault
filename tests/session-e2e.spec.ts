/**
 * End-to-end browser login-session test: serve a local page that sets cookies,
 * drive it through the real session module (openSession → collectSessionCookies
 * → closeSession) with a headless Chromium, then verify the collected CookieData.
 *
 * Skipped automatically when playwright-core or a Chromium build is missing.
 */

import { test, assert, expect } from 'vitest'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { openSession, collectSessionCookies, closeSession, closeAllSessions, resolveChromium, playwrightAvailable } from '../src/session.ts'

const available = playwrightAvailable() && resolveChromium() !== undefined

test.skipIf(!available)('session: end-to-end headed flow collects HttpOnly cookies', async () => {
  const server: Server = createServer((_req, res) => {
    res.setHeader('set-cookie', ['sid=secret123; Path=/; HttpOnly', 'theme=dark; Path=/; SameSite=Lax', 'secure_c=1; Path=/; Secure'])
    res.end('<html><body>ok</body></html>')
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
  const port = (server.address() as { port: number }).port
  try {
    const session = await openSession(`http://127.0.0.1:${port}/`, { headless: true })
    expect(session.id).toBeTruthy()
    expect(session.url).toBe(`http://127.0.0.1:${port}/`)
    const cookies = await collectSessionCookies(session.id)
    expect(cookies.length).toBeGreaterThanOrEqual(2)
    const sid = cookies.find(c => c.name === 'sid')
    assert(sid, 'sid cookie collected')
    expect(sid.value).toBe('secret123')
    expect(sid.httpOnly).toBe(true) // page scripts could never read this
    const theme = cookies.find(c => c.name === 'theme')
    assert(theme, 'theme cookie collected')
    expect(theme.sameSite).toBe('Lax')
    await closeSession(session.id)
    await expect(collectSessionCookies(session.id)).rejects.toThrow('unknown session')
  } finally {
    server.close()
  }
})

test.skipIf(!available)('session: openSession adds https:// to bare domains', async () => {
  // openSession with a bare host — we only assert the normalized URL here since
  // the host may not resolve; the browser stays open on failure.
  const session = await openSession('example.com', { headless: true })
  expect(session.url).toBe('https://example.com')
  await closeSession(session.id)
})

test.skipIf(!available)('session: closeAllSessions cleans up', async () => {
  await closeAllSessions()
  expect((await import('../src/session.ts')).openSessionCount()).toBe(0)
})
