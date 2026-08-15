/**
 * Browser login-session manager for dsh-vault.
 *
 * `vault_session_*` tools let a user log into an arbitrary website in a real
 * (headed) browser window opened by this module, then collect the resulting
 * session cookies into the vault. This is the only portable way to capture
 * cookies for sites that do not cooperate with embedding (X-Frame-Options,
 * SameSite, cross-origin iframe cookie isolation all block the iframe +
 * postMessage trick used by e.g. dsh-tokensforce-login, which only works when
 * the site itself posts its token back).
 *
 * The heavy lifting is done by Playwright (playwright-core): it launches the
 * locally installed Chromium in headed mode, so the user sees a normal browser
 * window, logs in manually (password, 2FA, captcha, …), and when they come
 * back the module reads `context.cookies()` — every cookie of that session,
 * including HttpOnly session cookies that a page script could never read.
 *
 * Because there is no way to drive a headed login without a real browser, the
 * module lazily requires `playwright-core` and resolves a browser executable
 * from the standard Playwright cache or well-known install paths; when neither
 * exists, the tools fail with a clear message instead of crashing.
 *
 * @module dsh-vault/session
 */

import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import type { CookieData } from './store.ts'

/** CommonJS require for lazily loading playwright-core (ESM-safe). */
const nodeRequire = createRequire(import.meta.url)

export interface SessionHandle {
  /** Stable id of this browser session (used by open/collect/close). */
  id: string
  /** URL the session was opened at. */
  url: string
  /** Epoch millis when the session was opened. */
  openedAt: number
}

/** Playwright's own cookie shape (superset of our CookieData). */
interface PlaywrightCookie {
  name: string
  value: string
  domain: string
  path: string
  expires: number
  httpOnly: boolean
  secure: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
}

interface BrowserLike {
  newContext(options?: Record<string, unknown>): Promise<ContextLike>
  close(): Promise<void>
}

interface ContextLike {
  cookies(urls?: string | string[]): Promise<PlaywrightCookie[]>
  newPage(): Promise<PageLike>
  close(): Promise<void>
}

interface PageLike {
  goto(url: string): Promise<unknown>
}

interface ChromiumLike {
  launch(options: { headless: boolean; executablePath?: string }): Promise<BrowserLike>
}

let chromiumModule: ChromiumLike | undefined
let chromiumError: string | undefined

/** Lazily load playwright-core; returns the chromium API or throws a helpful message. */
function chromium(): ChromiumLike {
  if (chromiumModule !== undefined) return chromiumModule
  if (chromiumError !== undefined) throw new Error(chromiumError)
  try {
    const pw = nodeRequire('playwright-core') as { chromium: ChromiumLike }
    chromiumModule = pw.chromium
    return pw.chromium
  } catch {
    chromiumError = 'playwright-core is not installed — run `npm i playwright-core` (or `pnpm add playwright-core`) to enable browser login sessions, then retry.'
    throw new Error(chromiumError)
  }
}

/** Candidate Chromium executables in priority order. */
function candidateExecutables(): string[] {
  const home = homedir()
  const cache = join(home, 'Library', 'Caches', 'ms-playwright')
  const out: string[] = []
  // Playwright cache: any installed chromium build.
  try {
    const { readdirSync } = nodeRequire('node:fs') as typeof import('node:fs')
    if (existsSync(cache)) {
      const builds = readdirSync(cache).filter(n => n.startsWith('chromium-'))
      builds.sort().reverse() // newest first
      for (const build of builds) {
        const dir = join(cache, build)
        for (const sub of ['chrome-mac/Chromium.app/Contents/MacOS/Chromium', 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing', 'chrome-linux/chrome', 'chrome-win/chrome.exe']) {
          const candidate = join(dir, sub)
          if (existsSync(candidate)) out.push(candidate)
        }
      }
    }
  } catch { /* ignore */ }
  // Well-known system browsers.
  out.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
  out.push('/Applications/Chromium.app/Contents/MacOS/Chromium')
  out.push('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge')
  out.push('/usr/bin/chromium')
  out.push('/usr/bin/chromium-browser')
  return out
}

/** Resolve a usable Chromium executable, or undefined when none exists. */
export function resolveChromium(): string | undefined {
  for (const candidate of candidateExecutables()) {
    if (existsSync(candidate)) return candidate
  }
  return undefined
}

/** Whether playwright-core is loadable (diagnostics/tests). */
export function playwrightAvailable(): boolean {
  try {
    chromium()
    return true
  } catch {
    return false
  }
}

/** Normalize a cookie into our stored shape. */
export function toCookieData(cookie: PlaywrightCookie): CookieData {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    expires: cookie.expires,
    httpOnly: cookie.httpOnly,
    secure: cookie.secure,
    ...(cookie.sameSite !== undefined ? { sameSite: cookie.sameSite } : {}),
  }
}

/** Serialize stored cookies into a `Cookie` request header value. */
export function cookieHeader(cookies: CookieData[]): string {
  return cookies.map(c => `${c.name}=${c.value}`).join('; ')
}

/** Serialize stored cookies as a Netscape-format cookie jar (curl -b compatible).
 * Cookies without a domain are skipped — a jar line with an empty domain is
 * unusable by curl/wget. */
export function netscapeJar(cookies: CookieData[]): string {
  const lines = ['# Netscape HTTP Cookie File', '# Generated by dsh-vault', '# This file can be used with curl -b, wget, and similar tools.']
  for (const c of cookies) {
    if (c.domain.length === 0) continue
    const domain = c.domain.startsWith('.') ? c.domain : `.${c.domain}`
    const includeSubdomains = 'TRUE'
    const path = c.path || '/'
    const secure = c.secure ? 'TRUE' : 'FALSE'
    const expiry = c.expires >= 0 ? String(c.expires) : '0'
    lines.push([domain, includeSubdomains, path, secure, expiry, c.name, c.value].join('\t'))
  }
  return lines.join('\n')
}

/** Parse a Netscape cookie-jar file (curl -b / wget / browser-extension export)
 * into CookieData rows. Comment lines (#), blank lines and header rows are
 * ignored; the tab-separated columns are domain (optionally prefixed with
 * `#HttpOnly_`), include-subdomains, path, secure, expiry (epoch seconds, or
 * 0 = session), name, value. */
export function parseNetscapeJar(text: string): CookieData[] {
  const out: CookieData[] = []
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line.length === 0) continue
    if (line.startsWith('#') && !line.startsWith('#HttpOnly_')) continue
    const cols = line.split('\t')
    if (cols.length < 7) continue
    const [rawDomain, includeSubdomains, path, secure, expiry, name, value] = cols
    if (rawDomain === undefined || name === undefined || value === undefined) continue
    const httpOnly = rawDomain.startsWith('#HttpOnly_')
    const domain = httpOnly ? rawDomain.slice('#HttpOnly_'.length) : rawDomain
    if (domain.length === 0) continue
    const numericExpiry = Number.parseInt(expiry ?? '0', 10)
    out.push({
      name,
      value,
      domain,
      path: (path ?? '/').length > 0 ? path! : '/',
      expires: Number.isFinite(numericExpiry) ? numericExpiry : -1,
      httpOnly,
      secure: secure === 'TRUE',
    })
  }
  return out
}

/** Map a stored CookieData back into Playwright's addCookies shape. */
export function toAddCookie(cookie: CookieData): PlaywrightCookie {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    expires: cookie.expires,
    httpOnly: cookie.httpOnly,
    secure: cookie.secure,
    ...(cookie.sameSite !== undefined ? { sameSite: cookie.sameSite } : {}),
  }
}

/** Live browser sessions opened by this process (never persisted). */
const sessions = new Map<string, { browser: BrowserLike; context: ContextLike; url: string; openedAt: number }>()

/** Open a headed browser session at the given URL. Returns a handle; the
 * browser window stays open for the user to log in manually. Pass
 * `headless: true` for automation/tests (no visible window). */
export async function openSession(url: string, options?: { headless?: boolean }): Promise<SessionHandle> {
  if (typeof url !== 'string' || url.trim().length === 0) throw new Error('session: url is required')
  const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`
  const headless = options?.headless === true
  const exe = resolveChromium()
  const launchOptions: { headless: boolean; executablePath?: string } = exe !== undefined
    ? { headless, executablePath: exe }
    : { headless }
  const browser = await chromium().launch(launchOptions)
  const context = await browser.newContext({ viewport: { width: 1280, height: 860 } })
  const page = await context.newPage()
  await page.goto(normalized).catch(() => { /* the site may reject; keep the window open */ })
  const id = randomUUID()
  sessions.set(id, { browser, context, url: normalized, openedAt: Date.now() })
  return { id, url: normalized, openedAt: Date.now() }
}

/** Collect the cookies of the given browser session. When `url` is provided,
 * only cookies relevant to that URL (Playwright's cookie URL matching) are
 * returned — handy when the session touched several sites. */
export async function collectSessionCookies(sessionId: string, url?: string): Promise<CookieData[]> {
  const session = sessions.get(sessionId)
  if (session === undefined) throw new Error(`session: unknown session ${sessionId} — open one with vault_session_open first`)
  const cookies = url !== undefined && url.length > 0
    ? await session.context.cookies(url)
    : await session.context.cookies()
  return cookies.map(toCookieData)
}

/** Close a browser session (the window closes; collected cookies are already in the vault). */
export async function closeSession(sessionId: string): Promise<void> {
  const session = sessions.get(sessionId)
  if (session === undefined) return
  sessions.delete(sessionId)
  await session.context.close().catch(() => {})
  await session.browser.close().catch(() => {})
}

/** List open sessions (no secrets). */
export function listSessions(): SessionHandle[] {
  const out: SessionHandle[] = []
  for (const [id, s] of sessions) out.push({ id, url: s.url, openedAt: s.openedAt })
  return out
}

/** Number of open sessions (tests). */
export function openSessionCount(): number {
  return sessions.size
}

/** Close every open session (tests/teardown). */
export async function closeAllSessions(): Promise<void> {
  const ids = [...sessions.keys()]
  for (const id of ids) await closeSession(id)
}
