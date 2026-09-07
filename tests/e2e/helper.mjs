// Shared helpers for browser E2E against the real dsh web.
// Tests run against a dedicated vault (default: 'test') so the user's real
// 'default' vault is never touched. Requires playwright-core + an authed page.
import { createHash, createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const EXE = path.join(os.homedir(), 'Library', 'Caches', 'ms-playwright', 'chromium-1228', 'chrome-mac-arm64', 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing')
export const TEST_VAULT = process.env.DSH_E2E_VAULT ?? 'test'

export async function authedContext(browser) {
  const raw = readFileSync(path.join(os.homedir(), '.dsh', '.credentials.yaml'), 'utf8')
  const idx = raw.indexOf('client-connection/browser-session')
  const m = /secret:\s*['"]?([A-Za-z0-9_\-]+)['"]?/.exec(raw.slice(idx, idx + 400))
  if (!m) throw new Error('no browser-session secret')
  const b64 = m[1]
  const secret = Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - b64.length % 4) % 4), 'base64')
  const encB64 = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')
  const now = Date.now()
  const payload = { version: 1, authority: '127.0.0.1:3080', issuedAt: now, expiresAt: now + 30 * 24 * 3600 * 1000 }
  const body = encB64(Buffer.from(JSON.stringify(payload), 'utf8'))
  const cookieValue = `v1.${body}.${encB64(createHmac('sha256', secret).update(body).digest())}`
  const cookieName = 'dsh-auth-' + encB64(createHash('sha256').update('127.0.0.1:3080').digest())
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } })
  await ctx.addCookies([{ name: cookieName, value: cookieValue, domain: '127.0.0.1', path: '/', httpOnly: true }])
  return ctx
}

export async function openSettings(page, tab = '凭据库') {
  await page.goto('http://127.0.0.1:3080/', { waitUntil: 'domcontentloaded' })
  await page.waitForTimeout(3000)
  await page.evaluate(() => { [...document.querySelectorAll('button')].find(x => /^(设置|Settings)$/.test((x.textContent || '').trim()))?.click() })
  await page.waitForTimeout(1500)
  await page.evaluate((t) => { [...document.querySelectorAll('button,[role=tab],li,span')].find(x => new RegExp('^' + t + '$').test((x.textContent || '').trim()))?.click() }, tab)
  await page.waitForTimeout(2500)
}

/** Ensure a dedicated vault exists and is active (creating it on first use). */
export async function useVault(page, name = TEST_VAULT) {
  await openSettings(page, '凭据库')
  const exists = await page.evaluate((n) => {
    const sel = [...document.querySelectorAll('select')].find(x => (x.getAttribute('aria-label') || '').includes('保险库'))
    return sel ? [...sel.querySelectorAll('option')].some(o => o.value === n) : false
  }, name)
  if (!exists) {
    // create via vault management (＋ New vault → prompt name)
    await page.evaluate(() => { [...document.querySelectorAll('button,[role=tab],li,span')].find(x => /^权限$/.test((x.textContent || '').trim()))?.click() })
    await page.waitForTimeout(1200)
    await page.evaluate(() => { [...document.querySelectorAll('button')].find(x => /新建保险库/.test((x.textContent || '').trim()))?.click() })
    await page.waitForTimeout(400)
    await page.evaluate((n) => { const dlg = [...document.querySelectorAll('[role=dialog],body')].find(() => true); return null }, name)
    // window.prompt handled via page.on('dialog'); simulate by typing if prompt used
    const prompter = (d) => d.type() === 'prompt' ? d.accept(name) : d.accept()
    page.once('dialog', prompter)
    await page.waitForTimeout(1800)
  } else {
    await switchVault(page, name)
  }
  return name
}

export async function switchVault(page, name) {
  const sel = page.locator('select[aria-label*="保险库"], select').first()
  await sel.waitFor({ state: 'visible', timeout: 8000 }).catch(() => {})
  await page.evaluate((n) => {
    const s = [...document.querySelectorAll('select')].find(x => (x.getAttribute('aria-label') || '').includes('保险库'))
    if (!s) return
    const ev = new Event('change', { bubbles: true })
    s.value = n
    s.dispatchEvent(ev)
  }, name)
  await page.waitForTimeout(1500)
}

/** Delete every entry of the given vault (keeps the vault itself). */
export async function wipeVault(page, name = TEST_VAULT) {
  await switchVault(page, name)
  await page.waitForTimeout(1200)
  // toggle bulk select, tick all visible rows, delete
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /批量选择/.test((x.textContent || '').trim())); b?.click() })
  await page.waitForTimeout(700)
  const ticked = await page.evaluate(() => {
    let n = 0
    for (const cb of [...document.querySelectorAll('ul li input[type=checkbox]')]) { if (!cb.checked) { cb.click(); n++ } }
    return n
  })
  if (ticked > 0) {
    await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /^删除$/.test((x.textContent || '').trim())); b?.click() })
    await page.waitForTimeout(1500)
  }
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /^(完成|完成选择)$/.test((x.textContent || '').trim())); b?.click() })
  await page.waitForTimeout(500)
  // empty the trash
  await page.evaluate(() => { const t = [...document.querySelectorAll('button,[role=tab]')].find(b => /^回收站$/.test((b.textContent || '').trim())); t?.click() })
  await page.waitForTimeout(1000)
  await page.evaluate(() => { const b = [...document.querySelectorAll('button')].find(x => /清空回收站/.test((x.textContent || '').trim())); b?.click() })
  await page.waitForTimeout(1500)
  await openSettings(page, '凭据库')
}
