import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { authedContext, EXE, useVault, activeVault, installDialogs, openSettings } from './helper.mjs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const tab = (p, name) => p.evaluate((t) => { const el = [...document.querySelectorAll('button,[role=tab],span,li')].find(x => (x.textContent || '').trim() === t); el?.click() }, name)
const theme = (p, name) => p.evaluate((n) => { const el = [...document.querySelectorAll('button')].find(x => (x.textContent || '').trim() === n); el?.click() }, name)

// Parse a computed colour into [r,g,b,a] and compute WCAG contrast over a bg.
const probe = (p) => p.evaluate(() => {
  const sec = document.querySelector('section')
  const paint = (el) => { if (!el) return null; const cs = getComputedStyle(el); return { color: cs.color, fontSize: cs.fontSize, opacity: cs.opacity } }
  const out = {}
  // the trash empty state lives inside OUR section (DSH has its own "空面板")
  const trashEmpty = [...(sec ? sec.querySelectorAll('p') : [])].find(x => /回收站为空|Trash is empty/.test(x.textContent || ''))
  out.emptyText = trashEmpty ? (trashEmpty.textContent || '').trim() : null
  out.emptyStyle = paint(trashEmpty)
  out.hintStyle = paint(trashEmpty ? trashEmpty.querySelector('span') : null)
  const when = sec ? sec.querySelector('[class*="auditWhen"]') : null
  out.whenText = when ? (when.textContent || '').trim() : null
  out.whenTitle = when ? when.getAttribute('title') : null
  out.whenStyle = paint(when)
  out.auditLines = sec ? [...sec.querySelectorAll('[class*="reportLine"]')].length : 0
  out.dark = document.body.hasAttribute('data-ds-dark-theme')
  out.bodyBg = getComputedStyle(document.body).backgroundColor
  return out
})

const contrast = (fg, bg) => {
  const parse = (s) => {
    if (!s) return null
    let m = /rgba?\(([^)]+)\)/.exec(s)
    if (m) { const p = m[1].split(',').map(Number); return [p[0], p[1], p[2], p[3] === undefined ? 1 : p[3]] }
    m = /color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+))?\)/.exec(s)
    if (m) return [Number(m[1]) * 255, Number(m[2]) * 255, Number(m[3]) * 255, m[4] === undefined ? 1 : Number(m[4])]
    return null
  }
  const lin = (c) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4) }
  const L = (c) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2])
  const f = parse(fg); const g = parse(bg)
  if (!f || !g) return null
  // flatten the (possibly translucent) text colour over the page background
  const a = f[3]
  const flat = [0, 1, 2].map(i => f[i] * a + g[i] * (1 - a))
  const l1 = L(flat); const l2 = L(g)
  return Math.round(((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)) * 100) / 100
}

try {
  const ctx = await authedContext(b); const p = await ctx.newPage()
  installDialogs(p)
  p.on('pageerror', e => console.log('PAGEERR:', String(e).slice(0, 160)))
  await useVault(p, 'test')
  check('E2E runs in the throwaway vault', (await activeVault(p)) === 'test', `active=${await activeVault(p)}`)

  // ---- seed one entry so the audit log has a fresh event to show ----
  await p.evaluate(() => { [...document.querySelectorAll('button')].find(x => /新增凭据/.test((x.textContent || '').trim()))?.click() })
  await p.waitForTimeout(1000)
  await p.evaluate(() => {
    const exact = (el, re) => { const l = el.closest('label'); if (!l) return false; return re.test((l.textContent || '').replace(/[*\s]+$/g, '').trim()) }
    const dlg = [...document.querySelectorAll('[role=dialog]')].find(d => [...d.querySelectorAll('input[type=text],input:not([type])')].some(i => exact(i, /^(标题|Title)$/)))
    if (!dlg) return
    const inputs = [...dlg.querySelectorAll('input,textarea')]
    const setV = (el, v) => { const s = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set; s.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })) }
    const title = inputs.find(i => exact(i, /^(标题|Title)$/)); const pw = inputs.find(i => exact(i, /^(密码|Password)$/))
    if (title) setV(title, 'E2E 审计校验')
    if (pw) setV(pw, 'Zq7!auditCheck-2024')
    ;[...dlg.querySelectorAll('button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))?.click()
  })
  await p.waitForTimeout(2200)

  // ---- trash empty state (the throwaway vault's trash is empty) ----
  await openSettings(p, '凭据库'); await tab(p, '回收站'); await p.waitForTimeout(1600)
  await tab(p, '通用设置'); await p.waitForTimeout(900); await theme(p, '浅色'); await p.waitForTimeout(1100)
  await openSettings(p, '凭据库'); await tab(p, '回收站'); await p.waitForTimeout(1600)
  const trashLight = await probe(p)
  await tab(p, '通用设置'); await p.waitForTimeout(900); await theme(p, '深色'); await p.waitForTimeout(1100)
  await openSettings(p, '凭据库'); await tab(p, '回收站'); await p.waitForTimeout(1600)
  const trashDark = await probe(p)

  check('empty trash explains itself', /回收站为空/.test(trashLight.emptyText || '') && /(不会自动清理|恢复)/.test(trashLight.emptyText || ''), JSON.stringify(trashLight.emptyText))
  const hintContrastLight = contrast(trashLight.hintStyle?.color, trashLight.bodyBg)
  const hintContrastDark = contrast(trashDark.hintStyle?.color, trashDark.bodyBg)
  check('hint line is readable in both themes', hintContrastLight >= 4.5 && hintContrastDark >= 4.5, `contrast light ${hintContrastLight} / dark ${hintContrastDark}`)
  check('hint is dimmer than the headline', Number(trashLight.hintStyle?.opacity) < Number(trashLight.emptyStyle?.opacity ?? 1), `hint ${trashLight.hintStyle?.opacity} vs headline ${trashLight.emptyStyle?.opacity}`)

  // ---- audit rows: absolute time visible, relative age on hover ----
  await openSettings(p, '凭据库'); await tab(p, '审计'); await p.waitForTimeout(2000)
  const auditDarkProbe = await probe(p)
  await tab(p, '通用设置'); await p.waitForTimeout(900); await theme(p, '浅色'); await p.waitForTimeout(1100)
  await openSettings(p, '凭据库'); await tab(p, '审计'); await p.waitForTimeout(2000)
  const auditLight = await probe(p)

  check('audit line shows an absolute timestamp', /\d{4}|\d{1,2}:\d{2}/.test(auditLight.whenText || ''), JSON.stringify(auditLight.whenText))
  check('hover hint carries the relative age', /(刚刚|分钟前|小时前|天前)/.test(auditLight.whenTitle || ''), JSON.stringify(auditLight.whenTitle))
  check('hover hint keeps the absolute value too', /\d/.test((auditLight.whenTitle || '').split('·')[0] || ''), JSON.stringify(auditLight.whenTitle))
  const whenContrastLight = contrast(auditLight.whenStyle?.color, auditLight.bodyBg)
  const whenContrastDark = contrast(auditDarkProbe.whenStyle?.color, auditDarkProbe.bodyBg)
  check('timestamp is readable in both themes', whenContrastLight >= 4.5 && whenContrastDark >= 4.5, `contrast light ${whenContrastLight} / dark ${whenContrastDark}`)

  // ---- restore the user's theme preference ----
  await tab(p, '通用设置'); await p.waitForTimeout(900); await theme(p, '跟随系统'); await p.waitForTimeout(900)
  await openSettings(p, '凭据库'); await p.waitForTimeout(1200)
  const back = await probe(p)
  check('theme preference restored', back.dark === false, `dark=${back.dark}`)

  console.log('\ntrash(light):', JSON.stringify(trashLight))
  console.log('audit(light):', JSON.stringify({ when: auditLight.whenText, title: auditLight.whenTitle, color: auditLight.whenStyle?.color }))
  await ctx.close()
} catch (e) {
  console.log('SCRIPT-ERR:', e && e.message ? e.message : String(e))
} finally {
  await b.close()
  process.exit(R.some(r => !r.ok) ? 1 : 0)
}
