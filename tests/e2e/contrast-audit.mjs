// Full contrast audit of the Vault UI in both host themes: walk every visible
// element inside the section, resolve the effective background by walking up,
// and report text that falls below WCAG AA (4.5:1, or 3:1 for large/bold text).
import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { authedContext, EXE, useVault, installDialogs, openSettings } from './helper.mjs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const tab = (p, name) => p.evaluate((t) => { const el = [...document.querySelectorAll('button,[role=tab],span,li')].find(x => (x.textContent || '').trim() === t); el?.click() }, name)
const theme = (p, name) => p.evaluate((n) => { const el = [...document.querySelectorAll('button')].find(x => (x.textContent || '').trim() === n); el?.click() }, name)
const TABS = ['条目', '安全', '导入/导出', '备份', '权限', '会话', '审计', '回收站']

const audit = (p) => p.evaluate(() => {
  const sec = document.querySelector('section')
  if (!sec) return { error: 'no section' }
  const parseColor = (s) => {
    if (!s) return null
    let m = /rgba?\(([^)]+)\)/.exec(s)
    if (m) { const p = m[1].split(',').map(Number); return [p[0], p[1], p[2], p[3] === undefined ? 1 : p[3]] }
    m = /color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*([\d.]+))?\)/.exec(s)
    if (m) return [Number(m[1]) * 255, Number(m[2]) * 255, Number(m[3]) * 255, m[4] === undefined ? 1 : Number(m[4])]
    return null
  }
  const lin = (c) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4) }
  const L = (c) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2])
  const over = (fg, bg) => [0, 1, 2].map(i => fg[i] * fg[3] + bg[i] * (1 - fg[3]))
  const ratio = (flat, bg) => { const l1 = L(flat), l2 = L(bg); return Math.round(((Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05)) * 100) / 100 }
  // effective background: walk ancestors until a non-transparent background
  const bgOf = (el) => {
    let node = el
    let acc = [255, 255, 255]
    const layers = []
    while (node && node !== document.documentElement) {
      const c = parseColor(getComputedStyle(node).backgroundColor)
      if (c && c[3] > 0) layers.push(c)
      node = node.parentElement
    }
    const bodyBg = parseColor(getComputedStyle(document.body).backgroundColor) || [255, 255, 255, 1]
    acc = [bodyBg[0], bodyBg[1], bodyBg[2]]
    for (const l of layers.reverse()) acc = over(l, acc)
    return acc
  }
  const fails = []
  let checked = 0
  const unparsed = []
  for (const el of sec.querySelectorAll('*')) {
    // only elements that own visible text
    const own = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join('')
    if (own.length === 0) continue
    const cs = getComputedStyle(el)
    if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) continue
    const rect = el.getBoundingClientRect()
    if (rect.width === 0 || rect.height === 0) continue
    const fg = parseColor(cs.color)
    if (!fg) { unparsed.push(cs.color); continue }
    if (fg[3] === 0) continue
    let alpha = fg[3] * Number(cs.opacity)
    const bg = bgOf(el)
    const flat = over([fg[0], fg[1], fg[2], alpha], bg)
    const r = ratio(flat, bg)
    const px = parseFloat(cs.fontSize)
    const bold = Number(cs.fontWeight) >= 600
    const large = px >= 24 || (px >= 18.66 && bold)
    const need = large ? 3 : 4.5
    checked++
    if (r < need) {
      fails.push({ cls: String(el.className).slice(0, 40), text: own.slice(0, 26), color: cs.color, bg: `rgb(${bg.map(Math.round).join(', ')})`, size: cs.fontSize, weight: cs.fontWeight, ratio: r, need, dark: document.body.hasAttribute('data-ds-dark-theme') })
    }
  }
  return { checked, fails, unparsed: [...new Set(unparsed)].slice(0, 5) }
})

try {
  const ctx = await authedContext(b); const p = await ctx.newPage()
  installDialogs(p)
  p.on('pageerror', e => console.log('PAGEERR:', String(e).slice(0, 160)))
  await useVault(p, 'test')

  // give the vaults content so the panels are not all empty
  await p.evaluate(() => { [...document.querySelectorAll('button')].find(x => /新增凭据/.test((x.textContent || '').trim()))?.click() })
  await p.waitForTimeout(900)
  await p.evaluate(() => {
    const exact = (el, re) => { const l = el.closest('label'); if (!l) return false; return re.test((l.textContent || '').replace(/[*\s]+$/g, '').trim()) }
    const dlg = [...document.querySelectorAll('[role=dialog]')].find(d => [...d.querySelectorAll('input[type=text],input:not([type])')].some(i => exact(i, /^(标题|Title)$/)))
    if (!dlg) return
    const inputs = [...dlg.querySelectorAll('input,textarea')]
    const setV = (el, v) => { const s = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set; s.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })) }
    const title = inputs.find(i => exact(i, /^(标题|Title)$/)); const pw = inputs.find(i => exact(i, /^(密码|Password)$/)); const host = inputs.find(i => exact(i, /^(主机|Host)$/))
    if (title) setV(title, '弱口令示例'); if (pw) setV(pw, 'password123'); if (host) setV(host, 'example.com')
    ;[...dlg.querySelectorAll('button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))?.click()
  })
  await p.waitForTimeout(2200)
  // expand the row so the detail box is audited too
  await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
  await p.waitForTimeout(1200)

  let totalFails = 0
  for (const mode of ['浅色', '深色']) {
    await tab(p, '通用设置'); await p.waitForTimeout(900)
    await theme(p, mode); await p.waitForTimeout(1100)
    await openSettings(p, '凭据库'); await p.waitForTimeout(1200)
    await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
    await p.waitForTimeout(1000)
    console.log(`\n===== ${mode} =====`)
    for (const t of TABS) {
      await openSettings(p, '凭据库'); await p.waitForTimeout(700)
      await tab(p, t); await p.waitForTimeout(1400)
      const r = await audit(p)
      if (r.error) { console.log(`${t}: ERROR ${r.error}`); continue }
      console.log(`${t.padEnd(8)} checked ${String(r.checked).padStart(4)}  fails ${r.fails.length}${r.unparsed && r.unparsed.length ? '  UNPARSED ' + JSON.stringify(r.unparsed) : ''}`)
      for (const f of r.fails) { totalFails++; console.log(`   ✗ ${f.ratio} < ${f.need}  ${f.color} on ${f.bg}  ${f.size}/${f.weight}  .${f.cls}  "${f.text}"`) }
      await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
      await p.waitForTimeout(400)
    }
  }
  await tab(p, '通用设置'); await p.waitForTimeout(800); await theme(p, '跟随系统'); await p.waitForTimeout(800)
  console.log(`\nTOTAL low-contrast findings: ${totalFails}`)
  await ctx.close()
} finally { await b.close() }
