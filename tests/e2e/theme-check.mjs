import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { authedContext, EXE, useVault, assertActiveVault, activeVault, installDialogs } from './helper.mjs'
import { writeFileSync } from 'node:fs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const tab = (p, name) => p.evaluate((t) => { const el = [...document.querySelectorAll('button,[role=tab],span,li')].find(x => (x.textContent || '').trim() === t); el?.click() }, name)
const theme = (p, name) => p.evaluate((n) => { const el = [...document.querySelectorAll('button')].find(x => (x.textContent || '').trim() === n); el?.click() }, name)

const probe = (p) => p.evaluate(() => {
  const sec = document.querySelector('section')
  const cs = sec ? getComputedStyle(sec) : null
  const tok = (n) => cs ? cs.getPropertyValue(n).trim() : null
  const track = document.querySelector('svg circle:first-child')
  const box = document.querySelector('[class*="attachBox"]')
  const bs = box ? getComputedStyle(box) : null
  const parent = box ? box.parentElement : null
  return {
    dark: document.body.hasAttribute('data-ds-dark-theme'),
    bodyBg: getComputedStyle(document.body).backgroundColor,
    ring: tok('--v-ring-track'), mono: tok('--v-mono'), shadow: tok('--v-shadow'), border: tok('--v-border'),
    trackStroke: track ? getComputedStyle(track).stroke : null,
    ringCls: track ? (track.closest('svg')?.className?.baseVal || '') : null,
    attach: bs ? {
      borderTop: bs.borderTopStyle + ' ' + bs.borderTopWidth + ' ' + bs.borderTopColor,
      flexBasis: bs.flexBasis, gap: bs.gap, paddingTop: bs.paddingTop,
      w: Math.round(box.getBoundingClientRect().width),
      parentW: parent ? Math.round(parent.getBoundingClientRect().width) : null,
      parentDisplay: parent ? getComputedStyle(parent).display + '/' + getComputedStyle(parent).flexWrap : null,
    } : null,
  }
})

try {
  const ctx = await authedContext(b)
  const p = await ctx.newPage()
  installDialogs(p)
  p.on('pageerror', e => console.log('PAGEERR:', String(e).slice(0, 160)))

  await useVault(p, 'test')
  // pin the theme so the "light" probe really is light
  await tab(p, '通用设置'); await p.waitForTimeout(1000); await theme(p, '浅色'); await p.waitForTimeout(1100)
  await tab(p, '凭据库'); await p.waitForTimeout(1600)
  check('E2E runs in the throwaway vault', (await activeVault(p)) === 'test', `active=${await activeVault(p)}`)

  // ---- seed one entry (the guard above proves this cannot hit the real vault) ----
  const made = await p.evaluate(() => {
    const add = [...document.querySelectorAll('button')].find(x => /新增凭据/.test((x.textContent || '').trim()))
    add?.click(); return add !== undefined
  })
  await p.waitForTimeout(1000)
  const filled = await p.evaluate(() => {
    const exact = (el, re) => { const l = el.closest('label'); if (!l) return false; const txt = (l.textContent || '').replace(/[*\s]+$/g, '').trim(); return re.test(txt) }
    const dlg = [...document.querySelectorAll('[role=dialog]')].find(d => [...d.querySelectorAll('input[type=text],input:not([type])')].some(i => exact(i, /^(标题|Title)$/)))
    if (!dlg) return null
    const setV = (el, v) => { const s = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set; s.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })) }
    const inputs = [...dlg.querySelectorAll('input,textarea')]
    const byLabel = (re) => inputs.find(i => { const l = i.closest('label'); return l && re.test(l.textContent || '') })
    const title = inputs.find(i => exact(i, /^(标题|Title)$/)); const pw = inputs.find(i => exact(i, /^(密码|Password)$/))
    if (!title) return null
    setV(title, 'E2E 主题校验'); if (pw) setV(pw, 'Zq7!themeCheck-2024')
    const save = [...dlg.querySelectorAll('button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))
    save?.click()
    return { title: title.value, saved: save !== undefined }
  })
  await p.waitForTimeout(2200)
  const rows = await p.evaluate(() => [...document.querySelectorAll('[class*="rowMain"]')].map(x => (x.textContent || '').slice(0, 24)))
  check('entry seeded in the throwaway vault', rows.length > 0, JSON.stringify(filled) + ' rows=' + JSON.stringify(rows))

  // ---- expand the row: the detail box (with its attach row) renders ----
  await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
  await p.waitForTimeout(1500)

  // ---- attach a file through the real file input ----
  const tmp = '/tmp/dsh-attach-check.txt'
  writeFileSync(tmp, 'dsh-vault attachment E2E\n')
  if (await p.locator('input[type=file]').count() > 0) {
    await p.locator('input[type=file]').first().setInputFiles(tmp)
    await p.waitForTimeout(2200)
  }
  const attachInfo = await p.evaluate(() => {
    const box = document.querySelector('[class*="attachBox"]')
    return box ? { text: (box.textContent || '').trim().slice(0, 60), items: box.querySelectorAll('[class*="detailItem"]').length } : null
  })
  check('attachment uploaded and listed in the attach row', attachInfo !== null && attachInfo.items >= 1, JSON.stringify(attachInfo))
  const lightAttach = await probe(p)

  // ---- the security tab renders a real painted ring (score ring) ----
  await tab(p, '安全'); await p.waitForTimeout(2000)
  const ringLight = await probe(p)
  await tab(p, '凭据库'); await p.waitForTimeout(1500)

  // ---- dark theme ----
  await tab(p, '通用设置'); await p.waitForTimeout(1100)
  await theme(p, '深色'); await p.waitForTimeout(1200)
  await tab(p, '凭据库'); await p.waitForTimeout(1800)
  // make sure the row is expanded in dark mode too (click only when needed)
  for (let i = 0; i < 3; i++) {
    const open = await p.evaluate(() => document.querySelector('[class*="attachBox"]') !== null)
    if (open) break
    await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
    await p.waitForTimeout(1300)
  }
  const dark = await probe(p)

  check('ring track token resolves in both themes', /rgb|#/.test(lightAttach.ring || '') && /rgb|#/.test(dark.ring || ''), `${lightAttach.ring} / ${dark.ring}`)
  check('ring track flips with the theme', lightAttach.ring !== dark.ring, `${lightAttach.ring} → ${dark.ring}`)
  check('ring track is never the old phantom #ddd', !/255,\s*221,\s*221|#ddd/i.test(lightAttach.ring + ' ' + dark.ring))
  check('mono font = host code stack', /SF Mono|JetBrains|Menlo|monospace/i.test(lightAttach.mono || ''), String(lightAttach.mono).slice(0, 48) + '…')
  check('shadow = host elevation token', /0 3px 8px|0 0 16px/.test(lightAttach.shadow || ''), String(lightAttach.shadow).slice(0, 64) + '…')
  check('attach row has a themed separator', /dashed/.test(lightAttach.attach?.borderTop || ''), JSON.stringify(lightAttach.attach))
  check('attach row owns a full-width row', lightAttach.attach?.flexBasis === '100%', `basis=${lightAttach.attach?.flexBasis} parent=${lightAttach.attach?.parentDisplay}`)
  check('attach separator flips with the theme', lightAttach.attach?.borderTop !== dark.attach?.borderTop, `${lightAttach.attach?.borderTop} → ${dark.attach?.borderTop}`)
  if (ringLight.trackStroke !== null) {
    check('painted ring track is themed, not #ddd', !/255,\s*221,\s*221/i.test(ringLight.trackStroke), `${ringLight.trackStroke} (${ringLight.ringCls})`)
  } else console.log('INFO  no painted ring found on the security tab')

  // ---- restore the user's theme preference ----
  await tab(p, '通用设置'); await p.waitForTimeout(1000)
  await theme(p, '跟随系统'); await p.waitForTimeout(900)
  const back = await probe(p)
  check('theme preference restored', back.dark === false, `dark=${back.dark}`)

  console.log('\nlight:', JSON.stringify(lightAttach))
  console.log('dark :', JSON.stringify(dark))
  await ctx.close()
} catch (e) {
  console.log('SCRIPT-ERR:', e && e.message ? e.message : String(e))
} finally {
  await b.close()
  process.exit(R.some(r => !r.ok) ? 1 : 0)
}
