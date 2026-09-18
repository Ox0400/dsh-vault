// Regression for the reported white screen: 新增凭据 -> 套用模板/类型 -> OAuth
// must not crash the settings slot (it used to die with
// "RangeError: Invalid time value" from the template's expiresAt hint).
import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { EXE, authedContext, installDialogs, openSettings, prepareVault, useVault, wipeVault } from './helper.mjs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const alive = (p) => p.evaluate(() => ({
  section: document.querySelector('section') !== null,
  editor: document.querySelectorAll('[role=dialog][aria-label="新增凭据"]').length,
  crashed: document.body.textContent.includes('slot entry crashed'),
  len: ((document.querySelector('section') || {}).textContent || '').length,
}))

try {
  const ctx = await authedContext(b)
  const p = await ctx.newPage()
  installDialogs(p)
  const errors = []
  p.on('pageerror', e => { errors.push(String(e).slice(0, 300)); console.log('>>> PAGEERROR:', String(e).slice(0, 300)) })
  p.on('console', m => { if (m.type() === 'error') { errors.push(m.text()); console.log('>>> CONSOLE-ERR:', m.text().slice(0, 300)) } })

  await prepareVault(p)
  await p.waitForTimeout(1000)

  // ---- path 1: the 套用模板 dropdown -> OAuth (the user's crash) ----
  await p.evaluate(() => { [...document.querySelectorAll('button')].find(x => String(x.className).includes('addButton') && /新增凭据/.test(x.textContent || ''))?.click() })
  await p.waitForTimeout(1200)
  const tplSel = p.locator('[role=dialog][aria-label="新增凭据"] select').first()
  await tplSel.selectOption({ label: 'OAuth' })
  await p.waitForTimeout(1400)
  const afterTemplate = await alive(p)
  check('applying the OAuth template does not crash', afterTemplate.section && afterTemplate.editor === 1 && !afterTemplate.crashed, JSON.stringify(afterTemplate))

  // the hint must NOT have been written into the date field
  const dateValue = await p.evaluate(() => {
    const dlg = document.querySelector('[role=dialog][aria-label="新增凭据"]')
    const input = dlg.querySelector('input[type=datetime-local]')
    const label = input ? input.closest('label') : null
    return { value: input ? input.value : null, hint: label ? label.getAttribute('title') : null, kind: (dlg.querySelector('select:nth-of-type(2)') || {}).value }
  })
  check('expiry field stays empty and shows the hint as a tooltip', dateValue.value === '' && /epoch|expiry/i.test(dateValue.hint || ''), JSON.stringify(dateValue))

  // ---- path 2: the 类型 dropdown -> OAuth ----
  await p.locator('[role=dialog][aria-label="新增凭据"] select').filter({ has: p.locator('option[value="oauth"]') }).first().selectOption('oauth')
  await p.waitForTimeout(1200)
  const afterKind = await alive(p)
  check('selecting the OAuth kind does not crash', afterKind.section && afterKind.editor === 1 && !afterKind.crashed, JSON.stringify(afterKind))

  // ---- save it and open the entry again ----
  await p.evaluate(() => {
    const exact = (el, re) => { const l = el.closest('label'); if (!l) return false; return re.test((l.textContent || '').replace(/[*\s]+$/g, '').trim()) }
    const dlg = document.querySelector('[role=dialog][aria-label="新增凭据"]')
    const inputs = [...dlg.querySelectorAll('input,textarea')]
    const setV = (el, v) => { const s = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set; s.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })) }
    const t = inputs.find(i => exact(i, /^(标题|Title)$/)); if (t) setV(t, 'OAuth 模板回归')
    const acc = inputs.find(i => exact(i, /^(访问令牌|Access token)$/)); if (acc) setV(acc, 'tok')
    ;[...dlg.querySelectorAll('button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))?.click()
  })
  await p.waitForTimeout(2500)
  const saved = await p.evaluate(() => ({
    rows: document.querySelectorAll('[class*="rowMain"]').length,
    msg: (document.querySelector('[class*="headerMessage"]') || {}).textContent,
  }))
  check('the OAuth entry saves and lists', saved.rows === 1 && /创建/.test(saved.msg || ''), JSON.stringify(saved))

  // reopening it as an editor must not crash either
  await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
  await p.waitForTimeout(1000)
  await p.evaluate(() => {
    document.querySelector('[class*="moreButton"]')?.click()
  })
  await p.waitForTimeout(700)
  await p.evaluate(() => {
    const edit = [...document.querySelectorAll('[class*="moreMenu"] button')].find(x => /编辑|Edit/.test(x.textContent || ''))
    edit?.click()
  })
  await p.waitForTimeout(1500)
  const editing = await p.evaluate(() => ({
    editing: document.querySelectorAll('[role=dialog][aria-label="编辑"]').length,
    crashed: document.body.textContent.includes('slot entry crashed'),
    date: (() => { const i = document.querySelector('[role=dialog][aria-label="编辑"] input[type=datetime-local]'); return i ? i.value : null })(),
  }))
  check('re-opening the entry for edit does not crash', editing.editing === 1 && !editing.crashed, JSON.stringify(editing))

  check('no page errors during the whole flow', errors.length === 0, errors.slice(0, 2).join(' | ').slice(0, 200))

  await openSettings(p, '凭据库')
  await wipeVault(p)
  await ctx.close()
} catch (e) {
  console.log('SCRIPT-ERR:', e && e.message ? e.message : String(e))
} finally {
  await b.close()
  process.exit(R.some(r => !r.ok) ? 1 : 0)
}
