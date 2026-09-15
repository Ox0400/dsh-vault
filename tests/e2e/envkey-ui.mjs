// The env-var name field: create -> edit round-trip and the detail drawer.
import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { authedContext, EXE, useVault, wipeVault, installDialogs } from './helper.mjs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }

const setField = (p, label, value) => p.evaluate(([lbl, v]) => {
  const exact = (el) => { const l = el.closest('label'); if (!l) return false; return new RegExp('^(' + lbl + ')').test((l.textContent || '').replace(/[*\s]+$/g, '').trim()) }
  const dlg = document.querySelector('[role=dialog][aria-label="新增凭据"], [role=dialog][aria-label="编辑"]')
  const input = [...dlg.querySelectorAll('input,textarea')].find(exact)
  if (!input) return false
  const s = Object.getOwnPropertyDescriptor(input.constructor.prototype, 'value').set
  s.call(input, v); input.dispatchEvent(new Event('input', { bubbles: true }))
  return true
}, [label, value])

try {
  const ctx = await authedContext(b)
  const p = await ctx.newPage()
  installDialogs(p)
  const errors = []
  p.on('pageerror', e => errors.push(String(e).slice(0, 200)))
  await useVault(p, 'test')
  await wipeVault(p, 'test')
  await p.waitForTimeout(1000)

  await p.evaluate(() => { [...document.querySelectorAll('button')].find(x => String(x.className).includes('addButton') && /新增凭据/.test(x.textContent || ''))?.click() })
  await p.waitForTimeout(1200)
  await p.locator('[role=dialog][aria-label="新增凭据"] select').filter({ has: p.locator('option[value="api-key"]') }).first().selectOption('api-key')
  await p.waitForTimeout(600)
  const setTitle = await setField(p, '标题|Title', 'DASHSCOPE 环境变量')
  const setKey = await setField(p, 'API 密钥|API key', 'sk-live-123')
  const setEnv = await setField(p, '环境变量名（可选）|Env var name \\(optional\\)', 'DASHSCOPE_API_KEY')
  check('the editor exposes an env-var name field', setTitle && setKey && setEnv, JSON.stringify({ setTitle, setKey, setEnv }))
  await p.evaluate(() => { [...document.querySelectorAll('[role=dialog][aria-label="新增凭据"] button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))?.click() })
  await p.waitForTimeout(2400)
  const saved = await p.evaluate(() => ({ rows: document.querySelectorAll('[class*="rowMain"]').length, msg: (document.querySelector('[class*="headerMessage"]') || {}).textContent }))
  check('entry with an env key saves', saved.rows === 1 && /创建/.test(saved.msg || ''), JSON.stringify(saved))

  // reopen for editing: the value must round-trip
  await p.evaluate(() => { document.querySelector('[class*="rowMain"]')?.click() })
  await p.waitForTimeout(900)
  await p.evaluate(() => { document.querySelector('[class*="moreButton"]')?.click() })
  await p.waitForTimeout(600)
  await p.evaluate(() => { const e = [...document.querySelectorAll('[class*="moreMenu"] button')].find(x => /编辑|Edit/.test(x.textContent || '')); e?.click() })
  await p.waitForTimeout(1500)
  const roundTrip = await p.evaluate(() => {
    const dlg = document.querySelector('[role=dialog][aria-label="编辑"]')
    if (!dlg) return null
    const input = [...dlg.querySelectorAll('input')].find(i => (i.placeholder || '') === 'DASHSCOPE_API_KEY')
    const label = input ? input.closest('label') : null
    return { value: input ? input.value : null, hint: label ? label.getAttribute('title') : null }
  })
  check('the env key round-trips into the editor', roundTrip?.value === 'DASHSCOPE_API_KEY', JSON.stringify(roundTrip))
  check('the field explains itself on hover', /vault_env|环境变量/.test(roundTrip?.hint || ''), JSON.stringify(roundTrip?.hint))
  await p.evaluate(() => { const c = [...document.querySelectorAll('[role=dialog] button')].find(x => /^(取消|Cancel)$/.test((x.textContent || '').trim())); c?.click() })
  await p.waitForTimeout(700)
  check('no page errors', errors.length === 0, errors.join(' | ').slice(0, 160))

  await wipeVault(p, 'test')
  await ctx.close()
} catch (e) {
  console.log('SCRIPT-ERR:', e && e.message ? e.message : String(e))
} finally {
  await b.close()
  process.exit(R.some(r => !r.ok) ? 1 : 0)
}
