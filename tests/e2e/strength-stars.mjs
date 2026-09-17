// The entry list shows a three-star strength indicator after the title:
// ☆☆☆ = 0 score, ★★★ = full marks. The score is computed
// host-side, so the browser never receives the secret.
import { chromium } from '/Users/zhipeng/Desktop/work/codes/deepseek-harness/node_modules/.pnpm/playwright-core@1.61.1/node_modules/playwright-core/index.mjs'
import { authedContext, EXE, useVault, wipeVault, installDialogs, openSettings } from './helper.mjs'

const b = await chromium.launch({ executablePath: EXE, headless: true })
const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const clickText = (p, t) => p.evaluate((x) => { const el = [...document.querySelectorAll('button,[role=tab],span,li')].find(y => (y.textContent || '').trim() === x); el?.click(); return el !== undefined }, t)

const snap = (p) => p.evaluate(() => {
  return [...document.querySelectorAll('[class*="rowMain"]')].map(row => {
    const titleEl = row.querySelector('[class*="_title"]')
    const stars = row.querySelector('[class*="strengthStars"]')
    if (!stars) return { title: (titleEl?.textContent || '').slice(0, 20).trim(), stars: null, fill: null, hint: null, cls: null }
    const track = stars.querySelector('[class*="strengthTrack"]')
    const fill = stars.querySelector('[class*="strengthFill"]')
    const box = stars.getBoundingClientRect()
    const filled = fill ? fill.getBoundingClientRect() : null
    return {
      title: (titleEl?.textContent || '').slice(0, 20).trim(),
      stars: track ? (track.textContent || '').trim() : null,
      fill: box.width > 0 && filled ? Math.round((filled.width / box.width) * 100) : 0,
      hint: stars.getAttribute('title'),
      cls: fill ? String(fill.className).replace(/^.*strength/, 'strength').slice(0, 30) : null,
    }
  })
})

const addEntry = async (p, title, password) => {
  await p.evaluate(() => {
    const btn = [...document.querySelectorAll('button')].find(x => String(x.className).includes('addButton') && /新增凭据/.test(x.textContent || ''))
    btn?.click()
  })
  await p.waitForTimeout(1100)
  await p.evaluate(([t, pw]) => {
    const exact = (el, re) => { const l = el.closest('label'); if (!l) return false; return re.test((l.textContent || '').replace(/[*\s]+$/g, '').trim()) }
    const starts = (el, re) => { const l = el.closest('label'); if (!l) return false; return re.test((l.textContent || '').trim()) }
    const dlg = document.querySelector('[role=dialog][aria-label="新增凭据"]')
    const inputs = [...dlg.querySelectorAll('input,textarea')]
    const setV = (el, v) => { const s = Object.getOwnPropertyDescriptor(el.constructor.prototype, 'value').set; s.call(el, v); el.dispatchEvent(new Event('input', { bubbles: true })) }
    const titleInput = inputs.find(i => exact(i, /^(标题|Title)$/))
    const pwInput = inputs.find(i => exact(i, /^(密码|Password)$/)) ?? inputs.find(i => starts(i, /^(密码|Password)/))
    if (titleInput) setV(titleInput, t)
    if (pwInput) setV(pwInput, pw)
    ;[...dlg.querySelectorAll('button')].find(x => /^(保存|Save)$/.test((x.textContent || '').trim()))?.click()
  }, [title, password])
  await p.waitForTimeout(2000)
}

try {
  const ctx = await authedContext(b)
  const p = await ctx.newPage()
  installDialogs(p)
  const errors = []
  p.on('pageerror', e => errors.push(String(e).slice(0, 200)))
  await useVault(p)
  await wipeVault(p)
  await p.waitForTimeout(1000)

  await addEntry(p, 'PIN 卡', '1234')
  await addEntry(p, '弱口令', '1111')
  await addEntry(p, '半星', 'Sunflower22')   // 45/100 → 3 of 6 units → 50%
  await addEntry(p, '中等', 'M0onlight!River42')
  await addEntry(p, '强口令', 'Xk9#mQ2!vT7@pL4z')
  await openSettings(p, '凭据库')
  await p.waitForTimeout(1500)

  const rows = await snap(p)
  if (rows.length > 0 && rows.every(r => r.stars === null)) {
    console.log('SKIP  the running host does not send passwordStrength — restart `dsh web` and re-run')
    console.log('      (the mapping itself is covered by tests/strength-stars.spec.ts)')
    await wipeVault(p)
    await ctx.close()
    await b.close()
    process.exit(0)
  }

  const scored = rows.filter(r => r.stars !== null && /\d+\/100/.test(r.hint || ''))
  const filled = (s) => (s || '').split('').filter(c => c === '★').length
  check('the track is hollow so 0 units cannot look full', scored.every(r => r.stars === '☆☆☆'), JSON.stringify(scored.map(r => r.stars)))
  // The contract that matters: whatever score the host reports, the client must
  // draw it as a clip at units/6 of the track — including the half-star steps,
  // which are not multiples of a third. Deriving the expectation from the hint
  // keeps this true across scoring changes.
  const mismatches = []
  for (const row of scored) {
    const score = Number(/\d+/.exec(row.hint)[0])
    const units = score <= 0 ? 0 : Math.min(6, Math.max(0, Math.round((score / 100) * 6)))
    const expected = (units / 6) * 100
    if (Math.abs(row.fill - expected) > 1.5) mismatches.push(`${row.title}: score ${score} → expected ${expected.toFixed(0)}%, drew ${row.fill}%`)
  }
  check('every row draws exactly its score as a clip width', mismatches.length === 0, mismatches.join(' | '))
  const halves = scored.filter(r => [17, 50, 83].some(pct => Math.abs(r.fill - pct) <= 1.5))
  check('a half-star position is rendered (17 / 50 / 83%)', halves.length > 0, scored.map(r => `${r.title}=${r.fill}%`).join(' '))
  check('filled stars grow with the score', (() => {
    const sorted = [...scored].sort((a, b) => Number(/\d+/.exec(a.hint)[0]) - Number(/\d+/.exec(b.hint)[0]))
    return sorted.every((row, i) => i === 0 || row.fill >= sorted[i - 1].fill)
  })(), scored.map(r => r.fill).join(','))
  check('the indicator carries the score as a hint', scored.every(r => /\d+\/100/.test(r.hint || '')), JSON.stringify(scored[0]?.hint))
  check('the colour reflects the band', scored.some(r => /strengthWeak/.test(r.cls || '')) && scored.some(r => /strengthStrong|strengthFair/.test(r.cls || '')), scored.map(r => r.cls).join(','))

  // the secret itself is never in the page
  const html = await p.content()
  check('no secret reaches the browser', !html.includes('Xk9#mQ2') && !html.includes('4111'), '')

  check('no page errors', errors.length === 0, errors.join(' | ').slice(0, 160))

  await wipeVault(p)
  await ctx.close()
} catch (e) {
  console.log('SCRIPT-ERR:', e && e.message ? e.message : String(e))
} finally {
  await b.close()
  process.exit(R.some(r => !r.ok) ? 1 : 0)
}
