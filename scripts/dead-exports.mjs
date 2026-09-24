/**
 * Guard against code that nothing calls.
 *
 * This project accumulated eleven exported symbols whose only occurrence in the
 * whole repository was their own declaration — leftovers like a `toAddCookie`
 * that implied a cookie-injection feature nobody wrote, and two "diagnostics/
 * tests" hooks that no test ever imported. Dead code is not free: it reads as a
 * capability, and a hook whose comment says "set by tests" actively misleads.
 *
 * The rule is deliberately narrow so it can stay enabled: an exported
 * declaration must be referenced *somewhere* outside its own declaration line.
 * That still allows a module to export a type it uses internally, which is a
 * normal convention — it only catches symbols with no reference at all.
 *
 *   node scripts/dead-exports.mjs
 */
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve } from 'node:path'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))

/** Cordis reads these off the plugin object by convention, not by import. */
export const FRAMEWORK_EXPORTS = ['apply', 'name', 'inject', 'Config', 'default']

const DECLARATION = /^export\s+(?:async\s+)?(?:function|const|let|class|type|interface)\s+([A-Za-z_$][\w$]*)/gm

/**
 * Symbols whose only reference anywhere is their own declaration.
 *
 * Pure: `sources` is path -> text for files that *declare* exports, and
 * `references` is path -> text for everything that may *use* them (tests,
 * scripts, docs). A symbol is used if its name appears anywhere other than the
 * declaration itself, or a second time within its own file.
 */
export function findDeadExports({ sources, references, allow = [] }) {
  const allowed = new Set(allow)
  const all = [...Object.values(sources), ...Object.values(references)].join('\n')
  const dead = []
  for (const [path, text] of Object.entries(sources)) {
    for (const match of text.matchAll(new RegExp(DECLARATION.source, DECLARATION.flags))) {
      const name = match[1]
      if (allowed.has(name)) continue
      const count = all.match(new RegExp(`\\b${name.replace(/\$/g, '\\$')}\\b`, 'g'))?.length ?? 0
      if (count <= 1) dead.push({ path, name })
    }
  }
  return dead
}

/** Read every file under `dir` whose extension is in `extensions`. */
function collect(dir, extensions) {
  const out = {}
  const walk = current => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (!extensions.some(ext => entry.name.endsWith(ext))) continue
      out[relative(ROOT, full)] = readFileSync(full, 'utf8')
    }
  }
  walk(resolve(ROOT, dir))
  return out
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const sources = collect('src', ['.ts', '.tsx'])
  const references = {
    ...collect('tests', ['.ts', '.mjs']),
    ...collect('scripts', ['.mjs']),
    ...collect('docs', ['.md']),
    'README.md': readFileSync(join(ROOT, 'README.md'), 'utf8'),
    'README-zh.md': readFileSync(join(ROOT, 'README-zh.md'), 'utf8'),
  }
  const dead = findDeadExports({ sources, references, allow: FRAMEWORK_EXPORTS })
  if (dead.length === 0) {
    console.log(`ok  ${Object.keys(sources).length} 个源文件里没有无人引用的导出`)
  } else {
    console.log(`${dead.length} 个导出在全仓库只出现在自己的声明处:`)
    for (const { path, name } of dead) console.log(`  ✗ ${path}: ${name}`)
    console.log('\n要么删掉它,要么让代码/测试真的引用它。若它确实是给外部消费者的 API,请加进 FRAMEWORK_EXPORTS 并说明原因。')
    process.exit(1)
  }
}
