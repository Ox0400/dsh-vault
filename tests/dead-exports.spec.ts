/**
 * The dead-export guard (`scripts/dead-exports.mjs`).
 *
 * Eleven exported symbols once existed whose only occurrence in the repository
 * was their own declaration. This test runs the rule over the real tree and
 * proves it is not vacuous by feeding it a planted symbol.
 */
import { test, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve } from 'node:path'
import { FRAMEWORK_EXPORTS, findDeadExports } from '../scripts/dead-exports.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

function collect(dir: string, extensions: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      if (!extensions.some(ext => entry.name.endsWith(ext))) continue
      out[relative(root, full)] = readFileSync(full, 'utf8')
    }
  }
  walk(resolve(root, dir))
  return out
}

test('the rule actually catches a symbol nothing references', () => {
  const sources = {
    'src/a.ts': 'export function used() { return 1 }\nexport function orphan() { return 2 }\n',
    'src/b.ts': 'export const ALSO_ORPHAN = 3\n',
  }
  const references = { 'tests/a.spec.ts': "import { used } from '../src/a'\nused()\n" }
  const dead = findDeadExports({ sources, references })
  expect(dead.map(d => d.name).sort()).toEqual(['ALSO_ORPHAN', 'orphan'])
  // …and a referenced symbol is not reported, so the rule is not vacuous.
  expect(dead.some(d => d.name === 'used')).toBe(false)
})

test('a symbol used only inside its own module still counts as used', () => {
  // Exporting a module's own types is a normal convention, not dead code.
  const sources = { 'src/a.ts': 'export type Opts = { x: number }\nexport function f(o: Opts) { return o.x }\nf({ x: 1 })\n' }
  expect(findDeadExports({ sources, references: {} })).toEqual([])
})

test('the framework exports Cordis reads by convention are exempt', () => {
  const sources = { 'src/a.ts': 'export const name = "x"\nexport const inject = []\nexport async function apply() {}\n' }
  expect(findDeadExports({ sources, references: {}, allow: FRAMEWORK_EXPORTS })).toEqual([])
  expect(findDeadExports({ sources, references: {} }).length).toBe(3)
})

test('no exported symbol in src/ is unreferenced', () => {
  const sources = collect('src', ['.ts', '.tsx'])
  const references = {
    ...collect('tests', ['.ts', '.mjs']),
    ...collect('scripts', ['.mjs']),
    ...collect('docs', ['.md']),
    'README.md': readFileSync(join(root, 'README.md'), 'utf8'),
    'README-zh.md': readFileSync(join(root, 'README-zh.md'), 'utf8'),
  }
  expect(sources['src/index.ts']).toBeDefined()
  const dead = findDeadExports({ sources, references, allow: FRAMEWORK_EXPORTS })
  expect(dead.map(d => `${d.path}: ${d.name}`)).toEqual([])
})
