/**
 * The README tool list must match the tools the plugin actually registers.
 *
 * It drifted once: the plugin registered 113 tools while both READMEs listed
 * 77, and the missing 36 were not trivia — they included `vault_clipboard`
 * (a default/basic tool), `vault_export_env`, `vault_import_browser` and the
 * whole `pass`-wallet pair. A user reading the README could not discover them.
 *
 * Groups are compared by their contents, not by their headings, so the English
 * and Chinese sections are checked by the same rule and a translated title
 * cannot silently slip a tool into the wrong group.
 */
import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const source = readFileSync(join(root, 'src', 'index.ts'), 'utf8')

/** Every tool the plugin registers. */
const registered = new Set([...source.matchAll(/^ {4}name: '(vault_[a-z0-9_]+)',/gm)].map(m => m[1]))

function setOf(name: string): Set<string> {
  const block = new RegExp(`const ${name} = new Set\\(\\[(.*?)\\]\\)`, 's').exec(source)?.[1] ?? ''
  return new Set([...block.matchAll(/'([a-z_0-9]+)'/g)].map(m => m[1]!))
}

const CORE = setOf('CORE_TOOLS')
const IO = setOf('IO_TOOLS')
const SESSIONS = setOf('SESSION_TOOLS')
const FILES = setOf('FILE_TOOLS')

/** Group membership as the code decides it — everything else is management. */
function expectedGroup(tool: string): string {
  if (CORE.has(tool)) return 'core'
  if (IO.has(tool)) return 'io'
  if (SESSIONS.has(tool)) return 'sessions'
  if (FILES.has(tool)) return 'files'
  return 'management'
}

/**
 * Tool names written in the FIRST cell of a table row.
 *
 * Only that column names the tool being documented. Descriptions mention other
 * tools on purpose (`vault_notes` points at `vault_update`), and counting those
 * would both credit an undocumented tool and file a core tool under management.
 */
function toolColumn(text: string): Set<string> {
  const names = new Set<string>()
  for (const line of text.split('\n')) {
    if (!line.startsWith('|')) continue
    const firstCell = line.replace(/^\|/, '').split('|')[0] ?? ''
    for (const match of firstCell.matchAll(/`(vault_[a-z0-9_]+)`/g)) names.add(match[1]!)
  }
  return names
}

/** The documented tools per group, in document order. */
function documentedGroups(path: string, heading: string): { heading: string; tools: Set<string> }[] {
  const section = readFileSync(join(root, path), 'utf8').split(heading)[1]!.split('\n## ')[0]!
  return section.split(/^### /m).slice(1).map(block => {
    const [title = '', ...rest] = block.split('\n')
    return { heading: title.trim(), tools: toolColumn(rest.join('\n')) }
  })
}

const ORDER = ['core', 'management', 'io', 'sessions', 'files'] as const

for (const [path, heading] of [['README.md', '## Tools'], ['README-zh.md', '## 工具']] as const) {
  test(`${path}: every registered tool is documented, and nothing else is`, () => {
    const section = readFileSync(join(root, path), 'utf8').split(heading)[1]!.split('\n## ')[0]!
    const mentioned = toolColumn(section)
    expect([...registered].filter(tool => !mentioned.has(tool))).toEqual([])
    // A tool named in the README that the plugin does not register would be a
    // promise the code cannot keep.
    expect([...mentioned].filter(tool => !registered.has(tool))).toEqual([])
  })

  test(`${path}: the five groups hold exactly the tools the code assigns`, () => {
    const groups = documentedGroups(path, heading)
    expect(groups).toHaveLength(ORDER.length)
    for (const [index, key] of ORDER.entries()) {
      const documented = [...groups[index]!.tools].sort()
      const expected = [...registered].filter(tool => expectedGroup(tool) === key).sort()
      expect(documented, `${path}: ${key}`).toEqual(expected)
      // The heading states the group size; a reclassified tool must update it.
      const declared = Number(/—\s*(\d+)/.exec(groups[index]!.heading)?.[1])
      expect(declared, `${path}: ${key} heading count`).toBe(expected.length)
    }
  })
}

test('the grouping covers every registered tool exactly once', () => {
  const grouped = ['core', 'management', 'io', 'sessions', 'files']
    .flatMap(key => [...registered].filter(tool => expectedGroup(tool) === key))
  expect(new Set(grouped).size).toBe(registered.size)
  // Guards the parser itself: if the source layout changes and the tool regex
  // stops matching, this test fails instead of passing over an empty set.
  expect(registered.size).toBeGreaterThan(100)
})
