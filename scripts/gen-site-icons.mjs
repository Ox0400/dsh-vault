/**
 * Regenerate the brand glyph table in `src/client/site-icons.ts`.
 *
 * That file's header has always said "machine-generated", but the generator was
 * never committed — so refreshing a brand's artwork or adding a site meant
 * hand-editing 67 KB of SVG paths, and nobody could reproduce the existing
 * table. This is that generator.
 *
 * Only the `GLYPHS` table is rewritten. The hand-curated host map (`HOST_SLUG`)
 * is knowledge that simple-icons does not carry — `gist.github.com` and
 * `console.cloud.google.com` are choices, not lookups — so it is preserved
 * byte-for-byte, as are the resolver functions below it.
 *
 * A brand that the pinned simple-icons version no longer ships (the header
 * mentions v11 legacy glyphs for removed brands) is kept as-is and reported, so
 * the file stays a superset instead of silently losing a mark.
 *
 *   npm i --no-save simple-icons@16        # not a dependency: 25 MB, dev-only
 *   node scripts/gen-site-icons.mjs        # refreshes src/client/site-icons.ts
 *   node scripts/gen-site-icons.mjs --check
 *
 * `--check` writes nothing and exits 1 if any glyph is out of date.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const TARGET = join(ROOT, 'src', 'client', 'site-icons.ts')

/** Where the pinned artwork set lives. `npm i --no-save simple-icons@16` puts it here. */
function simpleIconsRoot() {
  const candidate = process.argv[2] !== undefined && !process.argv[2].startsWith('--')
    ? resolve(process.argv[2])
    : join(ROOT, 'node_modules', 'simple-icons')
  if (!existsSync(join(candidate, 'data', 'simple-icons.json'))) {
    throw new Error(`no simple-icons at ${candidate}\n  install it first: npm i --no-save simple-icons@16`)
  }
  return candidate
}

/** The `d` attribute of an icon's SVG, or undefined when that slug is gone. */
function iconPath(root, slug) {
  const file = join(root, 'icons', `${slug}.svg`)
  if (!existsSync(file)) return undefined
  const match = readFileSync(file, 'utf8').match(/\sd="([^"]+)"/)
  return match?.[1]
}

const GLYPHS_OPEN = '\nconst GLYPHS: Record<string, SiteGlyphData> = {'

function main() {
  const check = process.argv.includes('--check')
  const root = simpleIconsRoot()
  const metadata = JSON.parse(readFileSync(join(root, 'data', 'simple-icons.json'), 'utf8'))
  const hexBySlug = new Map(metadata.map(entry => [entry.slug, entry.hex]))

  const source = readFileSync(TARGET, 'utf8')
  const start = source.indexOf(GLYPHS_OPEN)
  if (start < 0) throw new Error(`cannot find the GLYPHS table in ${TARGET}`)
  const bodyStart = start + GLYPHS_OPEN.length
  const bodyEnd = source.indexOf('\n}\n', bodyStart)
  if (bodyEnd < 0) throw new Error('cannot find the end of the GLYPHS table')
  const body = source.slice(bodyStart, bodyEnd)

  // Two quoting styles live in this file: the bulk uses single-quoted colours,
  // while a handful of hand-added brands (amazonaws, slack, …) used double
  // quotes. Accept both and normalise to the single-quoted form, which is what
  // "machine-generated" has to mean if it is to stay true.
  const entry = /^ {2}"([a-z0-9.-]+)": \{ p: "([^"]*)", c: (['"])(.*?)\3 \},$/
  const slugs = []
  for (const line of body.split('\n')) {
    if (line.trim().length === 0) continue
    const match = line.match(entry)
    if (match === null) {
      throw new Error(`unparsable line in the GLYPHS table — refusing to skip it silently:\n  ${line.slice(0, 120)}`)
    }
    slugs.push(match[1])
  }
  if (slugs.length === 0) throw new Error('the GLYPHS table parsed as empty')

  const legacy = []
  const refreshed = new Map()
  for (const slug of slugs) {
    const path = iconPath(root, slug)
    const hex = hexBySlug.get(slug)
    if (path === undefined || hex === undefined) {
      legacy.push(slug)
      continue
    }
    refreshed.set(slug, { path, hex: `#${hex}` })
  }

  const lines = body.split('\n').map(line => {
    const match = line.match(entry)
    if (match === null) return line
    const slug = match[1]
    const existing = { path: match[2], hex: match[4] }
    const next = refreshed.get(slug) ?? existing
    // Re-emit even the preserved legacy entries in the canonical form, so the
    // whole table really is this script's output rather than two generations of
    // hand edits that merely look alike.
    return `  "${slug}": { p: "${next.path}", c: '${next.hex}' },`
  })
  const nextBody = lines.join('\n')

  const unchanged = nextBody === body
  console.log(`${slugs.length} 个品牌:simple-icons 命中 ${refreshed.size},保留旧数据 ${legacy.length}`)
  if (legacy.length > 0) console.log(`  保留(该版本已不再提供,多为已下架品牌):${legacy.join(', ')}`)

  if (unchanged) {
    console.log('ok  与 simple-icons 完全一致,无需改动')
    return
  }

  // Show what would change, so a refresh is reviewable rather than opaque.
  let changed = 0
  for (const [slug, next] of refreshed) {
    const current = new RegExp(`^ {2}"${slug}": \\{ p: "([^"]*)", c: (['"])(.*?)\\2 \\},$`, 'm').exec(body)
    if (current === null) { changed += 1; continue }
    const currentHex = current[3]
    if (current[1] !== next.path || currentHex !== next.hex) {
      changed += 1
      const color = currentHex === next.hex ? '' : ` (颜色 ${currentHex} → ${next.hex})`
      const path = current[1] === next.path ? '' : ' (图形有更新)'
      console.log(`  ~ ${slug}${color}${path}`)
    }
  }
  console.log(`${changed} 个品牌的数据与 simple-icons 不同`)

  if (check) {
    console.log('--check:文件已过期,请运行 node scripts/gen-site-icons.mjs')
    process.exit(1)
  }
  writeFileSync(TARGET, source.slice(0, bodyStart) + nextBody + source.slice(bodyEnd))
  console.log(`已更新 ${TARGET}`)
}

main()
