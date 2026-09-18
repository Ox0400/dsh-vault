/**
 * Every version published to npm must also have a GitHub release.
 *
 * This exists because it once did not: 1.10.73 went to npm while the GitHub
 * release stayed at 1.10.72, and nothing complained. The check is deliberately
 * loud in both places a release happens — run it before tagging
 * (`pnpm release:check`) and it also runs automatically as `postpublish`, so a
 * forgotten release turns the `npm publish` command itself red.
 *
 *   node scripts/release-check.mjs            # audit every published version
 *   node scripts/release-check.mjs --version  # only the version in package.json
 *
 * It reads npm and the public GitHub API, so it needs no token and no secrets.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const PACKAGE_NAME = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).name

/**
 * Which published versions have no release.
 *
 * Pure so the rule can be tested without a network: `versions` are published
 * npm versions, `tags` are the tags that exist on the remote, and `releases`
 * are the tag names that carry a GitHub release.
 */
export function findGaps({ versions, tags, releases }) {
  const releaseSet = new Set(releases)
  const tagSet = new Set(tags)
  const versionSet = new Set(versions)
  return {
    // Published and tagged, but nobody reading GitHub can see what changed.
    missingReleases: versions.filter(v => tagSet.has(`v${v}`) && !releaseSet.has(`v${v}`)),
    // A tag is public but that version was never published to npm.
    untagged: versions.filter(v => !tagSet.has(`v${v}`)),
    // A release points at a version that is not on npm.
    orphanReleases: releases.filter(t => !versionSet.has(t.replace(/^v/, ''))),
  }
}

/**
 * Narrow a full audit to one version, for `postpublish`.
 *
 * The gap lists must be computed against *all* published versions — scoping the
 * input instead would make every other release look like an orphan — so the
 * narrowing happens afterwards, on the report.
 */
export function narrowToVersion({ missingReleases }, version) {
  return {
    missingReleases: missingReleases.filter(v => v === version),
    untagged: [],
    orphanReleases: [],
  }
}

/**
 * Which gaps actually fail the check.
 *
 * The invariant that matters is one-directional: if a version is on npm, a
 * reader of the repository must be able to see what changed in it. The reverse
 * direction is history, not a defect — this project has older GitHub
 * prereleases (1.9.3-rc.1…13) that were never published, and no action now can
 * change that, so they are a note unless `--strict` asks for them too.
 */
export function fatalProblems({ missingReleases, orphanReleases }, { strict = false } = {}) {
  const fatal = missingReleases.map(v => `v${v} 已在 npm 发布,但没有 GitHub release`)
  if (strict) fatal.push(...orphanReleases.map(t => `${t} 有 release,但 npm 上没有这个版本`))
  return fatal
}

async function getJson(url) {
  const headers = { 'User-Agent': 'dsh-vault-release-check' }
  if (process.env.GH_TOKEN) headers.Authorization = `Bearer ${process.env.GH_TOKEN}`
  const res = await fetch(url, { headers })
  if (!res.ok) throw new Error(`${res.status} ${url}`)
  return res.json()
}

function originSlug() {
  const url = execFileSync('git', ['remote', 'get-url', 'origin'], { cwd: ROOT, encoding: 'utf8' }).trim()
  const match = url.match(/github\.com[:/]([^/]+\/[^/.]+?)(?:\.git)?$/)
  if (!match) throw new Error(`unsupported origin: ${url}`)
  return match[1]
}

async function collect() {
  const slug = originSlug()
  const registry = await getJson(`https://registry.npmjs.org/${PACKAGE_NAME}`)
  const versions = Object.keys(registry.versions ?? {})
  const tags = execFileSync('git', ['ls-remote', '--tags', 'origin'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n')
    .map(line => line.split('refs/tags/')[1]?.replace(/\^\{\}$/, ''))
    .filter(Boolean)
  const releases = []
  for (let page = 1; ; page += 1) {
    const batch = await getJson(`https://api.github.com/repos/${slug}/releases?per_page=100&page=${page}`)
    if (batch.length === 0) break
    for (const release of batch) releases.push(release.tag_name)
  }
  return { slug, versions, tags, releases }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const only = process.argv.includes('--version')
  const strict = process.argv.includes('--strict')
  const current = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version
  const { slug, versions, tags, releases } = await collect()
  // Always audit against every published version; `--version` only narrows what
  // is reported, so the other 261 releases are not mistaken for orphans.
  const gaps = only
    ? narrowToVersion(findGaps({ versions, tags, releases }), current)
    : findGaps({ versions, tags, releases })
  const fatal = fatalProblems(gaps, { strict })

  console.log(`release check — ${slug}: npm ${versions.length} 个版本 / tag ${tags.length} 个 / release ${releases.length} 个`)

  if (only && !versions.includes(current)) {
    console.log(`  note  npm 上还没有 ${current}(注册表尚未同步?);无法核对 release`)
  }
  if (gaps.untagged.length > 0) {
    console.log(`  note  ${gaps.untagged.length} 个 npm 版本没有对应 tag:${gaps.untagged.join(', ')}`)
  }
  if (gaps.orphanReleases.length > 0) {
    const shown = gaps.orphanReleases.slice(0, 4).join(', ')
    const more = gaps.orphanReleases.length > 4 ? ` 等 ${gaps.orphanReleases.length} 个` : ''
    console.log(`  note  ${gaps.orphanReleases.length} 个 release 对应的版本不在 npm 上(历史遗留,加 --strict 视为失败):${shown}${more}`)
  }
  for (const item of fatal) console.log(`  ✗ ${item}`)

  if (fatal.length === 0) {
    console.log(only ? `  ok  ${current}:npm 与 GitHub release 齐全` : '  ok  每个已发布版本都有对应的 GitHub release')
  } else {
    console.log(`\n${fatal.length} 处不一致。补建 release 后再继续:`)
    console.log('  GitHub 网页端新建 release,或调用 POST /repos/<owner>/<repo>/releases(tag_name 用已存在的 tag)')
    process.exit(1)
  }
}
