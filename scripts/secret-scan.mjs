/**
 * Guard against publishing a credential.
 *
 * Everything this project publishes — the npm tarball, GitHub releases, issue
 * and discussion comments — must be free of secrets. Two synthetic values in
 * the `vault_mask` test are the only allowed pattern matches: they exist to be
 * redacted, and they are not real credentials.
 *
 * Run it directly for a full check, including anything already posted publicly:
 *
 *   node scripts/secret-scan.mjs            # working tree + tracked files + git log
 *   node scripts/secret-scan.mjs --public   # also scan GitHub releases/comments
 *
 * `tests/secret-scan.spec.ts` runs the local half inside `pnpm test`, so a
 * secret cannot be committed unnoticed.
 */
import { readFileSync, statSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'

/** Credential shapes that must never appear in published content. */
export const SECRET_PATTERNS = [
  { name: 'github fine-grained PAT', pattern: /github_pat_[A-Za-z0-9_]{20,}/g },
  { name: 'github classic token', pattern: /gh[porsu]_[A-Za-z0-9]{20,}/g },
  { name: 'npm token', pattern: /npm_[A-Za-z0-9]{20,}/g },
  { name: 'OpenAI-style key', pattern: /sk-[A-Za-z0-9]{20,}/g },
  { name: 'AWS access key id', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { name: 'Slack token', pattern: /xox[abpsr]-[A-Za-z0-9-]{10,}/g },
]

/**
 * Synthetic values that tests use on purpose. Matching them exactly keeps the
 * guard honest: a *changed* fixture fails, so a real token can never hide here.
 */
export const ALLOWED_FIXTURES = [
  'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
  'npm_123456789012345678901234567890',
]

/** Scan one blob of text; `where` only labels the finding. */
export function scanText(text, where) {
  const findings = []
  for (const { name, pattern } of SECRET_PATTERNS) {
    for (const match of text.matchAll(new RegExp(pattern.source, pattern.flags))) {
      const value = match[0]
      if (ALLOWED_FIXTURES.includes(value)) continue
      // Tests store a bare PEM marker around a placeholder body ("abc"); a real
      // key carries a long base64 payload, which is what we flag.
      if (name === 'private key block' && !hasRealKeyBody(text, match.index ?? 0, value.length)) continue
      // Never echo the value: a masked prefix is enough to locate it.
      findings.push({ where, pattern: name, sample: `${value.slice(0, 6)}…(${value.length} chars)` })
    }
  }
  return findings
}

/** Whether a PEM marker is followed by something that looks like key material. */
function hasRealKeyBody(text, at, markerLength) {
  const body = text.slice(at + markerLength, at + markerLength + 800)
  return /[A-Za-z0-9+/]{40,}/.test(body)
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'coverage', 'dist', '.vite', '.vite-temp', 'tmp'])
const TEXT_EXT = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.json', '.md', '.yml', '.yaml', '.css', '.html', '.sh', '.txt'])
const MAX_BYTES = 4_000_000

function isTextFile(name) {
  const dot = name.lastIndexOf('.')
  if (dot < 0) return name === 'LICENSE'
  return TEXT_EXT.has(name.slice(dot))
}

/** Walk a directory and scan every text file (`lib/` is build output). */
export async function scanDirectory(root, options = {}) {
  const findings = []
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        if (entry.name === 'lib' && options.includeLib !== true) continue
        await walk(full)
        continue
      }
      if (!entry.isFile() || !isTextFile(entry.name)) continue
      if (statSync(full).size > MAX_BYTES) continue
      findings.push(...scanText(await readFile(full, 'utf8'), relative(root, full)))
    }
  }
  await walk(root)
  return findings
}

/** Tracked files only, so ignored build output cannot hide anything either. */
export function scanTrackedFiles(cwd) {
  let files = []
  try {
    files = execFileSync('git', ['ls-files'], { cwd, encoding: 'utf8' }).split('\n').filter(Boolean)
  } catch {
    return []
  }
  const findings = []
  for (const file of files) {
    if (!isTextFile(file) && !file.endsWith('package.json')) continue
    try {
      const full = join(cwd, file)
      if (statSync(full).size > MAX_BYTES) continue
      findings.push(...scanText(readFileSync(full, 'utf8'), file))
    } catch { /* unreadable entry: skip */ }
  }
  return findings
}

/** Commit messages are published with the repository and read by everyone. */
export function scanCommitMessages(cwd) {
  try {
    return scanText(execFileSync('git', ['log', '--format=%H%n%s%n%b'], { cwd, encoding: 'utf8' }), 'git log')
  } catch {
    return []
  }
}

/** Local scan: the working tree, the tracked set, and every commit message. */
export async function scanLocal(root) {
  return [
    ...await scanDirectory(root, { includeLib: true }),
    ...scanTrackedFiles(root),
    ...scanCommitMessages(root),
  ]
}

/** Everything already posted to GitHub (releases, issue comments, discussions). */
export async function fetchPublicText({ repo, discussion, token }) {
  const items = []
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'dsh-vault-secret-scan' }
  const get = async (url) => (await fetch(url, { headers })).json()
  const releases = await get(`https://api.github.com/repos/${repo}/releases?per_page=30`)
  for (const r of releases) items.push({ label: `release ${r.tag_name}`, body: r.body ?? '' })
  const issues = await get(`https://api.github.com/repos/${repo}/issues?state=all&per_page=30`)
  for (const issue of issues) {
    const comments = await get(`https://api.github.com/repos/${repo}/issues/${issue.number}/comments?per_page=50`)
    for (const c of comments) items.push({ label: `issue #${issue.number}`, body: c.body ?? '' })
  }
  if (discussion !== undefined) {
    const { owner, name, number } = discussion
    const query = `query{repository(owner:"${owner}",name:"${name}"){discussion(number:${number}){comments(first:80){nodes{body}}}}}`
    const res = await fetch('https://api.github.com/graphql', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
    })
    const json = await res.json()
    for (const c of json.data?.repository?.discussion?.comments?.nodes ?? []) {
      items.push({ label: `discussion #${number}`, body: c.body ?? '' })
    }
  }
  return items
}

function report(findings, what) {
  if (findings.length === 0) {
    console.log(`ok  ${what}: no credential-shaped strings`)
    return 0
  }
  console.error(`FAIL  ${what}: ${findings.length} finding(s)`)
  for (const f of findings) console.error(`  ${f.where} → ${f.pattern} (${f.sample})`)
  return 1
}

async function main() {
  const root = process.cwd()
  let failures = report(await scanLocal(root), 'local (working tree + tracked files + git log)')

  if (process.argv.includes('--public')) {
    const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN
    if (token === undefined) {
      console.error('--public needs GH_TOKEN (read-only access is enough)')
      failures += 1
    } else {
      const items = await fetchPublicText({
        repo: 'Ox0400/dsh-vault',
        discussion: { owner: 'deepseek-ai', name: 'deepseek-harness', number: 1457 },
        token,
      })
      failures += report(items.flatMap(item => scanText(item.body, item.label)), `public GitHub content (${items.length} items)`)
    }
  }
  process.exitCode = failures === 0 ? 0 : 1
}

if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  await main()
}
