/**
 * `dsh-vault` CLI. Driven through `runCli(argv, io)` with injected IO so the
 * command surface (parsing, output, exit codes) is tested without spawning a
 * process; `tests/e2e/cli.mjs` covers the built bin as a child process.
 */
import { test, expect } from 'vitest'
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openVault } from '../src/store.ts'
import { runCli, resolveCliVaultPath, type CliIo } from '../src/cli.ts'
import { totp } from '../src/totp.ts'

const PASSWORD = 'cli-test-pw'

interface Capture { code: number; out: string; err: string }

async function withVault(
  run: (io: (overrides?: Partial<CliIo>) => CliIo & { result: () => Capture }, dir: string, vaultPath: string) => Promise<void>,
): Promise<void> {
  const home = await mkdtemp(join(tmpdir(), 'cli-home-'))
  const vaultPath = join(home, 'vault', 'default.json')
  const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
  await store.add({ title: 'DASHSCOPE', kind: 'api-key', apiKey: 'sk-dash-secret', tags: ['env'], username: 'ada' })
  await store.add({
    title: 'Tavily', kind: 'oauth', envKey: 'TAVILY_TOKEN', accessToken: 'at-123', refreshToken: 'rt-456',
    fields: { scope: 'read write' }, tags: ['env'],
  })
  await store.add({ title: 'Plain', kind: 'login', password: 'pw-not-exported', username: 'bob' })
  await store.lock()

  const chunks: string[] = []
  let errText = ''
  // A fresh capture per invocation keeps assertions simple.
  const io = (overrides: Partial<CliIo> = {}): CliIo & { result: () => Capture } => ({
    out: text => chunks.push(text),
    err: text => { errText += text },
    env: { DSH_HOME: home, DSH_VAULT_MASTER_PASSWORD: PASSWORD },
    ...overrides,
    result: () => ({ code: -1, out: chunks.splice(0).join(''), err: (() => { const e = errText; errText = ''; return e })() }),
  })
  try {
    await run(io, home, vaultPath)
  } finally {
    await rm(home, { recursive: true, force: true })
  }
}

/** Run and return everything the command produced. */
async function invoke(argv: string[], overrides: Partial<CliIo> = {}, home?: string): Promise<Capture> {
  let out = ''
  let err = ''
  const code = await runCli(argv, {
    out: text => { out += text },
    err: text => { err += text },
    env: { ...(home !== undefined ? { DSH_HOME: home } : {}), DSH_VAULT_MASTER_PASSWORD: PASSWORD },
    ...overrides,
  })
  return { code, out, err }
}

test('list prints entries without any secret, with the env name to copy', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['list', '--path', vaultPath])
    expect(r.code).toBe(0)
    expect(r.out).toContain('DASHSCOPE')
    expect(r.out).not.toContain('sk-dash-secret')
    // the login entry is listed with its identity, still without secrets
    expect(r.out).toContain('bob')
    expect(r.out).not.toContain('pw-not-exported')
    // grouped by what `env` actually exports, so "potential name" can never be
    // mistaken for "already exported"
    expect(r.out).toContain('Exported by `env` (tag "env") — 2 entries:')
    expect(r.out).toContain('Not exported (no "env" tag) — 1 entry')
    expect(r.out).toMatch(/DASHSCOPE.*→ DASHSCOPE_API_KEY/)
    expect(r.out).toContain('TAVILY_TOKEN (+2)')
    // the untagged entry still shows the name `get` accepts
    const plainRow = r.out.split('\n').find(line => line.includes('Plain'))!
    expect(plainRow).toContain('→ PLAIN_PASSWORD')
  })
})

test('list --json is machine readable and flags secrets', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['list', '--json', '--path', vaultPath])
    const parsed = JSON.parse(r.out) as Array<Record<string, unknown>>
    expect(parsed).toHaveLength(3)
    expect(parsed.every(e => e.hasSecret === true)).toBe(true)
    expect(JSON.stringify(parsed)).not.toContain('sk-dash-secret')
    expect(parsed[1]!.envKeys).toEqual(['TAVILY_TOKEN', 'TAVILY_TOKEN_REFRESH_TOKEN', 'TAVILY_TOKEN_SCOPE'])
    // one name for "what this entry exports", plus whether `env` includes it
    expect(parsed[0]!.envKeys).toEqual(['DASHSCOPE_API_KEY'])
    expect(parsed[0]!.envTagged).toBe(true)
    expect(parsed[1]!.envKeys).toEqual(['TAVILY_TOKEN', 'TAVILY_TOKEN_REFRESH_TOKEN', 'TAVILY_TOKEN_SCOPE'])
    expect(parsed[2]!.envTagged).toBe(false)
  })
})

test('get prints exactly one value, and --field / --mask / fields.<name> work', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    expect((await invoke(['get', 'DASHSCOPE', '--path', vaultPath])).out).toBe('sk-dash-secret\n')
    expect((await invoke(['get', 'Tavily', '--field', 'refreshToken', '--path', vaultPath])).out).toBe('rt-456\n')
    expect((await invoke(['get', 'Tavily', '--field', 'fields.scope', '--path', vaultPath])).out).toBe('read write\n')
    expect((await invoke(['get', 'DASHSCOPE', '--mask', '--path', vaultPath])).out).toBe('sk-d***\n')
    // --json wraps the same single value
    const json = JSON.parse((await invoke(['get', 'DASHSCOPE', '--json', '--path', vaultPath])).out) as Record<string, unknown>
    expect(json.field).toBe('apiKey')
    expect(json.value).toBe('sk-dash-secret')
  })
})

test('get resolves entries by env name, not just id or title', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    // Every name `env` emits must be retrievable, including derived ones.
    expect((await invoke(['get', 'DASHSCOPE_API_KEY', '--path', vaultPath])).out).toBe('sk-dash-secret\n')
    expect((await invoke(['get', 'TAVILY_TOKEN', '--path', vaultPath])).out).toBe('at-123\n')
    expect((await invoke(['get', 'TAVILY_TOKEN_REFRESH_TOKEN', '--path', vaultPath])).out).toBe('rt-456\n')
    expect((await invoke(['get', 'TAVILY_TOKEN_SCOPE', '--path', vaultPath])).out).toBe('read write\n')
    // An env-name lookup also honours --mask and --json.
    expect((await invoke(['get', 'DASHSCOPE_API_KEY', '--mask', '--path', vaultPath])).out).toBe('sk-d***\n')
    const json = JSON.parse((await invoke(['get', 'TAVILY_TOKEN_REFRESH_TOKEN', '--json', '--path', vaultPath])).out) as Record<string, unknown>
    expect(json.field).toBe('refreshToken')
    // Titles and ids still win over env names, and a miss says what was tried.
    expect((await invoke(['get', 'DASHSCOPE', '--path', vaultPath])).out).toBe('sk-dash-secret\n')
    const miss = await invoke(['get', 'NOPE_API_KEY', '--path', vaultPath])
    expect(miss.code).toBe(1)
    expect(miss.err).toMatch(/no entry, envKey or exported key matches/)
  })
})

test('env renders vendor-standard names and honours the env tag', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['env', '--path', vaultPath])
    const keys = r.out.trim().split('\n').map(l => l.split('=')[0])
    expect(keys).toContain('DASHSCOPE_API_KEY')
    expect(keys).toContain('TAVILY_TOKEN')
    expect(keys).toContain('TAVILY_TOKEN_REFRESH_TOKEN')
    expect(keys).toContain('TAVILY_TOKEN_SCOPE')
    expect(r.out).not.toContain('pw-not-exported')

    const keysOnly = await invoke(['env', '--keys-only', '--path', vaultPath])
    expect(keysOnly.out).not.toContain('sk-dash-secret')
    expect(keysOnly.out).toContain('DASHSCOPE_API_KEY')

    const masked = await invoke(['env', '--mask', '--path', vaultPath])
    expect(masked.out).toContain('sk-d***')
    expect(masked.out).not.toContain('sk-dash-secret')

    const prefixed = await invoke(['env', '--prefix', 'APP_', '--path', vaultPath])
    expect(prefixed.out).toContain('APP_DASHSCOPE_API_KEY=')
    // an explicit envKey is never rewritten by the prefix
    expect(prefixed.out).toContain('TAVILY_TOKEN=')
  })
})

test('env --mask shows both what is exported and what is not', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const masked = await invoke(['env', '--mask', '--path', vaultPath])
    expect(masked.code).toBe(0)
    expect(masked.out).toContain('## exported items')
    expect(masked.out).toContain('## unexported items')
    // the exported value is masked, and the untagged entry is listed with the
    // name `get` would accept — but never with a value
    expect(masked.out).toContain('DASHSCOPE_API_KEY=sk-d***')
    expect(masked.out).not.toContain('sk-dash-secret')
    // the untagged entry appears in the SAME KEY=VALUE shape, value hidden
    expect(masked.out).toContain('PLAIN_PASSWORD=***')
    expect(masked.out).not.toContain('pw-not-exported')
    // --explain uses real values for the exported section, but keeps the
    // unexported one hidden (the tag is what opts a value into a shell)
    const explained = await invoke(['env', '--explain', '--path', vaultPath])
    expect(explained.out).toContain('## exported items')
    expect(explained.out).toContain("DASHSCOPE_API_KEY='sk-dash-secret'")
    expect(explained.out).toContain('PLAIN_PASSWORD=***')
    expect(explained.out).not.toContain('pw-not-exported')
  })
})

test('plain env stays pure KEY=VALUE so eval and pipelines keep working', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['env', '--path', vaultPath])
    expect(r.out).not.toContain('##')
    expect(r.out.split('\n').filter(Boolean).every(line => /^[A-Za-z_][A-Za-z0-9_]*=/.test(line))).toBe(true)
  })
})

test('export-env writes a 0600 file', async () => {
  await withVault(async (_io, dir, vaultPath) => {
    const target = join(dir, 'nested', 'out.env')
    const r = await invoke(['export-env', target, '--path', vaultPath])
    expect(r.code).toBe(0)
    expect((await stat(target)).mode & 0o777).toBe(0o600)
    expect(await readFile(target, 'utf8')).toContain("DASHSCOPE_API_KEY='sk-dash-secret'")
    expect(r.out).toBe('') // progress goes to stderr so stdout stays pipeable
  })
})

test('verify, show and --password-stdin behave', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const verify = await invoke(['verify', '--path', vaultPath])
    expect(verify.code).toBe(0)
    expect(verify.out).toBe('')

    const show = JSON.parse((await invoke(['show', 'Tavily', '--path', vaultPath])).out) as Record<string, unknown>
    expect(show.envKeys).toEqual(['TAVILY_TOKEN', 'TAVILY_TOKEN_REFRESH_TOKEN', 'TAVILY_TOKEN_SCOPE'])
    expect(show.hasSecret).toBe(true)
    expect(JSON.stringify(show)).not.toContain('at-123')

    const stdin = await invoke(['list', '--password-stdin', '--path', vaultPath], {
      env: {},
      readStdinLine: async () => `${PASSWORD}\n`,
    })
    expect(stdin.code).toBe(0)
    expect(stdin.out).toContain('DASHSCOPE')
  })
})

test('failures explain themselves and use distinct exit codes', async () => {
  await withVault(async (_io, dir, vaultPath) => {
    // wrong password → 1, and a readable message rather than an AEAD error
    const wrong = await invoke(['list', '--path', vaultPath], { env: { DSH_VAULT_MASTER_PASSWORD: 'nope' } })
    expect(wrong.code).toBe(1)
    expect(wrong.out).toBe('')
    expect(wrong.err).toMatch(/master password is incorrect/)

    // no password source → 1 with the supported ways to supply one
    const none = await invoke(['list', '--path', vaultPath], { env: {} })
    expect(none.code).toBe(1)
    expect(none.err).toMatch(/DSH_VAULT_MASTER_PASSWORD/)

    // missing vault → 1
    const missing = await invoke(['list', '--path', join(dir, 'nope.json')])
    expect(missing.code).toBe(1)
    expect(missing.err).toMatch(/not found/)

    // unknown command / missing argument → 2 (usage errors)
    expect((await invoke(['frobnicate', '--path', vaultPath])).code).toBe(2)
    expect((await invoke(['get', '--path', vaultPath])).code).toBe(2)
    expect((await invoke(['export-env', '--path', vaultPath])).code).toBe(2)

    // unknown entry → 1
    const noEntry = await invoke(['get', 'nothing-like-this', '--path', vaultPath])
    expect(noEntry.code).toBe(1)
    expect(noEntry.err).toMatch(/no entry, envKey or exported key matches/)
  })
})

test('an ambiguous title lists the candidates instead of guessing', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({ title: 'DASHSCOPE', username: 'second' })
    await store.lock()
    const r = await invoke(['get', 'DASHSCOPE', '--path', vaultPath])
    expect(r.code).toBe(1)
    expect(r.err).toMatch(/ambiguous/)
    expect(r.out).toBe('')
  })
})

test('--help exits 0 and --version prints the package version', async () => {
  const help = await invoke(['--help'], { env: {} })
  expect(help.code).toBe(0)
  expect(help.out).toMatch(/export-env/)
  const version = await invoke(['--version'], { env: {} })
  expect(version.out).toMatch(/^\d+\.\d+\.\d+/)
  const noCommand = await invoke([], { env: {} })
  expect(noCommand.code).toBe(2)
})

test('resolveCliVaultPath prefers --path and honours $DSH_HOME for named vaults', () => {
  const parse = (argv: string[]): { command: string; positional: string[]; flags: Map<string, string | boolean> } => {
    const flags = new Map<string, string | boolean>()
    const positional: string[] = []
    let command = ''
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i]!
      if (!arg.startsWith('--')) { if (command === '') command = arg; else positional.push(arg); continue }
      const name = arg.slice(2)
      flags.set(name, true)
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith('--')) { flags.set(name, next); i++ }
    }
    return { command, positional, flags }
  }
  expect(resolveCliVaultPath(parse(['list', '--path', '/tmp/x.json']), {})).toBe('/tmp/x.json')
  const named = resolveCliVaultPath(parse(['list', '--vault', 'work']), { DSH_HOME: '/tmp/home' })
  expect(named.endsWith(join('vault', 'work.json'))).toBe(true)
  expect(named.startsWith('/tmp/home')).toBe(true)
  const fallback = resolveCliVaultPath(parse(['list']), { DSH_HOME: '/tmp/home' })
  expect(fallback.endsWith(join('vault', 'default.json'))).toBe(true)
})

/** RFC 6238 test secret (ASCII "12345678901234567890") — a published vector. */
const TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

test('totp prints the code alone on stdout', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({ title: 'TwoFactor', kind: 'login', otpSecret: TOTP_SECRET })
    await store.lock()
    const r = await invoke(['totp', 'TwoFactor', '--path', vaultPath])
    expect(r.code).toBe(0)
    // Digits only, so `code=$(dsh-vault totp …)` is the whole interface.
    expect(r.out).toMatch(/^\d{6}\n$/)
    // Allow the wall clock to move across a 30-second boundary while running.
    const now = Date.now()
    expect([totp(TOTP_SECRET, now - 1000), totp(TOTP_SECRET, now), totp(TOTP_SECRET, now + 1000)]).toContain(r.out.trim())
    expect(r.err).toBe('')
  })
})

test('totp --json reports digits, period and secondsRemaining', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({ title: 'TwoFactor', kind: 'login', otpSecret: TOTP_SECRET })
    await store.lock()
    const r = await invoke(['totp', 'TwoFactor', '--json', '--path', vaultPath])
    expect(r.code).toBe(0)
    const parsed = JSON.parse(r.out) as { code: string; digits: number; period: number; secondsRemaining: number; title: string }
    expect(parsed.title).toBe('TwoFactor')
    expect(parsed.code).toMatch(/^\d{6}$/)
    expect(parsed.digits).toBe(6)
    expect(parsed.period).toBe(30)
    // What a script needs to avoid racing an expiring code.
    expect(parsed.secondsRemaining).toBeGreaterThanOrEqual(1)
    expect(parsed.secondsRemaining).toBeLessThanOrEqual(30)
  })
})

test('an otpauth URI decides its own digits and period', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({
      title: 'Uri2FA', kind: 'login',
      otpSecret: `otpauth://totp/GitHub:ada?secret=${TOTP_SECRET}&issuer=GitHub&digits=8&period=60`,
    })
    await store.lock()
    const r = await invoke(['totp', 'Uri2FA', '--json', '--path', vaultPath])
    expect(r.code).toBe(0)
    const parsed = JSON.parse(r.out) as { code: string; digits: number; period: number; secondsRemaining: number }
    expect(parsed.digits).toBe(8)
    expect(parsed.period).toBe(60)
    expect(parsed.code).toMatch(/^\d{8}$/)
    expect(parsed.secondsRemaining).toBeLessThanOrEqual(60)
  })
})

test('totp explains an entry that has no TOTP secret', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['totp', 'Plain', '--path', vaultPath])
    expect(r.code).toBe(1)
    expect(r.out).toBe('')
    expect(r.err).toMatch(/no TOTP secret/)
    // Point at where the secret goes instead of leaving the user to guess.
    expect(r.err).toMatch(/otpSecret/)
  })
})

test('totp without an entry name and with an unknown option exits 2', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const missing = await invoke(['totp', '--path', vaultPath])
    expect(missing.code).toBe(2)
    const badFlag = await invoke(['totp', 'Plain', '--mask', '--path', vaultPath])
    expect(badFlag.code).toBe(2)
    expect(badFlag.err).toMatch(/unknown option/)
    // The accepted set is printed, so the fix is in the message itself.
    expect(badFlag.err).toMatch(/--totp|--json/)
  })
})

test('list --json and show report hasTotp without any secret', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({ title: 'TwoFactor', kind: 'login', otpSecret: TOTP_SECRET })
    await store.lock()
    const listed = JSON.parse((await invoke(['list', '--json', '--path', vaultPath])).out) as
      { title: string; hasTotp: boolean }[]
    expect(listed.find(e => e.title === 'TwoFactor')?.hasTotp).toBe(true)
    expect(listed.find(e => e.title === 'Plain')?.hasTotp).toBe(false)
    const shown = await invoke(['show', 'TwoFactor', '--path', vaultPath])
    expect(JSON.parse(shown.out).hasTotp).toBe(true)
    // Presence is reported; the secret itself never is.
    expect(shown.out).not.toContain(TOTP_SECRET)
  })
})

// ── flags that were documented but never exercised ──────────────────────────

test('list --kind and --tag actually filter', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const byKind = await invoke(['list', '--kind', 'oauth', '--path', vaultPath])
    expect(byKind.code).toBe(0)
    expect(byKind.out).toContain('Tavily')
    expect(byKind.out).not.toContain('Plain')

    const byTag = await invoke(['list', '--tag', 'env', '--path', vaultPath])
    expect(byTag.out).toContain('DASHSCOPE')
    expect(byTag.out).toContain('Tavily')
    expect(byTag.out).not.toContain('Plain')

    const noMatch = await invoke(['list', '--tag', 'nope', '--path', vaultPath])
    expect(noMatch.code).toBe(0)
    expect(noMatch.out).not.toContain('DASHSCOPE')
  })
})

test('get --all is the opt-in full dump, plain get is one value', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const one = await invoke(['get', 'Tavily', '--path', vaultPath])
    expect(one.out).toBe('at-123\n')
    const all = await invoke(['get', 'Tavily', '--all', '--path', vaultPath])
    const parsed = JSON.parse(all.out) as { accessToken: string; refreshToken: string; fields: Record<string, string> }
    expect(parsed.accessToken).toBe('at-123')
    expect(parsed.refreshToken).toBe('rt-456')
    expect(parsed.fields.scope).toBe('read write')
  })
})

test('env --file writes 0600, creates the directory and keeps stdout clean', async () => {
  await withVault(async (_io, dir, vaultPath) => {
    const file = join(dir, 'nested', 'out.env')
    const r = await invoke(['env', '--file', file, '--path', vaultPath])
    expect(r.code).toBe(0)
    // stdout stays a clean stream so the same command can be piped elsewhere.
    expect(r.out).toBe('')
    expect(r.err).toMatch(/mode 0600/)
    expect((await stat(file)).mode & 0o777).toBe(0o600)
    const body = await readFile(file, 'utf8')
    expect(body).toContain("DASHSCOPE_API_KEY='sk-dash-secret'")
  })
})

// ── regressions found by audit ──────────────────────────────────────────────

test('an empty entry name is refused instead of matching everything', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['get', '', '--path', vaultPath])
    expect(r.code).toBe(1)
    expect(r.out).toBe('')
    expect(r.err).toMatch(/empty name/)
  })
})

test('a string option without a value is a usage error, not a silent default', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['get', 'Tavily', '--field', '--path', vaultPath])
    expect(r.code).toBe(2)
    // The dangerous old behaviour: printing the primary secret instead.
    expect(r.out).toBe('')
    expect(r.err).toMatch(/--field needs a value/)
    const vaultFlag = await invoke(['list', '--vault', '--path', vaultPath])
    expect(vaultFlag.code).toBe(2)
    expect(vaultFlag.err).toMatch(/--vault needs a value/)
  })
})

test('a non-string field reports its value instead of "no field"', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const store = await openVault({ path: vaultPath, masterPassword: PASSWORD })
    await store.add({ title: 'Meta', kind: 'login', password: 'pw', tags: ['a', 'b'], favorite: true })
    await store.lock()
    const tags = await invoke(['get', 'Meta', '--field', 'tags', '--path', vaultPath])
    expect(tags.code).toBe(0)
    expect(tags.out.trim()).toBe('["a","b"]')
    const favorite = await invoke(['get', 'Meta', '--field', 'favorite', '--path', vaultPath])
    expect(favorite.out.trim()).toBe('true')
    // A field that genuinely is absent still says so.
    const absent = await invoke(['get', 'Meta', '--field', 'nope', '--path', vaultPath])
    expect(absent.code).toBe(1)
    expect(absent.err).toMatch(/has no field/)
  })
})

test('a corrupt vault file is reported with its path, not a raw TypeError', async () => {
  await withVault(async (_io, dir) => {
    const cases: Array<[string, RegExp]> = [
      ['null', /is not a vault file/],
      ['not json at all', /is not valid JSON/],
      ['{"version":"1"}', /unsupported vault format version/],
      ['{}', /unsupported vault format version/],
    ]
    for (const [content, expected] of cases) {
      const bad = join(dir, `bad-${content.length}.json`)
      await writeFile(bad, content)
      const r = await invoke(['list', '--path', bad])
      expect(r.code).toBe(1)
      expect(r.out).toBe('')
      expect(r.err).toMatch(expected)
      // Naming the file is the whole point: --path can point anywhere.
      expect(r.err).toContain(bad)
    }
  })
})

test('--password-stdin with nothing on stdin fails fast instead of hanging', async () => {
  await withVault(async (_io, _dir, vaultPath) => {
    const r = await invoke(['list', '--password-stdin', '--path', vaultPath], { readStdinLine: async () => '' })
    expect(r.code).toBe(1)
    expect(r.err).toMatch(/no password on stdin/)
  })
})
