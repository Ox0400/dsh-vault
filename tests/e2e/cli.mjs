// Requires lib/ to be built first (npm run build:host).
// Build a throwaway vault, then drive the REAL built CLI (lib/cli.js) as a child process.
import { spawn } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { mkdtemp, rm, stat, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dirname, join as joinPath } from 'node:path'

const repo = dirname(dirname(dirname(fileURLToPath(import.meta.url))))
const { openVault } = await import(joinPath(repo, 'lib', 'store.js'))

const home = await mkdtemp(join(tmpdir(), 'cli-home-'))
process.env.DSH_HOME = home
const vaultPath = join(home, 'vault', 'default.json')
const store = await openVault({ path: vaultPath, masterPassword: 'cli-pw' })
await store.add({ title: 'DASHSCOPE', kind: 'api-key', apiKey: 'sk-dash-secret', tags: ['env'], username: 'ada' })
await store.add({ title: 'Tavily', kind: 'oauth', envKey: 'TAVILY_TOKEN', accessToken: 'at-123', refreshToken: 'rt-456', fields: { scope: 'read write' }, tags: ['env'] })
await store.add({ title: 'NoEnv', kind: 'login', password: 'pw-not-exported', username: 'bob' })
// RFC 6238 test secret (ASCII "12345678901234567890") — a published vector.
const TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
await store.add({ title: 'TwoFactor', kind: 'login', otpSecret: TOTP_SECRET, username: 'ada' })
await store.lock()

const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const CLI = joinPath(repo, 'lib', 'cli.js')
function run(args, { input, env = {}, timeoutMs } = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, DSH_HOME: home, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let out = '', err = '', timer
    if (timeoutMs !== undefined) {
      // A command that hangs must be reported as a hang, not left to block the
      // whole suite — that is exactly how the empty-stdin bug went unnoticed.
      timer = setTimeout(() => { child.kill('SIGKILL'); resolve({ code: 'TIMEOUT', out, err }) }, timeoutMs)
    }
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { err += d })
    child.on('close', code => { if (timer) clearTimeout(timer); resolve({ code, out, err }) })
    if (input !== undefined) { child.stdin.write(input); }
    child.stdin.end()
  })
}

const listPlain = await run(['list'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('list works without leaking secrets', listPlain.code === 0 && listPlain.out.includes('DASHSCOPE') && !listPlain.out.includes('sk-dash-secret'), `exit ${listPlain.code}`)

check('list groups by what env exports, showing each name', listPlain.out.includes('DASHSCOPE_API_KEY') && /Exported by `env` \(tag "env"\) — 2 entries:/.test(listPlain.out) && listPlain.out.includes('TAVILY_TOKEN (+2)'), listPlain.out.split('\n')[0])

const listJson = await run(['list', '--json'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const parsed = JSON.parse(listJson.out)
check('list --json is machine readable', Array.isArray(parsed) && parsed.length === 4 && parsed[0].hasSecret === true, JSON.stringify(parsed.map(e => e.title)))

const get = await run(['get', 'DASHSCOPE'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get prints only the primary secret', get.out === 'sk-dash-secret\n' && get.code === 0, JSON.stringify(get.out))

const getField = await run(['get', 'Tavily', '--field', 'refreshToken'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get --field picks another field', getField.out === 'rt-456\n', JSON.stringify(getField.out))

const getCustom = await run(['get', 'Tavily', '--field', 'fields.scope'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get --field reaches custom fields', getCustom.out === 'read write\n', JSON.stringify(getCustom.out))

const aliasField = await run(['get', 'DASHSCOPE_API_KEY', '--fields', 'apikey'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('--fields is an alias and field names are case-insensitive', aliasField.out === 'sk-dash-secret\n', JSON.stringify(aliasField.out))

const unknownFlag = await run(['get', 'DASHSCOPE', '--nope', 'x'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('an unknown option is refused, not ignored', unknownFlag.code === 2 && /unknown option/.test(unknownFlag.err), JSON.stringify(unknownFlag.err.split('\n')[0]))

const showJson = await run(['show', 'Tavily'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const shownKeys = JSON.parse(showJson.out)
check('show reports the exported names once', JSON.stringify(shownKeys.envKeys) === '["TAVILY_TOKEN","TAVILY_TOKEN_REFRESH_TOKEN","TAVILY_TOKEN_SCOPE"]' && shownKeys.envTagged === true, JSON.stringify(shownKeys.envKeys))

const masked = await run(['get', 'DASHSCOPE', '--mask'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get --mask hides the value', masked.out === 'sk-d***\n', JSON.stringify(masked.out))

const env = await run(['env'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const keys = env.out.trim().split('\n').map(l => l.split('=')[0])
check('env derives vendor-standard names', keys.includes('DASHSCOPE_API_KEY') && keys.includes('TAVILY_TOKEN') && keys.includes('TAVILY_TOKEN_REFRESH_TOKEN'), JSON.stringify(keys))
check('env skips entries without the env tag', !env.out.includes('pw-not-exported'))

const byEnvKey = await run(['get', 'DASHSCOPE_API_KEY'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get resolves a derived env name', byEnvKey.out === 'sk-dash-secret\n', JSON.stringify(byEnvKey.out))

const byEnvSuffix = await run(['get', 'TAVILY_TOKEN_REFRESH_TOKEN'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('get resolves <envKey>_<SUFFIX>', byEnvSuffix.out === 'rt-456\n', JSON.stringify(byEnvSuffix.out))

const envMaskedView = await run(['env', '--mask'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('env --mask uses one KEY=VALUE shape for both sections', envMaskedView.out.includes('## exported items') && envMaskedView.out.includes('## unexported items') && /NOENV_PASSWORD=\*\*\*/.test(envMaskedView.out), JSON.stringify(envMaskedView.out.split('\n').slice(0, 2)))

const envPlain = await run(['env'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('plain env has no section headers', !envPlain.out.includes('##'), JSON.stringify(envPlain.out.split('\n')[0]))

const keysOnly = await run(['env', '--keys-only'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('env --keys-only prints names only', !keysOnly.out.includes('sk-dash-secret') && keysOnly.out.includes('DASHSCOPE_API_KEY'))

const envMasked = await run(['env', '--mask'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('env --mask hides values', envMasked.out.includes('sk-d***') && !envMasked.out.includes('sk-dash-secret'))

const dotenvPath = join(home, 'out.env')
const exported = await run(['export-env', dotenvPath], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const mode = (await stat(dotenvPath)).mode & 0o777
const body = await readFile(dotenvPath, 'utf8')
check('export-env writes the file 0600', exported.code === 0 && mode === 0o600, `mode ${mode.toString(8)}`)
check('export-env content matches env', body.includes("DASHSCOPE_API_KEY='sk-dash-secret'"), body.split('\n')[0])

const stdin = await run(['list', '--password-stdin'], { input: 'cli-pw\n' })
check('--password-stdin authenticates', stdin.code === 0 && stdin.out.includes('DASHSCOPE'))

const wrong = await run(['list'], { env: { DSH_VAULT_MASTER_PASSWORD: 'nope' } })
check('a wrong password fails cleanly', wrong.code === 1 && wrong.out === '' && /incorrect|password/i.test(wrong.err), JSON.stringify(wrong.err.slice(0, 80)))

const noPw = await run(['list'], { env: { DSH_VAULT_MASTER_PASSWORD: '' } })
check('a missing password explains itself', noPw.code === 1 && /DSH_VAULT_MASTER_PASSWORD/.test(noPw.err), JSON.stringify(noPw.err.slice(0, 90)))

const missing = await run(['list', '--vault', 'nope'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('a missing vault points at --vault', missing.code === 1 && /not found/.test(missing.err))

const unknown = await run(['frobnicate'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('an unknown command exits 2', unknown.code === 2 && /unknown command/.test(unknown.err))

const help = await run(['--help'])
check('--help exits 0 and lists the commands', help.code === 0 && /export-env/.test(help.out) && /env +Print/.test(help.out), '')

// ── totp: an INDEPENDENT RFC 6238 implementation decides what is correct ─────
// Written here from the RFC rather than imported, so a bug in src/totp.ts cannot
// agree with itself. Checked against a published vector before it is trusted.
function referenceTotp(base32, nowMs = Date.now(), digits = 6, period = 30) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of base32.replace(/=+$/, '').toUpperCase()) {
    const v = alphabet.indexOf(ch)
    if (v < 0) throw new Error(`bad base32 character: ${ch}`)
    bits += v.toString(2).padStart(5, '0')
  }
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 1000 / period)))
  const hmac = createHmac('sha1', Buffer.from(bytes)).update(counter).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff)
  return (binary % 10 ** digits).toString().padStart(digits, '0')
}
check('the reference TOTP matches the RFC 6238 vector', referenceTotp(TOTP_SECRET, 59_000, 8) === '94287082', referenceTotp(TOTP_SECRET, 59_000, 8))

const totpPlain = await run(['totp', 'TwoFactor'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const nowMs = Date.now()
const expectedCodes = [nowMs - 1000, nowMs, nowMs + 1000].map(t => referenceTotp(TOTP_SECRET, t))
check('totp prints the code the RFC says, and nothing else', totpPlain.code === 0 && expectedCodes.includes(totpPlain.out.trim()) && /^\d{6}\n$/.test(totpPlain.out), JSON.stringify(totpPlain.out))

const totpJson = await run(['totp', 'TwoFactor', '--json'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const totpParsed = JSON.parse(totpJson.out)
check('totp --json reports the window a script must respect', totpParsed.code === totpPlain.out.trim() && totpParsed.digits === 6 && totpParsed.period === 30 && totpParsed.secondsRemaining >= 1 && totpParsed.secondsRemaining <= 30, JSON.stringify(totpParsed))

const totpMissing = await run(['totp', 'NoEnv'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('totp explains an entry without a TOTP secret', totpMissing.code === 1 && totpMissing.out === '' && /no TOTP secret/.test(totpMissing.err), JSON.stringify(totpMissing.err.split('\n')[0]))

const totpByEnvKey = await run(['totp', 'DASHSCOPE_API_KEY'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('totp resolves an entry the same way get does', totpByEnvKey.code === 1 && /no TOTP secret/.test(totpByEnvKey.err), JSON.stringify(totpByEnvKey.err.split('\n')[0]))

const totpFlag = await run(['totp', 'TwoFactor', '--mask'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('totp refuses an option it does not implement', totpFlag.code === 2 && /unknown option/.test(totpFlag.err), JSON.stringify(totpFlag.err.split('\n')[0]))

const showTwoFactor = JSON.parse((await run(['show', 'TwoFactor'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })).out)
check('show says an entry has TOTP without printing the secret', showTwoFactor.hasTotp === true && !JSON.stringify(showTwoFactor).includes(TOTP_SECRET), JSON.stringify(showTwoFactor))

const listHasTotp = JSON.parse((await run(['list', '--json'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })).out)
check('list --json flags exactly the entries totp accepts', listHasTotp.filter(e => e.hasTotp).map(e => e.title).join(',') === 'TwoFactor', JSON.stringify(listHasTotp.map(e => [e.title, e.hasTotp])))

// ── regressions found by audit ──────────────────────────────────────────────
// The empty-stdin hang only reproduces against the real readline, so it has to
// be exercised as a child process: nothing may block forever.
const emptyStdin = await run(['list', '--password-stdin'], { input: '', env: {}, timeoutMs: 10_000 })
check('--password-stdin with empty stdin exits instead of hanging', emptyStdin.code === 1 && /no password on stdin/.test(emptyStdin.err), JSON.stringify(emptyStdin.code))

const blankName = await run(['get', ''], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('an empty entry name is refused', blankName.code === 1 && blankName.out === '' && /empty name/.test(blankName.err), JSON.stringify(blankName.err.split('\n')[0]))

const valuelessFlag = await run(['get', 'DASHSCOPE', '--field'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('--field without a value is a usage error, not the primary secret', valuelessFlag.code === 2 && valuelessFlag.out === '' && /needs a value/.test(valuelessFlag.err), JSON.stringify(valuelessFlag.err.split('\n')[0]))

const nonStringField = await run(['get', 'DASHSCOPE', '--field', 'createdAt'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('a non-string field prints its value', nonStringField.code === 0 && /^\d+$/.test(nonStringField.out.trim()), JSON.stringify(nonStringField.out))

const corruptPath = join(home, 'corrupt.json')
await writeFile(corruptPath, 'not json at all')
const corrupt = await run(['list', '--path', corruptPath], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('a corrupt vault names the file it could not read', corrupt.code === 1 && corrupt.err.includes(corruptPath) && /not valid JSON/.test(corrupt.err), JSON.stringify(corrupt.err.split('\n')[0]))

const helpMentionsTotp = await run(['--help'])
check('--help documents totp', /totp <id\|title\|ENVKEY>/.test(helpMentionsTotp.out) && /totp options:/.test(helpMentionsTotp.out))

const show = await run(['show', 'Tavily'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const shown = JSON.parse(show.out)
check('show exposes metadata but no secrets', JSON.stringify(shown.envKeys) === '["TAVILY_TOKEN","TAVILY_TOKEN_REFRESH_TOKEN","TAVILY_TOKEN_SCOPE"]' && shown.hasSecret === true && !JSON.stringify(shown).includes('at-123'), JSON.stringify(shown))

await rm(home, { recursive: true, force: true })
console.log(`\n${R.filter(r => r.ok).length}/${R.length} checks passed`)
process.exit(R.some(r => !r.ok) ? 1 : 0)
