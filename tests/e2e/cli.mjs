// Requires lib/ to be built first (npm run build:host).
// Build a throwaway vault, then drive the REAL built CLI (lib/cli.js) as a child process.
import { spawn } from 'node:child_process'
import { mkdtemp, rm, stat, readFile } from 'node:fs/promises'
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
await store.lock()

const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }
const CLI = joinPath(repo, 'lib', 'cli.js')
function run(args, { input, env = {} } = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, DSH_HOME: home, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let out = '', err = ''
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { err += d })
    child.on('close', code => resolve({ code, out, err }))
    if (input !== undefined) { child.stdin.write(input); }
    child.stdin.end()
  })
}

const listPlain = await run(['list'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
check('list works without leaking secrets', listPlain.code === 0 && listPlain.out.includes('DASHSCOPE') && !listPlain.out.includes('sk-dash-secret'), `exit ${listPlain.code}`)

check('list shows the env name to copy', listPlain.out.includes('DASHSCOPE_API_KEY') && /\[env\]/.test(listPlain.out) && listPlain.out.includes('TAVILY_TOKEN (+2)'), listPlain.out.split('\n')[0])

const listJson = await run(['list', '--json'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const parsed = JSON.parse(listJson.out)
check('list --json is machine readable', Array.isArray(parsed) && parsed.length === 3 && parsed[0].hasSecret === true, JSON.stringify(parsed.map(e => e.title)))

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
check('show separates configured from exported names', JSON.stringify(shownKeys.envKeys) === '["TAVILY_TOKEN"]' && shownKeys.exportedKeys.length === 3, JSON.stringify({ envKeys: shownKeys.envKeys, exportedKeys: shownKeys.exportedKeys }))

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

const show = await run(['show', 'Tavily'], { env: { DSH_VAULT_MASTER_PASSWORD: 'cli-pw' } })
const shown = JSON.parse(show.out)
check('show exposes metadata but no secrets', JSON.stringify(shown.envKeys) === '["TAVILY_TOKEN"]' && shown.hasSecret === true && !JSON.stringify(shown).includes('at-123'), JSON.stringify(shown))

await rm(home, { recursive: true, force: true })
console.log(`\n${R.filter(r => r.ok).length}/${R.length} checks passed`)
process.exit(R.some(r => !r.ok) ? 1 : 0)
