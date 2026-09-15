// The CLI must work from a plain npm install: a package directory with NO
// node_modules at all (npx / global install put it exactly there). Regression for
// "Cannot find package '@deepseek-ai/dsh-atomic-write' imported from lib/store.js".
//
//   node tests/e2e/cli-standalone.mjs      (requires npm run build:host first)
import { spawn } from 'node:child_process'
import { cp, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const repo = dirname(dirname(dirname(fileURLToPath(import.meta.url))))
const home = await mkdtemp(join(tmpdir(), 'cli-standalone-home-'))
const pkg = await mkdtemp(join(tmpdir(), 'cli-standalone-pkg-'))

const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }

// 1. Stage exactly what npm publishes: lib/ + package.json, no node_modules.
await cp(join(repo, 'lib'), join(pkg, 'lib'), { recursive: true })
await cp(join(repo, 'package.json'), join(pkg, 'package.json'))
const CLI = join(pkg, 'lib', 'cli.js')

const run = (args, env = {}) => new Promise(resolve => {
  const child = spawn(process.execPath, [CLI, ...args], {
    cwd: pkg,
    // A bare environment: nothing from the harness, no NODE_PATH tricks.
    env: { PATH: process.env.PATH, HOME: process.env.HOME, DSH_HOME: home, DSH_VAULT_MASTER_PASSWORD: 'standalone-pw', ...env },
  })
  let out = '', err = ''
  child.stdout.on('data', d => { out += d })
  child.stderr.on('data', d => { err += d })
  child.on('close', code => resolve({ code, out: out.trimEnd(), err: err.trimEnd() }))
})

// 2. Seed a vault from the repository build (where the harness packages ARE
// installed — a write needs them), then read it with the standalone copy.
process.env.DSH_HOME = home
const { openVault } = await import(pathToFileURL(join(repo, 'lib', 'store.js')).href)
const store = await openVault({ path: join(home, 'vault', 'default.json'), masterPassword: 'standalone-pw' })
await store.add({ title: 'DASHSCOPE', kind: 'api-key', apiKey: 'sk-standalone', tags: ['env'] })
await store.lock()

const version = await run(['--version'])
check('starts with no node_modules present', version.code === 0 && /^\d+\.\d+\.\d+/.test(version.out), `${version.out || version.err}`.slice(0, 120))

const list = await run(['list'])
check('list works standalone', list.code === 0 && list.out.includes('DASHSCOPE_API_KEY') && !list.out.includes('sk-standalone'), list.out.split('\n')[0])

const get = await run(['get', 'DASHSCOPE_API_KEY'])
check('get works standalone', get.out === 'sk-standalone', JSON.stringify(get.out || get.err))

const env = await run(['env'])
check('env works standalone', env.code === 0 && env.out.includes("DASHSCOPE_API_KEY='sk-standalone'"), JSON.stringify(env.out))

// 3. Writing must fail with a clear message, not a module-resolution crash.
const write = await run(['export-env', join(home, 'out.env')])
check('export-env explains the missing runtime', write.code === 0 && write.err.includes('wrote'), `${write.err}`.slice(0, 120))

// A real write (adding an entry) is what needs the harness runtime; the CLI has
// no such command, so the only requirement is that reading never needs one.
const dsh = await run(['--help'])
check('--help works standalone', dsh.code === 0 && dsh.out.includes('export-env'))

await rm(home, { recursive: true, force: true })
await rm(pkg, { recursive: true, force: true })
console.log(`\n${R.filter(r => r.ok).length}/${R.length} checks passed`)
process.exit(R.some(r => !r.ok) ? 1 : 0)
