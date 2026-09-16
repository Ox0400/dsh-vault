// The master-password prompt must NOT echo what you type. The first version
// opened /dev/tty but left echo on, so the password appeared in clear text.
// This drives the real CLI through a pseudo-terminal (`script`) and fails if the
// typed password shows up in the output.
//
//   node tests/e2e/cli-prompt.mjs      (requires npm run build:host first)
import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const repo = dirname(dirname(dirname(fileURLToPath(import.meta.url))))
const CLI = join(repo, 'lib', 'cli.js')
const PASSWORD = 'pty-secret-987'
const home = await mkdtemp(join(tmpdir(), 'cli-prompt-home-'))

const R = []
const check = (n, ok, x = '') => { R.push({ n, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x ? '  — ' + x : ''}`) }

process.env.DSH_HOME = home
const { openVault } = await import(pathToFileURL(join(repo, 'lib', 'store.js')).href)
const store = await openVault({ path: join(home, 'vault', 'default.json'), masterPassword: PASSWORD })
await store.add({ title: 'PTY', kind: 'api-key', apiKey: 'sk-pty', tags: ['env'] })
await store.lock()

/** Run the CLI with a pseudo-terminal, typing the password after the prompt. */
function runInPty(args, { delayMs = 1200 } = {}) {
  return new Promise(resolve => {
    // macOS: script -q /dev/null <cmd>;  Linux: script -q -c "<cmd>" /dev/null
    // The input pipeline is built by the shell on purpose: a Node `spawn` pipe is
    // a socket on macOS, which `script` refuses (tcgetattr on a socket).
    const isMac = process.platform === 'darwin'
    const inner = [process.execPath, CLI, ...args].map(a => (a.includes(' ') ? `"${a}"` : a)).join(' ')
    const pipeline = `(sleep ${(delayMs / 1000).toFixed(1)}; printf '%s\\n' "$DSH_PTY_PW") | `
      + (isMac ? `script -q /dev/null ${inner}` : `script -q -c "${inner}" /dev/null`)
    const child = spawn('/bin/sh', ['-c', pipeline], { env: { ...process.env, DSH_HOME: home, DSH_PTY_PW: PASSWORD } })
    let out = ''
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { out += d })
    child.on('close', code => resolve({ code, out }))
  })
}

try {
  if (process.platform !== 'darwin' && process.platform !== 'linux') {
    console.log('SKIP  pty check needs `script` (darwin/linux)')
  } else {
    const { code, out } = await runInPty(['list'])
    check('the prompt succeeds in a terminal', code === 0 && out.includes('PTY'), `exit ${code}`)
    check('the typed password is NOT echoed', !out.includes(PASSWORD), out.split('\n').slice(0, 3).join(' | ').slice(0, 120))
    check('the prompt itself is shown', out.includes('Vault master password:'))

    // A non-interactive path must keep working for scripts.
    const viaStdin = await new Promise(resolve => {
      const child = spawn(process.execPath, [CLI, 'list', '--password-stdin'], { env: { ...process.env, DSH_HOME: home } })
      let stdout = ''
      child.stdout.on('data', d => { stdout += d })
      child.stdin.write(`${PASSWORD}\n`)
      child.stdin.end()
      child.on('close', c => resolve({ code: c, out: stdout }))
    })
    check('--password-stdin still works without a terminal', viaStdin.code === 0 && viaStdin.out.includes('PTY'), `exit ${viaStdin.code}`)
  }
} finally {
  await rm(home, { recursive: true, force: true })
}

console.log(`\n${R.filter(r => r.ok).length}/${R.length} checks passed`)
process.exit(R.some(r => !r.ok) ? 1 : 0)
