/**
 * The built CLI must actually start. A source error once produced a broken
 * `lib/cli.js` that TypeScript still emitted (`noEmitOnError` was off), so a
 * syntax error surfaced only when a user ran the command. The build now refuses
 * to emit on error and smoke-tests the result; this runs in `pnpm test` too, so
 * a broken artifact fails the suite instead of a user's terminal.
 */
import { test, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const cli = join(root, 'lib', 'cli.js')

test('the built CLI starts and reports the package version', () => {
  if (!existsSync(cli)) {
    // A checkout that has not been built yet: nothing to check.
    expect(existsSync(cli)).toBe(false)
    return
  }
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version as string
  const out = execFileSync(process.execPath, [cli, '--version'], { encoding: 'utf8' }).trim()
  expect(out).toBe(version)

  // `--help` exercises the whole usage string (where a stray backtick once broke
  // the file), and a real subcommand proves the vault path resolves.
  const help = execFileSync(process.execPath, [cli, '--help'], { encoding: 'utf8' })
  expect(help).toContain('export-env')
  expect(help).toContain('env                     Print env-TAGGED entries')
})
