/**
 * `$DSH_HOME` resolution. This mirrors `@deepseek-ai/dsh-home-paths`, but lives
 * in the plugin so the `dsh-vault` CLI can run from a plain npm install where
 * no harness package exists — the behaviour must stay identical.
 */
import { test, expect } from 'vitest'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { defaultDshHome, dshHomePath, expandHomePath, resolveDshHome } from '../src/home-paths.ts'

test('$DSH_HOME wins, otherwise ~/.dsh is used', () => {
  expect(resolveDshHome(undefined, {})).toBe(resolve(join(homedir(), '.dsh')))
  expect(resolveDshHome(undefined, { DSH_HOME: '/tmp/custom' })).toBe(resolve('/tmp/custom'))
  // blank or whitespace-only values fall through to the default
  expect(resolveDshHome(undefined, { DSH_HOME: '' })).toBe(defaultDshHome())
  expect(resolveDshHome(undefined, { DSH_HOME: '   ' })).toBe(defaultDshHome())
  // an explicit argument beats the environment
  expect(resolveDshHome('/explicit', { DSH_HOME: '/tmp/custom' })).toBe(resolve('/explicit'))
})

test('a leading ~ is expanded and relative paths resolve against cwd', () => {
  expect(expandHomePath('~')).toBe(homedir())
  expect(expandHomePath('~/vault')).toBe(join(homedir(), 'vault'))
  expect(expandHomePath('/absolute/path')).toBe('/absolute/path')
  expect(resolveDshHome('~/harness-home', {})).toBe(join(homedir(), 'harness-home'))
  expect(resolveDshHome('relative-home', {})).toBe(resolve('relative-home'))
})

test('dshHomePath joins under the resolved home', () => {
  expect(dshHomePath('vault', 'default.json')).toBe(join(resolve(join(homedir(), '.dsh')), 'vault', 'default.json'))
})
