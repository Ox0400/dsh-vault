/**
 * `playwright-core` (13 MB) is needed only by browser login sessions, and it is
 * loaded lazily, so it must not be a hard runtime dependency: everyone else
 * would pay the download. It is declared as an optional peer and kept as a dev
 * dependency for this repository's own browser tests.
 *
 * Two things have to stay true, and the second is the one that would hurt:
 *   1. the manifest keeps it out of `dependencies` (checked here);
 *   2. the plugin still works when it is genuinely absent — a clear, actionable
 *      error instead of a crash at import time (also checked here, by making
 *      module resolution fail for that one name).
 */
import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import Module from 'node:module'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  peerDependenciesMeta?: Record<string, { optional?: boolean }>
  devDependencies?: Record<string, string>
}

test('playwright-core is an optional peer, not a runtime dependency', () => {
  // A hard dependency here is what made every install 13 MB heavier.
  expect(pkg.dependencies ?? {}).toEqual({})
  expect(pkg.peerDependencies?.['playwright-core']).toBeDefined()
  expect(pkg.peerDependenciesMeta?.['playwright-core']?.optional).toBe(true)
  // …while this repository's own browser suites still need it installed.
  expect(pkg.devDependencies?.['playwright-core']).toBeDefined()
})

test('every declared peer has metadata or is a hard requirement', () => {
  // An optional peer that is not declared in peerDependencies is ignored by npm,
  // which would silently turn it back into a package nobody can find.
  for (const name of Object.keys(pkg.peerDependenciesMeta ?? {})) {
    expect(Object.keys(pkg.peerDependencies ?? {})).toContain(name)
  }
})

test('the plugin degrades cleanly with playwright-core absent', async () => {
  const load = (Module as unknown as { _resolveFilename: (...args: unknown[]) => string })._resolveFilename
  ;(Module as unknown as { _resolveFilename: unknown })._resolveFilename = function (
    this: unknown, request: string, ...rest: unknown[]
  ) {
    if (request === 'playwright-core') {
      const error = new Error("Cannot find module 'playwright-core'") as NodeJS.ErrnoException
      error.code = 'MODULE_NOT_FOUND'
      throw error
    }
    return load.apply(this, [request, ...rest])
  }
  try {
    // Imported after the patch, so nothing cached a successful load.
    const session = await import('../src/session.ts')
    expect(session.playwrightAvailable()).toBe(false)
    // Importing the module at all must have worked — the failure is a runtime
    // message, not a crash that would take the whole plugin down.
    await expect(session.openSession('https://example.com')).rejects.toThrow(/playwright-core is not installed/)
    // …and the message says where to install it, since it is not automatic.
    await expect(session.openSession('https://example.com')).rejects.toThrow(/npm i playwright-core/)
  } finally {
    ;(Module as unknown as { _resolveFilename: unknown })._resolveFilename = load
  }
})
