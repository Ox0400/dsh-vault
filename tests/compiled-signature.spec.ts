/**
 * Protocol-level guard on the COMPILED bundle (lib/index.js): Typert's SRC
 * gateway inspects the emitted JavaScript method signatures via
 * Function.prototype.toString, so `?:` optional markers are erased but
 * parameter defaults (`= 5`), rest and destructuring survive and break the
 * gateway registration ("must use unique identifier parameters…").
 *
 * This test re-implements Typert's methodParameterNames against the compiled
 * VaultGateway and asserts every method's parameters are pure identifiers.
 * It runs only when lib/index.js exists (build output present); CI without a
 * build skips it, while the source-level gateway-signature test still guards.
 */

import { test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const LIB = join(__dirname, '..', 'lib', 'index.js')
const available = existsSync(LIB)

test.skipIf(!available)('compiled VaultGateway methods satisfy the SRC pure-identifier rule', async () => {
  const src = readFileSync(LIB, 'utf8')
  const ID = /^[$A-Z_a-z][$\w]*$/u
  const violations: string[] = []
  // Find `@Remote('x')` markers and the following method's parameter list in
  // the compiled JS (class methods: `async backups(limit = 5) {` etc.).
  const re = /(?:@Remote|__decorateClass|\.decorators)\s*\([^)]*\)|async\s+(\w+)\s*\(([^)]*)\)\s*\{/g
  // Simpler: locate every method signature line that Typert would parse.
  const methodRe = /async\s+(\w+)\s*\(([^)]*)\)\s*\{/g
  let m: RegExpExecArray | null
  while ((m = methodRe.exec(src)) !== null) {
    const name = m[1]!
    const params = m[2]!
    if (params.trim().length === 0) continue
    for (const raw of params.split(',')) {
      const part = raw.trim()
      if (part.length === 0) continue
      if (!ID.test(part)) violations.push(`${name}: ${JSON.stringify(part)}`)
    }
  }
  expect(violations).toEqual([])
})
