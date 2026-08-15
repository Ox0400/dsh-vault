/**
 * Regression guard for the Typert SRC constraint: remote-method parameters
 * must be pure identifiers once compiled. TypeScript optional markers (`?:`)
 * and type annotations compile away, but parameter DEFAULT VALUES (`= 5`),
 * rest (`...args`) and destructuring (`{ a, b }`) survive compilation and make
 * the SRC signature invalid — the harness gateway then rejects the whole
 * method with "must use unique identifier parameters without destructuring,
 * defaults, or rest". This test parses the @Remote method signatures in source
 * (with a depth-aware comma splitter for generic types like `Record<…>`) and
 * fails on any default value, rest, or destructured parameter.
 */

import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const SRC = readFileSync(join(__dirname, '..', 'src', 'index.ts'), 'utf8')

const remoteMethodRe = /@Remote\('([^']+)'\)\s*\n\s*async\s+\w+\(([^)]*)\)/g

/** Split a parameter list on top-level commas (ignoring those inside `<>`, `()`, `{}`, `[]`). */
function splitTopLevel(input: string): string[] {
  const parts: string[] = []
  let depth = 0
  let current = ''
  for (const ch of input) {
    if (ch === '<' || ch === '(' || ch === '{' || ch === '[') depth++
    else if (ch === '>' || ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1)
    if (ch === ',' && depth === 0) {
      parts.push(current)
      current = ''
    } else {
      current += ch
    }
  }
  if (current.trim().length > 0) parts.push(current)
  return parts
}

test('all @Remote method parameters are pure identifiers (no defaults/destructuring/rest)', () => {
  const violations: string[] = []
  let m: RegExpExecArray | null
  while ((m = remoteMethodRe.exec(SRC)) !== null) {
    const endpoint = m[1]!
    const params = m[2]!
    if (params.trim().length === 0) continue
    for (const rawPart of splitTopLevel(params)) {
      const part = rawPart.trim()
      if (part.length === 0) continue
      // Strip a trailing type annotation: `name: Type` or `name?: Type`.
      // After stripping, the remaining identifier must be a bare JS identifier.
      const stripped = part.replace(/\??\s*:.*$/s, '').trim()
      if (part.includes('=')) {
        // `name = default` keeps the default in the compiled JS — violation.
        violations.push(`${endpoint}: "${part}"`)
      } else if (stripped.startsWith('...')) {
        violations.push(`${endpoint}: "${part}" (rest)`)
      } else if (stripped.startsWith('{') || stripped.startsWith('[')) {
        violations.push(`${endpoint}: "${part}" (destructuring)`)
      } else if (!/^[$A-Z_a-z][$\w]*$/.test(stripped)) {
        violations.push(`${endpoint}: "${part}"`)
      }
    }
  }
  expect(violations).toEqual([])
})
