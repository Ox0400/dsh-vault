/**
 * Wire-consistency guard between the browser client invokes and the host
 * VaultGateway @Remote method signatures.
 *
 * In SRC (source-signature) mode the harness gateway names each argument by
 * the JavaScript parameter name: the client must send exactly those keys.
 * Sending extra keys (e.g. spreading an options object that the method
 * receives as a single `options` parameter) throws `arguments-invalid`; the
 * previous client sent `{ ...options }` for `generatePassword`/`keychainImport`/
 * `sessionSave` while the gateway declared a single `options` parameter, so
 * every UI call to those three failed.
 *
 * This test parses both sides and asserts every client invoke sends exactly
 * the gateway's parameter names (allowing a trailing omitted optional when
 * the client omits it — the src-json codec accepts missing optionals).
 */

import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const CLIENT = readFileSync(join(__dirname, '..', 'src', 'client', 'index.ts'), 'utf8')
const GATEWAY = readFileSync(join(__dirname, '..', 'src', 'index.ts'), 'utf8')

/** Split on top-level commas (ignoring nested `<>(){}[]`). */
function splitTopLevel(input: string): string[] {
  const parts: string[] = []
  let depth = 0
  let current = ''
  for (const ch of input) {
    if (ch === '<' || ch === '(' || ch === '{' || ch === '[') depth++
    else if (ch === '>' || ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1)
    if (ch === ',' && depth === 0) { parts.push(current); current = '' }
    else current += ch
  }
  if (current.trim().length > 0) parts.push(current)
  return parts
}

/** Gateway: `@Remote('x')` + next `async name(params)` → parameter identifier list. */
function gatewayParams(): Map<string, string[]> {
  const out = new Map<string, string[]>()
  const re = /@Remote\('([^']+)'\)\s*\n\s*async\s+\w+\(([^)]*)\)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(GATEWAY)) !== null) {
    const ids: string[] = []
    for (const part of splitTopLevel(m[2]!)) {
      const p = part.trim()
      if (p.length === 0) continue
      const id = /^([$A-Z_a-z][$\w]*)\s*\??\s*:/.exec(p)
      ids.push(id !== null ? id[1]! : p)
    }
    out.set(m[1]!, ids)
  }
  return out
}

/** Client: `name: (...) => invoke<...>('method', { ... })` → the object keys. */
function clientArgs(): Map<string, string[][]> {
  const out = new Map<string, string[][]>()
  const re = /(\w+):\s*\(([^)]*)\)\s*=>\s*invoke[^>]*>\('([^']+)',\s*\{(.*?)\}\s*\)/gs
  let m: RegExpExecArray | null
  while ((m = re.exec(CLIENT)) !== null) {
    const method = m[3]!
    const body = m[4]!
    const keys: string[] = []
    const spreads: string[] = []
    for (const part of splitTopLevel(body)) {
      const p = part.trim()
      if (p.length === 0) continue
      if (p.startsWith('...')) {
        spreads.push(p)
        continue
      }
      const colon = p.indexOf(':')
      if (colon > 0) {
        const k = p.slice(0, colon).trim()
        if (/^[$A-Z_a-z][$\w]*$/.test(k)) keys.push(k)
      } else if (/^[$A-Z_a-z][$\w]*$/.test(p)) {
        keys.push(p)
      }
    }
    const list = out.get(method) ?? []
    list.push(keys)
    out.set(method, list)
    // Record which methods use object spreads (survives for the strict check).
    if (spreads.length > 0) out.set(`spread:${method}`, [[...spreads]])
  }
  return out
}

test('every client invoke sends exactly the gateway parameter names', () => {
  const gw = gatewayParams()
  const cl = clientArgs()
  const violations: string[] = []
  for (const [method, gwIds] of gw) {
    const clientCalls = cl.get(method)
    if (clientCalls === undefined) continue // model-only remote; no client invoke
    for (const keys of clientCalls) {
      const extra = keys.filter(k => !gwIds.includes(k))
      if (extra.length > 0) {
        violations.push(`${method}: client sends unexpected ${JSON.stringify(extra)}; gateway expects ${JSON.stringify(gwIds)}`)
      }
    }
  }
  expect(violations).toEqual([])
})

test('single-object gateway params (options/patch/…) are sent as that key, not spread', () => {
  const gw = gatewayParams()
  const cl = clientArgs()
  const violations: string[] = []
  for (const [method, gwIds] of gw) {
    if (gwIds.length !== 1) continue
    const param = gwIds[0]!
    const keys = cl.get(method)?.[0]
    if (keys === undefined) continue
    const hasLiteralKey = keys.includes(param)
    const spread = cl.get(`spread:${method}`)?.[0]?.[0]
    if (spread === undefined) continue
    // A conditional spread that names the parameter inside its object literal
    // (`...(x !== undefined ? { maxBackups } : {})`) is fine; a bare spread of
    // the caller's whole object (`...(options ?? {})`) is not — the parameter
    // would arrive as extra keys and the gateway rejects it.
    const objectLiteralKeys = [...spread.matchAll(/\{\s*([$A-Z_a-z][$\w]*)/g)].map(mm => mm[1]!)
    const spreadNamesParam = objectLiteralKeys.includes(param)
    if (!hasLiteralKey && !spreadNamesParam) {
      violations.push(`${method}: client spreads an object but gateway expects a single ${param} parameter`)
    }
  }
  expect(violations).toEqual([])
})
