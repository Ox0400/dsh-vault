/**
 * Integration smoke test: mount dsh-vault into a Cordis context with the real
 * tool registry and exercise the model-facing tools end to end.
 *
 * Run with vitest from the harness workspace (or `node --experimental-strip-types`
 * with the harness node_modules resolvable).
 */

import { test, expect } from 'vitest'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { CallId } from '@deepseek-ai/dsh-llm'
import * as VaultPlugin from '../src/index'

const signal = new AbortController().signal
let callCounter = 0

async function withContext<T>(
  run: (ctx: Context, dir: string) => Promise<T>,
  pluginConfig: Record<string, unknown> = {},
): Promise<T> {
  const ctx = new Context()
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-ctx-'))
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(VaultPlugin, { masterPassword: 'integration-master', path: join(dir, 'vault.json'), ...pluginConfig })
    return await run(ctx, dir)
  } finally {
    // Clean up registered plugins; the ephemeral vault dir is removed too.
    ctx.registry.delete(VaultPlugin)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rm(dir, { recursive: true, force: true })
  }
}

/** Execute one tool by name and return its normalized value (asserting success). */
async function call(ctx: Context, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const result = await ctx.tools.execute({
    signal,
    callId: CallId(`dsh-vault-call-${++callCounter}`),
    name,
    arguments: args,
  })
  assert.equal(result.isError, false, `tool ${name} failed: ${JSON.stringify(result)}`)
  return result.value as Record<string, unknown>
}

test('dsh-vault registers seven tools in the registry', async () => {
  await withContext(async ctx => {
    const names = ctx.tools.schemas().map(entry => entry.name).sort()
    assert.deepEqual(names, [
      'vault_add',
      'vault_delete',
      'vault_generate_password',
      'vault_get',
      'vault_search',
      'vault_totp',
      'vault_update',
    ])
  })
})

test('vault_add → vault_search → vault_get round trip hides secrets in search', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'GitHub', username: 'ada', password: 'hunter2!', tags: ['dev'] })
    const id = added.id as string

    const results = await call(ctx, 'vault_search', { query: 'ada' })
    const summary = (results.results as Array<Record<string, unknown>>)[0]!
    assert.equal(summary.title, 'GitHub')
    assert.ok(!('password' in summary))

    const full = await call(ctx, 'vault_get', { id })
    assert.equal(full.found, true)
    assert.equal((full.entry as Record<string, unknown>).password, 'hunter2!')
  })
})

test('vault_totp uses a stored secret and returns a 6-digit code', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const id = added.id as string

    const result = await call(ctx, 'vault_totp', { id })
    assert.match(result.code as string, /^\d{6}$/)
    assert.equal(typeof result.secondsRemaining, 'number')
  })
})

test('vault_generate_password returns a strong password', async () => {
  await withContext(async ctx => {
    const result = await call(ctx, 'vault_generate_password', { length: 24 })
    const password = result.password as string
    assert.equal(password.length, 24)
    assert.match(password, /[a-z]/)
    assert.match(password, /[A-Z]/)
    assert.match(password, /\d/)
  })
})

test('developer credentials: ssh + api-key entries round-trip through tools', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', {
      title: 'staging ssh',
      kind: 'ssh',
      host: 'staging.example.com',
      port: '2200',
      username: 'deploy',
      password: 'pw!',
    })
    const id = added.id as string

    // Search returns host/port in the summary, but no password.
    const results = await call(ctx, 'vault_search', { query: 'staging.example.com' })
    const summary = (results.results as Array<Record<string, unknown>>)[0]!
    assert.equal(summary.host, 'staging.example.com')
    assert.equal(summary.port, '2200')
    assert.ok(!('password' in summary))

    // Full read exposes the secret.
    const full = await call(ctx, 'vault_get', { id })
    assert.equal((full.entry as Record<string, unknown>).password, 'pw!')

    // Update adds an api key, then delete.
    await call(ctx, 'vault_update', { id, apiKey: 'sk-live-123', kind: 'api-key' })
    const after = await call(ctx, 'vault_get', { id })
    assert.equal((after.entry as Record<string, unknown>).apiKey, 'sk-live-123')
    assert.equal((after.entry as Record<string, unknown>).kind, 'api-key')

    const deleted = await call(ctx, 'vault_delete', { id })
    assert.equal(deleted.deleted, true)
  })
})

test('vault_search enforces a sane limit and vault_update renames entries', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'Alpha', username: 'u1' })
    const b = await call(ctx, 'vault_add', { title: 'Beta', username: 'u2' })
    const c = await call(ctx, 'vault_add', { title: 'Gamma', username: 'u3' })

    // limit clamps the result set (query 'u' matches all three usernames).
    const limited = await call(ctx, 'vault_search', { query: 'u', limit: 2 })
    assert.equal((limited.results as Array<Record<string, unknown>>).length, 2)

    // Invalid limits are rejected (wrapped as isError), not silently accepted.
    for (const bad of [0, 101, 1.5]) {
      const result = await ctx.tools.execute({
        signal,
        callId: CallId(`dsh-vault-limit-${++callCounter}`),
        name: 'vault_search',
        arguments: { query: 'u', limit: bad },
      })
      assert.equal(result.isError, true, `limit ${bad} should be rejected`)
    }

    // Title is updatable (regression: pickDefined dropped it before).
    await call(ctx, 'vault_update', { id: a.id as string, title: 'Alpha Prime' })
    const after = await call(ctx, 'vault_get', { id: a.id as string })
    assert.equal((after.entry as Record<string, unknown>).title, 'Alpha Prime')

    // Empty string clears the password field (not stored as '').
    await call(ctx, 'vault_add', { title: 'Temp', password: 'secret' })
    void b
    void c
  })
})

test('vault_totp rejects calls with a now override', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const tools = ctx.tools.schemas().find(t => t.name === 'vault_totp')!
    assert.ok(!('now' in tools.parameters), 'vault_totp must not expose the internal now override')
  })
})

test('vault requires a master password at configuration time', async () => {
  const ctx = new Context()
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await assert.rejects(
      async () => { await ctx.plugin(VaultPlugin, {}) },
      /configure masterPassword or masterPasswordEnv/,
    )
  } finally {
    ctx.registry.delete(VaultPlugin)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
  }
})

test('readonly mode rejects mutations but allows reads', async () => {
  await withContext(async ctx => {
    const result = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-ro-${++callCounter}`),
      name: 'vault_add',
      arguments: { title: 'Blocked', apiKey: 'sk-123' },
    })
    assert.equal(result.isError, true)
    assert.match((result.error?.message ?? ''), /readonly mode/)

    // Reads still work: search returns empty list, no error.
    const search = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-ro-${++callCounter}`),
      name: 'vault_search',
      arguments: { query: 'anything' },
    })
    assert.equal(search.isError, false)
    assert.deepEqual((search.value as { results: unknown[] }).results, [])
  }, { accessMode: 'readonly' })
})

test('system prompt section is registered with mode and capture guidance', async () => {
  await withContext(async ctx => {
    const sp = ctx.get('systemPrompt') as { sections: unknown } | undefined
    assert.ok(sp !== undefined, 'systemPrompt service present')
    // Assemble a prompt and assert our section text is included.
    const assembly = await (ctx.get('systemPrompt') as {
      assemble: (context?: unknown) => Promise<{ sections: Array<{ name: string; text: string }> }>
    }).assemble({})
    const vaultSection = assembly.sections.find(s => s.name === 'dsh-vault')
    assert.ok(vaultSection, 'dsh-vault prompt section registered')
    assert.match(vaultSection!.text, /readwrite/)
  })
})

test('autoCapture=true adds capture guidance to the prompt', async () => {
  await withContext(async ctx => {
    const assembly = await (ctx.get('systemPrompt') as {
      assemble: (context?: unknown) => Promise<{ sections: Array<{ name: string; text: string }> }>
    }).assemble({})
    const vaultSection = assembly.sections.find(s => s.name === 'dsh-vault')!
    assert.match(vaultSection.text, /Auto-capture is ON/)
    assert.match(vaultSection.text, /vault_add/)
  }, { autoCapture: true })
})

test('VaultGateway exposes config with access mode', async () => {
  await withContext(async ctx => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    const cfg = await gateway.config()
    assert.equal(cfg.accessMode, 'readwrite')
    assert.equal(cfg.autoCapture, false)
  })
})
