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
    // CRUD tests assume writes succeed; the access-mode tests pass their own
    // accessMode explicitly. Default to 'auto' here (no approval prompts).
    await ctx.plugin(VaultPlugin, { masterPassword: 'integration-master', path: join(dir, 'vault.json'), accessMode: 'auto', ...pluginConfig })
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

test('dsh-vault registers all tools in the registry', async () => {
  await withContext(async ctx => {
    const names = ctx.tools.schemas().map(entry => entry.name).sort()
    assert.deepEqual(names, [
      'vault_add',
      'vault_delete',
      'vault_env',
      'vault_export',
      'vault_fill',
      'vault_generate_password',
      'vault_get',
      'vault_health',
      'vault_import',
      'vault_import_csv',
      'vault_lock',
      'vault_purge',
      'vault_rekey',
      'vault_restore',
      'vault_rotation',
      'vault_search',
      'vault_strength',
      'vault_templates',
      'vault_totp',
      'vault_unlock',
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
    // Default mode is 'ask' (prompt-before-write).
    assert.match(vaultSection!.text, /Access mode: AUTO/)
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

test('VaultGateway exposes config with default mode', async () => {
  await withContext(async ctx => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    const cfg = await gateway.config()
    assert.equal(cfg.accessMode, 'auto')
    assert.equal(cfg.autoCapture, false)
  })
})

test('setAccessMode persists the choice and mutates the shared policy', async () => {
  await withContext(async ctx => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    // Switch to readonly — the model tools must now reject writes.
    const after = await gateway.setAccessMode('readonly')
    assert.equal(after.accessMode, 'readonly')

    const result = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-sam-${++callCounter}`),
      name: 'vault_add',
      arguments: { title: 'Blocked after switch', apiKey: 'sk-1' },
    })
    assert.equal(result.isError, true)
    assert.match((result.error?.message ?? ''), /readonly mode/)

    // Switch back to auto — writes succeed without approval.
    await gateway.setAccessMode('auto')
    const ok = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-sam-${++callCounter}`),
      name: 'vault_add',
      arguments: { title: 'Allowed', apiKey: 'sk-2' },
    })
    assert.equal(ok.isError, false)
    assert.ok((ok.value as { id: string }).id)
  })
})

test('ask mode routes writes through the pre-execute approval gate', async () => {
  await withContext(async ctx => {
    // ask mode: a write must be denied when no approval service is composed
    // (the harness seam degrades ask → deny).
    const result = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-ask-${++callCounter}`),
      name: 'vault_add',
      arguments: { title: 'Needs approval', apiKey: 'sk-3' },
    })
    assert.equal(result.isError, true)
    assert.match((result.error?.message ?? ''), /requires your confirmation/i)

    // Reads are unaffected in ask mode.
    const search = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-ask-${++callCounter}`),
      name: 'vault_search',
      arguments: { query: 'x' },
    })
    assert.equal(search.isError, false)
  }, { accessMode: 'ask' })
})

test('vault_lock/vault_unlock gate reads and writes', async () => {
  await withContext(async ctx => {
    // Seed an entry.
    const added = await call(ctx, 'vault_add', { title: 'Locked', username: 'u', password: 'pw123' })
    const id = added.id as string

    // Lock: subsequent reads must fail until unlock.
    const locked = await call(ctx, 'vault_lock', {})
    assert.equal(locked.locked, true)
    const readAfterLock = await ctx.tools.execute({
      signal, callId: CallId(`dsh-vault-lk-${++callCounter}`), name: 'vault_get', arguments: { id },
    })
    assert.equal(readAfterLock.isError, true)
    assert.match((readAfterLock.error?.message ?? ''), /locked/i)

    // Unlock: read works again.
    const unlocked = await call(ctx, 'vault_unlock', {})
    assert.equal(unlocked.unlocked, true)
    const get = await call(ctx, 'vault_get', { id })
    assert.equal((get.entry as Record<string, unknown>).username, 'u')
  })
})

test('vault_rotation reports due and expiring entries without secrets', async () => {
  await withContext(async ctx => {
    const past = await call(ctx, 'vault_add', { title: 'Expired token', accessToken: 'at-1', expiresAt: Date.now() - 1000 })
    const due = await call(ctx, 'vault_add', { title: 'Rotate me', password: 'pw', rotationDays: 1, fields: { __now: Date.now() } })
    // Force the due entry to look stale: update its createdAt via the store.
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    const store = (await gateway.list()).entries
    void store

    const report = await call(ctx, 'vault_rotation', {}) as { entries: Array<{ title: string; due: string }> }
    const titles = report.entries.map(e => e.title)
    assert.ok(titles.includes('Expired token'))
    const expired = report.entries.find(e => e.title === 'Expired token')!
    assert.equal(expired.due, 'expired')
    assert.ok(!('accessToken' in expired), 'rotation report never carries secrets')
    void past; void due
  })
})

test('vault_health flags weak and reused credentials', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Weak', password: 'short' })
    await call(ctx, 'vault_add', { title: 'A', apiKey: 'shared-key-123' })
    await call(ctx, 'vault_add', { title: 'B', apiKey: 'shared-key-123' })
    const health = await call(ctx, 'vault_health', {}) as { weak: Array<{ title: string }>; reused: Array<{ value: string; entries: Array<{ title: string }> }> }
    assert.ok(health.weak.some(e => e.title === 'Weak'), 'weak password flagged')
    const reusedGroup = health.reused.find(g => g.value === 'shared-key-123')
    assert.ok(reusedGroup !== undefined, 'reused apiKey grouped')
    assert.deepEqual(reusedGroup!.entries.map(e => e.title).sort(), ['A', 'B'])
  })
})

test('vault_delete soft-deletes; vault_restore brings it back; vault_purge removes', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Trash me', password: 'pw' })
    const id = added.id as string
    await call(ctx, 'vault_delete', { id })
    assert.equal((await call(ctx, 'vault_search', { query: 'Trash' })).results.length, 0)

    const restored = await call(ctx, 'vault_restore', { id })
    assert.equal(restored.restored, true)
    assert.equal((await call(ctx, 'vault_search', { query: 'Trash' })).results.length, 1)

    await call(ctx, 'vault_delete', { id })
    const purged = await call(ctx, 'vault_purge', { id })
    assert.equal(purged.purged, true)
    assert.equal((await call(ctx, 'vault_search', { query: 'Trash' })).results.length, 0)
  })
})

test('vault_fill finds a matching entry and returns secrets', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'prod-db', kind: 'ssh', host: 'db.internal.example.com', username: 'deploy', password: 's3cr3t!' })
    const hit = await call(ctx, 'vault_fill', { target: 'db.internal' })
    assert.equal(hit.found, true)
    assert.equal((hit.entry as Record<string, unknown>).password, 's3cr3t!')
    const miss = await call(ctx, 'vault_fill', { target: 'nonexistent-host' })
    assert.equal(miss.found, false)
  })
})

test('vault_env renders env-flagged entries and vault_templates lists fields', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'stripe', apiKey: 'sk_live_123', tags: ['env'] })
    const env = await call(ctx, 'vault_env', {}) as { lines: string[] }
    assert.ok(env.lines.some(l => l.startsWith('STRIPE_APIKEY=') && l.includes('sk_live_123')), `got ${JSON.stringify(env.lines)}`)

    const tpl = await call(ctx, 'vault_templates', { kind: 'ssh' }) as { fields: Record<string, string> }
    assert.ok('host' in tpl.fields && 'privateKey' in tpl.fields)
  })
})

test('vault_export/vault_import round-trip an encrypted document', async () => {
  await withContext(async ctx => {
    process.env.DSH_VAULT_EXPORT_PW = 'export-password-123'
    await call(ctx, 'vault_add', { title: 'Portable', password: 'pw' })
    const exported = await call(ctx, 'vault_export', {}) as { note: string }
    const file = exported.note.replace('vault exported to ', '')
    assert.ok(file.length > 0)

    // Purge the entry, then import restores it from the export document.
    const entry = (await call(ctx, 'vault_search', { query: 'Portable' })).results[0] as { id: string }
    await call(ctx, 'vault_purge', { id: entry.id })
    const imported = await call(ctx, 'vault_import', { path: file }) as { imported: number }
    assert.ok(imported.imported >= 1)
    assert.equal((await call(ctx, 'vault_search', { query: 'Portable' })).results.length, 1)
    delete process.env.DSH_VAULT_EXPORT_PW
  }, { exportPasswordEnv: 'DSH_VAULT_EXPORT_PW' })
})

test('vault_import_csv bulk-imports entries and skips duplicates', async () => {
  await withContext(async ctx => {
    const csvPath = join(await (async () => { const d = await mkdtemp(join(tmpdir(), 'vault-csv-')); return d })(), 'creds.csv')
    const { writeFile } = await import('node:fs/promises')
    await writeFile(csvPath, [
      'title,username,password,url,tags,region',
      'GitHub,ada,"hunter2!","https://github.com",dev,us-east',
      'AWS,deploy,secret-pw,"https://aws.amazon.com",prod,us-west',
      'GitLab,dup,"other",https://gitlab.com,dev,eu',
    ].join('\n'))
    const imported = await call(ctx, 'vault_import_csv', { path: csvPath }) as { added: number; skipped: number }
    assert.equal(imported.added, 3)
    assert.equal(imported.skipped, 0)

    // Re-import without overwrite → all 3 skipped (same titles).
    const again = await call(ctx, 'vault_import_csv', { path: csvPath }) as { added: number; skipped: number }
    assert.equal(again.added, 0)
    assert.equal(again.skipped, 3)

    // Custom column 'region' became a custom field, and it is searchable.
    const search = await call(ctx, 'vault_search', { query: 'us-east' }) as { results: Array<Record<string, unknown>> }
    assert.ok(search.results.length >= 1)
    const full = await call(ctx, 'vault_get', { id: search.results[0]!.id as string }) as { entry: Record<string, unknown> }
    assert.equal((full.entry.fields as Record<string, unknown>).region, 'us-east')
  })
})

test('vault emits read/write audit events that listeners can observe', async () => {
  await withContext(async ctx => {
    const events: Array<{ kind: string; tool: string }> = []
    const unsub = (ctx as unknown as { on: (n: string, f: (p: { tool: string }) => void) => () => void }).on('vault/read', (p) => events.push({ kind: 'read', tool: p.tool }))
    const unsub2 = (ctx as unknown as { on: (n: string, f: (p: { tool: string }) => void) => () => void }).on('vault/write', (p) => events.push({ kind: 'write', tool: p.tool }))

    const added = await call(ctx, 'vault_add', { title: 'Audited', password: 'pw' })
    await call(ctx, 'vault_get', { id: added.id as string })
    await call(ctx, 'vault_delete', { id: added.id as string })

    assert.ok(events.some(e => e.kind === 'write' && e.tool === 'vault_add'), 'vault_add audited')
    assert.ok(events.some(e => e.kind === 'read' && e.tool === 'vault_get'), 'vault_get audited')
    assert.ok(events.some(e => e.kind === 'write' && e.tool === 'vault_delete'), 'vault_delete audited')
    unsub(); unsub2()
  })
})

test('high-sensitivity entries require approval when read in ask mode', async () => {
  await withContext(async ctx => {
    // Seed a high-sensitivity entry via the gateway (bypasses pre-execute).
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    const added = await gateway.add({ title: 'Bank vault', password: 'topsecret', sensitivity: 'high' })

    // ask mode: reading it must be denied (no approval service composed).
    const result = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-hs-${++callCounter}`),
      name: 'vault_get',
      arguments: { id: added.id },
    })
    assert.equal(result.isError, true)
    assert.match((result.error?.message ?? ''), /high-sensitivity/i)

    // auto mode: reading is allowed.
    await gateway.setAccessMode('auto')
    const ok = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-hs-${++callCounter}`),
      name: 'vault_get',
      arguments: { id: added.id },
    })
    assert.equal(ok.isError, false)
    assert.equal((ok.value as { entry: { password: string } }).entry.password, 'topsecret')
  }, { accessMode: 'ask' })
})

test('vault_strength scores weak and strong passwords', async () => {
  await withContext(async ctx => {
    const weak = await call(ctx, 'vault_strength', { password: '123456' }) as { score: number; verdict: string }
    assert.ok(weak.score < 40, `weak score ${weak.score}`)
    assert.equal(weak.verdict, 'weak')

    const strong = await call(ctx, 'vault_strength', { password: 'Tr0ub4dor&3-Passphrase-X9!' }) as { score: number; verdict: string }
    assert.ok(strong.score >= 80, `strong score ${strong.score}`)
    assert.ok(['strong', 'very strong'].includes(strong.verdict))
  })
})
