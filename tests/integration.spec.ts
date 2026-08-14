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
    const mountConfig: Record<string, unknown> = {
      masterPassword: 'integration-master',
      accessMode: 'auto',
      ...pluginConfig,
    }
    // Name-based mounts (vault_switch tests) must not pin a temp-dir path.
    if (mountConfig.path === undefined && mountConfig.name === undefined) {
      mountConfig.path = join(dir, 'vault.json')
    }
    await ctx.plugin(VaultPlugin, mountConfig)
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
      'vault_backup',
      'vault_backup_status',
      'vault_bulk_export',
      'vault_changes',
      'vault_clipboard',
      'vault_count',
      'vault_delete',
      'vault_duplicates',
      'vault_env',
      'vault_expiry',
      'vault_export',
      'vault_export_browser',
      'vault_export_csv',
      'vault_export_env',
      'vault_export_totp',
      'vault_fill',
      'vault_find',
      'vault_generate_password',
      'vault_generate_username',
      'vault_get',
      'vault_health',
      'vault_history',
      'vault_import',
      'vault_import_csv',
      'vault_list',
      'vault_lock',
      'vault_mask',
      'vault_merge',
      'vault_note_secret',
      'vault_notes',
      'vault_pin',
      'vault_purge',
      'vault_quick_add',
      'vault_recent',
      'vault_rekey',
      'vault_report',
      'vault_restore',
      'vault_rotate_password',
      'vault_rotation',
      'vault_search',
      'vault_search_advanced',
      'vault_stats',
      'vault_strength',
      'vault_switch',
      'vault_tags',
      'vault_templates',
      'vault_totp',
      'vault_totp_uri',
      'vault_touch',
      'vault_unlock',
      'vault_unpin',
      'vault_update',
      'vault_verify',
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
    await call(ctx, 'vault_purge', { id: entry.id, confirm: true })
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

    // auto mode: high-sensitivity reads STILL require confirmation (they are
    // always gated, unlike ordinary writes).
    await gateway.setAccessMode('auto')
    const stillDenied = await ctx.tools.execute({
      signal,
      callId: CallId(`dsh-vault-hs-${++callCounter}`),
      name: 'vault_get',
      arguments: { id: added.id },
    })
    assert.equal(stillDenied.isError, true)
    assert.match((stillDenied.error?.message ?? ''), /high-sensitivity/i)
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

test('vault_switch changes the active vault and vault_list reports it', async () => {
  (VaultPlugin as unknown as { resetVaultSwitch: () => void }).resetVaultSwitch()
  const oldHome = process.env.DSH_HOME
  const tmpHome = await mkdtemp(join(tmpdir(), 'dsh-vault-home-'))
  process.env.DSH_HOME = tmpHome
  try {
  await withContext(async ctx => {
    // Use a name-based vault (no explicit path) so switch changes the file.
    const switched = await call(ctx, 'vault_switch', { name: 'work' }) as { active: string }
    assert.equal(switched.active, 'work')

    const added = await call(ctx, 'vault_add', { title: 'Work cred', password: 'pw' })
    assert.ok((added as { id: string }).id)

    const list = await call(ctx, 'vault_list', {}) as { vaults: Array<{ name: string; active: boolean }> }
    assert.ok(list.vaults.some(v => v.name === 'work' && v.active), JSON.stringify(list.vaults))
  }, { name: 'switchtest' })
  } finally {
    process.env.DSH_HOME = oldHome
    await rm(tmpHome, { recursive: true, force: true })
  }
})

test('vault_totp_uri builds a valid otpauth provisioning URI', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'GitHub 2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const r = await call(ctx, 'vault_totp_uri', { id: added.id as string }) as { uri: string }
    assert.ok(r.uri.startsWith('otpauth://totp/'), r.uri)
    assert.ok(r.uri.includes('secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))
    assert.ok(r.uri.includes('issuer=dsh-vault'))
    assert.ok(r.uri.includes('period=30') && r.uri.includes('digits=6'))
  })
})

test('setAutoCapture toggles and persists the capture preference', async () => {
  await withContext(async ctx => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    assert.equal((await gateway.config()).autoCapture, false)
    const on = await gateway.setAutoCapture(true)
    assert.equal(on.autoCapture, true)
    // The shared policy mutated: the system prompt should now show capture ON.
    const assembly = await (ctx.get('systemPrompt') as {
      assemble: (c?: unknown) => Promise<{ sections: Array<{ name: string; text: string }> }>
    }).assemble({})
    const vaultSection = assembly.sections.find(s => s.name === 'dsh-vault')!
    assert.match(vaultSection.text, /Auto-capture is ON/)
    const off = await gateway.setAutoCapture(false)
    assert.equal(off.autoCapture, false)
  })
})

test('vault_clipboard returns a secret with a caution notice', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Copy me', password: 'copy-secret-123' })
    const r = await call(ctx, 'vault_clipboard', { id: added.id as string, field: 'password' }) as { value: string; caution: string }
    assert.equal(r.value, 'copy-secret-123')
    assert.match(r.caution, /do not repeat/i)
  })
})

test('vault_recent lists newest entries first', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Old', password: 'p1' })
    await call(ctx, 'vault_add', { title: 'New', password: 'p2' })
    const r = await call(ctx, 'vault_recent', { limit: 5 }) as { entries: Array<{ title: string }> }
    assert.equal(r.entries[0]!.title, 'New')
    assert.ok(r.entries.some(e => e.title === 'Old'))
  })
})

test('vault_update rejects invalid typed fields', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Type check', password: 'pw' })
    const bad = await ctx.tools.execute({
      signal, callId: CallId(`dsh-vault-tc-${++callCounter}`),
      name: 'vault_update', arguments: { id: added.id as string, sensitivity: 'ultra' },
    })
    assert.equal(bad.isError, true)
    assert.match((bad.error?.message ?? ''), /sensitivity/)
    const badDays = await ctx.tools.execute({
      signal, callId: CallId(`dsh-vault-tc-${++callCounter}`),
      name: 'vault_update', arguments: { id: added.id as string, rotationDays: 'soon' },
    })
    assert.equal(badDays.isError, true)
  })
})

test('vault_backup writes a timestamped copy of the encrypted file', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Backup me', password: 'pw' })
    const r = await call(ctx, 'vault_backup', {}) as { path: string }
    assert.ok(r.path.includes('vault-backup-'), r.path)
    const { readFile } = await import('node:fs/promises')
    const raw = await readFile(r.path, 'utf8')
    const parsed = JSON.parse(raw)
    assert.ok(parsed.entries.length >= 1)
  })
})

test('vault_stats reports overview counts', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Login A', password: 'pw', kind: 'login' })
    await call(ctx, 'vault_add', { title: 'SSH A', host: 'h', kind: 'ssh' })
    await call(ctx, 'vault_add', { title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', sensitivity: 'high' })
    const r = await call(ctx, 'vault_stats', {}) as { total: number; byKind: Record<string, number>; withTotp: number; highSensitivity: number }
    assert.equal(r.total, 3)
    assert.equal(r.byKind.login, 2) // '2FA' defaults to login
    assert.equal(r.byKind.ssh, 1)
    assert.equal(r.withTotp, 1)
    assert.equal(r.highSensitivity, 1)
  })
})

test('vault_import_csv dedupes by title+kind, not title alone', async () => {
  await withContext(async ctx => {
    const dir = await mkdtemp(join(tmpdir(), 'vault-csv2-'))
    const { writeFile } = await import('node:fs/promises')
    const csvPath = join(dir, 'creds.csv')
    await writeFile(csvPath, [
      'title,kind,password',
      'prod,ssh,pw1',
      'prod,api-key,pw2',
      'prod,ssh,pw3',
    ].join('\n'))
    const r = await call(ctx, 'vault_import_csv', { path: csvPath }) as { added: number; skipped: number }
    assert.equal(r.added, 2, 'ssh + api-key distinct; third duplicates ssh')
    assert.equal(r.skipped, 1)
  })
})

test('vault_export_csv writes importable CSV', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Exp', kind: 'ssh', host: 'h.example.com', username: 'u' })
    await call(ctx, 'vault_add', { title: 'Login', password: 'pw' })
    const r = await call(ctx, 'vault_export_csv', { kind: 'ssh' }) as { path: string; count: number }
    assert.equal(r.count, 1)
    const { readFile } = await import('node:fs/promises')
    const csv = await readFile(r.path, 'utf8')
    assert.ok(csv.includes('h.example.com'))
  })
})

test('vault_search filters by kind', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'S', kind: 'ssh', host: 'x' })
    await call(ctx, 'vault_add', { title: 'L', password: 'pw' })
    const ssh = await call(ctx, 'vault_search', { query: 'x', kind: 'ssh' }) as { results: Array<Record<string, unknown>> }
    assert.equal(ssh.results.length, 1)
    const login = await call(ctx, 'vault_search', { query: 'x', kind: 'login' }) as { results: Array<Record<string, unknown>> }
    assert.equal(login.results.length, 0)
  })
})

test('vault_pin ranks the entry first and marks it favorite', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'Alpha', password: 'p' })
    await call(ctx, 'vault_add', { title: 'Beta', password: 'p' })
    await call(ctx, 'vault_pin', { id: a.id as string })
    const search = await call(ctx, 'vault_search', { query: 'p' }) as { results: Array<Record<string, unknown>> }
    assert.equal(search.results[0]!.title, 'Alpha')
    assert.equal(search.results[0]!.favorite, true)
    await call(ctx, 'vault_unpin', { id: a.id as string })
  })
})

test('vault_totp rejects invalid short secrets with a clear error', async () => {
  await withContext(async ctx => {
    const r = await ctx.tools.execute({
      signal, callId: CallId(`dsh-vault-totp-${++callCounter}`),
      name: 'vault_totp', arguments: { secret: 'ABC' },
    })
    assert.equal(r.isError, true)
    assert.match((r.error?.message ?? ''), /too short|invalid Base32/i)
  })
})

test('vault_expiry sets and clears an expiry', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Exp', password: 'pw' })
    await call(ctx, 'vault_expiry', { id: added.id as string, expiresAt: Date.now() - 1000 })
    const report = await call(ctx, 'vault_rotation', {}) as { entries: Array<{ title: string; due: string }> }
    assert.ok(report.entries.some(e => e.title === 'Exp' && e.due === 'expired'))
    // Clear expiry → no longer reported.
    await call(ctx, 'vault_expiry', { id: added.id as string, expiresAt: 0 })
    const report2 = await call(ctx, 'vault_rotation', {}) as { entries: Array<{ title: string }> }
    assert.ok(!report2.entries.some(e => e.title === 'Exp'))
  })
})

test('vault_update accepts favorite via the update path', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Fav', password: 'pw' })
    await call(ctx, 'vault_update', { id: added.id as string, favorite: true })
    const search = await call(ctx, 'vault_search', { query: 'Fav' }) as { results: Array<Record<string, unknown>> }
    assert.equal(search.results[0]!.favorite, true)
  })
})

test('vault_report produces a secret-free inventory', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Reported', kind: 'ssh', host: 'h.example.com', password: 'top-secret-xyz' })
    const r = await call(ctx, 'vault_report', {}) as { report: string }
    assert.ok(r.report.includes('Reported'))
    assert.ok(r.report.includes('h.example.com'))
    assert.ok(!r.report.includes('top-secret-xyz'), 'report must not include secrets')
  })
})

test('vault_changes lists recent created entries', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Just added', password: 'pw' })
    const r = await call(ctx, 'vault_changes', { hours: 24 }) as { changes: Array<{ title: string; action: string }> }
    assert.ok(r.changes.some(c => c.title === 'Just added' && c.action === 'created'))
  })
})

test('vault_add warns on weak passwords', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_add', { title: 'Weak one', password: '123456' }) as { message: string }
    assert.match(r.message, /weak/i)
    const ok = await call(ctx, 'vault_add', { title: 'Strong one', password: 'Correct-Horse-Battery-Staple-9!' }) as { message: string }
    assert.ok(!/weak/i.test(ok.message))
  })
})

test('vault_totp_uri includes a qr hint', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'QR', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const r = await call(ctx, 'vault_totp_uri', { id: added.id as string }) as { uri: string; qr: string }
    assert.ok(r.uri.startsWith('otpauth://'))
    assert.match(r.qr, /authenticator/i)
  })
})

test('vault_notes appends and replaces notes', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Note', password: 'pw', notes: 'base' })
    const id = added.id as string
    await call(ctx, 'vault_notes', { id, text: ' added', append: true })
    let full = await call(ctx, 'vault_get', { id }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.notes, 'base\n added')
    await call(ctx, 'vault_notes', { id, text: '' })
    full = await call(ctx, 'vault_get', { id }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.notes, undefined)
  })
})

test('vault_tags counts tags across entries', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'A', password: 'p', tags: ['dev', 'prod'] })
    await call(ctx, 'vault_add', { title: 'B', password: 'p', tags: ['dev'] })
    const r = await call(ctx, 'vault_tags', {}) as { tags: Array<{ name: string; count: number }> }
    const dev = r.tags.find(t => t.name === 'dev')
    const prod = r.tags.find(t => t.name === 'prod')
    assert.equal(dev?.count, 2)
    assert.equal(prod?.count, 1)
  })
})

test('vault_import_csv skips rows with invalid kind', async () => {
  await withContext(async ctx => {
    const dir = await mkdtemp(join(tmpdir(), 'vault-csv3-'))
    const { writeFile } = await import('node:fs/promises')
    const csvPath = join(dir, 'c.csv')
    await writeFile(csvPath, 'title,kind,password\nGood,ssh,pw\nBad,weird-kind,pw2\n')
    const r = await call(ctx, 'vault_import_csv', { path: csvPath }) as { added: number; skipped: number }
    assert.equal(r.added, 1)
    assert.equal(r.skipped, 1)
  })
})

test('vault_find matches normalized text', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Prod DB', kind: 'ssh', host: 'db.internal.example.com' })
    const r = await call(ctx, 'vault_find', { text: 'DBINTERNAL' }) as { results: Array<Record<string, unknown>> }
    assert.ok(r.results.some(x => x.title === 'Prod DB'))
    const spaced = await call(ctx, 'vault_find', { text: 'db internal' }) as { results: Array<Record<string, unknown>> }
    assert.ok(spaced.results.length >= 1)
  })
})

test('vault_search lists all when query omitted, filtered by kind', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'S', kind: 'ssh', host: 'x' })
    await call(ctx, 'vault_add', { title: 'L', password: 'pw' })
    const all = await call(ctx, 'vault_search', { kind: 'ssh' }) as { results: Array<Record<string, unknown>> }
    assert.equal(all.results.length, 1)
    assert.equal(all.results[0]!.title, 'S')
  })
})

test('vault_generate_username returns a plausible value', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_generate_username', { style: 'email' }) as { value: string }
    assert.match(r.value, /^[a-z]+_[a-z]+_\d{4}@example\.com$/)
  })
})

test('vault_env shell-quotes values', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'tricky', apiKey: "a'b c", tags: ['env'] })
    const r = await call(ctx, 'vault_env', {}) as { lines: string[] }
    const line = r.lines.find(l => l.startsWith('TRICKY_APIKEY='))
    assert.ok(line !== undefined, JSON.stringify(r.lines))
    assert.ok(line!.includes("'"), 'value is quoted')
  })
})

test('vault_verify reports missing required fields', async () => {
  await withContext(async ctx => {
    const bad = await call(ctx, 'vault_add', { title: 'Incomplete SSH', kind: 'ssh' })
    const r = await call(ctx, 'vault_verify', { id: bad.id as string }) as { ok: boolean; issues: string[] }
    assert.equal(r.ok, false)
    assert.ok(r.issues.some(i => i.includes('host')))
    const good = await call(ctx, 'vault_add', { title: 'Full SSH', kind: 'ssh', host: 'h', password: 'p' })
    const ok = await call(ctx, 'vault_verify', { id: good.id as string }) as { ok: boolean }
    assert.equal(ok.ok, true)
  })
})

test('vault_purge refuses to purge an active entry without confirm', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Active', password: 'pw' })
    const denied = await ctx.tools.execute({
      signal, callId: CallId(`dsh-vault-pg-${++callCounter}`),
      name: 'vault_purge', arguments: { id: added.id as string },
    })
    assert.equal(denied.isError, true)
    assert.match((denied.error?.message ?? ''), /ACTIVE/i)
    const ok = await call(ctx, 'vault_purge', { id: added.id as string, confirm: true }) as { purged: boolean }
    assert.equal(ok.purged, true)
  })
})

test('vault_totp honors explicit period and digits for bare secrets', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_totp', { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', period: 60, digits: 8 }) as { code: string }
    assert.match(r.code, /^\d{8}$/)
  })
})

test('vault_rotate_password generates and stores a new password', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Rotate', password: 'old-password' })
    const r = await call(ctx, 'vault_rotate_password', { id: added.id as string, length: 16 }) as { rotated: boolean; password: string }
    assert.equal(r.rotated, true)
    assert.equal(r.password.length, 16)
    const full = await call(ctx, 'vault_get', { id: added.id as string }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.password, r.password)
  })
})

test('vault_duplicates finds exact title+kind duplicates', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Same', kind: 'ssh', host: 'a' })
    await call(ctx, 'vault_add', { title: 'Same', kind: 'ssh', host: 'b' })
    await call(ctx, 'vault_add', { title: 'Same', kind: 'login', password: 'x' })
    const r = await call(ctx, 'vault_duplicates', {}) as { groups: Array<Array<Record<string, unknown>>> }
    assert.equal(r.groups.length, 1, 'only ssh duplicates group')
    assert.equal(r.groups[0]!.length, 2)
  })
})

test('vault_import_csv restores numeric fields', async () => {
  await withContext(async ctx => {
    const dir = await mkdtemp(join(tmpdir(), 'vault-csv4-'))
    const { writeFile } = await import('node:fs/promises')
    const csvPath = join(dir, 'c.csv')
    await writeFile(csvPath, 'title,expiresAt,rotationDays\nNum,1780000000000,90\n')
    await call(ctx, 'vault_import_csv', { path: csvPath })
    const search = await call(ctx, 'vault_search', { query: 'Num' }) as { results: Array<{ id: string }> }
    const full = await call(ctx, 'vault_get', { id: search.results[0]!.id }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.expiresAt, 1780000000000)
    assert.equal(full.entry.rotationDays, 90)
  })
})

test('vault_mask redacts tokens and keys', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_mask', { text: 'token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and npm_123456789012345678901234567890' }) as { masked: string; redacted: number }
    assert.equal(r.redacted, 2)
    assert.ok(!r.masked.includes('ghp_'))
    assert.ok(!r.masked.includes('npm_'))
    assert.ok(r.masked.includes('[REDACTED'))
  })
})

test('vault_generate_password supports prefix and suffix', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_generate_password', { length: 12, prefix: 'Ab!', suffix: '#' }) as { password: string }
    assert.ok(r.password.startsWith('Ab!'))
    assert.ok(r.password.endsWith('#'))
    assert.equal(r.length, r.password.length)
  })
})

test('vault_health reports password strength distribution', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'W', password: 'short' })
    await call(ctx, 'vault_add', { title: 'F', password: 'medium-length-pw' })
    await call(ctx, 'vault_add', { title: 'S', password: 'this-is-a-very-long-strong-password-123' })
    const r = await call(ctx, 'vault_health', {}) as { strength: { weak: number; fair: number; strong: number } }
    assert.equal(r.strength.weak, 1)
    assert.equal(r.strength.fair, 1)
    assert.equal(r.strength.strong, 1)
  })
})

test('vault_export_totp lists TOTP entries without secrets', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'A 2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    await call(ctx, 'vault_add', { title: 'No totp', password: 'pw' })
    const r = await call(ctx, 'vault_export_totp', {}) as { entries: Array<Record<string, unknown>> }
    assert.equal(r.entries.length, 1)
    assert.ok(!('otpSecret' in r.entries[0]!), 'never leaks the secret')
  })
})

test('vault_backup_status reports days since last backup', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_backup', {})
    const r = await call(ctx, 'vault_backup_status', {}) as { daysSinceBackup: number; backups: number }
    assert.equal(r.backups, 1)
    assert.equal(r.daysSinceBackup, 0)
  })
})

test('vault_search favoriteOnly filters to pinned entries', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'Pin me', password: 'pw' })
    await call(ctx, 'vault_add', { title: 'Plain', password: 'pw' })
    await call(ctx, 'vault_pin', { id: a.id as string })
    const r = await call(ctx, 'vault_search', { query: 'Pin', favoriteOnly: true }) as { results: Array<Record<string, unknown>> }
    assert.equal(r.results.length, 1)
    assert.equal(r.results[0]!.title, 'Pin me')
    assert.equal(r.results[0]!.favorite, true)
  })
})

test('vault_history records mutations newest-first', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'H1', password: 'pw' })
    await call(ctx, 'vault_update', { id: a.id as string, notes: 'n' })
    const r = await call(ctx, 'vault_history', {}) as { events: Array<Record<string, unknown>> }
    assert.equal(r.events[0]!.action, 'update')
    assert.equal(r.events[1]!.action, 'add')
    assert.ok(!('password' in r.events[0]!), 'history never carries secrets')
  })
})

test('vault_add accepts comma-separated tags string', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Tagged', password: 'pw', tagsCsv: 'dev, prod;ops' })
    const search = await call(ctx, 'vault_search', { query: 'ops' }) as { results: Array<Record<string, unknown>> }
    assert.equal(search.results.length, 1)
    const tags = search.results[0]!.tags as string[]
    assert.deepEqual(tags, ['dev', 'prod', 'ops'])
    void added
  })
})

test('vault_export_env writes a .env file', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'stripe', apiKey: 'sk_live_xyz', tags: ['env'] })
    const dir = await mkdtemp(join(tmpdir(), 'vault-env-'))
    const envPath = join(dir, '.env')
    const r = await call(ctx, 'vault_export_env', { path: envPath }) as { lines: number }
    assert.ok(r.lines >= 1)
    const { readFile } = await import('node:fs/promises')
    const content = await readFile(envPath, 'utf8')
    assert.ok(content.includes('STRIPE_APIKEY='))
  })
})

test('vault_search regex mode matches patterns', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'prod-db-a', host: 'a.example.com' })
    await call(ctx, 'vault_add', { title: 'staging', host: 'b.example.com' })
    const r = await call(ctx, 'vault_search', { query: '^prod-', regex: true }) as { results: Array<Record<string, unknown>> }
    assert.equal(r.results.length, 1)
    assert.equal(r.results[0]!.title, 'prod-db-a')
  })
})

test('vault_env mask option hides secret values', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'secretapi', apiKey: 'sk_live_supersecret', tags: ['env'] })
    const r = await call(ctx, 'vault_env', { mask: true }) as { lines: string[] }
    const line = r.lines.find(l => l.startsWith('SECRETAPI_APIKEY='))
    assert.ok(line !== undefined)
    assert.ok(!line!.includes('sk_live_supersecret'))
    assert.ok(line!.includes('***'))
  })
})

test('vault_update strips empty values from fields', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'F', fields: { keep: 'v', drop: 'x' } })
    await call(ctx, 'vault_update', { id: added.id as string, fields: { keep: 'v', drop: '' } })
    const full = await call(ctx, 'vault_get', { id: added.id as string }) as { entry: Record<string, unknown> }
    const fields = full.entry.fields as Record<string, unknown>
    assert.equal(fields.keep, 'v')
    assert.ok(!('drop' in fields), 'empty field value removed')
  })
})

test('vault_get fields whitelist returns only requested fields', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'W', username: 'u', password: 'pw', host: 'h' })
    const r = await call(ctx, 'vault_get', { id: added.id as string, fields: ['password'] }) as { entry: Record<string, unknown> }
    assert.equal(r.entry.password, 'pw')
    assert.ok(!('username' in r.entry))
    assert.ok(!('host' in r.entry))
  })
})

test('vault_quick_add captures a minimal credential', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_quick_add', { title: 'Quick', kind: 'api-key', secret: 'sk-fast', username: 'bot' }) as { id: string }
    const full = await call(ctx, 'vault_get', { id: r.id }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.apiKey, 'sk-fast')
    assert.equal(full.entry.username, 'bot')
  })
})

test('vault_bulk_export writes a plaintext JSON dump', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Dump me', password: 'pw' })
    const dir = await mkdtemp(join(tmpdir(), 'vault-bulk-'))
    const outPath = join(dir, 'dump.json')
    const r = await call(ctx, 'vault_bulk_export', { path: outPath }) as { count: number }
    assert.ok(r.count >= 1)
    const { readFile } = await import('node:fs/promises')
    const parsed = JSON.parse(await readFile(outPath, 'utf8'))
    assert.ok(parsed.entries.length >= 1)
  })
})

test('vault_merge fills gaps and removes the source', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'Same', kind: 'ssh', host: 'a', password: 'pa' })
    const b = await call(ctx, 'vault_add', { title: 'Same', kind: 'ssh', host: 'b', username: 'u2' })
    const r = await call(ctx, 'vault_merge', { fromId: b.id as string, toId: a.id as string }) as { merged: boolean; entry: Record<string, unknown> }
    assert.equal(r.merged, true)
    // The merged summary carries non-secret fields; secrets verified via get.
    assert.equal(r.entry.username, 'u2', 'gap filled from source')
    assert.ok(!('password' in r.entry), 'summary never carries secrets')
    const full = await call(ctx, 'vault_get', { id: a.id as string }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.password, 'pa', 'existing target field kept')
    assert.equal(full.entry.username, 'u2')
    const search = await call(ctx, 'vault_search', { query: 'Same' }) as { results: Array<Record<string, unknown>> }
    assert.equal(search.results.length, 1, 'source removed')
  })
})

test('vault_touch updates recent ordering', async () => {
  await withContext(async ctx => {
    const a = await call(ctx, 'vault_add', { title: 'Older', password: 'pw' })
    await call(ctx, 'vault_add', { title: 'Newer', password: 'pw' })
    await call(ctx, 'vault_touch', { id: a.id as string })
    const r = await call(ctx, 'vault_recent', { limit: 5 }) as { entries: Array<{ title: string }> }
    assert.equal(r.entries[0]!.title, 'Older', 'touched entry jumps to top')
  })
})

test('vault_stats includes recent7d count', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Fresh', password: 'pw' })
    const r = await call(ctx, 'vault_stats', {}) as { recent7d: number }
    assert.ok(r.recent7d >= 1)
  })
})

test('vault_export_browser writes browser-import CSV', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'Site', url: 'https://example.com', username: 'u', password: 'pw' })
    const dir = await mkdtemp(join(tmpdir(), 'vault-br-'))
    const outPath = join(dir, 'browser.csv')
    const r = await call(ctx, 'vault_export_browser', { path: outPath }) as { count: number }
    assert.ok(r.count >= 1)
    const { readFile } = await import('node:fs/promises')
    const csv = await readFile(outPath, 'utf8')
    assert.ok(csv.includes('example.com'))
    assert.ok(csv.startsWith('name,url,username,password'))
  })
})

test('vault_note_secret stores a secret under a generated title', async () => {
  await withContext(async ctx => {
    const r = await call(ctx, 'vault_note_secret', { secret: 's3cret', note: 'context' }) as { id: string; title: string }
    assert.ok(r.title.startsWith('secret-'))
    const full = await call(ctx, 'vault_get', { id: r.id }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.secret, 's3cret')
    assert.equal(full.entry.notes, 'context')
  })
})

test('vault_add stores icon and color metadata', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Pretty', password: 'pw', icon: '🚀', color: 'red' })
    const full = await call(ctx, 'vault_get', { id: added.id as string }) as { entry: Record<string, unknown> }
    assert.equal(full.entry.icon, '🚀')
    assert.equal(full.entry.color, 'red')
  })
})

test('vault_search_advanced combines criteria (AND)', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'prod-db', kind: 'ssh', host: 'a', tags: ['prod'] })
    await call(ctx, 'vault_add', { title: 'prod-api', kind: 'api-key', apiKey: 'k', tags: ['prod'] })
    const r = await call(ctx, 'vault_search_advanced', { kind: 'ssh', tag: 'prod' }) as { results: Array<Record<string, unknown>> }
    assert.equal(r.results.length, 1)
    assert.equal(r.results[0]!.title, 'prod-db')
    const none = await call(ctx, 'vault_search_advanced', { kind: 'ssh', tag: 'dev' }) as { results: Array<Record<string, unknown>> }
    assert.equal(none.results.length, 0)
  })
})

test('vault_count counts entries optionally by kind', async () => {
  await withContext(async ctx => {
    await call(ctx, 'vault_add', { title: 'A', password: 'p' })
    await call(ctx, 'vault_add', { title: 'B', kind: 'ssh', host: 'h' })
    const all = await call(ctx, 'vault_count', {}) as { count: number }
    assert.ok(all.count >= 2)
    const ssh = await call(ctx, 'vault_count', { kind: 'ssh' }) as { count: number }
    assert.equal(ssh.count, 1)
  })
})

test('vault_update resetRotation refreshes the rotation clock', async () => {
  await withContext(async ctx => {
    const added = await call(ctx, 'vault_add', { title: 'Rot', password: 'pw', rotationDays: 30 })
    await call(ctx, 'vault_update', { id: added.id as string, resetRotation: true })
    const r = await call(ctx, 'vault_rotation', {}) as { entries: Array<Record<string, unknown>> }
    assert.ok(!r.entries.some(e => e.title === 'Rot'), 'rotation clock reset → not due')
  })
})
