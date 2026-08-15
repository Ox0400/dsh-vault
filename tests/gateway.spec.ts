/**
 * VaultGateway remote integration test: mount the gateway in a Cordis context
 * and exercise its @Remote methods directly (mirroring what the Typert gateway
 * invokes over /api).
 */

import { test, expect } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { remoteMethods } from '@deepseek-ai/dsh-typert-protocol'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { VaultGateway } from '../src/index'

async function withGateway<T>(run: (gateway: VaultGateway) => Promise<T>): Promise<T> {
  const ctx = new Context()
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-gw-'))
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(VaultGateway, { masterPassword: 'gw-test', path: join(dir, 'vault.json') })
    const gateway = ctx.get('vault') as VaultGateway
    return await run(gateway)
  } finally {
    ctx.registry.delete(VaultGateway)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rm(dir, { recursive: true, force: true })
  }
}

test('VaultGateway exposes the expected remote method names', async () => {
  await withGateway(async gateway => {
    const methods = remoteMethods(gateway).map(m => m.exportName ?? m.method).sort()
    expect(methods).toEqual([
      'add', 'backup', 'backupStatus', 'backups', 'breachCheck', 'config', 'delete', 'duplicateGroups', 'duplicates', 'generatePassword', 'generateUsername', 'generatorHistory', 'get', 'health', 'history', 'import1password', 'importChrome', 'importFirefox', 'importManagerCsv', 'keychainImport', 'list', 'listVaults', 'lock', 'merge', 'recent', 'renameTag', 'restore', 'restoreBackup', 'rotation',
      'saveTemplate', 'search', 'searchSystem', 'setAccessMode', 'setAutoCapture', 'stats', 'status', 'strength', 'switchVault', 'tags', 'templates', 'totp', 'totpUri', 'touch', 'trash', 'undeleteAll', 'update', 'verifyAll',
    ])
  })
})

test('VaultGateway add/list/get/search/update/delete round trip', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'GitHub', username: 'ada', password: 'hunter2!', tags: ['dev'] })
    expect(added.id).toBeTruthy()
    expect(added.password).toBeUndefined() // summaries never carry secrets

    const list = await gateway.list()
    expect(list.entries).toHaveLength(1)
    expect(list.entries[0]!.title).toBe('GitHub')
    expect(list.entries[0]!.password).toBeUndefined()

    const search = await gateway.search('ada')
    expect(search.entries).toHaveLength(1)

    const full = await gateway.get(added.id)
    expect(full.found).toBe(true)
    expect(full.entry?.password).toBe('hunter2!')

    const updated = await gateway.update(added.id, { email: 'ada@example.com' })
    expect(updated.found).toBe(true)
    expect(updated.entry?.email).toBe('ada@example.com')

    const deleted = await gateway.delete(added.id)
    expect(deleted.deleted).toBe(true)
    expect((await gateway.get(added.id)).found).toBe(false)
  })
})

test('VaultGateway totp uses a stored secret', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const result = await gateway.totp(added.id)
    expect(result.code).toMatch(/^\d{6}$/)
    expect(result.label).toBe('2FA')
  })
})

test('VaultGateway status reports unlocked with entry count', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'StatusEntry', password: 'pw' })
    const st = await gateway.status()
    expect(st.locked).toBe(false)
    expect(st.entries).toBe(1)
  })
})

test('VaultGateway totpUri builds an otpauth URI', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'URITest', otpSecret: 'GEZDGNBVGY3TQOJQ' })
    const r = await gateway.totpUri(added.id)
    expect(r.uri.startsWith('otpauth://totp/')).toBe(true)
    expect(r.uri).toContain('secret=GEZDGNBVGY3TQOJQ')
  })
})

test('VaultGateway breachCheck works with and without the online arg', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'BcTest', password: '123456' })
    const withArg = await gateway.breachCheck(true)
    expect(withArg.checked).toBe(1)
    expect(withArg.weak.some(w => w.title === 'BcTest')).toBe(true)
    const withoutArg = await gateway.breachCheck()
    expect(withoutArg.checked).toBe(1)
  })
})

test('VaultGateway renameTag merges a tag across entries', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'A', tags: ['old', 'keep'] })
    await gateway.add({ title: 'B', tags: ['old'] })
    const r = await gateway.renameTag('old', 'new')
    expect(r.renamed).toBe(2)
    const list = await gateway.list()
    const a = list.entries.find(e => e.title === 'A')!
    expect(a.tags).toContain('new')
    expect(a.tags).not.toContain('old')
    expect(a.tags).toContain('keep')
  })
})

test('VaultGateway exposes the system-import remotes (importChrome/keychainImport/importFirefox/searchSystem)', async () => {
  await withGateway(async gateway => {
    const methods = remoteMethods(gateway).map(m => m.exportName ?? m.method)
    expect(methods).toContain('importChrome')
    expect(methods).toContain('keychainImport')
    expect(methods).toContain('importFirefox')
    expect(methods).toContain('searchSystem')
  })
})

test('VaultGateway keychainImport validates arguments before touching the keychain', async () => {
  await withGateway(async gateway => {
    // Bad limit is rejected by the gateway without any security CLI call.
    await expect(gateway.keychainImport({ limit: 9999 })).rejects.toThrow(/limit/)
  })
})

test('VaultGateway backup/backups/restoreBackup round trip', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'GitHub', username: 'ada', password: 'hunter2!' })
    const bk = await gateway.backup()
    expect(bk.path).toMatch(/vault-backup-\d+.*\.json$/)

    const list = await gateway.backups(5)
    expect(list.length).toBe(1)
    expect(list[0]!.path).toBe(bk.path)

    // Mutate the vault, then restore from the backup — the original entry returns.
    await gateway.add({ title: 'Temp', username: 'x', password: 'y' })
    expect((await gateway.list()).entries).toHaveLength(2)

    const restored = await gateway.restoreBackup(bk.path)
    expect(restored.entries).toBe(1)
    expect(restored.safetyBackup).toMatch(/pre-restore\.json$/)
    const entries = (await gateway.list()).entries
    expect(entries).toHaveLength(1)
    expect(entries[0]!.title).toBe('GitHub')
    expect(entries[0]!.username).toBe('ada')
  })
})

test('VaultGateway restoreBackup rejects non-backup paths', async () => {
  await withGateway(async gateway => {
    await expect(gateway.restoreBackup('/tmp/not-a-backup.json')).rejects.toThrow(/not a vault backup/)
  })
})

test('VaultGateway import1password imports a 1PUX export', async () => {
  const pux = join(__dirname, 'fixtures', '1pux-sample.1pux')
  await withGateway(async gateway => {
    const r = await gateway.import1password(pux)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    const github = entries.find(e => e.title === 'GitHub')!
    expect(github.username).toBe('alice@example.com')
    // Second import is incremental → all skipped.
    const r2 = await gateway.import1password(pux)
    expect(r2.added).toBe(0)
    expect(r2.skipped).toBe(2)
  })
})

test('VaultGateway importManagerCsv imports a Dashlane export', async () => {
  const csv = join(__dirname, 'fixtures', 'dashlane.csv')
  await withGateway(async gateway => {
    const r = await gateway.importManagerCsv(csv)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    expect(entries.some(e => e.title === 'twitter.com' && e.username === 'ostqxi')).toBe(true)
  })
})

test('VaultGateway importManagerCsv imports a Keeper export (folder → tags)', async () => {
  const csv = join(__dirname, 'fixtures', 'keeper.csv')
  await withGateway(async gateway => {
    const r = await gateway.importManagerCsv(csv)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    const bank = entries.find(e => e.title === 'Keeper Bank')!
    expect(bank.username).toBe('kb-user')
    expect(bank.tags).toContain('Banking')
  })
})
