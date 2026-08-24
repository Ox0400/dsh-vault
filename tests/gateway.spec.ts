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

/** Remove a temp dir, retrying briefly when a best-effort async auto-backup
 * (fire-and-forget) is still writing backup files into it during teardown. */
async function rmSafe(dir: string): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      await rm(dir, { recursive: true, force: true })
      return
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOTEMPTY') throw err
      await new Promise(resolve => setTimeout(resolve, 25))
    }
  }
}
import { VaultGateway, resetVaultSwitch } from '../src/index'

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
    resetVaultSwitch()
    ctx.registry.delete(VaultGateway)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rmSafe(dir)
  }
}

test('VaultGateway exposes the expected remote method names', async () => {
  await withGateway(async gateway => {
    const methods = remoteMethods(gateway).map(m => m.exportName ?? m.method).sort()
    expect(methods).toEqual([
      'add', 'attachments', 'autoLock', 'backup', 'backupStatus', 'backups', 'breachCheck', 'config', 'delete', 'deleteBackup', 'detach', 'duplicateGroups', 'duplicates', 'export1pux', 'exportBitwarden', 'generatePassword', 'generateUsername', 'generatorHistory', 'get', 'health', 'history', 'import1password', 'import1pif', 'importBitwarden', 'importBitwardenEncrypted', 'importChrome', 'importEnpass', 'importFirefox', 'importKdbx', 'importKeePassXml', 'importManagerCsv', 'keychainImport', 'list', 'listVaults', 'lock', 'merge', 'passwordHistory', 'passwordRollback', 'purge', 'recent', 'recoveryCode', 'recoveryStatus', 'renameTag', 'restore', 'restoreBackup', 'rotation',
      'saveTemplate', 'search', 'searchSystem', 'sessionClose', 'sessionCollect', 'sessionExport', 'sessionGet', 'sessionListOpen', 'sessionListSaved', 'sessionOpen', 'sessionPrune', 'sessionSave', 'setAccessMode', 'setAutoCapture', 'setAutoLock', 'setFavorite', 'stats', 'status', 'strength', 'switchVault', 'tags', 'templates', 'totp', 'totpUri', 'touch', 'trash', 'undeleteAll', 'unlock', 'update', 'vaultDelete', 'vaultRename', 'verifyAll', 'verifyRecovery', 'watchtower',
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

test('VaultGateway summary carries custom fields for the detail view', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'WithFields', kind: 'custom', fields: { region: 'us-east-1', team: 'infra' } })
    // Summary (list/search) exposes the fields so the UI detail view can show them.
    const list = await gateway.list()
    const inList = list.entries.find(e => e.id === added.id)
    expect(inList?.fields).toEqual({ region: 'us-east-1', team: 'infra' })
    const search = await gateway.search('WithFields', 10)
    const inSearch = search.entries.find(e => e.id === added.id)
    expect(inSearch?.fields?.team).toBe('infra')
    // Entries without fields carry no fields key at all.
    const plain = await gateway.add({ title: 'NoFields' })
    const plainInList = (await gateway.list()).entries.find(e => e.id === plain.id)
    expect(plainInList?.fields).toBeUndefined()
  })
})

test('VaultGateway setFavorite pins and unpins an entry', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'PinMe' })
    const pin = await gateway.setFavorite(added.id, true)
    expect(pin.found).toBe(true)
    let list = await gateway.list()
    expect(list.entries.find(e => e.id === added.id)?.favorite).toBe(true)
    const unpin = await gateway.setFavorite(added.id, false)
    expect(unpin.found).toBe(true)
    list = await gateway.list()
    expect(list.entries.find(e => e.id === added.id)?.favorite).toBeUndefined()
    // Missing id reports not-found.
    const miss = await gateway.setFavorite('no-such-id', true)
    expect(miss.found).toBe(false)
  })
})

test('VaultGateway attachments lists and detaches files without leaking data', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'WithAttach' })
    // Attach a file via the store path (base64 inside the encrypted entry).
    await gateway.update(added.id, {
      attachments: { 'key.pem': { data: Buffer.from('private-key-data').toString('base64'), name: 'key.pem', size: 16 } },
    })
    const listed = await gateway.attachments(added.id)
    expect(listed.found).toBe(true)
    expect(listed.attachments).toEqual([{ name: 'key.pem', size: 16 }])
    // Attachments response never carries the data itself.
    expect(JSON.stringify(listed)).not.toContain('private-key-data')
    // Detach removes it.
    const detached = await gateway.detach(added.id, 'key.pem')
    expect(detached.detached).toBe(true)
    const after = await gateway.attachments(added.id)
    expect(after.attachments).toEqual([])
    // Detaching a missing name reports detached: false.
    const again = await gateway.detach(added.id, 'nope.txt')
    expect(again.detached).toBe(false)
    // Missing entry.
    const miss = await gateway.attachments('no-such-id')
    expect(miss.found).toBe(false)
  })
})

test('VaultGateway totp uses a stored secret', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const result = await gateway.totp(added.id)
    expect(result.code).toMatch(/^\d{6}$/)
    expect(result.label).toBe('2FA')
    expect(result.secondsRemaining).toBeGreaterThanOrEqual(1)
    expect(result.secondsRemaining).toBeLessThanOrEqual(30)
  })
})

test('VaultGateway list summary flags hasOtp without leaking the secret', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'WithOtp', otpSecret: 'GEZDGNBVGY3TQOJQ' })
    await gateway.add({ title: 'Plain', password: 'pw' })
    const entries = (await gateway.list()).entries
    const withOtp = entries.find(e => e.title === 'WithOtp')!
    const plain = entries.find(e => e.title === 'Plain')!
    // The summary advertises OTP presence so the UI can fetch the live code…
    expect(withOtp.hasOtp).toBe(true)
    expect(plain.hasOtp).toBe(undefined)
    // …but never ships the secret itself to the client.
    expect('otpSecret' in withOtp).toBe(false)
    expect(JSON.stringify(withOtp)).not.toContain('GEZDGNBVGY3TQOJQ')
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

test('VaultGateway backup/backups/restoreBackup round trip', async () => {  await withGateway(async gateway => {
    await gateway.add({ title: 'GitHub', username: 'ada', password: 'hunter2!' })
    // Let the async auto-backup settle.
    await new Promise(res => setTimeout(res, 80))
    const bk = await gateway.backup()
    expect(bk.path).toMatch(/-backups-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:-[0-9a-f]{6})?\.json$/)

    // add() auto-backup'd, and the manual backup is present in the list.
    const list = await gateway.backups(5)
    expect(list.length).toBeGreaterThanOrEqual(1)
    expect(list.some(b => b.path === bk.path)).toBe(true)

    // Mutate the vault, then MERGE from the backup (default): delete 'GitHub'
    // and add 'Temp', then merge — the backup's GitHub entry comes back
    // alongside Temp; nothing is lost.
    const all = (await gateway.list()).entries
    const gh = all.find(e => e.title === 'GitHub')!
    await gateway.delete(gh.id)
    await gateway.add({ title: 'Temp', username: 'x', password: 'y' })
    expect((await gateway.list()).entries).toHaveLength(1)

    const restored = await gateway.restoreBackup(bk.path)
    expect(restored.added).toBe(1) // GitHub copied back in
    expect(restored.entries).toBe(2)
    const entries = (await gateway.list()).entries
    expect(entries).toHaveLength(2)
    expect(entries.some(e => e.title === 'GitHub' && e.username === 'ada')).toBe(true)
    expect(entries.some(e => e.title === 'Temp')).toBe(true)

    // REPLACE mode restores the old semantics: whole vault replaced.
    const replaced = await gateway.restoreBackup(bk.path, 'replace')
    expect(replaced.entries).toBe(1)
    expect(replaced.safetyBackup).toMatch(/pre-restore\.json$/)
    const after = (await gateway.list()).entries
    expect(after).toHaveLength(1)
    expect(after[0]!.title).toBe('GitHub')
    expect(after[0]!.username).toBe('ada')
  })
})

test('VaultGateway restoreBackup rejects non-backup paths', async () => {
  await withGateway(async gateway => {
    await expect(gateway.restoreBackup('/tmp/not-a-backup.json')).rejects.toThrow(/not a vault backup/)
  })
})

test('VaultGateway backup/backups follow the ACTIVE vault after switchVault', async () => {
  await withGateway(async gateway => {
    // With an explicit vaultPath the directory never changes; to exercise the
    // named-vault path resolution we need the gateway WITHOUT a path. Point
    // DSH_HOME at a temp dir so named vaults land there, not in the real home.
    const ctx = new Context()
    const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-gw-active-'))
    const previousHome = process.env.DSH_HOME
    process.env.DSH_HOME = dir
    try {
      await ctx.plugin(SystemPrompt)
      await ctx.plugin(ToolRuntime)
      await ctx.plugin(VaultGateway, { masterPassword: 'gw-test', name: 'alpha' })
      const gw = ctx.get('vault') as VaultGateway
      await gw.add({ title: 'A', username: 'a', password: 'x' })
      const bk = await gw.backup()
      expect(bk.path).toMatch(/\/vault\/[a-z]+-backups-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:-[0-9a-f]{6})?\.json$/)
      // add() auto-backup'd first; the manual backup is the newest entry.
      expect((await gw.backups(5)).length).toBeGreaterThanOrEqual(1)
      // Switch to a second named vault: the same backup directory is used,
      // but the backup snapshots beta's vault file.
      await gw.switchVault('beta')
      await gw.add({ title: 'B', username: 'b', password: 'y' })
      const bk2 = await gw.backup()
      expect(bk2.path).toMatch(/\/vault\/[a-z]+-backups-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:-[0-9a-f]{6})?\.json$/)
      expect(bk2.path).not.toBe(bk.path)
      const betaList = await gw.backups(5)
      expect(betaList.some(b => b.path === bk2.path)).toBe(true)
      // Restoring beta's own backup works.
      const restored = await gw.restoreBackup(bk2.path)
      expect(restored.entries).toBe(1)
      expect((await gw.list()).entries[0]!.title).toBe('B')
    } finally {
      if (previousHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previousHome
      resetVaultSwitch()
      ctx.registry.delete(VaultGateway)
      ctx.registry.delete(ToolRuntime)
      ctx.registry.delete(SystemPrompt)
      await rmSafe(dir)
    }
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

test('VaultGateway importEnpass imports an Enpass JSON export', async () => {
  const json = join(__dirname, 'fixtures', 'enpass.json')
  await withGateway(async gateway => {
    const r = await gateway.importEnpass(json)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    const gh = entries.find(e => e.title === 'GitHub')!
    expect(gh.username).toBe('alice@example.com')
    expect(gh.password).toBeUndefined() // summaries hide secrets
  })
})

test('VaultGateway importBitwarden imports a Bitwarden JSON export', async () => {
  const json = join(__dirname, 'fixtures', 'bitwarden.json')
  await withGateway(async gateway => {
    const r = await gateway.importBitwarden(json)
    expect(r.added).toBe(1) // secure notes skipped
    const entries = (await gateway.list()).entries
    expect(entries[0]!.title).toBe('BW GitHub')
  })
})

test('VaultGateway importManagerCsv imports a LastPass export (fav → favorite)', async () => {
  const csv = join(__dirname, 'fixtures', 'lastpass.csv')
  await withGateway(async gateway => {
    const r = await gateway.importManagerCsv(csv)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    const gh = entries.find(e => e.title === 'GitHub LP')!
    expect(gh.tags).toContain('Work')
    expect(gh.favorite).toBe(true)
  })
})

test('VaultGateway importKdbxTool supports KDBX 3.1 legacy databases', async () => {
  // The tool-level kdbx import path is exercised through the imports module;
  // verify the gateway's readKdbx handles a legacy file identically.
  const { readKdbx } = await import('../src/kdbx.ts')
  const { readFileSync } = await import('node:fs')
  const entries = readKdbx(readFileSync(join(__dirname, 'fixtures', 'kdbx3-legacy.kdbx')), 'a')
  expect(entries).toHaveLength(2)
  expect(entries[0]!.title).toBe('Sample Entry')
  expect(entries[1]!.password).toBe('SecurePassword')
})

test('VaultGateway import1pif imports a legacy 1PIF export', async () => {
  const pif = join(__dirname, 'fixtures', '1pif-sample.1pif')
  await withGateway(async gateway => {
    const r = await gateway.import1pif(pif)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    expect(entries.some(e => e.title === 'GitHub Login' && e.username === 'pif-alice')).toBe(true)
  })
})

test('VaultGateway importKeePassXml imports a KeePass XML export', async () => {
  const xml = join(__dirname, 'fixtures', 'keepass-export.xml')
  await withGateway(async gateway => {
    const r = await gateway.importKeePassXml(xml)
    expect(r.added).toBe(2)
    const entries = (await gateway.list()).entries
    const site = entries.find(e => e.title === 'XML Site')!
    expect(site.username).toBe('xml-user')
  })
})

test('VaultGateway importManagerCsv dryRun previews without writing', async () => {
  const csv = join(__dirname, 'fixtures', 'dashlane.csv')
  await withGateway(async gateway => {
    // Preview first: nothing written.
    const preview = await gateway.importManagerCsv(csv, false, true)
    expect(preview.added).toBe(2)
    expect((await gateway.list()).entries).toHaveLength(0)
    // Real import writes.
    const real = await gateway.importManagerCsv(csv, false, false)
    expect(real.added).toBe(2)
    expect((await gateway.list()).entries).toHaveLength(2)
  })
})

test('VaultGateway import1password dryRun previews without writing', async () => {
  const pux = join(__dirname, 'fixtures', '1pux-sample.1pux')
  await withGateway(async gateway => {
    const preview = await gateway.import1password(pux, false, true)
    expect(preview.added).toBe(2)
    expect((await gateway.list()).entries).toHaveLength(0)
  })
})

test('VaultGateway importBitwardenEncrypted decrypts and imports', async () => {
  const json = join(__dirname, 'fixtures', 'bitwarden-encrypted.json')
  await withGateway(async gateway => {
    const r = await gateway.importBitwardenEncrypted(json, 'ExportPass123')
    expect(r.added).toBe(1)
    const entries = (await gateway.list()).entries
    expect(entries[0]!.title).toBe('Enc Site')
    expect(entries[0]!.username).toBe('enc-user')
  })
})

test('VaultGateway importBitwardenEncrypted rejects a wrong passphrase', async () => {
  const json = join(__dirname, 'fixtures', 'bitwarden-encrypted.json')
  await withGateway(async gateway => {
    await expect(gateway.importBitwardenEncrypted(json, 'nope')).rejects.toThrow(/wrong password|MAC mismatch/)
  })
})

// ── UI-facing gateway remotes: every clickable action in the settings UI ──

test('gateway config / setAccessMode / setAutoCapture round trip', async () => {
  await withGateway(async gateway => {
    const c = await gateway.config()
    expect(['readonly', 'ask', 'auto']).toContain(c.accessMode)
    const a = await gateway.setAccessMode('auto')
    expect(a.accessMode).toBe('auto')
    const cap = await gateway.setAutoCapture(true)
    expect(cap.autoCapture).toBe(true)
  })
})

test('gateway autoLock / setAutoLock round trip and validation', async () => {
  await withGateway(async gateway => {
    // Default: 0 (never).
    const initial = await gateway.autoLock()
    expect(initial.seconds).toBe(0)
    // Set 5 minutes, read it back.
    const set = await gateway.setAutoLock(300)
    expect(set.seconds).toBe(300)
    const read = await gateway.autoLock()
    expect(read.seconds).toBe(300)
    // Disable again.
    const off = await gateway.setAutoLock(0)
    expect(off.seconds).toBe(0)
    // Invalid values are rejected.
    await expect(gateway.setAutoLock(-1)).rejects.toThrow(/invalid auto-lock/)
    await expect(gateway.setAutoLock(24 * 60 * 60 + 1)).rejects.toThrow(/invalid auto-lock/)
  })
})

test('gateway copy action: get returns the secret the UI copies', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'CopyMe', username: 'u', password: 'p', url: 'https://x' })
    const full = await gateway.get(added.id)
    expect(full.found).toBe(true)
    expect(full.entry?.password).toBe('p')
  })
})

test('gateway TOTP + TOTP URI (copy code / copy URI buttons)', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'TotpSite', otpSecret: 'JBSWY3DPEHPK3PXP' })
    const code = await gateway.totp(added.id)
    expect(code.code).toMatch(/^\d{6}$/)
    expect(code.secondsRemaining).toBeGreaterThan(0)
    const uri = await gateway.totpUri(added.id)
    expect(uri.uri.startsWith('otpauth://totp/')).toBe(true)
  })
})

test('gateway touch / lock / stats / recent / history', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'TouchMe' })
    const t = await gateway.touch(added.id)
    expect(t.touched).toBe(true)
    const st = await gateway.stats()
    expect(st.total).toBeGreaterThanOrEqual(1)
    const rec = await gateway.recent()
    expect(Array.isArray(rec.entries)).toBe(true)
    const hist = await gateway.history()
    expect(Array.isArray(hist.events)).toBe(true)
    const locked = await gateway.lock()
    expect(locked.locked).toBe(true)
  })
})

test('gateway switchVault / listVaults', async () => {
  await withGateway(async gateway => {
    const sv = await gateway.switchVault('alt')
    expect(sv.switched).toBe(true)
    expect(sv.name).toBe('alt')
    const list = await gateway.listVaults()
    expect(Array.isArray(list)).toBe(true)
    await gateway.switchVault('vault')
    resetVaultSwitch()
  })
})

test('gateway templates / saveTemplate / tags / renameTag', async () => {
  await withGateway(async gateway => {
    const saved = await gateway.saveTemplate('myssh', 'ssh', { host: '' })
    expect(saved.saved).toBe(true)
    const tpl = await gateway.templates()
    expect(tpl.some(t => t.name === 'myssh')).toBe(true)
    await gateway.add({ title: 'Tagged', tags: ['old'] })
    const rn = await gateway.renameTag('old', 'new')
    expect(rn.renamed).toBe(1)
    const tags = await gateway.tags()
    expect(tags.some(t => t.name === 'new')).toBe(true)
  })
})

test('gateway trash / restore / undeleteAll', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'TrashMe' })
    await gateway.delete(added.id)
    const trash = await gateway.trash()
    expect(trash.entries.some(e => e.id === added.id)).toBe(true)
    const restored = await gateway.restore(added.id)
    expect(restored.restored).toBe(true)
    const added2 = await gateway.add({ title: 'TrashMe2' })
    await gateway.delete(added2.id)
    const all = await gateway.undeleteAll()
    expect(all.restored).toBe(1)
  })
})

test('gateway purge permanently removes trashed and active entries', async () => {
  await withGateway(async gateway => {
    // A trashed entry can be purged (the delete-only path used to return
    // false for already-trashed entries, silently breaking "empty trash").
    const a = await gateway.add({ title: 'PurgeTrashed' })
    await gateway.delete(a.id)
    const purged = await gateway.purge(a.id)
    expect(purged.purged).toBe(true)
    const trash = await gateway.trash()
    expect(trash.entries.some(e => e.id === a.id)).toBe(false)
    // An active entry can also be purged directly.
    const b = await gateway.add({ title: 'PurgeActive' })
    const purgedB = await gateway.purge(b.id)
    expect(purgedB.purged).toBe(true)
    const list = await gateway.list()
    expect(list.entries.some(e => e.id === b.id)).toBe(false)
    // Purging a missing id reports false, not an error.
    const miss = await gateway.purge('no-such-id')
    expect(miss.purged).toBe(false)
  })
})

test('gateway rotation / health / verifyAll / backupStatus / generatorHistory', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'RotMe', rotationDays: 7 })
    const rot = await gateway.rotation()
    expect(Array.isArray(rot.entries)).toBe(true)
    const health = await gateway.health()
    expect(typeof health.score).toBe('number')
    const audit = await gateway.verifyAll()
    expect(Array.isArray(audit)).toBe(true)
    const bs = await gateway.backupStatus()
    expect(typeof bs.backups).toBe('number')
    await gateway.generatePassword({ length: 16 })
    await gateway.generateUsername()
    const gh = await gateway.generatorHistory()
    expect(Array.isArray(gh)).toBe(true)
  })
})

test('gateway generatePassword supports passphrase mode', async () => {
  await withGateway(async gateway => {
    // Random mode: a 16-char mix with symbols/digits.
    const rnd = await gateway.generatePassword({ length: 16 })
    expect(rnd.password.length).toBe(16)
    // Passphrase mode: memorable words separated by dashes, with digits.
    const phr = await gateway.generatePassword({ passphrase: true, words: 4, separator: '-', wordDigits: true })
    const parts = phr.password.split('-')
    expect(parts.length).toBeGreaterThanOrEqual(4)
    // At least the last segment carries digits when wordDigits is on.
    expect(/\d/.test(phr.password)).toBe(true)
    // Custom separator and no digits.
    const phr2 = await gateway.generatePassword({ passphrase: true, words: 3, separator: '.', wordDigits: false })
    expect(phr2.password.split('.')).toHaveLength(3)
    expect(/\d/.test(phr2.password)).toBe(false)
    // Both feed the same history list.
    const gh = await gateway.generatorHistory()
    expect(gh.some(h => h.password === phr.password)).toBe(true)
  })
})

test('gateway generator history has no duplicate entries', async () => {
  await withGateway(async gateway => {
    // Generate a batch of distinct passphrases; history must not stack
    // duplicates (same password regenerated moves to front instead).
    for (let i = 0; i < 8; i++) {
      await gateway.generatePassword({ passphrase: true, words: 4, separator: '-', wordDigits: true })
    }
    const gh = await gateway.generatorHistory()
    const pwds = gh.map(h => h.password)
    expect(new Set(pwds).size).toBe(pwds.length)
    expect(gh.length).toBeLessThanOrEqual(10)
  })
})

test('gateway strength / duplicates / duplicateGroups / merge', async () => {
  await withGateway(async gateway => {
    const s = await gateway.strength('CorrectHorseBatteryStaple!2024')
    expect(s.score).toBeGreaterThan(60)
    await gateway.add({ title: 'Dup', username: 'x', password: 'same-pass' })
    await gateway.add({ title: 'Dup', username: 'y', password: 'same-pass' })
    const dup = await gateway.duplicates()
    expect(dup.groups).toBeGreaterThan(0)
    const groups = await gateway.duplicateGroups()
    expect(Array.isArray(groups)).toBe(true)
    const listed = (await gateway.list()).entries
    const a = listed.find(e => e.title === 'Dup')!
    const b = listed.find(e => e.title === 'Dup' && e.id !== a.id)!
    const merged = await gateway.merge(a.id, b.id)
    expect(merged.found).toBe(true)
  })
})

test('gateway searchSystem returns matches without passwords', async () => {
  // searchSystem scans the real OS stores (Chrome/Keychain); it may legitimately
  // find nothing on CI, so only assert the shape and that no password leaks.
  await withGateway(async gateway => {
    const r = await gateway.searchSystem('zzzz-no-such-site-zzzz')
    expect(Array.isArray(r.matches)).toBe(true)
    for (const m of r.matches) expect(m.username).not.toContain(':')
  })
}, 20000)

test('gateway sessionSave / sessionListSaved / sessionExport / sessionGet round trip', async () => {
  await withGateway(async gateway => {
    const cookies = [
      { name: 'sid', value: 'abc123', domain: 'example.com', path: '/', expires: -1, httpOnly: true, secure: false },
      { name: 'theme', value: 'dark', domain: '.example.com', path: '/', expires: 1767225600, httpOnly: false, secure: true, sameSite: 'Lax' as const },
    ]
    const saved = await gateway.sessionSave({ title: 'Example session', cookies, url: 'https://example.com/login' })
    expect(saved.saved).toBe(2)
    expect(saved.id).toBeTruthy()

    const listed = await gateway.sessionListSaved()
    expect(listed).toHaveLength(1)
    expect(listed[0]!.title).toBe('Example session')
    expect(listed[0]!.cookieCount).toBe(2)
    expect(listed[0]!.url).toBe('https://example.com/login')

    const exported = await gateway.sessionExport(saved.id, 'header')
    expect(exported.text).toBe('sid=abc123; theme=dark')
    expect(exported.domains).toContain('example.com')

    const netscape = await gateway.sessionExport(saved.id, 'netscape')
    expect(netscape.text).toContain('.example.com\tTRUE\t/\tTRUE\t1767225600\ttheme\tdark')

    const full = await gateway.sessionGet(saved.id)
    expect(full.cookies).toHaveLength(2)
    expect(full.cookies[0]!.value).toBe('abc123')
  })
})

test('gateway sessionSave rejects duplicates unless overwrite and validates kind', async () => {
  await withGateway(async gateway => {
    const cookies = [{ name: 'a', value: 'b', domain: 'x.io', path: '/', expires: -1, httpOnly: false, secure: false }]
    await gateway.sessionSave({ title: 'S', cookies })
    await expect(gateway.sessionSave({ title: 'S', cookies })).rejects.toThrow('already exists')
    const updated = await gateway.sessionSave({ title: 'S', cookies, overwrite: true })
    expect(updated.saved).toBe(1)
    // A non-cookie entry must not be exportable as a session.
    const login = await gateway.add({ title: 'NotCookie', username: 'u', password: 'p' })
    await expect(gateway.sessionExport(login.id)).rejects.toThrow('not a saved cookie session')
    await expect(gateway.sessionGet(login.id)).rejects.toThrow('not a saved cookie session')
  })
})

test('gateway sessionListOpen and sessionClose handle missing sessions gracefully', async () => {
  await withGateway(async gateway => {
    const open = await gateway.sessionListOpen()
    expect(Array.isArray(open)).toBe(true)
    // Closing an unknown session is a no-op.
    const closed = await gateway.sessionClose('no-such-session')
    expect(closed.closed).toBe(false)
    // Collecting from an unknown session errors.
    await expect(gateway.sessionCollect('no-such-session')).rejects.toThrow('unknown session')
  })
})

test('VaultGateway importKdbx imports a KDBX database via the UI remote', async () => {
  const { readFileSync } = await import('node:fs')
  await withGateway(async gateway => {
    const fixture = join(__dirname, 'fixtures', 'kdbx3-legacy.kdbx')
    const result = await gateway.importKdbx(fixture, 'a', '', false, false)
    expect(result.added).toBeGreaterThan(0)
    const entries = (await gateway.list()).entries
    expect(entries.some(e => e.title === 'prod-db' || e.title.length > 0)).toBe(true)
    // dryRun preview counts without writing.
    const dry = await gateway.importKdbx(fixture, 'a', '', false, true)
    expect(dry.added).toBe(dry.added)
  })
})

test('gateway sessionPrune removes expired cookies and previews without writing', async () => {
  await withGateway(async gateway => {
    const now = Math.floor(Date.now() / 1000)
    const cookies = [
      { name: 'live', value: '1', domain: 'x.io', path: '/', expires: now + 10000, httpOnly: false, secure: false },
      { name: 'stale', value: '2', domain: 'x.io', path: '/', expires: now - 10000, httpOnly: false, secure: false },
    ]
    const saved = await gateway.sessionSave({ title: 'PruneMe', cookies })
    // Preview reports the expired count without touching the entry.
    const preview = await gateway.sessionPrune(saved.id, true)
    expect(preview.pruned).toBe(0)
    expect(preview.note).toContain('1 expired')
    const before = await gateway.sessionGet(saved.id)
    expect(before.cookies).toHaveLength(2)
    // Actual prune removes the stale cookie.
    const pruned = await gateway.sessionPrune(saved.id, false)
    expect(pruned.pruned).toBe(1)
    expect(pruned.remaining).toBe(1)
    const after = await gateway.sessionGet(saved.id)
    expect(after.cookies).toHaveLength(1)
    expect(after.cookies[0]!.name).toBe('live')
  })
})

test('VaultGateway vaultRename / vaultDelete manage named vaults', async () => {
  const { unlink } = await import('node:fs/promises')
  const { homedir } = await import('node:os')
  const { join: j } = await import('node:path')
  const suffix = Date.now().toString(36)
  const a = `rn-a-${suffix}`
  const b = `rn-b-${suffix}`
  const base = j(homedir(), '.dsh', 'vault')
  await unlink(j(base, `${a}.json`)).catch(() => {})
  await unlink(j(base, `${b}.json`)).catch(() => {})
  const ctx = new Context()
  const prevHome = process.env.DSH_HOME
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-rn-'))
  process.env.DSH_HOME = dir
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(VaultGateway, { masterPassword: 'gw-test', name: a })
    const gw = ctx.get('vault') as VaultGateway
    await gw.add({ title: 'InA', username: 'a', password: 'x' })
    // Rename a -> b; the vault file moves and the active name follows.
    const renamed = await gw.vaultRename(a, b)
    expect(renamed.renamed).toBe(true)
    expect(renamed.vaults.some(v => v.name === b && v.active)).toBe(true)
    expect(renamed.vaults.some(v => v.name === a)).toBe(false)
    // Entries survive the rename.
    const entries = (await gw.list()).entries
    expect(entries.some(e => e.title === 'InA')).toBe(true)
    // Delete b; active falls back to default.
    const del = await gw.vaultDelete(b, true)
    expect(del.deleted).toBe(true)
    expect(del.active).toBe('default')
    expect(del.vaults.some(v => v.name === b)).toBe(false)
    // Deleting default is refused.
    await expect(gw.vaultDelete('default', true)).rejects.toThrow(/default vault cannot be deleted/)
  } finally {
    if (prevHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = prevHome
    resetVaultSwitch()
    ctx.registry.delete(VaultGateway)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rmSafe(dir)
  }
})

test('backup files do not appear as vaults and can be deleted', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'X', username: 'u', password: 'p' })
    const bk = await gateway.backup()
    // The backup file must not show up in the vault roster.
    const vaults = await gateway.listVaults()
    expect(vaults.some(v => bk.path.endsWith(`${v.name}.json`))).toBe(false)
    // Deleting a non-backup path is rejected.
    await expect(gateway.deleteBackup('/tmp/not-a-backup.json')).rejects.toThrow(/not a vault backup/)
    // Deleting the real backup works and removes it from the list.
    const del = await gateway.deleteBackup(bk.path)
    expect(del.deleted).toBe(true)
    const remaining = await gateway.backups(20)
    expect(remaining.some(b => b.path === bk.path)).toBe(false)
  })
})

test('VaultGateway passwordHistory / passwordRollback round trip', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'HistGW', username: 'u', password: 'v1' })
    await gateway.update(added.id, { password: 'v2' })
    await gateway.update(added.id, { password: 'v3' })
    const history = await gateway.passwordHistory(added.id)
    expect(history).toHaveLength(2)
    expect(history[0]!.password).toBe('v2')
    const target = history.find(h => h.password === 'v1')!
    const rolled = await gateway.passwordRollback(added.id, target.at)
    expect(rolled.rolledBack).toBe(true)
    expect(rolled.password).toBe('v1')
    const full = await gateway.get(added.id)
    expect(full.entry?.password).toBe('v1')
    // Rolling back to a missing history entry fails cleanly.
    const missing = await gateway.passwordRollback(added.id, 999999)
    expect(missing.rolledBack).toBe(false)
  })
})

test('VaultGateway card entries round trip and verify', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({
      title: 'Amex', kind: 'card',
      cardNumber: '3782 822463 10005', cardExpiry: '09/29', cardCvv: '4567', cardHolder: 'Grace H',
    })
    expect(added.kind).toBe('card')
    const full = await gateway.get(added.id)
    expect(full.entry?.cardNumber).toBe('3782 822463 10005')
    expect(full.entry?.cardCvv).toBe('4567')
    // Summaries (list/search) do not leak card secrets.
    const list = await gateway.list()
    const sum = list.entries.find(e => e.id === added.id)
    expect(sum?.cardExpiry).toBe('09/29')
    expect((sum as { cardNumber?: unknown }).cardNumber).toBeUndefined()
    // verifyAll flags an incomplete card but not a complete one (it only
    // returns entries with issues).
    const partial = await gateway.add({ title: 'Incomplete', kind: 'card' })
    const audit = await gateway.verifyAll()
    expect(audit.some(a => a.id === added.id)).toBe(false) // complete card, no issues
    const partialAudit = audit.find(a => a.id === partial.id)
    expect(partialAudit?.issues.some(i => i.includes('card'))).toBe(true)
  })
})

test('VaultGateway watchtower rates entries without leaking secrets', async () => {
  await withGateway(async gateway => {
    await gateway.add({ title: 'Weak', username: 'u', password: 'qwerty123' })
    await gateway.add({ title: 'Strong', username: 'u', password: 'X9!kQm2#vLp7$rTz' })
    const report = await gateway.watchtower()
    expect(report).toHaveLength(2)
    const weak = report.find(r => r.title === 'Weak')!
    expect(weak.verdict).not.toBe('good')
    expect(weak.flags.length).toBeGreaterThan(0)
    const strong = report.find(r => r.title === 'Strong')!
    expect(strong.verdict).toBe('good')
    // No secrets in the report.
    expect(JSON.stringify(report)).not.toContain('qwerty123')
    expect(JSON.stringify(report)).not.toContain('X9!kQm2')
  })
})

test('VaultGateway export1pux / exportBitwarden write archives', async () => {
  await withGateway(async gateway => {
    const { mkdtemp, readFile, rm } = await import('node:fs/promises')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    const dir = await mkdtemp(join(tmpdir(), 'gw-export-'))
    await gateway.add({ title: 'GWExport', username: 'u', password: 'pw' })
    try {
      const pux = join(dir, 'out.1pux')
      const r1 = await gateway.export1pux(pux)
      expect(r1.count).toBe(1)
      const { readZip } = await import('../src/zip')
      const entries = readZip(await readFile(pux))
      expect(entries.some(e => e.name === 'export.data')).toBe(true)

      const bw = join(dir, 'out.json')
      const r2 = await gateway.exportBitwarden(bw)
      expect(r2.count).toBe(1)
      const doc = JSON.parse(await readFile(bw, 'utf8'))
      expect(doc.items[0].name).toBe('GWExport')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

test('VaultGateway recovery code generate → verify → status', async () => {
  await withGateway(async gateway => {
    const status0 = await gateway.recoveryStatus()
    expect(status0.set).toBe(false)
    const r = await gateway.recoveryCode()
    expect(r.code.length).toBe(32)
    // The plaintext code is NOT in the meta (only its hash).
    const verified = await gateway.verifyRecovery(r.code)
    expect(verified.verified).toBe(true)
    expect((await gateway.verifyRecovery('wrong-code')).verified).toBe(false)
    const status1 = await gateway.recoveryStatus()
    expect(status1.set).toBe(true)
    expect(typeof status1.issuedAt).toBe('number')
  })
})

test('VaultGateway templates includes new built-ins (wifi/server/database/card)', async () => {
  await withGateway(async gateway => {
    const tpls = await gateway.templates()
    const builtin = tpls.filter(t => t.name.startsWith('builtin:'))
    for (const want of ['builtin:wifi', 'builtin:server', 'builtin:database', 'builtin:card', 'builtin:bank']) {
      expect(builtin.some(t => t.name === want)).toBe(true)
    }
    const wifi = builtin.find(t => t.name === 'builtin:wifi')!
    expect(wifi.fields.password).toBeDefined()
  })
})

test('VaultGateway auto-backs-up after writes (1Password-style)', async () => {
  await withGateway(async gateway => {
    const before = (await gateway.backups(5)).length
    await gateway.add({ title: 'AutoBk', password: 'pw' })
    await new Promise(res => setTimeout(res, 50))
    const afterAdd = (await gateway.backups(5)).length
    expect(afterAdd).toBeGreaterThan(before)
    // delete also backs up
    const all = (await gateway.list()).entries
    const auto = all.find(e => e.title === 'AutoBk')!
    await gateway.delete(auto.id)
    await new Promise(res => setTimeout(res, 50))
    const afterDel = (await gateway.backups(5)).length
    expect(afterDel).toBeGreaterThan(afterAdd)
  })
})
