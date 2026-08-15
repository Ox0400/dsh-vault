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
    await rm(dir, { recursive: true, force: true })
  }
}

test('VaultGateway exposes the expected remote method names', async () => {
  await withGateway(async gateway => {
    const methods = remoteMethods(gateway).map(m => m.exportName ?? m.method).sort()
    expect(methods).toEqual([
      'add', 'backup', 'backupStatus', 'backups', 'breachCheck', 'config', 'delete', 'duplicateGroups', 'duplicates', 'generatePassword', 'generateUsername', 'generatorHistory', 'get', 'health', 'history', 'import1password', 'import1pif', 'importBitwarden', 'importBitwardenEncrypted', 'importChrome', 'importEnpass', 'importFirefox', 'importKeePassXml', 'importManagerCsv', 'keychainImport', 'list', 'listVaults', 'lock', 'merge', 'recent', 'renameTag', 'restore', 'restoreBackup', 'rotation',
      'saveTemplate', 'search', 'searchSystem', 'sessionClose', 'sessionCollect', 'sessionExport', 'sessionGet', 'sessionListOpen', 'sessionListSaved', 'sessionOpen', 'sessionSave', 'setAccessMode', 'setAutoCapture', 'stats', 'status', 'strength', 'switchVault', 'tags', 'templates', 'totp', 'totpUri', 'touch', 'trash', 'undeleteAll', 'update', 'verifyAll',
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
      expect(bk.path).toMatch(/\/vault\/vault-backup-\d+.*\.json$/)
      expect((await gw.backups(5)).length).toBe(1)
      // Switch to a second named vault: the same backup directory is used,
      // but the backup snapshots beta's vault file.
      await gw.switchVault('beta')
      await gw.add({ title: 'B', username: 'b', password: 'y' })
      const bk2 = await gw.backup()
      expect(bk2.path).toMatch(/\/vault\/vault-backup-\d+.*\.json$/)
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
      await rm(dir, { recursive: true, force: true })
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
