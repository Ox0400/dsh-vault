/**
 * dsh-vault browser half: a Vault settings page managing encrypted
 * credentials — list, search, add, edit, delete, and copy — through the host
 * VaultGateway remote over the /api RPC channel.
 *
 * @module dsh-vault/client
 */

import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type { ConnectionHandle } from '@deepseek-ai/dsh-api-remotes/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
// Type-only: pulls the SlotRegistry service merge (ctx.slots).
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import { VaultSection, type VaultSectionInjected } from './VaultSection.tsx'
import type { VaultSectionTypes } from './VaultSection.tsx'
import { en, zh, type VaultLocaleKey } from './locales.ts'

export type { VaultSectionInjected, VaultSectionProps } from './VaultSection.tsx'
export type { VaultSectionTypes } from './VaultSection.tsx'
export type { VaultLocaleKey } from './locales.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Vault settings page copy. */
    'settings.vault': VaultLocaleKey
  }
}

/** Dictionary namespace owned by this plugin. */
export const NS = 'settings.vault'

/** Services required by the Settings registration and the RPC face. */
export const inject = ['slots', 'locale', 'connection']

/**
 * Register the Vault settings section once the `settings.section` declaration
 * is on the ledger. The section talks to the host through the connection RPC
 * channel (endpoints `vault/*` served by the host VaultGateway remote).
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-vault: dictionaries')

  const t = ctx.locale.bind(NS)
  const connection = ctx.get('connection') as ConnectionHandle

  /** Invoke one host vault remote and normalize the RPC envelope. */
  async function invoke<T>(method: string, args: Record<string, unknown> = {}): Promise<T> {
    const result = await connection.rpc.call('/api', `vault/${method}`, { args })
    if (!result.ok) {
      throw new Error(`vault.${method} failed: ${result.error.code}: ${result.error.message}`)
    }
    return result.value as T
  }

  const injected = (): VaultSectionInjected => ({
    t,
    config: () => invoke<VaultSectionTypes['config']>('config'),
    setAccessMode: (mode) => invoke<VaultSectionTypes['config']>('setAccessMode', { mode }),
    setAutoCapture: (enabled) => invoke<VaultSectionTypes['config']>('setAutoCapture', { enabled }),
    setAutoLock: (seconds) => invoke<{ seconds: number }>('setAutoLock', { seconds }),
    list: () => invoke<{ entries: VaultSectionTypes['entries'] }>('list').then(r => r.entries),
    search: (query, limit) => invoke<{ entries: VaultSectionTypes['entries'] }>('search', { query, limit: limit ?? 50 }).then(r => r.entries),
    get: (id) => invoke<{ found: boolean; entry?: VaultSectionTypes['fullEntry'] }>('get', { id }),
    add: (patch) => invoke<VaultSectionTypes['summaryEntry']>('add', { patch }),
    update: (id, patch) => invoke<{ found: boolean; entry?: VaultSectionTypes['summaryEntry'] }>('update', { id, patch }),
    remove: (id) => invoke<{ deleted: boolean }>('delete', { id }),
    purge: (id) => invoke<{ purged: boolean }>('purge', { id }),
    trash: () => invoke<{ entries: VaultSectionTypes['entries'] }>('trash').then(r => r.entries),
    rotation: () => invoke<{ entries: unknown[] }>('rotation').then(r => r.entries),
    history: () => invoke<{ events: unknown[] }>('history').then(r => r.events),
    stats: () => invoke<Record<string, unknown>>('stats'),
    recent: () => invoke<{ entries: unknown[] }>('recent').then(r => r.entries),
    backupStatus: () => invoke<{ daysSinceBackup: number; backups: number }>('backupStatus'),
    backup: (maxBackups) => invoke<{ path: string; kept: number; pruned: number }>('backup', { ...(maxBackups !== undefined ? { maxBackups } : {}) }),
    health: () => invoke<{ weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number }; no2fa: unknown[]; httpSites: unknown[]; score: number; verdict: string }>('health'),
    duplicates: () => invoke<{ groups: number }>('duplicates'),
    status: () => invoke<{ locked: boolean; entries: number }>('status'),
    switchVault: (name) => invoke<{ switched: boolean; name: string }>('switchVault', { name }),
    listVaults: () => invoke<Array<{ name: string; active: boolean; entries?: number }>>('listVaults'),
    touch: (id) => invoke<{ touched: boolean }>('touch', { id }),
    setFavorite: (id, favorite) => invoke<{ found: boolean }>('setFavorite', { id, favorite }),
    attachments: (id) => invoke<{ found: boolean; attachments: Array<{ name: string; size: number }> }>('attachments', { id }),
    detach: (id, name) => invoke<{ found: boolean; detached: boolean }>('detach', { id, name }),
    attach: (id, name, dataBase64, mime) => invoke<{ found: boolean; attached: boolean; name?: string; size?: number; attachments?: number }>('attach', { id, name, dataBase64, mime }),
    downloadAttachment: (id, name) => invoke<{ found: boolean; name?: string; size?: number; mime?: string; dataBase64?: string }>('downloadAttachment', { id, name }),
    lock: () => invoke<{ locked: boolean }>('lock'),
    unlock: () => invoke<{ locked: boolean }>('unlock'),
    totpUri: (id) => invoke<{ uri: string }>('totpUri', { id }),
    tags: () => invoke<Array<{ name: string; count: number }>>('tags'),
    renameTag: (from, to) => invoke<{ renamed: number }>('renameTag', { from, to }),
    removeTag: (tag) => invoke<{ removed: number }>('removeTag', { tag }),
    generatorHistory: () => invoke<Array<{ password: string; at: number }>>('generatorHistory'),
    backups: (limit) => invoke<Array<{ path: string; at: number; vaultName: string; size: number }>>('backups', { limit: limit ?? 5 }),
    deleteBackup: (path) => invoke<{ deleted: boolean; path: string }>('deleteBackup', { path }),
    restoreBackup: (path, mode, overwrite) => invoke<{ entries: number; safetyBackup: string; note: string; added?: number; skipped?: number; updated?: number }>('restoreBackup', { path, mode: mode ?? 'merge', overwrite: overwrite ?? false }),
    importChrome: (overwrite) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importChrome', { overwrite: overwrite ?? false }),
    importFirefox: (masterPassword, overwrite) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importFirefox', { masterPassword: masterPassword ?? '', overwrite: overwrite ?? false }),
    keychainImport: (options) => invoke<{ added: number; skipped: number; updated: number; note: string }>('keychainImport', { options: options ?? {} }),
    import1password: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('import1password', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    importManagerCsv: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importManagerCsv', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    previewImportCsv: (path) => invoke<{ rows: Array<{ title: string; kind: string; username: string; hasPassword: boolean }>; total: number; skipped: number }>('previewImportCsv', { path }),
    importEnpass: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importEnpass', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    importBitwarden: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importBitwarden', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    import1pif: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('import1pif', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    importBitwardenEncrypted: (path, password, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importBitwardenEncrypted', { path, password, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    importKeePassXml: (path, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importKeePassXml', { path, overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    importKdbx: (path, password, keyfile, overwrite, dryRun) => invoke<{ added: number; skipped: number; updated: number; note: string }>('importKdbx', { path, password: password ?? '', keyfile: keyfile ?? '', overwrite: overwrite ?? false, dryRun: dryRun ?? false }),
    searchSystem: (query, source, limit) => invoke<{ matches: Array<{ source: string; name: string; username: string }>; note: string }>('searchSystem', { query, source: source ?? 'all', limit: limit ?? 15 }),
    verifyAll: () => invoke<Array<{ id: string; title: string; issues: string[] }>>('verifyAll'),
    breachCheck: (online) => invoke<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean }>('breachCheck', { online: online ?? true }),
    generatePassword: (options) => invoke<{ password: string }>('generatePassword', { options: options ?? {} }),
    strength: (password) => invoke<{ score: number; verdict: string; feedback: string; bits: number }>('strength', { password }),
    templates: () => invoke<Array<{ name: string; kind: string; fields: Record<string, string> }>>('templates'),
    saveTemplate: (name, kind, fields) => invoke<{ saved: boolean }>('saveTemplate', { name, kind, fields }),
    generateUsername: () => invoke<{ username: string }>('generateUsername'),
    duplicateGroups: () => invoke<Array<Array<{ id: string; title: string }>>>('duplicateGroups'),
    merge: (fromId, toId, keepSource) => invoke<{ found: boolean }>('merge', { fromId, toId, keepSource: keepSource ?? false }),
    restore: (id) => invoke<{ restored: boolean }>('restore', { id }),
    undeleteAll: () => invoke<{ restored: number }>('undeleteAll'),
    totp: (id) => invoke<{ code: string; label?: string; secondsRemaining: number }>('totp', { id }),
    sessionOpen: (url) => invoke<{ sessionId: string; url: string }>('sessionOpen', { url }),
    sessionCollect: (sessionId, url) => invoke<{ cookies: unknown[]; count: number }>('sessionCollect', { sessionId, url: url ?? '' }),
    sessionClose: (sessionId) => invoke<{ closed: boolean }>('sessionClose', { sessionId }),
    sessionListOpen: () => invoke<Array<{ sessionId: string; url: string; openedAt: number }>>('sessionListOpen'),
    sessionListSaved: () => invoke<Array<{ id: string; title: string; url?: string; cookieCount: number; expiredCount?: number; expiringSoon?: number; updatedAt?: number }>>('sessionListSaved'),
    sessionSave: (options) => invoke<{ saved: number; id: string }>('sessionSave', { options: options ?? {} }),
    sessionExport: (id, format) => invoke<{ text: string; cookieCount: number; domains: string[] }>('sessionExport', { id, format: format ?? 'header' }),
    sessionGet: (id) => invoke<{ id: string; title: string; url?: string; cookies: unknown[]; notes?: string }>('sessionGet', { id }),
    sessionPrune: (id, preview) => invoke<{ pruned: number; remaining: number; note: string }>('sessionPrune', { id, preview: preview ?? false }),
    passwordHistory: (id) => invoke<Array<{ password: string; at: number }>>('passwordHistory', { id }),
    passwordRollback: (id, at) => invoke<{ rolledBack: boolean; password?: string }>('passwordRollback', { id, at }),
    watchtower: () => invoke<Array<{ id: string; title: string; kind: string; flags: string[]; score: number; verdict: string; bits?: number }>>('watchtower'),
    export1pux: (path) => invoke<{ path: string; count: number }>('export1pux', { path }),
    exportBitwarden: (path) => invoke<{ path: string; count: number }>('exportBitwarden', { path }),
    exportCsv: (path, fields) => invoke<{ path: string; count: number; fields: string[] }>('exportCsv', { path, fields }),
    recoveryCode: () => invoke<{ code: string; note: string }>('recoveryCode'),
    verifyRecovery: (code) => invoke<{ verified: boolean }>('verifyRecovery', { code }),
    recoveryStatus: () => invoke<{ set: boolean; issuedAt?: number }>('recoveryStatus'),
    vaultRename: (from, to) => invoke<{ renamed: boolean; from?: string; to?: string; vaults: Array<{ name: string; active: boolean }>; note: string }>('vaultRename', { from, to }),
    vaultDelete: (name, confirm) => invoke<{ deleted: boolean; name?: string; active: string; vaults: Array<{ name: string; active: boolean }>; note: string }>('vaultDelete', { name, confirm }),
  })

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'vault',
    order: 30,
    label: () => t('nav'),
    inject: injected,
  }, VaultSection))
}
