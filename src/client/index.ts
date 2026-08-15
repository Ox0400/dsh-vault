/**
 * dsh-vault browser half: a Vault settings page managing encrypted
 * credentials — list, search, add, edit, delete, and copy — through the host
 * VaultGateway remote over the /api RPC channel.
 *
 * @module dsh-vault/client
 */

import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
import type { ConnectionHandle } from '@deepseek-ai/dsh-api-remotes/client'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
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
    list: () => invoke<{ entries: VaultSectionTypes['entries'] }>('list').then(r => r.entries),
    search: (query, limit) => invoke<{ entries: VaultSectionTypes['entries'] }>('search', { query, limit: limit ?? 50 }).then(r => r.entries),
    get: (id) => invoke<{ found: boolean; entry?: VaultSectionTypes['fullEntry'] }>('get', { id }),
    add: (patch) => invoke<VaultSectionTypes['summaryEntry']>('add', { patch }),
    update: (id, patch) => invoke<{ found: boolean; entry?: VaultSectionTypes['summaryEntry'] }>('update', { id, patch }),
    remove: (id) => invoke<{ deleted: boolean }>('delete', { id }),
    trash: () => invoke<{ entries: VaultSectionTypes['entries'] }>('trash').then(r => r.entries),
    rotation: () => invoke<{ entries: unknown[] }>('rotation').then(r => r.entries),
    history: () => invoke<{ events: unknown[] }>('history').then(r => r.events),
    stats: () => invoke<Record<string, unknown>>('stats'),
    recent: () => invoke<{ entries: unknown[] }>('recent').then(r => r.entries),
    backupStatus: () => invoke<{ daysSinceBackup: number; backups: number }>('backupStatus'),
    backup: (maxBackups) => invoke<{ path: string; kept: number; pruned: number }>('backup', { maxBackups: maxBackups ?? 10 }),
    health: () => invoke<{ weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number } }>('health'),
    duplicates: () => invoke<{ groups: number }>('duplicates'),
    status: () => invoke<{ locked: boolean; entries: number }>('status'),
    duplicateGroups: () => invoke<Array<Array<{ id: string; title: string }>>>('duplicateGroups'),
    merge: (fromId, toId, keepSource) => invoke<{ found: boolean }>('merge', { fromId, toId, keepSource: keepSource ?? false }),
    restore: (id) => invoke<{ restored: boolean }>('restore', { id }),
    undeleteAll: () => invoke<{ restored: number }>('undeleteAll'),
    totp: (id) => invoke<{ code: string; label?: string; secondsRemaining: number }>('totp', { id }),
  })

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'vault',
    order: 30,
    label: () => t('nav'),
    inject: injected,
  }, VaultSection))
}
