/**
 * macOS Keychain importer for dsh-vault.
 *
 * Uses the `security` CLI: `dump-keychain` enumerates generic-password
 * (`genp`) and internet-password (`inet`) entries (no secrets), then
 * `find-generic-password -w` / `find-internet-password -w` fetches each
 * password. System entries (com.apple.*, etc.) are filtered out.
 *
 * Internet-password entries are the ones that actually back website logins
 * (they carry a server, account and protocol); generic-password entries are
 * mostly app-internal secrets (Wi-Fi, system services, …), so by default the
 * importer prefers `inet` entries and only falls back to `genp` when asked.
 *
 * To avoid repeatedly prompting for the keychain password: fetched entries are
 * cached for the session (same entry never re-fetched), the default batch is
 * small, and callers should tell the user to pick "Always Allow" in the
 * keychain authorization dialog the first time (that grants one-time consent
 * for this process).
 *
 * @module dsh-vault/keychain
 */

import { execFileSync } from 'node:child_process'

export type KeychainEntryClass = 'genp' | 'inet'

export interface KeychainEntry {
  /** `genp` (generic password) or `inet` (internet password). */
  class: KeychainEntryClass
  /** Generic password: the service name. Internet password: the server host. */
  service: string
  /** Account / username. */
  account: string
  /** Internet-password only: protocol code such as `htps`, `http`, `smtp`. */
  protocol?: string
  /** Internet-password only: TCP port, when the entry carries one. */
  port?: string
}

export interface KeychainCredential extends KeychainEntry {
  password: string
}

/** Session cache: keychainPath\0class\0service\0account → password. macOS
 * authorizes per (program, entry), so re-fetching the same entry in this
 * process would trigger another dialog; the cache avoids that. There is NO
 * one-shot CLI export: `security dump-keychain -d` prompts once PER entry too
 * (and worse, blocks the whole dump), so the only mitigations are this cache,
 * small batches, and the preview mode. */
const fetchCache = new Map<string, string>()

/** Number of entries currently cached (diagnostics/tests). */
export function keychainCacheSize(): number {
  return fetchCache.size
}

/** Clear the session keychain cache. */
export function clearKeychainCache(): void {
  fetchCache.clear()
}

const SYSTEM_PREFIXES = ['com.apple.', 'com.apple', 'AirPlay', 'Microsoft', 'iCloud', 'CloudKit', 'Wi-Fi', 'Bluetooth', 'AirDrop', 'App Store', 'iTunes', 'FaceTime', 'Messages', 'iMessage']

/** Parse a `security dump-keychain` listing into typed (class, service,
 * account, …) pairs. Both `genp` and `inet` classes are understood. */
export function parseDump(dump: string): KeychainEntry[] {
  const blocks = dump.split(/\n(?=keychain:)/)
  const out: KeychainEntry[] = []
  for (const block of blocks) {
    const cls = /class: "(genp|inet)"/.exec(block)?.[1] as KeychainEntryClass | undefined
    if (cls !== 'genp' && cls !== 'inet') continue
    if (cls === 'genp') {
      const svce = /"svce"<blob>="([^"]*)"/.exec(block)?.[1]
      const acct = /"acct"<blob>="([^"]*)"/.exec(block)?.[1]
      if (!svce || !acct) continue
      out.push({ class: 'genp', service: svce, account: acct })
    } else {
      const srvr = /"srvr"<blob>="([^"]*)"/.exec(block)?.[1]
      const acct = /"acct"<blob>="([^"]*)"/.exec(block)?.[1]
      const ptcl = /"ptcl"<uint32>="([^"]*)"/.exec(block)?.[1]
      const port = /"port"<uint32>=0x([0-9a-fA-F]+)/.exec(block)?.[1]
      if (!srvr || !acct) continue
      out.push({
        class: 'inet',
        service: srvr,
        account: acct,
        ...(ptcl !== undefined ? { protocol: ptcl } : {}),
        ...(port !== undefined ? { port: String(parseInt(port, 16)) } : {}),
      })
    }
  }
  return out
}

/** Whether a service/account pair looks like a real credential (not a system item). */
export function isUserCredential(service: string, account: string): boolean {
  if (service.length === 0 || account.length === 0) return false
  if (SYSTEM_PREFIXES.some(p => service.startsWith(p) || account.startsWith(p))) return false
  if (/^[0-9a-f]{40}$/i.test(account) && !service.includes('.')) return false // hash-like system ids
  if (service === 'login' || service === 'login.keychain') return false
  return true
}

/** Fetch one entry's password without hitting the per-entry dialog twice. */
function fetchPassword(entry: KeychainEntry): string | undefined {
  const cacheKey = `${entry.class}\u0000${entry.service}\u0000${entry.account}`
  const cached = fetchCache.get(cacheKey)
  if (cached !== undefined) return cached
  try {
    const args = entry.class === 'inet'
      ? ['find-internet-password', '-s', entry.service, '-a', entry.account, '-w']
      : ['find-generic-password', '-s', entry.service, '-a', entry.account, '-w']
    const password = execFileSync('security', args, {
      encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024,
    }).replace(/\s+$/, '')
    fetchCache.set(cacheKey, password)
    return password
  } catch {
    return undefined // unreadable entry — skip
  }
}

/**
 * Enumerate and fetch entries from the login keychain.
 * @param limit - max entries to fetch (the CLI is called once per entry).
 * @param minLength - skip passwords shorter than this.
 * @param classes - which entry classes to read; internet passwords (`inet`)
 *   back website logins and are the useful kind, so they are the default.
 */
export function readKeychainPasswords(
  limit = 50,
  minLength = 4,
  classes: KeychainEntryClass[] = ['inet'],
): KeychainCredential[] {
  const dump = execFileSync('security', ['dump-keychain'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  const entries = parseDump(dump)
    .filter(e => classes.includes(e.class))
    .filter(e => isUserCredential(e.service, e.account))
  const out: KeychainCredential[] = []
  for (const entry of entries) {
    if (out.length >= limit) break
    const password = fetchPassword(entry)
    if (password === undefined || password.length < minLength) continue
    out.push({ ...entry, password })
  }
  return out
}

/** Enumerate matching entries WITHOUT fetching passwords (no dialogs). */
export function listKeychainEntries(
  limit = 100,
  classes: KeychainEntryClass[] = ['inet'],
): KeychainEntry[] {
  const dump = execFileSync('security', ['dump-keychain'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  return parseDump(dump)
    .filter(e => classes.includes(e.class))
    .filter(e => isUserCredential(e.service, e.account))
    .slice(0, limit)
}
