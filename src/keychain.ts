/**
 * macOS Keychain importer for dsh-vault.
 *
 * Uses the `security` CLI: `dump-keychain` enumerates generic-password
 * entries (service + account, no secrets), then `find-generic-password -w`
 * fetches each password. System entries (com.apple.*, etc.) are filtered out.
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

export interface KeychainCredential {
  service: string
  account: string
  password: string
}

/** Session cache: keychainPath\0service\0account → password. Re-fetching the
 * same entry is what caused repeated authorization dialogs. */
const fetchCache = new Map<string, string>()

/** Number of entries currently cached (diagnostics/tests). */
export function keychainCacheSize(): number {
  return fetchCache.size
}

/** Clear the session keychain cache. */
export function clearKeychainCache(): void {
  fetchCache.clear()
}

const SYSTEM_PREFIXES = ['com.apple.', 'com.apple', 'AirPlay', 'Microsoft', 'iCloud', 'CloudKit', 'Wi-Fi', 'Bluetooth']

/** Parse a `security dump-keychain` listing into (service, account) pairs. */
export function parseDump(dump: string): Array<{ service: string; account: string }> {
  const blocks = dump.split(/\n(?=keychain:)/)
  const out: Array<{ service: string; account: string }> = []
  for (const block of blocks) {
    if (!block.includes('class: "genp"')) continue
    const svce = /"svce"<blob>="([^"]*)"/.exec(block)?.[1]
    const acct = /"acct"<blob>="([^"]*)"/.exec(block)?.[1]
    if (!svce || !acct) continue
    out.push({ service: svce, account: acct })
  }
  return out
}

/** Whether a service/account pair looks like a real credential (not a system item). */
export function isUserCredential(service: string, account: string): boolean {
  if (service.length === 0 || account.length === 0) return false
  if (SYSTEM_PREFIXES.some(p => service.startsWith(p) || account.startsWith(p))) return false
  if (/^[0-9a-f]{40}$/i.test(account) && !service.includes('.')) return false // hash-like system ids
  return true
}

/**
 * Enumerate and fetch generic-password entries from the login keychain.
 * @param limit - max entries to fetch (the CLI is called once per entry).
 * @param minLength - skip passwords shorter than this.
 */
export function readKeychainPasswords(limit = 50, minLength = 4): KeychainCredential[] {
  const dump = execFileSync('security', ['dump-keychain'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  const pairs = parseDump(dump).filter(p => isUserCredential(p.service, p.account))
  const out: KeychainCredential[] = []
  for (const pair of pairs) {
    if (out.length >= limit) break
    const cacheKey = `${pair.service}\u0000${pair.account}`
    const cached = fetchCache.get(cacheKey)
    if (cached !== undefined) {
      if (cached.length >= minLength) out.push({ service: pair.service, account: pair.account, password: cached })
      continue
    }
    try {
      const password = execFileSync(
        'security', ['find-generic-password', '-s', pair.service, '-a', pair.account, '-w'],
        { encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024 },
      ).replace(/\s+$/, '')
      fetchCache.set(cacheKey, password)
      if (password.length < minLength) continue
      out.push({ service: pair.service, account: pair.account, password })
    } catch { /* unreadable entry — skip */ }
  }
  return out
}

/** Enumerate matching entries WITHOUT fetching passwords (no dialogs). */
export function listKeychainEntries(limit = 100): Array<{ service: string; account: string }> {
  const dump = execFileSync('security', ['dump-keychain'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  return parseDump(dump).filter(p => isUserCredential(p.service, p.account)).slice(0, limit)
}
