/**
 * URL matching for dsh-vault autofill (Bitwarden/1Password-inspired).
 *
 * Given a target URL (e.g. `https://login.example.com/path`) and a stored
 * entry URL (`https://example.com`), decides whether the entry should be
 * offered. Rules follow Bitwarden's match-detection options plus 1Password's
 * domain matching:
 *
 * - Hosts are compared case-insensitively; schemes, ports, and `www.` are
 *   normalized away for domain-level checks.
 * - A stored host matches a target when the target is the same host, a
 *   subdomain of it (`mail.example.com` matches `example.com`), or its parent.
 * - Paths: a stored URL path is a prefix of the target path (login pages are
 *   stored as bare domains, so the whole target path counts).
 *
 * @module dsh-vault/urlmatch
 */

/** Extract the hostname (lowercased, www. stripped) from a URL or bare host. */
export function normalizedHost(input: string): string {
  const trimmed = input.trim().toLowerCase()
  let host = trimmed
  const scheme = /^https?:\/\//.exec(trimmed)
  if (scheme !== null) {
    const after = trimmed.slice(scheme[0].length)
    const slash = after.indexOf('/')
    host = slash >= 0 ? after.slice(0, slash) : after
    const at = host.lastIndexOf('@')
    if (at >= 0) host = host.slice(at + 1)
    const colon = host.lastIndexOf(':')
    if (colon >= 0 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon)
  } else {
    // Bare host: strip any path and port.
    const slash = host.indexOf('/')
    if (slash >= 0) host = host.slice(0, slash)
    const colon = host.lastIndexOf(':')
    if (colon >= 0 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon)
  }
  if (host.startsWith('www.')) host = host.slice(4)
  return host
}

/** Whether `stored` should be offered for `target`. */
export function urlMatches(target: string, stored: string): boolean {
  const targetHost = normalizedHost(target)
  const storedHost = normalizedHost(stored)
  if (targetHost.length === 0 || storedHost.length === 0) return false
  // Exact host, or one is a subdomain of the other.
  if (targetHost === storedHost) return true
  if (targetHost.endsWith(`.${storedHost}`) || storedHost.endsWith(`.${targetHost}`)) return true
  // Path-prefix check for entries that store a path (e.g. /login): the stored
  // path must be a prefix of the target path.
  const targetPath = pathOf(target)
  const storedPath = pathOf(stored)
  if (storedPath.length > 1 && storedPath.length <= targetPath.length && targetPath.startsWith(storedPath)) return true
  return false
}

/** Extract a normalized path (leading slash, no trailing slash except root). */
export function pathOf(input: string): string {
  const trimmed = input.trim().toLowerCase()
  const scheme = /^https?:\/\//.exec(trimmed)
  let rest = scheme !== null ? trimmed.slice(scheme[0].length) : trimmed
  const slash = rest.indexOf('/')
  const path = slash >= 0 ? rest.slice(slash) : '/'
  if (path.length > 1 && path.endsWith('/')) return path.slice(0, -1)
  return path
}

/** Score a match: 0 = no match, higher = more specific (best candidate). */
export function matchScore(target: string, stored: string): number {
  const targetHost = normalizedHost(target)
  const storedHost = normalizedHost(stored)
  if (targetHost.length === 0 || storedHost.length === 0) return 0
  if (targetHost === storedHost) return 100
  if (targetHost.endsWith(`.${storedHost}`)) return 80 // target is a subdomain of stored
  if (storedHost.endsWith(`.${targetHost}`)) return 60 // stored is a subdomain of target
  const targetPath = pathOf(target)
  const storedPath = pathOf(stored)
  if (storedPath.length > 1 && targetPath.startsWith(storedPath)) return 40
  return 0
}
