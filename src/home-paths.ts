/**
 * `$DSH_HOME` resolution, mirrored from `@deepseek-ai/dsh-home-paths`.
 *
 * The plugin runs inside the harness and could import that package, but the
 * `dsh-vault` CLI must also work from a plain `npm install` / `npx`, where no
 * harness package exists — a peer dependency the CLI cannot resolve made it
 * fail to start (`ERR_MODULE_NOT_FOUND`). The rule itself is short and stable,
 * so it lives here; `tests/home-paths.spec.ts` pins it, and the behaviour is
 * identical to the harness helper:
 *
 *   `$DSH_HOME` (when set and non-blank) → otherwise `~/.dsh`, with a leading
 *   `~` expanded and the result resolved to an absolute path.
 */
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'

/** Environment variable that overrides the harness home directory. */
export const DSH_HOME_ENV = 'DSH_HOME'

/** Directory name used under the user's home when `$DSH_HOME` is unset. */
export const DSH_HOME_DIR_NAME = '.dsh'

/** Expand a leading `~` (and `~/`), leaving every other path untouched. */
export function expandHomePath(path: string): string {
  if (path === '~') return homedir()
  if (path.startsWith('~/') || path.startsWith('~\\')) return join(homedir(), path.slice(2))
  return path
}

/** The default harness home (`~/.dsh`). */
export function defaultDshHome(): string {
  return join(homedir(), DSH_HOME_DIR_NAME)
}

/** Resolve the harness home: an explicit value wins, then `$DSH_HOME`, then `~/.dsh`. */
export function resolveDshHome(configured?: string, env: Record<string, string | undefined> = process.env): string {
  const fromEnv = env[DSH_HOME_ENV]
  const selected = configured ?? (fromEnv !== undefined && fromEnv.trim().length > 0 ? fromEnv : defaultDshHome())
  return resolve(expandHomePath(selected))
}

/** Join path segments under the resolved harness home. */
export function dshHomePath(...segments: string[]): string {
  return join(resolveDshHome(), ...segments)
}
