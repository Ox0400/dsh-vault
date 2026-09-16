#!/usr/bin/env node
/**
 * `dsh-vault` — script-facing access to a vault, without the model in the loop.
 *
 * The plugin hands the vault to the assistant; this CLI hands the same vault to
 * shells and scripts, so a skill's Python/Node child process can read a secret
 * without the plaintext ever entering the model's context:
 *
 *   eval "$(dsh-vault env)"                  # env-tagged entries as KEY=VALUE
 *   set -a; . <(dsh-vault env); set +a       # same, without eval
 *   dsh-vault get my-entry --field apiKey    # one field, stdout only
 *   dsh-vault export-env .env                # 0600 file for docker/systemd
 *
 * Secrets go to stdout and everything else (progress, errors) to stderr, so
 * `dsh-vault get … | pbcopy` and `$(dsh-vault get …)` behave.
 *
 * The core is `runCli(argv, io)`, which tests drive directly without spawning.
 */
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import { existsSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createInterface } from 'node:readline'
import { openVault, defaultVaultPath, type VaultEntry, type VaultStore } from './store.ts'
import { envLinesFor, envPairsForEntry, maskSecret, primarySecret, type EnvExportable } from './env-export.ts'

export interface CliIo {
  out: (text: string) => void
  err: (text: string) => void
  env: Record<string, string | undefined>
  /** Read the master password interactively. Absent when there is no TTY. */
  readPassword?: (prompt: string) => Promise<string>
  /** Read one line from stdin (used by --password-stdin). */
  readStdinLine?: () => Promise<string>
}

function packageVersion(): string {
  try {
    const require = createRequire(import.meta.url)
    const pkg = require('../package.json') as { version?: string }
    return pkg.version ?? '0.0.0'
  } catch {
    return '0.0.0'
  }
}

const USAGE = `dsh-vault — encrypted credential vault, from the command line

Usage:
  dsh-vault <command> [options]

Commands:
  list                    List entries with their env name (never secrets)
  get <id|title|ENVKEY>   Print one field of an entry (default: its main secret)
  show <id|title|ENVKEY>  Print an entry's non-secret fields as JSON
  env                     Print env-TAGGED entries as KEY=VALUE lines (an entry
                          must carry the tag "env"; "list" marks those [env]).
                          One value only? "get <entry>" needs no tag.
  export-env <path>       Write those lines to a file (mode 0600)
  verify                  Check the master password (nothing on stdout)

Options:
  --vault <name>          Named vault (default: "default")
  --path <file>           Explicit vault file (overrides --vault)
  --password-stdin        Read the master password from the first stdin line
  --json                  Machine-readable output
  -h, --help              This help
  -V, --version           Version

list options:
  --kind <k>              Only entries of this kind
  --tag <t>               Only entries carrying this tag
                          (each row also shows the env name that "get" accepts,
                          the count of further keys in parentheses, and [env]
                          when the entry is included in "dsh-vault env")

JSON output ("list --json", "show") reports per entry:
  envKeys                 the env names it exports (what "get" accepts)
  envTagged               whether "dsh-vault env" includes it

get options:
  --field <name>          apiKey | secret | accessToken | refreshToken | privateKey
                          | password | cardNumber | username | url | fields.<custom>
                          (case-insensitive; --fields is accepted as an alias)
  --mask                  Print a masked value (first 4 chars + ***)
  --all                   Print the whole entry as JSON (every secret — opt-in)

env options:
  --prefix <P>            Prefix for derived key names (an explicit envKey is kept verbatim)
  --kind <k>              Only entries of this kind
  --keys-only             Print key names without values
  --mask                  Print masked values
  --file <path>           Write to a file instead of stdout

Exported lines are shell-quoted (KEY='value'), so read them with
  eval "$(dsh-vault env)"          # into this shell
  dsh-vault export-env .env && set -a && . ./.env && set +a    # or via a file
"export $(dsh-vault env)" looks similar but is wrong: word splitting breaks
values containing spaces and the quotes are kept literally.

An entry may be named by its id, its title, its envKey, or any key it exports
(DASHSCOPE_API_KEY, TAVILY_TOKEN_REFRESH_TOKEN, …) — so a script that knows the
name it exports does not need to know the title.

The master password comes from --password-stdin, then $DSH_VAULT_MASTER_PASSWORD
(or $DSH_VAULT_PASSWORD), then an interactive prompt. It is never read from the
plugin's own config file.
`

interface Parsed {
  command: string
  positional: string[]
  flags: Map<string, string | boolean>
}

const BOOLEAN_FLAGS = new Set(['json', 'mask', 'keys-only', 'all', 'password-stdin', 'help', 'version'])

function parseArgs(argv: string[]): Parsed {
  const flags = new Map<string, string | boolean>()
  const positional: string[] = []
  let command = ''
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    if (arg === '-h' || arg === '--help') { flags.set('help', true); continue }
    if (arg === '-V' || arg === '--version') { flags.set('version', true); continue }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      const name = eq >= 0 ? arg.slice(2, eq) : arg.slice(2)
      if (eq >= 0) { flags.set(name, arg.slice(eq + 1)); continue }
      const next = argv[i + 1]
      if (BOOLEAN_FLAGS.has(name) || next === undefined || next.startsWith('-')) { flags.set(name, true); continue }
      flags.set(name, next); i++
      continue
    }
    if (command === '') command = arg
    else positional.push(arg)
  }
  return { command, positional, flags }
}

function stringFlag(parsed: Parsed, name: string): string | undefined {
  const value = parsed.flags.get(name)
  return typeof value === 'string' ? value : undefined
}

/**
 * Vault file selection, mirroring how the plugin resolves `$DSH_HOME/vault`.
 *
 * The injected environment wins over `process.env` so a caller (or a test) can
 * point the CLI at another harness home without mutating the real one.
 */
export function resolveCliVaultPath(parsed: Parsed, env: Record<string, string | undefined>): string {
  const explicit = stringFlag(parsed, 'path')
  if (explicit !== undefined) return resolve(explicit)
  const name = stringFlag(parsed, 'vault') ?? 'default'
  const home = env.DSH_HOME
  if (home !== undefined && home.length > 0) return resolve(home, 'vault', `${name}.json`)
  return defaultVaultPath(name)
}

/** Interactive prompt with echo off, read from the terminal rather than stdin. */
async function promptHidden(prompt: string): Promise<string> {
  const { open } = await import('node:fs/promises')
  let handle: Awaited<ReturnType<typeof open>> | undefined
  try {
    handle = await open('/dev/tty', 'r+')
  } catch {
    const rl = createInterface({ input: process.stdin, output: process.stderr })
    const answer = await new Promise<string>(res => rl.question(prompt, res))
    rl.close()
    return answer
  }
  const reader = handle.createReadStream()
  const writer = handle.createWriteStream()
  writer.write(prompt)
  reader.setEncoding('utf8')
  return await new Promise<string>((res, rej) => {
    let value = ''
    const finish = (result: string): void => {
      reader.destroy()
      void handle?.close()
      res(result)
    }
    reader.on('data', (chunk: string | Buffer) => {
      for (const ch of String(chunk)) {
        if (ch === '\n' || ch === '\r') { writer.write('\n'); finish(value); return }
        if (ch === '\u0003') { reader.destroy(); void handle?.close(); rej(new Error('aborted')); return }
        if (ch === '\u007f' || ch === '\b') { value = value.slice(0, -1); continue }
        value += ch
      }
    })
    reader.on('error', rej)
  })
}

async function readStdinLine(): Promise<string> {
  const rl = createInterface({ input: process.stdin })
  const line = await new Promise<string>(res => rl.once('line', res))
  rl.close()
  return line
}

/** Master password: --password-stdin, then the environment, then a prompt. */
async function resolvePassword(parsed: Parsed, io: CliIo): Promise<string> {
  if (parsed.flags.get('password-stdin') === true) {
    const read = io.readStdinLine ?? readStdinLine
    const line = (await read()).replace(/\r?\n$/, '')
    if (line.length === 0) throw new Error('no password on stdin')
    return line
  }
  for (const key of ['DSH_VAULT_MASTER_PASSWORD', 'DSH_VAULT_PASSWORD']) {
    const value = io.env[key]
    if (value !== undefined && value.length > 0) return value
  }
  const prompt = io.readPassword ?? (process.stdin.isTTY ? promptHidden : undefined)
  if (prompt === undefined) {
    throw new Error('no master password: pass --password-stdin or set DSH_VAULT_MASTER_PASSWORD')
  }
  const typed = await prompt('Vault master password: ')
  if (typed.length === 0) throw new Error('empty master password')
  return typed
}

/**
 * Resolve an entry by id, title, `envKey`, or an exported env name
 * (`DASHSCOPE_API_KEY`, `TAVILY_TOKEN_REFRESH_TOKEN`, …) — a script usually
 * knows the name it exports, not the entry title.
 *
 * Also returns the field an env name points at, so `get DASHSCOPE_API_KEY`
 * prints exactly the value `env` would emit for that key.
 */
export function resolveEntry(store: VaultStore, needle: string): { entry: VaultEntry; field?: string } {
  const entries = store.list()
  const byId = entries.find(e => e.id === needle)
  if (byId !== undefined) return { entry: byId }

  const exactTitle = entries.filter(e => e.title === needle)
  if (exactTitle.length === 1) return { entry: exactTitle[0]! }
  if (exactTitle.length > 1) {
    throw new Error(`"${needle}" is ambiguous (${exactTitle.map(e => e.title).join(', ')}) — use the id`)
  }

  // An explicit envKey wins over anything derived.
  const byEnvKey = entries.filter(e => e.envKey === needle)
  if (byEnvKey.length === 1) return { entry: byEnvKey[0]! }
  if (byEnvKey.length > 1) {
    throw new Error(`"${needle}" is the envKey of ${byEnvKey.map(e => e.title).join(', ')} — use the id`)
  }

  // Then any key the entry would export (derived names included).
  const keyed: Array<{ entry: VaultEntry; field: string }> = []
  for (const entry of entries) {
    for (const pair of envPairsForEntry(entry as unknown as EnvExportable)) {
      if (pair.key === needle) keyed.push({ entry, field: pair.field })
    }
  }
  if (keyed.length === 1) return { entry: keyed[0]!.entry, field: keyed[0]!.field }
  if (keyed.length > 1) {
    throw new Error(`"${needle}" is exported by ${keyed.map(k => k.entry.title).join(', ')} — use the entry id`)
  }

  const partial = entries.filter(e => e.title.toLowerCase().includes(needle.toLowerCase()))
  if (partial.length === 1) return { entry: partial[0]! }
  if (partial.length === 0) {
    throw new Error(`no entry, envKey or exported key matches "${needle}"`)
  }
  throw new Error(`"${needle}" is ambiguous (${partial.map(e => e.title).join(', ')}) — use the id`)
}

/** Look one field up, supporting `fields.<name>` for custom fields. */
function fieldValue(entry: VaultEntry, name: string): unknown {
  const record = entry as unknown as Record<string, unknown>
  const direct = record[name]
  if (direct !== undefined) return direct
  // Field names are camelCase in the store but nobody types them that way.
  const lower = name.toLowerCase()
  const match = Object.keys(record).find(key => key.toLowerCase() === lower)
  if (match !== undefined) return record[match]
  if (!name.startsWith('fields.')) {
    const custom = entry.fields ?? {}
    const customMatch = Object.keys(custom).find(key => `fields.${key}`.toLowerCase() === lower)
    return customMatch !== undefined ? custom[customMatch] : undefined
  }
  return (entry.fields ?? {})[name.slice('fields.'.length)]
}

/** Non-secret projection of an entry, for `list --json` / `show`. */
function publicFields(entry: VaultEntry): Record<string, unknown> {
  const { id, title, kind, username, email, phone, host, port, url, tags, icon, color, sensitivity,
    favorite, createdAt, updatedAt, rotationDays, expiresAt, cardExpiry, cardHolder } = entry
  const optional: Record<string, unknown> = {
    kind, username, email, phone, host, port, url, tags, icon, color, sensitivity,
    favorite, rotationDays, expiresAt, cardExpiry, cardHolder, createdAt, updatedAt,
  }
  const out: Record<string, unknown> = { id, title }
  for (const [key, value] of Object.entries(optional)) {
    if (value !== undefined) out[key] = value
  }
  out.hasSecret = primarySecret(entry as unknown as EnvExportable) !== undefined
  // ONE name for "the env names this entry exports": `envKeys`. It used to be a
  // configured `envKeys` plus a computed `exportedKeys`, which read as two
  // similar things — the computed list is the useful one (it already starts with
  // whatever was pinned), so only that is reported.
  out.envKeys = envPairsForEntry(entry as unknown as EnvExportable).map(pair => pair.key)
  // Whether `dsh-vault env` includes this entry (the tag decides).
  out.envTagged = (entry.tags ?? []).includes('env')
  return out
}

const COMMANDS = new Set(['list', 'get', 'show', 'env', 'export-env', 'verify'])

/** Run one CLI invocation; returns the process exit code. */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  const parsed = parseArgs(argv)
  if (parsed.flags.get('version') === true) { io.out(`${packageVersion()}\n`); return 0 }
  if (parsed.flags.get('help') === true || parsed.command === 'help') { io.out(USAGE); return 0 }
  if (parsed.command === '') { io.err(USAGE); return 2 }
  if (!COMMANDS.has(parsed.command)) {
    io.err(`dsh-vault: unknown command "${parsed.command}"\n\n${USAGE}`)
    return 2
  }

  // An unknown flag used to be ignored silently — `--fields apikey` looked like
  // it worked while doing nothing. Reject it with the accepted set instead.
  const perCommand: Record<string, string[]> = {
    list: ['kind', 'tag'],
    get: ['field', 'fields', 'mask', 'all'],
    show: [],
    env: ['prefix', 'kind', 'keys-only', 'mask', 'file'],
    'export-env': ['prefix', 'kind', 'keys-only'],
    verify: [],
  }
  const common = ['json', 'vault', 'path', 'password-stdin', 'help', 'version']
  const allowed = new Set([...common, ...(perCommand[parsed.command] ?? [])])
  const unknown = [...parsed.flags.keys()].filter(name => !allowed.has(name))
  if (unknown.length > 0) {
    io.err(`dsh-vault: unknown option${unknown.length > 1 ? 's' : ''} ${unknown.map(f => `--${f}`).join(', ')} for "${parsed.command}"\n`)
    io.err(`accepted: ${[...allowed].map(f => `--${f}`).join(' ')}\n`)
    return 2
  }

  const json = parsed.flags.get('json') === true
  const mask = parsed.flags.get('mask') === true
  const keysOnly = parsed.flags.get('keys-only') === true
  const path = resolveCliVaultPath(parsed, io.env)
  if (!existsSync(path)) {
    io.err(`dsh-vault: vault not found at ${path}\n`)
    io.err('hint: --vault <name> selects a named vault; set DSH_HOME if the vault lives elsewhere.\n')
    return 1
  }

  let store: VaultStore
  try {
    store = await openVault({ path, masterPassword: await resolvePassword(parsed, io) })
  } catch (err) {
    io.err(`dsh-vault: ${err instanceof Error ? err.message : String(err)}\n`)
    return 1
  }

  try {
    if (parsed.command === 'verify') {
      // Nothing on stdout, so `dsh-vault verify && …` is usable in scripts.
      io.err(`dsh-vault: master password ok (${store.list().length} entries)\n`)
      return 0
    }

    if (parsed.command === 'list') {
      const kind = stringFlag(parsed, 'kind')
      const tag = stringFlag(parsed, 'tag')
      const entries = store.list().filter(entry =>
        (kind === undefined || (entry.kind ?? 'login') === kind)
        && (tag === undefined || (entry.tags ?? []).includes(tag)))
      if (json) {
        io.out(`${JSON.stringify(entries.map(publicFields), null, 2)}\n`)
        return 0
      }
      // Group by what `env` actually does, because a bare `→ NAME` column used
      // to read as "this is exported" for every entry: the name is only
      // POTENTIAL until the entry carries the tag.
      const line = (entry: VaultEntry): string => {
        const identity = [entry.username, entry.host, entry.url]
          .filter((v): v is string => typeof v === 'string' && v.length > 0).join(' · ')
        const keys = envPairsForEntry(entry as unknown as EnvExportable).map(pair => pair.key)
        const suffix = keys.length > 0 ? `  → ${keys[0]}${keys.length > 1 ? ` (+${keys.length - 1})` : ''}` : ''
        return `${entry.id}  ${(entry.kind ?? 'login').padEnd(8)}  ${entry.title}`
          + `${identity.length > 0 ? `  (${identity})` : ''}${suffix}`
      }
      const tagged = entries.filter(entry => (entry.tags ?? []).includes('env'))
      const untagged = entries.filter(entry => !(entry.tags ?? []).includes('env'))
      if (tagged.length > 0) {
        io.out(`Exported by \`env\` (tag "env") — ${tagged.length} ${tagged.length === 1 ? 'entry' : 'entries'}:\n`)
        for (const entry of tagged) io.out(`  ${line(entry)}\n`)
      } else {
        io.out('Exported by `env` (tag "env"): none.\n')
        io.out('  `env` prints only tagged entries; add the tag to one (UI: the entry\'s tags field)\n')
        io.out('  or ask the assistant: vault_update { id, tags: ["env"] }.\n')
      }
      if (untagged.length > 0) {
        io.out(`\nNot exported (no "env" tag) — ${untagged.length} ${untagged.length === 1 ? 'entry' : 'entries'}; \`get <name>\` still works for them:\n`)
        for (const entry of untagged) io.out(`  ${line(entry)}\n`)
      }
      return 0
    }

    if (parsed.command === 'show') {
      const needle = parsed.positional[0]
      if (needle === undefined) { io.err('dsh-vault: show needs an entry id or title\n'); return 2 }
      io.out(`${JSON.stringify(publicFields(resolveEntry(store, needle).entry), null, 2)}\n`)
      return 0
    }

    if (parsed.command === 'get') {
      const needle = parsed.positional[0]
      if (needle === undefined) { io.err('dsh-vault: get needs an entry id, title or env key\n'); return 2 }
      const resolved = resolveEntry(store, needle)
      const entry = resolved.entry
      if (parsed.flags.get('all') === true) {
        io.out(`${JSON.stringify(entry, null, 2)}\n`)
        return 0
      }
      // An env-key lookup already names the field it points at.
      let name = stringFlag(parsed, 'field') ?? stringFlag(parsed, 'fields') ?? resolved.field
      let value: unknown
      if (name === undefined) {
        const primary = primarySecret(entry as unknown as EnvExportable)
        if (primary === undefined) { io.err(`dsh-vault: "${entry.title}" holds no secret\n`); return 1 }
        name = primary.field
        value = primary.value
      } else {
        value = fieldValue(entry, name)
      }
      if (typeof value !== 'string' || value.length === 0) {
        io.err(`dsh-vault: "${entry.title}" has no field "${name}"\n`)
        return 1
      }
      const textual = name === 'username' || name === 'url' || name === 'notes' || name.startsWith('fields.')
      const shown = mask && !textual ? maskSecret(value) : value
      io.out(json ? `${JSON.stringify({ id: entry.id, title: entry.title, field: name, value: shown })}\n` : `${shown}\n`)
      return 0
    }

    // env / export-env
    const prefix = stringFlag(parsed, 'prefix') ?? ''
    const kind = stringFlag(parsed, 'kind')
    const lines = envLinesFor(store.list() as unknown as EnvExportable[], { prefix, ...(kind !== undefined ? { kind } : {}) })
    const rendered = lines.map(line => {
      if (keysOnly) return line.split('=')[0] ?? line
      if (!mask) return line
      const eq = line.indexOf('=')
      return `${line.slice(0, eq)}=${maskSecret(line.slice(eq + 1).replace(/^'|'$/g, ''))}`
    })
    const target = parsed.command === 'export-env' ? parsed.positional[0] : stringFlag(parsed, 'file')
    if (parsed.command === 'export-env' && target === undefined) {
      io.err('dsh-vault: export-env needs a file path\n')
      return 2
    }
    if (target !== undefined) {
      const body = rendered.join('\n') + (rendered.length > 0 ? '\n' : '')
      const file = resolve(target)
      await mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await writeFile(file, body, { mode: 0o600 })
      await chmod(file, 0o600)
      io.err(keysOnly
        ? `dsh-vault: wrote ${rendered.length} key names to ${file} (no values — --keys-only)\n`
        : `dsh-vault: wrote ${rendered.length} lines to ${file} (mode 0600)\n`)
      return 0
    }
    io.out(rendered.join('\n') + (rendered.length > 0 ? '\n' : ''))
    if (rendered.length === 0) {
      // The usual first-run wall: `env` only exports entries tagged `env`, and
      // that tag exists so a shell never receives every secret in the vault.
      io.err('dsh-vault: nothing to export — no entry carries the "env" tag.\n')
      io.err('  `env` exports only entries whose tags include "env"; that tag is what\n')
      io.err('  keeps the rest of the vault (cards, notes, unrelated logins) out of your shell.\n')
      io.err('  Tag one entry and run it again:\n')
      io.err('    UI:        Settings → Credentials → the entry → tags → env\n')
      io.err('    assistant: vault_update { id, tags: ["env"] }\n')
      io.err('  `dsh-vault list` marks tagged entries with [env] and shows the name each exports.\n')
      io.err('  Only need one value? `dsh-vault get <entry>` needs no tag at all.\n')
    }
    return 0
  } catch (err) {
    io.err(`dsh-vault: ${err instanceof Error ? err.message : String(err)}\n`)
    return 1
  } finally {
    await store.lock().catch(() => {})
  }
}

/**
 * Whether this module is the process entry point (the bin shim).
 *
 * `import.meta.url` is the REAL path, while argv[1] may be a symlink (a profile
 * installs `node_modules/dsh-vault` as one) and may contain characters that need
 * URL encoding (a space in the checkout path). Compare realpaths instead of
 * string-building a file URL, which silently failed in both cases.
 */
function isEntryPoint(): boolean {
  const entry = process.argv[1]
  if (entry === undefined) return false
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return import.meta.url === pathToFileURL(entry).href
  }
}

if (isEntryPoint()) {
  void runCli(process.argv.slice(2), {
    out: text => process.stdout.write(text),
    err: text => process.stderr.write(text),
    env: process.env,
  }).then(code => { process.exitCode = code })
}
