# dsh-vault — Encrypted Credential Vault for DeepSeek Harness

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/dsh-vault?color=cb3837&logo=npm)](https://www.npmjs.com/package/dsh-vault)
[![GitHub Release](https://img.shields.io/github/v/release/Ox0400/dsh-vault?logo=github)](https://github.com/Ox0400/dsh-vault/releases)
[![npm downloads](https://img.shields.io/npm/dm/dsh-vault)](https://www.npmjs.com/package/dsh-vault)
[![GitHub issues](https://img.shields.io/github/issues/Ox0400/dsh-vault)](https://github.com/Ox0400/dsh-vault/issues)

**English** | [中文](README-zh.md)

dsh-vault is a security-focused plugin for DeepSeek Harness that stores sensitive credentials — **usernames, emails, phone numbers, passwords, TOTP secrets**, and developer credentials like **SSH connections, API keys, secrets, and OAuth access/refresh tokens** — encrypted at rest, and exposes them to the model through CRUD, search, password generation, and TOTP tools, plus a Settings UI page.

## Security & Implementation

- **Zero external crypto dependencies**: everything is built on Node's built-in `node:crypto` (AES-256-GCM authenticated encryption, scrypt key derivation, RFC 6238 TOTP).
- **Master password**: every entry is encrypted with a 256-bit key derived via `scrypt(master password, salt)` and AES-256-GCM. The key never touches disk; after unlock it is cached in-process and re-derived on restart.
- **Tamper-evident**: GCM auth tags plus a fixed-plaintext verification envelope — a wrong master password or modified ciphertext fails immediately, never returning garbage.
- **No plaintext at rest**: the on-disk document contains no plaintext credentials; each entry uses an independent random nonce.
- **Atomic writes**: reuses the harness `writeFileAtomic` + file lock; in-process writes are serialized, cross-process writers take the lock.
- **Search never leaks**: `vault_search` returns summaries only (id/title/kind/username/email/phone/host/port/url/tags) — **never passwords, keys, tokens, or TOTP secrets**. Full credentials are readable only via explicit `vault_get` by id.

## Entry Model

Each record has a `title`, an optional `kind`, and any combination of fields:

| Field | Description |
|---|---|
| `kind` | `login` (default) / `ssh` / `api-key` / `secret` / `oauth` / `custom` |
| `username` / `email` / `phone` | Account identity |
| `password` | The password |
| `host` / `port` | SSH host and port (e.g. `db.internal` / `2222`) |
| `privateKey` | SSH private key (PEM) |
| `apiKey` | API key |
| `secret` | Generic secret (client secret, shared secret, …) |
| `accessToken` / `refreshToken` / `expiresAt` | OAuth token pair and expiry (epoch millis) |
| `otpSecret` | TOTP secret (bare Base32 or otpauth:// URI) |
| `url` / `notes` / `tags` | Metadata |
| `fields` | Arbitrary key/value pairs (e.g. `{"region": "us-east-1"}`), searchable |

## Tools

| Tool | Purpose |
|---|---|
| `vault_add` | Add an entry (any combination of fields; empty strings/arrays are ignored) |
| `vault_get` | Read a full entry by id (including all secrets) |
| `vault_search` | Search titles/categories/usernames/emails/phones/hosts/ports/URLs/notes/tags/custom fields (incl. numeric/boolean/nested values; whitespace-separated terms OR-match); optional `createdAfter`/`createdBefore` epoch-millis filters; returns secret-free summaries; `limit` must be an integer 1–100 |
| `vault_update` | Update fields by id (unprovided fields kept; empty string clears a field; `title` is renamable; `rotationDays: 0` clears rotation = never rotate) |
| `vault_compare` | Compare two entries field by field (`onlyA`/`onlyB`/`differ`/`equal`) — field names only, never secret values |
| `vault_rename` | Rename an entry in one call (shortcut for `vault_update`) |
| `vault_delete` | Soft-delete an entry (moves it to the trash, still encrypted on disk) |
| `vault_restore` / `vault_purge` / `vault_restore_recent` | Bring a trashed entry back / purge it / undo the last delete |
| `vault_lock` / `vault_unlock` | Explicitly lock the vault (wipe the in-memory key) / re-unlock it |
| `vault_totp` | Generate the current 6-digit code for a stored otpSecret (or a bare Base32 / otpauth URI) |
| `vault_generate_password` | Generate a strong random password (length/classes/grouping) **or a memorable passphrase** (`passphrase: true`, EFF-style word list, `words`/`separator`/`wordDigits`) |
| `vault_strength` | Zero-dependency password strength estimate (score 0–100, weak/fair/strong/very strong) |
| `vault_rekey` | Upgrade the vault to fresh scrypt KDF parameters in place |
| `vault_backup` | Timestamped encrypted backup with retention: prunes old copies beyond `maxBackups` (default 10) |
| `vault_import_csv` | Bulk-import credentials from a CSV file (custom columns become fields; `overwrite: true` merges fields into existing entries instead of duplicating) |
| `vault_apply_tags` | Bulk add/remove/replace tags on every entry matching a query (dry-run supported, no secrets) |
| `vault_totp_uri` | Build an otpauth:// provisioning URI for a stored or bare TOTP secret |
| `vault_switch` / `vault_list` | Switch the active vault by name / list available vaults |
| `vault_rotation` | Report expired / due-for-rotation / expiring-soon credentials; `soonWindowDays` (1-90, default 7) tunes the soon horizon (no secrets) |
| `vault_health` | Vault health scan: weak/reused passwords, missing 2FA, insecure http:// sites, and an overall security score (0–100) |
| `vault_breach_check` | Watchtower-style breach scan against Have I Been Pwned (k-anonymity: only the SHA-1 prefix leaves the machine), with an offline common-password fallback |
| `vault_merge` | Merge one entry into another; `keepSource: true` keeps the source after merging |
| `vault_quick_add` | Fast capture (title + one secret) with optional tags/notes |
| `vault_expiry` | Set/clear expiry (`expiresAt: 0` removes it) |
| `vault_stats` | Overview counts incl. `trashCount` (no secrets) |
| `vault_verify` | Verify one entry or audit every entry (`all: true`) for per-kind completeness, port/expiry sanity (no secrets) |
| `vault_duplicates` | Find duplicate groups: `mode` = `both` (default) / `title` / `content` (no secrets) |
| `vault_report` | Printable inventory with expiry/rotation columns and a stats footer (no secrets) |
| `vault_export` / `vault_import` | Portable encrypted backup/migration of the whole vault (separate export password) |
| `vault_fill` | Find the entry matching a host/URL/username/title and return its credentials |
| `vault_env` | Render env-flagged entries (tags contain `env`) as `KEY=VALUE` lines |
| `vault_templates` | List recommended fields for a credential kind (ssh / api-key / oauth / …) |

**Typical workflows**: store an SSH credential (`kind: ssh` + host/port/username/password or privateKey) and have the model `vault_search` for the host then `vault_get` the connection details; keep `api-key`/`oauth` entries for API-gateway access/refresh token rotation.

## Installation

dsh-vault is a **bundle** (a package declaring `dsh.bundle`): once installed into a profile, its `cordis.patch.yml` automatically inserts the `vault` plugin row (referenced by package name `dsh-vault`; the master password is injected via the `DSH_VAULT_PASSWORD` environment variable). The package ships a self-contained build script — git installs compile `lib/` automatically.

All four install paths below are **verified end-to-end** (install → bundle layer recognized → plugin activates with all 7 `vault_*` tools registered → real `vault_add`/`vault_get` round trip → uninstall removes the layer):

| Path | Command | Build needed | `allowBuilds` |
|---|---|---|---|
| npm | `add dsh-vault` | no (prebuilt `lib/`) | no |
| GitHub | `add github:Ox0400/dsh-vault#v0.1.1` | yes (`prepare`) | yes (first run) |
| local path | `add /abs/path/to/dsh-vault` | no (link to built source) | no |
| tarball | `add ./dsh-vault-0.1.1.tgz` | no (prebuilt `lib/`) | no |

### Option 1: Install from npm (easiest)

```sh
dsh plugin --profile demo add dsh-vault
```

npm packages ship **prebuilt `lib/` artifacts** — no allowBuilds, no local compilation, install and go. Set the master password before launching:

```sh
export DSH_VAULT_PASSWORD='your strong master password'
```

### Option 2: Install from GitHub (pin a tag or commit)

```sh
dsh plugin --profile demo add github:Ox0400/dsh-vault#v0.1.1
```

A git install fetches **sources, not built artifacts**, so the `prepare` script builds `lib/` at install time. pnpm ≥10 blocks git dependencies from running build scripts by default. The verified flow:

1. Run the `add` command — it fails with an `allowBuilds` error and prints the exact key to allow (the line containing the repo URL, including the resolved commit hash):

   ```text
   allowBuilds:
     dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
   ```

2. Append that exact key to the profile's `pnpm-workspace.yaml` (`$DSH_HOME/profiles/<name>/pnpm-workspace.yaml`):

   ```yaml
   packages:
     - .
   allowBuilds:
     dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
   ```

3. Re-run the `add` — pnpm now runs the `prepare` script, builds `lib/`, and installs.

**Pin a tag/commit** so a later upstream push cannot silently change what runs on install. Treat the allowance for what it is: permission to execute that package's code on your machine at install time — only grant it to sources you trust.

### Option 3: Install from a local path

```sh
dsh plugin --profile demo add /absolute/path/to/dsh-vault
```

pnpm links the checkout into the profile; the bundle is recognized as long as `lib/` exists (run `pnpm build` in the checkout first if needed).

### Option 4: Install from a tarball

```sh
npm pack && dsh plugin --profile demo add ./dsh-vault-0.1.1.tgz
```

The tarball ships prebuilt `lib/` artifacts, so no build step or `allowBuilds` is required.

`dsh plugin --profile demo remove dsh-vault` uninstalls (removes both the dependency and the layer).

## Configuration

| Option | Description |
|---|---|
| `masterPassword` | The master password inline (appears in cordis.yml; not recommended) |
| `masterPasswordEnv` | Environment variable name holding the master password (recommended) |
| `path` | Vault file path; defaults to `$DSH_HOME/vault/default.json` |
| `name` | Vault name for the default path (e.g. `name: work` → `$DSH_HOME/vault/work.json`) |
| `accessMode` | Access policy for the model tools. Three states: `readonly` (mutations rejected on tools + UI), `ask` (default — reads free, every add/update/delete goes through the harness approval channel so the user confirms each write), or `auto` (automatic read-write, no per-call prompt). The Settings UI offers this exact three-way choice and persists it to `<vault dir>/access.json`. |
| `autoCapture` | `false` (default). When `true`, the system prompt instructs the model to detect credentials shared in conversation and — per user preference — offer to save them with `vault_add`. |
| `lockTimeoutSeconds` | Auto-lock: after this many seconds of inactivity the vault re-locks (key wiped) and every read/write requires `vault_unlock`. `0`/absent disables. |
| `exportPasswordEnv` | Environment variable holding the export/import password for `vault_export`/`vault_import` (never pass it as a model argument). |
| `backupRetention` | How many encrypted backups to keep (default 10); `vault_backup` prunes older copies. |

Example:

```yaml
- id: vault
  name: dsh-vault
  config:
    masterPasswordEnv: DSH_VAULT_PASSWORD
    accessMode: ask
    autoCapture: true
```

With `autoCapture: true`, when you share a credential in chat (e.g. "my npm token is npm_…"), the assistant offers to store it; on your consent it calls `vault_add` immediately. With `autoCapture` off, credentials are only saved when you explicitly ask. The Settings UI shows the current mode (read-only / ask-before-write / automatic read-write) with a dropdown to switch it, an **auto-capture toggle** (detect credentials shared in chat → offer to save), a kind filter, a health & rotation summary, a trash view, and masked secret fields with a Show/Hide toggle.

The vault is created automatically on first tool use; every launch re-unlocks with the master password. **Forgetting the master password = permanent data loss** (no backdoor — by design).

## Development

Clone and develop locally:

```sh
git clone git@github.com:Ox0400/dsh-vault.git
cd dsh-vault
pnpm install    # installs devDependencies (typescript/tsdown/vitest, …)
pnpm build      # builds host lib/*.js and the browser bundle lib/client.js
pnpm test       # runs the 41 vitest tests
```

> Tests need harness peer packages such as `dsh-llm`/`dsh-system-prompt`; inside the harness monorepo these resolve via workspace links.

Common commands:

```sh
pnpm test          # unit + integration tests (vitest, 41)
pnpm typecheck     # tsc -p tsconfig.json --noEmit
pnpm build         # = build:host (tsc) + build:client (tsdown)
npm pack           # optional: tarball for `dsh plugin add ./dsh-vault-0.1.1.tgz`
```

All 41 tests pass (crypto / TOTP / password generation / store CRUD / gateway / integration).

## Packaging & Publishing

This package is a standard npm bundle:

- `dsh.bundle.patch` → `cordis.patch.yml` (the layer applied automatically when a profile lists this bundle)
- `dsh.client` → browser-side declaration (`exports["./client"]` points at `lib/client.js`)
- `prepare` script → self-contained build on git install (`tsc` host + `tsdown` client)
- Runtime dependencies are all `peerDependencies` (provided by the host harness — no duplicate instances)

Distribution options:

```sh
npm pack                  # tarball → dsh plugin add ./dsh-vault-0.1.1.tgz
npm publish --access public   # registry → dsh plugin add dsh-vault
```

## Security Boundaries & Known Limitations

- Vault strength is bounded by master-password strength; use ≥ 16 characters of high entropy.
- scrypt cost parameters (N=32768, r=8, p=1) are persisted in the document and can be raised in future versions; old documents remain decryptable.
- Plaintext credentials exist only in process memory and during explicit `vault_get` reads; `vault_search`/`vault_update` outputs never contain passwords, keys, or tokens. Secrets returned by `vault_get` enter that tool call's result (model context) — callers should avoid repeating them in conversation.
- This plugin targets single-machine / personal deployments; team-shared vaults are out of scope.
