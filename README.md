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
| `vault_search` | Search titles/categories/usernames/emails/phones/hosts/ports/URLs/notes/tags/custom fields (incl. numeric/boolean/nested values); returns secret-free summaries; `limit` must be an integer 1–100 |
| `vault_update` | Update fields by id (unprovided fields kept; empty string clears a field; `title` is renamable) |
| `vault_delete` | Delete an entry by id (irreversible) |
| `vault_totp` | Generate the current 6-digit code for a stored otpSecret (or a bare Base32 / otpauth URI) |
| `vault_generate_password` | Generate a strong random password (length/character classes/ambiguity exclusion/grouping; `group` must be an integer ≥ 2) |

**Typical workflows**: store an SSH credential (`kind: ssh` + host/port/username/password or privateKey) and have the model `vault_search` for the host then `vault_get` the connection details; keep `api-key`/`oauth` entries for API-gateway access/refresh token rotation.

## Installation

dsh-vault is a **bundle** (a package declaring `dsh.bundle`): once installed into a profile, its `cordis.patch.yml` automatically inserts the `vault` plugin row (referenced by package name `dsh-vault`; the master password is injected via the `DSH_VAULT_PASSWORD` environment variable). The package ships a self-contained build script — git installs compile `lib/` automatically.

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
dsh plugin --profile demo add github:Ox0400/dsh-vault#v0.1.0
```

A git install fetches **sources, not built artifacts**, so the `prepare` script builds `lib/` at install time. pnpm ≥10 blocks git dependencies from running build scripts by default — the first `add` fails and prints an `allowBuilds` key. Copy the **exact key** (the line containing the repo URL) into the profile's `pnpm-workspace.yaml`, then re-run `add`:

```yaml
# $DSH_HOME/profiles/<name>/pnpm-workspace.yaml
allowBuilds:
  dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
```

**Pin a tag/commit** so a later upstream push cannot silently change what runs on install. Treat the allowance for what it is: permission to execute that package's code on your machine at install time — only grant it to sources you trust.

### Option 3: Install from a local path

```sh
dsh plugin --profile demo add /absolute/path/to/dsh-vault
```

### Option 4: Install from a tarball

```sh
npm pack && dsh plugin --profile demo add ./dsh-vault-0.1.0.tgz
```

`dsh plugin --profile demo remove dsh-vault` uninstalls (removes both the dependency and the layer).

## Configuration

| Option | Description |
|---|---|
| `masterPassword` | The master password inline (appears in cordis.yml; not recommended) |
| `masterPasswordEnv` | Environment variable name holding the master password (recommended) |
| `path` | Vault file path; defaults to `$DSH_HOME/vault/default.json` |
| `name` | Vault name for the default path (e.g. `name: work` → `$DSH_HOME/vault/work.json`) |

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
npm pack           # optional: tarball for `dsh plugin add ./dsh-vault-0.1.0.tgz`
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
npm pack                  # tarball → dsh plugin add ./dsh-vault-0.1.0.tgz
npm publish --access public   # registry → dsh plugin add dsh-vault
```

## Security Boundaries & Known Limitations

- Vault strength is bounded by master-password strength; use ≥ 16 characters of high entropy.
- scrypt cost parameters (N=32768, r=8, p=1) are persisted in the document and can be raised in future versions; old documents remain decryptable.
- Plaintext credentials exist only in process memory and during explicit `vault_get` reads; `vault_search`/`vault_update` outputs never contain passwords, keys, or tokens. Secrets returned by `vault_get` enter that tool call's result (model context) — callers should avoid repeating them in conversation.
- This plugin targets single-machine / personal deployments; team-shared vaults are out of scope.
