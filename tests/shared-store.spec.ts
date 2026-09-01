/**
 * Shared-store integration test: writes through the model tools must be
 * visible through the VaultGateway (and vice versa), because both surfaces
 * resolve ONE shared VaultStore instance per vault path.
 */

import { test, expect } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import * as VaultPlugin from '../src/index.ts'

const signal = new AbortController().signal
let callCounter = 0

async function withContext<T>(run: (ctx: Context, dir: string) => Promise<T>): Promise<T> {
  const ctx = new Context()
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-shared-'))
  const prevDshHome = process.env.DSH_HOME
  process.env.DSH_HOME = join(dir, 'dsh-home')
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(VaultPlugin, { masterPassword: 'shared-test', path: join(dir, 'vault.json'), accessMode: 'auto' })
    return await run(ctx, dir)
  } finally {
    if (prevDshHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = prevDshHome
    VaultPlugin.resetVaultSwitch()
    ctx.registry.delete(VaultPlugin)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rm(dir, { recursive: true, force: true })
  }
}

/** Execute one tool by name and return its value (asserting success). */
async function callTool(ctx: Context, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const result = await ctx.tools.execute({
    signal,
    callId: ToolCallId(`dsh-vault-shared-${++callCounter}`),
    name,
    arguments: args,
  })
  expect(result.isError).toBe(false)
  return result.value as Record<string, unknown>
}

test('model-tool writes are visible through the VaultGateway remote', async () => {
  await withContext(async (ctx, dir) => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway

    // 1. Write via the model tool.
    const added = await callTool(ctx, 'vault_add', { title: 'Shared', username: 'shared_user', password: 'pw!' })
    const id = added.id as string

    // 2. Read via the gateway — must see the tool's write.
    const list = await gateway.list()
    expect(list.entries.map(e => e.title)).toContain('Shared')
    const full = await gateway.get(id)
    expect(full.found).toBe(true)
    expect(full.entry?.password).toBe('pw!')

    // 3. Write via the gateway — must be visible to the tool's store.
    const updated = await gateway.update(id, { email: 'shared@example.com' })
    expect(updated.found).toBe(true)
    const viaTool = await callTool(ctx, 'vault_search', { query: 'shared@example.com' })
    expect((viaTool.results as Array<Record<string, unknown>>).length).toBe(1)

    // 4. Both surfaces observe the same store instance.
    const storeA = ctx.get('vault') as VaultPlugin.VaultGateway
    // The gateway's store and the tool's store are the same instance:
    // deleting via the tool is visible to the gateway.
    await callTool(ctx, 'vault_delete', { id })
    expect((await gateway.list()).entries).toHaveLength(0)
    void storeA
    void dir
  })
})

test('gateway reads refuse while the vault is locked via tools', async () => {
  await withContext(async (ctx, dir) => {
    const gateway = ctx.get('vault') as VaultPlugin.VaultGateway
    const added = await callTool(ctx, 'vault_add', { title: 'LockedRead', password: 'pw' })
    expect((added.id as string).length).toBeGreaterThan(0)
    // Tool-level lock wipes the shared store's key; the gateway must then refuse reads.
    await callTool(ctx, 'vault_lock', {})
    await expect(gateway.list()).rejects.toThrow(/locked/)
    await expect(gateway.get(added.id as string)).rejects.toThrow(/locked/)
    // Unlock restores access.
    await callTool(ctx, 'vault_unlock', {})
    const after = await gateway.list()
    expect(after.entries).toHaveLength(1)
    void dir
  })
})
