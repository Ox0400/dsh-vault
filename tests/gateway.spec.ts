/**
 * VaultGateway remote integration test: mount the gateway in a Cordis context
 * and exercise its @Remote methods directly (mirroring what the Typert gateway
 * invokes over /api).
 */

import { test, expect } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { remoteMethods } from '@deepseek-ai/dsh-typert-protocol'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import { VaultGateway } from '../src/index'

async function withGateway<T>(run: (gateway: VaultGateway) => Promise<T>): Promise<T> {
  const ctx = new Context()
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-gw-'))
  try {
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(VaultGateway, { masterPassword: 'gw-test', path: join(dir, 'vault.json') })
    const gateway = ctx.get('vault') as VaultGateway
    return await run(gateway)
  } finally {
    ctx.registry.delete(VaultGateway)
    ctx.registry.delete(ToolRuntime)
    ctx.registry.delete(SystemPrompt)
    await rm(dir, { recursive: true, force: true })
  }
}

test('VaultGateway exposes the expected remote method names', async () => {
  await withGateway(async gateway => {
    const methods = remoteMethods(gateway).map(m => m.exportName ?? m.method).sort()
    expect(methods).toEqual(['add', 'config', 'delete', 'get', 'list', 'search', 'setAccessMode', 'totp', 'update'])
  })
})

test('VaultGateway add/list/get/search/update/delete round trip', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: 'GitHub', username: 'ada', password: 'hunter2!', tags: ['dev'] })
    expect(added.id).toBeTruthy()
    expect(added.password).toBeUndefined() // summaries never carry secrets

    const list = await gateway.list()
    expect(list.entries).toHaveLength(1)
    expect(list.entries[0]!.title).toBe('GitHub')
    expect(list.entries[0]!.password).toBeUndefined()

    const search = await gateway.search('ada')
    expect(search.entries).toHaveLength(1)

    const full = await gateway.get(added.id)
    expect(full.found).toBe(true)
    expect(full.entry?.password).toBe('hunter2!')

    const updated = await gateway.update(added.id, { email: 'ada@example.com' })
    expect(updated.found).toBe(true)
    expect(updated.entry?.email).toBe('ada@example.com')

    const deleted = await gateway.delete(added.id)
    expect(deleted.deleted).toBe(true)
    expect((await gateway.get(added.id)).found).toBe(false)
  })
})

test('VaultGateway totp uses a stored secret', async () => {
  await withGateway(async gateway => {
    const added = await gateway.add({ title: '2FA', otpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' })
    const result = await gateway.totp(added.id)
    expect(result.code).toMatch(/^\d{6}$/)
    expect(result.label).toBe('2FA')
  })
})
