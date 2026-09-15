/**
 * Timestamp handling in the store. A catalog template hint
 * ("expiry epoch millis") must never reach an entry: the editor used to copy it
 * into `expiresAt` and crashed the whole settings slot with
 * `RangeError: Invalid time value` when rendering the date input.
 */
import { test, expect } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openVault } from '../src/store.ts'

/** Reach the private map/persist the way an older build would have written it. */
type Mutable = { entries: Map<string, Record<string, unknown>> }

test('add/update reject a timestamp that is not a finite number', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ts-guard-'))
  try {
    const store = await openVault({ path: join(dir, 'v.json'), masterPassword: 'pw' })
    await expect(store.add({ title: 'poisoned', expiresAt: 'expiry epoch millis' } as never))
      .rejects.toThrow(/expiresAt must be a finite number/)
    await expect(store.add({ title: 'poisoned', rotationDays: 'soon' } as never))
      .rejects.toThrow(/rotationDays must be a finite number/)
    await expect(store.add({ title: 'poisoned', expiresAt: Number.NaN } as never))
      .rejects.toThrow(/expiresAt must be a finite number/)
    const ok = await store.add({ title: 'fine', expiresAt: 4102444800000 })
    expect(ok.expiresAt).toBe(4102444800000)
    await expect(store.update(ok.id, { expiresAt: 'nope' } as never)).rejects.toThrow(/finite number/)
    // zero still means "no expiry" and clears the field
    expect((await store.update(ok.id, { expiresAt: 0 }) as { expiresAt?: number }).expiresAt).toBeUndefined()
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a poisoned timestamp already on disk is healed when the vault opens', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ts-heal-'))
  try {
    const path = join(dir, 'v.json')
    const store = await openVault({ path, masterPassword: 'pw' })
    const entry = await store.add({ title: 'legacy', kind: 'oauth', accessToken: 'tok' })
    // exactly what the older build could persist
    const mutable = store as unknown as Mutable
    mutable.entries.get(entry.id)!.expiresAt = 'expiry epoch millis'
    mutable.entries.get(entry.id)!.rotationDays = 'soon'
    await store.persist()

    const reopened = await openVault({ path, masterPassword: 'pw' })
    const healed = reopened.list()[0]!
    expect(healed.expiresAt).toBeUndefined()
    expect((healed as Record<string, unknown>).rotationDays).toBeUndefined()

    // numeric strings from a hand-edited file are coerced, not dropped
    mutable.entries.get(entry.id)!.expiresAt = '4102444800000'
    await store.persist()
    const again = await openVault({ path, masterPassword: 'pw' })
    expect(again.list()[0]!.expiresAt).toBe(4102444800000)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
