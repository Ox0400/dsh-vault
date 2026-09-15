/**
 * The repository must stay free of credentials: everything here is published
 * (npm tarball, GitHub, public review). `scripts/secret-scan.mjs` holds the
 * rules; this test runs them on every `pnpm test`, and proves the scanner is
 * not vacuous by feeding it a planted value.
 */
import { test, expect } from 'vitest'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import { loadPrivateTerms, scanCommitMessages, scanDirectory, scanText, scanTrackedFiles, setPrivateTerms } from '../scripts/secret-scan.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

test('the scanner actually catches credentials', () => {
  // A value assembled at runtime, so this test file itself stays clean.
  const planted = 'ghp_' + 'A'.repeat(36)
  const findings = scanText(`token=${planted}`, 'planted')
  expect(findings).toHaveLength(1)
  expect(findings[0]!.pattern).toBe('github classic token')
  // …and the finding never repeats the secret
  expect(JSON.stringify(findings)).not.toContain(planted)

  // the allowed fixtures are exactly the synthetic ones
  expect(scanText('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', 'fixture')).toHaveLength(0)
  // a PEM marker around a placeholder body is fine; real key material is not
  expect(scanText('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----', 'placeholder')).toHaveLength(0)
  expect(scanText(`-----BEGIN PRIVATE KEY-----\n${'A1b2C3d4'.repeat(12)}\n-----END PRIVATE KEY-----`, 'real')).toHaveLength(1)
})

test('the working tree contains no credentials or real vault data', async () => {
  // The machine-local denylist is optional; when present it also fails the suite
  // if a real entry title/id reaches a tracked file.
  setPrivateTerms(loadPrivateTerms(root))
  const findings = await scanDirectory(root, { includeLib: true })
  expect(findings, JSON.stringify(findings)).toEqual([])
})

test('every tracked file and commit message is clean', () => {
  expect(scanTrackedFiles(root), 'tracked files').toEqual([])
  expect(scanCommitMessages(root), 'commit messages').toEqual([])
})
