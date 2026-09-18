/**
 * A version on npm with no GitHub release is invisible to anyone reading the
 * repository, and it happened once: 1.10.73 shipped to npm while GitHub stayed
 * on 1.10.72. These tests pin the rule that would have caught it, using the
 * real shape of the data (`scripts/release-check.mjs` fetches the same three
 * lists at runtime).
 */
import { test, expect } from 'vitest'
import { fatalProblems, findGaps, narrowToVersion } from '../scripts/release-check.mjs'

/** Every published version has a tag and a release. */
test('a consistent three-way state reports nothing', () => {
  const gaps = findGaps({
    versions: ['1.10.71', '1.10.72', '1.10.73'],
    tags: ['v1.10.71', 'v1.10.72', 'v1.10.73'],
    releases: ['v1.10.71', 'v1.10.72', 'v1.10.73'],
  })
  expect(gaps.missingReleases).toEqual([])
  expect(gaps.orphanReleases).toEqual([])
  expect(gaps.untagged).toEqual([])
})

/** The actual regression: published + tagged, release forgotten. */
test('the 1.10.73 case is reported', () => {
  const gaps = findGaps({
    versions: ['1.10.71', '1.10.72', '1.10.73'],
    tags: ['v1.10.71', 'v1.10.72', 'v1.10.73'],
    releases: ['v1.10.71', 'v1.10.72'],
  })
  expect(gaps.missingReleases).toEqual(['1.10.73'])
})

/** A release for a version that was never published is also wrong. */
test('a release without an npm version is reported', () => {
  const gaps = findGaps({
    versions: ['1.10.72'],
    tags: ['v1.10.72', 'v1.10.73'],
    releases: ['v1.10.72', 'v1.10.73'],
  })
  expect(gaps.missingReleases).toEqual([])
  expect(gaps.orphanReleases).toEqual(['v1.10.73'])
})

/** Published but never tagged: worth noting, not a failure on its own. */
test('an npm version without a tag is noted separately', () => {
  const gaps = findGaps({ versions: ['1.10.20', '1.10.20-rc.1'], tags: [], releases: [] })
  expect(gaps.untagged).toEqual(['1.10.20', '1.10.20-rc.1'])
  expect(gaps.missingReleases).toEqual([])
})

/** A prerelease is held to the same rule as a stable one. */
test('prereleases are checked too', () => {
  const gaps = findGaps({
    versions: ['1.10.64-rc.9', '1.10.64'],
    tags: ['v1.10.64-rc.9', 'v1.10.64'],
    releases: ['v1.10.64'],
  })
  expect(gaps.missingReleases).toEqual(['1.10.64-rc.9'])
})

/** Only a missing release is fatal by default; legacy orphans need --strict. */
test('the failure policy separates the actionable gap from history', () => {
  const gaps = { missingReleases: ['1.10.73'], orphanReleases: ['v1.9.3-rc.1'], untagged: [] }
  expect(fatalProblems(gaps)).toEqual(['v1.10.73 已在 npm 发布,但没有 GitHub release'])
  expect(fatalProblems(gaps, { strict: true })).toHaveLength(2)
  expect(fatalProblems({ missingReleases: [], orphanReleases: ['v1.9.3-rc.1'], untagged: [] })).toEqual([])
})

/**
 * `--version` narrows the report, never the input. Scoping the input instead
 * made all 261 other releases look like orphans.
 */
test('narrowing to one version keeps the other versions out of the report', () => {
  const gaps = findGaps({
    versions: ['1.10.72', '1.10.73'],
    tags: ['v1.10.72', 'v1.10.73'],
    releases: ['v1.10.72'],
  })
  const scoped = narrowToVersion(gaps, '1.10.73')
  expect(scoped.missingReleases).toEqual(['1.10.73'])
  expect(scoped.orphanReleases).toEqual([])
  expect(scoped.untagged).toEqual([])
})

/** The version being checked is the only one that can fail the narrowed check. */
test('a healthy version reports nothing even while others are missing', () => {
  const gaps = findGaps({
    versions: ['1.10.72', '1.10.73'],
    tags: ['v1.10.72', 'v1.10.73'],
    releases: ['v1.10.73'],
  })
  expect(narrowToVersion(gaps, '1.10.73').missingReleases).toEqual([])
})
