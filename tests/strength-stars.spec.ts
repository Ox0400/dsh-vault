/**
 * The three-star strength indicator. Half stars are rendered by clipping the
 * coloured copy of the glyphs, so these units are what the component turns into
 * a width — worth pinning at the boundaries.
 */
import { test, expect } from 'vitest'
import { strengthTone, strengthUnits, strengthWidthPercent } from '../src/client/strength-stars.ts'

test('score 0 shows no filled star and 100 shows all three', () => {
  expect(strengthUnits(0)).toBe(0)
  expect(strengthWidthPercent(0)).toBe(0)
  expect(strengthUnits(100)).toBe(6)
  expect(strengthWidthPercent(6)).toBe(100)
  // nothing usable → nothing shown
  for (const bad of [undefined, Number.NaN, -5]) expect(strengthUnits(bad as number | undefined)).toBe(0)
})

test('the six half-star steps land where they should', () => {
  // units = round(score × 6 / 100), so each step is a ~16.7-point band:
  // 8 → 0, 9 → 1, 25 → 2, 42 → 3, 59 → 4, 75 → 5, 92 → 6 (full)
  expect([0, 8].map(strengthUnits)).toEqual([0, 0])
  expect([9, 25, 42, 59, 75, 92, 100].map(strengthUnits)).toEqual([1, 2, 3, 4, 5, 6, 6])
  // the band edges are exact, not approximate
  expect([24, 25, 41, 42, 58, 59, 74, 75, 91, 92].map(strengthUnits)).toEqual([1, 2, 2, 3, 3, 4, 4, 5, 5, 6])
  // half of the track is exactly three units (½ = 1.5 stars)
  expect(strengthWidthPercent(3)).toBe(50)
  expect(strengthWidthPercent(1)).toBeCloseTo(16.67, 1)
})

test('units never leave the track and stay monotone', () => {
  let previous = -1
  for (let score = 0; score <= 100; score++) {
    const units = strengthUnits(score)
    expect(units).toBeGreaterThanOrEqual(previous)
    expect(units).toBeLessThanOrEqual(6)
    previous = units
  }
  expect(strengthUnits(1000)).toBe(6)
})

test('the colour bands follow the units', () => {
  expect([0, 1, 2].map(strengthTone)).toEqual(['weak', 'weak', 'weak'])
  expect([3, 4].map(strengthTone)).toEqual(['fair', 'fair'])
  expect([5, 6].map(strengthTone)).toEqual(['strong', 'strong'])
})
