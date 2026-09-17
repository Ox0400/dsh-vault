/**
 * The strength indicator shown after an entry title: **three stars in six
 * half-star steps**.
 *
 *   units:  0     1     2     3     4     5     6
 *   shows:  ☆☆☆   ½☆☆   ★☆☆   ★½☆   ★★☆   ★★½   ★★★
 *
 * A half star is not a Unicode glyph (most fonts lack one) — the component
 * stacks the same three `★` twice and clips the coloured copy to a percentage,
 * so these units drive a `width`, not a character.
 */
export type StrengthTone = 'weak' | 'fair' | 'strong'

/** Half-star units for a 0–100 score: 0 → none, 6 → full marks. */
export function strengthUnits(score: number | undefined): number {
  if (score === undefined || !Number.isFinite(score) || score <= 0) return 0
  return Math.min(6, Math.max(0, Math.round((score / 100) * 6)))
}

/** Colour band: 0–2 units weak, 3–4 fair, 5–6 strong. */
export function strengthTone(units: number): StrengthTone {
  return units <= 2 ? 'weak' : units <= 4 ? 'fair' : 'strong'
}

/** Clip width, as a percentage of the three-star track. */
export function strengthWidthPercent(units: number): number {
  const clamped = Math.min(6, Math.max(0, units))
  return (clamped / 6) * 100
}
