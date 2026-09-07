/** Pure judgment for the editor password-risk banner. Returns which risks
 * apply. `reusedOther` = number of OTHER entries sharing this exact password
 * (the entry being edited, when its stored password already equals it, is not
 * counted against the user). No secrets leave this module. */
export interface PwRisk {
  weak: boolean
  reusedOther: number
}
export function judgePasswordRisk(
  password: string,
  strengthScore: number | null,
  reusedGroups: Array<{ value?: unknown; entries?: Array<unknown> }>,
  isEditingSamePassword: boolean,
): PwRisk {
  const pw = (password ?? '').trim()
  if (pw.length === 0) return { weak: false, reusedOther: 0 }
  const dup = reusedGroups.find(g => g.value === pw)
  const total = dup !== undefined && Array.isArray(dup.entries) ? dup.entries.length : 0
  return {
    weak: strengthScore !== null && strengthScore < 40,
    reusedOther: Math.max(0, total - (isEditingSamePassword ? 1 : 0)),
  }
}
