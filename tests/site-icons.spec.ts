/** Offline brand-glyph resolution (simple-icons data merged module). */
import { test, expect } from 'vitest'
import { siteGlyph } from '../src/client/site-icons.ts'

const hit = (url: string) => {
  const g = siteGlyph(url)
  return g !== undefined ? g.c : undefined
}

test('site icons: v16 brand hosts resolve to brand colors', () => {
  expect(hit('https://github.com/org/repo')).toBe('#181717')
  expect(hit('https://gitlab.com/x')).toBe('#FC6D26')
  expect(hit('https://gitee.com/x')).toBe('#C71D23')
  expect(hit('https://hub.docker.com/team')).toBe('#2496ED')
  expect(hit('https://www.google.com/')).toBe('#4285F4')
  expect(hit('https://mail.google.com/')).toBe('#EA4335') // gmail entry? assert non-empty below
})

test('site icons: v11 legacy brands (removed from newer simple-icons)', () => {
  expect(hit('https://console.aws.amazon.com/iam')).toBe('#232F3E')
  expect(hit('https://aws.amazon.com/')).toBe('#232F3E')
  expect(hit('https://portal.azure.com/')).toBe('#0078D4')
  expect(hit('https://dev.azure.com/org')).toBe('#0078D7')
  expect(hit('https://acme.slack.com/apps')).toBe('#4A154B') // subdomain suffix
  expect(hit('https://www.linkedin.com/in/me')).toBe('#0A66C2')
  expect(hit('https://dashboard.heroku.com/')).toBe('#430098')
})

test('site icons: atlassian workspace suffix and fallbacks', () => {
  expect(hit('https://myorg.atlassian.net/jira')).toBe('#0052CC')
  expect(hit('https://example.com/unknown')).toBeUndefined()
  expect(siteGlyph('not a url')).toBeUndefined()
  expect(siteGlyph(undefined, undefined)).toBeUndefined()
  expect(siteGlyph(undefined, 'github.com')?.c).toBe('#181717') // ssh host fallback
})
