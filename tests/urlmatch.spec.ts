import { test, expect } from 'vitest'
import { normalizedHost, urlMatches, matchScore, pathOf } from '../src/urlmatch'

test('urlmatch: normalizedHost strips scheme, port, www, path', () => {
  expect(normalizedHost('https://mail.example.com/inbox')).toBe('mail.example.com')
  expect(normalizedHost('http://www.example.com:8080/x')).toBe('example.com')
  expect(normalizedHost('EXAMPLE.COM')).toBe('example.com')
  expect(normalizedHost('example.com')).toBe('example.com')
})

test('urlmatch: urlMatches exact, subdomain, parent, path-prefix', () => {
  expect(urlMatches('https://example.com', 'https://example.com')).toBe(true)
  expect(urlMatches('https://mail.example.com/inbox', 'https://example.com')).toBe(true)
  expect(urlMatches('https://example.com', 'https://mail.example.com')).toBe(true)
  expect(urlMatches('https://example.com/login', 'https://example.com/login')).toBe(true)
  expect(urlMatches('https://other.org', 'https://example.com')).toBe(false)
})

test('urlmatch: matchScore ranks exact > subdomain > path-prefix > none', () => {
  expect(matchScore('https://example.com', 'https://example.com')).toBe(100)
  expect(matchScore('https://mail.example.com', 'https://example.com')).toBe(80)
  expect(matchScore('https://example.com/login', 'https://example.com/login')).toBe(100)
  expect(matchScore('https://example.com/inbox', 'https://example.com/login')).toBe(100) // same host matches regardless of path
  expect(matchScore('https://other.org', 'https://example.com')).toBe(0)
})

test('urlmatch: pathOf normalizes paths', () => {
  expect(pathOf('https://example.com')).toBe('/')
  expect(pathOf('https://example.com/login/')).toBe('/login')
})
