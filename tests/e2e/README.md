# Browser E2E checks

These scripts drive the real `dsh web` in a Chromium that carries a valid
session cookie (minted from `~/.dsh/.credentials.yml` by `helper.mjs`). They are
not part of `vitest` — run them by hand after a client change:

```bash
node tests/e2e/theme-check.mjs      # dual-theme tokens, ring track, attach row
node tests/e2e/polish-check.mjs     # trash empty state, audit relative-age hint
node tests/e2e/contrast-audit.mjs   # WCAG sweep over every tab in both themes
```

## Safety rules (enforced by the helper)

Every script must run against a **throwaway vault**, never the real one:

- `useVault(page, 'test')` creates the vault if needed and then verifies that it
  is really the active one — it **throws** otherwise.
- `useVault(page, 'default')` is refused unless `DSH_E2E_ALLOW_DEFAULT=1`
  (read-only checks only).
- `installDialogs(page)` answers `window.prompt` from a queue. Never rely on a
  bare `dialog.accept()`: an empty answer silently aborts vault creation, and
  the script then keeps running against whatever vault was active.
- `wipeVault(page, name)` re-asserts the active vault before deleting anything.
- Scripts that change the host theme must set it back to the user's previous
  choice (`跟随系统` / `浅色` / `深色`) before exiting.
- Switchers live in the Vault header; the host's own theme buttons live on the
  `通用设置` page — after toggling a theme, navigate back with
  `openSettings(page, '凭据库')` before touching Vault tabs.

## Reading the contrast audit

`contrast-audit.mjs` walks every element that owns visible text, resolves the
*effective* background by walking the ancestor chain and compositing
translucent layers, multiplies in the element's `opacity`, and reports anything
under 4.5:1 (3:1 for large or bold text).

Two traps it is written to avoid:

1. **Colour formats.** `color-mix()` and friends are serialised as
   `color(srgb …)`, not `rgb()`. A parser that only understands `rgb()` will
   silently skip exactly the values it was meant to check — report unparsed
   colours instead of skipping them.
2. **`opacity` is part of the colour.** Dimming a row to 0.8 turns a 5.8:1
   colour into 3.87:1. Prefer a muted token over `opacity` on text.
