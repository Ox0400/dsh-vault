/**
 * Standalone tsdown config for dsh-vault's browser bundle. Mirrors the
 * harness clientBundle() preset (packages/client/tsdown.client.ts): emits a
 * closure-factory artifact lib/client.js that registers through
 * window.__ModuleLoader__.load, keeps platform modules external, and inlines
 * everything else.
 */
import { fileURLToPath } from 'node:url'
import { dirname, relative, resolve } from 'node:path'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { transform } from 'lightningcss'

/**
 * Repository root for sourcemap path rewriting. When the bundle is built
 * inside the harness monorepo (../deepseek-harness exists) the transform maps
 * sources back to the dsh-vault tree; standalone builds (git install, npm
 * pack) have no sibling checkout, so the transform falls back to passing
 * paths through untouched.
 */
const REPOSITORY_ROOT = fileURLToPath(new URL('../deepseek-harness', import.meta.url))
const HAS_SIBLING_REPO = existsSync(REPOSITORY_ROOT)

/** Virtual-id wrapper keeping module CSS away from tsdown's own css pipeline. */
const CSS_VIRTUAL_PREFIX = '\0dsh-css:'
const CSS_VIRTUAL_SUFFIX = '.mjs'

/** Platform modules resolved from the loader module table (see packages/client/web/src/platform.ts). */
const PLATFORM_MODULES = [
  'react',
  'react/jsx-runtime',
  'react-dom',
  'react-dom/client',
  '@deepseek-ai/cordis',
  '@deepseek-ai/cordis-plugin-hmr',
  '@deepseek-ai/cordis-plugin-loader',
  '@deepseek-ai/cordis-plugin-timer',
  '@deepseek-ai/dsh-api-gateway',
  '@deepseek-ai/dsh-api-remotes',
  '@deepseek-ai/dsh-client-connection',
  '@deepseek-ai/dsh-client-hmr',
  '@deepseek-ai/dsh-client-locale',
  '@deepseek-ai/dsh-client-modules',
  '@deepseek-ai/dsh-client-runtime',
  '@deepseek-ai/dsh-client-ui-layout',
  '@deepseek-ai/dsh-client-ui-settings',
  '@deepseek-ai/dsh-client-ui-settings-general',
  '@deepseek-ai/dsh-client-ui-settings-models',
  '@deepseek-ai/dsh-client-ui-settings-plugin-inventory',
  '@deepseek-ai/dsh-client-ui-settings-plugins',
  '@deepseek-ai/dsh-client-ui-slots',
  '@deepseek-ai/dsh-client-ui-theme',
  '@deepseek-ai/dsh-client-web-react',
  '@deepseek-ai/dsh-cordis-client-runner',
  '@deepseek-ai/dsh-session',
  '@deepseek-ai/dsh-typert-registry',
  '@deepseek-ai/dsh-typert-protocol',
]

/** Browser-safe wire layers with no shared runtime identity (inline is fine). */
const INLINE_SAFE = /^@deepseek-ai\/dsh-(host-apiproxy|session|llm|tools|brand)(\/|$)/

export default {
  name: 'dsh-vault/client',
  entry: { client: 'src/client/index.ts' },
  outDir: 'lib',
  format: 'cjs',
  platform: 'browser',
  dts: false,
  sourcemap: true,
  clean: false,
  external: PLATFORM_MODULES,
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production'),
    'import.meta.env.MODE': JSON.stringify(process.env.NODE_ENV ?? 'production'),
    'import.meta.env': JSON.stringify({ MODE: process.env.NODE_ENV ?? 'production' }),
  },
  noExternal: (id: string) => (PLATFORM_MODULES.includes(id) ? undefined : true),
  plugins: [{
    name: 'dsh-vault-bundle-purity',
    resolveId(source: string) {
      if (!source.startsWith('@deepseek-ai/')) return null
      if (PLATFORM_MODULES.includes(source)) return null
      if (INLINE_SAFE.test(source)) return null
      // Type-only imports are erased before this gate; a value import here
      // would duplicate a runtime instance — reject it.
      throw new Error(`dsh-vault client bundle purity: "${source}" is not a platform module or inline-safe wire layer`)
    },
  }, {
    name: 'dsh-vault-css-modules-inline',
    resolveId(source: string, importer: string | undefined) {
      if (!source.endsWith('.module.css')) return null
      const abs = importer !== undefined ? resolve(dirname(importer), source) : source
      return CSS_VIRTUAL_PREFIX + abs + CSS_VIRTUAL_SUFFIX
    },
    async load(virtualId: string) {
      if (!virtualId.startsWith(CSS_VIRTUAL_PREFIX)) return null
      const fileId = virtualId.slice(CSS_VIRTUAL_PREFIX.length, -CSS_VIRTUAL_SUFFIX.length)
      this.addWatchFile(fileId)
      const source = await readFile(fileId)
      const { code, exports: cssExports } = transform({
        filename: fileId,
        code: source,
        cssModules: { pattern: '[hash]_[local]' },
        minify: true,
      })
      const classMap: Record<string, string> = {}
      for (const [local, exp] of Object.entries(cssExports ?? {})) classMap[local] = exp.name
      const tagId = `dsh-vault/${fileId.split('/').pop()!}`
      return [
        `const css = ${JSON.stringify(code.toString())};`,
        `const tagId = ${JSON.stringify(tagId)};`,
        `if (typeof document !== 'undefined' && document.querySelector('style[data-plugin-css=' + JSON.stringify(tagId) + ']') === null) {`,
        `  const tag = document.createElement('style');`,
        `  tag.dataset.plugin = ${JSON.stringify('dsh-vault')};`,
        '  tag.dataset.pluginCss = tagId;',
        '  tag.textContent = css;',
        '  document.head.appendChild(tag);',
        '}',
        `export default ${JSON.stringify(classMap)};`,
      ].join('\n')
    },
  }],
  outputOptions: {
    entryFileNames: 'client.js',
    sourcemapPathTransform(source: string, sourcemapPath: string) {
      if (!source.startsWith('.')) return source
      if (!HAS_SIBLING_REPO) return source
      const physical = resolve(dirname(sourcemapPath), source)
      const repositoryPath = relative(REPOSITORY_ROOT, physical).split('/').join('/')
      return repositoryPath.startsWith('dsh-vault/') ? `../../../${repositoryPath}` : source
    },
    banner: `window.__ModuleLoader__.load({ id: "dsh-vault", factory: (require) => {`,
    footer: 'return module.exports; } });',
    intro: 'var module = { exports: {} }; var exports = module.exports;',
  },
}
