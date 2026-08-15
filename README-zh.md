# dsh-vault — 加密凭据保险库插件

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/dsh-vault?color=cb3837&logo=npm)](https://www.npmjs.com/package/dsh-vault)
[![GitHub Release](https://img.shields.io/github/v/release/Ox0400/dsh-vault?logo=github)](https://github.com/Ox0400/dsh-vault/releases)
[![npm downloads](https://img.shields.io/npm/dm/dsh-vault)](https://www.npmjs.com/package/dsh-vault)
[![GitHub issues](https://img.shields.io/github/issues/Ox0400/dsh-vault)](https://github.com/Ox0400/dsh-vault/issues)

dsh-vault 是一个面向 DeepSeek Harness 的安全加密插件：把你在使用 AI 过程中产生的**用户名、邮箱、手机号、密码、二次动态密钥（TOTP）** 以及开发工作流中常用的 **SSH 连接、API Key、Secret、OAuth access/refresh token** 等敏感凭据加密存储，并通过模型工具提供增删改查、检索、密码生成与动态验证码生成能力。

**安全性与实现**

- **零外部依赖**：全部加密基于 Node 内置 `node:crypto`（AES-256-GCM 认证加密 + scrypt 密钥派生 + RFC 6238 TOTP），不引入任何第三方加密库。
- **主密码**：所有条目由 `scrypt(主密码, 盐)` 派生的 256 位密钥经 **AES-256-GCM** 加密。密钥永不落盘；进程内解锁后缓存复用（避免每次写入重复 scrypt），重启后重新派生。
- **防篡改**：GCM 认证标签 + 文档内固定明文的校验信封，错误主密码、密文被改动都会立即失败，绝不返回垃圾数据。
- **磁盘无明文**：加密文档中不含任何明文凭据；每个条目独立随机 nonce。
- **原子写入**：复用 harness 的 `writeFileAtomic` + 文件锁，任何时刻磁盘上都是完整的新/旧文档；进程内写入串行化、跨进程写入加锁。
- **检索不泄密**：`vault_search` 只返回摘要（id/标题/分类/用户名/邮箱/手机/主机/端口/URL/标签），**绝不返回密码、密钥、令牌与 TOTP 密钥**；完整凭据只能通过 `vault_get` 按 id 显式读取。

## 条目模型

每条记录包含一个 `title`、一个可选 `kind` 分类，以及任意组合的字段：

| 字段 | 说明 |
|---|---|
| `kind` | `login`（默认）/ `ssh` / `api-key` / `secret` / `oauth` / `custom` |
| `username` / `email` / `phone` | 账号身份 |
| `password` | 密码 |
| `host` / `port` | SSH 主机与端口（如 `db.internal` / `2222`） |
| `privateKey` | SSH 私钥（PEM） |
| `apiKey` | API 密钥 |
| `secret` | 通用 Secret（client secret、共享密钥等） |
| `accessToken` / `refreshToken` / `expiresAt` | OAuth 令牌对与过期时间（epoch millis） |
| `otpSecret` | TOTP 密钥（Base32 或 otpauth:// URI） |
| `url` / `notes` / `tags` | 元信息 |
| `fields` | 任意附加键值（如 `{"region": "us-east-1"}`），可检索 |

## 工具

| 工具 | 作用 |
|---|---|
| `vault_add` | 新增条目（上述字段任意组合；空字符串/空数组字段会被忽略） |
| `vault_get` | 按 id 读取完整条目（含全部密钥） |
| `vault_search` | 跨标题/分类/用户名/邮箱/手机/主机/端口/URL/备注/标签/自定义字段（含数字/布尔/嵌套值；空格分隔多词 OR 命中）检索；可选 `createdAfter`/`createdBefore` 毫秒时间戳过滤；返回无密摘要；`limit` 须为 1–100 的整数 |
| `vault_update` | 按 id 更新字段（未提供的字段保留；空字符串清除该字段；`title` 可改名；`rotationDays: 0` 清除轮换 = 永不轮换） |
| `vault_compare` | 逐字段比较两个条目（`onlyA`/`onlyB`/`differ`/`equal`）——只返回字段名，绝不返回密钥值 |
| `vault_rename` | 一次调用即可重命名条目（`vault_update` 的快捷方式） |
| `vault_delete` | 软删除条目（移入回收站，磁盘上仍加密保留） |
| `vault_restore` / `vault_purge` / `vault_restore_recent` | 从回收站恢复 / 永久删除 / 撤销最近一次删除 |
| `vault_lock` / `vault_unlock` | 显式锁定保险库（清空内存密钥）/ 重新解锁 |
| `vault_totp` | 为存储的 otpSecret（或直接传入的 Base32/otpauth URI）生成当前 6 位动态验证码 |
| `vault_generate_password` | 生成强随机密码（长度/字符集/分组可选）**或易记口令短语**（`passphrase: true`，EFF 词表，`words`/`separator`/`wordDigits`） |
| `vault_strength` | 零依赖密码强度评估（0–100 分，weak/fair/strong/very strong） |
| `vault_rekey` | 原地升级 scrypt KDF 参数并重加密 |
| `vault_backup` | 带时间戳的加密备份，支持保留策略：超过 `maxBackups`（默认 10）的旧备份自动清理 |
| `vault_import_csv` | 从 CSV 批量导入凭据（自定义列变为 fields；`overwrite: true` 合并字段到已有条目，不再产生重复） |
| `vault_apply_tags` | 按查询批量增/删/替换条目标签（支持 dry-run，不含密钥） |
| `vault_totp_uri` | 为存储的或裸 TOTP 密钥生成 otpauth:// 配置 URI |
| `vault_switch` / `vault_list` | 按名称切换当前保险库 / 列出可用保险库 |
| `vault_rotation` | 报告已过期 / 待轮换 / 即将过期的凭据；`soonWindowDays`（1-90，默认 7）调整即将窗口（不含密钥） |
| `vault_health` | 保险库健康扫描：弱密码/复用凭据、未启用 2FA、不安全的 http:// 站点,以及整体安全评分（0–100） |
| `vault_breach_check` | Watchtower 风格泄露扫描：对接 Have I Been Pwned（k-anonymity,仅发送 SHA-1 前缀）,附离线常见密码兜底 |
| `vault_merge` | 合并一个条目到另一个；`keepSource: true` 保留源条目 |
| `vault_quick_add` | 快速录入（标题 + 一个密钥），支持 tags/notes |
| `vault_expiry` | 设置/清除过期（`expiresAt: 0` 移除） |
| `vault_stats` | 概览计数，含 `trashCount`（不含密钥） |
| `vault_verify` | 校验单个条目或审计全部条目（`all: true`）：按 kind 检查完整性、端口/过期合理性（不含密钥） |
| `vault_duplicates` | 查找重复分组：`mode` = `both`（默认）/ `title` / `content`（不含密钥） |
| `vault_report` | 可打印清单，含到期/轮换列与统计页脚（不含密钥） |
| `vault_export` / `vault_import` | 整库加密备份/迁移（独立导出密码） |
| `vault_fill` | 按 host/URL/用户名/标题匹配条目并返回其凭据 |
| `vault_env` | 把标记 env 的条目（tags 含 `env`）渲染为 `KEY=VALUE` 行 |
| `vault_templates` | 返回某类凭据（ssh/api-key/oauth 等）的推荐字段 |

**典型开发场景**：存一条 SSH 凭据（`kind: ssh` + host/port/username/password 或 privateKey），开发时让模型 `vault_search` 找主机、`vault_get` 取连接信息；存 API 网关的 `api-key`/`oauth` 条目管理 access/refresh token 轮换。

## 安装

dsh-vault 是一个 **bundle**(声明 `dsh.bundle` 的包):安装到 profile 后,它的 `cordis.patch.yml` 会自动插入 `vault` 插件行(按包名 `dsh-vault` 引用,主密码经 `DSH_VAULT_PASSWORD` 环境变量注入)。包内含自包含构建脚本,git 安装时会自动编译 `lib/`。

以下四种安装方式均已**端到端实测通过**(安装 → bundle 层被识别 → 插件激活且 7 个 `vault_*` 工具全部注册 → `vault_add`/`vault_get` 真实往返成功 → 卸载移除 layer):

| 方式 | 命令 | 需构建 | 需 allowBuilds |
|---|---|---|---|
| npm | `add dsh-vault` | 否(预构建 lib) | 否 |
| GitHub | `add github:Ox0400/dsh-vault#v0.1.1` | 是(prepare) | 是(首次) |
| 本地路径 | `add /绝对/路径/to/dsh-vault` | 否(链接已构建源码) | 否 |
| tarball | `add ./dsh-vault-0.1.1.tgz` | 否(预构建 lib) | 否 |

### 方式一：从 npm 安装(最省事)

```sh
dsh plugin --profile demo add dsh-vault
```

npm 包自带**预构建的 `lib/` 产物**,无需 allowBuilds、无需本地编译,安装即用。启动前设置主密码:

```sh
export DSH_VAULT_PASSWORD='你的强主密码'
```

### 方式二：从 GitHub 安装(锁 tag 或 commit)

```sh
dsh plugin --profile demo add github:Ox0400/dsh-vault#v0.1.1
```

git 安装拉取的是**源码**,`prepare` 脚本会在安装时构建 `lib/`。pnpm ≥10 默认阻止 git 依赖执行构建脚本。实测流程:

1. 执行 `add` 命令——会因 `allowBuilds` 失败,并打印需要放行的**精确键**(含仓库 URL 与解析后的 commit hash 的那行):

   ```text
   allowBuilds:
     dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
   ```

2. 把该精确键追加到 profile 的 `pnpm-workspace.yaml`(`$DSH_HOME/profiles/<name>/pnpm-workspace.yaml`):

   ```yaml
   packages:
     - .
   allowBuilds:
     dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
   ```

3. 重新执行 `add`——pnpm 现在会运行 `prepare` 脚本,构建 `lib/` 并完成安装。

建议**锁定 tag/commit** 再安装,避免上游推送改变安装时执行的代码。允许构建 = 允许该包的代码在你的机器上于安装时执行;只对你信任的源码授予。

### 方式三：本地路径安装到 profile

```sh
dsh plugin --profile demo add /绝对/路径/to/dsh-vault
```

pnpm 将 checkout 链接进 profile;只要 `lib/` 存在(必要时先在 checkout 里执行 `pnpm build`)即被识别为 bundle。

### 方式四：本地 tarball 安装

```sh
npm pack && dsh plugin --profile demo add ./dsh-vault-0.1.1.tgz
```

tarball 自带预构建 `lib/` 产物,无需构建或 allowBuilds。

`dsh plugin --profile demo remove dsh-vault` 卸载(同时移除依赖与 layer)。

## 配置

| 配置项 | 说明 |
|---|---|
| `masterPassword` | 直接配置主密码（会出现在 cordis.yml 中，不推荐） |
| `masterPasswordEnv` | 环境变量名，运行时从该变量读取主密码（推荐） |
| `path` | 保险库文件路径，默认 `$DSH_HOME/vault/default.json` |
| `name` | 保险库名，用于默认路径（如 `name: work` → `$DSH_HOME/vault/work.json`） |
| `accessMode` | 模型工具的访问策略，三态：`readonly`（只读，工具与设置页的增/改/删全部被拒绝）、`ask`（默认——写入前询问，每次增/改/删都会走 harness 审批通道请你确认）、`auto`（自动读写，无需逐次确认）。设置页提供同样的三选一下拉并持久化到 `<vault 目录>/access.json`。 |
| `autoCapture` | `false`（默认）。设为 `true` 时，系统提示词会指导模型识别对话中出现的凭据，并**按用户偏好**用 `vault_add` 提供保存。 |
| `lockTimeoutSeconds` | 自动锁库：空闲超过该秒数后自动重新锁定（清空内存密钥），之后每次读写需 `vault_unlock`。`0`/缺省为禁用。 |
| `exportPasswordEnv` | 存放 `vault_export`/`vault_import` 导出密码的环境变量名（绝不能作为模型参数传入）。 |
| `backupRetention` | 保留多少个加密备份（默认 10）；`vault_backup` 自动清理更旧的副本。 |

示例：

```yaml
- id: vault
  name: dsh-vault
  config:
    masterPasswordEnv: DSH_VAULT_PASSWORD
    accessMode: ask
    autoCapture: true
```

`autoCapture: true` 时，当你在对话中分享凭据（如 "我的 npm token 是 npm_…"），助手会提议存入；你同意后立即调用 `vault_add`。`autoCapture` 关闭时，只有你明确要求才保存。设置页显示当前模式（只读 / 写入前询问 / 自动读写）可用下拉切换，还有**自动捕获开关**（检测对话中的凭据 → 提议保存）、类型筛选、健康与轮换摘要、回收站视图、以及默认遮罩的密钥字段（显示/隐藏切换）。

首次调用任一工具时自动创建保险库；之后每次启动用主密码重新解锁。**忘记主密码 = 数据永久丢失**（无后门，这是设计使然）。

## 开发

本地 clone 开发:

```sh
git clone git@github.com:Ox0400/dsh-vault.git
cd dsh-vault
pnpm install    # 安装 devDependencies(typescript/tsdown/vitest 等)
pnpm build      # 构建 host 侧 lib/*.js 与浏览器 bundle lib/client.js
pnpm test       # 运行 41 项 vitest 测试
```

> 测试需要 harness 的 `dsh-llm`/`dsh-system-prompt` 等 peer 包,在 harness monorepo 内开发时由 workspace 链接提供。

常用命令:

```sh
# 单元 + 集成测试（vitest，41 项）
pnpm test            # 或 npx vitest run

# 类型检查
pnpm typecheck       # tsc -p tsconfig.json --noEmit

# 构建（host 侧 lib/*.js 与浏览器 bundle lib/client.js）
pnpm build           # = build:host (tsc) + build:client (tsdown)

# 打包发布（可选：npm pack 产物可直接 `dsh plugin add ./dsh-vault-0.1.1.tgz`）
npm pack
```

仓库内所有测试通过：41/41（crypto/TOTP/密码生成/store CRUD/网关/集成）。

## 打包与发布

本包是标准 npm bundle:

- `dsh.bundle.patch` → `cordis.patch.yml`(安装到 profile 后自动应用的 layer)
- `dsh.client` → 浏览器端声明(`exports["./client"]` 指向 `lib/client.js`)
- `prepare` 脚本 → git 安装时自包含构建(`tsc` host + `tsdown` client)
- 运行时依赖全部走 `peerDependencies`(由宿主 harness 提供,避免重复实例)

可选发布途径:

```sh
npm pack                  # 产出 tarball → dsh plugin add ./dsh-vault-0.1.1.tgz
npm publish --access public   # 发布 npm → dsh plugin add dsh-vault
```

## 安全边界与已知限制

- 主密码强度决定保险库强度；建议 ≥ 16 字符高熵。
- scrypt 成本参数（N=32768, r=8, p=1）已持久化在文档中，可随版本提升，旧文档仍可解密。
- 明文凭据仅存在于进程内存与 `vault_get` 显式读取期间；`vault_search`/`vault_update` 的输出均不含密码、密钥与令牌。`vault_get` 返回的秘密会进入该次工具调用结果（模型上下文），调用方应避免在对话中复述。
- 本插件面向单机/个人部署；团队共享保险库不在范围内。
