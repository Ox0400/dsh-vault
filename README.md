# dsh-vault — 加密凭据保险库插件

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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
| `vault_search` | 跨标题/分类/用户名/邮箱/手机/主机/端口/URL/备注/标签/自定义字段（含数字/布尔/嵌套值）检索，返回无密摘要；`limit` 须为 1–100 的整数 |
| `vault_update` | 按 id 更新字段（未提供的字段保留；空字符串清除该字段；`title` 可改名） |
| `vault_delete` | 按 id 删除条目（不可恢复） |
| `vault_totp` | 为存储的 otpSecret（或直接传入的 Base32/otpauth URI）生成当前 6 位动态验证码 |
| `vault_generate_password` | 生成强随机密码（长度/字符集/去歧义/分组可选；`group` 须为 ≥2 的整数） |

**典型开发场景**：存一条 SSH 凭据（`kind: ssh` + host/port/username/password 或 privateKey），开发时让模型 `vault_search` 找主机、`vault_get` 取连接信息；存 API 网关的 `api-key`/`oauth` 条目管理 access/refresh token 轮换。

## 安装

dsh-vault 是一个 **bundle**(声明 `dsh.bundle` 的包):安装到 profile 后,它的 `cordis.patch.yml` 会自动插入 `vault` 插件行(按包名 `dsh-vault` 引用,主密码经 `DSH_VAULT_PASSWORD` 环境变量注入)。包内含自包含构建脚本,git 安装时会自动编译 `lib/`。

### 方式一：从 GitHub 安装(推荐)

```sh
dsh plugin --profile demo add github:Ox0400/dsh-vault
```

git 安装拉取的是**源码**,`prepare` 脚本会在安装时构建 `lib/`。pnpm ≥10 默认阻止 git 依赖执行构建脚本,首次 `add` 会失败并打印一个 `allowBuilds` 键——把**精确的键**(含仓库 URL 的那行)加入 profile 的 `pnpm-workspace.yaml`,再重新 `add`:

```yaml
# $DSH_HOME/profiles/<name>/pnpm-workspace.yaml
allowBuilds:
  dsh-vault@https://codeload.github.com/Ox0400/dsh-vault/tar.gz/<sha>: true
```

建议**锁定 commit** 再安装,避免上游推送改变安装时执行的代码:

```sh
dsh plugin --profile demo add github:Ox0400/dsh-vault#<sha>
```

允许构建 = 允许该包的代码在你的机器上于安装时执行;只对你信任的源码授予。

### 方式二：本地 clone 开发

```sh
git clone git@github.com:Ox0400/dsh-vault.git
cd dsh-vault
pnpm install    # 安装 devDependencies(typescript/tsdown/vitest 等)
pnpm build      # 构建 host 侧 lib/*.js 与浏览器 bundle lib/client.js
pnpm test       # 运行 41 项 vitest 测试
```

> 测试需要 harness 的 `dsh-llm`/`dsh-system-prompt` 等 peer 包,在 harness monorepo 内开发时由 workspace 链接提供。

### 方式三：本地路径安装到 profile

```sh
dsh plugin --profile demo add /绝对/路径/to/dsh-vault
```

启动前设置主密码:

```sh
export DSH_VAULT_PASSWORD='你的强主密码'
```

`dsh plugin --profile demo remove dsh-vault` 卸载(同时移除依赖与 layer)。

## 配置

| 配置项 | 说明 |
|---|---|
| `masterPassword` | 直接配置主密码（会出现在 cordis.yml 中，不推荐） |
| `masterPasswordEnv` | 环境变量名，运行时从该变量读取主密码（推荐） |
| `path` | 保险库文件路径，默认 `$DSH_HOME/vault/default.json` |
| `name` | 保险库名，用于默认路径（如 `name: work` → `$DSH_HOME/vault/work.json`） |

首次调用任一工具时自动创建保险库；之后每次启动用主密码重新解锁。**忘记主密码 = 数据永久丢失**（无后门，这是设计使然）。

## 开发

```sh
# 单元 + 集成测试（vitest，41 项）
pnpm test            # 或 npx vitest run

# 类型检查
pnpm typecheck       # tsc -p tsconfig.json --noEmit

# 构建（host 侧 lib/*.js 与浏览器 bundle lib/client.js）
pnpm build           # = build:host (tsc) + build:client (tsdown)

# 打包发布（可选：npm pack 产物可直接 `dsh plugin add ./dsh-vault-0.1.0.tgz`）
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
npm pack                  # 产出 tarball → dsh plugin add ./dsh-vault-0.1.0.tgz
npm publish --access public   # 发布 npm → dsh plugin add dsh-vault
```

## 安全边界与已知限制

- 主密码强度决定保险库强度；建议 ≥ 16 字符高熵。
- scrypt 成本参数（N=32768, r=8, p=1）已持久化在文档中，可随版本提升，旧文档仍可解密。
- 明文凭据仅存在于进程内存与 `vault_get` 显式读取期间；`vault_search`/`vault_update` 的输出均不含密码、密钥与令牌。`vault_get` 返回的秘密会进入该次工具调用结果（模型上下文），调用方应避免在对话中复述。
- 本插件面向单机/个人部署；团队共享保险库不在范围内。
