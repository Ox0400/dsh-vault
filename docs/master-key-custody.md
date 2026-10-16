# 主密钥托管方案（调研与设计草案）

> 状态：**待评审**。本文先回答"怎么做、会不会弹窗、能不能用三方托管"，等确定方案后再实现。
> 所有标 🔬 的结论都有本机实测支撑；标 📚 的来自文档（附来源）；标 ⚠️ 的是未决/有风险的假设。

## 0. 一句话结论（先给答案）

| 问题 | 结论 |
|---|---|
| macOS 上能不能做 | **能，而且实测零弹窗**。keychain 的写入与读取都走 `/usr/bin/security`（同一个 Apple 签名二进制），条目的 ACL 自动被满足；读取 **22–44ms**。🔬 |
| 会不会频繁弹窗 | **正常路径不会**。🔬 但**钥匙串处于锁定状态时**，`security` 的行为不确定：可能弹出"解锁钥匙串"对话框并**阻塞**（实测遇到一次），也可能 **31–47ms 内以退出码 152 快速失败**（干净复测四次都是这个）。🔬 所以实现必须**给每次读取加超时**，并按"不可用"降级，绝不能让它挂住 harness。 |
| 会不会每次操作都触发 | 不会，**设计上每个进程只解析一次**（解锁时），锁库即清空；绝不按操作读取。 |
| 三方（1Password 等）能不能托管 | **能，但不要为每家写适配器**：统一成"**跑一条用户配置的命令、从 stdout 读秘密**"（上游 DSH 的 Dev Notes 里把这叫 helper-command provider）。1Password / Bitwarden / pass / Vault 都只是不同的命令行。📚（细节见第 5 节） |
| 该存"主密码"还是"包裹密钥" | **短期存主密码（零格式变更，立刻可用）；长期做密钥包裹**。理由不是性能（解锁才 56–80ms🔬），而是**存主密码会把一个可能被复用的口令交给任何能读钥匙串的东西**；包裹方案只泄露这一个库的密钥。见 §3。 |
| Windows | **纯 Node 下读回凭据不可行**（`cmdkey` 只能写不能读）。要么明确不支持，要么走 DPAPI 加密文件（无弹窗、绑定用户账号）。⚠️ 见 §4.4 |

## 1. 要解决的问题，以及不承诺什么

**要解决**：现在主密码只能放在 `cordis.patch.yml`（明文，易被提交/截图/进日志）或环境变量里（易被 `ps`/日志/子进程继承泄漏）。托管的目标是**让磁盘上不再有明文主密码**，同时不降低日常使用的顺畅度。

**不承诺**（与 README 的威胁模型保持一致）：

- 不解决**同进程的其他插件**能读到解密值——它们在同一个进程里，钥匙串托管改变不了这一点；
- 不解决**被攻陷的账号/机器**：以你的身份运行的进程同样可以向钥匙串索取同一个条目（macOS 的 ACL 区分的是**应用**，而这里所有插件都在同一个 node 应用身份下）；
- 不承诺"系统弹窗一次都没有"：锁定/被拒时可能弹窗，见 §2.3。

也就是说，托管带来的是**静态暴露面的收敛**（磁盘、备份、配置泄漏、环境继承），不是进程内隔离。这句话必须写进 README，否则又变成一次误导。

## 2. macOS：实测结果（这一节的每个数字都是本机跑出来的）

实测环境：macOS 26.3（25D125），`/usr/bin/security`，Node v24。所有实验都在**临时钥匙串**里做，最后连登录钥匙串里那条临时项一起删掉了。

### 2.1 三种 ACL 写法，读取有区别吗？——没有

在临时钥匙串里分别用三种方式写入，然后（钥匙串处于解锁状态）从 node 子进程读取：

| 写入方式 | 读取结果 |
|---|---|
| 不加 `-T` / `-A`（默认 ACL） | ✅ 直接读到，无弹窗 |
| `-T /usr/bin/security` | ✅ 直接读到，无弹窗 |
| `-A`（允许任何应用） | ✅ 直接读到，无弹窗 |

**原因**（📚 与实测一致）：ACL 校验的是"**发起请求的应用**"，而写入和读取都是 `/usr/bin/security` 这个 Apple 签名二进制在请求——不是调用它的 node。所以**同一个 `security` 写、同一个 `security` 读，默认就满足 ACL**。这也解释了为什么"由钥匙串访问.app 创建的条目会让 CLI 弹窗"，以及为什么**不需要 `-A`**（`-A` 会让任何应用都能读，等于白白放弃这一层）。

### 2.2 真实场景（登录钥匙串）端到端

用一次性临时条目在**登录钥匙串**里走了一遍插件的真实调用路径：

```
security add-generic-password -s <service> -a <account> -w <密码> -U   # 用户一次性动作
node 里 execFile('/usr/bin/security', ['find-generic-password','-s',…,'-a',…,'-w'])
```

结果：**写入成功 → 从 node 子进程读回 ✅ 无弹窗 → 删除成功**。

再做了一次完整原型（建真实保险库 → 密码进钥匙串 → 只从钥匙串解析 → 解锁真实库）：

```
=== 3. 像插件一样解析并解锁 ===
  从钥匙串取回: ✅ 与写入一致 (22ms)
  解锁成功: 1 条 (56ms, 含 scrypt 派生)
```

另一次运行是 44ms / 80ms。**读取延迟 22–159ms**（首次含进程启动），解锁额外 56–80ms（scrypt）。也就是说"每次会话多花约 0.1 秒"，换来配置/环境里不再有明文。

### 2.3 唯一真正的坑：钥匙串锁定时的行为不确定

同一台机器上观察到**两种**结果：

| 复测 | 行为 |
|---|---|
| 第一次实验（`spawn`，锁定后读） | ❌ **阻塞 6 秒以上**（超时被我 kill；当时很可能真的弹出了对话框） |
| 干净复测（新建→锁定→读，`execFile` 与 `spawn` 各两次） | ⚡ **31–47ms 内以退出码 152 失败**，不弹窗不阻塞 |

结论不是"锁定会挂"也不是"锁定会报错"，而是：**它取决于 securityd 当时能不能/愿不愿意弹窗**（很可能与刚刚是否出现过被拒绝的对话框有关）。

设计后果（必须做到）：

1. **每次读取都带硬超时**（建议 3–5s），超时按"钥匙串当前不可用"处理；
2. **区分三种失败**：条目不存在（退出码 **44**，`SecKeychainSearchCopyNext: The specified item could not be found in the keychain`🔬）、被拒绝/不支持交互（退出码 **152**🔬）、超时（我们自己的 kill）；
3. **绝不因为钥匙串失败就让 harness 挂住或直接崩**：降级到交互式提示，或给出可执行的修复建议（例如"锁屏后重试 / 手动运行 `security unlock-keychain`"）。

另外注意：`security show-keychain-info` **看起来**能查锁定状态，但它在锁定时**同样会阻塞**（实测 5s 超时🔬），所以**不能**用它做无阻塞预检。

### 2.4 文档层面的确认：为什么"走 CLI"这条路成立

实测之外，另一路调研从 Apple 文档与相关项目的源码/issue 里确认了同一结论，并补上了两个我原本解释不了的现象：

**（1）有两个完全不同的对话框，必须分开谈**（这解释了我 §2.3 里"一次阻塞、四次快速失败"的矛盾）：

| | 触发条件 | 文案（Apple 自己的字符串表） |
|---|---|---|
| **钥匙串锁定框** | 目标钥匙串是锁的 | "Please enter the keychain password." / "Enter the password for keychain “%@”"（`SecurityAgent.bundle/…/KeychainPassphraseUnlock.loctable`） |
| **应用授权框（ACL）** | 钥匙串已解锁，但**发起请求的应用身份**不在该条目的受信列表里 | "%1$@ wants to use your confidential information stored in “%2$@" in your keychain."，按钮 **Always Allow / Deny / Allow**（`ConfirmAccess.loctable`） |

所以：**锁定时弹的是第一种**（我 probe 1 遇到的就是它——临时钥匙串刚被我锁上）；**第二种才是"应用授权"，也才会问"始终允许"**，而我们这条路径**根本不会碰到它**。

**（2）ACL 校验的对象确实是 `/usr/bin/security`，且它是 Apple 签名、身份稳定**：

- `man security` 的原文：*"By default, the application which creates an item is trusted to access its data without warning."* —— "the application which creates" 就是执行 API 调用的那个进程，也就是 `security`；
- Python `keyring` 作者在 issue 里的原话：*"ownership belongs to calling process not to 'security' app"*（`jaraco/keyring#144`）；
- 本机验证：`codesign -d -r- /usr/bin/security` → `designated => identifier "com.apple.security" and anchor apple`。
- 推论：**ACL 不会上溯到 node**，也不继承 node 的身份。所以"只信任 node 的条目"用 CLI 读**仍然会弹窗**，而"由 `security` 创建（默认即信任 `security`）的条目"，**从任何会 shell out 的进程读都不弹，且 node 升级后依旧不弹**。

**（3）`-A` 为什么不必需、以及它的代价**：man page 写的是 *"Allow any application to access this item without warning (insecure, not recommended!)"*。它确实是**唯一**文档化的"任何应用、零弹窗"写法，但代价是钥匙串不再是一道用户确认边界，只剩余静态加密——正是我们要避免的。默认（不加 `-T`）已经够用。

**（4）前人踩过的坑，正好说明我们为什么躲开了**：`aws-vault` 的 README 直接写着 *"The macOS release builds are code-signed to avoid extra prompts in Keychain."*，并且它用 `KeychainTrustApplication: true`（信任调用者）；未签名版本会遇到"点 Always Allow 也没用"——因为 **ACL 记录的是 cdhash，每次重新构建都会变**（`99designs/aws-vault#211/#219/#267`；`jaraco/keyring` 的作者也实测过"No app trusted"变体会产生约 10 次交互提示且"始终允许"不生效）。**我们不受这个影响，恰恰因为调用方是 Apple 签名的 `security` 而不是 node。**

**（5）无 GUI 时的失败形态**：Apple 文档化的错误是 `errSecInteractionNotAllowed`（**-25308**，docker 的 osxkeychain helper 在代码里就专门映射了它并提示用户手动 `security -v unlock-keychain`）。但**我实测锁定时拿到的是退出码 152**，不是 -25308 —— 所以结论是：**不要按具体数字码分类**，只保证两条：**44 = 条目不存在**（可诊断），**其余任何失败（含超时）= 钥匙串当前不可用 → 降级**。

**（6）fail-fast 的旋钮都不好用**：CLI **没有**任何"禁止弹窗"的 flag 或环境变量（`man security` 的 ENVIRONMENT 只有 `MallocStackLogging`）；API 侧的 `SecKeychainSetUserInteractionAllowed(FALSE)`、`kSecUseAuthenticationUIFail`、`kSecUseNoAuthenticationUI` 在当前 SDK 里**都已废弃**。所以"加超时"不是偷懒，是**唯一现实可行的 fail-fast**。

**（7）仍未验证、要在实现前补的实验**（诚实标注）：
- `security add-generic-password` 创建的条目，其 ACL 受信项究竟渲染成 `identifier … anchor apple` 还是 cdhash（用 `security dump-keychain -a` 前后对比即可，但会改动状态，没在这次只读调研里做）；
- **最关键的待验证项**：node 升级之后（换 nvm 版本/重装），同一个条目是否仍零弹窗——理论上应如此（身份是 `security`），但没有任何文档明确写过；
- 无 Aqua 会话的 `launchd` 上下文里 `security unlock-keychain -p` 是否可行；
- 屏幕共享会话是否算"有 UI"（决定弹窗还是 -25308）。

### 2.5 macOS 的结论

**可以做，且正常路径零弹窗。** 实现上必须做到三件事：

1. 写入与读取**都走 `/usr/bin/security`**，**不要加 `-T`/`-A`**（默认就信任创建者，即 `security` 自己）；
2. 每次读取**带硬超时**（3–5s），把超时与任何非 44 的失败都当"不可用"，降级到交互式提示或清晰报错；
3. 不要依赖具体错误码（-25308 与 152 都可能出现），只在文档里给出**可执行的修复指引**（例如"锁屏后重试 / 手动 `security unlock-keychain`"）。


## 3. 存"主密码"还是"包裹密钥"：两条路线的取舍

现有格式（`src/store.ts`）：

```ts
interface VaultFile { version: number; kdf: KdfParams; verify: EncryptedBlob; entries: EncryptedBlob[] }
```

`openVault({ masterPassword })` 用 scrypt（N=32768,r=8,p=1，盐持久化）派生密钥。**`resolveMasterPassword(config)` 是唯一接缝**（`src/index.ts:5997`），目前同步、只认 `masterPasswordEnv` / `masterPassword`。

### 方案 A：钥匙串里存**主密码**（零格式变更）

- 配置：`masterPasswordKeychain: { service, account }`（或 `masterPasswordSource: keychain`）；
- 解锁：读钥匙串 → 交给现有 scrypt 流程，**其余代码一行不用改**；
- 优点：立刻可用；库文件格式不变；换了机器/丢了钥匙串，用户仍能用密码打开（只要他记得）；
- 缺点：**钥匙串里躺着的是"用户可能复用的那个口令"**。谁能读到钥匙串（同进程插件、你的其他程序、备份）就拿到了这个口令，而不只是这一个库的密钥。

### 方案 B：钥匙串里存**随机密钥**，用它包裹库（格式 v2）

- 新增一个随机 32 字节的库密钥 `K`；条目用 `HKDF(K)` 加密；
- 钥匙串里存 `K`（或 `K` 的包装），**密码路径保留**：`verify` 旁再加一个"用密码派生的 KEK 包裹 K"的信封，两种解锁方式并存（这就是 Bitwarden 的 user key + KDF 包裹、1Password 的双密钥思路📚）；
- 优点：**钥匙串泄露 ≠ 口令泄露**；解锁可以跳过 scrypt（但实测只省 56–80ms🔬，**这点不构成理由**）；可以同时支持"密码 / 钥匙串 / helper command"多把钥匙；
- 缺点：格式变更 + 迁移 + 新旧路径都要测；是一次真正的功能改造，不是加一个配置项。

**建议**：先做 A（本周能落地、收益立刻可见：配置与环境里不再有明文），把 **B 记录为下一步**，并确保 A 的实现**不挡 B 的路**（即：解析出来的东西叫"解锁材料"而不是写死"密码"，为将来替换留位置）。

## 4. 平台矩阵

### 4.1 macOS：见 §2，已实测

### 4.2 Linux：能做，但**前提条件比 macOS 多得多**，而且"没有 per-app ACL"

调研结论（📚 均有来源，见文末）：

**用什么**：桌面环境走 freedesktop Secret Service（`org.freedesktop.secrets`），命令行工具是 `secret-tool`（GNOME Keyring）或 `kwallet-query`（KDE）。注意 **`secret-tool` 在 Debian/Ubuntu 属于单独的 `libsecret-tools` 包**（Ubuntu 在 universe），Fedora 才随 `libsecret` 一起装 —— 所以"能不能用"要先探测，不能假设存在。

**弹窗与解锁**：
- 登录钥匙环只有在 **PAM 拿到了密码**时才自动解锁，也就是要求"**钥匙环密码 == 登录密码**"；**自动登录（autologin）、指纹（fprintd 不设置 `PAM_AUTHTOK`）、智能卡登录都不会解锁它** —— 这时**第一个来取秘密的应用会弹一次解锁框**；
- 解锁框需要有显示环境且它被导出到 session bus（`dbus-update-activation-environment DISPLAY XAUTHORITY WAYLAND_DISPLAY`），**否则 GUI 提示根本无法弹出** → 此时调用会**一直等在那里**（挂住）；
- **Secret Service 规范明确不管访问控制**（"This specification does not mandate any form of access control"），**没有 per-app ACL、也没有 macOS 那种"始终允许"**。ArchWiki 甚至直说：只要钥匙环解锁了，**任何应用都能读**。所以 **Linux 上钥匙串托管买到的只是"不用每次输"，不是"别人读不到"** —— 这与 §1 的威胁模型一致，但比 macOS 更弱（macOS 至少有 per-app ACL 这一层）。

**必须在运行期探测**（否则会挂住），调研给出的清单很具体：
1. `DBUS_SESSION_BUS_ADDRESS` 未设置 → 没有 session bus，直接放弃（错误串形如 `Cannot autolaunch D-Bus without X11 $DISPLAY`）；
2. `XDG_RUNTIME_DIR` 未设置 → 私有 bus 也不成立；
3. `DISPLAY` / `WAYLAND_DISPLAY` 都没有 → **即使 bus 在，也不可能弹窗** → 若 collection 是锁的，必须**快速失败**而不是去调用会弹窗的接口；
4. **无阻塞预检**（不弹窗地看锁定状态）：
   `busctl --timeout=10 --user get-property org.freedesktop.secrets /org/freedesktop/secrets/collection/login org.freedesktop.Secret.Collection Locked`
   → `true`/`false`/非零表示没有可用服务；
5. **每次 `secret-tool lookup` 都套超时**（例如 `timeout 10`），把超时当作"不可用"；
6. **`secret-tool store` 必须关掉 stdin**（它"读到 EOF"，继承来的 stdin 会永远挂住）。

**没有桌面钥匙环时的现实**（服务器/SSH/cron/容器/WSL2/systemd 服务）：这些环境**根本没有可用的 Secret Service**，可选替代是 `systemd-creds`（TPM2 + `/var/lib/systemd/credential.secret`，可绑定 machine-id + UID，无弹窗，但 **root 能读**，且非特权桌面插件通常只能通过 unit 的 `LoadCredentialEncrypted=` 拿到）、内核 keyutils 持久钥匙环（无 D-Bus 依赖、能跨登出，但**静态不加密**、重启即失）、或**加密文件 + 显式密钥**。

**对设计的直接后果**：Linux 上"钥匙串"只能当作**可用则用的便利路径**（探测通过才走），**默认降级顺序**应是：钥匙串（探测通过）→ helper command（`pass`/1Password CLI 等）→ 交互式提示；并且要在文档里明说 Linux 下它**不提供跨进程保护**。

### 4.3 三方托管（helper command）：能做，而且**不要为每家写适配器**

调研结论（📚 有来源；一条在本机实测🔬）：

| 工具 | 只输出值的命令 | 弹窗频率 | 无 TTY / headless |
|---|---|---|---|
| **1Password** | `op read "op://Vault/Item/password"`（stdout 干净） | 桌面 App 集成：**每个新终端窗口/Tab 一次生物识别**，之后 **10 分钟滑动窗口、上限 12 小时**；服务账号：**从不** | ⚠️ **App 集成的会话凭据按 tty + 启动时间派生，无 TTY 的进程适配很差**；要稳定无提示就用 **service account token** |
| **Bitwarden** | `bw get password <id>`（需先有 `BW_SESSION`） | 会话密钥**直到 `bw lock`/登出**，不开新终端则一直有效；**没有文档化 TTL** | ⚠️ **API key 不能替代主密码**（官方明说），所以**无法在不保存主密码的前提下做到完全无提示** |
| **pass + gpg-agent** | `pass show <path>`（单行条目干净；多行条目会多打几行） | **由 gpg-agent 缓存决定**：默认 600s 空闲（每次访问重置）、上限 7200s | ✅ **本机实测**：先以 loopback 预热 agent，再由**另一个无 TTY、无口令**的进程执行 `gpg --batch -d` → **0 秒成功、stdout 干净**；缓存冷且无 TTY 时**约 2 秒快速失败**（不是挂住）🔬 —— **唯一"天然跨进程复用"的方案** |
| **HashiCorp Vault** | `vault kv get -field=password -mount=secret <path>` | 无（token 来自 `VAULT_TOKEN` 或 `~/.vault-token`） | ✅ 完全无提示；**官方说它不带结尾换行**（"ideal for piping"） |
| **sops / age** | `sops decrypt --extract '["password"]' <file>` / `age -d -i <keyfile> <file.age>` | 无（密钥文件）；sops 还支持 `SOPS_AGE_KEY_CMD`（stdout 给密钥） | ✅ 需要密钥文件在盘上 |
| **KeePassXC** | `keepassxc-cli show -q --no-password -k <keyfile> -a Password <db> <entry>` | **无 key file 时每次调用都提示**（CLI 没有 agent/缓存） | ⚠️ **裸 `show` 会输出 Title/UserName/Password/… 摘要，把值弄脏**；必须 `-a Password` |

**由此得到的设计要点（比"支持哪几家"更重要）**：

1. **`op` 的桌面集成依赖 tty**：从终端启动的 harness 会继承那个 tty，可能可用；launchd/守护进程上下文就不是。文档必须写清："1Password 桌面集成只在从终端启动时可用；要稳定无提示请用 service account token"。
2. **Bitwarden 的诚实结论**：想要"零提示"就得要么保存主密码（回到方案 A 的问题），要么让用户自己把 `BW_SESSION` 交给它。不该假装能自动搞定。
3. **结果缓存要有显式的 per-provider TTL**：AWS 的 `credential_process` 文档明确说它**不缓存**，"要缓存就在你自己的进程里做"。而我们这里缓存直接决定**弹窗频率**（例如把 1Password 的 10 分钟窗口用到极致），所以设计里要有带 TTL 的缓存，且**锁库时清空**。
4. **照抄 AWS 文档里的三条警告**：① **绝不要把秘密写进 stderr**（SDK/CLI 会捕获进日志）；② **能改配置的人就能改这条命令**，所以配置文件权限要收紧（README 已要求 `0600`）；③ **命令用绝对路径**，不要依赖环境变量与 `~` 展开。
5. **必须设 `stdin = /dev/null`**：`secret-tool store`、`pass` 这类会读到 EOF 为止，继承来的 stdin 可能让它永远挂着。
6. **可引用的真实翻车案例**：claude-code 的 issue 记录过"钥匙串条目写入时没带受信应用列表 → **每次读凭据都弹一次**"——正是我们用"`security` 写、`security` 读"避开的坑；Apple 自己对 `-A`/未签名的警告是"另一个应用可以**冒充**它来获得访问"（伪装 / TOCTOU）。

### 4.4 Windows：⚠️ 预期"读回凭据"不可行（`cmdkey` 只写不读，读需要原生 addon 或 DPAPI）。备选是 **DPAPI 加密文件**（`CryptProtectData` 绑定当前用户，无弹窗），但那需要原生调用；纯 Node 方案有限。待确认。

## 5. 建议的设计（先给形状，等调研补细节）

### 5.1 统一成一个"解锁材料来源链"

不要为每家产品写适配器，而是**一条链 + 两类 provider**：

```yaml
# 三种来源，按顺序尝试，第一个成功即用
masterPasswordEnv: DSH_VAULT_PASSWORD            # 已有
masterPasswordKeychain:                           # 新增:系统钥匙串(macOS 已实测)
  service: dsh-vault
  account: default
masterPasswordCommand:                            # 新增:任意 helper(覆盖三方)
  - op
  - read
  - op://Private/dsh-vault/password
  # 1Password / Bitwarden / pass / Vault 的写法见 §4.3
```

`masterPasswordCommand` 的语义（安全相关，必须写死）。下面每条都用桩程序验过（🔬）：

- **数组形式、不经 shell**，等价于 `execFile(argv[0], argv.slice(1))`。实测参数里的 `a b;$(rm -rf /)` 原样传给孩子进程，没有被解释 —— 注入面为零。🔬
- **stderr 完全忽略**（只进脱敏日志）：实测 helper 往 stderr 打 "touch id required" 时，stdout 的值仍然是干净的。🔬
- **stdout 的处理必须可配，不能一刀切**。桩程序实测：helper 若在值前多打一行 banner，值就变成 `"warning: banner\ns3cret"`。🔬 而现实里几种工具的差异是真实的：
  - `op read` / `bw get password` 只打印值本身；
  - **`pass show` 是首行为密码、后续行还有别的字段**📚 ——此时"整段 stdout"是错的；
  - 所以：默认 `whole`（整段去一个结尾换行），并提供 `line: first | last` 给 `pass` 这类工具；**若结果里出现换行，要显式警告**（真实口令极少含换行），而不是静默当密码用。
- **退出码与失败分类必须精确**（桩程序踩到过这个坑）：`execFile` 对"命令不存在"给的是**字符串** `code: 'ENOENT'`，我第一版只判断数字码，于是把它误报成 `timeout`，报错信息完全把人带偏。正确的分类：

  | 情况 | 判据 | 给用户的提示 |
  |---|---|---|
  | helper 未安装 | `error.code === 'ENOENT'` | "没找到 op/bw/pass，先安装或写绝对路径" |
  | helper 失败 | 数字 `error.code` | 带上退出码与 stderr（脱敏） |
  | 超时 | `error.killed === true` / signal | "helper 超过 N 秒未返回（可能在等 Touch ID/主密码）" |
  | 输出为空 | `stdout === ''` | "helper 没有输出，检查它的用法" |

- **硬超时**（默认 10s，可配）+ **SIGKILL**：这是防止"等 Touch ID 弹窗"挂住 harness 的唯一保险。
- **`stdin` 强制 `/dev/null`**：`secret-tool store`、`pass` 这类会读到 EOF 为止，继承来的 stdin 可能让它永远挂着。
- **最小化环境变量**（只传必要的，如 `PATH` + provider 自己的），避免把主密码/令牌通过环境泄漏给无关子进程；**用绝对路径**调 helper，不依赖 `~` 展开。
- **结果按 provider 缓存并带 TTL**（默认 0 = 不缓存；`pass`+gpg-agent 这类可设 0，1Password 这类可设到它的会话窗口内），**`vault_lock` 时一并清空**。AWS 的 `credential_process` 文档说它自己**不缓存**、"要缓存请在自己的进程里做" —— 我们这里缓存直接决定弹窗频率，所以必须做。
- **绝不把 stdout 打进日志或错误信息**，非零退出时**绝不把半截输出当密码**（实测：`process.exit(3)` 前已打印 "partial"，仍必须整体拒绝🔬）。
- **只剥掉一个结尾换行（`\n` 或 `\r\n`），不 trim 其他空白**。实测：主密码结尾多一个空格就开不了库（`vault master password is incorrect`），而 helper 几乎总是会补一个换行🔬 —— 这是"看起来配好了却打不开"的最常见原因，值得在文档里直说。若要容错更多（例如手写命令多打了空格），应做成显式选项而非常规行为。

### 5.2 一次性写入的用户体验（决定这东西会不会被用错）

必须给一个命令，而不是让用户手抄 `security add-generic-password`：

```
dsh-vault keychain set     # 交互式输入主密码(不回显) → 写入钥匙串,不回显、不进历史
dsh-vault keychain status  # 是否已托管、service/account、上次读取是否成功
dsh-vault keychain remove
```

CLI 本身也应该支持同样的来源链（`--keychain`、`DSH_VAULT_MASTER_PASSWORD_COMMAND`），否则"脚本不碰明文密码"这件事只做了一半。**注意**：现在的 CLI 明确"不读插件配置文件"，这条原则应保留——CLI 用自己的参数/环境变量，不去解析 `cordis.patch.yml`。

### 5.3 弹窗频率的硬保证

- **每个进程只解析一次**，结果存在内存里（现有 `sharedVaultStore` 已经是每进程一份）；
- `vault_lock` / `lockTimeoutSeconds` 之后**清空内存**；重新解锁时是否再读钥匙串，取决于设计——建议：**解锁时重读**（安全优先），但因为它无弹窗、仅 ~30ms，用户无感；
- **绝不在每次工具调用/每次条目读取时碰钥匙串**（现有 `keychain.ts` 的 `fetchCache` 就是为"避免弹窗轰炸"存在的，同一条原则）；
- 每次读取都带超时，失败即降级到交互式提示。

## 6. 验证计划（做完怎么证明它对）

1. **单测**：用一个假的 `security`/helper（把 `exec` 注入进来）覆盖：成功、条目不存在(44)、被拒(152)、超时、stdout 带多余行、命令不存在、退出码非 0；
2. **反证**：断言"超时不会被当成密码"、"stderr 不泄漏到 stdout"、"日志里不出现秘密"（用植入值检验，沿用 `secret-scan` 的思路）；
3. **真机 E2E**：macOS 上真的写一条**临时** service 到登录钥匙串 → 插件解锁 → 删除；用 `assertVaultEmpty` 相同的护栏确保只碰自动化库；
4. **降级路径**：模拟钥匙串不可用（指向一个不存在的 keychain / 用坏命令），断言插件给出清晰指引且**不挂**；
5. **README**：把"托管改善的是静态暴露、不解决同进程"写进威胁模型那一节。

## 7. 未决问题（需要你拍板）

1. **先做 A 还是直接做 B？**（我的建议：A 先落地，B 排进后续，但接口留好位置）
2. **Linux 上要不要支持 `secret-tool`**？调研显示它：包不总是装、无 per-app ACL、锁定且无显示时会挂、且"任何应用都能读"。我的建议是**支持但严格探测 + 超时 + 明说不提供跨进程保护**；如果你觉得收益不抵复杂度，也可以**只在 Linux 支持 helper command**（`pass`/1Password CLI/systemd-creds），完全不碰 Secret Service。这条我倾向听你的。
3. **无桌面环境的默认行为**：读取失败时**降级到提示输入**，还是**直接报错并说明**？（建议：能交互就提示，不能就报错并给出具体指引）
4. **要不要支持 Windows**（纯 Node 下读回凭据基本不可行，需要原生依赖；DPAPI 文件是另一条路）？
5. **CLI 是否也支持托管来源**（建议支持，否则脚本侧仍要明文密码）。
6. **`masterPasswordKeychain` 的默认 service/account 命名**（`dsh-vault` / `default`，多库用 `dsh-vault:<vault>`？）
7. **helper 预设给几个**？调研建议只给 3–4 个（`op read` / `pass show` / `vault kv get -field` / `bw get password`）+ **永远保留"自己写命令"的逃生口**，不要为每家做 SDK 依赖。我同意这个范围——预设太多就变成维护负担。

## 8. 主要来源

- macOS 实测：`security(1)`；本机（macOS 26.3 / `/usr/bin/security`）—— 见 §2 的每个数字。
- macOS 文档确认：Apple《Access Control Lists》<https://developer.apple.com/documentation/security/access-control-lists>、《SecAccessCreate》<https://developer.apple.com/documentation/security/secaccesscreate(_:_:_:)>、《SecTrustedApplicationCreateFromPath》<https://developer.apple.com/documentation/security/sectrustedapplicationcreatefrompath(_:_:)>、`errSecInteractionNotAllowed` <https://developer.apple.com/documentation/security/errsecinteractionnotallowed>
- 前人经验：`jaraco/keyring#144`（"ownership belongs to calling process not to 'security' app"、以及"no app trusted"变体产生约 10 次提示）、`99designs/aws-vault` README（发布版做代码签名以避免额外弹窗）与 #211/#219/#267（"Always Allow 不生效"）、`docker-credential-helpers` 的 osxkeychain（映射 -25308 并提示手动解锁）
- Secret Service 规范：<https://specifications.freedesktop.org/secret-service/latest-single/>
- `secret-tool(1)`：<https://manpages.ubuntu.com/manpages/jammy/man1/secret-tool.1.html>；打包差异见 <https://packages.debian.org/bookworm/libsecret-tools>、<https://packages.ubuntu.com/jammy/libsecret-tools>
- GNOME Keyring 解锁条件与安全模型：<https://wiki.archlinux.org/title/GNOME/Keyring>（含"任何应用都能读"与 CVE-2018-19358 的说明）
- `kwallet-query(1)`：<https://manpages.ubuntu.com/manpages/jammy/man1/kwallet-query.1.html>
- `gnome-keyring-daemon(1)`（`--unlock` / `--login`）：<https://manpages.ubuntu.com/manpages/noble/man1/gnome-keyring-daemon.1.html>
- `systemd-creds(1)`：<https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html>
- `keyrings(7)`（持久钥匙环 3 天默认）：<https://man7.org/linux/man-pages/man7/keyrings.7.html>
- gpg-agent 缓存与 `gpg-preset-passphrase`：<https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html>、<https://manpages.debian.org/trixie/gpg-agent/gpg-preset-passphrase.1.en.html>
- DSH 侧：`@deepseek-ai/dsh-credentials-local` 的 Known Limitations / Dev Note（"OS-keychain provider is deferred"、seam 预留 helper-command 与 KMS）
- 三方：1Password CLI 会话与 service account <https://www.1password.dev/cli/app-integration-security>、<https://www.1password.dev/service-accounts/use-with-1password-cli>；Bitwarden CLI <https://bitwarden.com/help/cli/>；GnuPG agent 缓存 <https://gnupg.org/documentation/manuals/gnupg/Agent-Options.html>；Vault `kv get` <https://developer.hashicorp.com/vault/docs/commands/kv/get>；sops/age 密钥来源 <https://getsops.io/docs/usage/identities/age/>；KeePassXC CLI man page
- 前人警告：AWS `credential_process` <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html>（不要把秘密写进 stderr、配置文件写入权限即命令控制权、禁用环境变量与 `~`）
