# SafeDrive

面向不可信云端的加密数据源管理服务。所有文件在**服务端**加密后再写入云端存储（百度网盘 / 阿里云盘 / 夸克网盘 / WebDAV / 服务器磁盘），云端只见到加密名称的文件夹和短名密文分卷；解密、在线播放（Range/seek）、下载全部由服务端流式完成，浏览器与外部播放器只需访问一个普通 URL。

类似 alist 的单二进制部署形态：一个 Rust 可执行文件内嵌全部前端资源。信任模型（模仿 hydraria）：**服务器可信，云端存储不可信**。启用加密的数据源使用信封链（cryptree）：每个数据源一个**根密码**，每个文件/目录的独立随机密钥加密后**藏在它自己的云端名称里**，由父目录密钥解开 —— 云端数据 + 数据源根密码即可完整恢复。

> 本项目仅供技术学习、研究与管理**本人合法持有的数据**使用。使用前请阅读[免责声明](#免责声明)。

## 快速开始

```bash
# 安装（仅需 Rust 工具链，前端产物已随仓库预构建，无需 bun/npm）
cargo install safedrive                                      # crates.io 稳定版
cargo install --git https://github.com/qy527145/safedrive   # 最新开发版

# 或从源码构建（需要 Rust 工具链 + Bun）
bun install
bun run build   # turbo：web 构建 → cargo release，内容哈希缓存，无变更时秒级完成

# 运行
safedrive --bind 0.0.0.0:5266 --admin-password <管理密码>
```

打开 `http://<host>:5266`：

1. **数据源管理** —— 添加百度网盘、阿里云盘、夸克网盘、WebDAV 或本地文件系统；加密、分卷、卷名和缓存均在数据源中配置
2. **不可逆模式** —— 数据源创建后不可切换“是否加密”和“是否分卷”；可修改加密密码、后续分卷大小和固定/随机分卷策略
3. **数据管理** —— 浏览 / 上传 / 下载 / 在线预览播放 / 复制外部播放链接 / 跨数据源复制（可秒传）
4. **设置** —— 全局传输参数（最大分片/并发）与持久块缓存；顶部实时展示服务端到网盘的上下行速度

| 参数 | 说明 |
| --- | --- |
| `--bind` | 监听地址，默认 `127.0.0.1:5266` |
| `--data-dir` | 数据目录（数据源注册表、缓存和设置），默认 `~/.safedrive` |
| `--admin-password` / 环境变量 `SAFEDRIVE_ADMIN_PASSWORD` | 管理密码；不设置则免登录（仅建议本机使用） |
| `--http-proxy` / `SAFEDRIVE_HTTP_PROXY` | 数据源上游代理，例如 `http://127.0.0.1:8080` |
| `--http-ca-cert` / `SAFEDRIVE_HTTP_CA_CERT` | 额外信任的 PEM/DER CA；mitmproxy 通常为 `~/.mitmproxy/mitmproxy-ca-cert.pem` |
| `--insecure-tls` / `SAFEDRIVE_INSECURE_TLS=true` | 跳过上游证书校验，仅用于临时抓包调试 |

> 数据源文件 `datasources.json` 含连接凭据和加密根密码，明文存放在 `--data-dir`。**根密码丢失 = 对应加密数据源永久无法解密**。公网部署请置于 HTTPS 反向代理之后，并备份该文件。

### 使用 mitmproxy 抓取上游请求

SafeDrive 的上游客户端会读取 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 环境变量，也可使用独立参数显式配置。Windows 的“系统代理”不会自动转换成这些环境变量，建议使用以下方式启动：

```powershell
cargo run -- `
  --http-proxy http://127.0.0.1:8080 `
  --http-ca-cert "$HOME\.mitmproxy\mitmproxy-ca-cert.pem"
```

使用 `bun run dev` 时可通过环境变量传给后端：

```powershell
$env:SAFEDRIVE_HTTP_PROXY = "http://127.0.0.1:8080"
$env:SAFEDRIVE_HTTP_CA_CERT = "$HOME\.mitmproxy\mitmproxy-ca-cert.pem"
bun run dev
```

如果只是临时排查证书问题，可改用 `--insecure-tls`，但不要在正常运行时启用。该选项会关闭 SafeDrive 到所有上游数据源的 HTTPS 证书校验。

### 百度网盘凭证

最简配置只需填写登录百度网盘账号的 `BDUSS` 值。推荐直接点击表单中的「扫码登录自动获取」：用百度网盘 App 扫码并在手机上确认后，BDUSS 会自动填入，无需手动查浏览器 Cookie（扫码走 passport.baidu.com 网页版登录协议，由 SafeDrive 服务端代理，凭证不经过第三方）。首次连接时，服务会参考 onepan 的流程申请 OAuth 设备码、使用 BDUSS 完成设备授权并自动换取 Access/Refresh Token。AT 到期前会使用 RT 刷新；每次成功都将轮换后的新 AT、新 RT 与根据 `expires_in` 计算的 `accessTokenExpiresAt` 原子写回 `datasources.json`。

界面仍提供可选的 API Key（Client ID）和 Secret Key（Client Secret）入口；两者同时留空时使用内置客户端。BDUSS 除了首次设备授权，只发送给 `locatedownload` 与其返回的 CDN 下载地址；列目录、CRUD 和上传不会携带 Cookie。开放平台应用只能访问其获授权的路径时，请将“网盘根目录”设置在该授权范围内。

### 阿里云盘凭证

走[阿里云盘开放平台](https://www.alipan.com/developer)的自建应用：填入自己的 `client_id` 与 `client_secret`，然后点「扫码授权自动获取」—— 二维码由 SafeDrive 服务端向 `openapi.alipan.com` 申请并代理下发，手机确认后 `refresh_token` 直接回填表单，凭证不经过任何第三方中转。（后续会内置若干已知的开放应用，做成下拉选择。）

- **盘位**：默认盘 / 资源库 / 备份盘，对应 `getDriveInfo` 的 `default_drive_id` / `resource_drive_id` / `backup_drive_id`；改盘位后缓存的 `driveId` 自动作废，重新查询
- **令牌轮换**：access token 到期前自动用 refresh token 换新，阿里每次都会轮换 refresh token，新值原子写回 `datasources.json`。设置页若是在轮换之前打开的，保存时不会把旧令牌写回去（按“种子值”判定用户到底改没改）
- **秒传**：先用头 1 KiB 的 `pre_hash` 做廉价预检，命中 `PreHashMatched` 才计算全量 SHA1 与 `proof_code` 正式秒传；小于 100 KiB 的对象不走秒传。列目录自带 `content_hash`，所以阿里云盘之间互相复制连摘要都不用自己算

### 夸克网盘凭证

浏览器登录 `pan.quark.cn` 后复制整串 Cookie 填入即可（需包含 `__puus`）。`__puus` 每次响应都可能轮换，服务端会就地吸收并写回 `datasources.json`，同一份配置可长期使用。

秒传走 `/file/upload/pre` + `/file/update/hash`，需要同时提供 MD5 与 SHA1；夸克的列表接口不返回摘要，因此只有在源端读取廉价（本地磁盘）时才会现算摘要去撞秒传，其他情况直接走普通传输。

## 跨数据源复制与秒传

文件列表选中条目后点「复制到…」，选目标数据源与目录即可（同一数据源换个目录也行）。WebDAV 的 `COPY` / `MOVE` 跨 `/dav/<数据源名>/` 时走同一条实现，`MOVE` = 复制成功后再删源。

关键点是**文件密钥随复制一起搬过去**：SafeDrive 的内容加密只由文件密钥 `pw` 和合并坐标系里的字节偏移决定，分卷边界对密文没有任何影响。复制时只用目标父目录的密钥重编最外层信封名，`pw` 原样保留 —— 于是源与目标的每个分卷都是**逐字节相同**的对象，连卷名（由 `pw` 派生的 PRP）都一样。复制退化成纯存储层的对象搬运，一次加解密都不用做，也就能直接吃到网盘的秒传。

两条硬约束：

1. **分卷切分跟随源**：目标数据源自己的分卷大小/策略在跨源复制时不生效。改了边界卷内容就变了，摘要对不上，秒传必然落空
2. **两端「是否加密」必须一致**才能原样搬运；一边加密一边明文时内容天然不同，只能降级为解密 → 重加密的完整传输

实际走了哪条路会如实回报：传输队列里每个复制任务完成后标注「秒传 N 卷 xx / 实传 N 卷 xx」，完成时也弹一条提示。秒传落空的常见原因是目标网盘没有这份内容、目标不支持秒传（本地磁盘 / WebDAV），或源端读取太贵且拿不到现成摘要。

## WebDAV 服务

服务内置 WebDAV 服务端（**默认关闭**，在「系统设置 → WebDAV 服务」开启），把全部数据源以 `/dav/<数据源名>/<路径>` 暴露成一棵标准 WebDAV 树；Finder、Windows 网络位置、rclone、Infuse/nPlayer 等客户端可直接挂载 —— 解密由服务端现场完成，客户端全程只见明文文件。

```
macOS Finder   ⌘K → http://<host>:5266/dav        （用户名任意，密码 = 管理密码）
rclone         rclone lsd --webdav-url http://<host>:5266/dav --webdav-user any --webdav-pass $(rclone obscure <管理密码>) :webdav:
Windows        映射网络驱动器 → http://<host>:5266/dav （HTTP 下需放行 Basic，建议走 HTTPS 反代）
```

- 管理配置在「系统设置 → WebDAV 服务」：可整体开关（**默认关闭**，需手动开启；关闭后 `/dav` 返回 404），可设置专用账号密码（默认为空）
- 鉴权：设置了专用账号密码则 Basic 校验该账号（用户名留空 = 任意用户名）；未设置时沿用管理密码（用户名任意）；管理密码也未设置时免鉴权。Bearer 会话 token 恒可用
- 读写全集：PROPFIND / GET（Range，播放器可直接拖动）/ PUT（流式加密分卷上传，需 `Content-Length`）/ MKCOL / DELETE / MOVE / COPY
- MOVE / COPY 的 `Destination` 指向另一个数据源时走[跨数据源复制](#跨数据源复制与秒传)（含目录递归，能秒传就秒传）；同数据源内 MOVE 是一次 rename，COPY 仅支持文件（服务端解密回源重加密）
- LOCK/UNLOCK 是假锁，仅满足 Finder / Windows / Office 的 class 2 写入探测；PROPPATCH 假成功（云端没有可写的元数据位）
- 解不开信封的外来条目不会出现在 WebDAV 列表中

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│ 前端（React + antd）   纯 UI：明文路径 CRUD + <video src=/stream> │
├─────────────────────────────────────────────────────────────┤
│ Rust 服务端（axum）                                          │
│   /api/files/*  明文路径文件 API（list/mkdir/rename/…/upload）│
│   /stream/{ds}/{path}  流式解密数据面（Range/206、断开即停）   │
│   /dav/{ds}/{path}  WebDAV 服务端（Basic 鉴权，复用同一核心）  │
│   crypto  ChaCha20 + HKDF + CJK 大进制名称编码 + 纯 Rust 压缩   │
│   vault   密码本（一文件一随机密码）                          │
│   engine  分片规划 / 断流续拉 / 并行拉取 / 顺序拼接 / 密文缓存 │
├─────────────────────────────────────────────────────────────┤
│ 适配器  localfs、webdav、baidupan、aliyundrive、quark（秒传）  │
└─────────────────────────────────────────────────────────────┘
```

- 客户端眼中的一个文件 = 存储端一个加密名文件夹，内含若干短名密文分卷（名字由文件密码确定性派生，2 字符起步按需加宽）
- ChaCha20 密文长度 = 明文长度，分卷布局由 list + 前缀和自描述，任意字节偏移可直接寻址解密（视频拖动即发 Range 请求）
- 下载引擎按全局参数并行拉取分片、按序拼接、断流从准确偏移续拉，客户端断开立即中止全部上游请求（参考 hydraria）
- 全局缓存以 1 MiB 完整块持久化云端密文；缓存命中后仍按合并偏移解密，重启后可继续复用
- 百度网盘列目录、建目录、移动、删除和分块上传采用开放平台 OAuth `xpan` API；首次由 BDUSS 设备授权换取 Token，后续自动刷新并持久化。下载直链按稳定的远端分卷路径单飞缓存 10 分钟，只在实际 Range 命中该分卷时按需获取；全局密文缓存键为数据源 ID + 加密对象路径，不含会变化的直链
- 秒传能力由适配器声明（需要哪些摘要、有没有廉价预检、列目录是否自带摘要），跨源复制据此决定「直接秒传 / 现算摘要再秒传 / 老实传输」，不支持的目标一次多余的摘要都不算

## 安全边界

- **云端看不到**：文件名与各节点密钥（v5 信封编码：一段随机汉字，无格式特征）、内容（ChaCha20）、目录结构语义
- **服务器持有**：各加密数据源的根密码 —— 服务器被攻破即数据泄露，这是有意的取舍（换取免解锁、外部播放器直连）
- 百度网盘 BDUSS、阿里云盘 client_secret / refresh_token、夸克 Cookie、自动轮换的 Access/Refresh Token 及绝对到期时间明文保存在 `datasources.json`；必须像根密码一样保护 `--data-dir`
- **跨目录移动/重命名**：仅一次云端 rename，内容永不重加密；分享目录 = 交出该目录密钥（快照与长期分享皆可）
- **跨数据源复制会保留文件密钥**：两份副本的密文逐字节相同，云端因此能看出「这两个对象内容一样」（秒传的固有代价）。介意的话用下载 + 重新上传代替
- 内容加密无完整性校验（ChaCha20 无 MAC）：云端篡改密文会解出乱码而不会被检测
- 单文件上限约 256 GiB（ChaCha20 32 位块计数器）

## 开发

```bash
bun run dev                # 调试：vite(:5173，/api 代理到后端) + cargo run(:5266) 并行
bun run build              # 打包：web 构建 → cargo release（turbo 内容哈希缓存）
cargo test                 # Rust 单测（crypto/vault/engine/adapters/…）
cd web && bun run test     # 前端单测
cd web && bun run test:e2e # 集成 E2E（真实二进制 + 真实 WebDAV 服务，前置 bun run build）
cd web && bun run test:ui  # 浏览器 E2E
```

> 前端产物 `web/dist` 已随仓库提交（供 `cargo install` 直接嵌入，用户无需 bun）。改动 `web/` 后请执行 `bun run --cwd web build` 并将 `web/dist` 一并提交。

设计细节见 [docs/DESIGN.md](docs/DESIGN.md)。

## 免责声明

本项目（SafeDrive，下称“本软件”）是一个开源的技术研究项目，按 [Apache License 2.0](LICENSE) 以“**现状**”（AS IS）提供，不含任何明示或默示的担保。使用本软件即表示你已阅读、理解并同意以下条款：

1. **用途限制**：本软件仅供个人技术学习、安全研究与管理**你本人合法拥有或已获得明确授权**的数据。严禁将本软件用于任何违反所在国家或地区法律法规的用途，包括但不限于传播、存储侵犯他人著作权、隐私权的内容，或任何违法违规信息。

2. **第三方服务合规**：本软件通过公开或逆向的接口与百度网盘等第三方存储服务交互。这些接口及其使用方式**可能不受第三方服务商的官方支持，甚至可能违反其用户协议或服务条款**。是否使用、以及因此可能导致的账号受限、封禁、数据丢失等一切后果，由使用者自行评估并承担；本软件与第三方服务商无任何隶属、合作或授权关系，相关商标归各自权利人所有。

3. **凭证与数据安全**：本软件在本地明文保存网盘凭证（BDUSS、Cookie、Token 等）与加密根密码。妥善保管运行环境与数据目录是使用者的责任；因密码丢失、凭证泄露、部署不当或环境被攻破造成的数据泄露或无法恢复，作者与贡献者不承担责任。

4. **责任限制**：在适用法律允许的最大范围内，作者与贡献者对任何因使用或无法使用本软件而产生的直接、间接、偶然或后果性损害（包括但不限于数据丢失、业务中断、账号损失、法律纠纷）不承担任何责任。

5. **使用即接受**：你对本软件的下载、安装、编译或运行，均视为对本免责声明的完全接受。若不同意上述任何条款，请立即停止使用并删除本软件。

> 本免责声明为中文与英文双语的技术说明，不构成法律意见；如有需要请咨询专业法律人士。作者保留在不另行通知的情况下更新本声明的权利。
