# SafeDrive

面向不可信云端的加密数据源管理服务。所有文件在**服务端**加密后再写入云端存储（百度网盘 / WebDAV / 服务器磁盘），云端只见到加密名称的文件夹和短名密文分卷；解密、在线播放（Range/seek）、下载全部由服务端流式完成，浏览器与外部播放器只需访问一个普通 URL。

类似 alist 的单二进制部署形态：一个 Rust 可执行文件内嵌全部前端资源。信任模型（模仿 hydraria）：**服务器可信，云端存储不可信**。启用加密的数据源使用信封链（cryptree）：每个数据源一个**根密码**，每个文件/目录的独立随机密钥加密后**藏在它自己的云端名称里**，由父目录密钥解开 —— 云端数据 + 数据源根密码即可完整恢复。

## 快速开始

```bash
# 构建（需要 Rust 工具链 + Bun）
bun install
bun run build   # turbo：web 构建 → cargo release，内容哈希缓存，无变更时秒级完成

# 运行
./target/release/safedrive --bind 0.0.0.0:5266 --admin-password <管理密码>
```

打开 `http://<host>:5266`：

1. **数据源管理** —— 添加百度网盘、WebDAV 或本地文件系统；加密、分卷、卷名和缓存均在数据源中配置
2. **不可逆模式** —— 数据源创建后不可切换“是否加密”和“是否分卷”；可修改加密密码、后续分卷大小和固定/随机分卷策略
3. **数据管理** —— 浏览 / 上传 / 下载 / 在线预览播放 / 复制外部播放链接
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

最简配置只需填写登录百度网盘账号的 `BDUSS` 值。首次连接时，服务会参考 onepan 的流程申请 OAuth 设备码、使用 BDUSS 完成设备授权并自动换取 Access/Refresh Token。AT 到期前会使用 RT 刷新；每次成功都将轮换后的新 AT、新 RT 与根据 `expires_in` 计算的 `accessTokenExpiresAt` 原子写回 `datasources.json`。

界面仍提供可选的 API Key（Client ID）和 Secret Key（Client Secret）入口；两者同时留空时使用内置客户端。BDUSS 除了首次设备授权，只发送给 `locatedownload` 与其返回的 CDN 下载地址；列目录、CRUD 和上传不会携带 Cookie。开放平台应用只能访问其获授权的路径时，请将“网盘根目录”设置在该授权范围内。

## WebDAV 服务

服务内置 WebDAV 服务端（**默认关闭**，在「系统设置 → WebDAV 服务」开启），把全部数据源以 `/dav/<数据源名>/<路径>` 暴露成一棵标准 WebDAV 树；Finder、Windows 网络位置、rclone、Infuse/nPlayer 等客户端可直接挂载 —— 解密由服务端现场完成，客户端全程只见明文文件。

```
macOS Finder   ⌘K → http://<host>:5266/dav        （用户名任意，密码 = 管理密码）
rclone         rclone lsd --webdav-url http://<host>:5266/dav --webdav-user any --webdav-pass $(rclone obscure <管理密码>) :webdav:
Windows        映射网络驱动器 → http://<host>:5266/dav （HTTP 下需放行 Basic，建议走 HTTPS 反代）
```

- 管理配置在「系统设置 → WebDAV 服务」：可整体开关（**默认关闭**，需手动开启；关闭后 `/dav` 返回 404），可设置专用账号密码（默认为空）
- 鉴权：设置了专用账号密码则 Basic 校验该账号（用户名留空 = 任意用户名）；未设置时沿用管理密码（用户名任意）；管理密码也未设置时免鉴权。Bearer 会话 token 恒可用
- 读写全集：PROPFIND / GET（Range，播放器可直接拖动）/ PUT（流式加密分卷上传，需 `Content-Length`）/ MKCOL / DELETE / MOVE / COPY（仅文件，服务端解密回源重加密）
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
│ 适配器    localfs、webdav、baidupan（Cookie + 预览下载链接）    │
└─────────────────────────────────────────────────────────────┘
```

- 客户端眼中的一个文件 = 存储端一个加密名文件夹，内含若干短名密文分卷（名字由文件密码确定性派生，2 字符起步按需加宽）
- ChaCha20 密文长度 = 明文长度，分卷布局由 list + 前缀和自描述，任意字节偏移可直接寻址解密（视频拖动即发 Range 请求）
- 下载引擎按全局参数并行拉取分片、按序拼接、断流从准确偏移续拉，客户端断开立即中止全部上游请求（参考 hydraria）
- 全局缓存以 1 MiB 完整块持久化云端密文；缓存命中后仍按合并偏移解密，重启后可继续复用
- 百度网盘列目录、建目录、移动、删除和分块上传采用开放平台 OAuth `xpan` API；首次由 BDUSS 设备授权换取 Token，后续自动刷新并持久化。下载直链按稳定的远端分卷路径单飞缓存 10 分钟，只在实际 Range 命中该分卷时按需获取；全局密文缓存键为数据源 ID + 加密对象路径，不含会变化的直链

## 安全边界

- **云端看不到**：文件名与各节点密钥（v5 信封编码：一段随机汉字，无格式特征）、内容（ChaCha20）、目录结构语义
- **服务器持有**：各加密数据源的根密码 —— 服务器被攻破即数据泄露，这是有意的取舍（换取免解锁、外部播放器直连）
- 百度网盘 BDUSS、可选 Client Secret、自动轮换的 Access/Refresh Token 及绝对到期时间明文保存在 `datasources.json`；必须像根密码一样保护 `--data-dir`
- **跨目录移动/重命名**：仅一次云端 rename，内容永不重加密；分享目录 = 交出该目录密钥（快照与长期分享皆可）
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

设计细节见 [docs/DESIGN.md](docs/DESIGN.md)。
