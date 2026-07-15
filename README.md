# SafeDrive

面向不可信云端的加密数据源管理服务。所有文件在**服务端**加密后再写入云端存储（百度网盘 / WebDAV / 服务器磁盘），云端只见到加密名称的文件夹和短名密文分卷；解密、在线播放（Range/seek）、下载全部由服务端流式完成，浏览器与外部播放器只需访问一个普通 URL。

类似 alist 的单二进制部署形态：一个 Rust 可执行文件内嵌全部前端资源。信任模型（模仿 hydraria）：**服务器可信，云端存储不可信**。密钥架构为信封链（cryptree）：每个策略一个**根密码**（多数据源可共享），每个文件/目录的独立随机密钥加密后**藏在它自己的云端名称里**，由父目录密钥解开 —— 云端数据 + 根密码即可完整恢复。

## 快速开始

```bash
# 构建（需要 Rust 工具链 + Node.js/pnpm）
cd web && pnpm install && pnpm build && cd ..
cargo build --release

# 运行
./target/release/safedrive --bind 0.0.0.0:5266 --admin-password <管理密码>
```

打开 `http://<host>:5266`：

1. **策略管理** —— 新建映射策略（根密码 + 上传分卷大小，默认 300MiB，可选不分卷）
2. **数据源管理** —— 添加百度网盘（开放平台 OAuth + 下载 Cookie）、WebDAV 或本地文件系统数据源，绑定策略
3. **数据管理** —— 浏览 / 上传 / 下载 / 在线预览播放 / 复制外部播放链接
4. **设置** —— 全局传输参数（最大分片/并发）、持久密文块缓存、策略备份导出/导入

| 参数 | 说明 |
| --- | --- |
| `--bind` | 监听地址，默认 `127.0.0.1:5266` |
| `--data-dir` | 数据目录（数据源注册表、策略、密码本），默认 `~/.safedrive` |
| `--admin-password` / 环境变量 `SAFEDRIVE_ADMIN_PASSWORD` | 管理密码；不设置则免登录（仅建议本机使用） |

> 策略文件 `strategies.json`（含根密码）明文存放在 `--data-dir`。**根密码丢失 = 该策略下云端数据永久无法解密**，创建策略后请立即在「设置」页导出备份。公网部署请置于 HTTPS 反向代理之后。

### 百度网盘凭证

先在百度智能云/网盘开放平台创建具备网盘权限的应用，并按官方 OAuth 授权码流程取得 Refresh Token。数据源中填写应用的 API Key（Client ID）、Secret Key（Client Secret）与 Refresh Token；Access Token 可以留空，首次连接时会自动获取。令牌过期后服务会自动刷新，并将百度返回的新 Access/Refresh Token 原子写回 `datasources.json`。

Cookie 仍需提供，但只发送给 `locatedownload` 与其返回的 CDN 下载地址；列目录、CRUD 和上传不会携带 Cookie。开放平台应用只能访问其获授权的路径时，请将“网盘根目录”设置在该授权范围内。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│ 前端（React + antd）   纯 UI：明文路径 CRUD + <video src=/stream> │
├─────────────────────────────────────────────────────────────┤
│ Rust 服务端（axum）                                          │
│   /api/files/*  明文路径文件 API（list/mkdir/rename/…/upload）│
│   /stream/{ds}/{path}  流式解密数据面（Range/206、断开即停）   │
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
- 百度网盘列目录、建目录、移动、删除和分块上传采用开放平台 OAuth `xpan` API，Access Token 失效时用 Client ID、Client Secret 与 Refresh Token 自动刷新并持久化；Cookie 只用于 Android `locatedownload` 与 CDN 下载，单个 Range 自动限制为 5 MiB，并在多个 CDN URL 间分散分片

## 安全边界

- **云端看不到**：文件名与各节点密钥（v5 信封编码：一段随机汉字，无格式特征）、内容（ChaCha20）、目录结构语义
- **服务器持有**：策略根密码 —— 服务器被攻破即数据泄露，这是有意的取舍（换取免解锁、外部播放器直连）
- 百度网盘开放平台 Client Secret、Access/Refresh Token 与下载 Cookie 明文保存在 `datasources.json`；必须像根密码一样保护 `--data-dir`，凭证失效后需在数据源管理中更新
- **跨目录移动/重命名**：仅一次云端 rename，内容永不重加密；分享目录 = 交出该目录密钥（快照与长期分享皆可）
- 内容加密无完整性校验（ChaCha20 无 MAC）：云端篡改密文会解出乱码而不会被检测
- 单文件上限约 256 GiB（ChaCha20 32 位块计数器）

## 开发

```bash
cargo test                 # Rust 单测（crypto/vault/engine/adapters/…）
cd web
pnpm vitest run            # 前端单测
pnpm build && cd .. && cargo build --release
cd web && E2E=1 pnpm vitest run src/e2e/   # 集成 E2E（真实二进制 + 真实 WebDAV 服务）
npx playwright test        # 浏览器 E2E
```

设计细节见 [docs/DESIGN.md](docs/DESIGN.md)。
