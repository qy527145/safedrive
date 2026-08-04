//! 阿里云盘适配器（开放平台 openapi.alipan.com）。
//!
//! 与百度网盘一样是「ID 寻址」的网盘，而 SafeDrive 的 Storage 抽象是路径
//! 寻址：这里用进程级 `路径 → file_id` 缓存把两者对上，list 一次就把整个
//! 目录的子项 ID 一起喂进缓存。
//!
//! 秒传：`openFile/create` 带 `content_hash`(SHA1) + `proof_code` 命中云端
//! 已有内容时直接返回 `rapid_upload: true`，零字节落地。跨数据源复制时
//! 源侧列表自带 `content_hash`，连读都不用读（只取 8 字节算 proof_code）。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{StreamExt, TryStreamExt};
use md5::Digest as _;
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;

use super::{
    ByteStream, ContentHashes, CredentialPersister, Entry, HashKind, ProgressFn, RapidSource,
    Storage, read_spool, sanitize, spool_with_hashes,
};
use crate::error::{ApiError, ApiResult};

pub const DEFAULT_API_BASE: &str = "https://openapi.alipan.com";
/// 官方文档给的授权 scope：读 + 写 + 基本信息。
pub const OAUTH_SCOPES: &str = "user:base,file:all:read,file:all:write";

/// 阿里云盘对 100 KiB 以下的小文件不做秒传（openlist 同款阈值）。
const RAPID_MIN_SIZE: u64 = 100 * 1024;
/// 分片上限（开放平台：单文件最多 10000 片）。
const MAX_PARTS: u64 = 10_000;
/// 上传直链 50 分钟后必须换新（官方 1 小时过期）。
const UPLOAD_URL_TTL: Duration = Duration::from_secs(50 * 60);
const PATH_ID_TTL: Duration = Duration::from_secs(300);
/// getDownloadUrl 的 expire_sec 给 4 小时，本地只敢缓存 10 分钟。
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(600);
const TOKEN_REFRESH_SKEW_SECS: u64 = 120;

/// 进程级 `账号\u{1}明文路径 → file_id`。适配器是每请求新建的，缓存必须
/// 挂在进程上，否则每次 list 都要从根重新下钻。
static PATH_IDS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 进程级 `账号\u{1}file_id → 下载直链`。
static DOWNLOAD_URLS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 进程级令牌。阿里云盘**每次刷新都会轮换 refresh_token**，并发刷新会把
/// 账号刷废，所以令牌状态与刷新锁都必须是账号级全局的。
static TOKENS: LazyLock<Mutex<HashMap<String, LiveTokens>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TOKEN_LOCKS: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug, Default)]
struct LiveTokens {
    access_token: String,
    refresh_token: String,
    /// 绝对到期时间（Unix 秒）；None 表示未知，下次用之前先刷。
    expires_at: Option<u64>,
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mask_secret(value: &str) -> String {
    let visible = value.chars().take(6).collect::<String>();
    format!("{visible}…({}字符)", value.chars().count())
}

/// 阿里云盘的 refresh_token 是 JWT，`sub` 在轮换中保持不变 —— 拿它当账号
/// 标识，令牌缓存才不会因为一次轮换就整体失效。
fn jwt_sub(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    value.get("sub")?.as_str().map(str::to_owned)
}

fn cache_key(account: &str, path: &str) -> String {
    format!("{account}\u{1}{path}")
}

/// 清掉 `path` 自身与其整棵子树的 ID 缓存（改名/删除后必须做）。
fn evict_path_ids(account: &str, path: &str) {
    let exact = cache_key(account, path);
    let prefix = format!("{exact}/");
    PATH_IDS
        .lock()
        .unwrap()
        .retain(|key, _| key != &exact && !key.starts_with(&prefix));
}

#[derive(Debug, Clone, Deserialize)]
struct AliFile {
    file_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    file_name: String,
    #[serde(default)]
    size: u64,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    content_hash: String,
    #[serde(default)]
    updated_at: String,
}

impl AliFile {
    fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.file_name
        } else {
            &self.name
        }
    }

    fn is_dir(&self) -> bool {
        self.kind == "folder"
    }

    /// `2026-08-04T12:00:00.000Z` → 毫秒时间戳（解析失败给 0）。
    fn mtime_ms(&self) -> u64 {
        parse_rfc3339_ms(&self.updated_at).unwrap_or(0)
    }
}

/// 只处理阿里云盘固定吐出的 `YYYY-MM-DDTHH:MM:SS(.sss)Z` 形态，够用且无依赖。
fn parse_rfc3339_ms(value: &str) -> Option<u64> {
    let (date, rest) = value.split_once('T')?;
    let time = rest.trim_end_matches('Z');
    let (clock, millis) = match time.split_once('.') {
        Some((clock, frac)) => (clock, frac.get(..3).unwrap_or("0").parse::<u64>().ok()?),
        None => (time, 0),
    };
    let mut date = date.split('-');
    let (year, month, day) = (
        date.next()?.parse::<i64>().ok()?,
        date.next()?.parse::<i64>().ok()?,
        date.next()?.parse::<i64>().ok()?,
    );
    let mut clock = clock.split(':');
    let (hour, minute, second) = (
        clock.next()?.parse::<i64>().ok()?,
        clock.next()?.parse::<i64>().ok()?,
        clock.next()?.parse::<i64>().ok()?,
    );
    // Howard Hinnant 的 days_from_civil：把公历日期换算成 Unix 天数。
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(secs.checked_mul(1000)?.checked_add(millis as i64)?).ok()
}

/// 一次 API 调用的结果：传输层问题直接是 `ApiError`，业务层 `code` 单独
/// 拿出来 —— 秒传要靠 `PreHashMatched` 这种「错误」推进流程。
enum Call {
    Ok(Value),
    Failed { code: String, message: String },
}

pub struct AliyunDriveFs {
    api_base: Url,
    /// 明文根目录（相对网盘根，已 sanitize）。
    root: String,
    client_id: String,
    client_secret: String,
    /// `default`（备份盘）或 `resource`（资源库）。
    drive_type: String,
    /// 账号标识：令牌 / 路径 / 直链缓存的命名空间。
    account: String,
    drive_id: Mutex<Option<String>>,
    persist: Option<CredentialPersister>,
    http: Client,
}

impl AliyunDriveFs {
    pub fn from_config_with_persister(
        config: &Value,
        http: Client,
        persist: Option<CredentialPersister>,
    ) -> ApiResult<Self> {
        let text = |key: &str| {
            config
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let client_id = text("clientId")
            .ok_or_else(|| ApiError::BadRequest("阿里云盘配置缺少 clientId".into()))?;
        let client_secret = text("clientSecret")
            .ok_or_else(|| ApiError::BadRequest("阿里云盘配置缺少 clientSecret".into()))?;
        let refresh_token = text("refreshToken")
            .ok_or_else(|| ApiError::BadRequest("阿里云盘配置缺少 refreshToken（请先扫码授权）".into()))?;
        let api_base = Url::parse(text("apiBase").as_deref().unwrap_or(DEFAULT_API_BASE))
            .map_err(|e| ApiError::BadRequest(format!("阿里云盘 apiBase 非法: {e}")))?;
        let root = sanitize(text("root").as_deref().unwrap_or(""))?;
        let drive_type = text("driveType").unwrap_or_else(|| "default".into());
        let account = format!(
            "{client_id}\u{1}{}",
            jwt_sub(&refresh_token).unwrap_or_else(|| refresh_token.clone())
        );

        // 进程内已有更新的令牌就用它（配置里的可能已经被轮换掉了）。
        {
            let mut tokens = TOKENS.lock().unwrap();
            tokens.entry(account.clone()).or_insert_with(|| LiveTokens {
                access_token: text("accessToken").unwrap_or_default(),
                refresh_token,
                expires_at: config
                    .get("accessTokenExpiresAt")
                    .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok())),
            });
        }

        Ok(Self {
            api_base,
            root,
            client_id,
            client_secret,
            drive_type,
            account,
            drive_id: Mutex::new(text("driveId")),
            persist,
            http,
        })
    }

    fn endpoint(&self, path: &str) -> ApiResult<Url> {
        self.api_base
            .join(path)
            .map_err(|e| ApiError::BadRequest(format!("阿里云盘接口地址非法: {e}")))
    }

    fn live_tokens(&self) -> LiveTokens {
        TOKENS
            .lock()
            .unwrap()
            .get(&self.account)
            .cloned()
            .unwrap_or_default()
    }

    fn token_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = TOKEN_LOCKS.lock().unwrap();
        Arc::clone(locks.entry(self.account.clone()).or_default())
    }

    /// 取可用 access token。`stale` 是刚刚被上游判定失效的那个令牌 ——
    /// 只要缓存里的不是它且还没到期就直接复用，否则刷新。
    async fn access_token(&self, stale: Option<&str>) -> ApiResult<String> {
        let usable = |tokens: &LiveTokens| {
            !tokens.access_token.is_empty()
                && Some(tokens.access_token.as_str()) != stale
                && tokens
                    .expires_at
                    .is_some_and(|at| at > unix_time_secs() + TOKEN_REFRESH_SKEW_SECS)
        };
        let current = self.live_tokens();
        if usable(&current) {
            return Ok(current.access_token);
        }

        // 账号级串行：refresh_token 一次性使用，并发刷新会互相作废。
        let lock = self.token_lock();
        let _guard = lock.lock().await;
        // 抢锁期间别的请求可能已经刷好了。
        let current = self.live_tokens();
        if usable(&current) {
            return Ok(current.access_token);
        }
        if current.refresh_token.is_empty() {
            return Err(ApiError::BadRequest(
                "阿里云盘缺少 refreshToken，请重新扫码授权".into(),
            ));
        }

        let body = json!({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": current.refresh_token,
        });
        let value = self.oauth_token(&body).await?;
        let access = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("阿里云盘刷新令牌响应缺少 access_token".into()))?
            .to_owned();
        let refresh = value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&current.refresh_token)
            .to_owned();
        let ttl = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(7200);
        let expires_at = unix_time_secs().saturating_add(ttl);

        TOKENS.lock().unwrap().insert(
            self.account.clone(),
            LiveTokens {
                access_token: access.clone(),
                refresh_token: refresh.clone(),
                expires_at: Some(expires_at),
            },
        );
        if let Some(persist) = &self.persist {
            persist(vec![
                ("accessToken".into(), access.clone().into()),
                ("refreshToken".into(), refresh.into()),
                ("accessTokenExpiresAt".into(), expires_at.into()),
            ])?;
        }
        tracing::info!(
            "阿里云盘令牌已刷新: {} (有效期 {ttl}s)",
            mask_secret(&access)
        );
        Ok(access)
    }

    /// OAuth 端点（不带 Authorization，也不参与 401 重试）。
    async fn oauth_token(&self, body: &Value) -> ApiResult<Value> {
        let url = self.endpoint("/oauth/access_token")?;
        let response = self
            .http
            .post(url.clone())
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("阿里云盘换取令牌失败: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !status.is_success() {
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or(text.as_str());
            return Err(ApiError::Upstream(format!(
                "阿里云盘换取令牌失败: HTTP {status} {code} {message}"
            )));
        }
        Ok(value)
    }

    /// 开放平台 POST 调用；令牌失效自动刷新重试一次。
    async fn call(&self, endpoint: &str, body: &Value, what: &str) -> ApiResult<Call> {
        let mut stale: Option<String> = None;
        loop {
            let token = self.access_token(stale.as_deref()).await?;
            let url = self.endpoint(endpoint)?;
            let response = self
                .http
                .post(url.clone())
                .bearer_auth(&token)
                .json(body)
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("阿里云盘{what}请求失败: {e}")))?;
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if status.is_success() && code.is_empty() {
                return Ok(Call::Ok(value));
            }
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or(text.as_str())
                .to_owned();
            let token_dead = matches!(
                code.as_str(),
                "AccessTokenInvalid" | "AccessTokenExpired" | "I400JD"
            ) || status == StatusCode::UNAUTHORIZED;
            if token_dead && stale.is_none() {
                stale = Some(token);
                continue;
            }
            if code.is_empty() {
                return Err(ApiError::Upstream(format!(
                    "阿里云盘{what}失败: HTTP {status} {}",
                    text.chars().take(300).collect::<String>()
                )));
            }
            return Ok(Call::Failed { code, message });
        }
    }

    /// `call` 的便捷版：业务层错误一律升成 `ApiError`。
    async fn post(&self, endpoint: &str, body: &Value, what: &str) -> ApiResult<Value> {
        match self.call(endpoint, body, what).await? {
            Call::Ok(value) => Ok(value),
            Call::Failed { code, message } => Err(ApiError::Upstream(format!(
                "阿里云盘{what}失败: {code} {message}"
            ))),
        }
    }

    async fn drive_id(&self) -> ApiResult<String> {
        if let Some(id) = self.drive_id.lock().unwrap().clone() {
            return Ok(id);
        }
        let info = self
            .post("/adrive/v1.0/user/getDriveInfo", &json!({}), "获取网盘信息")
            .await?;
        let field = format!("{}_drive_id", self.drive_type);
        let id = info
            .get(&field)
            .and_then(Value::as_str)
            .or_else(|| info.get("default_drive_id").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream(format!("阿里云盘响应缺少 {field}")))?
            .to_owned();
        *self.drive_id.lock().unwrap() = Some(id.clone());
        if let Some(persist) = &self.persist {
            persist(vec![("driveId".into(), id.clone().into())])?;
        }
        Ok(id)
    }

    /// 列一个目录 ID 下的全部条目（marker 翻页），顺带把子项 ID 写进缓存。
    async fn list_folder(&self, parent_id: &str, cache_prefix: Option<&str>) -> ApiResult<Vec<AliFile>> {
        let drive_id = self.drive_id().await?;
        let mut marker = String::new();
        let mut out: Vec<AliFile> = Vec::new();
        loop {
            let mut body = json!({
                "drive_id": drive_id,
                "parent_file_id": parent_id,
                "limit": 200,
            });
            if !marker.is_empty() {
                body["marker"] = marker.clone().into();
            }
            let value = self
                .post("/adrive/v1.0/openFile/list", &body, "列目录")
                .await?;
            let items: Vec<AliFile> = serde_json::from_value(
                value.get("items").cloned().unwrap_or_else(|| json!([])),
            )
            .map_err(|e| ApiError::Upstream(format!("阿里云盘列目录响应解析失败: {e}")))?;
            out.extend(items);
            marker = value
                .get("next_marker")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if marker.is_empty() {
                break;
            }
        }
        if let Some(prefix) = cache_prefix {
            let now = Instant::now();
            let mut cache = PATH_IDS.lock().unwrap();
            for item in &out {
                let path = if prefix.is_empty() {
                    item.display_name().to_owned()
                } else {
                    format!("{prefix}/{}", item.display_name())
                };
                cache.insert(cache_key(&self.account, &path), (item.file_id.clone(), now));
            }
        }
        Ok(out)
    }

    async fn find_child(&self, parent_id: &str, name: &str) -> ApiResult<Option<AliFile>> {
        Ok(self
            .list_folder(parent_id, None)
            .await?
            .into_iter()
            .find(|item| item.display_name() == name))
    }

    /// 数据源根目录（配置里的 `root`）的 file_id；缺失时按需创建。
    async fn root_id(&self) -> ApiResult<String> {
        if self.root.is_empty() {
            return Ok("root".into());
        }
        self.folder_id_from("root", "", &self.root, true).await
    }

    /// 存储端相对路径 → 目录 ID。
    async fn folder_id(&self, path: &str, create: bool) -> ApiResult<String> {
        let root = self.root_id().await?;
        if path.is_empty() {
            return Ok(root);
        }
        self.folder_id_from(&root, "", path, create).await
    }

    /// 从 `base_id`（其明文前缀为 `base_path`）逐段下钻/创建。
    async fn folder_id_from(
        &self,
        base_id: &str,
        base_path: &str,
        relative: &str,
        create: bool,
    ) -> ApiResult<String> {
        let mut parent = base_id.to_owned();
        let mut prefix = base_path.to_owned();
        for seg in relative.split('/').filter(|s| !s.is_empty()) {
            prefix = if prefix.is_empty() {
                seg.to_owned()
            } else {
                format!("{prefix}/{seg}")
            };
            let key = cache_key(&self.account, &prefix);
            if let Some((id, at)) = PATH_IDS.lock().unwrap().get(&key).cloned()
                && at.elapsed() < PATH_ID_TTL
            {
                parent = id;
                continue;
            }
            let found = self.find_child(&parent, seg).await?;
            let id = match found {
                Some(item) if item.is_dir() => item.file_id,
                Some(_) => return Err(ApiError::BadRequest(format!("{prefix} 已存在且是文件"))),
                None if create => self.create_folder(&parent, seg).await?,
                None => return Err(ApiError::NotFound(format!("路径不存在: {prefix}"))),
            };
            PATH_IDS
                .lock()
                .unwrap()
                .insert(key, (id.clone(), Instant::now()));
            parent = id;
        }
        Ok(parent)
    }

    async fn create_folder(&self, parent_id: &str, name: &str) -> ApiResult<String> {
        let drive_id = self.drive_id().await?;
        let body = json!({
            "drive_id": drive_id,
            "parent_file_id": parent_id,
            "name": name,
            "type": "folder",
            // refuse：已存在时原样返回既有目录，天然幂等（并发 mkdir 不会建出两个）
            "check_name_mode": "refuse",
        });
        let value = self
            .post("/adrive/v1.0/openFile/create", &body, "创建目录")
            .await?;
        value
            .get("file_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream("阿里云盘创建目录响应缺少 file_id".into()))
    }

    /// 定位一个具体对象（文件或目录）。
    async fn stat(&self, path: &str) -> ApiResult<AliFile> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不能对数据源根目录取元数据".into()));
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_id = self.folder_id(parent, false).await?;
        self.find_child(&parent_id, name)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {path}")))
    }

    async fn trash(&self, file_id: &str) -> ApiResult<()> {
        let drive_id = self.drive_id().await?;
        let body = json!({ "drive_id": drive_id, "file_id": file_id });
        self.post(
            "/adrive/v1.0/openFile/recyclebin/trash",
            &body,
            "删除（移入回收站）",
        )
        .await
        .map(|_| ())
    }

    async fn download_url(&self, file_id: &str) -> ApiResult<String> {
        let key = cache_key(&self.account, file_id);
        if let Some((url, at)) = DOWNLOAD_URLS.lock().unwrap().get(&key).cloned()
            && at.elapsed() < DOWNLOAD_URL_TTL
        {
            return Ok(url);
        }
        let drive_id = self.drive_id().await?;
        let body = json!({ "drive_id": drive_id, "file_id": file_id, "expire_sec": 14400 });
        let value = self
            .post("/adrive/v1.0/openFile/getDownloadUrl", &body, "获取下载直链")
            .await?;
        let url = value
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("阿里云盘下载直链为空".into()))?
            .to_owned();
        DOWNLOAD_URLS
            .lock()
            .unwrap()
            .insert(key, (url.clone(), Instant::now()));
        Ok(url)
    }

    async fn fetch(&self, path: &str, range: Option<(u64, u64)>) -> ApiResult<(Option<u64>, ByteStream)> {
        let file = self.stat(path).await?;
        if file.is_dir() {
            return Err(ApiError::BadRequest(format!("{path} 是目录")));
        }
        let url = self.download_url(&file.file_id).await?;
        let mut request = self.http.get(&url);
        if let Some((start, end)) = range {
            request = request.header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
        }
        let response = request
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("阿里云盘下载失败: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            // 直链可能提前失效：清缓存让下次重新申请。
            DOWNLOAD_URLS
                .lock()
                .unwrap()
                .remove(&cache_key(&self.account, &file.file_id));
            return Err(ApiError::Upstream(format!("阿里云盘下载失败: HTTP {status}")));
        }
        let size = response.content_length();
        let stream = response.bytes_stream().map_err(std::io::Error::other);
        Ok((size, stream.boxed()))
    }

    /// 分片大小阶梯（照抄开放平台建议值，保证片数 ≤ 10000）。
    fn part_size(size: u64) -> u64 {
        const MB: u64 = 1024 * 1024;
        const GB: u64 = 1024 * MB;
        let base = match size {
            s if s > 1024 * GB => 5 * GB,
            s if s > 768 * GB => 109_951_163,
            s if s > 512 * GB => 82_463_373,
            s if s > 384 * GB => 54_975_582,
            s if s > 256 * GB => 41_231_687,
            s if s > 128 * GB => 27_487_791,
            _ => 20 * MB,
        };
        // 兜底：万一阶梯不够，按 10000 片反推。
        base.max(size.div_ceil(MAX_PARTS))
    }

    fn part_info_list(count: u64) -> Value {
        Value::Array(
            (1..=count)
                .map(|number| json!({ "part_number": number }))
                .collect(),
        )
    }

    /// proof_code：取 `md5(access_token)[0..16]` 当 16 进制数模文件大小，
    /// 从该偏移读 8 字节做 base64。
    fn proof_offset(access_token: &str, size: u64) -> Option<(u64, u64)> {
        if size == 0 {
            return None;
        }
        let digest = hex::encode(md5::Md5::digest(access_token.as_bytes()));
        let index = u64::from_str_radix(&digest[..16], 16).ok()? % size;
        Some((index, (index + 8).min(size) - index))
    }

    /// 建文件记录。`extra` 里放 pre_hash 或 content_hash+proof_code。
    async fn create_file(
        &self,
        parent_id: &str,
        name: &str,
        size: u64,
        extra: Value,
    ) -> ApiResult<Call> {
        let drive_id = self.drive_id().await?;
        let parts = if size == 0 {
            0
        } else {
            size.div_ceil(Self::part_size(size))
        };
        let mut body = json!({
            "drive_id": drive_id,
            "parent_file_id": parent_id,
            "name": name,
            "type": "file",
            "check_name_mode": "refuse",
            "size": size,
            "part_info_list": Self::part_info_list(parts),
        });
        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                body[key] = value.clone();
            }
        }
        self.call("/adrive/v1.0/openFile/create", &body, "创建文件").await
    }

    /// `put` 语义是覆盖：同名已存在就先扔回收站。
    async fn remove_existing(&self, parent_id: &str, name: &str) -> ApiResult<()> {
        if let Some(existing) = self.find_child(parent_id, name).await? {
            self.trash(&existing.file_id).await?;
        }
        Ok(())
    }

    async fn upload_urls(&self, file_id: &str, upload_id: &str, parts: u64) -> ApiResult<Vec<String>> {
        let drive_id = self.drive_id().await?;
        let body = json!({
            "drive_id": drive_id,
            "file_id": file_id,
            "upload_id": upload_id,
            "part_info_list": Self::part_info_list(parts),
        });
        let value = self
            .post("/adrive/v1.0/openFile/getUploadUrl", &body, "获取上传直链")
            .await?;
        Ok(value
            .get("part_info_list")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|item| item.get("upload_url").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn complete(&self, file_id: &str, upload_id: &str) -> ApiResult<()> {
        let drive_id = self.drive_id().await?;
        let body = json!({ "drive_id": drive_id, "file_id": file_id, "upload_id": upload_id });
        self.post("/adrive/v1.0/openFile/complete", &body, "完成上传")
            .await
            .map(|_| ())
    }

    /// 落盘缓冲 → 分片 PUT → complete。
    async fn upload_parts(
        &self,
        create: &Value,
        spool: &std::path::Path,
        size: u64,
        progress: &ProgressFn,
    ) -> ApiResult<()> {
        let file_id = create
            .get("file_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::Upstream("阿里云盘创建文件响应缺少 file_id".into()))?;
        let upload_id = create
            .get("upload_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let part_size = Self::part_size(size);
        let parts = size.div_ceil(part_size);
        let mut urls: Vec<String> = create
            .get("part_info_list")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|item| item.get("upload_url").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let mut issued_at = Instant::now();

        for index in 0..parts {
            if issued_at.elapsed() > UPLOAD_URL_TTL || urls.len() as u64 <= index {
                urls = self.upload_urls(file_id, upload_id, parts).await?;
                issued_at = Instant::now();
            }
            let url = urls.get(index as usize).cloned().ok_or_else(|| {
                ApiError::Upstream(format!("阿里云盘缺少第 {} 片上传直链", index + 1))
            })?;
            let offset = index * part_size;
            let length = part_size.min(size - offset) as usize;
            let chunk = read_spool(spool, offset, length).await?;
            let mut last_error = None;
            let mut done = false;
            for attempt in 1..=3u32 {
                match self.http.put(&url).body(chunk.clone()).send().await {
                    // 409 = 该片已经传过（重试导致），照官方 SDK 一样视为成功
                    Ok(response)
                        if response.status().is_success()
                            || response.status() == StatusCode::CONFLICT =>
                    {
                        done = true;
                        break;
                    }
                    Ok(response) => {
                        last_error = Some(format!("HTTP {}", response.status()));
                    }
                    Err(e) => last_error = Some(e.to_string()),
                }
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
                }
            }
            if !done {
                return Err(ApiError::Upstream(format!(
                    "阿里云盘上传第 {} 片失败: {}",
                    index + 1,
                    last_error.unwrap_or_default()
                )));
            }
            progress(length as u64);
        }
        if !upload_id.is_empty() {
            self.complete(file_id, upload_id).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for AliyunDriveFs {
    fn download_profile_key(&self) -> Option<String> {
        Some(format!("aliyundrive:{}", self.account))
    }

    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        let parent_id = self.folder_id(path, false).await?;
        let items = self.list_folder(&parent_id, Some(path)).await?;
        Ok(items
            .into_iter()
            .map(|item| Entry {
                id: None,
                name: item.display_name().to_owned(),
                is_dir: item.is_dir(),
                size: if item.is_dir() { 0 } else { item.size },
                mtime: item.mtime_ms(),
            })
            .collect())
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        self.folder_id(path, true).await.map(|_| ())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        let file = self.stat(path).await?;
        self.trash(&file.file_id).await?;
        evict_path_ids(&self.account, path);
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法重命名路径".into()));
        }
        let drive_id = self.drive_id().await?;
        let file = self.stat(from).await?;
        let (from_parent, from_name) = from.rsplit_once('/').unwrap_or(("", from));
        let (to_parent, to_name) = to.rsplit_once('/').unwrap_or(("", to));
        if from_parent == to_parent {
            let body = json!({ "drive_id": drive_id, "file_id": file.file_id, "name": to_name });
            self.post("/adrive/v1.0/openFile/update", &body, "重命名")
                .await?;
        } else {
            let target_parent = self.folder_id(to_parent, true).await?;
            let mut body = json!({
                "drive_id": drive_id,
                "file_id": file.file_id,
                "to_parent_file_id": target_parent,
                "check_name_mode": "refuse",
            });
            if from_name != to_name {
                body["new_name"] = to_name.into();
            }
            self.post("/adrive/v1.0/openFile/move", &body, "移动").await?;
        }
        evict_path_ids(&self.account, from);
        evict_path_ids(&self.account, to);
        Ok(())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        self.fetch(path, None).await
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        if end < start {
            return Err(ApiError::BadRequest("非法字节区间".into()));
        }
        self.fetch(path, Some((start, end))).await.map(|(_, s)| s)
    }

    async fn put(&self, path: &str, body: ByteStream) -> ApiResult<()> {
        // 未知长度无法规划分片：先落盘量出大小。
        let spool = super::TempSpool::new("aliyun");
        let mut body = body;
        let mut file = tokio::fs::File::create(&spool.path).await?;
        let mut size = 0u64;
        {
            use tokio::io::AsyncWriteExt as _;
            while let Some(chunk) = body.next().await {
                let chunk = chunk?;
                size += chunk.len() as u64;
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
        }
        drop(file);
        let reopened = tokio::fs::File::open(&spool.path).await?;
        let stream = tokio_util::io::ReaderStream::with_capacity(reopened, 256 * 1024);
        self.put_sized(path, size, stream.boxed()).await
    }

    async fn put_sized(&self, path: &str, size: u64, body: ByteStream) -> ApiResult<()> {
        self.put_sized_tracked(path, size, body, Arc::new(|_| {}))
            .await
    }

    async fn put_sized_tracked(
        &self,
        path: &str,
        size: u64,
        body: ByteStream,
        progress: ProgressFn,
    ) -> ApiResult<()> {
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_id = self.folder_id(parent, true).await?;

        // 先落盘：既算出秒传要的 SHA1，也让分片可以重放重试。
        let (spool, hashes) = spool_with_hashes("aliyun", size, body, &[HashKind::Sha1]).await?;
        let sha1 = hashes.sha1.clone().unwrap_or_default();

        self.remove_existing(&parent_id, name).await?;

        // 内容摘要已经在手，直接冲秒传（命中就零字节落地）。
        let mut extra = json!({
            "content_hash_name": "sha1",
            "content_hash": sha1.to_uppercase(),
            "proof_version": "v1",
        });
        if let Some((offset, length)) =
            Self::proof_offset(&self.access_token(None).await?, size)
        {
            let sample = read_spool(&spool.path, offset, length as usize).await?;
            extra["proof_code"] = B64.encode(&sample).into();
        } else {
            extra["proof_code"] = "".into();
        }
        let created = match self.create_file(&parent_id, name, size, extra).await? {
            Call::Ok(value) => value,
            Call::Failed { code, message } => {
                return Err(ApiError::Upstream(format!(
                    "阿里云盘创建文件失败: {code} {message}"
                )));
            }
        };
        evict_path_ids(&self.account, path);
        if created
            .get("rapid_upload")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            tracing::debug!("阿里云盘秒传命中: {path} ({size} 字节)");
            progress(size);
            return Ok(());
        }
        if size == 0 {
            if let Some(upload_id) = created.get("upload_id").and_then(Value::as_str)
                && !upload_id.is_empty()
                && let Some(file_id) = created.get("file_id").and_then(Value::as_str)
            {
                self.complete(file_id, upload_id).await?;
            }
            return Ok(());
        }
        self.upload_parts(&created, &spool.path, size, &progress)
            .await
    }

    // ---- 秒传 ----

    async fn dir_content_hashes(&self, dir: &str) -> ApiResult<HashMap<String, ContentHashes>> {
        let parent_id = self.folder_id(dir, false).await?;
        Ok(self
            .list_folder(&parent_id, Some(dir))
            .await?
            .into_iter()
            .filter(|item| !item.is_dir() && !item.content_hash.is_empty())
            .map(|item| {
                (
                    item.display_name().to_owned(),
                    ContentHashes {
                        sha1: Some(item.content_hash.to_lowercase()),
                        md5: None,
                    },
                )
            })
            .collect())
    }

    fn rapid_hash_kinds(&self) -> &'static [HashKind] {
        &[HashKind::Sha1]
    }

    async fn rapid_precheck(&self, path: &str, source: &dyn RapidSource) -> ApiResult<bool> {
        let size = source.size();
        if size < RAPID_MIN_SIZE {
            return Ok(false);
        }
        if source.hashes().sha1.is_some() {
            return Ok(true); // 摘要已经免费拿到了，直接冲全量秒传
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_id = self.folder_id(parent, true).await?;
        let head = source.read_at(0, 1024.min(size)).await?;
        let pre_hash = hex::encode(Sha1::digest(&head));
        let extra = json!({ "pre_hash": pre_hash });
        match self.create_file(&parent_id, name, size, extra).await? {
            // 云端存在同样开头的文件 —— 值得算全量 SHA1 再试一次
            Call::Failed { code, .. } if code == "PreHashMatched" => Ok(true),
            Call::Failed { code, message } => Err(ApiError::Upstream(format!(
                "阿里云盘秒传预检失败: {code} {message}"
            ))),
            // 没匹配上：留下了一条待上传记录，清掉并明确告知「别试了」
            Call::Ok(value) => {
                if let Some(file_id) = value.get("file_id").and_then(Value::as_str) {
                    let _ = self.trash(file_id).await;
                }
                Ok(false)
            }
        }
    }

    async fn rapid_put(&self, path: &str, source: &dyn RapidSource) -> ApiResult<bool> {
        let size = source.size();
        let Some(sha1) = source.hashes().sha1.clone() else {
            return Ok(false);
        };
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_id = self.folder_id(parent, true).await?;
        self.remove_existing(&parent_id, name).await?;

        let mut extra = json!({
            "content_hash_name": "sha1",
            "content_hash": sha1.to_uppercase(),
            "proof_version": "v1",
        });
        let token = self.access_token(None).await?;
        match Self::proof_offset(&token, size) {
            Some((offset, length)) => {
                let sample = source.read_at(offset, length).await?;
                extra["proof_code"] = B64.encode(&sample).into();
            }
            None => extra["proof_code"] = "".into(),
        }
        let created = match self.create_file(&parent_id, name, size, extra).await? {
            Call::Ok(value) => value,
            Call::Failed { code, message } => {
                return Err(ApiError::Upstream(format!(
                    "阿里云盘秒传失败: {code} {message}"
                )));
            }
        };
        evict_path_ids(&self.account, path);
        if created
            .get("rapid_upload")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(true);
        }
        // 没命中：清掉刚建出来的待上传记录，交回给调用方走真实传输。
        if let Some(file_id) = created.get("file_id").and_then(Value::as_str) {
            let _ = self.trash(file_id).await;
        }
        Ok(false)
    }
}

/// 扫码授权：向开放平台申请二维码，返回 (授权页地址, sid)。
pub async fn qr_authorize(
    http: &Client,
    api_base: &str,
    client_id: &str,
    client_secret: &str,
) -> ApiResult<(String, String)> {
    let url = format!("{}/oauth/authorize/qrcode", api_base.trim_end_matches('/'));
    let body = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": OAUTH_SCOPES.split(',').collect::<Vec<_>>(),
        "width": 430,
        "height": 430,
    });
    let value = post_json(http, &url, &body, "申请授权二维码").await?;
    let qr = value
        .get("qrCodeUrl")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Upstream("阿里云盘授权二维码为空".into()))?
        .to_owned();
    let sid = value
        .get("sid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok((qr, sid))
}

/// 轮询扫码状态。返回 (状态, 可换令牌的 authCode)。
pub async fn qr_status(http: &Client, api_base: &str, sid: &str) -> ApiResult<(String, String)> {
    let url = format!(
        "{}/oauth/qrcode/{sid}/status",
        api_base.trim_end_matches('/')
    );
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘查询扫码状态失败: {e}")))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(ApiError::Upstream(format!(
            "阿里云盘查询扫码状态失败: HTTP {status}"
        )));
    }
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok((
        value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        value
            .get("authCode")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    ))
}

/// authCode → refresh_token（配置里只存 refresh_token，AT 由适配器自己刷）。
pub async fn exchange_auth_code(
    http: &Client,
    api_base: &str,
    client_id: &str,
    client_secret: &str,
    auth_code: &str,
) -> ApiResult<(String, String, u64)> {
    let url = format!("{}/oauth/access_token", api_base.trim_end_matches('/'));
    let body = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": auth_code,
    });
    let value = post_json(http, &url, &body, "换取令牌").await?;
    let access = value
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let refresh = value
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Upstream("阿里云盘授权响应缺少 refresh_token".into()))?
        .to_owned();
    let ttl = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(7200);
    Ok((access, refresh, unix_time_secs().saturating_add(ttl)))
}

async fn post_json(http: &Client, url: &str, body: &Value, what: &str) -> ApiResult<Value> {
    let response = http
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘{what}失败: {e}")))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        let code = value.get("code").and_then(Value::as_str).unwrap_or("");
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or(text.as_str());
        return Err(ApiError::Upstream(format!(
            "阿里云盘{what}失败: HTTP {status} {code} {message}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_to_millis() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(
            parse_rfc3339_ms("2024-02-29T12:34:56.789Z"),
            Some(1_709_210_096_789)
        );
        assert_eq!(parse_rfc3339_ms("garbage"), None);
    }

    #[test]
    fn proof_offset_stays_inside_the_file() {
        for size in [1u64, 7, 8, 9, 1024, 1 << 20] {
            let (offset, length) = AliyunDriveFs::proof_offset("token", size).unwrap();
            assert!(offset < size);
            assert!(length > 0 && offset + length <= size);
            assert!(length <= 8);
        }
        assert!(AliyunDriveFs::proof_offset("token", 0).is_none());
    }

    #[test]
    fn part_size_keeps_part_count_under_the_cap() {
        for size in [1u64, 20 << 20, 100 << 30, 300 << 30, 2 << 40] {
            let parts = size.div_ceil(AliyunDriveFs::part_size(size));
            assert!(parts <= MAX_PARTS, "size={size} parts={parts}");
        }
    }

    #[test]
    fn jwt_sub_survives_rotation() {
        // header.payload.signature，payload = {"sub":"user-1"}
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"user-1"}"#)
        );
        assert_eq!(jwt_sub(&token).as_deref(), Some("user-1"));
        assert_eq!(jwt_sub("not-a-jwt"), None);
    }
}
