//! 百度网盘开放平台适配器。
//!
//! 目录、写操作和上传使用 OAuth `xpan` 开放平台 API；Cookie 只用于 onepan
//! `get_download_url1` 对应的 Android `locatedownload` 下载链路。
//! 上传对齐 OpenList baidu_netdisk 驱动的实测高速形态：
//! precreate → locateupload 取最优上传域名 → superfile2 并发分片
//! （type=tmpfile，分片大小按会员等级 4/16/32MiB，失败重试 3 次）→ create。
//! 其余开放平台接口（list / filemanager / OAuth）对齐官方 Python SDK
//! （pythonsdk_20220616）：请求 query 均带 `openapi=xpansdk` 标识
//! （superfile2 除外——与 OpenList 一致不带）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt, stream};
use md5::{Digest, Md5};
use reqwest::header::{CONTENT_RANGE, COOKIE, HeaderValue, RANGE, USER_AGENT};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use super::{ByteStream, Entry, ProgressFn, Storage};
use crate::error::{ApiError, ApiResult};

const XPAN_API: &str = "https://pan.baidu.com/rest/2.0/";
const OAUTH_TOKEN_API: &str = "https://openapi.baidu.com/oauth/2.0/token";
const OAUTH_DEVICE_CODE_API: &str = "https://openapi.baidu.com/oauth/2.0/device/code";
const OAUTH_DEVICE_APPROVE_API: &str = "https://openapi.baidu.com/device";
const PCS_FILE_API: &str = "https://pcs.baidu.com/rest/2.0/pcs/file";
const PCS_UPLOAD_API: &str = "https://d.pcs.baidu.com/rest/2.0/pcs/superfile2";
/// locateupload（动态上传域名调度）走 d.pcs 域（对齐 OpenList）。
const PCS_LOCATE_UPLOAD_API: &str = "https://d.pcs.baidu.com/rest/2.0/pcs/file";
const DEFAULT_CLIENT_ID: &str = "iYCeC9g08h5vuP9UqvPHKKSVrKFXGa1v";
const DEFAULT_CLIENT_SECRET: &str = "jXiFMOPVPCWlO2M5CwWQzffpNPaGTRBG";
const PAN_APP_ID: &str = "250528";
const DEFAULT_DOWNLOAD_UA: &str = "netdisk;P2SP;2.2.61.31;android";
const DEFAULT_WEB_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const MAX_PREVIEW_RANGE: u64 = 5 * 1024 * 1024;
/// 分片大小按会员等级（对齐 OpenList）：普通 4MiB、会员 16MiB、超级会员 32MiB。
const DEFAULT_SLICE_SIZE: usize = 4 * 1024 * 1024;
const VIP_SLICE_SIZE: usize = 16 * 1024 * 1024;
const SVIP_SLICE_SIZE: usize = 32 * 1024 * 1024;
const MAX_UPLOAD_BLOCKS: usize = 2048;
/// 瞬时故障（网络错误 / 5xx）重试的基础退避毫秒数；测试构建下压缩以免拖慢用例。
const RETRY_BACKOFF_MS: u64 = if cfg!(test) { 10 } else { 500 };
/// 整卷兜底重试的基础退避毫秒数。
const VOLUME_RETRY_BACKOFF_MS: u64 = if cfg!(test) { 50 } else { 5_000 };
/// superfile2 分片并发数（OpenList 默认 3，可配 uploadThreads 1..=32）。
/// 早期实测「并发即 BFE 500」是在静态 d.pcs 域名 + 无 type=tmpfile 的
/// 组合下发生的；对齐 OpenList（locateupload 动态域名 + type=tmpfile）
/// 后并发稳定。仍以账号级信号量限制同账号总并发。
const DEFAULT_UPLOAD_THREADS: usize = 3;
const LINK_TTL: Duration = Duration::from_secs(10 * 60);

/// 账号级（BDUSS 维度）superfile2 并发槽：同一账号哪怕来自不同适配器
/// 实例（并发上传多个文件时每个请求各建一个实例）也共享同一配额，
/// 避免多文件叠加把账号总并发推过上游容忍度。适配器按请求新建，
/// uploadThreads 变更时换新信号量（在途任务持旧槽自然收尾）。
type SlotMap = HashMap<u64, (usize, Arc<tokio::sync::Semaphore>)>;
static UPLOAD_SLOTS: std::sync::LazyLock<std::sync::Mutex<SlotMap>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// 账号级会员类型缓存（决定分片大小；进程生命周期内成功查询一次即复用）。
static VIP_TYPES: std::sync::LazyLock<std::sync::Mutex<HashMap<u64, i64>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn account_key(bduss: &HeaderValue) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    bduss.as_bytes().hash(&mut hasher);
    hasher.finish()
}

fn upload_slots_for(key: u64, threads: usize) -> Arc<tokio::sync::Semaphore> {
    let mut slots = UPLOAD_SLOTS.lock().unwrap();
    let entry = slots
        .entry(key)
        .or_insert_with(|| (threads, Arc::new(tokio::sync::Semaphore::new(threads))));
    if entry.0 != threads {
        *entry = (threads, Arc::new(tokio::sync::Semaphore::new(threads)));
    }
    Arc::clone(&entry.1)
}

pub type TokenPersister = Arc<dyn Fn(&str, &str, u64) -> ApiResult<()> + Send + Sync>;

const TOKEN_REFRESH_SKEW_SECS: u64 = 60;
const DEFAULT_ACCESS_TOKEN_TTL_SECS: u64 = 30 * 24 * 60 * 60;

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Clone)]
struct CachedLinks {
    inserted: Instant,
    urls: Vec<String>,
}

struct OAuthTokens {
    access_token: String,
    refresh_token: String,
    access_expires_at: Option<u64>,
}

struct TempUpload {
    path: PathBuf,
}

impl TempUpload {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "safedrive-baidu-{}.upload",
                uuid::Uuid::new_v4().simple()
            )),
        }
    }
}

impl Drop for TempUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct BaiduPanFs {
    root: String,
    xpan_api_base: Url,
    oauth_token_api: Url,
    oauth_device_code_api: Url,
    oauth_device_approve_api: Url,
    pcs_api_base: Url,
    upload_api_base: Url,
    upload_locate_api: Url,
    client_id: String,
    client_secret: String,
    tokens: Mutex<OAuthTokens>,
    persist_tokens: Option<TokenPersister>,
    download_cookie: HeaderValue,
    web_user_agent: HeaderValue,
    download_user_agent: HeaderValue,
    http: Client,
    links: Mutex<HashMap<String, CachedLinks>>,
    link_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// 账号级 superfile2 并发槽（见 UPLOAD_SLOTS）。
    upload_slots: Arc<tokio::sync::Semaphore>,
    /// superfile2 分片并发数（uploadThreads，1..=32，默认 3）。
    upload_threads: usize,
    /// 账号哈希（UPLOAD_SLOTS / VIP_TYPES 缓存键）。
    account_key: u64,
}

#[derive(Debug, Deserialize)]
struct BaiduListItem {
    server_filename: String,
    #[serde(default)]
    isdir: i8,
    #[serde(default)]
    size: u64,
    #[serde(default, alias = "mtime")]
    server_mtime: u64,
}

struct SpooledUpload {
    temp: TempUpload,
    block_md5: Vec<String>,
}

impl BaiduPanFs {
    pub fn from_config_with_persister(
        config: &Value,
        http: Client,
        persist_tokens: Option<TokenPersister>,
    ) -> ApiResult<Self> {
        let bduss = config
            .get("bduss")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                config
                    .get("cookie")
                    .and_then(Value::as_str)
                    .and_then(|cookie| cookie_value(cookie, "BDUSS"))
                    .map(str::to_owned)
            })
            .ok_or_else(|| ApiError::BadRequest("百度网盘配置缺少 BDUSS".into()))?;
        let download_cookie = HeaderValue::from_str(&format!("BDUSS={bduss}"))
            .map_err(|_| ApiError::BadRequest("百度网盘 BDUSS 含非法字符".into()))?;
        let download_user_agent = HeaderValue::from_str(
            config
                .get("userAgent")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_DOWNLOAD_UA),
        )
        .map_err(|_| ApiError::BadRequest("百度网盘下载 User-Agent 含非法字符".into()))?;
        let root = normalize_root(
            config
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or("/safedrive"),
        )?;
        let parse_url = |field: &str, default: &str| -> ApiResult<Url> {
            let url = Url::parse(config.get(field).and_then(Value::as_str).unwrap_or(default))
                .map_err(|e| ApiError::BadRequest(format!("百度网盘 {field} 无效: {e}")))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ApiError::BadRequest(format!(
                    "百度网盘 {field} 必须是 http(s)"
                )));
            }
            Ok(url)
        };
        let configured_client_id = config
            .get("clientId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let configured_client_secret = config
            .get("clientSecret")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let (client_id, client_secret) = match (configured_client_id, configured_client_secret) {
            (Some(id), Some(secret)) => (id.to_owned(), secret.to_owned()),
            (None, None) => (
                DEFAULT_CLIENT_ID.to_owned(),
                DEFAULT_CLIENT_SECRET.to_owned(),
            ),
            _ => {
                return Err(ApiError::BadRequest(
                    "百度开放平台 API Key 与 Secret Key 必须同时填写或同时留空".into(),
                ));
            }
        };
        let upload_threads = config
            .get("uploadThreads")
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.trim().parse().ok()))
            .map_or(DEFAULT_UPLOAD_THREADS, |n| (n as usize).clamp(1, 32));
        let account_key = account_key(&download_cookie);
        let upload_slots = upload_slots_for(account_key, upload_threads);
        Ok(Self {
            root,
            xpan_api_base: parse_url("openApiBase", XPAN_API)?,
            oauth_token_api: parse_url("oauthTokenUrl", OAUTH_TOKEN_API)?,
            oauth_device_code_api: parse_url("oauthDeviceCodeUrl", OAUTH_DEVICE_CODE_API)?,
            oauth_device_approve_api: parse_url("oauthDeviceApproveUrl", OAUTH_DEVICE_APPROVE_API)?,
            pcs_api_base: parse_url("pcsApiBase", PCS_FILE_API)?,
            upload_api_base: parse_url("uploadApiBase", PCS_UPLOAD_API)?,
            upload_locate_api: parse_url("uploadLocateApi", PCS_LOCATE_UPLOAD_API)?,
            client_id,
            client_secret,
            tokens: Mutex::new(OAuthTokens {
                access_token: config
                    .get("accessToken")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned(),
                refresh_token: config
                    .get("refreshToken")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned(),
                access_expires_at: config
                    .get("accessTokenExpiresAt")
                    .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok())),
            }),
            persist_tokens,
            download_cookie,
            web_user_agent: HeaderValue::from_static(DEFAULT_WEB_UA),
            download_user_agent,
            http,
            links: Mutex::new(HashMap::new()),
            link_locks: Mutex::new(HashMap::new()),
            upload_slots,
            upload_threads,
            account_key,
        })
    }

    fn remote_path(&self, rel: &str) -> String {
        if rel.is_empty() {
            return self.root.clone();
        }
        if self.root == "/" {
            format!("/{rel}")
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    fn xpan_url(&self, endpoint: &str) -> ApiResult<Url> {
        self.xpan_api_base
            .join(endpoint)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("构造百度开放平台地址失败: {e}")))
    }

    fn web_request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(USER_AGENT, self.web_user_agent.clone())
    }

    async fn response_json(resp: reqwest::Response, what: &str) -> ApiResult<Value> {
        let status = resp.status();
        let url = log_url(resp.url());
        // 失败时响应体可能为空（如 superfile2 偶发 500），响应头是仅剩线索
        let headers = super::log_headers(resp.headers());
        let text = resp.text().await.map_err(|e| {
            tracing::error!(
                "百度网盘{what}读取响应失败: HTTP {status} 请求: {url} 响应头: {headers} err: {e}"
            );
            ApiError::Upstream(format!("读取百度网盘{what}响应失败: {e}"))
        })?;
        if !status.is_success() {
            tracing::error!(
                "百度网盘{what}失败: HTTP {status} 请求: {url} 响应头: {headers} 原始响应: {}",
                log_body(&text),
            );
            return Err(ApiError::Upstream(format!(
                "百度网盘{what}失败 ({status}): {}",
                if text.trim().is_empty() {
                    "(空响应体，详见日志文件)".to_string()
                } else {
                    text.chars().take(300).collect::<String>()
                },
            )));
        }
        if text.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&text).map_err(|e| {
            tracing::error!(
                "百度网盘{what}响应无法解析: HTTP {status} 请求: {url} 响应头: {headers} 原始响应: {}",
                log_body(&text),
            );
            ApiError::Upstream(format!("解析百度网盘{what}响应失败: {e}; {text}"))
        })
    }

    fn api_code(value: &Value) -> i64 {
        value
            .get("errno")
            .or_else(|| value.get("error_code"))
            .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
            .unwrap_or(0)
    }

    fn ensure_api_ok(value: &Value, what: &str, allowed: &[i64]) -> ApiResult<()> {
        let code = Self::api_code(value);
        if code == 0 || allowed.contains(&code) {
            return Ok(());
        }
        let message = value
            .get("errmsg")
            .or_else(|| value.get("error_msg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        if matches!(code, -9 | 31066) {
            return Err(ApiError::NotFound(format!("百度网盘{what}: 不存在")));
        }
        Err(ApiError::Upstream(format!(
            "百度网盘{what}失败: code={code}, {message}"
        )))
    }

    async fn access_token(&self) -> ApiResult<String> {
        let refresh_before = unix_time_secs().saturating_add(TOKEN_REFRESH_SKEW_SECS);
        let needs_refresh = {
            let tokens = self.tokens.lock().await;
            tokens.access_token.is_empty()
                || tokens
                    .access_expires_at
                    .is_none_or(|expires| expires <= refresh_before)
        };
        if needs_refresh {
            self.refresh_access_token(None).await
        } else {
            Ok(self.tokens.lock().await.access_token.clone())
        }
    }

    async fn refresh_access_token(&self, invalid_token: Option<&str>) -> ApiResult<String> {
        let mut tokens = self.tokens.lock().await;
        if let Some(invalid) = invalid_token
            && !tokens.access_token.is_empty()
            && tokens.access_token != invalid
        {
            return Ok(tokens.access_token.clone());
        }
        let now = unix_time_secs();
        let value = if tokens.refresh_token.is_empty() {
            let mut code_url = self.oauth_device_code_api.clone();
            code_url
                .query_pairs_mut()
                .append_pair("response_type", "device_code")
                .append_pair("openapi", "xpansdk")
                .append_pair("client_id", &self.client_id)
                .append_pair("client_secret", &self.client_secret)
                .append_pair("scope", "basic,netdisk");
            let code_resp = self
                .http
                .get(code_url)
                .header(USER_AGENT, "pan.baidu.com")
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("获取百度设备码失败: {}", mask_err(&e))))?;
            let code_info = Self::response_json(code_resp, "获取设备码").await?;
            let device_code = code_info
                .get("device_code")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::Upstream(format!("设备码响应无 device_code: {code_info}"))
                })?;
            let user_code = code_info
                .get("user_code")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::Upstream(format!("设备码响应无 user_code: {code_info}"))
                })?;

            let mut approve_url = self.oauth_device_approve_api.clone();
            approve_url
                .query_pairs_mut()
                .append_pair("code", user_code)
                .append_pair("display", "page")
                .append_pair("redirect_uri", "")
                .append_pair("force_login", "");
            let approve = self
                .web_request(Method::GET, approve_url)
                .header(COOKIE, self.download_cookie.clone())
                .send()
                .await
                .map_err(|e| {
                    ApiError::Upstream(format!("使用 BDUSS 授权设备码失败: {}", mask_err(&e)))
                })?;
            if !approve.status().is_success() {
                return Err(ApiError::Upstream(format!(
                    "使用 BDUSS 授权设备码失败: HTTP {}",
                    approve.status()
                )));
            }

            let interval = code_info
                .get("interval")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .clamp(1, 5);
            let mut token_info = None;
            for attempt in 0..6 {
                let mut token_url = self.oauth_token_api.clone();
                token_url
                    .query_pairs_mut()
                    .append_pair("grant_type", "device_token")
                    .append_pair("openapi", "xpansdk")
                    .append_pair("code", device_code)
                    .append_pair("client_id", &self.client_id)
                    .append_pair("client_secret", &self.client_secret);
                let token_resp = self
                    .web_request(Method::GET, token_url)
                    .send()
                    .await
                    .map_err(|e| {
                        ApiError::Upstream(format!("设备码换取令牌失败: {}", mask_err(&e)))
                    })?;
                let candidate = Self::response_json(token_resp, "设备码换取令牌").await?;
                let pending = candidate
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|error| matches!(error, "authorization_pending" | "slow_down"));
                if !pending {
                    token_info = Some(candidate);
                    break;
                }
                if attempt < 5 {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
            }
            token_info
                .ok_or_else(|| ApiError::Upstream("BDUSS 设备授权超时，请确认 BDUSS 有效".into()))?
        } else {
            let mut url = self.oauth_token_api.clone();
            url.query_pairs_mut()
                .append_pair("grant_type", "refresh_token")
                .append_pair("openapi", "xpansdk")
                .append_pair("refresh_token", &tokens.refresh_token)
                .append_pair("client_id", &self.client_id)
                .append_pair("client_secret", &self.client_secret);
            let resp = self
                .web_request(Method::GET, url)
                .send()
                .await
                .map_err(|e| {
                    ApiError::Upstream(format!("刷新百度开放平台令牌失败: {}", mask_err(&e)))
                })?;
            Self::response_json(resp, "刷新开放平台令牌").await?
        };
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            let description = value
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            // 失败响应只含 error/error_description，无凭据，可整体落日志
            tracing::error!(
                "百度 OAuth 令牌请求被拒: grant_type={} 原始响应: {}",
                if tokens.refresh_token.is_empty() {
                    "device_token"
                } else {
                    "refresh_token"
                },
                truncate_chars(&value.to_string(), LOG_BODY_MAX),
            );
            return Err(ApiError::Upstream(format!(
                "刷新百度开放平台令牌失败: {error}: {description}"
            )));
        }
        let access = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("刷新令牌响应缺少 access_token".into()))?
            .to_owned();
        let refresh = value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&tokens.refresh_token)
            .to_owned();
        let access_ttl = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_ACCESS_TOKEN_TTL_SECS);
        let access_expires_at = now.saturating_add(access_ttl);
        if let Some(persist) = &self.persist_tokens {
            persist(&access, &refresh, access_expires_at)?;
        }
        tokens.access_token = access.clone();
        tokens.refresh_token = refresh;
        tokens.access_expires_at = Some(access_expires_at);
        tracing::info!(
            "百度开放平台令牌已更新: {} (有效期 {access_ttl}s)",
            mask_secret(&access),
        );
        Ok(access)
    }

    async fn xpan_request(
        &self,
        method: Method,
        endpoint: &str,
        query: &[(&str, String)],
        form: Option<&[(String, String)]>,
        what: &str,
        allowed: &[i64],
    ) -> ApiResult<Value> {
        let mut token = self.access_token().await?;
        // 失败日志用（惰性构造）：query 不含 access_token（已单独脱敏），form 原样截断
        let query_log = || log_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        let form_log = || {
            form.map_or_else(String::new, |f| {
                log_pairs(f.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            })
        };
        let mut refreshed = false;
        let mut last_err: Option<ApiError> = None;
        // 瞬时故障（网络错误 / 5xx）兜底重试；errno 拒绝是确定性失败，不重试
        for attempt in 1..=3usize {
            let mut url = self.xpan_url(endpoint)?;
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("access_token", &token);
                // 官方 Python SDK：所有开放平台请求都带此标识
                pairs.append_pair("openapi", "xpansdk");
                for (key, value) in query {
                    pairs.append_pair(key, value);
                }
            }
            // 正常请求也留痕（token 首尾可辨认）；日常 CRUD 走 debug 免刷屏
            tracing::debug!("百度网盘{what}请求: {method} {}", log_url(&url));
            let mut request = self.web_request(method.clone(), url);
            if let Some(form) = form {
                request = request.form(form);
            }
            let resp = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    let masked = mask_err(&e);
                    tracing::warn!(
                        "百度网盘{what}请求发送失败(第 {attempt}/3 次): {method} {endpoint} query: {} form: {} err: {masked}",
                        query_log(),
                        form_log(),
                    );
                    last_err = Some(ApiError::Upstream(format!(
                        "百度网盘{what}请求失败: {masked}"
                    )));
                    tokio::time::sleep(Duration::from_millis(RETRY_BACKOFF_MS * attempt as u64))
                        .await;
                    continue;
                }
            };
            let status = resp.status();
            let value = match Self::response_json(resp, what).await {
                Ok(value) => value,
                Err(e) => {
                    // response_json 已记录请求地址与原始响应，这里补 form 体
                    if form.is_some() {
                        tracing::error!("百度网盘{what}失败时的 form 参数: {}", form_log());
                    }
                    // 5xx 属上游瞬时故障（bfe 偶发 500/502），重试；4xx 等确定性失败直接返回
                    if !status.is_server_error() {
                        return Err(e);
                    }
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(RETRY_BACKOFF_MS * attempt as u64))
                        .await;
                    continue;
                }
            };
            if matches!(Self::api_code(&value), 111 | -6) && !refreshed {
                refreshed = true;
                token = self.refresh_access_token(Some(&token)).await?;
                continue;
            }
            if let Err(e) = Self::ensure_api_ok(&value, what, allowed) {
                tracing::error!(
                    "百度网盘{what}被拒: {method} {endpoint} query: {} form: {} 原始响应: {}",
                    query_log(),
                    form_log(),
                    truncate_chars(&value.to_string(), LOG_BODY_MAX),
                );
                return Err(e);
            }
            return Ok(value);
        }
        Err(last_err.unwrap_or_else(|| ApiError::Upstream(format!("百度网盘{what}失败: 重试耗尽"))))
    }

    async fn locatedownload(&self, remote_path: &str) -> ApiResult<Vec<String>> {
        {
            let links = self.links.lock().await;
            if let Some(hit) = links.get(remote_path)
                && hit.inserted.elapsed() < LINK_TTL
            {
                return Ok(hit.urls.clone());
            }
        }
        let path_lock = {
            let mut locks = self.link_locks.lock().await;
            Arc::clone(
                locks
                    .entry(remote_path.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = path_lock.lock().await;
        {
            let links = self.links.lock().await;
            if let Some(hit) = links.get(remote_path)
                && hit.inserted.elapsed() < LINK_TTL
            {
                return Ok(hit.urls.clone());
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let random = uuid::Uuid::new_v4().simple().to_string();
        let mut url = self.pcs_api_base.clone();
        {
            let mut q = url.query_pairs_mut();
            for (key, value) in [
                ("app_id", PAN_APP_ID),
                ("method", "locatedownload"),
                ("check_blue", "1"),
                ("es", "1"),
                ("esl", "1"),
                ("path", remote_path),
                ("ver", "4.0"),
                ("dtype", "1"),
                ("err_ver", "1.0"),
                ("ehps", "1"),
                ("eck", "1"),
                ("vip", "0"),
                ("clienttype", "17"),
                ("version", "2.2.61.31"),
                ("time", &now),
                ("rand", &random),
                ("devuid", "E8E43120BC3C98E0EAAEA7BF7749C465|VJXGDD546"),
                ("channel", "0"),
                ("version_app", "9999"),
                ("apn_id", "1.0"),
                ("freeisp", "0"),
                ("queryfree", "0"),
                ("cuid", "12345620BC3C98E0EAAEA7BF7749C465|VJXGDD547"),
                ("use", "1"),
            ] {
                q.append_pair(key, value);
            }
        }
        let resp = self
            .http
            .get(url)
            .header(USER_AGENT, self.download_user_agent.clone())
            .header(COOKIE, self.download_cookie.clone())
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("百度网盘获取下载链接失败: {e}")))?;
        let value = Self::response_json(resp, "获取下载链接").await?;
        if let Err(e) = Self::ensure_api_ok(&value, "获取下载链接", &[]) {
            tracing::error!(
                "百度网盘获取下载链接被拒: path={remote_path} 原始响应: {}",
                truncate_chars(&value.to_string(), LOG_BODY_MAX),
            );
            return Err(e);
        }
        let urls = value
            .get("urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("url").and_then(Value::as_str))
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if urls.is_empty() {
            return Err(ApiError::Upstream(format!(
                "百度网盘下载链接响应中没有 urls: {value}"
            )));
        }
        self.links.lock().await.insert(
            remote_path.to_owned(),
            CachedLinks {
                inserted: Instant::now(),
                urls: urls.clone(),
            },
        );
        Ok(urls)
    }

    async fn invalidate_links_if_same(&self, remote_path: &str, used_urls: &[String]) {
        let mut links = self.links.lock().await;
        if links
            .get(remote_path)
            .is_some_and(|cached| cached.urls == used_urls)
        {
            links.remove(remote_path);
        }
    }

    async fn download_response(
        &self,
        remote_path: &str,
        range: Option<(u64, u64)>,
    ) -> ApiResult<reqwest::Response> {
        for attempt in 0..2 {
            let urls = self.locatedownload(remote_path).await?;
            let pick =
                range.map_or(0, |(start, _)| (start / MAX_PREVIEW_RANGE) as usize) % urls.len();
            let url = Url::parse(&urls[pick])
                .map_err(|e| ApiError::Upstream(format!("百度返回非法下载链接: {e}")))?;
            let mut request = self
                .http
                .get(url)
                .header(USER_AGENT, self.download_user_agent.clone())
                .header(COOKIE, self.download_cookie.clone());
            if let Some((start, end)) = range {
                request = request.header(RANGE, format!("bytes={start}-{end}"));
            }
            let resp = request
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("百度网盘下载请求失败: {e}")))?;
            if resp.status().is_success() {
                return Ok(resp);
            }
            if attempt == 0
                && matches!(resp.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND)
            {
                self.invalidate_links_if_same(remote_path, &urls).await;
                continue;
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Upstream(format!(
                "百度网盘下载失败 ({status}): {}",
                body.chars().take(300).collect::<String>()
            )));
        }
        unreachable!()
    }

    async fn spool_upload(
        &self,
        size: u64,
        slice_size: usize,
        mut body: ByteStream,
    ) -> ApiResult<SpooledUpload> {
        if size == 0 {
            return Err(ApiError::BadRequest("百度网盘开放平台不支持空文件".into()));
        }
        let block_count = size.div_ceil(slice_size as u64) as usize;
        if block_count > MAX_UPLOAD_BLOCKS {
            return Err(ApiError::BadRequest(format!(
                "单个百度网盘分卷超过开放平台上限: {block_count} 块"
            )));
        }
        let temp = TempUpload::new();
        let mut file = tokio::fs::File::create(&temp.path).await?;
        let mut block = Md5::new();
        let mut block_bytes = 0usize;
        let mut received = 0u64;
        let mut block_md5 = Vec::with_capacity(block_count);
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            received = received.saturating_add(chunk.len() as u64);
            if received > size {
                return Err(ApiError::BadRequest("上传数据超过声明大小".into()));
            }
            file.write_all(&chunk).await?;
            let mut offset = 0usize;
            while offset < chunk.len() {
                let take = (slice_size - block_bytes).min(chunk.len() - offset);
                block.update(&chunk[offset..offset + take]);
                block_bytes += take;
                offset += take;
                if block_bytes == slice_size {
                    block_md5.push(hex::encode(block.finalize_reset()));
                    block_bytes = 0;
                }
            }
        }
        file.flush().await?;
        drop(file);
        if received != size {
            return Err(ApiError::BadRequest(format!(
                "上传数据大小不匹配: 声明 {size}，实际 {received}"
            )));
        }
        if block_bytes != 0 {
            block_md5.push(hex::encode(block.finalize()));
        }
        Ok(SpooledUpload { temp, block_md5 })
    }

    async fn read_upload_block(
        path: &Path,
        part_seq: usize,
        size: u64,
        slice_size: usize,
    ) -> ApiResult<Bytes> {
        let offset = part_seq as u64 * slice_size as u64;
        let length = (size - offset).min(slice_size as u64) as usize;
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).await?;
        Ok(Bytes::from(bytes))
    }

    /// 会员类型（0 普通 / 1 会员 / 2 超级会员），决定分片大小。
    /// 账号级缓存；查询失败按普通账号处理（4MiB 分片总是可用）。
    async fn vip_type(&self) -> i64 {
        if let Some(&cached) = VIP_TYPES.lock().unwrap().get(&self.account_key) {
            return cached;
        }
        let vip = match self
            .xpan_request(
                Method::GET,
                "xpan/nas",
                &[("method", "uinfo".into())],
                None,
                "查询账号信息",
                &[],
            )
            .await
        {
            Ok(value) => value.get("vip_type").and_then(Value::as_i64).unwrap_or(0),
            Err(e) => {
                tracing::warn!("百度网盘查询会员类型失败，按普通账号 4MiB 分片: {e}");
                return 0;
            }
        };
        VIP_TYPES.lock().unwrap().insert(self.account_key, vip);
        vip
    }

    fn slice_size_for(vip_type: i64) -> usize {
        match vip_type {
            2 => SVIP_SLICE_SIZE,
            1 => VIP_SLICE_SIZE,
            _ => DEFAULT_SLICE_SIZE,
        }
    }

    /// locateupload 动态获取最近的上传集群域名（OpenList 实测这是高速
    /// 上传的关键：静态 d.pcs.baidu.com 常被调度到远端/限速节点）。
    /// 失败时回退配置的静态上传地址。
    async fn upload_url(&self, remote: &str, upload_id: &str) -> Url {
        let fallback = self.upload_api_base.clone();
        let token = match self.access_token().await {
            Ok(token) => token,
            Err(_) => return fallback,
        };
        let mut url = self.upload_locate_api.clone();
        url.query_pairs_mut()
            .append_pair("method", "locateupload")
            .append_pair("appid", PAN_APP_ID)
            .append_pair("access_token", &token)
            .append_pair("path", remote)
            .append_pair("uploadid", upload_id)
            .append_pair("upload_version", "2.0");
        let server = async {
            let resp = self.web_request(Method::GET, url).send().await.ok()?;
            let value = Self::response_json(resp, "获取上传域名").await.ok()?;
            let pick = |key: &str| {
                value
                    .get(key)?
                    .as_array()?
                    .iter()
                    .filter_map(|item| item.get("server")?.as_str())
                    .find(|server| server.starts_with("https://") || server.starts_with("http://"))
                    .map(str::to_owned)
            };
            pick("servers").or_else(|| pick("bak_servers"))
        }
        .await;
        match server.and_then(|server| {
            Url::parse(&server)
                .ok()?
                .join("/rest/2.0/pcs/superfile2")
                .ok()
        }) {
            Some(url) => {
                tracing::info!(
                    "百度网盘 locateupload 选定上传域名: {}",
                    url.host_str().unwrap_or("?"),
                );
                url
            }
            None => {
                tracing::warn!("百度网盘 locateupload 未返回可用域名，回退静态上传地址");
                fallback
            }
        }
    }

    async fn upload_block_once(
        &self,
        upload_url: &Url,
        remote: &str,
        upload_id: &str,
        part_seq: usize,
        block: Bytes,
        token: &str,
    ) -> ApiResult<Value> {
        // 对齐 OpenList：superfile2 带 method/access_token/type=tmpfile/
        // path/uploadid/partseq（不带 openapi），multipart 字段名 "file"
        let mut url = upload_url.clone();
        url.query_pairs_mut()
            .append_pair("method", "upload")
            .append_pair("access_token", token)
            .append_pair("type", "tmpfile")
            .append_pair("path", remote)
            .append_pair("uploadid", upload_id)
            .append_pair("partseq", &part_seq.to_string());
        let len = block.len() as u64;
        // 正常请求留痕：实际上传地址（locateupload 动态域名）+ 所用 token（首尾可辨认）
        tracing::info!("百度网盘上传分块: POST {} len={len}", log_url(&url));
        let part = Part::stream_with_length(reqwest::Body::from(block), len)
            .file_name("file")
            .mime_str("application/octet-stream")
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
        let resp = self
            .web_request(Method::POST, url)
            .multipart(Form::new().part("file", part))
            .send()
            .await
            .map_err(|e| {
                ApiError::Upstream(format!(
                    "百度网盘上传第 {part_seq} 块失败: {}",
                    mask_err(&e)
                ))
            })?;
        Self::response_json(resp, "上传文件块").await
    }

    async fn upload_block(
        &self,
        upload_url: &Url,
        remote: &str,
        upload_id: &str,
        part_seq: usize,
        block: Bytes,
    ) -> ApiResult<()> {
        let mut token = self.access_token().await?;
        let block_len = block.len();
        let mut refreshed = false;
        let mut last_err: Option<ApiError> = None;
        // OpenList/官方 SDK 均对 superfile2 重试 3 次；偶发 500 重试即恢复
        for attempt in 1..=3usize {
            let result = {
                // 账号级并发槽：限制同账号跨文件/跨分卷的 superfile2 总并发
                let _permit = self
                    .upload_slots
                    .acquire()
                    .await
                    .map_err(|_| ApiError::Internal(anyhow::anyhow!("上传并发槽已关闭")))?;
                self.upload_block_once(
                    upload_url,
                    remote,
                    upload_id,
                    part_seq,
                    block.clone(),
                    &token,
                )
                .await
            };
            let value = match result {
                Ok(value) => value,
                Err(e) => {
                    tracing::warn!(
                        "百度网盘上传分块第 {attempt}/3 次失败: path={remote} uploadid={upload_id} partseq={part_seq} len={block_len} err: {e}"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(RETRY_BACKOFF_MS * attempt as u64))
                        .await;
                    continue;
                }
            };
            if matches!(Self::api_code(&value), 111 | -6) && !refreshed {
                refreshed = true;
                token = self.refresh_access_token(Some(&token)).await?;
                continue;
            }
            // errno != 0 是确定性拒绝，不重试
            if let Err(e) = Self::ensure_api_ok(&value, "上传文件块", &[]) {
                tracing::error!(
                    "百度网盘上传分块被拒: path={remote} uploadid={upload_id} partseq={part_seq} len={block_len} 原始响应: {}",
                    truncate_chars(&value.to_string(), LOG_BODY_MAX),
                );
                return Err(e);
            }
            // 官方 SDK 校验：成功响应必须带该分块的 md5
            if value
                .get("md5")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                tracing::error!(
                    "百度网盘上传分块未返回 md5: path={remote} uploadid={upload_id} partseq={part_seq} len={block_len} 原始响应: {}",
                    truncate_chars(&value.to_string(), LOG_BODY_MAX),
                );
                return Err(ApiError::Upstream(format!(
                    "百度网盘上传第 {part_seq} 块异常: 响应未返回 md5"
                )));
            }
            return Ok(());
        }
        Err(last_err.unwrap_or_else(|| {
            ApiError::Upstream(format!("百度网盘上传第 {part_seq} 块失败: 重试耗尽"))
        }))
    }

    async fn upload_sized(
        &self,
        path: &str,
        size: u64,
        body: ByteStream,
        progress: ProgressFn,
    ) -> ApiResult<()> {
        let remote = self.remote_path(path);
        let slice_size = Self::slice_size_for(self.vip_type().await);
        // spool 阶段只是本地落盘算 md5，不算上传进度
        let spooled = self.spool_upload(size, slice_size, body).await?;
        tracing::info!(
            "百度网盘上传分卷开始: path={remote} size={size} 分片大小={slice_size} 分块数={}",
            spooled.block_md5.len(),
        );
        // 进度高水位：report 收「本卷累计已确认字节」，只把超出历史水位的
        // 增量转发给 progress —— 整卷重试时已上报的字节不会重复计数
        let reported = Arc::new(AtomicU64::new(0));
        let report: ProgressFn = {
            let reported = Arc::clone(&reported);
            Arc::new(move |confirmed: u64| {
                let mut prev = reported.load(Ordering::Relaxed);
                while confirmed > prev {
                    match reported.compare_exchange(
                        prev,
                        confirmed,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            progress(confirmed - prev);
                            break;
                        }
                        Err(now) => prev = now,
                    }
                }
            })
        };
        // 整卷兜底重试：块级/请求级重试都耗尽后，隔段时间从 precreate 重来
        // （分卷已落盘，重试不需要重新接收数据）
        let mut last_err: Option<ApiError> = None;
        for attempt in 1..=3usize {
            match self
                .upload_spooled(&remote, size, slice_size, &spooled, &report)
                .await
            {
                Ok(()) => {
                    tracing::info!("百度网盘分卷上传完成: path={remote} size={size}");
                    return Ok(());
                }
                // 只有上游瞬时故障值得整卷重试；BadRequest 等确定性错误直接失败
                Err(e @ ApiError::Upstream(_)) if attempt < 3 => {
                    tracing::warn!(
                        "百度网盘分卷上传第 {attempt}/3 次失败，稍后整卷重试: path={remote} err: {e}"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(
                        VOLUME_RETRY_BACKOFF_MS * attempt as u64,
                    ))
                    .await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            ApiError::Upstream(format!("百度网盘分卷上传失败: 重试耗尽 path={remote}"))
        }))
    }

    /// 已落盘分卷的 precreate → superfile2 分块 → create 全流程。
    /// `report` 语义为「本卷累计已确认字节」（高水位去重，可安全重放）。
    async fn upload_spooled(
        &self,
        remote: &str,
        size: u64,
        slice_size: usize,
        spooled: &SpooledUpload,
        report: &ProgressFn,
    ) -> ApiResult<()> {
        let block_list = serde_json::to_string(&spooled.block_md5).unwrap();
        // 官方 SDK 表单：path/size/block_list/isdir/autoinit/rtype，
        // 不带 content-md5 / slice-md5（秒传探测对唯一密文永不命中）
        let precreate = self
            .xpan_request(
                Method::POST,
                "xpan/file",
                &[("method", "precreate".into())],
                Some(&[
                    ("path".into(), remote.to_owned()),
                    ("size".into(), size.to_string()),
                    ("block_list".into(), block_list.clone()),
                    ("isdir".into(), "0".into()),
                    ("autoinit".into(), "1".into()),
                    // path 冲突且 block_list 不同才重命名（与官方 SDK 一致）
                    ("rtype".into(), "2".into()),
                ]),
                "预创建上传",
                &[],
            )
            .await?;
        if precreate
            .get("return_type")
            .and_then(Value::as_i64)
            .is_some_and(|kind| kind == 2)
        {
            tracing::info!("百度网盘秒传命中: path={remote}");
            report(size); // 秒传：整卷即刻完成
            return Ok(());
        }
        let upload_id = precreate
            .get("uploadid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ApiError::Upstream(format!("预创建未返回 uploadid: {precreate}")))?
            .to_owned();
        let missing = precreate
            .get("block_list")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_u64)
                    .map(|index| index as usize)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| (0..spooled.block_md5.len()).collect());
        let block_count = spooled.block_md5.len();
        tracing::info!(
            "百度网盘 precreate 完成: uploadid={upload_id} 待传分块 {}/{block_count}",
            missing.len(),
        );
        let temp_path = spooled.temp.path.clone();
        // 分块字节数（末块可能不满）；越界序号记 0，后面会精确报错
        let block_len = |seq: usize| -> u64 {
            size.saturating_sub(seq as u64 * slice_size as u64)
                .min(slice_size as u64)
        };
        // precreate 未列出的分块 = 上游已持有，直接计入进度
        let missing_bytes: u64 = missing.iter().map(|&seq| block_len(seq)).sum();
        let confirmed = Arc::new(AtomicU64::new(size.saturating_sub(missing_bytes)));
        report(confirmed.load(Ordering::Relaxed));
        // 每个分卷取一次动态上传域名（uploadid 生命周期内有效）
        let upload_url = self.upload_url(remote, &upload_id).await;
        stream::iter(missing)
            .map(|part_seq| {
                let remote = remote.to_owned();
                let upload_id = upload_id.clone();
                let upload_url = upload_url.clone();
                let path = temp_path.clone();
                let confirmed = Arc::clone(&confirmed);
                let report = Arc::clone(report);
                async move {
                    if part_seq >= block_count {
                        return Err(ApiError::Upstream(format!(
                            "百度返回非法上传分片序号: {part_seq}"
                        )));
                    }
                    let block = Self::read_upload_block(&path, part_seq, size, slice_size).await?;
                    let len = block.len() as u64;
                    self.upload_block(&upload_url, &remote, &upload_id, part_seq, block)
                        .await?;
                    report(confirmed.fetch_add(len, Ordering::Relaxed) + len);
                    Ok(())
                }
            })
            .buffer_unordered(self.upload_threads)
            .try_collect::<Vec<_>>()
            .await?;
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "create".into())],
            Some(&[
                ("rtype".into(), "2".into()),
                ("path".into(), remote.to_owned()),
                ("size".into(), size.to_string()),
                ("isdir".into(), "0".into()),
                ("block_list".into(), block_list),
                ("uploadid".into(), upload_id),
            ]),
            "合并上传文件",
            &[],
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Storage for BaiduPanFs {
    fn max_range_size(&self) -> Option<u64> {
        Some(MAX_PREVIEW_RANGE)
    }

    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        let remote = self.remote_path(path);
        const LIMIT: usize = 1000;
        let mut entries = Vec::new();
        for start in (0..10_000_000usize).step_by(LIMIT) {
            let value = self
                .xpan_request(
                    Method::GET,
                    "xpan/file",
                    &[
                        ("method", "list".into()),
                        ("dir", remote.clone()),
                        ("web", "web".into()),
                        ("order", "name".into()),
                        ("desc", "0".into()),
                        ("start", start.to_string()),
                        ("limit", LIMIT.to_string()),
                    ],
                    None,
                    "列目录",
                    &[],
                )
                .await?;
            let items: Vec<BaiduListItem> =
                serde_json::from_value(value.get("list").cloned().unwrap_or_else(|| json!([])))
                    .map_err(|e| ApiError::Upstream(format!("解析百度网盘目录条目失败: {e}")))?;
            let count = items.len();
            entries.extend(items.into_iter().map(|item| Entry {
                name: item.server_filename,
                is_dir: item.isdir == 1,
                size: item.size,
                mtime: item.server_mtime.saturating_mul(1000),
            }));
            if count < LIMIT {
                return Ok(entries);
            }
        }
        Err(ApiError::Upstream("百度网盘列目录分页超过安全上限".into()))
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        let remote = self.remote_path(path);
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "create".into())],
            Some(&[
                ("path".into(), remote),
                ("size".into(), "0".into()),
                ("isdir".into(), "1".into()),
                ("rtype".into(), "3".into()),
            ]),
            "创建目录",
            &[-8, 31061],
        )
        .await
        .map(|_| ())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        // 官方 Python SDK 演示形态：filelist 为对象数组
        let file_list = json!([{"path": self.remote_path(path)}]).to_string();
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "filemanager".into()), ("opera", "delete".into())],
            Some(&[
                ("async".into(), "0".into()),
                ("filelist".into(), file_list),
                ("ondup".into(), "fail".into()),
            ]),
            "删除",
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法移动或重命名路径".into()));
        }
        let from = self.remote_path(from);
        let to = self.remote_path(to);
        let (from_parent, _) = from
            .rsplit_once('/')
            .ok_or_else(|| ApiError::BadRequest("非法来源路径".into()))?;
        let (to_parent, new_name) = to
            .rsplit_once('/')
            .ok_or_else(|| ApiError::BadRequest("非法目标路径".into()))?;
        let (operation, file_list) = if from_parent == to_parent {
            (
                "rename",
                json!([{"path": from, "newname": new_name}]).to_string(),
            )
        } else {
            let destination = if to_parent.is_empty() { "/" } else { to_parent };
            (
                "move",
                json!([{"path": from, "dest": destination, "newname": new_name}]).to_string(),
            )
        };
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[
                ("method", "filemanager".into()),
                ("opera", operation.into()),
            ],
            Some(&[
                ("async".into(), "0".into()),
                ("filelist".into(), file_list),
                ("ondup".into(), "fail".into()),
            ]),
            "移动或重命名",
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        let resp = self
            .download_response(&self.remote_path(path), None)
            .await?;
        let size = resp.content_length();
        Ok((
            size,
            resp.bytes_stream().map_err(std::io::Error::other).boxed(),
        ))
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        if end < start || end - start + 1 > MAX_PREVIEW_RANGE {
            return Err(ApiError::BadRequest(
                "百度网盘单个下载分片必须在 1..=5MiB".into(),
            ));
        }
        let resp = self
            .download_response(&self.remote_path(path), Some((start, end)))
            .await?;
        if resp.status() != StatusCode::PARTIAL_CONTENT {
            return Err(ApiError::Upstream(format!(
                "百度网盘忽略 Range 请求，返回 {}",
                resp.status()
            )));
        }
        let expected = format!("bytes {start}-{end}/");
        let actual = resp
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !actual.starts_with(&expected) {
            return Err(ApiError::Upstream(format!(
                "百度网盘 Content-Range 不匹配: 期望 {expected}*, 实际 {actual}"
            )));
        }
        Ok(resp.bytes_stream().map_err(std::io::Error::other).boxed())
    }

    async fn put(&self, path: &str, mut body: ByteStream) -> ApiResult<()> {
        const MAX_BUFFERED: usize = 512 * 1024 * 1024;
        let mut bytes = BytesMut::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > MAX_BUFFERED {
                return Err(ApiError::BadRequest(
                    "百度网盘未知长度上传超过 512MiB".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let size = bytes.len() as u64;
        self.upload_sized(
            path,
            size,
            stream::once(async move { Ok(bytes.freeze()) }).boxed(),
            Arc::new(|_| {}),
        )
        .await
    }

    async fn put_sized(&self, path: &str, size: u64, body: ByteStream) -> ApiResult<()> {
        self.upload_sized(path, size, body, Arc::new(|_| {})).await
    }

    async fn put_sized_tracked(
        &self,
        path: &str,
        size: u64,
        body: ByteStream,
        progress: ProgressFn,
    ) -> ApiResult<()> {
        self.upload_sized(path, size, body, progress).await
    }
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value)
    })
}

// ---------------- 排查日志辅助 ----------------

/// 日志中原始响应体的最大长度（字符）。
const LOG_BODY_MAX: usize = 4096;
/// 单个参数值在日志中的最大长度（block_list 之类可达几十 KB）。
const LOG_PARAM_MAX: usize = 512;

fn truncate_chars(s: &str, max: usize) -> String {
    let total = s.chars().count();
    if total <= max {
        return s.to_owned();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…(截断，共 {total} 字符)")
}

/// 响应体日志形态：空体明确标注（区别于「没打出来」），非空截断。
fn log_body(text: &str) -> String {
    if text.trim().is_empty() {
        "(空)".to_owned()
    } else {
        truncate_chars(text, LOG_BODY_MAX)
    }
}

/// 凭据脱敏：保留首 8 位 + 尾 6 位（可辨认是哪个 token 而不暴露全值）；
/// 过短的值全遮。
fn mask_secret(value: &str) -> String {
    let n = value.chars().count();
    if n <= 16 {
        return "…(已脱敏)".to_owned();
    }
    let head: String = value.chars().take(8).collect();
    let tail: String = value.chars().skip(n - 6).collect();
    format!("{head}…{tail}(已脱敏,共{n}字符)")
}

/// 参数值脱敏：凭据类走 mask_secret；超长值截断。
fn log_value(key: &str, value: &str) -> String {
    if matches!(
        key,
        "access_token" | "refresh_token" | "client_secret" | "code"
    ) {
        return mask_secret(value);
    }
    truncate_chars(value, LOG_PARAM_MAX)
}

fn log_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={}", log_value(k, v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 完整请求地址（query 参数脱敏后），供错误日志还原现场。
fn log_url(url: &Url) -> String {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut base = url.clone();
    base.set_query(None);
    if pairs.is_empty() {
        return base.to_string();
    }
    let qs = log_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    format!("{base}?{qs}")
}

/// reqwest 错误信息内嵌完整 URL（含 access_token 等凭据），入日志或
/// 返回给客户端前必须脱敏。
fn mask_err(e: &reqwest::Error) -> String {
    mask_credentials(&e.to_string())
}

fn mask_credentials(s: &str) -> String {
    let mut text = s.to_owned();
    for key in ["access_token=", "refresh_token=", "client_secret=", "code="] {
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(pos) = rest.find(key) {
            let start = pos + key.len();
            out.push_str(&rest[..start]);
            let tail = &rest[start..];
            let end = tail.find(['&', ' ', ')']).unwrap_or(tail.len());
            out.push_str(&mask_secret(&tail[..end]));
            rest = &tail[end..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

fn normalize_root(root: &str) -> ApiResult<String> {
    let root = root.trim().replace('\\', "/");
    if root.contains("..") || root.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ApiError::BadRequest("百度网盘根目录非法".into()));
    }
    let normalized = format!("/{}", root.trim_matches('/'));
    Ok(if normalized == "/" {
        normalized
    } else {
        normalized.trim_end_matches('/').to_owned()
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use axum::body::Body;
    use axum::extract::{Form as AxumForm, Query, State};
    use axum::http::{HeaderMap, Response};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    #[derive(Clone)]
    struct MockState {
        download_url: String,
        upload_server: String,
        locate_calls: Arc<AtomicUsize>,
        /// 剩余注入的 upload-create 瞬时 500 次数（模拟 bfe 偶发故障）。
        create_failures: Arc<AtomicUsize>,
    }

    fn config(base: &str) -> Value {
        json!({
            "bduss": "test",
            "root": "/safe",
            "userAgent": "download-android-test",
            "openApiBase": format!("{base}/rest/2.0/"),
            "oauthTokenUrl": format!("{base}/oauth/token"),
            "oauthDeviceCodeUrl": format!("{base}/oauth/device/code"),
            "oauthDeviceApproveUrl": format!("{base}/device"),
            "pcsApiBase": format!("{base}/rest/2.0/pcs/file"),
            "uploadApiBase": format!("{base}/rest/2.0/pcs/superfile2"),
            "uploadLocateApi": format!("{base}/rest/2.0/pcs/locateupload")
        })
    }

    #[test]
    fn mask_credentials_hides_all_secret_query_values() {
        let raw = "error sending request for url (https://pan.baidu.com/rest/2.0/xpan/file?access_token=126.a7b45358db9a19f7022eec804c56a140.YGiVySf2.i0ZBMw&openapi=xpansdk&method=create)";
        let masked = mask_credentials(raw);
        assert!(
            !masked.contains("a7b45358db9a19f7022eec804c56a140"),
            "{masked}"
        );
        assert!(
            masked.contains("access_token=126.a7b4…i0ZBMw(已脱敏"),
            "首尾保留便于辨认 token: {masked}"
        );
        assert!(masked.contains("openapi=xpansdk"), "非敏感参数保留");
        let oauth = "url (https://openapi.baidu.com/oauth/2.0/token?grant_type=device_token&code=secret-device-code&client_id=abc&client_secret=verysecretvalue)";
        let masked = mask_credentials(oauth);
        assert!(!masked.contains("verysecretvalue"), "{masked}");
        assert!(!masked.contains("secret-device-code"), "{masked}");
        assert!(masked.contains("client_id=abc"), "{masked}");
    }

    #[tokio::test]
    async fn persisted_access_token_expiry_survives_restart() {
        let mut value = config("http://127.0.0.1:1");
        let object = value.as_object_mut().unwrap();
        object.insert("accessToken".into(), "persisted-access".into());
        object.insert("refreshToken".into(), "persisted-refresh".into());
        object.insert(
            "accessTokenExpiresAt".into(),
            (unix_time_secs() + 3600).into(),
        );
        let fs = BaiduPanFs::from_config_with_persister(&value, Client::new(), None).unwrap();
        assert_eq!(fs.access_token().await.unwrap(), "persisted-access");
    }

    #[test]
    fn validates_config_and_paths() {
        let base = "http://127.0.0.1:1";
        let fs =
            BaiduPanFs::from_config_with_persister(&config(base), Client::new(), None).unwrap();
        assert_eq!(fs.remote_path(""), "/safe");
        assert_eq!(fs.remote_path("a/b"), "/safe/a/b");
        assert_eq!(fs.max_range_size(), Some(5 * 1024 * 1024));
        let mut invalid = config(base);
        invalid.as_object_mut().unwrap().remove("bduss");
        assert!(BaiduPanFs::from_config_with_persister(&invalid, Client::new(), None).is_err());
        let mut half_client = config(base);
        half_client["clientId"] = "custom-client".into();
        assert!(BaiduPanFs::from_config_with_persister(&half_client, Client::new(), None).is_err());
        assert!(normalize_root("/a/../b").is_err());
    }

    #[tokio::test]
    async fn spooling_uses_official_block_md5_and_cleans_up() {
        let fs = BaiduPanFs::from_config_with_persister(
            &config("http://127.0.0.1:1"),
            Client::new(),
            None,
        )
        .unwrap();
        let data = (0..DEFAULT_SLICE_SIZE + 37)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let chunks = vec![
            Bytes::copy_from_slice(&data[..123_457]),
            Bytes::copy_from_slice(&data[123_457..3_500_001]),
            Bytes::copy_from_slice(&data[3_500_001..]),
        ];
        let spooled = fs
            .spool_upload(
                data.len() as u64,
                DEFAULT_SLICE_SIZE,
                stream::iter(chunks.into_iter().map(Ok)).boxed(),
            )
            .await
            .unwrap();
        // 官方 SDK 语义：block_list = 每个分片的 md5（末块不满照算）
        assert_eq!(spooled.block_md5.len(), 2);
        assert_eq!(
            spooled.block_md5[0],
            hex::encode(Md5::digest(&data[..DEFAULT_SLICE_SIZE]))
        );
        assert_eq!(
            spooled.block_md5[1],
            hex::encode(Md5::digest(&data[DEFAULT_SLICE_SIZE..]))
        );
        let temp_path = spooled.temp.path.clone();
        assert!(temp_path.exists());
        drop(spooled);
        assert!(!temp_path.exists());
    }

    #[tokio::test]
    async fn stale_link_invalidation_never_removes_a_concurrent_refresh() {
        let fs = BaiduPanFs::from_config_with_persister(
            &config("http://127.0.0.1:1"),
            Client::new(),
            None,
        )
        .unwrap();
        let old = vec!["https://cdn.example/old".to_owned()];
        let new = vec!["https://cdn.example/new".to_owned()];
        fs.links.lock().await.insert(
            "/safe/volume".into(),
            CachedLinks {
                inserted: Instant::now(),
                urls: new.clone(),
            },
        );
        fs.invalidate_links_if_same("/safe/volume", &old).await;
        assert_eq!(
            fs.links.lock().await["/safe/volume"].urls,
            new,
            "晚到的旧链接 403 不能删除其他分片刚刷新的链接"
        );
        fs.invalidate_links_if_same("/safe/volume", &new).await;
        assert!(!fs.links.lock().await.contains_key("/safe/volume"));
    }

    fn assert_open_headers(headers: &HeaderMap) {
        assert!(headers.get(COOKIE).is_none(), "开放平台请求不得携带 Cookie");
        let ua = headers.get(USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.starts_with("Mozilla/5.0"));
        assert!(!ua.to_ascii_lowercase().contains("android"));
    }

    async fn oauth_token(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(query.get("openapi").map(String::as_str), Some("xpansdk"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some(DEFAULT_CLIENT_ID)
        );
        match query.get("grant_type").map(String::as_str) {
            Some("device_token") => {
                assert_eq!(query.get("code").map(String::as_str), Some("device-code"));
                Json(json!({
                    "access_token": "fresh-token",
                    "refresh_token": "refresh-new",
                    "expires_in": 3600
                }))
            }
            Some("refresh_token") => {
                assert_eq!(
                    query.get("refresh_token").map(String::as_str),
                    Some("refresh-new")
                );
                Json(json!({
                    "access_token": "renewed-token",
                    "refresh_token": "refresh-new-2",
                    "expires_in": 3600
                }))
            }
            other => panic!("unexpected grant_type: {other:?}"),
        }
    }

    async fn oauth_device_code(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert!(headers.get(COOKIE).is_none());
        assert_eq!(headers.get(USER_AGENT).unwrap(), "pan.baidu.com");
        assert_eq!(query.get("openapi").map(String::as_str), Some("xpansdk"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some(DEFAULT_CLIENT_ID)
        );
        Json(json!({
            "device_code": "device-code",
            "user_code": "user-code",
            "interval": 1,
            "expires_in": 60
        }))
    }

    async fn oauth_device_approve(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
        assert_eq!(query.get("code").map(String::as_str), Some("user-code"));
        StatusCode::OK
    }

    async fn xpan_get(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(query.get("method").map(String::as_str), Some("list"));
        assert_eq!(query.get("openapi").map(String::as_str), Some("xpansdk"));
        let token = query.get("access_token").map(String::as_str);
        if token == Some("expired-token") {
            return Json(json!({"errno": 111}));
        }
        assert!(matches!(token, Some("fresh-token" | "renewed-token")));
        assert_eq!(query.get("dir").map(String::as_str), Some("/safe"));
        Json(json!({
            "errno": 0,
            "list": [{
                "server_filename": "cipher-dir",
                "isdir": 1,
                "size": 0,
                "server_mtime": 123
            }]
        }))
    }

    async fn xpan_post(
        State(state): State<MockState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
        AxumForm(form): AxumForm<HashMap<String, String>>,
    ) -> axum::response::Response {
        assert_open_headers(&headers);
        assert_eq!(query.get("openapi").map(String::as_str), Some("xpansdk"));
        assert_eq!(
            query.get("access_token").map(String::as_str),
            Some("renewed-token")
        );
        match query.get("method").map(String::as_str) {
            Some("precreate") => {
                // 官方 SDK 表单：不带 content-md5 / slice-md5，rtype=2
                assert_eq!(form.get("path").map(String::as_str), Some("/safe/volume"));
                assert_eq!(form.get("size").map(String::as_str), Some("4"));
                assert_eq!(form.get("isdir").map(String::as_str), Some("0"));
                assert_eq!(form.get("autoinit").map(String::as_str), Some("1"));
                assert_eq!(form.get("rtype").map(String::as_str), Some("2"));
                assert!(!form.contains_key("content-md5"), "官方 SDK 无 content-md5");
                assert!(!form.contains_key("slice-md5"), "官方 SDK 无 slice-md5");
                assert_eq!(
                    form.get("block_list").map(String::as_str),
                    Some(r#"["8d777f385d3dfec8815d20f7496026dc"]"#)
                );
                Json(
                    json!({"errno": 0, "return_type": 1, "uploadid": "upload-1", "block_list": [0]}),
                )
                .into_response()
            }
            Some("create") => {
                // 上传收口的 create（isdir=0）走 SDK 语义；mkdir（isdir=1）不在本断言范围
                if form.get("isdir").map(String::as_str) == Some("0") {
                    // 注入瞬时 500（空响应体，复刻 bfe 偶发故障）驱动重试路径
                    if state
                        .create_failures
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                    {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    assert_eq!(form.get("rtype").map(String::as_str), Some("2"));
                    assert_eq!(form.get("uploadid").map(String::as_str), Some("upload-1"));
                    assert_eq!(
                        form.get("block_list").map(String::as_str),
                        Some(r#"["8d777f385d3dfec8815d20f7496026dc"]"#)
                    );
                }
                Json(json!({"errno": 0})).into_response()
            }
            Some("filemanager") => {
                // 官方 Python SDK 演示形态：filelist 为对象数组
                if query.get("opera").map(String::as_str) == Some("delete") {
                    assert_eq!(
                        form.get("filelist").map(String::as_str),
                        Some(r#"[{"path":"/safe/renamed"}]"#)
                    );
                }
                Json(json!({"errno": 0})).into_response()
            }
            other => panic!("unexpected xpan operation: {other:?}"),
        }
    }

    async fn upload_block(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(
            query.get("access_token").map(String::as_str),
            Some("renewed-token")
        );
        // 对齐 OpenList：superfile2 带 type=tmpfile，不带 openapi 标识
        assert_eq!(query.get("method").map(String::as_str), Some("upload"));
        assert_eq!(query.get("type").map(String::as_str), Some("tmpfile"));
        assert!(!query.contains_key("openapi"), "OpenList 形态无 openapi");
        assert_eq!(query.get("path").map(String::as_str), Some("/safe/volume"));
        assert_eq!(query.get("uploadid").map(String::as_str), Some("upload-1"));
        assert_eq!(query.get("partseq").map(String::as_str), Some("0"));
        // 官方成功响应：md5 + request_id（无 errno）
        Json(json!({"md5": "8d777f385d3dfec8815d20f7496026dc", "request_id": 1}))
    }

    async fn uinfo(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
        assert_eq!(query.get("method").map(String::as_str), Some("uinfo"));
        Json(json!({"errno": 0, "vip_type": 0}))
    }

    async fn locate_upload(
        State(state): State<MockState>,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(
            query.get("method").map(String::as_str),
            Some("locateupload")
        );
        assert_eq!(query.get("appid").map(String::as_str), Some("250528"));
        assert_eq!(query.get("uploadid").map(String::as_str), Some("upload-1"));
        assert_eq!(query.get("upload_version").map(String::as_str), Some("2.0"));
        // 返回 mock 自身作为动态上传域名 → superfile2 仍落回本 mock
        Json(json!({"servers": [{"server": state.upload_server}]}))
    }

    async fn locatedownload(
        State(state): State<MockState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(
            query.get("method").map(String::as_str),
            Some("locatedownload")
        );
        assert_eq!(headers.get(USER_AGENT).unwrap(), "download-android-test");
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
        state.locate_calls.fetch_add(1, Ordering::SeqCst);
        Json(json!({"urls": [{"url": state.download_url}]}))
    }

    async fn download(headers: HeaderMap) -> Response<Body> {
        assert_eq!(headers.get(USER_AGENT).unwrap(), "download-android-test");
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
        let range = headers.get(RANGE).unwrap().to_str().unwrap();
        let (start, end) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .map(|(start, end)| {
                (
                    start.parse::<usize>().unwrap(),
                    end.parse::<usize>().unwrap(),
                )
            })
            .unwrap();
        let source = b"0123456789";
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(CONTENT_RANGE, format!("bytes {start}-{end}/10"))
            .body(Body::from(source[start..=end].to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn oauth_crud_upload_and_cookie_download_work_end_to_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let locate_calls = Arc::new(AtomicUsize::new(0));
        let create_failures = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/oauth/token", get(oauth_token))
            .route("/oauth/device/code", get(oauth_device_code))
            .route("/device", get(oauth_device_approve))
            .route("/rest/2.0/xpan/file", get(xpan_get).post(xpan_post))
            .route("/rest/2.0/xpan/nas", get(uinfo))
            .route("/rest/2.0/pcs/superfile2", post(upload_block))
            .route("/rest/2.0/pcs/locateupload", get(locate_upload))
            .route("/rest/2.0/pcs/file", get(locatedownload))
            .route("/download", get(download))
            .with_state(MockState {
                download_url: format!("{base}/download"),
                upload_server: base.clone(),
                locate_calls: Arc::clone(&locate_calls),
                create_failures: Arc::clone(&create_failures),
            });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let persisted = Arc::new(StdMutex::new(None));
        let persisted_for_callback = Arc::clone(&persisted);
        let persister: TokenPersister = Arc::new(move |access, refresh, access_expires| {
            *persisted_for_callback.lock().unwrap() =
                Some((access.to_owned(), refresh.to_owned(), access_expires));
            Ok(())
        });
        let fs =
            BaiduPanFs::from_config_with_persister(&config(&base), Client::new(), Some(persister))
                .unwrap();
        let entries = fs.list("").await.unwrap();
        assert_eq!(entries[0].name, "cipher-dir");
        assert_eq!(entries[0].mtime, 123_000);
        let first = persisted.lock().unwrap().clone().unwrap();
        assert_eq!(
            (&first.0, &first.1),
            (&"fresh-token".to_string(), &"refresh-new".to_string())
        );
        assert!(first.2 >= unix_time_secs() + 3599);
        {
            let mut tokens = fs.tokens.lock().await;
            tokens.access_token = "expired-token".into();
            tokens.access_expires_at = None;
        }
        fs.list("").await.unwrap();
        let second = persisted.lock().unwrap().clone().unwrap();
        assert_eq!(
            (&second.0, &second.1),
            (&"renewed-token".to_string(), &"refresh-new-2".to_string())
        );
        assert!(second.2 >= unix_time_secs() + 3599);
        fs.mkdir("new").await.unwrap();
        fs.rename("new", "renamed").await.unwrap();
        fs.delete("renamed").await.unwrap();
        // 注入 3 次 create 瞬时 500：请求级重试（3 次）耗尽后，由整卷兜底
        // 重试第二轮走通；进度经高水位去重，重传的分块不得重复计数
        create_failures.store(3, Ordering::SeqCst);
        let confirmed = Arc::new(AtomicU64::new(0));
        let confirmed_cb = Arc::clone(&confirmed);
        fs.put_sized_tracked(
            "volume",
            4,
            stream::once(async { Ok(Bytes::from_static(b"data")) }).boxed(),
            Arc::new(move |n| {
                confirmed_cb.fetch_add(n, Ordering::SeqCst);
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            create_failures.load(Ordering::SeqCst),
            0,
            "注入的瞬时失败应全部被重试消化"
        );
        assert_eq!(
            confirmed.load(Ordering::SeqCst),
            4,
            "整卷重试后进度不得重复计数"
        );

        assert_eq!(locate_calls.load(Ordering::SeqCst), 0);
        let (first, second) =
            tokio::join!(fs.get_range("volume", 0, 1), fs.get_range("volume", 2, 5));
        drop(first.unwrap());
        drop(second.unwrap());
        assert_eq!(
            locate_calls.load(Ordering::SeqCst),
            1,
            "同一分卷并发 Range 必须通过单飞只获取一次直链"
        );
        drop(fs.get_range("another-volume", 0, 1).await.unwrap());
        assert_eq!(
            locate_calls.load(Ordering::SeqCst),
            2,
            "只有实际访问另一个分卷时才按需获取其直链"
        );

        let mut stream = fs.get_range("volume", 2, 5).await.unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"2345");
    }
}
