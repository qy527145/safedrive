//! 阿里云盘**官网**接口（PDS，api.aliyundrive.com）。
//!
//! 开放平台没有分享/转存能力，要把别人的阿里云盘分享转存进自己的盘只能
//! 走官网接口，而官网令牌与开放平台令牌是两套体系 —— 因此数据源里有一项
//! 可选的「官网刷新令牌」，配了才支持分享与转存。
//!
//! 官网令牌同样只在本机与阿里官方域名之间流动。它的权限比开放平台令牌大
//! 得多（等同网页登录），所以除了分享/转存，其他读写一律仍走开放平台。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine as _;
use reqwest::Client;
use reqwest::header::{HeaderName, ORIGIN, REFERER, SET_COOKIE, USER_AGENT};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{CredentialPersister, ImportedEntry};
use crate::error::{ApiError, ApiResult};

/// 官网 API 网关。
const API_BASE: &str = "https://api.aliyundrive.com";
/// 官网令牌刷新（客户端口子，不需要 Cookie）。
const TOKEN_URL: &str = "https://auth.alipan.com/v2/account/token";
const PASSPORT_BASE: &str = "https://passport.aliyundrive.com";
/// 扫码前必须先摸一次授权页拿会话 Cookie，`sid` 缺了拿到的令牌无法刷新。
const AUTHORIZE_URL: &str = "https://auth.aliyundrive.com/v2/oauth/authorize";
const AUTHORIZE_SID: &str = "m10qxi1syey6h";
const AUTHORIZE_CLIENT_ID: &str = "25dzX3vbYqktVxyX";
const WEB_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
/// 官网数据接口（api.aliyundrive.com）的写操作（分享/转存等）走风控，必须带一整套
/// 反滥用请求头，否则边缘 WAF 直接回 `403 Forbidden`（纯文本，不带 JSON code）。
/// 这个 App UA 与下面的 `X_CANARY` 成对出现，比桌面浏览器 UA 更不容易触发风控。
const APP_UA: &str = "AliApp(AYSD/5.8.0) com.alicloud.databox/37029260 Channel/36176927979800@rimet_android_5.8.0 language/zh-CN /Android Mobile";
/// 风控放行标记（提升频率上限，声明客户端渠道/版本）。
const X_CANARY: &str = "client=Android,app=adrive,version=v5.8.0";
/// aligo 项目公开的固定设备签名与 **公钥**（均为公开常量，非私钥）。官网写接口需要
/// 一份「设备会话」：用这套已知可用的静态签名 + 公钥调一次 create_session 注册设备，
/// 之后带上同一 device-id + 签名即可通过，省掉引入 secp256k1 现场签名的依赖。
const DEVICE_SIGNATURE: &str = "f4b7bed5d8524a04051bd2da876dd79afe922b8205226d65855d02b267422adb1e0d8a816b021eaf5c36d101892180f79df655c5712b348c2a540ca136e6b22001";
const DEVICE_PUBKEY: &str = "04d9d2319e0480c840efeeb75751b86d0db0c5b9e72c6260a1d846958adceaf9dee789cab7472741d23aafc1a9c591f72e7ee77578656e6c8588098dea1488ac2a";
const TOKEN_REFRESH_SKEW_SECS: u64 = 120;
/// 分享密码取数字 2-9：阿里接受纯数字密码，且落在 `sd://` 的密码字母表内。
const SHARE_PASSWORD_ALPHABET: &[u8] = b"23456789";
/// 转存文件夹是异步任务，最多等这么久。
const ASYNC_TASK_TRIES: u32 = 30;

/// 进程级官网令牌。与开放平台一样按账号串行刷新。
static TOKENS: LazyLock<Mutex<HashMap<String, LiveTokens>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TOKEN_LOCKS: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug, Default)]
struct LiveTokens {
    access_token: String,
    refresh_token: String,
    expires_at: Option<u64>,
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn share_token_header() -> HeaderName {
    HeaderName::from_static("x-share-token")
}

/// 官网分享链接。`share_id` 本身就是短链后缀。
pub fn share_url(share_id: &str) -> String {
    format!("https://www.alipan.com/s/{share_id}")
}

/// 从分享链接里取回 `share_id`。阿里的短链有 alipan.com / aliyundrive.com
/// 两个域名，后面还常带 `?` 查询串。
pub fn share_id_from_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url.trim()).ok()?;
    let segments: Vec<&str> = parsed.path_segments()?.collect();
    segments
        .windows(2)
        .find(|parts| parts[0] == "s")
        .map(|parts| parts[1])
        .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
}

/// 生成 4 位分享密码。
pub fn gen_share_password() -> ApiResult<String> {
    let mut random = [0u8; 4];
    getrandom::fill(&mut random)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("生成分享密码失败: {e}")))?;
    Ok(random
        .into_iter()
        .map(|byte| SHARE_PASSWORD_ALPHABET[byte as usize % SHARE_PASSWORD_ALPHABET.len()] as char)
        .collect())
}

/// 官网接口客户端。账号标识沿用开放平台那份（同一个阿里账号），
/// 令牌缓存因此不会被官网令牌自身的轮换打散。
pub struct WebClient {
    http: Client,
    account: String,
    persist: Option<CredentialPersister>,
}

impl WebClient {
    pub fn new(
        http: Client,
        account: String,
        refresh_token: String,
        access_token: String,
        expires_at: Option<u64>,
        persist: Option<CredentialPersister>,
    ) -> Self {
        let key = format!("{account}\u{1}web");
        TOKENS.lock().unwrap().entry(key.clone()).or_insert(LiveTokens {
            access_token,
            refresh_token,
            expires_at,
        });
        Self {
            http,
            account: key,
            persist,
        }
    }

    fn live(&self) -> LiveTokens {
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

    /// 取可用的官网 access token；`stale` 是刚被上游判定失效的那个。
    async fn access_token(&self, stale: Option<&str>) -> ApiResult<String> {
        let usable = |tokens: &LiveTokens| {
            if tokens.access_token.is_empty() || Some(tokens.access_token.as_str()) == stale {
                return false;
            }
            // 官网 access_token 是 RS256 JWT：优先用 PDS 公钥验签并读它自带的 exp，
            // 以令牌自身为准比盲信配置里存的 expires_at 可靠（验不出就退回存的值）。
            let expiry = super::aliyun_apps::web_access_token_expiry(&tokens.access_token)
                .or(tokens.expires_at);
            expiry.is_some_and(|at| at > unix_time_secs() + TOKEN_REFRESH_SKEW_SECS)
        };
        if usable(&self.live()) {
            return Ok(self.live().access_token);
        }
        let lock = self.token_lock();
        let _guard = lock.lock().await;
        let current = self.live();
        if usable(&current) {
            return Ok(current.access_token);
        }
        if current.refresh_token.is_empty() {
            return Err(ApiError::BadRequest(
                "阿里云盘未配置官网刷新令牌，无法分享或转存".into(),
            ));
        }
        let value = self.refresh_tokens(&current.refresh_token).await?;
        let access = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| ApiError::Upstream("阿里云盘官网刷新响应缺少 access_token".into()))?
            .to_owned();
        let refresh = value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .unwrap_or(&current.refresh_token)
            .to_owned();
        let ttl = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(7200);
        // access_token 自带 exp，验签通过就以它为准；验不出再退回 now + expires_in。
        let expires_at = super::aliyun_apps::web_access_token_expiry(&access)
            .unwrap_or_else(|| unix_time_secs().saturating_add(ttl));
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
                ("webAccessToken".into(), access.clone().into()),
                ("webRefreshToken".into(), refresh.into()),
                ("webAccessTokenExpiresAt".into(), expires_at.into()),
            ])?;
        }
        tracing::info!("阿里云盘官网令牌已刷新（有效期 {ttl}s）");
        Ok(access)
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> ApiResult<Value> {
        refresh_web_token(&self.http, refresh_token).await
    }

    /// 本账号稳定的 device-id：由账号派生，重启不变（aligo 的静态签名与
    /// device-id 无关，只要 device-id 稳定并注册过设备会话即可）。
    fn device_id(&self) -> String {
        let digest = Sha256::digest(self.account.as_bytes());
        hex::encode(digest)[..32].to_owned()
    }

    /// 给官网写接口挂上一整套反滥用请求头。少任何一项都可能被边缘 WAF 拦成 403。
    fn apply_write_headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header(USER_AGENT, APP_UA)
            .header(REFERER, "https://www.aliyundrive.com/")
            .header(ORIGIN, "https://www.aliyundrive.com")
            .header(HeaderName::from_static("x-canary"), X_CANARY)
            .header(HeaderName::from_static("x-device-id"), self.device_id())
            .header(HeaderName::from_static("x-signature"), DEVICE_SIGNATURE)
            .header(
                HeaderName::from_static("x-request-id"),
                uuid::Uuid::new_v4().to_string(),
            )
    }

    /// 注册设备会话。写接口报「设备会话签名无效 / 设备离线」时调一次，
    /// 用固定公钥把当前 device-id 登记到服务端，然后重试原请求。
    async fn create_session(&self, token: &str) -> ApiResult<()> {
        let body = json!({
            "deviceName": "SafeDrive",
            "modelName": "SafeDrive",
            "pubKey": DEVICE_PUBKEY,
        });
        let request = self
            .http
            .post(format!("{API_BASE}/users/v1/users/device/create_session"))
            .bearer_auth(token)
            .json(&body);
        let response = self
            .apply_write_headers(request)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("阿里云盘注册设备会话失败: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            tracing::warn!("阿里云盘注册设备会话未成功（HTTP {status}）: {text}");
        }
        Ok(())
    }

    /// 官网 POST 调用；令牌失效自动刷新重试一次，设备会话缺失自动注册重试一次。
    async fn post(
        &self,
        path: &str,
        body: &Value,
        what: &str,
        share_token: Option<&str>,
    ) -> ApiResult<Value> {
        let mut stale: Option<String> = None;
        let mut session_retried = false;
        loop {
            let token = self.access_token(stale.as_deref()).await?;
            let mut request = self
                .apply_write_headers(self.http.post(format!("{API_BASE}{path}")).bearer_auth(&token))
                .json(body);
            if let Some(share_token) = share_token {
                request = request.header(share_token_header(), share_token);
            }
            let response = request
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("阿里云盘{what}请求失败: {e}")))?;
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if status.is_success() {
                return Ok(value);
            }
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or(text.as_str());
            // 设备会话缺失/失效：注册一次设备会话后重试（与令牌刷新各重试一次）。
            let device_dead = matches!(code.as_str(), "DeviceSessionSignatureInvalid")
                || message.contains("device session")
                || message.contains("not found device info")
                || (code == "UserDeviceOffline");
            if device_dead && !session_retried {
                session_retried = true;
                self.create_session(&token).await?;
                continue;
            }
            let token_dead = status == reqwest::StatusCode::UNAUTHORIZED
                || matches!(code.as_str(), "AccessTokenInvalid" | "AccessTokenExpired");
            if token_dead && stale.is_none() {
                stale = Some(token);
                continue;
            }
            return Err(ApiError::Upstream(format!(
                "阿里云盘{what}失败: HTTP {status} {code} {message}"
            )));
        }
    }

    /// 官网令牌对应的用户 ID（access token 是 JWT，`sub` 即 user_id）。
    /// 用于提醒用户「官网令牌和开放平台令牌不是同一个账号」。
    pub async fn user_id(&self) -> ApiResult<String> {
        let token = self.access_token(None).await?;
        Ok(super::aliyun_apps::jwt_claim(&token, "sub").unwrap_or_default())
    }

    /// 创建原生分享，返回 (share_id, 分享密码)。
    pub async fn create_share(
        &self,
        drive_id: &str,
        file_ids: &[String],
        password: &str,
    ) -> ApiResult<String> {
        let body = json!({
            "drive_id": drive_id,
            "file_id_list": file_ids,
            "share_pwd": password,
            // 空字符串 = 永久有效；首页不同步，避免出现在个人主页。
            "expiration": "",
            "sync_to_homepage": false,
        });
        let value = self
            .post("/adrive/v2/share_link/create", &body, "创建分享", None)
            .await?;
        value
            .get("share_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream("阿里云盘创建分享响应缺少 share_id".into()))
    }

    /// 用分享 ID + 密码换取一次性的 share_token。
    pub async fn share_token(&self, share_id: &str, password: &str) -> ApiResult<String> {
        let body = json!({ "share_id": share_id, "share_pwd": password });
        let value = self
            .post("/v2/share_link/get_share_token", &body, "校验分享密码", None)
            .await?;
        value
            .get("share_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                ApiError::Upstream("阿里云盘分享校验响应缺少 share_token（密码可能不对）".into())
            })
    }

    /// 列出分享根目录下的条目，返回 (file_id, 名称)。
    pub async fn share_root_items(
        &self,
        share_id: &str,
        share_token: &str,
    ) -> ApiResult<Vec<(String, String)>> {
        let mut marker = String::new();
        let mut items = Vec::new();
        loop {
            let mut body = json!({
                "share_id": share_id,
                "parent_file_id": "root",
                "limit": 200,
                "order_by": "name",
                "order_direction": "ASC",
            });
            if !marker.is_empty() {
                body["marker"] = marker.clone().into();
            }
            let value = self
                .post("/adrive/v3/file/list", &body, "读取分享内容", Some(share_token))
                .await?;
            for item in value
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let (Some(file_id), Some(name)) = (
                    item.get("file_id").and_then(Value::as_str),
                    item.get("name").and_then(Value::as_str),
                ) else {
                    continue;
                };
                items.push((file_id.to_owned(), name.to_owned()));
            }
            marker = value
                .get("next_marker")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if marker.is_empty() {
                break;
            }
        }
        if items.is_empty() {
            return Err(ApiError::Upstream("该阿里云盘分享中没有可转存的内容".into()));
        }
        Ok(items)
    }

    /// 把分享里的条目转存到 `to_parent_id`，返回「分享内名称 → 落地名称」。
    pub async fn copy_from_share(
        &self,
        share_id: &str,
        share_token: &str,
        items: &[(String, String)],
        to_drive_id: &str,
        to_parent_id: &str,
    ) -> ApiResult<Vec<ImportedEntry>> {
        let requests: Vec<Value> = items
            .iter()
            .enumerate()
            .map(|(index, (file_id, _))| {
                json!({
                    "body": {
                        "file_id": file_id,
                        "share_id": share_id,
                        // 同名不覆盖：阿里会自动加后缀，落地名由 file/get 反查
                        "auto_rename": true,
                        "to_parent_file_id": to_parent_id,
                        "to_drive_id": to_drive_id,
                    },
                    "headers": { "Content-Type": "application/json" },
                    "id": index.to_string(),
                    "method": "POST",
                    "url": "/file/copy",
                })
            })
            .collect();
        let body = json!({ "requests": requests, "resource": "file" });
        let value = self
            .post("/adrive/v2/batch", &body, "转存分享", Some(share_token))
            .await?;

        // 按 id 对回原条目：批量接口不保证顺序。
        let mut landed: HashMap<usize, (String, String)> = HashMap::new();
        for response in value
            .get("responses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = response
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| id.parse::<usize>().ok());
            let status = response
                .get("status")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let Some(index) = index.filter(|index| *index < items.len()) else {
                continue;
            };
            if !(200..300).contains(&status) {
                let message = response
                    .pointer("/body/message")
                    .and_then(Value::as_str)
                    .unwrap_or("未知错误");
                return Err(ApiError::Upstream(format!(
                    "阿里云盘转存 {} 失败: HTTP {status} {message}",
                    items[index].1
                )));
            }
            let file_id = response
                .pointer("/body/file_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let task = response
                .pointer("/body/async_task_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            landed.insert(index, (file_id, task));
        }

        let mut out = Vec::with_capacity(items.len());
        for (index, (_, source_name)) in items.iter().enumerate() {
            let (file_id, task) = landed.remove(&index).ok_or_else(|| {
                ApiError::Upstream(format!("阿里云盘转存结果缺少条目 {source_name}"))
            })?;
            if !task.is_empty() {
                self.await_async_task(&task).await?;
            }
            if file_id.is_empty() {
                return Err(ApiError::Upstream(format!(
                    "阿里云盘转存 {source_name} 未返回落地 file_id"
                )));
            }
            let name = self.file_name(to_drive_id, &file_id).await?;
            out.push(ImportedEntry {
                source_name: source_name.clone(),
                name,
            });
        }
        Ok(out)
    }

    /// 转存文件夹是异步任务，等它落地再去读名字。
    async fn await_async_task(&self, task_id: &str) -> ApiResult<()> {
        for _ in 0..ASYNC_TASK_TRIES {
            let value = self
                .post(
                    "/v2/async_task/get",
                    &json!({ "async_task_id": task_id }),
                    "查询转存任务",
                    None,
                )
                .await?;
            match value.get("state").and_then(Value::as_str).unwrap_or_default() {
                "Succeed" | "done" => return Ok(()),
                "Failed" => return Err(ApiError::Upstream("阿里云盘转存任务失败".into())),
                _ => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
        Err(ApiError::Upstream(
            "阿里云盘转存任务超时未完成，请稍后到目标目录确认".into(),
        ))
    }

    async fn file_name(&self, drive_id: &str, file_id: &str) -> ApiResult<String> {
        let body = json!({ "drive_id": drive_id, "file_id": file_id });
        let value = self.post("/v2/file/get", &body, "读取转存结果", None).await?;
        value
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream("阿里云盘转存结果缺少名称".into()))
    }
}

// ---------------- 官网令牌刷新 ----------------

/// 用官网刷新令牌换一份新令牌（客户端口子，不需要 Cookie）。
async fn refresh_web_token(http: &Client, refresh_token: &str) -> ApiResult<Value> {
    let body = json!({ "grant_type": "refresh_token", "refresh_token": refresh_token });
    let response = http
        .post(TOKEN_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘官网刷新令牌失败: {e}")))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        let code = value.get("code").and_then(Value::as_str).unwrap_or_default();
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or(text.as_str());
        // 官网令牌过期只能重新扫码，说清楚免得用户以为是开放平台的问题。
        return Err(ApiError::Upstream(format!(
            "阿里云盘官网刷新令牌失败（请重新扫码获取官网令牌）: HTTP {status} {code} {message}"
        )));
    }
    Ok(value)
}

/// 用官网刷新令牌换一枚官网 access_token（一次性使用，不进缓存）。
/// 静默授权第三方应用时用它当 Bearer。
pub async fn web_access_token(http: &Client, refresh_token: &str) -> ApiResult<String> {
    refresh_web_token(http, refresh_token)
        .await?
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::Upstream("阿里云盘官网刷新响应缺少 access_token".into()))
}

// ---------------- 官网扫码登录 ----------------

/// 扫码登录整体超时。客户端由调用方（`AppState::passport`）提供，
/// 与其他上游共享代理、附加 CA 以及「不跟随重定向」的策略 ——
/// passport 的会话 Cookie 挂在 302 响应上，跟随重定向就丢了。
const QR_TIMEOUT: Duration = Duration::from_secs(30);

/// 一次扫码会话。SafeDrive 自己不存会话态：整个对象原样回给前端，
/// 轮询时再带回来。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebQrSession {
    /// generate.do 返回的 `content.data`，query.do 要把它整份回传。
    pub data: Value,
    /// 会话 Cookie（`k=v; k=v`）。
    pub cookies: String,
}

/// 申请官网登录二维码，返回 (二维码内容, 会话)。二维码是纯文本，由前端渲染。
pub async fn qr_generate(http: &Client) -> ApiResult<(String, WebQrSession)> {
    // 先摸一次授权页：拿会话 Cookie。带 sid 才能拿到可刷新的令牌。
    let authorize = http
        .get(AUTHORIZE_URL)
        .query(&[
            ("login_type", "custom"),
            ("response_type", "code"),
            ("redirect_uri", "https://www.aliyundrive.com/sign/callback"),
            ("sid", AUTHORIZE_SID),
            ("client_id", AUTHORIZE_CLIENT_ID),
            ("state", r#"{"origin":"file://"}"#),
        ])
        .header(USER_AGENT, WEB_UA)
        .timeout(QR_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘官网授权页访问失败: {e}")))?;
    let mut cookies = collect_cookies(authorize.headers(), "");

    let response = http
        .get(format!("{PASSPORT_BASE}/newlogin/qrcode/generate.do"))
        .query(&[("appName", "aliyun_drive")])
        .header(USER_AGENT, WEB_UA)
        .timeout(QR_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("获取阿里云盘官网二维码失败: {e}")))?;
    cookies = collect_cookies(response.headers(), &cookies);
    let value: Value = response
        .json()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘官网二维码响应无法解析: {e}")))?;
    let data = value
        .pointer("/content/data")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| ApiError::Upstream("阿里云盘官网二维码响应缺少数据".into()))?;
    let code_content = data
        .get("codeContent")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| ApiError::Upstream("阿里云盘官网二维码内容为空".into()))?
        .to_owned();
    Ok((code_content, WebQrSession { data, cookies }))
}

/// 官网扫码状态：waiting / scanned / expired / confirmed(refresh_token)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebQrStatus {
    Waiting,
    Scanned,
    Expired,
    Confirmed(String),
}

pub async fn qr_query(http: &Client, session: &WebQrSession) -> ApiResult<WebQrStatus> {
    let form = form_pairs(&session.data);
    let response = http
        .post(format!("{PASSPORT_BASE}/newlogin/qrcode/query.do"))
        .query(&[("appName", "aliyun_drive")])
        .header(USER_AGENT, WEB_UA)
        .header(reqwest::header::COOKIE, session.cookies.clone())
        .form(&form)
        .timeout(QR_TIMEOUT)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("查询阿里云盘官网扫码状态失败: {e}")))?;
    let value: Value = response
        .json()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘官网扫码状态无法解析: {e}")))?;
    let data = value
        .pointer("/content/data")
        .ok_or_else(|| ApiError::Upstream("阿里云盘官网扫码状态缺少数据".into()))?;
    match data
        .get("qrCodeStatus")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "CONFIRMED" => {
            let biz_ext = data
                .get("bizExt")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::Upstream("阿里云盘官网扫码结果缺少 bizExt".into()))?;
            let token = refresh_token_from_biz_ext(biz_ext).ok_or_else(|| {
                ApiError::Upstream("阿里云盘官网扫码结果中没有找到刷新令牌".into())
            })?;
            Ok(WebQrStatus::Confirmed(token))
        }
        "SCANED" | "SCANNED" => Ok(WebQrStatus::Scanned),
        "EXPIRED" | "CANCELED" => Ok(WebQrStatus::Expired),
        _ => Ok(WebQrStatus::Waiting),
    }
}

/// `content.data` 原样回传给 query.do（值只可能是字符串/数字/布尔）。
fn form_pairs(data: &Value) -> Vec<(String, String)> {
    data.as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| {
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                _ => return None,
            };
            Some((key.clone(), text))
        })
        .collect()
}

/// 合并 Set-Cookie（只保留 name=value，忽略属性）。
fn collect_cookies(headers: &reqwest::header::HeaderMap, existing: &str) -> String {
    let mut jar: Vec<(String, String)> = existing
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    for header in headers.get_all(SET_COOKIE).iter() {
        let Some(pair) = header.to_str().ok().and_then(|raw| raw.split(';').next()) else {
            continue;
        };
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        match jar.iter_mut().find(|(existing, _)| existing == name) {
            Some(slot) => slot.1 = value.to_owned(),
            None => jar.push((name.to_owned(), value.to_owned())),
        }
    }
    jar.iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// bizExt 是 base64 的 gb18030 JSON（里面有中文昵称）。刷新令牌是纯 ASCII，
/// 直接在字节流里按键名扫出来，省掉一个 gb18030 解码器。
fn refresh_token_from_biz_ext(biz_ext: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(biz_ext)
        .ok()?;
    let needle = br#""refreshToken":""#;
    let start = raw
        .windows(needle.len())
        .position(|window| window == needle)?
        + needle.len();
    let rest = raw.get(start..)?;
    let end = rest.iter().position(|byte| *byte == b'"')?;
    let token = std::str::from_utf8(&rest[..end]).ok()?;
    (!token.is_empty()).then(|| token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_refresh_token_from_gb18030_biz_ext() {
        // 昵称用 gb18030 编码（非 UTF-8），令牌本身是 ASCII。
        let mut raw = br#"{"pds_login_result":{"nickName":""#.to_vec();
        raw.extend_from_slice(&[0xd6, 0xd0, 0xce, 0xc4]); // “中文” 的 gb18030
        raw.extend_from_slice(br#"","refreshToken":"3b00f739f30d458b80f492cc55ffcd36"}}"#);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(
            refresh_token_from_biz_ext(&encoded).as_deref(),
            Some("3b00f739f30d458b80f492cc55ffcd36")
        );
        assert!(refresh_token_from_biz_ext("not-base64!!").is_none());
        let empty = base64::engine::general_purpose::STANDARD.encode(br#"{"refreshToken":""}"#);
        assert!(refresh_token_from_biz_ext(&empty).is_none());
    }

    #[test]
    fn merges_set_cookie_into_a_single_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(SET_COOKIE, "SESSIONID=abc; Path=/; HttpOnly".parse().unwrap());
        headers.append(SET_COOKIE, "cna=xyz; Domain=.aliyundrive.com".parse().unwrap());
        headers.append(SET_COOKIE, "dropme=; Path=/".parse().unwrap());
        let cookies = collect_cookies(&headers, "cna=old; keep=1");
        // 后来的值覆盖同名 Cookie，空值被忽略，其余保留
        assert!(cookies.contains("cna=xyz"), "{cookies}");
        assert!(cookies.contains("keep=1"), "{cookies}");
        assert!(cookies.contains("SESSIONID=abc"), "{cookies}");
        assert!(!cookies.contains("dropme"), "{cookies}");
    }

    #[test]
    fn query_form_flattens_scalar_fields_only() {
        let data = json!({ "t": 1717082331i64, "ck": "code", "codeContent": "https://x", "nested": {"a": 1} });
        let form = form_pairs(&data);
        assert!(form.contains(&("t".into(), "1717082331".into())));
        assert!(form.contains(&("ck".into(), "code".into())));
        assert!(!form.iter().any(|(key, _)| key == "nested"));
    }

    #[test]
    fn share_passwords_fit_the_link_alphabet() {
        let password = gen_share_password().unwrap();
        assert_eq!(password.len(), 4);
        assert!(
            password
                .bytes()
                .all(|byte| SHARE_PASSWORD_ALPHABET.contains(&byte))
        );
        assert_eq!(share_url("abc123"), "https://www.alipan.com/s/abc123");
    }

    #[test]
    fn parses_share_id_from_both_domains() {
        for url in [
            "https://www.alipan.com/s/3XCkDNb1Cfa",
            "https://www.aliyundrive.com/s/3XCkDNb1Cfa",
            "https://www.aliyundrive.com/s/3XCkDNb1Cfa?spm=x",
            " https://www.alipan.com/s/3XCkDNb1Cfa/folder ",
        ] {
            assert_eq!(
                share_id_from_url(url).as_deref(),
                Some("3XCkDNb1Cfa"),
                "{url}"
            );
        }
        assert!(share_id_from_url("https://www.alipan.com/").is_none());
        assert!(share_id_from_url("https://pan.baidu.com/s/1abc").is_some_and(|id| id == "1abc"));
        // 路径注入不能混进 share_id
        assert!(share_id_from_url("https://www.alipan.com/s/..%2Ffoo").is_none());
        assert!(share_id_from_url("not a url").is_none());
    }
}
