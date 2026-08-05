//! 阿里云盘开放平台的「第三方应用」。
//!
//! 开放平台的 `client_secret` 只有应用作者手上有，社区通行的做法是把
//! 「authCode → refresh_token」和「refresh_token → access_token」这两步
//! 交给应用作者的中转服务，客户端只保管 refresh_token。这里把常见的几家
//! 中转协议内置进来：用户扫码即用，不必自己去开放平台申请应用。
//!
//! refresh_token 是 JWT，`aud` 就是签发它的 client_id —— 用户手填令牌时
//! 据此反查属于哪个内置应用。不在内置名单里的令牌降级为「自定义应用」：
//! 用户自己填 client_id / client_secret，直接走开放平台标准刷新。
//!
//! 凭证流向：内置应用的令牌只在本机与「开放平台 / 该应用作者的中转服务」
//! 之间流动，SafeDrive 不做任何转发或留存。

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use md5::Digest as _;
use reqwest::Client;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier as _;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::LazyLock;

use crate::error::{ApiError, ApiResult};

pub const DEFAULT_API_BASE: &str = "https://openapi.alipan.com";
/// 静默授权接口：拿官网 access_token 直接给第三方应用授权，免扫码。
const OAUTH_USERS_AUTHORIZE_URL: &str =
    "https://open.aliyundrive.com/oauth/users/qrcode/authorize";
/// 官方文档给的授权 scope：读 + 写 + 基本信息。
pub const OAUTH_SCOPES: &str = "user:base,file:all:read,file:all:write";
/// 扫码授权默认走阿里云盘 TV：中转最稳，且不需要用户自备应用。
pub const DEFAULT_APP: &str = "tv";
/// 用户自备 client_id / client_secret 的伪应用键。
pub const CUSTOM_APP: &str = "custom";

/// 开放平台 refresh_token 的验签公钥（RS256）。开放平台的 refresh_token 是一枚
/// RS256 签名的 JWT，这里只用公钥做验签，判断用户粘进来的到底是不是一枚货真价实
/// 的开放平台 refresh_token（PDS 官网令牌是不透明串、不是 JWT，验签自然过不了）。
const OPEN_REFRESH_TOKEN_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMZ8ykhQjL4KNvllo73N+EMnQ5Cq4GY+\n\
LUyXDpTbpA4Sjk3lkuf7sTbdav/WV2ANHcClYVlIAeZgKu1gV5DY+t0CAwEAAQ==\n\
-----END PUBLIC KEY-----";

static OPEN_RT_VERIFIER: LazyLock<Option<VerifyingKey<Sha256>>> = LazyLock::new(|| {
    RsaPublicKey::from_public_key_pem(OPEN_REFRESH_TOKEN_PUBKEY_PEM)
        .ok()
        .map(VerifyingKey::new)
});

/// 一个应用的令牌协议。`Open` 直连开放平台（要有 client_secret），
/// 其余都是各家中转服务自己的协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Open,
    Tv,
    Alist,
    Openlist,
    AlistGo,
    XiaoBai,
    CloudDrive2,
    Webdav,
}

/// 内置应用。`client_secret` 为空表示密钥在中转服务那边，本机拿不到。
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltinApp {
    pub key: &'static str,
    pub name: &'static str,
    pub client_id: &'static str,
    #[serde(skip)]
    client_secret: &'static str,
    #[serde(skip)]
    flavor: Flavor,
    /// 提示文案：这个应用的令牌由谁签发/刷新。
    pub note: &'static str,
}

/// 内置的第三方应用名单。client_id 就是 refresh_token 的 `aud`，
/// 顺序即前端下拉框顺序（默认项排最前）。
const BUILTINS: &[BuiltinApp] = &[
    BuiltinApp {
        key: "tv",
        name: "阿里云盘TV",
        client_id: "6b5b52e144f748f78b3f96a2626ed5d7",
        client_secret: "",
        flavor: Flavor::Tv,
        note: "扫码与刷新经 api.extscreen.com 中转（默认）",
    },
    BuiltinApp {
        key: "alist",
        name: "AList",
        client_id: "76917ccccd4441c39457a04f6084fb2f",
        client_secret: "",
        flavor: Flavor::Alist,
        note: "扫码与刷新经 api.xhofe.top 中转",
    },
    BuiltinApp {
        key: "openlist",
        name: "OpenList",
        client_id: "c78079b71f42427b8c899f81fbe36961",
        client_secret: "",
        flavor: Flavor::Openlist,
        note: "扫码与刷新经 api.oplist.org 中转",
    },
    BuiltinApp {
        key: "alistgo",
        name: "AList（alistgo）",
        client_id: "b8c990e60b18446eb07f5dca30398e8a",
        client_secret: "",
        flavor: Flavor::AlistGo,
        note: "扫码与刷新经 api.alistgo.com 中转",
    },
    BuiltinApp {
        key: "xiaobai",
        name: "小白网盘",
        client_id: "db59315fb2474133bc4a74cec0a1ea27",
        client_secret: "",
        flavor: Flavor::XiaoBai,
        note: "扫码与刷新经小白 cloudisk 中转",
    },
    BuiltinApp {
        key: "clouddrive2",
        name: "CloudDrive2",
        client_id: "58480866958f4e8497581ba7fc9dd331",
        client_secret: "",
        flavor: Flavor::CloudDrive2,
        note: "扫码与刷新经 aliredirect.zhenyunpan.com 中转",
    },
    BuiltinApp {
        key: "webdav",
        name: "aliyundrive-webdav",
        client_id: "73e611831a7c4d87ac49c8481bf9f2c4",
        client_secret: "",
        flavor: Flavor::Webdav,
        note: "扫码与刷新经 aliyundrive-oauth.messense.me 中转",
    },
    BuiltinApp {
        key: "xiaoya",
        name: "小雅",
        client_id: "10e184c407cb4d8087f9d3b8f1fd2c23",
        client_secret: "2742a36daad341a8b032b40e92d91bb1",
        flavor: Flavor::Open,
        note: "密钥公开，直连开放平台刷新",
    },
    BuiltinApp {
        key: "infuse",
        name: "Infuse",
        client_id: "b0d5065f002c45b09c5068986c505675",
        client_secret: "ab91b1ae3de849e885d27d6b84d1e100",
        flavor: Flavor::Open,
        note: "密钥公开，直连开放平台刷新",
    },
    BuiltinApp {
        key: "vidhub",
        name: "VidHub",
        client_id: "fb81e4931c654290bc9296f24d943d50",
        client_secret: "e1fc5b14bc4a4b7bb1a730c7d0e7c4f3",
        flavor: Flavor::Open,
        note: "密钥公开，直连开放平台刷新",
    },
    BuiltinApp {
        key: "xiaobaiyang",
        name: "小白羊",
        client_id: "df43e22f022d4c04b6e29964f3b8b46d",
        client_secret: "63f06c3c5c5d4e1196e2c13e8588ae29",
        flavor: Flavor::Open,
        note: "密钥公开，直连开放平台刷新",
    },
    BuiltinApp {
        key: "woniu",
        name: "蜗牛云盘",
        client_id: "e90a7b360e894c60b7b314579f42827d",
        client_secret: "a3d3a7036fa9417399eef14891f6084f",
        flavor: Flavor::Open,
        note: "密钥公开，直连开放平台刷新",
    },
];

pub fn builtins() -> &'static [BuiltinApp] {
    BUILTINS
}

pub fn find(key: &str) -> Option<&'static BuiltinApp> {
    BUILTINS.iter().find(|app| app.key == key)
}

/// 按 refresh_token 的 `aud`（= 签发它的 client_id）反查内置应用。
pub fn detect(refresh_token: &str) -> Option<&'static BuiltinApp> {
    let client_id = jwt_claim(refresh_token, "aud")?;
    BUILTINS.iter().find(|app| app.client_id == client_id)
}

/// 手填 refresh_token 的校验结果：是否是货真价实的开放平台令牌、有没有
/// 过期、属于哪个内置应用。前端据此决定放行、提示重扫，还是降级到自定义应用。
#[derive(Debug, Clone)]
pub struct TokenInspection {
    /// RS256 验签通过：确实是开放平台签发的 refresh_token。
    pub valid: bool,
    /// 已过期（`exp` 早于当前时间）。
    pub expired: bool,
    /// `exp`（unix 秒）。
    pub expires_at: Option<u64>,
    /// 按 `aud` 识别到的内置应用（认不出即 `None`，降级为自定义应用）。
    pub app: Option<&'static BuiltinApp>,
}

/// 校验并识别一枚手填的开放平台 refresh_token。
pub fn inspect(refresh_token: &str) -> TokenInspection {
    let token = refresh_token.trim();
    let expires_at = jwt_claim(token, "exp").and_then(|exp| exp.parse::<u64>().ok());
    TokenInspection {
        valid: verify_open_refresh_token(token),
        expired: expires_at.is_some_and(|exp| exp <= unix_time_secs()),
        expires_at,
        app: detect(token),
    }
}

/// RS256 验签：`header.payload` 用开放平台公钥验证末段签名。
fn verify_open_refresh_token(token: &str) -> bool {
    let Some(verifier) = OPEN_RT_VERIFIER.as_ref() else {
        return false;
    };
    // token = header.payload.signature；验签对象是前两段（含中间的点）。
    let Some((message, signature)) = token.rsplit_once('.') else {
        return false;
    };
    if message.split('.').count() != 2 {
        return false;
    }
    let Ok(signature) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return false;
    };
    verifier.verify(message.as_bytes(), &signature).is_ok()
}

/// 读 JWT 载荷里的一个字符串字段（不验签 —— 只用来做路由和缓存分区）。
pub fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    let field = value.get(claim)?;
    field
        .as_str()
        .map(str::to_owned)
        .or_else(|| field.as_u64().map(|n| n.to_string()))
}

/// 解析好的应用：适配器与扫码路由都用它去跑令牌流程。
#[derive(Debug, Clone)]
pub struct App {
    /// 内置应用键，或 [`CUSTOM_APP`]。
    pub key: String,
    pub name: String,
    pub client_id: String,
    client_secret: String,
    flavor: Flavor,
    /// 只对 `Open` 有意义（自定义接口地址/私有网关）。
    api_base: String,
}

/// 一次令牌调用的产物。中转服务未必回全，缺的字段留空由调用方兜底。
#[derive(Debug, Clone, Default)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// 二维码：`image_url` 是上游给的图片地址，前端渲染前由服务端代取。
#[derive(Debug, Clone)]
pub struct Qr {
    pub image_url: String,
    pub sid: String,
}

/// 扫码状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrStatus {
    Waiting,
    Scanned,
    Expired,
    /// 已确认，附可换令牌的 authCode。
    Confirmed(String),
}

/// 决定用哪个应用刷新令牌：
/// 1. 明确指定了内置应用键 → 用它；
/// 2. 指定 `custom`（或未指定但认不出令牌）→ 用户自填的 client_id/secret；
/// 3. 未指定 → 按 refresh_token 的 `aud` 自动识别。
pub fn resolve(
    app_key: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    refresh_token: Option<&str>,
    api_base: Option<&str>,
) -> ApiResult<App> {
    let api_base = api_base
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .unwrap_or(DEFAULT_API_BASE)
        .trim_end_matches('/')
        .to_owned();
    let custom = |reason: &str| -> ApiResult<App> {
        let (Some(id), Some(secret)) = (
            client_id.map(str::trim).filter(|v| !v.is_empty()),
            client_secret.map(str::trim).filter(|v| !v.is_empty()),
        ) else {
            return Err(ApiError::BadRequest(format!(
                "{reason}：请选择内置的第三方应用，或填写自有应用的 client_id 与 client_secret"
            )));
        };
        Ok(App {
            key: CUSTOM_APP.into(),
            name: "自定义应用".into(),
            client_id: id.to_owned(),
            client_secret: secret.to_owned(),
            flavor: Flavor::Open,
            api_base: api_base.clone(),
        })
    };
    let builtin = |app: &'static BuiltinApp| App {
        key: app.key.into(),
        name: app.name.into(),
        client_id: app.client_id.into(),
        client_secret: app.client_secret.into(),
        flavor: app.flavor,
        api_base: api_base.clone(),
    };

    match app_key.map(str::trim).filter(|key| !key.is_empty()) {
        Some(CUSTOM_APP) => custom("已选择自定义应用"),
        Some(key) => find(key)
            .map(builtin)
            .ok_or_else(|| ApiError::BadRequest(format!("未知的阿里云盘第三方应用: {key}"))),
        None => match refresh_token.and_then(detect) {
            Some(app) => Ok(builtin(app)),
            None => custom("无法识别该 refresh_token 属于哪个第三方应用"),
        },
    }
}

impl App {
    fn open_url(&self, path: &str) -> String {
        format!("{}{path}", self.api_base)
    }

    /// 申请扫码授权二维码。
    pub async fn qr(&self, http: &Client) -> ApiResult<Qr> {
        let what = "申请授权二维码";
        let value = match self.flavor {
            Flavor::Open => {
                let body = json!({
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scopes": OAUTH_SCOPES.split(',').collect::<Vec<_>>(),
                    "width": 430,
                    "height": 430,
                });
                send(http.post(self.open_url("/oauth/authorize/qrcode")).json(&body), what).await?
            }
            Flavor::Tv => {
                tv_call(
                    http,
                    "/qrcode",
                    &[
                        ("scopes", OAUTH_SCOPES.to_owned()),
                        ("width", "500".into()),
                        ("height", "500".into()),
                    ],
                    None,
                    None,
                    what,
                )
                .await?
            }
            Flavor::Alist => send(http.post(format!("{ALIST_BASE}/alist/ali_open/qr")), what).await?,
            Flavor::Openlist => send(
                http.get(format!("{OPENLIST_BASE}/alicloud/requests"))
                    .query(&[("server_use", "true")]),
                what,
            )
            .await?,
            Flavor::AlistGo => {
                send(http.post(format!("{ALISTGO_BASE}/alist/ali_open/qr")), what).await?
            }
            Flavor::XiaoBai => send(
                http.get(format!("{XIAOBAI_BASE}/api/oauth/authorize/qrcode")),
                what,
            )
            .await?,
            Flavor::CloudDrive2 => {
                send(http.get(format!("{CLOUDDRIVE2_BASE}/qrcode_url")), what).await?
            }
            Flavor::Webdav => {
                let body = json!({
                    "scopes": OAUTH_SCOPES.split(',').collect::<Vec<_>>(),
                    "width": 430,
                    "height": 430,
                });
                send(
                    http.post(format!("{WEBDAV_BASE}/oauth/authorize/qrcode"))
                        .json(&body),
                    what,
                )
                .await?
            }
        };
        // OpenList 用 text 字段装二维码图片地址，其余都是 qrCodeUrl。
        let image_url = field(&value, &["qrCodeUrl", "qr_code_url", "text"])
            .ok_or_else(|| ApiError::Upstream(format!("{}未返回二维码地址", self.name)))?
            .to_owned();
        let sid = field(&value, &["sid"])
            .ok_or_else(|| ApiError::Upstream(format!("{}未返回扫码会话 sid", self.name)))?
            .to_owned();
        Ok(Qr { image_url, sid })
    }

    /// 轮询扫码状态。所有应用共用开放平台的状态接口（sid 是开放平台签发的）。
    pub async fn qr_status(&self, http: &Client, sid: &str) -> ApiResult<QrStatus> {
        let value = send(
            http.get(self.open_url(&format!("/oauth/qrcode/{sid}/status"))),
            "查询扫码状态",
        )
        .await?;
        // 开放平台状态字面量：WaitLogin / ScanSuccess / LoginSuccess / QRCodeExpired
        match field(&value, &["status"]).unwrap_or_default() {
            "LoginSuccess" => {
                let code = field(&value, &["authCode"]).ok_or_else(|| {
                    ApiError::Upstream("扫码已确认但未返回 authCode".into())
                })?;
                Ok(QrStatus::Confirmed(code.to_owned()))
            }
            "ScanSuccess" => Ok(QrStatus::Scanned),
            "QRCodeExpired" => Ok(QrStatus::Expired),
            _ => Ok(QrStatus::Waiting),
        }
    }

    /// authCode → refresh_token。`sid` 只有 OpenList 的中转协议要用。
    pub async fn exchange(&self, http: &Client, sid: &str, auth_code: &str) -> ApiResult<Tokens> {
        let what = "换取令牌";
        let value = match self.flavor {
            Flavor::Open => {
                let body = json!({
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "authorization_code",
                    "code": auth_code,
                });
                send(http.post(self.open_url("/oauth/access_token")).json(&body), what).await?
            }
            Flavor::Tv => {
                tv_call(
                    http,
                    "/v2/token",
                    &[("code", auth_code.to_owned())],
                    None,
                    Some(&TV_V2_KEY),
                    what,
                )
                .await?
            }
            Flavor::Alist => {
                let body = json!({
                    "client_id": "",
                    "client_secret": "",
                    "grant_type": "authorization_code",
                    "code": auth_code,
                });
                send(
                    http.post(format!("{ALIST_BASE}/alist/ali_open/token"))
                        .json(&body),
                    what,
                )
                .await?
            }
            // OpenList 的回调用 sid 反查授权结果，code 参数也传 sid。
            Flavor::Openlist => send(
                http.get(format!("{OPENLIST_BASE}/alicloud/callback"))
                    .query(&[
                        ("client_id", ""),
                        ("client_secret", ""),
                        ("server_use", "true"),
                        ("grant_type", "authorization_code"),
                        ("code", sid),
                        ("sid", sid),
                    ])
                    .header(reqwest::header::COOKIE, "driver_txt=alicloud_qr; server_use=true"),
                what,
            )
            .await?,
            Flavor::AlistGo => {
                let body = json!({
                    "client_id": "",
                    "client_secret": "",
                    "grant_type": "authorization_code",
                    "code": auth_code,
                });
                send(
                    http.post(format!("{ALISTGO_BASE}/alist/ali_open/code"))
                        .json(&body),
                    what,
                )
                .await?
            }
            Flavor::XiaoBai => send(
                http.get(format!("{XIAOBAI_BASE}/api/oauth/accessToken"))
                    .query(&[("authCode", auth_code)]),
                what,
            )
            .await?,
            Flavor::CloudDrive2 => send(
                http.get(format!(
                    "{CLOUDDRIVE2_BASE}/access_token/authorization_code/{auth_code}"
                )),
                what,
            )
            .await?,
            Flavor::Webdav => {
                let body = json!({ "grant_type": "authorization_code", "code": auth_code });
                send(
                    http.post(format!("{WEBDAV_BASE}/oauth/access_token"))
                        .json(&body),
                    what,
                )
                .await?
            }
        };
        let tokens = tokens_of(&value);
        if tokens.refresh_token.is_empty() {
            return Err(ApiError::Upstream(format!(
                "{}的授权响应缺少 refresh_token{}",
                self.name,
                message_suffix(&value)
            )));
        }
        Ok(tokens)
    }

    /// refresh_token → access_token。部分应用会同时轮换 refresh_token。
    pub async fn refresh(&self, http: &Client, refresh_token: &str) -> ApiResult<Tokens> {
        let what = "刷新令牌";
        let value = match self.flavor {
            Flavor::Open => {
                let body = json!({
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                });
                send(http.post(self.open_url("/oauth/access_token")).json(&body), what).await?
            }
            Flavor::Tv => {
                // TV 的 v3 接口按请求头派生一次性 AES 密钥，响应整体加密。
                let now = unix_time_secs().to_string();
                let params = tv_v3_params();
                let key = tv_v3_key(&params, &now);
                let mut headers: Vec<(&str, String)> = params;
                headers.push(("t", now));
                headers.push(("User-Agent", TV_USER_AGENT.to_owned()));
                tv_call(
                    http,
                    "/v3/token",
                    &[("refresh_token", refresh_token.to_owned())],
                    Some(&headers),
                    Some(&key),
                    what,
                )
                .await?
            }
            Flavor::Alist => {
                let body = json!({
                    "client_id": "",
                    "client_secret": "",
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                });
                send(
                    http.post(format!("{ALIST_BASE}/alist/ali_open/token"))
                        .json(&body),
                    what,
                )
                .await?
            }
            Flavor::Openlist => send(
                http.get(format!("{OPENLIST_BASE}/alicloud/renewapi"))
                    .query(&[("server_use", "true"), ("refresh_ui", refresh_token)]),
                what,
            )
            .await?,
            Flavor::AlistGo => {
                let body = json!({
                    "client_id": "",
                    "client_secret": "",
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                });
                send(
                    http.post(format!("{ALISTGO_BASE}/alist/ali_open/token"))
                        .json(&body),
                    what,
                )
                .await?
            }
            Flavor::XiaoBai => send(
                http.get(format!("{XIAOBAI_BASE}/api/oauth/accessToken"))
                    .query(&[("refreshToken", refresh_token)]),
                what,
            )
            .await?,
            Flavor::CloudDrive2 => send(
                http.get(format!(
                    "{CLOUDDRIVE2_BASE}/access_token/refresh_token/{refresh_token}"
                )),
                what,
            )
            .await?,
            Flavor::Webdav => {
                let body = json!({ "grant_type": "refresh_token", "refresh_token": refresh_token });
                send(
                    http.post(format!("{WEBDAV_BASE}/oauth/access_token"))
                        .json(&body),
                    what,
                )
                .await?
            }
        };
        let tokens = tokens_of(&value);
        if tokens.access_token.is_empty() {
            return Err(ApiError::Upstream(format!(
                "{}的刷新响应缺少 access_token{}",
                self.name,
                message_suffix(&value)
            )));
        }
        Ok(tokens)
    }

    /// 用官网（PDS）access_token 静默授权本应用，免扫码换取开放平台令牌。
    ///
    /// 等价于「申请授权二维码 → 用户扫码确认」，只是把「确认」这一步换成拿
    /// 官网 access_token 直接调授权接口 —— 官网令牌权限等同网页登录，足以替
    /// 用户点下这个授权。sid 是开放平台签发的，因此对任何中转应用都通用。
    pub async fn silent_grant(&self, http: &Client, pds_access_token: &str) -> ApiResult<Tokens> {
        let qr = self.qr(http).await?;
        let body = json!({
            "scopes": OAUTH_SCOPES.split(',').collect::<Vec<_>>(),
            "sid": qr.sid,
            "scope": OAUTH_SCOPES,
            "authorize": 1,
            "drives": ["backup", "resource"],
        });
        send(
            http.post(format!("{OAUTH_USERS_AUTHORIZE_URL}?sid={}", qr.sid))
                .bearer_auth(pds_access_token)
                .json(&body),
            "静默授权第三方应用",
        )
        .await?;
        // 授权后开放平台状态几乎立即变为 LoginSuccess；给几次短轮询兜底。
        let mut auth_code = None;
        for _ in 0..10 {
            match self.qr_status(http, &qr.sid).await? {
                QrStatus::Confirmed(code) => {
                    auth_code = Some(code);
                    break;
                }
                QrStatus::Expired => {
                    return Err(ApiError::Upstream(
                        "阿里云盘静默授权会话已失效，请重试".into(),
                    ));
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
        let auth_code = auth_code.ok_or_else(|| {
            ApiError::Upstream("阿里云盘静默授权未在预期时间内完成".into())
        })?;
        self.exchange(http, &qr.sid, &auth_code).await
    }
}

// ---------------- 各中转服务的地址 ----------------

/// AList 的中转（原文用 IP + Host 头绕 DNS，这里直接走域名）。
const ALIST_BASE: &str = "https://api.xhofe.top";
const OPENLIST_BASE: &str = "https://api.oplist.org";
const ALISTGO_BASE: &str = "https://api.alistgo.com";
/// 小白的中转只有 IP 入口，没有证书可校验，只能走 http。
const XIAOBAI_BASE: &str = "http://159.75.208.47/cloudisk";
const CLOUDDRIVE2_BASE: &str = "https://aliredirect.zhenyunpan.com";
const WEBDAV_BASE: &str = "https://aliyundrive-oauth.messense.me";
const TV_BASE_HTTPS: &str = "https://api.extscreen.com/aliyundrive";
const TV_BASE_HTTP: &str = "http://api.extscreen.com/aliyundrive";
const TV_USER_AGENT: &str =
    "AliTV/1.3.6 (Linux; U; Android 10; zh_CN; 1496; SM-G9730 Build/QKQ1.190828.002)";
/// TV v2 接口的固定 AES-256-CBC 密钥。
const TV_V2_KEY: [u8; 32] = *b"^(i/x>>5(ebyhumz*i1wkpk^orIs^Na.";

// ---------------- 通用 HTTP / 解析 ----------------

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// 发一次请求并解析 JSON；顺带把中转服务的业务错误码翻成 `ApiError`。
async fn send(request: reqwest::RequestBuilder, what: &str) -> ApiResult<Value> {
    let response = request
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("阿里云盘{what}失败: {e}")))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(ApiError::Upstream(format!(
            "阿里云盘{what}失败: HTTP {status}{}",
            message_suffix(&value)
        )));
    }
    ensure_business_ok(&value, what)?;
    Ok(value)
}

/// 中转服务多用 `{"code":200,...}`；开放平台失败时 `code` 是字符串错误码。
fn ensure_business_ok(value: &Value, what: &str) -> ApiResult<()> {
    let bad = match value.get("code") {
        Some(Value::Number(code)) => code.as_u64() != Some(200),
        Some(Value::String(code)) => !code.is_empty(),
        _ => false,
    };
    if bad {
        return Err(ApiError::Upstream(format!(
            "阿里云盘{what}失败{}",
            message_suffix(value)
        )));
    }
    Ok(())
}

fn message_suffix(value: &Value) -> String {
    let code = field(value, &["code"]).unwrap_or_default();
    let message = field(value, &["message", "msg", "error", "error_description"]).unwrap_or_default();
    if code.is_empty() && message.is_empty() {
        return String::new();
    }
    format!(": {code} {message}").trim_end().to_owned()
}

/// 中转服务的响应形态不一：有的直接摊在顶层，有的裹在 `data` 里，
/// 键名有蛇形也有驼峰 —— 两层一起按候选键名找。
fn field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for layer in [Some(value), value.get("data")].into_iter().flatten() {
        for key in keys {
            if let Some(text) = layer
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
            {
                return Some(text);
            }
        }
    }
    None
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    for layer in [Some(value), value.get("data")].into_iter().flatten() {
        for key in keys {
            if let Some(found) = layer
                .get(*key)
                .and_then(|found| found.as_u64().or_else(|| found.as_str()?.parse().ok()))
            {
                return Some(found);
            }
        }
    }
    None
}

fn tokens_of(value: &Value) -> Tokens {
    Tokens {
        access_token: field(value, &["access_token", "accessToken"])
            .unwrap_or_default()
            .to_owned(),
        refresh_token: field(value, &["refresh_token", "refreshToken"])
            .unwrap_or_default()
            .to_owned(),
        expires_in: number(value, &["expires_in", "expiresIn"]).unwrap_or(7200),
    }
}

// ---------------- 阿里云盘 TV（api.extscreen.com） ----------------

fn tv_v3_params() -> Vec<(&'static str, String)> {
    // 值参与密钥派生，顺序不能动。
    vec![
        ("akv", "2.8.1496".to_owned()),
        ("apv", "1.3.6".to_owned()),
        ("b", "abc".to_owned()),
        ("d", uuid::Uuid::new_v4().simple().to_string()),
        ("m", "abc".to_owned()),
        ("n", "abc".to_owned()),
    ]
}

/// v3 的一次性密钥：把请求头值拼起来去重，按时间戳做字符位移，取 md5 十六进制。
fn tv_v3_key(params: &[(&'static str, String)], now: &str) -> [u8; 32] {
    let joined: String = params.iter().map(|(_, value)| value.as_str()).collect();
    let modifier: i64 = now.get(7..).and_then(|tail| tail.parse().ok()).unwrap_or(0);
    let mut seen: Vec<char> = Vec::new();
    let mut transformed = String::new();
    for ch in joined.chars() {
        if seen.contains(&ch) {
            continue;
        }
        seen.push(ch);
        let mut code = ((ch as i64) - (modifier % 127) - 1).abs();
        if code < 33 {
            code += 33;
        }
        transformed.push(char::from_u32(code as u32).unwrap_or('!'));
    }
    let digest = hex::encode(md5::Md5::digest(transformed.as_bytes()));
    digest
        .into_bytes()
        .try_into()
        .expect("md5 十六进制固定 32 字节")
}

/// TV 中转只提供 form 表单接口。优先 https 保持链路加密，但只要 https 这一跳
/// 整段（含解密）有任何闪失就退回 http 重试 —— 该服务历史上只有 http 入口（参考
/// 实现也一律走 http），其 https 前置常由 WAF/负载均衡兜着，可能连不上、证书对
/// 不上、回非 2xx，甚至回一个 200 的挑战页导致解密失败；这些都不该让 TV 授权
/// 失败，而应落到能用的 http 上。
///
/// `decrypt_key` 为 `Some` 时，响应体在函数内直接解密并校验（TV 的 token 接口
/// 整体加密），这样 https 侧返回“能收下却解不开”的垃圾也能触发 http 回退；`None`
/// 用于二维码接口这类明文响应。
async fn tv_call(
    http: &Client,
    path: &str,
    form: &[(&str, String)],
    headers: Option<&[(&str, String)]>,
    decrypt_key: Option<&[u8; 32]>,
    what: &str,
) -> ApiResult<Value> {
    let attempt = |base: &'static str| async move {
        let mut request = http.post(format!("{base}{path}")).form(form);
        for (name, value) in headers.unwrap_or_default() {
            request = request.header(*name, value);
        }
        let value = send(request, what).await?;
        match decrypt_key {
            Some(key) => tv_decrypt(&value, key),
            None => Ok(value),
        }
    };
    match attempt(TV_BASE_HTTPS).await {
        Ok(value) => Ok(value),
        Err(_) => attempt(TV_BASE_HTTP).await,
    }
}

/// TV 中转的响应体是 AES-256-CBC 密文（padding 只看最后一个字节，
/// 与上游实现保持一致，不做严格 PKCS7 校验）。
fn tv_decrypt(value: &Value, key: &[u8; 32]) -> ApiResult<Value> {
    let bad = |what: &str| ApiError::Upstream(format!("阿里云盘TV 响应{what}"));
    let iv = hex::decode(field(value, &["iv"]).ok_or_else(|| bad("缺少 iv"))?)
        .map_err(|_| bad("iv 不是十六进制"))?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| bad("iv 长度非法"))?;
    let mut buffer = B64
        .decode(field(value, &["ciphertext"]).ok_or_else(|| bad("缺少 ciphertext"))?)
        .map_err(|_| bad("密文不是 base64"))?;
    if buffer.is_empty() || buffer.len() % 16 != 0 {
        return Err(bad("密文长度非法"));
    }
    let plain = cbc::Decryptor::<aes::Aes256>::new(key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| bad("解密失败"))?;
    let padding = *plain.last().expect("非空密文解出非空明文") as usize;
    let end = plain
        .len()
        .checked_sub(padding)
        .filter(|end| *end > 0)
        .ok_or_else(|| bad("填充非法（密钥可能已失效）"))?;
    serde_json::from_slice(&plain[..end]).map_err(|_| bad("明文不是 JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;
    use aes::cipher::block_padding::Pkcs7;

    fn jwt(claims: &str) -> String {
        format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
        )
    }

    #[test]
    fn builtin_keys_and_client_ids_are_unique() {
        for (index, app) in BUILTINS.iter().enumerate() {
            assert_eq!(app.client_id.len(), 32, "{} 的 client_id 形态异常", app.key);
            for other in &BUILTINS[index + 1..] {
                assert_ne!(app.key, other.key);
                assert_ne!(app.client_id, other.client_id);
            }
            // 直连开放平台的应用必须带上公开密钥，中转型的必须留空。
            assert_eq!(
                app.flavor == Flavor::Open,
                !app.client_secret.is_empty(),
                "{} 的 client_secret 与协议不匹配",
                app.key
            );
        }
        assert!(find(DEFAULT_APP).is_some());
    }

    #[test]
    fn detects_builtin_app_from_refresh_token_audience() {
        let tv = find("tv").unwrap();
        let token = jwt(&format!(r#"{{"sub":"u1","aud":"{}"}}"#, tv.client_id));
        assert_eq!(detect(&token).map(|app| app.key), Some("tv"));
        assert_eq!(jwt_claim(&token, "sub").as_deref(), Some("u1"));
        // 不认识的 aud、以及压根不是 JWT 的令牌都识别不出来。
        assert!(detect(&jwt(r#"{"aud":"someone-else"}"#)).is_none());
        assert!(detect("not-a-jwt").is_none());
    }

    /// 公钥 PEM 必须能解析出验签器 —— 否则所有 refresh_token 都会被判成「验签
    /// 未通过」，等于把用户合法的令牌统统拒之门外，是个致命回归。
    #[test]
    fn open_refresh_token_pubkey_parses() {
        assert!(OPEN_RT_VERIFIER.is_some(), "开放平台验签公钥 PEM 解析失败");
    }

    /// `inspect` 读 `exp` 判过期、按 `aud` 识别应用，都不依赖签名有效性；而 `valid`
    /// 只认公钥签得出的真令牌 —— 未签名的伪 JWT、篡改签名、非 JWT 串都判 false。
    #[test]
    fn inspect_reads_expiry_and_audience_and_rejects_unsigned() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let tv = find("tv").unwrap();

        // 未来到期、可按 aud 识别为 TV（这枚是测试自造的未签名 JWT）。
        let future = jwt(&format!(r#"{{"aud":"{}","exp":9999999999}}"#, tv.client_id));
        let good = inspect(&future);
        assert_eq!(good.expires_at, Some(9_999_999_999));
        assert!(!good.expired);
        assert_eq!(good.app.map(|app| app.key), Some("tv"));
        assert!(!good.valid, "未签名的伪 JWT 不应通过验签");

        // exp 在过去 → expired 置位。
        assert!(inspect(&jwt(r#"{"exp":1}"#)).expired);

        // 结构像 JWT 但签名是伪造的、以及 PDS 那种非 JWT 的不透明串，都过不了验签。
        let (message, _) = future.rsplit_once('.').unwrap();
        assert!(!inspect(&format!("{message}.{}", B64URL.encode([0u8; 64]))).valid);
        assert!(!inspect("3b00f739f30d458b80f492cc55ffcd36").valid);
    }

    /// 认不出应用时降级为自定义应用；此时必须有用户自填的 client 凭证。
    #[test]
    fn unknown_token_falls_back_to_custom_app() {
        let unknown = jwt(r#"{"aud":"nobody"}"#);
        let app = resolve(None, Some("cid"), Some("csec"), Some(&unknown), None).unwrap();
        assert_eq!(app.key, CUSTOM_APP);
        assert_eq!(app.client_id, "cid");

        let error = resolve(None, None, None, Some(&unknown), None).unwrap_err();
        assert!(matches!(error, ApiError::BadRequest(ref m) if m.contains("client_id")));
    }

    /// 指定了内置应用就用内置密钥，用户填的 client 凭证不参与。
    #[test]
    fn explicit_builtin_wins_over_user_credentials() {
        let app = resolve(Some("vidhub"), Some("cid"), Some("csec"), None, None).unwrap();
        assert_eq!(app.client_id, find("vidhub").unwrap().client_id);
        assert_eq!(app.key, "vidhub");
        assert!(resolve(Some("nope"), None, None, None, None).is_err());
        // custom 必须自带凭证
        assert!(resolve(Some(CUSTOM_APP), None, None, None, None).is_err());
    }

    #[test]
    fn api_base_override_applies_to_open_endpoints() {
        let app = resolve(Some("tv"), None, None, None, Some("https://gateway.local/")).unwrap();
        assert_eq!(
            app.open_url("/oauth/access_token"),
            "https://gateway.local/oauth/access_token"
        );
        let app = resolve(Some("tv"), None, None, None, None).unwrap();
        assert!(app.open_url("/x").starts_with(DEFAULT_API_BASE));
    }

    #[test]
    fn reads_tokens_from_either_case_and_nesting() {
        let flat = json!({ "access_token": "at", "refresh_token": "rt", "expires_in": 60 });
        let nested = json!({ "code": 200, "data": { "accessToken": "at", "refreshToken": "rt" } });
        assert_eq!(tokens_of(&flat).access_token, "at");
        assert_eq!(tokens_of(&flat).expires_in, 60);
        assert_eq!(tokens_of(&nested).refresh_token, "rt");
        // 缺 expires_in 时给个保守默认值
        assert_eq!(tokens_of(&nested).expires_in, 7200);
    }

    #[test]
    fn business_errors_become_upstream_errors() {
        assert!(ensure_business_ok(&json!({ "code": 200 }), "刷新令牌").is_ok());
        assert!(ensure_business_ok(&json!({ "access_token": "at" }), "刷新令牌").is_ok());
        let error = ensure_business_ok(
            &json!({ "code": 400, "message": "用户未授权应用" }),
            "刷新令牌",
        )
        .unwrap_err();
        assert!(matches!(error, ApiError::Upstream(ref m) if m.contains("用户未授权应用")));
        // 开放平台的字符串错误码
        assert!(ensure_business_ok(&json!({ "code": "InvalidParameter" }), "x").is_err());
    }

    /// 与上游 Python 实现对齐：同样的时间戳与参数派生出同样的密钥。
    #[test]
    fn tv_v3_key_matches_reference_derivation() {
        let params = vec![
            ("akv", "2.8.1496".to_owned()),
            ("apv", "1.3.6".to_owned()),
            ("b", "abc".to_owned()),
            ("d", "0123456789abcdef0123456789abcdef".to_owned()),
            ("m", "abc".to_owned()),
            ("n", "abc".to_owned()),
        ];
        // 拼接值 = "2.8.14961.3.6abc0123456789abcdef0123456789abcdefabcabc"
        // 位移量取时间戳的后三位（"1717082331"[7:] = 331）
        let key = tv_v3_key(&params, "1717082331");
        let expected = {
            let joined = "2.8.14961.3.6abc0123456789abcdef0123456789abcdefabcabc";
            let mut seen = Vec::new();
            let mut transformed = String::new();
            for ch in joined.chars() {
                if seen.contains(&ch) {
                    continue;
                }
                seen.push(ch);
                let mut code = ((ch as i64) - (331 % 127) - 1).abs();
                if code < 33 {
                    code += 33;
                }
                transformed.push(char::from_u32(code as u32).unwrap());
            }
            hex::encode(md5::Md5::digest(transformed.as_bytes()))
        };
        assert_eq!(std::str::from_utf8(&key).unwrap(), expected);
        // 时间戳只有后三位参与位移：同秒同参数必然同密钥。
        assert_eq!(key, tv_v3_key(&params, "1717082331"));
        assert_ne!(key, tv_v3_key(&params, "1717082332"));
    }

    #[test]
    fn tv_ciphertext_roundtrips() {
        let key = TV_V2_KEY;
        let iv = [0x11u8; 16];
        let plain = br#"{"access_token":"at","refresh_token":"rt","expires_in":7200}"#;
        let mut buffer = vec![0u8; plain.len() + 16];
        buffer[..plain.len()].copy_from_slice(plain);
        let cipher = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plain.len())
            .unwrap();
        let value = json!({
            "iv": hex::encode(iv),
            "ciphertext": B64.encode(cipher),
        });
        let decoded = tv_decrypt(&value, &key).unwrap();
        assert_eq!(tokens_of(&decoded).access_token, "at");
        assert_eq!(tokens_of(&decoded).refresh_token, "rt");
        // 换个密钥解出来的明文填充必然不成立
        assert!(tv_decrypt(&value, &[0u8; 32]).is_err());
        assert!(tv_decrypt(&json!({ "iv": "zz" }), &key).is_err());
    }
}
