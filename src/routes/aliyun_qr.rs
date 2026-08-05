//! 阿里云盘扫码授权。两条独立的令牌线：
//!
//! * **开放平台**（`/aliyun/qrcode`）：内置第三方应用或用户自备应用，扫码
//!   拿 refresh_token，日常读写全靠它。默认用阿里云盘TV。
//! * **官网**（`/aliyun/web/qrcode`）：可选，只为分享与转存服务 ——
//!   开放平台没有这两个能力。
//!
//! 凭证不经过 SafeDrive 之外的第三方：内置应用会经该应用作者的中转服务
//! （这是拿到其 client_secret 的唯一途径，见 `adapters::aliyun_apps`），
//! 其余全程只跟阿里官方域名打交道，服务端不落盘、不记录。

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::adapters::{aliyun_apps, aliyun_web};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/aliyun/apps", get(list_apps))
        .route("/aliyun/detect", post(detect_app))
        .route("/aliyun/qrcode", post(create_qrcode))
        .route("/aliyun/qrcode/poll", post(poll_qrcode))
        .route("/aliyun/silent", post(silent_grant))
        .route("/aliyun/web/qrcode", post(create_web_qrcode))
        .route("/aliyun/web/qrcode/poll", post(poll_web_qrcode))
}

/// 内置第三方应用清单（前端下拉框）。
async fn list_apps() -> Json<Value> {
    Json(json!({
        "apps": aliyun_apps::builtins(),
        "default": aliyun_apps::DEFAULT_APP,
        "custom": aliyun_apps::CUSTOM_APP,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DetectBody {
    refresh_token: String,
}

/// 校验手填的 refresh_token：验签是否合法、有没有过期、属于哪个内置应用。
/// 识别不出（但令牌合法）就让用户自己填 client_id / client_secret。
async fn detect_app(Json(body): Json<DetectBody>) -> Json<Value> {
    let inspection = aliyun_apps::inspect(body.refresh_token.trim());
    Json(json!({
        "valid": inspection.valid,
        "expired": inspection.expired,
        "expiresAt": inspection.expires_at,
        "app": inspection.app.map(|app| app.key),
        "name": inspection.app.map(|app| app.name),
        "note": inspection.app.map(|app| app.note),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppBody {
    /// 内置应用键或 `custom`；缺省即默认应用（阿里云盘TV）。
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    /// 轮询时才有：申请二维码时拿到的会话 ID。
    #[serde(default)]
    sid: Option<String>,
}

impl AppBody {
    /// 扫码流程没有 refresh_token 可供识别，所以不传 app 就用默认应用。
    fn app(&self) -> ApiResult<aliyun_apps::App> {
        let key = self
            .app
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .unwrap_or(aliyun_apps::DEFAULT_APP);
        aliyun_apps::resolve(
            Some(key),
            self.client_id.as_deref(),
            self.client_secret.as_deref(),
            None,
            None,
        )
    }
}

async fn create_qrcode(
    State(state): State<AppState>,
    Json(body): Json<AppBody>,
) -> ApiResult<Json<Value>> {
    let app = body.app()?;
    let qr = app.qr(&state.http).await?;
    // 二维码图片由服务端取回后同源下发：浏览器不必直连阿里/中转域名，
    // 也避免图片被拦截时用户只看到一个空白框。
    let img = fetch_qr_image(&state.http, &qr.image_url).await;
    Ok(Json(json!({
        "app": app.key,
        "appName": app.name,
        "qrCodeUrl": qr.image_url,
        "sid": qr.sid,
        "img": img,
    })))
}

/// 取回二维码图片并转 base64；失败返回空串（前端退回直链渲染）。
async fn fetch_qr_image(http: &reqwest::Client, url: &str) -> String {
    use base64::Engine as _;
    let Ok(response) = http.get(url).send().await else {
        return String::new();
    };
    if !response.status().is_success() {
        return String::new();
    }
    match response.bytes().await {
        Ok(bytes) if !bytes.is_empty() => base64::engine::general_purpose::STANDARD.encode(&bytes),
        _ => String::new(),
    }
}

/// 轮询一次扫码状态。status：waiting（等待扫码）/ scanned（已扫码待确认）
/// / confirmed（已确认，附 refreshToken）/ expired（二维码失效）。
async fn poll_qrcode(
    State(state): State<AppState>,
    Json(body): Json<AppBody>,
) -> ApiResult<Json<Value>> {
    let app = body.app()?;
    let sid = body
        .sid
        .as_deref()
        .map(str::trim)
        .filter(|sid| !sid.is_empty())
        .ok_or_else(|| ApiError::BadRequest("缺少扫码会话 sid".into()))?;
    match app.qr_status(&state.http, sid).await? {
        aliyun_apps::QrStatus::Confirmed(auth_code) => {
            let tokens = app.exchange(&state.http, sid, &auth_code).await?;
            Ok(Json(json!({
                "status": "confirmed",
                "app": app.key,
                "refreshToken": tokens.refresh_token,
                "accessToken": tokens.access_token,
                "accessTokenExpiresAt": crate::registry::now_ms() / 1000 + tokens.expires_in,
            })))
        }
        aliyun_apps::QrStatus::Scanned => Ok(Json(json!({ "status": "scanned" }))),
        aliyun_apps::QrStatus::Expired => Ok(Json(json!({ "status": "expired" }))),
        aliyun_apps::QrStatus::Waiting => Ok(Json(json!({ "status": "waiting" }))),
    }
}

// ---------------- 官网令牌静默授权（免扫码换开放平台令牌） ----------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SilentBody {
    /// 官网（PDS）刷新令牌：先换官网 access_token，再拿它替用户授权第三方应用。
    web_refresh_token: String,
    /// 要授权的第三方应用；缺省即默认应用（阿里云盘TV）。
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// 用已配置的官网令牌静默授权第三方应用，免扫码直接拿到开放平台 refresh_token。
/// 用户填了官网令牌后，开放平台那份令牌就不必再单独扫一次码。
async fn silent_grant(
    State(state): State<AppState>,
    Json(body): Json<SilentBody>,
) -> ApiResult<Json<Value>> {
    let web_refresh = body.web_refresh_token.trim();
    if web_refresh.is_empty() {
        return Err(ApiError::BadRequest("缺少官网令牌，无法静默授权".into()));
    }
    let key = body
        .app
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .unwrap_or(aliyun_apps::DEFAULT_APP);
    let app = aliyun_apps::resolve(
        Some(key),
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
        None,
        None,
    )?;
    let pds_access = aliyun_web::web_access_token(&state.http, web_refresh).await?;
    let tokens = app.silent_grant(&state.http, &pds_access).await?;
    Ok(Json(json!({
        "app": app.key,
        "appName": app.name,
        "refreshToken": tokens.refresh_token,
        "accessToken": tokens.access_token,
        "accessTokenExpiresAt": crate::registry::now_ms() / 1000 + tokens.expires_in,
    })))
}

// ---------------- 官网令牌（分享 / 转存专用） ----------------

/// 官网扫码是有状态的（passport 会话 Cookie + 二维码参数）。服务端不存
/// 会话：整个 session 原样交给前端，轮询时带回来。
#[derive(Deserialize)]
struct WebPollBody {
    session: aliyun_web::WebQrSession,
}

async fn create_web_qrcode(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let (code_content, session) = aliyun_web::qr_generate(&state.passport).await?;
    Ok(Json(json!({
        // 官网二维码是纯文本，由前端自己渲染（服务端没有二维码编码器）。
        "codeContent": code_content,
        "session": session,
    })))
}

async fn poll_web_qrcode(
    State(state): State<AppState>,
    Json(body): Json<WebPollBody>,
) -> ApiResult<Json<Value>> {
    match aliyun_web::qr_query(&state.passport, &body.session).await? {
        aliyun_web::WebQrStatus::Confirmed(refresh_token) => Ok(Json(json!({
            "status": "confirmed",
            "webRefreshToken": refresh_token,
        }))),
        aliyun_web::WebQrStatus::Scanned => Ok(Json(json!({ "status": "scanned" }))),
        aliyun_web::WebQrStatus::Expired => Ok(Json(json!({ "status": "expired" }))),
        aliyun_web::WebQrStatus::Waiting => Ok(Json(json!({ "status": "waiting" }))),
    }
}
