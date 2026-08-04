//! 阿里云盘扫码授权：代理开放平台的 OAuth 二维码流程，用户手机扫码
//! 确认后直接把 refreshToken 回填到数据源表单，免去手动折腾令牌。
//!
//! 凭证不经过任何第三方 —— 全程只跟用户自己填的 client_id/client_secret
//! 与 openapi.alipan.com 打交道。二维码图片由前端用返回的 qrCodeUrl 渲染。

use axum::routing::post;
use axum::extract::State;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::adapters::aliyundrive;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/aliyun/qrcode", post(create_qrcode))
        .route("/aliyun/qrcode/poll", post(poll_qrcode))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppBody {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    api_base: Option<String>,
    /// 轮询时才有：申请二维码时拿到的会话 ID。
    #[serde(default)]
    sid: Option<String>,
}

impl AppBody {
    fn validate(&self) -> ApiResult<&str> {
        if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "请先填写阿里云盘的 client_id 与 client_secret".into(),
            ));
        }
        Ok(self
            .api_base
            .as_deref()
            .map(str::trim)
            .filter(|base| !base.is_empty())
            .unwrap_or(aliyundrive::DEFAULT_API_BASE))
    }
}

async fn create_qrcode(
    State(state): State<AppState>,
    Json(body): Json<AppBody>,
) -> ApiResult<Json<Value>> {
    let api_base = body.validate()?;
    let (qr_code_url, sid) = aliyundrive::qr_authorize(
        &state.http,
        api_base,
        body.client_id.trim(),
        body.client_secret.trim(),
    )
    .await?;
    // 二维码图片由服务端取回后同源下发：浏览器不必直连阿里域名，
    // 也避免图片被拦截时用户只看到一个空白框。
    let img = fetch_qr_image(&state.http, &qr_code_url).await;
    Ok(Json(json!({
        "qrCodeUrl": qr_code_url,
        "sid": sid,
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
        Ok(bytes) if !bytes.is_empty() => {
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        }
        _ => String::new(),
    }
}

/// 轮询一次扫码状态。status：waiting（等待扫码）/ scanned（已扫码待确认）
/// / confirmed（已确认，附 refreshToken）/ expired（二维码失效）。
async fn poll_qrcode(
    State(state): State<AppState>,
    Json(body): Json<AppBody>,
) -> ApiResult<Json<Value>> {
    let api_base = body.validate()?;
    let sid = body
        .sid
        .as_deref()
        .map(str::trim)
        .filter(|sid| !sid.is_empty())
        .ok_or_else(|| ApiError::BadRequest("缺少扫码会话 sid".into()))?;
    let (status, auth_code) = aliyundrive::qr_status(&state.http, api_base, sid).await?;
    // 开放平台的状态字面量：WaitLogin / ScanSuccess / LoginSuccess / QRCodeExpired
    match status.as_str() {
        "LoginSuccess" => {
            if auth_code.is_empty() {
                return Err(ApiError::Upstream("扫码已确认但未返回 authCode".into()));
            }
            let (access_token, refresh_token, expires_at) = aliyundrive::exchange_auth_code(
                &state.http,
                api_base,
                body.client_id.trim(),
                body.client_secret.trim(),
                &auth_code,
            )
            .await?;
            Ok(Json(json!({
                "status": "confirmed",
                "refreshToken": refresh_token,
                "accessToken": access_token,
                "accessTokenExpiresAt": expires_at,
            })))
        }
        "ScanSuccess" => Ok(Json(json!({ "status": "scanned" }))),
        "QRCodeExpired" => Ok(Json(json!({ "status": "expired" }))),
        _ => Ok(Json(json!({ "status": "waiting" }))),
    }
}
