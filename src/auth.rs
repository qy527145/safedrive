use axum::Json;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginBody {
    pub password: String,
}

/// 常量时间比较，避免时序侧信道。
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(expected) = &state.admin_password else {
        return Ok(Json(json!({ "token": null })));
    };
    if !ct_eq(expected, &body.password) {
        return Err(ApiError::Unauthorized);
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("随机数生成失败: {e}"))?;
    let token = hex::encode(raw);
    state.sessions.write().unwrap().insert(token.clone());
    Ok(Json(json!({ "token": token })))
}

/// 鉴权中间件：管理密码未配置时直接放行（本机模式）。
pub async fn require_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.admin_password.is_none() {
        return Ok(next.run(req).await);
    }
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !token.is_empty() && state.sessions.read().unwrap().contains(token) {
        Ok(next.run(req).await)
    } else {
        Err(ApiError::Unauthorized)
    }
}
