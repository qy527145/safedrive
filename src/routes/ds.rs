use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::registry::{DataSource, now_ms};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ds", get(list).post(create))
        .route("/ds/{id}", put(update).delete(remove))
        .route("/ds/{id}/test", post(test))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DsBody {
    name: String,
    #[serde(rename = "type")]
    ds_type: String,
    config: serde_json::Value,
    strategy_id: String,
}

fn validate(state: &AppState, body: &DsBody) -> ApiResult<()> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("数据源名称不能为空".into()));
    }
    if state.strategies.get(&body.strategy_id).is_none() {
        return Err(ApiError::BadRequest("绑定的数据映射策略不存在".into()));
    }
    match body.ds_type.as_str() {
        "localfs" => {
            let root = body
                .config
                .get("root")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if root.is_empty() {
                return Err(ApiError::BadRequest("localfs 需要 root 目录".into()));
            }
            std::fs::create_dir_all(root)
                .map_err(|e| ApiError::BadRequest(format!("root 目录不可用: {e}")))?;
        }
        "webdav" => {
            let url = body
                .config
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(ApiError::BadRequest("webdav 需要 http(s) url".into()));
            }
        }
        "baidupan" => {
            let cookie = body
                .config
                .get("cookie")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !cookie
                .split(';')
                .any(|part| part.trim().starts_with("BDUSS="))
            {
                return Err(ApiError::BadRequest(
                    "百度网盘需要包含 BDUSS 的 cookie".into(),
                ));
            }
            for (field, label) in [
                ("clientId", "开放平台 API Key"),
                ("clientSecret", "开放平台 Secret Key"),
                ("refreshToken", "开放平台 Refresh Token"),
            ] {
                if body
                    .config
                    .get(field)
                    .and_then(|value| value.as_str())
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(ApiError::BadRequest(format!("百度网盘需要{label}")));
                }
            }
            let root = body
                .config
                .get("root")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if root.contains("..") || root.contains('\\') {
                return Err(ApiError::BadRequest("百度网盘根目录非法".into()));
            }
        }
        other => return Err(ApiError::BadRequest(format!("未知数据源类型: {other}"))),
    }
    Ok(())
}

async fn list(State(state): State<AppState>) -> Json<Vec<DataSource>> {
    Json(state.registry.list())
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<DsBody>,
) -> ApiResult<Json<DataSource>> {
    validate(&state, &body)?;
    let ds = DataSource {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name,
        ds_type: body.ds_type,
        config: body.config,
        strategy_id: body.strategy_id,
        created_at: now_ms(),
    };
    Ok(Json(state.registry.create(ds)?))
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<DsBody>,
) -> ApiResult<Json<DataSource>> {
    validate(&state, &body)?;
    let old = state
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
    let ds = DataSource {
        id: id.clone(),
        name: body.name,
        ds_type: body.ds_type,
        config: body.config,
        strategy_id: body.strategy_id,
        created_at: old.created_at,
    };
    Ok(Json(state.registry.update(&id, ds)?))
}

async fn remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state.registry.remove(&id)?;
    // 云端密文仍在；只要策略（根密码）还在，重新挂同一存储即可找回数据
    state.cache.evict_datasource(&id);
    Ok(Json(json!({ "ok": true })))
}

/// 测试连接：列根目录。
async fn test(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let adapter = state.adapter(&id)?;
    let entries = match adapter.list("").await {
        Ok(entries) => entries,
        Err(ApiError::NotFound(_))
            if state
                .registry
                .get(&id)
                .is_some_and(|ds| ds.ds_type == "baidupan") =>
        {
            adapter.mkdir("").await?;
            adapter.list("").await?
        }
        Err(e) => return Err(e),
    };
    Ok(Json(json!({ "ok": true, "entries": entries.len() })))
}
