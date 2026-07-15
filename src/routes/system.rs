//! 全局传输设置、缓存和实时传输状态 API。

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings", get(settings_get).put(settings_put))
        .route("/cache", get(cache_stats).delete(cache_clear))
        .route("/transfers", get(transfer_status))
}

async fn settings_get(State(state): State<AppState>) -> Json<crate::settings::Settings> {
    Json(state.settings.get())
}

async fn settings_put(
    State(state): State<AppState>,
    Json(body): Json<crate::settings::Settings>,
) -> ApiResult<Json<crate::settings::Settings>> {
    Ok(Json(state.settings.set(body)?))
}

async fn cache_stats(State(state): State<AppState>) -> Json<crate::cache::CacheStats> {
    Json(state.content_cache.stats())
}

async fn cache_clear(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let freed = state.content_cache.clear_all()?;
    Ok(Json(json!({ "ok": true, "freed": freed })))
}

async fn transfer_status(State(state): State<AppState>) -> Json<crate::transfer::TransferSnapshot> {
    Json(state.transfers.snapshot())
}
