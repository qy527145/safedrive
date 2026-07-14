//! 策略管理（含根密码）+ 全局传输设置 + 策略备份 API。

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::registry::now_ms;
use crate::state::AppState;
use crate::strategies::Strategy;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/strategies", get(list).post(create))
        .route("/strategies/{id}", put(update).delete(remove))
        .route("/settings", get(settings_get).put(settings_put))
        .route("/vault/export", get(vault_export))
        .route("/vault/import", axum::routing::post(vault_import))
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StrategyBody {
    name: String,
    /// None/缺省 = 不分卷；接受数字（字节）或 "300M"/"1.5GB" 等字符串。
    #[serde(default, deserialize_with = "crate::settings::de_opt_size")]
    volume_size: Option<u64>,
    /// 根密码（任意非空字符串）；创建时缺省则自动生成随机密码。
    #[serde(default)]
    password: Option<String>,
}

async fn list(State(state): State<AppState>) -> Json<Vec<Strategy>> {
    Json(state.strategies.list())
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<StrategyBody>,
) -> ApiResult<Json<Strategy>> {
    let s = Strategy {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name,
        volume_size: body.volume_size,
        password: body
            .password
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(crate::strategies::gen_share_password),
        prev_password: None,
        created_at: now_ms(),
    };
    Ok(Json(state.strategies.create(s)?))
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<StrategyBody>,
) -> ApiResult<Json<Strategy>> {
    let old = state
        .strategies
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("策略不存在: {id}")))?;
    let new_password =
        body.password.filter(|p| !p.trim().is_empty()).unwrap_or(old.password.clone());
    // 密码变化，或上次换密码迁移中断（prev_password 残留）→ 跑/续跑迁移
    let password_changed = new_password != old.password;
    let resume_pending = !password_changed && old.prev_password.is_some();

    if password_changed || resume_pending {
        // 换根密码 = 只需重编码各数据源**根目录直属**的信封（子孙锚在
        // 各自父 FK 上不受影响）。先落盘 prev_password 再迁移：任何一步
        // 失败/断网/宕机，旧信封仍可用 prev 解开（resolve 的候选钥回退），
        // 重试本接口即可从断点继续 —— 无需回滚。
        // 续传时沿用残留的 prev；新换密码时记录当前密码为 prev
        let prev_password =
            if resume_pending { old.prev_password.clone().unwrap() } else { old.password.clone() };
        let s = Strategy {
            id: id.clone(),
            name: body.name.clone(),
            volume_size: body.volume_size,
            password: new_password.clone(),
            prev_password: Some(prev_password.clone()),
            created_at: 0,
        };
        state.strategies.update(&id, s)?;

        let new_key = crate::crypto::derive_root_key(new_password.as_bytes());
        let old_key = crate::crypto::derive_root_key(prev_password.as_bytes());
        let bound: Vec<crate::registry::DataSource> = state
            .registry
            .list()
            .into_iter()
            .filter(|d| d.strategy_id == id)
            .collect();
        let mut migrated = 0usize;
        for ds in &bound {
            state.cache.evict_datasource(&ds.id);
            let storage = state.adapter(&ds.id)?;
            migrated += migrate_root_envelopes(storage.as_ref(), &old_key, &new_key)
                .await
                .map_err(|e| {
                    ApiError::Upstream(format!(
                        "数据源「{}」根信封迁移失败（旧密码仍可解读，修复网络后重试本操作即可续传）: {e}",
                        ds.name
                    ))
                })?;
        }
        // 全部迁移成功才清除过渡密码
        let done = Strategy {
            id: id.clone(),
            name: body.name,
            volume_size: body.volume_size,
            password: new_password,
            prev_password: None,
            created_at: 0,
        };
        let saved = state.strategies.update(&id, done)?;
        tracing::info!("策略 {id} 根密码更换完成，迁移根信封 {migrated} 个");
        return Ok(Json(saved));
    }

    let s = Strategy {
        id: id.clone(),
        name: body.name,
        volume_size: body.volume_size,
        password: new_password,
        prev_password: old.prev_password,
        created_at: 0, // update 保留原值
    };
    Ok(Json(state.strategies.update(&id, s)?))
}

async fn remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let bound: Vec<String> = state
        .registry
        .list()
        .into_iter()
        .filter(|d| d.strategy_id == id)
        .map(|d| d.name)
        .collect();
    if !bound.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "策略正被数据源使用: {}",
            bound.join("、")
        )));
    }
    state.strategies.remove(&id)?;
    Ok(Json(json!({ "ok": true })))
}

/// 导出策略备份（JSON 下载，含根密码）。丢失根密码 = 数据永久不可恢复。
async fn vault_export(State(state): State<AppState>) -> ApiResult<Response> {
    let data = state.strategies.export_json()?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"safedrive-strategies.json\"".to_string(),
            ),
        ],
        data,
    )
        .into_response())
}

/// 导入合并（按 id 并集，本地优先）。
async fn vault_import(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let added = state.strategies.import_merge(&body)?;
    Ok(Json(json!({ "ok": true, "added": added })))
}

/// 把存储根目录下所有旧根钥信封重编码为新根钥（secret/名字原样）。
/// 幂等：已是新钥的条目解不开旧钥，自然跳过；可从任意断点重试。
async fn migrate_root_envelopes(
    storage: &dyn crate::adapters::Storage,
    old_key: &[u8; crate::crypto::SECRET_LEN],
    new_key: &[u8; crate::crypto::SECRET_LEN],
) -> ApiResult<usize> {
    use crate::crypto::names::{decode_name, encode_name};
    let entries = storage.list("").await?;
    let mut migrated = 0;
    for e in entries.iter().filter(|e| e.is_dir) {
        let Some(meta) = decode_name(old_key, &e.name) else {
            continue; // 新钥信封 / 外来条目
        };
        let new_nc = encode_name(new_key, &meta)
            .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {}", meta.name)))?;
        storage.rename(&e.name, &new_nc).await?;
        migrated += 1;
    }
    Ok(migrated)
}
