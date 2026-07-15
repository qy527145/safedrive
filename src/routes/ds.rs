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
    #[serde(default)]
    encryption_enabled: Option<bool>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    volume_enabled: Option<bool>,
    #[serde(default, deserialize_with = "crate::settings::de_opt_size")]
    volume_size: Option<u64>,
    #[serde(default)]
    volume_strategy: Option<String>,
    #[serde(default)]
    volume_name_format: Option<String>,
    #[serde(default)]
    cache_enabled: Option<bool>,
}

fn validate(body: &DsBody) -> ApiResult<()> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("数据源名称不能为空".into()));
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
            let has_bduss = body
                .config
                .get("bduss")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            let legacy_cookie_has_bduss = body
                .config
                .get("cookie")
                .and_then(|value| value.as_str())
                .is_some_and(|cookie| {
                    cookie
                        .split(';')
                        .any(|part| part.trim().starts_with("BDUSS="))
                });
            if !has_bduss && !legacy_cookie_has_bduss {
                return Err(ApiError::BadRequest("百度网盘需要 BDUSS".into()));
            }
            let has_client_id = body
                .config
                .get("clientId")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            let has_client_secret = body
                .config
                .get("clientSecret")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            if has_client_id != has_client_secret {
                return Err(ApiError::BadRequest(
                    "百度开放平台 API Key 与 Secret Key 必须同时填写或同时留空".into(),
                ));
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

fn mapping_config(
    body: &DsBody,
    old: Option<&DataSource>,
) -> ApiResult<(bool, String, bool, u64, String, String, bool)> {
    let encrypted = body
        .encryption_enabled
        .or_else(|| old.map(|d| d.encryption_enabled))
        .unwrap_or(true);
    let password = body
        .password
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .or_else(|| old.map(|d| d.password.clone()))
        .unwrap_or_else(crate::registry::gen_password);
    let volume_enabled = body
        .volume_enabled
        .or_else(|| old.map(|d| d.volume_enabled))
        .unwrap_or(true);
    let volume_size = body
        .volume_size
        .or_else(|| old.map(|d| d.volume_size))
        .unwrap_or(crate::registry::DEFAULT_VOLUME_SIZE);
    let strategy = body
        .volume_strategy
        .clone()
        .or_else(|| old.map(|d| d.volume_strategy.clone()))
        .unwrap_or_else(|| "random".into());
    let format = body
        .volume_name_format
        .clone()
        .or_else(|| old.map(|d| d.volume_name_format.clone()))
        .unwrap_or_else(|| "{s}_{i}.bin".into());
    let cache = body
        .cache_enabled
        .or_else(|| old.map(|d| d.cache_enabled))
        .unwrap_or(true);
    if encrypted && password.is_empty() {
        return Err(ApiError::BadRequest("启用加密时密码不能为空".into()));
    }
    if volume_enabled {
        if volume_size < crate::registry::MIN_VOLUME_SIZE {
            return Err(ApiError::BadRequest("最大分卷大小至少 64KiB".into()));
        }
        if strategy != "fixed" && strategy != "random" {
            return Err(ApiError::BadRequest(
                "分卷策略只能是 fixed 或 random".into(),
            ));
        }
        if !encrypted {
            if !format.contains("{i}") {
                return Err(ApiError::BadRequest("分卷名称格式必须包含 {i}".into()));
            }
            let sample = format.replace("{s}", "sample").replace("{i}", "0001");
            if sample.contains('/') || sample.contains('\\') || sample == "." || sample == ".." {
                return Err(ApiError::BadRequest("分卷名称格式包含非法路径字符".into()));
            }
        }
    }
    Ok((
        encrypted,
        if encrypted { password } else { String::new() },
        volume_enabled,
        volume_size,
        strategy,
        format,
        cache,
    ))
}

async fn list(State(state): State<AppState>) -> Json<Vec<DataSource>> {
    Json(state.registry.list())
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<DsBody>,
) -> ApiResult<Json<DataSource>> {
    validate(&body)?;
    let (
        encryption_enabled,
        password,
        volume_enabled,
        volume_size,
        volume_strategy,
        volume_name_format,
        cache_enabled,
    ) = mapping_config(&body, None)?;
    let ds = DataSource {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name,
        ds_type: body.ds_type,
        config: body.config,
        encryption_enabled,
        password,
        prev_password: None,
        volume_enabled,
        volume_size,
        volume_strategy,
        volume_name_format,
        cache_enabled,
        created_at: now_ms(),
    };
    Ok(Json(state.registry.create(ds)?))
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<DsBody>,
) -> ApiResult<Json<DataSource>> {
    validate(&body)?;
    let old = state
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
    let (
        encryption_enabled,
        password,
        volume_enabled,
        volume_size,
        volume_strategy,
        volume_name_format,
        cache_enabled,
    ) = mapping_config(&body, Some(&old))?;
    if encryption_enabled != old.encryption_enabled {
        return Err(ApiError::BadRequest(
            "加密模式在数据源创建后不可更改；请新建数据源进行迁移".into(),
        ));
    }
    if volume_enabled != old.volume_enabled {
        return Err(ApiError::BadRequest(
            "分卷模式在数据源创建后不可更改；可调整最大分卷大小和分卷策略".into(),
        ));
    }
    if body.ds_type != old.ds_type {
        return Err(ApiError::BadRequest("数据源类型创建后不可更改".into()));
    }
    if old.encryption_enabled && (password != old.password || old.prev_password.is_some()) {
        // 先持久化过渡密码，迁移中断时读路径仍可用旧密码。
        let previous = if password == old.password {
            old.prev_password.clone().expect("已检查存在过渡密码")
        } else {
            old.password.clone()
        };
        let transitional = DataSource {
            password: password.clone(),
            prev_password: Some(previous.clone()),
            ..old.clone()
        };
        state.registry.update(&id, transitional)?;
        state.cache.evict_datasource(&id);
        let storage = state.adapter(&id)?;
        let old_key = crate::crypto::derive_root_key(previous.as_bytes());
        let new_key = crate::crypto::derive_root_key(password.as_bytes());
        migrate_root_envelopes(storage.as_ref(), &old_key, &new_key)
            .await
            .map_err(|e| {
                ApiError::Upstream(format!(
                    "密码已进入过渡状态，但存储文件名迁移未完成；修复连接后用相同新密码重试: {e}"
                ))
            })?;
        if let Err(error) = state.content_cache.clear_datasource(&id) {
            tracing::warn!("密码修改后清理数据源缓存失败: ds={id} err={error}");
        }
    }
    let ds = DataSource {
        id: id.clone(),
        name: body.name,
        ds_type: body.ds_type,
        config: body.config,
        encryption_enabled,
        password,
        prev_password: None,
        volume_enabled,
        volume_size,
        volume_strategy,
        volume_name_format,
        cache_enabled,
        created_at: old.created_at,
    };
    Ok(Json(state.registry.update(&id, ds)?))
}

/// 修改数据源根密码时，仅需重编码根目录直属信封；子孙密钥不变。
async fn migrate_root_envelopes(
    storage: &dyn crate::adapters::Storage,
    old_key: &[u8; crate::crypto::SECRET_LEN],
    new_key: &[u8; crate::crypto::SECRET_LEN],
) -> ApiResult<usize> {
    use crate::crypto::names::{decode_name, encode_name};
    let entries = storage.list("").await?;
    let mut migrated = 0;
    for entry in entries.iter().filter(|entry| entry.is_dir) {
        let Some(meta) = decode_name(old_key, &entry.name) else {
            continue;
        };
        let new_name = encode_name(new_key, &meta)
            .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {}", meta.name)))?;
        storage.rename(&entry.name, &new_name).await?;
        migrated += 1;
    }
    Ok(migrated)
}

async fn remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    state.registry.remove(&id)?;
    // 只删除连接配置和本地缓存，不删除远端数据。
    state.cache.evict_datasource(&id);
    if let Err(error) = state.content_cache.clear_datasource(&id) {
        tracing::warn!("删除数据源后清理缓存失败: ds={id} err={error}");
    }
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
