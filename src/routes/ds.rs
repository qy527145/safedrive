use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::registry::{DataSource, now_ms};
use crate::state::AppState;

use super::bits::DecodeError;
use super::ds_codec;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/ds", get(list).post(create))
        .route("/ds/import", post(import))
        .route("/ds/{id}", put(update).delete(remove))
        .route("/ds/{id}/test", post(test))
        .route("/ds/{id}/share", post(share))
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
            check_root(root, "百度网盘")?;
        }
        "aliyundrive" => {
            let text = config_text(body);
            if text("refreshToken").is_empty() {
                return Err(ApiError::BadRequest(
                    "阿里云盘需要 refresh_token（请先扫码授权）".into(),
                ));
            }
            // 内置第三方应用自带 client_id（密钥在应用作者的中转服务那边）；
            // 认不出的令牌降级为自定义应用，这时才要用户自己填 client_id/secret。
            crate::adapters::aliyun_apps::resolve(
                empty_to_none(text("app")),
                empty_to_none(text("clientId")),
                empty_to_none(text("clientSecret")),
                Some(text("refreshToken")),
                empty_to_none(text("apiBase")),
            )?;
            // 盘位决定用哪个 *_drive_id，写错了会一直查不到盘。
            if !matches!(text("driveType"), "" | "default" | "resource" | "backup") {
                return Err(ApiError::BadRequest(
                    "阿里云盘盘位只能是 default / resource / backup".into(),
                ));
            }
            check_root(text("root"), "阿里云盘")?;
            check_api_base(text("apiBase"), "阿里云盘")?;
        }
        "quark" => {
            let text = config_text(body);
            if text("cookie").is_empty() {
                return Err(ApiError::BadRequest("夸克网盘需要 Cookie".into()));
            }
            check_root(text("root"), "夸克网盘")?;
            check_api_base(text("apiBase"), "夸克网盘")?;
        }
        other => return Err(ApiError::BadRequest(format!("未知数据源类型: {other}"))),
    }
    Ok(())
}

fn config_text<'a>(body: &'a DsBody) -> impl Fn(&str) -> &'a str {
    move |key: &str| {
        body.config
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .unwrap_or("")
    }
}

/// 配置项留空等于「没填」。
fn empty_to_none(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// 网盘根目录是相对网盘根的明文路径片段，别让它爬出授权范围。
fn check_root(root: &str, what: &str) -> ApiResult<()> {
    if root.contains("..") || root.contains('\\') {
        return Err(ApiError::BadRequest(format!("{what}根目录非法")));
    }
    Ok(())
}

/// 自定义接口地址留空即用默认值，填了就必须是 http(s)。
fn check_api_base(base: &str, what: &str) -> ApiResult<()> {
    let ok = base.is_empty() || base.starts_with("http://") || base.starts_with("https://");
    if !ok {
        return Err(ApiError::BadRequest(format!("{what}接口地址必须是 http(s)")));
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

/// 生成 `sdds://` 配置分享链接。链接包含凭证与根密码，属于不记名密钥，
/// 服务端不落盘、不记录，只回给当前已鉴权的管理端。
async fn share(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let ds = state
        .registry
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
    let pack = ds_codec::DsPack {
        ds_type: ds.ds_type,
        name: ds.name,
        config: ds.config,
        encryption_enabled: ds.encryption_enabled,
        password: ds.password,
        volume_enabled: ds.volume_enabled,
        volume_size: ds.volume_size,
        volume_strategy: ds.volume_strategy,
        volume_name_format: ds.volume_name_format,
        cache_enabled: ds.cache_enabled,
    };
    let link =
        ds_codec::encode(&pack).map_err(|message| ApiError::Internal(anyhow::anyhow!(message)))?;
    Ok(Json(json!({ "link": link })))
}

#[derive(Deserialize)]
struct DsImportBody {
    link: String,
}

/// 通过 `sdds://` 链接导入数据源：走与手工创建完全相同的校验路径，
/// 名称冲突时自动追加序号。
async fn import(
    State(state): State<AppState>,
    Json(body): Json<DsImportBody>,
) -> ApiResult<Json<DataSource>> {
    if body.link.len() > 64 * 1024 {
        return Err(ApiError::BadRequest("分享链接过长".into()));
    }
    let pack = ds_codec::decode(&body.link).map_err(|error| match error {
        DecodeError::UnsupportedVersion(version) => {
            ApiError::BadRequest(format!("不支持的数据源分享协议版本: {version}"))
        }
        DecodeError::Invalid => ApiError::BadRequest("数据源分享链接格式无效或已损坏".into()),
    })?;
    let body = DsBody {
        name: unique_name(&state, &pack.name),
        ds_type: pack.ds_type,
        config: pack.config,
        encryption_enabled: Some(pack.encryption_enabled),
        password: pack.encryption_enabled.then_some(pack.password),
        volume_enabled: Some(pack.volume_enabled),
        volume_size: Some(pack.volume_size),
        volume_strategy: Some(pack.volume_strategy),
        volume_name_format: Some(pack.volume_name_format),
        cache_enabled: Some(pack.cache_enabled),
    };
    create(State(state), Json(body)).await
}

/// WebDAV 数据平面按名称寻址数据源，导入时避开重名。
fn unique_name(state: &AppState, wanted: &str) -> String {
    let taken: Vec<String> = state.registry.list().into_iter().map(|d| d.name).collect();
    if !taken.iter().any(|name| name == wanted) {
        return wanted.to_owned();
    }
    (2..)
        .map(|n| format!("{wanted} ({n})"))
        .find(|candidate| !taken.iter().any(|name| name == candidate))
        .expect("总能找到未占用的名称")
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn setup() -> (crate::state::AppState, axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::state::AppState::new(dir.path().join("data"), None).unwrap();
        (state.clone(), crate::routes::router(state), dir)
    }

    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        let body = match body {
            Some(json) => {
                builder = builder.header("content-type", "application/json");
                axum::body::Body::from(json.to_string())
            }
            None => axum::body::Body::empty(),
        };
        let resp = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (parts.status, json)
    }

    /// 分享 → 导入闭环：导入结果与原数据源配置一致，重名自动加序号。
    #[tokio::test]
    async fn share_link_roundtrip_and_unique_name() {
        let (_state, app, dir) = setup();
        let root = dir.path().join("cloud");
        let body = serde_json::json!({
            "name": "我的空间", "type": "localfs",
            "config": { "root": root.to_str().unwrap() },
            "encryptionEnabled": true, "password": "root-pw-123",
            "volumeEnabled": true, "volumeSize": 128 * 1024,
            "volumeStrategy": "fixed", "cacheEnabled": false,
        });
        let (status, created) = send(&app, "POST", "/api/ds", Some(body)).await;
        assert_eq!(status, 200, "{created}");
        let id = created["id"].as_str().unwrap();

        let (status, shared) = send(&app, "POST", &format!("/api/ds/{id}/share"), None).await;
        assert_eq!(status, 200, "{shared}");
        let link = shared["link"].as_str().unwrap();
        assert!(link.starts_with("sdds://"));
        assert!(!link.contains("root-pw-123"));

        let import = serde_json::json!({ "link": link });
        let (status, imported) = send(&app, "POST", "/api/ds/import", Some(import.clone())).await;
        assert_eq!(status, 200, "{imported}");
        assert_eq!(imported["name"], "我的空间 (2)");
        assert_ne!(imported["id"], created["id"]);
        for key in ["type", "config", "encryptionEnabled", "password",
                    "volumeEnabled", "volumeSize", "volumeStrategy", "cacheEnabled"] {
            assert_eq!(imported[key], created[key], "field {key}");
        }

        // 再导入一次：继续顺延序号
        let (_, third) = send(&app, "POST", "/api/ds/import", Some(import)).await;
        assert_eq!(third["name"], "我的空间 (3)");
    }

    /// 两个新驱动的配置校验：缺凭证、盘位写错、根目录越界、接口地址非法都要拦下；
    /// 填全了能落库（创建过程不连网，只校验 + 写注册表）。
    #[tokio::test]
    async fn new_driver_configs_are_validated() {
        let (_state, app, _dir) = setup();
        let body = |ds_type: &str, config: serde_json::Value| {
            serde_json::json!({
                "name": "新盘", "type": ds_type, "config": config,
                "encryptionEnabled": false, "volumeEnabled": false, "cacheEnabled": false,
            })
        };
        // 基准配置 + 逐项改坏，确保拦的是被改的那一项。
        let patched = |base: serde_json::Value, patch: serde_json::Value| {
            let mut config = base;
            for (key, value) in patch.as_object().expect("patch 是对象") {
                config[key.as_str()] = value.clone();
            }
            config
        };
        let aliyun_base = serde_json::json!({
            "root": "/safedrive", "clientId": "cid", "clientSecret": "csec",
            "refreshToken": "rt", "driveType": "resource", "apiBase": "",
        });
        let quark_base =
            serde_json::json!({ "root": "safedrive", "cookie": "__pus=a; __puus=b", "apiBase": "" });

        for (ds_type, base, patch, expect) in [
            ("aliyundrive", &aliyun_base, serde_json::json!({ "clientId": "  " }), "client_id"),
            ("aliyundrive", &aliyun_base, serde_json::json!({ "clientSecret": "" }), "client_secret"),
            ("aliyundrive", &aliyun_base, serde_json::json!({ "refreshToken": "" }), "refresh_token"),
            ("aliyundrive", &aliyun_base, serde_json::json!({ "driveType": "vault" }), "盘位"),
            ("aliyundrive", &aliyun_base, serde_json::json!({ "root": "../别人的盘" }), "根目录非法"),
            ("aliyundrive", &aliyun_base, serde_json::json!({ "apiBase": "ftp://x" }), "http(s)"),
            ("quark", &quark_base, serde_json::json!({ "cookie": " " }), "Cookie"),
            ("quark", &quark_base, serde_json::json!({ "root": "a\\b" }), "根目录非法"),
            ("quark", &quark_base, serde_json::json!({ "apiBase": "drive.quark.cn" }), "http(s)"),
        ] {
            let config = patched(base.clone(), patch.clone());
            let (status, resp) = send(&app, "POST", "/api/ds", Some(body(ds_type, config))).await;
            assert_eq!(status, 400, "{ds_type} {patch} 应被拒绝: {resp}");
            let message = resp["error"].as_str().unwrap_or_default();
            assert!(message.contains(expect), "{ds_type} {patch} → {message}");
        }

        // 盘位留空 = 默认盘；夸克根目录可为空（即网盘根）。
        for (ds_type, config) in [
            ("aliyundrive", patched(aliyun_base.clone(), serde_json::json!({ "driveType": "" }))),
            ("aliyundrive", aliyun_base.clone()),
            ("quark", patched(quark_base.clone(), serde_json::json!({ "root": "" }))),
            ("quark", quark_base.clone()),
        ] {
            let (status, created) = send(&app, "POST", "/api/ds", Some(body(ds_type, config))).await;
            assert_eq!(status, 200, "{ds_type} {created}");
            assert_eq!(created["type"], ds_type);
        }
    }

    #[tokio::test]
    async fn import_rejects_garbage_links() {
        let (_state, app, _dir) = setup();
        for link in ["", "sd://abcdef", "sdds://!!!", "sdds://AAAA"] {
            let body = serde_json::json!({ "link": link });
            let (status, _) = send(&app, "POST", "/api/ds/import", Some(body)).await;
            assert_eq!(status, 400, "link {link:?} should be rejected");
        }
    }
}
