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
        .route("/ds/{id}/drive", post(set_drive))
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
    #[serde(default, alias = "volumeNameFormat")]
    leaf_name_format: Option<String>,
    #[serde(default)]
    disguise_enabled: Option<bool>,
    #[serde(default)]
    disguise_algorithm: Option<String>,
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
            if !has_bduss {
                return Err(ApiError::BadRequest("百度网盘需要 BDUSS".into()));
            }
            let text = config_text(body);
            // 内置的 ES 文件管理器（默认）或用户自备应用；自定义应用要求
            // API Key 与 Secret Key 成对填写。
            crate::adapters::baidu_apps::resolve(
                empty_to_none(text("app")),
                empty_to_none(text("clientId")),
                empty_to_none(text("clientSecret")),
            )?;
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
        return Err(ApiError::BadRequest(format!(
            "{what}接口地址必须是 http(s)"
        )));
    }
    Ok(())
}

/// 数据源里与连接无关的那部分配置（加密 / 分卷 / 伪装 / 缓存）。
/// 字段名与 `DataSource` 一致，便于直接展开。
struct Options {
    encryption_enabled: bool,
    password: String,
    volume_enabled: bool,
    volume_size: u64,
    volume_strategy: String,
    leaf_name_format: String,
    disguise_enabled: bool,
    disguise_algorithm: String,
    cache_enabled: bool,
}

fn mapping_config(body: &DsBody, old: Option<&DataSource>) -> ApiResult<Options> {
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
    let disguise_enabled = body
        .disguise_enabled
        .or_else(|| old.map(|d| d.disguise_enabled))
        .unwrap_or(false);
    let disguise_algorithm = body
        .disguise_algorithm
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .or_else(|| old.map(|d| d.disguise_algorithm.clone()))
        .unwrap_or_else(|| crate::disguise::DEFAULT_ALGORITHM.into());
    let cache = body
        .cache_enabled
        .or_else(|| old.map(|d| d.cache_enabled))
        .unwrap_or(true);
    if disguise_enabled && crate::disguise::Disguise::from_algorithm(&disguise_algorithm).is_none()
    {
        return Err(ApiError::BadRequest(format!(
            "不支持的伪装算法: {disguise_algorithm}（目前支持 {}）",
            crate::disguise::ALGORITHMS.join(" / ")
        )));
    }
    let disguise = if disguise_enabled {
        crate::disguise::Disguise::from_algorithm(&disguise_algorithm).unwrap_or_default()
    } else {
        crate::disguise::Disguise::None
    };

    // 加密 / 分卷 / 伪装任一开启即「受管」：文件落进一个信封目录，目录名由根
    // 密码派生的密钥链加密 —— 所以三者都吃根密码。
    let managed = encrypted || volume_enabled || disguise_enabled;
    if managed && password.is_empty() {
        return Err(ApiError::BadRequest(
            "启用加密、分卷或伪装时根密码不能为空".into(),
        ));
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
    }

    // 叶子名模版：只有受管数据源有叶子可命名，非受管的归一到默认值。
    let default_format = crate::naming::default_format(encrypted, volume_enabled, disguise);
    let leaf_name_format = if managed {
        let format = body
            .leaf_name_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| old.map(|d| d.leaf_name_format.clone()))
            .unwrap_or(default_format);
        crate::naming::validate_format(&format, encrypted, volume_enabled)
            .map_err(ApiError::BadRequest)?;
        format
    } else {
        // 非受管数据源没有信封、也没有叶子可命名。显式塞了模版说明调用方
        // 搞错了对象，明说比悄悄丢掉好（前端在这种组合下不会显示该输入）。
        if body
            .leaf_name_format
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(ApiError::BadRequest(
                "未启用加密、分卷或伪装时没有叶子对象可命名，不能设置叶子文件名模版".into(),
            ));
        }
        default_format
    };

    Ok(Options {
        encryption_enabled: encrypted,
        password: if managed { password } else { String::new() },
        volume_enabled,
        volume_size,
        volume_strategy: strategy,
        leaf_name_format,
        disguise_enabled,
        disguise_algorithm,
        cache_enabled: cache,
    })
}

async fn list(State(state): State<AppState>) -> Json<Vec<DataSource>> {
    Json(state.registry.list())
}

async fn create(
    State(state): State<AppState>,
    Json(body): Json<DsBody>,
) -> ApiResult<Json<DataSource>> {
    validate(&body)?;
    let Options {
        encryption_enabled,
        password,
        volume_enabled,
        volume_size,
        volume_strategy,
        leaf_name_format,
        disguise_enabled,
        disguise_algorithm,
        cache_enabled,
    } = mapping_config(&body, None)?;
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
        leaf_name_format,
        disguise_enabled,
        disguise_algorithm,
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
    let Options {
        encryption_enabled,
        password,
        volume_enabled,
        volume_size,
        volume_strategy,
        leaf_name_format,
        disguise_enabled,
        disguise_algorithm,
        cache_enabled,
    } = mapping_config(&body, Some(&old))?;
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
    // 伪装改变落地字节（头部长度、头部内容都跟着算法走），翻转或换算法都会
    // 让已经写下去的对象读不回来。
    if disguise_enabled != old.disguise_enabled {
        return Err(ApiError::BadRequest(
            "伪装模式在数据源创建后不可更改；请新建数据源进行迁移".into(),
        ));
    }
    if disguise_enabled && disguise_algorithm != old.disguise_algorithm {
        return Err(ApiError::BadRequest(
            "伪装算法在数据源创建后不可更改；请新建数据源进行迁移".into(),
        ));
    }
    // 读取靠按模版生成候选名再查表，改了模版已经写下去的叶子就再也认不出来。
    if leaf_name_format != old.leaf_name_format {
        return Err(ApiError::BadRequest(
            "叶子文件名模版在数据源创建后不可更改；请新建数据源进行迁移".into(),
        ));
    }
    if body.ds_type != old.ds_type {
        return Err(ApiError::BadRequest("数据源类型创建后不可更改".into()));
    }
    if old.managed() && (password != old.password || old.prev_password.is_some()) {
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
        leaf_name_format,
        disguise_enabled,
        disguise_algorithm,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveBody {
    drive_type: String,
}

/// 切换阿里云盘盘位（资源库 / 备份盘）。写入新盘位并丢弃缓存的 driveId 与
/// 路径缓存，随后 `mkdir("")` 在新盘里按需建出配置的根目录。
async fn set_drive(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<DriveBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let drive_type = body.drive_type.trim();
    if !matches!(drive_type, "resource" | "backup") {
        return Err(ApiError::BadRequest(
            "阿里云盘盘位只能是资源库（resource）或备份盘（backup）".into(),
        ));
    }
    state.registry.set_drive_type(&id, drive_type)?;
    // 同一明文路径在两个盘里对应不同的云端目录，切盘后必须清掉路径与内容缓存。
    state.cache.evict_datasource(&id);
    if let Err(error) = state.content_cache.clear_datasource(&id) {
        tracing::warn!("切换盘位后清理数据源缓存失败: ds={id} err={error}");
    }
    // 配置里设了根目录时，在新盘里按需建出来（root 为空即网盘根，什么都不建）。
    state.adapter(&id)?.mkdir("").await?;
    Ok(Json(json!({ "ok": true, "driveType": drive_type })))
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
        leaf_name_format: ds.leaf_name_format,
        disguise_enabled: ds.disguise_enabled,
        disguise_algorithm: ds.disguise_algorithm,
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
        password: (pack.encryption_enabled || pack.disguise_enabled).then_some(pack.password),
        volume_enabled: Some(pack.volume_enabled),
        volume_size: Some(pack.volume_size),
        volume_strategy: Some(pack.volume_strategy),
        leaf_name_format: Some(pack.leaf_name_format),
        disguise_enabled: Some(pack.disguise_enabled),
        disguise_algorithm: Some(pack.disguise_algorithm),
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
        let resp = app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
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
        for key in [
            "type",
            "config",
            "encryptionEnabled",
            "password",
            "volumeEnabled",
            "volumeSize",
            "volumeStrategy",
            "cacheEnabled",
        ] {
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
        let quark_base = serde_json::json!({ "root": "safedrive", "cookie": "__pus=a; __puus=b", "apiBase": "" });

        for (ds_type, base, patch, expect) in [
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "clientId": "  " }),
                "client_id",
            ),
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "clientSecret": "" }),
                "client_secret",
            ),
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "refreshToken": "" }),
                "refresh_token",
            ),
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "driveType": "vault" }),
                "盘位",
            ),
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "root": "../别人的盘" }),
                "根目录非法",
            ),
            (
                "aliyundrive",
                &aliyun_base,
                serde_json::json!({ "apiBase": "ftp://x" }),
                "http(s)",
            ),
            (
                "quark",
                &quark_base,
                serde_json::json!({ "cookie": " " }),
                "Cookie",
            ),
            (
                "quark",
                &quark_base,
                serde_json::json!({ "root": "a\\b" }),
                "根目录非法",
            ),
            (
                "quark",
                &quark_base,
                serde_json::json!({ "apiBase": "drive.quark.cn" }),
                "http(s)",
            ),
        ] {
            let config = patched(base.clone(), patch.clone());
            let (status, resp) = send(&app, "POST", "/api/ds", Some(body(ds_type, config))).await;
            assert_eq!(status, 400, "{ds_type} {patch} 应被拒绝: {resp}");
            let message = resp["error"].as_str().unwrap_or_default();
            assert!(message.contains(expect), "{ds_type} {patch} → {message}");
        }

        // 盘位留空 = 默认盘；夸克根目录可为空（即网盘根）。
        for (ds_type, config) in [
            (
                "aliyundrive",
                patched(aliyun_base.clone(), serde_json::json!({ "driveType": "" })),
            ),
            ("aliyundrive", aliyun_base.clone()),
            (
                "quark",
                patched(quark_base.clone(), serde_json::json!({ "root": "" })),
            ),
            ("quark", quark_base.clone()),
        ] {
            let (status, created) =
                send(&app, "POST", "/api/ds", Some(body(ds_type, config))).await;
            assert_eq!(status, 200, "{ds_type} {created}");
            assert_eq!(created["type"], ds_type);
        }
    }

    /// 伪装也吃根密码：信封名由它派生，没有它就无从判断一个存储对象到底是不是
    /// SafeDrive 写的。未提供时服务端自动生成一个，并如实回给管理端。
    #[tokio::test]
    async fn disguise_gets_a_root_password_even_without_encryption() {
        let (_state, app, dir) = setup();
        let root = dir.path().join("cloud");
        let (status, created) = send(
            &app,
            "POST",
            "/api/ds",
            Some(serde_json::json!({
                "name": "只伪装", "type": "localfs",
                "config": { "root": root.to_str().unwrap() },
                "encryptionEnabled": false, "volumeEnabled": false, "cacheEnabled": false,
                "disguiseEnabled": true,
            })),
        )
        .await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["encryptionEnabled"], false);
        assert_eq!(created["disguiseEnabled"], true);
        assert_eq!(created["disguiseAlgorithm"], "bmp");
        assert!(
            !created["password"].as_str().unwrap_or_default().is_empty(),
            "受管数据源必须有根密码: {created}"
        );

        // 既不加密也不伪装 → 不需要根密码，保持空串。
        let plain = dir.path().join("plain");
        let (status, created) = send(
            &app,
            "POST",
            "/api/ds",
            Some(serde_json::json!({
                "name": "纯明文", "type": "localfs",
                "config": { "root": plain.to_str().unwrap() },
                "encryptionEnabled": false, "volumeEnabled": false, "cacheEnabled": false,
                "disguiseEnabled": false,
            })),
        )
        .await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["password"], "");
    }

    /// 统一命名策略的六条规则，逐条钉在接口层。
    #[tokio::test]
    async fn leaf_name_template_rules_are_enforced() {
        let (_state, app, dir) = setup();
        let create = |name: &str, enc: bool, vol: bool, dis: bool, format: Option<&str>| {
            let root = dir.path().join(name);
            let mut body = serde_json::json!({
                "name": name, "type": "localfs",
                "config": { "root": root.to_str().unwrap() },
                "encryptionEnabled": enc, "volumeEnabled": vol, "disguiseEnabled": dis,
                "cacheEnabled": false,
            });
            if let Some(format) = format {
                body["leafNameFormat"] = format.into();
            }
            body
        };

        // 规则 1 + 3 + 5：受管数据源自动拿到根密码，模版按开关取默认值，
        // 开了 BMP 伪装则在默认模版尾部加 .bmp。
        for (label, enc, vol, dis, want) in [
            ("加密", true, false, false, "{e}"),
            ("加密分卷", true, true, false, "{e}"),
            ("分卷", false, true, false, "{s}.{i}"),
            ("伪装", false, false, true, "{s}.bmp"),
            ("分卷伪装", false, true, true, "{s}.{i}.bmp"),
            ("加密分卷伪装", true, true, true, "{e}.bmp"),
        ] {
            let (status, created) = send(
                &app,
                "POST",
                "/api/ds",
                Some(create(label, enc, vol, dis, None)),
            )
            .await;
            assert_eq!(status, 200, "{label}: {created}");
            assert_eq!(created["leafNameFormat"], want, "{label} 的默认模版");
            assert!(
                !created["password"].as_str().unwrap_or_default().is_empty(),
                "{label}: 受管数据源必须有根密码"
            );
        }

        // 三个开关全关 → 非受管：没有信封、没有叶子、不需要根密码。
        let (status, created) = send(
            &app,
            "POST",
            "/api/ds",
            Some(create("裸文件", false, false, false, None)),
        )
        .await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["password"], "");

        // 规则 2 + 3 + 4：占位符的可用性与必填性。
        for (label, enc, vol, format, expect) in [
            ("加密缺 {e}", true, true, "{s}_{i}.bin", "必须包含 {e}"),
            ("未加密用 {e}", false, true, "{e}_{i}", "只在启用加密时可用"),
            ("未加密分卷缺 {i}", false, true, "{s}.bin", "必须包含 {i}"),
            (
                "加密未分卷用 {i}",
                true,
                false,
                "{e}_{i}",
                "只在启用分卷时可用",
            ),
            ("未知占位符", true, true, "{q}{e}", "无法识别"),
            ("越界路径", true, true, "../{e}", "非法路径"),
        ] {
            let (status, resp) = send(
                &app,
                "POST",
                "/api/ds",
                Some(create(label, enc, vol, false, Some(format))),
            )
            .await;
            assert_eq!(status, 400, "{label} 应被拒绝: {resp}");
            let message = resp["error"].as_str().unwrap_or_default();
            assert!(message.contains(expect), "{label} → {message}");
        }

        // 非受管数据源没有叶子可命名：显式给模版直接报错，而不是悄悄丢掉。
        let (status, resp) = send(
            &app,
            "POST",
            "/api/ds",
            Some(create("裸文件带模版", false, false, false, Some("{s}.dat"))),
        )
        .await;
        assert_eq!(status, 400, "{resp}");
        assert!(
            resp["error"]
                .as_str()
                .unwrap_or_default()
                .contains("没有叶子对象可命名"),
            "{resp}"
        );

        // {s} 任何时候都可用；加密时 {i} 可省也可带。
        for (label, enc, vol, format) in [
            ("加密带 {s}", true, true, "{s}-{e}"),
            ("加密带 {i}", true, true, "{e}_{i}.dat"),
            ("未加密分卷", false, true, "{s}-第{i}卷.dat"),
        ] {
            let (status, created) = send(
                &app,
                "POST",
                "/api/ds",
                Some(create(label, enc, vol, false, Some(format))),
            )
            .await;
            assert_eq!(status, 200, "{label}: {created}");
            assert_eq!(created["leafNameFormat"], format);
        }

        // 模版创建后不可更改（读取靠按模版生成候选名再查表）。
        let (_, created) = send(
            &app,
            "POST",
            "/api/ds",
            Some(create("锁定", true, true, false, Some("{e}"))),
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let mut update = create("锁定", true, true, false, Some("{e}_{i}"));
        update["password"] = created["password"].clone();
        let (status, resp) = send(&app, "PUT", &format!("/api/ds/{id}"), Some(update)).await;
        assert_eq!(status, 400, "{resp}");
        assert!(
            resp["error"]
                .as_str()
                .unwrap_or_default()
                .contains("模版在数据源创建后不可更改"),
            "{resp}"
        );
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
