//! 标准 `sd://` 分享协议与云盘原生分享/转存编排。

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::adapters::{CloudShare, sanitize};
use crate::crypto::names::{decode_name, encode_name};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::share_codec::{self as codec, DecodeError};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/files/{ds}/share", post(share_export))
        .route("/files/{ds}/import", post(share_import))
        .route("/files/{ds}/dedupe", post(dedupe))
}

// ---------------- 导出 ----------------

#[derive(Deserialize)]
struct ShareBody {
    paths: Vec<String>,
}

async fn share_export(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<ShareBody>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.paths.is_empty() {
        return Err(ApiError::BadRequest("请至少选择一个文件或文件夹".into()));
    }
    if body.paths.len() > 100 {
        return Err(ApiError::BadRequest("单次最多分享 100 个条目".into()));
    }
    let datasource = state.datasource(&ds)?;
    let storage = state.adapter(&ds)?;
    let mut storage_paths = Vec::with_capacity(body.paths.len());
    let item_count = body.paths.len();
    let mut parent_keys = Vec::new();
    for raw_path in body.paths {
        let path = sanitize(&raw_path)?;
        if path.is_empty() {
            return Err(ApiError::BadRequest("不能分享数据源根目录".into()));
        }
        if datasource.encryption_enabled {
            let node = super::files::resolve(&state, storage.as_ref(), &ds, &path).await?;
            storage_paths.push(node.enc_path);
            if !parent_keys.contains(&node.parent_key) {
                parent_keys.push(node.parent_key);
            }
        } else {
            let (_, actual, _) = super::files::plain_locate(storage.as_ref(), &path).await?;
            storage_paths.push(actual);
        }
    }
    let cloud = storage.share(&storage_paths).await?;
    let share_id = codec::baidu_share_id(&cloud.url)
        .ok_or_else(|| ApiError::Upstream("无法从百度分享短链提取分享 ID".into()))?;
    let pack = codec::Pack {
        source_type: datasource.ds_type,
        share_id,
        password: cloud.password,
        encrypted: datasource.encryption_enabled,
        item_count,
        parent_keys,
    };
    let link =
        codec::encode(&pack).map_err(|message| ApiError::Internal(anyhow::anyhow!(message)))?;
    Ok(Json(json!({ "link": link })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportBody {
    link: String,
    dir: String,
    #[serde(default)]
    force: bool,
}

async fn share_import(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<ImportBody>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.link.len() > 64 * 1024 {
        return Err(ApiError::BadRequest("分享链接过长".into()));
    }
    let pack = codec::decode(&body.link).map_err(|error| match error {
        DecodeError::UnsupportedVersion(version) => {
            ApiError::BadRequest(format!("不支持的分享协议版本: {version}"))
        }
        DecodeError::Invalid => ApiError::BadRequest("分享链接格式无效或已损坏".into()),
    })?;
    let datasource = state.datasource(&ds)?;
    if datasource.ds_type != pack.source_type {
        return Err(ApiError::BadRequest(format!(
            "分享属于 {} 数据源，不能导入到 {} 数据源",
            pack.source_type, datasource.ds_type
        )));
    }
    if datasource.encryption_enabled != pack.encrypted && !body.force {
        return Err(ApiError::BadRequest(
            "加密模式不兼容：分享与当前数据源一个加密、一个未加密；确认强制导入后内容将按外来条目显示".into(),
        ));
    }
    let dir = sanitize(&body.dir)?;
    let storage = state.adapter(&ds)?;
    let parent = if datasource.encryption_enabled {
        Some(super::files::resolve(&state, storage.as_ref(), &ds, &dir).await?)
    } else {
        None
    };
    let dest = parent
        .as_ref()
        .map_or(dir.as_str(), |node| node.enc_path.as_str());
    let cloud = CloudShare {
        url: format!("https://pan.baidu.com/s/1{}", pack.share_id),
        password: pack.password.clone(),
    };
    let transferred = storage.import_share(&cloud, dest).await?;

    // 两端均加密：内容无需重加密，只把每个根信封改用当前目录密钥封装；
    // 这正是一次存储端 rename，节点 secret 与整棵子树密码链保持不变。
    if pack.encrypted && datasource.encryption_enabled {
        let parent = parent.expect("加密数据源必有目标父节点");
        if transferred.len() != pack.item_count {
            return Err(ApiError::Upstream(format!(
                "百度转存返回 {} 个条目，分享包包含 {} 个，无法安全重建加密文件名",
                transferred.len(),
                pack.item_count
            )));
        }
        for entry in &transferred {
            let mut matches = pack
                .parent_keys
                .iter()
                .filter_map(|key| decode_name(key, &entry.source_name));
            let meta = matches.next().ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "分享包无法解密转存条目 {} 的名称",
                    entry.source_name
                ))
            })?;
            if matches.next().is_some() {
                return Err(ApiError::BadRequest(format!(
                    "转存条目 {} 匹配了多个目录密钥",
                    entry.source_name
                )));
            }
            let new_name = encode_name(&parent.secret, &meta)
                .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {}", meta.name)))?;
            storage
                .rename(
                    &super::files::join_enc(&parent.enc_path, &entry.name),
                    &super::files::join_enc(&parent.enc_path, &new_name),
                )
                .await?;
        }
        state.cache.evict_subtree(&ds, &dir);
    }
    Ok(Json(json!({ "ok": true, "imported": transferred.len() })))
}

// ---------------- 同名清理（rclone dedupe 式兜底） ----------------

#[derive(Deserialize)]
struct DedupeBody {
    /// 要扫描的明文目录（"" = 根）。
    path: String,
}

/// 扫描目录，报告解密后同名的条目组（nc 最小者为规范条目，其余为副本）。
/// 只报告不删除 —— 清理走 delete-foreign（它允许删非规范副本）。
async fn dedupe(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<DedupeBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = sanitize(&body.path)?;
    let storage = state.adapter(&ds)?;
    let node = super::files::resolve(&state, storage.as_ref(), &ds, &dir).await?;
    if !node.dir {
        return Err(ApiError::BadRequest(format!("{dir} 不是目录")));
    }
    let entries = storage.list(&node.enc_path).await?;
    let mut groups: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for e in entries.iter().filter(|e| e.is_dir) {
        if let Some(m) = decode_name(&node.secret, &e.name) {
            groups.entry(m.name).or_default().push(e.name.clone());
        }
    }
    let dups: Vec<serde_json::Value> = groups
        .into_iter()
        .filter(|(_, ncs)| ncs.len() > 1)
        .map(|(name, mut ncs)| {
            ncs.sort();
            json!({ "name": name, "canonical": ncs[0], "duplicates": &ncs[1..] })
        })
        .collect();
    Ok(Json(json!({ "groups": dups })))
}
