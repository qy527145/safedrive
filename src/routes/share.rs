//! 分享 API：子树快照导出 + 分享包导入（嫁接）。
//!
//! v5 信封链下的分享物 = 节点密钥 + 定位信息：
//! - 文件分享包：`{ kind:"file", name, size, secret }`
//! - 目录分享包：`{ kind:"dir",  name, secret }` —— 持 FK 者可解开整棵
//!   子树（含分享后新增的条目）。
//!
//! 导入 = **嫁接（graft）**：接收方先把密文数据放进自己数据源（云盘侧
//! 转存/手动拷贝，内容零重加密），再调 import 在目标目录下用自己的
//! nameKey 编一个新信封（secret 原样），指向该密文数据。
//!
//! 重名策略（on_conflict）：rename（默认，自动加「 (N)」后缀，Finder 式）
//! / skip / error。

use axum::extract::{Path, Query, State};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::adapters::sanitize;
use crate::crypto::SECRET_LEN;
use crate::crypto::names::{NameMeta, decode_name, encode_name};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/files/{ds}/share", post(share_export))
        .route("/files/{ds}/import", post(share_import))
        .route("/files/{ds}/dedupe", post(dedupe))
}

// ---------------- 导出 ----------------

#[derive(Deserialize)]
struct ShareBody {
    /// 要分享的明文路径。
    path: String,
}

#[derive(Serialize, Deserialize)]
struct SharePack {
    sdshare: u32,
    kind: String, // "file" | "dir"
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// base64(节点秘密)：文件 pw / 目录 FK。
    secret: String,
    /// 该节点在导出方云端的密文路径（云盘侧转存时定位用）。
    enc_path: String,
}

/// 导出分享包。**分享包含密钥明文** —— 请通过安全渠道传递。
async fn share_export(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<ShareBody>,
) -> ApiResult<Json<SharePack>> {
    let path = sanitize(&body.path)?;
    if path.is_empty() {
        return Err(ApiError::BadRequest("不能分享数据源根目录".into()));
    }
    let storage = state.adapter(&ds)?;
    let node = super::files::resolve(&state, storage.as_ref(), &ds, &path).await?;
    let meta = decode_name(&node.parent_key, &node.nc)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法解码 {path} 的密文名")))?;
    Ok(Json(SharePack {
        sdshare: 1,
        kind: if node.dir {
            "dir".into()
        } else {
            "file".into()
        },
        name: meta.name,
        size: (!node.dir).then_some(meta.size),
        secret: B64.encode(node.secret),
        enc_path: node.enc_path,
    }))
}

// ---------------- 导入（嫁接） ----------------

#[derive(Deserialize)]
struct ImportQuery {
    /// 冲突策略：rename（默认）/ skip / error。
    #[serde(default)]
    on_conflict: Option<String>,
}

#[derive(Deserialize)]
struct ImportBody {
    /// 分享包。
    pack: SharePack,
    /// 目标明文目录（"" = 根）。
    dir: String,
    /// 密文数据在**本数据源**中的当前位置（云盘转存后的密文文件夹名，
    /// 相对目标目录的存储端路径；即转存落地的那个乱名目录）。
    enc_name: String,
}

/// 把分享的密文数据嫁接进自己的文件树：给它编一个自己父钥的新信封。
/// 前置：接收方已把密文文件夹放到目标目录对应的存储端目录下。
async fn share_import(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<ImportQuery>,
    Json(body): Json<ImportBody>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.pack.sdshare != 1 {
        return Err(ApiError::BadRequest("不支持的分享包版本".into()));
    }
    let is_dir = match body.pack.kind.as_str() {
        "dir" => true,
        "file" => false,
        other => return Err(ApiError::BadRequest(format!("未知分享类型: {other}"))),
    };
    let secret: [u8; SECRET_LEN] = B64
        .decode(&body.pack.secret)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("分享包密钥格式无效".into()))?;
    let enc_name = body.enc_name.trim();
    if enc_name.is_empty() || enc_name.contains('/') {
        return Err(ApiError::BadRequest("enc_name 必须是单段存储名".into()));
    }
    let on_conflict = q.on_conflict.as_deref().unwrap_or("rename");

    let dir = sanitize(&body.dir)?;
    let storage = state.adapter(&ds)?;

    // 嫁接与 mkdir 同锁：判存 + rename 必须互斥
    let lock = state.mkdir_lock(&ds);
    let _guard = lock.lock().await;

    let parent = super::files::resolve(&state, storage.as_ref(), &ds, &dir).await?;
    if !parent.dir {
        return Err(ApiError::BadRequest(format!("{dir} 不是目录")));
    }
    // 密文数据必须已就位
    let src_enc = super::files::join_enc(&parent.enc_path, enc_name);
    storage
        .list(&src_enc)
        .await
        .map_err(|_| ApiError::BadRequest(format!("密文数据未就位: {enc_name}")))?;

    // 重名解决：rename → 「name (N)」；skip → 幂等返回；error → 409 语义
    let entries = storage.list(&parent.enc_path).await?;
    let taken: std::collections::HashSet<String> = entries
        .iter()
        .filter(|e| e.is_dir)
        .filter_map(|e| decode_name(&parent.secret, &e.name).map(|m| m.name))
        .collect();
    let final_name = if !taken.contains(&body.pack.name) {
        body.pack.name.clone()
    } else {
        match on_conflict {
            "skip" => {
                return Ok(Json(
                    json!({ "ok": true, "skipped": true, "name": body.pack.name }),
                ));
            }
            "error" => {
                return Err(ApiError::BadRequest(format!(
                    "已存在同名条目: {}",
                    body.pack.name
                )));
            }
            _ => next_free_name(&body.pack.name, &taken)
                .ok_or_else(|| ApiError::BadRequest("无法生成不冲突的名字".into()))?,
        }
    };

    // 新信封（secret 原样 → 分享者的整棵子树钥匙链保持有效）
    let meta = NameMeta {
        name: final_name.clone(),
        size: body.pack.size.unwrap_or(0),
        is_dir,
        secret,
    };
    let new_nc = encode_name(&parent.secret, &meta)
        .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {final_name}")))?;
    let dst_enc = super::files::join_enc(&parent.enc_path, &new_nc);
    storage.rename(&src_enc, &dst_enc).await?;

    let child_path = if dir.is_empty() {
        final_name.clone()
    } else {
        format!("{dir}/{final_name}")
    };
    state.cache.put(
        &ds,
        &child_path,
        crate::vault::CachedNode {
            secret,
            nc: new_nc,
            dir: is_dir,
        },
    );
    Ok(Json(
        json!({ "ok": true, "name": final_name, "renamed": final_name != body.pack.name }),
    ))
}

/// Finder 式后缀：「报告.pdf」→「报告 (1).pdf」；目录「电影」→「电影 (1)」。
fn next_free_name(name: &str, taken: &std::collections::HashSet<String>) -> Option<String> {
    let (stem, ext) = match name.rsplit_once('.') {
        // 隐藏文件（.gitignore）或无扩展名的按整名处理
        Some((s, e)) if !s.is_empty() => (s, Some(e)),
        _ => (name, None),
    };
    for n in 1..1000u32 {
        let candidate = match ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        if !taken.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
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
