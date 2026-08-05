//! 标准 `sd://` 分享协议与云盘原生分享/转存编排。

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::adapters::{CloudShare, sanitize};
use crate::crypto::names::{decode_name, encode_name};
use crate::error::{ApiError, ApiResult};
use crate::routes::files::Located;
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
#[serde(rename_all = "camelCase")]
struct ShareBody {
    paths: Vec<String>,
    /// true = 云盘官网原生分享（链接 + 提取码，任何人可用官方 App 打开）；
    /// 默认 false = SafeDrive 标准 `sd://` 分享（含解密信息，接收方需 SafeDrive）。
    #[serde(default)]
    native: bool,
    /// 官网原生分享的自定义提取码（留空 = 随机生成）。仅对原生分享生效：
    /// `sd://` 分享的密码受协议字母表约束，只能由服务端生成。
    #[serde(default)]
    password: String,
}

/// 校验用户自定义的官网提取码：正好 4 位 ASCII 字母或数字（百度、阿里官网
/// 提取码的通用形态）。留空由调用方决定回退到随机。
fn validate_native_password(raw: &str) -> ApiResult<String> {
    let password = raw.trim();
    if password.chars().count() != 4 || !password.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ApiError::BadRequest(
            "自定义提取码必须是 4 位字母或数字".into(),
        ));
    }
    Ok(password.to_owned())
}

/// 把提取码内嵌进云盘官网短链，凑成一条可直接打开的组合链接（如
/// `https://pan.baidu.com/s/1xxxx?pwd=8xbq`）。夸克用 `passcode`，其余用 `pwd`；
/// 密码为空或链接里已带则原样返回。
fn combine_native_url(ds_type: &str, url: &str, password: &str) -> String {
    if password.is_empty() || url.contains("pwd=") || url.contains("passcode=") {
        return url.to_owned();
    }
    let param = if ds_type == "quark" {
        "passcode"
    } else {
        "pwd"
    };
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{param}={password}")
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
    let mut any_managed = false;
    let mut any_foreign = false;
    for raw_path in &body.paths {
        let path = sanitize(raw_path)?;
        if path.is_empty() {
            return Err(ApiError::BadRequest("不能分享数据源根目录".into()));
        }
        if datasource.encryption_enabled {
            // 受管条目走信封（只能 sd://）；外来（明文）条目按字面存储路径原样
            // 分享（只能原生）—— 二者语义与落地格式都不同。
            match super::files::locate_any(&state, storage.as_ref(), &ds, &path).await? {
                Located::Managed(node) => {
                    any_managed = true;
                    if !parent_keys.contains(&node.parent_key) {
                        parent_keys.push(node.parent_key);
                    }
                    storage_paths.push(node.enc_path);
                }
                Located::Foreign { enc_path, .. } => {
                    any_foreign = true;
                    storage_paths.push(enc_path);
                }
            }
        } else {
            let (_, actual, _) = super::files::plain_locate(storage.as_ref(), &path).await?;
            storage_paths.push(actual);
        }
    }
    // 受管密文与外来明文不能混在一次分享里：一个只能 sd://、一个只能原生。
    if any_managed && any_foreign {
        return Err(ApiError::BadRequest(
            "不能把受管加密条目与外来明文条目放在同一次分享，请分开分享".into(),
        ));
    }
    // 全外来（明文）→ 强制原生：sd:// 封装的是解密信息，对明文对象无意义。
    let native = body.native || (any_foreign && !any_managed);
    // 原生分享的是云端「原样对象」：受管加密条目在云端是乱码密文，官网分享对
    // 接收方毫无意义 —— 只有明文（未加密数据源，或加密数据源里的外来条目）可原生。
    if native && any_managed {
        return Err(ApiError::BadRequest(
            "加密数据源的受管条目在云端是密文，官网原生分享对接收方没有意义；请改用 sd:// 标准分享"
                .into(),
        ));
    }
    // 自定义提取码只在原生分享时有意义（sd:// 密码受协议字母表约束，由服务端生成）。
    let custom_password = if native && !body.password.trim().is_empty() {
        Some(validate_native_password(&body.password)?)
    } else {
        None
    };
    let cloud = storage
        .share(&storage_paths, custom_password.as_deref())
        .await?;

    // 原生分享：把提取码内嵌进官网短链，交给用户一条可直接打开的组合链接。
    if native {
        let url = combine_native_url(&datasource.ds_type, &cloud.url, &cloud.password);
        return Ok(Json(json!({
            "native": true,
            "url": url,
            "password": cloud.password,
        })));
    }

    let share_id = codec::share_id(&datasource.ds_type, &cloud.url)
        .ok_or_else(|| ApiError::Upstream(format!("无法从分享短链提取分享 ID: {}", cloud.url)))?;
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
    Ok(Json(json!({ "native": false, "link": link })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportBody {
    link: String,
    dir: String,
    #[serde(default)]
    force: bool,
    /// 云盘原生分享的提取码。`sd://` 链接自带密码，此项可留空。
    #[serde(default)]
    password: String,
}

async fn share_import(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<ImportBody>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.link.len() > 64 * 1024 {
        return Err(ApiError::BadRequest("分享链接过长".into()));
    }
    let link = body.link.trim();
    let datasource = state.datasource(&ds)?;
    let dir = sanitize(&body.dir)?;
    let storage = state.adapter(&ds)?;

    // 不是 sd:// 就当云盘官网原生分享处理：按链接自动识别数据源类型，转存进来。
    // 分享的是别人的明文文件；落进加密数据源解不开信封，会按「外来条目」呈现，
    // 但照常可以预览/下载/复制。
    if !link.starts_with("sd://") {
        let source_type = codec::native_source(link).ok_or_else(|| {
            ApiError::BadRequest(
                "无法识别的分享链接：既不是 sd:// 标准分享，也不是支持的网盘官网分享短链".into(),
            )
        })?;
        if datasource.ds_type != source_type {
            return Err(ApiError::BadRequest(format!(
                "分享属于 {source_type} 数据源，不能导入到 {} 数据源",
                datasource.ds_type
            )));
        }
        let dest = if datasource.encryption_enabled {
            super::files::resolve(&state, storage.as_ref(), &ds, &dir)
                .await?
                .enc_path
        } else {
            dir.clone()
        };
        // 提取码优先用用户手填的；留空则回退到链接里内嵌的 `?pwd=`。
        let password = if body.password.trim().is_empty() {
            codec::native_password(link).unwrap_or_default()
        } else {
            body.password.trim().to_owned()
        };
        let cloud = CloudShare {
            url: link.to_owned(),
            password: password.clone(),
        };
        // 没提供任何密码就转存失败 → 多半是需要提取码。不当作错误，让前端弹框
        // 补填后重试（免密分享则此次已直接成功）。提供了密码仍失败才如实报错。
        let transferred = match storage.import_share(&cloud, &dest).await {
            Ok(transferred) => transferred,
            Err(_) if password.is_empty() => {
                return Ok(Json(json!({ "ok": false, "needPassword": true })));
            }
            Err(e) => return Err(e),
        };
        if datasource.encryption_enabled {
            state.cache.evict_subtree(&ds, &dir);
        }
        return Ok(Json(json!({
            "ok": true,
            "imported": transferred.len(),
            // 明文内容进了加密数据源 → 以外来条目呈现（前端据此提示）。
            "foreign": datasource.encryption_enabled,
        })));
    }

    let pack = codec::decode(link).map_err(|error| match error {
        DecodeError::UnsupportedVersion(version) => {
            ApiError::BadRequest(format!("不支持的分享协议版本: {version}"))
        }
        DecodeError::Invalid => ApiError::BadRequest("分享链接格式无效或已损坏".into()),
    })?;
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
    let parent = if datasource.encryption_enabled {
        Some(super::files::resolve(&state, storage.as_ref(), &ds, &dir).await?)
    } else {
        None
    };
    let dest = parent
        .as_ref()
        .map_or(dir.as_str(), |node| node.enc_path.as_str());
    let cloud = CloudShare {
        url: codec::share_url(&pack.source_type, &pack.share_id).ok_or_else(|| {
            ApiError::BadRequest(format!("{} 数据源不支持转存分享", pack.source_type))
        })?,
        password: pack.password.clone(),
    };
    let transferred = storage.import_share(&cloud, dest).await?;

    // 两端均加密：内容无需重加密，只把每个根信封改用当前目录密钥封装；
    // 这正是一次存储端 rename，节点 secret 与整棵子树密码链保持不变。
    if pack.encrypted && datasource.encryption_enabled {
        let parent = parent.expect("加密数据源必有目标父节点");
        if transferred.len() != pack.item_count {
            return Err(ApiError::Upstream(format!(
                "转存返回 {} 个条目，分享包包含 {} 个，无法安全重建加密文件名",
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
