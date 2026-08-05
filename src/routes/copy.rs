//! 跨数据源复制。
//!
//! 关键洞见：SafeDrive 的内容加密只由**文件密钥 pw** 与**合并坐标系里的
//! 字节偏移**决定，分卷边界对密文毫无影响。所以只要复制时把 pw 原样带到
//! 目标数据源（只用目标父目录的 FK 重编外层信封名），源与目标的每个分卷
//! 就是**逐字节相同**的对象 —— 复制退化成纯存储层的对象搬运，一次加解密
//! 都不用做，也就能直接吃到网盘的秒传。
//!
//! 两条硬约束：
//!   1. 分卷切分跟随源。改了边界，卷内容就变了，摘要对不上，秒传必然落空。
//!   2. 源与目标的「是否加密」必须一致才能走原样搬运；一边加密一边明文时
//!      内容天然不同，只能降级为解密 → 重加密的完整传输。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, header};
use axum::routing::post;
use axum::{Json, Router};
use futures_util::{StreamExt, TryStreamExt};
use serde::Deserialize;
use serde_json::json;

use crate::adapters::{ContentHashes, RapidSource, Storage, hash_stream, sanitize};
use crate::crypto::names::{NameMeta, decode_name, encode_name};
use crate::engine;
use crate::error::{ApiError, ApiResult};
use crate::routes::files::{
    Located, PLAIN_VOLUME_SUFFIX, ensure_dir, ensure_plain_dir, join_enc, list_dir, locate_any,
    mkdir_path, parent_and_name, plain_locate, resolve, resolve_root, stat_path, upload_file,
    volume_names,
};
use crate::state::AppState;
use crate::vault::CachedNode;

pub fn routes() -> Router<AppState> {
    Router::new().route("/files/{ds}/copy", post(copy))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CopyBody {
    /// 源明文路径（文件或目录）。
    path: String,
    /// 目标数据源；缺省即源数据源。
    #[serde(default)]
    dest_ds: Option<String>,
    /// 目标明文全路径（含新名字）。
    dest_path: String,
    #[serde(default)]
    overwrite: bool,
    /// 进度 ID，与上传共用 GET /api/uploads/{id}/progress。
    #[serde(default)]
    progress: Option<String>,
}

async fn copy(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<CopyBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let src_path = sanitize(&body.path)?;
    let dest_path = sanitize(&body.dest_path)?;
    let dest_ds = body.dest_ds.unwrap_or_else(|| ds.clone());
    // 提前校验两端都存在，别等递归到一半才报错。
    state.datasource(&ds)?;
    state.datasource(&dest_ds)?;
    let report = copy_path(
        &state,
        &ds,
        &src_path,
        &dest_ds,
        &dest_path,
        body.overwrite,
        body.progress.as_deref(),
    )
    .await?;
    let mut value = serde_json::to_value(&report).map_err(|e| anyhow::anyhow!(e))?;
    value
        .as_object_mut()
        .expect("CopyReport 序列化成对象")
        .insert("mode".into(), json!(report.mode()));
    Ok(Json(json!({ "ok": true, "report": value })))
}

/// 一次复制的成绩单。前端据此告诉用户「实际用的是秒传还是普通传输」。
#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CopyReport {
    pub(crate) files: u64,
    pub(crate) dirs: u64,
    /// 云端直接引用、零字节落地的分卷数。
    pub(crate) rapid_volumes: u64,
    /// 真实搬了字节的分卷数。
    pub(crate) transferred_volumes: u64,
    /// 秒传省下的字节数。
    pub(crate) rapid_bytes: u64,
    /// 真实经过 SafeDrive 的字节数。
    pub(crate) transferred_bytes: u64,
    /// 因为源/目标加密设置不同而必须解密重加密的文件数。
    pub(crate) reencrypted_files: u64,
    /// 解不开信封、跳过没复制的外来条目。
    pub(crate) skipped: Vec<String>,
}

impl CopyReport {
    /// 供 UI 直接展示的总体判定。
    pub(crate) fn mode(&self) -> &'static str {
        match (self.rapid_volumes, self.transferred_volumes) {
            (0, 0) => "empty",
            (_, 0) => "rapid",
            (0, _) => "transfer",
            _ => "mixed",
        }
    }

    fn merge(&mut self, other: CopyReport) {
        self.files += other.files;
        self.dirs += other.dirs;
        self.rapid_volumes += other.rapid_volumes;
        self.transferred_volumes += other.transferred_volumes;
        self.rapid_bytes += other.rapid_bytes;
        self.transferred_bytes += other.transferred_bytes;
        self.reencrypted_files += other.reencrypted_files;
        self.skipped.extend(other.skipped);
    }
}

/// 复制期间的一次性缓存：同一个存储端目录的内容摘要只 list 一次。
#[derive(Default)]
struct HashCache(HashMap<String, HashMap<String, ContentHashes>>);

impl HashCache {
    async fn get(&mut self, storage: &dyn Storage, dir: &str, name: &str) -> ContentHashes {
        if !self.0.contains_key(dir) {
            // 拿不到摘要不是错误（多数数据源本来就不提供），静默退成空表。
            let hashes = storage.dir_content_hashes(dir).await.unwrap_or_else(|e| {
                tracing::debug!("读取 {dir} 的内容摘要失败（将不尝试秒传）: {e}");
                HashMap::new()
            });
            self.0.insert(dir.to_owned(), hashes);
        }
        self.0
            .get(dir)
            .and_then(|dir| dir.get(name))
            .cloned()
            .unwrap_or_default()
    }
}

/// 把一个存储端对象包装成秒传取数口。目标适配器只会从这里读极少量字节
/// （pre_hash 头 1 KiB、proof_code 8 字节）。
struct ObjectSource {
    storage: Arc<dyn Storage>,
    path: String,
    size: u64,
    hashes: ContentHashes,
}

#[async_trait]
impl RapidSource for ObjectSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn hashes(&self) -> &ContentHashes {
        &self.hashes
    }

    async fn read_at(&self, offset: u64, len: u64) -> ApiResult<bytes::Bytes> {
        if len == 0 {
            return Ok(bytes::Bytes::new());
        }
        if offset + len > self.size {
            return Err(ApiError::BadRequest("秒传取样越界".into()));
        }
        let mut stream = self
            .storage
            .get_range(&self.path, offset, offset + len - 1)
            .await?;
        let mut buf = bytes::BytesMut::with_capacity(len as usize);
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
            if buf.len() as u64 >= len {
                break;
            }
        }
        if (buf.len() as u64) < len {
            return Err(ApiError::Upstream(format!(
                "秒传取样读到 {} 字节，期望 {len}",
                buf.len()
            )));
        }
        buf.truncate(len as usize);
        Ok(buf.freeze())
    }
}

/// 搬运单个存储端对象：先尽力秒传，落空再走真实传输。返回是否命中秒传。
async fn copy_object(
    src: &Arc<dyn Storage>,
    src_path: &str,
    dst: &dyn Storage,
    dst_path: &str,
    size: u64,
    known: ContentHashes,
    progress: &Arc<engine::UploadProgress>,
) -> ApiResult<bool> {
    let kinds = dst.rapid_hash_kinds();
    if !kinds.is_empty() && size > 0 {
        let mut source = ObjectSource {
            storage: Arc::clone(src),
            path: src_path.to_owned(),
            size,
            hashes: known,
        };
        // 廉价预检（阿里云盘只看头 1 KiB）：明确落空就别浪费全量摘要。
        let worth_trying = match dst.rapid_precheck(dst_path, &source).await {
            Ok(worth) => worth,
            Err(e) => {
                tracing::debug!("{dst_path} 秒传预检失败，转普通传输: {e}");
                false
            }
        };
        if worth_trying {
            // 摘要不齐时只在「源侧读免费」（本地磁盘）的前提下补算：
            // 为了赌一次秒传而把云端文件整个拉下来是净亏。
            if !source.hashes.covers(kinds) && src.reads_are_free() {
                let (_, body) = src.get(src_path).await?;
                source.hashes = hash_stream(body, kinds).await?;
            }
            if source.hashes.covers(kinds) {
                match dst.rapid_put(dst_path, &source).await {
                    Ok(true) => {
                        // 秒传没有真实字节流动，但进度条得走完这一卷。
                        progress
                            .encrypted
                            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                        progress
                            .uploaded
                            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                        return Ok(true);
                    }
                    Ok(false) => {}
                    Err(e) => tracing::debug!("{dst_path} 秒传失败，转普通传输: {e}"),
                }
            }
        }
    }

    // 降级：源侧读出的密文原样写到目标，全程不碰加解密。
    let (_, body) = src.get(src_path).await?;
    let counted = {
        let progress = Arc::clone(progress);
        body.map(move |item| {
            if let Ok(chunk) = &item {
                progress
                    .encrypted
                    .fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            item
        })
    };
    let reported = {
        let progress = Arc::clone(progress);
        Arc::new(move |bytes: u64| progress.record_uploaded(bytes)) as crate::adapters::ProgressFn
    };
    dst.put_sized_tracked(dst_path, size, counted.boxed(), reported)
        .await?;
    Ok(false)
}

/// 源侧一个文件的「原样搬运计划」：容器目录 + 各分卷（名字与字节数）。
struct RawPlan {
    /// 分卷所在的存储端目录（未分卷的明文文件即其父目录）。
    container: String,
    volumes: Vec<(String, u64)>,
    /// 明文逻辑总大小。
    total: u64,
    /// 加密文件的文件密钥；明文数据源为 None。
    secret: Option<[u8; crate::crypto::SECRET_LEN]>,
    /// 明文数据源：源文件是否用分卷容器承载。
    plain_split: bool,
}

async fn plan_source(
    state: &AppState,
    storage: &dyn Storage,
    ds: &str,
    path: &str,
) -> ApiResult<RawPlan> {
    if state.datasource(ds)?.encryption_enabled {
        let node = resolve(state, storage, ds, path).await?;
        if node.dir {
            return Err(ApiError::BadRequest(format!("{path} 是目录")));
        }
        let meta = decode_name(&node.parent_key, &node.nc)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法解码 {path} 的密文名")))?;
        // load_layout 会校验分卷号无空洞 —— 缺卷时宁可报错也不要复制出半个文件。
        let layout = engine::load_layout(storage, &node.enc_path, &node.secret).await?;
        if layout.total != meta.size {
            return Err(ApiError::Upstream(format!(
                "云端分卷总大小 {} 与记录 {} 不符（数据可能被外部修改）",
                layout.total, meta.size
            )));
        }
        return Ok(RawPlan {
            container: node.enc_path,
            volumes: layout
                .volumes
                .into_iter()
                .map(|volume| (volume.name, volume.size))
                .collect(),
            total: layout.total,
            secret: Some(node.secret),
            plain_split: false,
        });
    }

    let (entry, actual, split) = plain_locate(storage, path).await?;
    if split {
        let layout = engine::load_layout_ordered(storage, &actual).await?;
        Ok(RawPlan {
            container: actual,
            volumes: layout
                .volumes
                .into_iter()
                .map(|volume| (volume.name, volume.size))
                .collect(),
            total: layout.total,
            secret: None,
            plain_split: true,
        })
    } else {
        if entry.is_dir {
            return Err(ApiError::BadRequest(format!("{path} 是目录")));
        }
        let (parent, name) = parent_and_name(&actual);
        Ok(RawPlan {
            container: parent.to_owned(),
            volumes: vec![(name.to_owned(), entry.size)],
            total: entry.size,
            secret: None,
            plain_split: false,
        })
    }
}

/// 目标侧准备好容器与卷名，返回 (容器路径, 卷名, 失败时要清理的路径, 落缓存的回调)。
struct DestPlan {
    container: String,
    names: Vec<String>,
    /// 失败清理目标：分卷容器或单个文件。
    cleanup: Option<String>,
    /// 成功后要写进路径缓存的信封（加密数据源）。
    cache: Option<CachedNode>,
}

async fn plan_dest(
    state: &AppState,
    storage: &dyn Storage,
    ds: &str,
    path: &str,
    plan: &RawPlan,
) -> ApiResult<DestPlan> {
    let datasource = state.datasource(ds)?;
    let (parent, name) = parent_and_name(path);

    if datasource.encryption_enabled {
        let secret = plan
            .secret
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("加密目标缺少文件密钥")))?;
        let parent_node = if parent.is_empty() {
            resolve_root(state, ds)?
        } else {
            ensure_dir(state, storage, ds, parent).await?
        };
        // 只换外层信封：pw 原样保留，卷名与卷内容因此完全不变。
        let nc = encode_name(
            &parent_node.secret,
            &NameMeta {
                name: name.to_owned(),
                size: plan.total,
                is_dir: false,
                secret,
            },
        )
        .ok_or_else(|| ApiError::BadRequest(format!("文件名过长: {name}")))?;
        let container = join_enc(&parent_node.enc_path, &nc);
        storage.mkdir(&container).await?;
        return Ok(DestPlan {
            container: container.clone(),
            names: plan.volumes.iter().map(|(name, _)| name.clone()).collect(),
            cleanup: Some(container),
            cache: Some(CachedNode {
                secret,
                nc,
                dir: false,
            }),
        });
    }

    ensure_plain_dir(storage, parent).await?;
    if plan.plain_split {
        // 切分跟随源，但卷名按目标数据源的模板重排（明文卷名不参与内容）。
        let container = join_enc(parent, &format!("{name}{PLAIN_VOLUME_SUFFIX}"));
        storage.mkdir(&container).await?;
        Ok(DestPlan {
            container: container.clone(),
            names: volume_names(&datasource.volume_name_format, name, plan.volumes.len()),
            cleanup: Some(container),
            cache: None,
        })
    } else {
        Ok(DestPlan {
            container: parent.to_owned(),
            names: vec![name.to_owned()],
            cleanup: Some(path.to_owned()),
            cache: None,
        })
    }
}

/// 复制一个文件。加密设置一致时走原样搬运（可秒传），否则解密重加密。
#[allow(clippy::too_many_arguments)]
async fn copy_file(
    state: &AppState,
    src_ds: &str,
    src_path: &str,
    dst_ds: &str,
    dst_path: &str,
    overwrite: bool,
    hashes: &mut HashCache,
    progress: &Arc<engine::UploadProgress>,
) -> ApiResult<CopyReport> {
    let src_encrypted = state.datasource(src_ds)?.encryption_enabled;
    let dst_encrypted = state.datasource(dst_ds)?.encryption_enabled;

    // 加密设置不一致：内容本身就不同，只能整条链路解密再重加密。
    if src_encrypted != dst_encrypted {
        let response = crate::routes::files::stream_file(
            state,
            src_ds,
            src_path,
            true,
            Method::GET,
            &HeaderMap::new(),
        )
        .await?;
        let size = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法确定 {src_path} 的明文大小")))?;
        let body = response
            .into_body()
            .into_data_stream()
            .map_err(std::io::Error::other);
        upload_file(
            state,
            dst_ds,
            dst_path,
            size,
            overwrite,
            Box::pin(body),
            Arc::clone(progress),
        )
        .await?;
        return Ok(CopyReport {
            files: 1,
            reencrypted_files: 1,
            transferred_volumes: 1,
            transferred_bytes: size,
            ..Default::default()
        });
    }

    let src_storage = state.adapter_arc(src_ds)?;
    let dst_storage = state.adapter_arc(dst_ds)?;

    // 并发防线：与普通上传共用同一把「同路径同时只允许一个写」的锁。
    let upload_key = format!("{dst_ds}:{dst_path}");
    if !state.uploading.lock().unwrap().insert(upload_key.clone()) {
        return Err(ApiError::BadRequest(format!("目标正在写入中: {dst_path}")));
    }
    struct UploadingGuard<'a>(&'a AppState, String);
    impl Drop for UploadingGuard<'_> {
        fn drop(&mut self) {
            self.0.uploading.lock().unwrap().remove(&self.1);
        }
    }
    let _guard = UploadingGuard(state, upload_key);

    let plan = plan_source(state, src_storage.as_ref(), src_ds, src_path).await?;
    remove_existing(state, dst_storage.as_ref(), dst_ds, dst_path, overwrite).await?;
    let dest = plan_dest(state, dst_storage.as_ref(), dst_ds, dst_path, &plan).await?;

    let mut report = CopyReport {
        files: 1,
        ..Default::default()
    };
    let result: ApiResult<()> = async {
        for ((src_name, size), dst_name) in plan.volumes.iter().zip(dest.names.iter()) {
            let from = join_enc(&plan.container, src_name);
            let to = join_enc(&dest.container, dst_name);
            let known = hashes
                .get(src_storage.as_ref(), &plan.container, src_name)
                .await;
            let rapid = copy_object(
                &src_storage,
                &from,
                dst_storage.as_ref(),
                &to,
                *size,
                known,
                progress,
            )
            .await?;
            if rapid {
                report.rapid_volumes += 1;
                report.rapid_bytes += size;
            } else {
                report.transferred_volumes += 1;
                report.transferred_bytes += size;
            }
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!(
            "复制失败: {src_ds}:{src_path} → {dst_ds}:{dst_path} 分卷数={} err={e}",
            plan.volumes.len()
        );
        if let Some(cleanup) = &dest.cleanup
            && let Err(del) = dst_storage.delete(cleanup).await
            && !matches!(del, ApiError::NotFound(_))
        {
            tracing::warn!("复制失败后清理 {cleanup} 也失败: {del}");
        }
        state.cache.evict_subtree(dst_ds, dst_path);
        return Err(e);
    }
    if let Some(node) = dest.cache {
        state.cache.put(dst_ds, dst_path, node);
    }
    Ok(report)
}

/// 目标已存在时按 `overwrite` 决定报错还是先删。
async fn remove_existing(
    state: &AppState,
    storage: &dyn Storage,
    ds: &str,
    path: &str,
    overwrite: bool,
) -> ApiResult<()> {
    if state.datasource(ds)?.encryption_enabled {
        match resolve(state, storage, ds, path).await {
            Ok(node) => {
                if !overwrite {
                    return Err(ApiError::BadRequest(format!("已存在同名条目: {path}")));
                }
                if node.dir {
                    return Err(ApiError::BadRequest(format!("已存在同名目录: {path}")));
                }
                match storage.delete(&node.enc_path).await {
                    Ok(()) | Err(ApiError::NotFound(_)) => {}
                    Err(e) => return Err(e),
                }
                state.cache.evict_subtree(ds, path);
            }
            Err(ApiError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        return Ok(());
    }
    match plain_locate(storage, path).await {
        Ok((entry, actual, split)) => {
            if !overwrite {
                return Err(ApiError::BadRequest(format!("已存在同名条目: {path}")));
            }
            if entry.is_dir && !split {
                return Err(ApiError::BadRequest(format!("已存在同名目录: {path}")));
            }
            storage.delete(&actual).await?;
            Ok(())
        }
        Err(ApiError::NotFound(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// 复制入口（文件或整棵目录）。`dst_path` 是复制后的完整明文路径。
/// `progress_id` 非空时把进度注册到 `/api/uploads/{id}/progress`，与普通
/// 上传共用同一个轮询端点。
pub(crate) async fn copy_path(
    state: &AppState,
    src_ds: &str,
    src_path: &str,
    dst_ds: &str,
    dst_path: &str,
    overwrite: bool,
    progress_id: Option<&str>,
) -> ApiResult<CopyReport> {
    if src_path.is_empty() {
        return Err(ApiError::BadRequest("不能复制数据源根目录".into()));
    }
    if dst_path.is_empty() {
        return Err(ApiError::BadRequest("目标路径不能为空".into()));
    }
    if src_ds == dst_ds && (dst_path == src_path || dst_path.starts_with(&format!("{src_path}/"))) {
        return Err(ApiError::BadRequest("不能复制到自身或其子目录".into()));
    }

    let src_storage = state.adapter_arc(src_ds)?;
    let entry = stat_path(state, src_storage.as_ref(), src_ds, src_path).await?;

    // 目录复制的总量要遍历整棵树才知道，不值当多跑一轮 list：total 记 0，
    // 前端按「已传字节」显示即可。
    let total = if entry.is_dir { 0 } else { entry.size };
    let progress = Arc::new(engine::UploadProgress::tracked(
        total,
        Arc::clone(&state.transfers),
    ));
    struct ProgressGuard<'a>(&'a AppState, Option<String>);
    impl Drop for ProgressGuard<'_> {
        fn drop(&mut self) {
            if let Some(id) = &self.1 {
                self.0.upload_progress.lock().unwrap().remove(id);
            }
        }
    }
    let progress_id = progress_id.map(str::trim).filter(|id| !id.is_empty());
    if let Some(id) = progress_id {
        state
            .upload_progress
            .lock()
            .unwrap()
            .insert(id.to_string(), Arc::clone(&progress));
    }
    let _progress_guard = ProgressGuard(state, progress_id.map(str::to_owned));

    // 外来（明文）对象：整棵按字面存储路径直传，落地仍是外来条目——不纳管、
    // 不加解密（受管条目才走保留文件密钥的信封搬运）。
    if entry.foreign {
        let src_enc = match locate_any(state, src_storage.as_ref(), src_ds, src_path).await? {
            Located::Foreign { enc_path, .. } => enc_path,
            // stat_path 已判为外来，不会走到这
            Located::Managed(_) => {
                return Err(ApiError::Internal(anyhow::anyhow!("外来判定不一致")));
            }
        };
        let dst_storage = state.adapter_arc(dst_ds)?;
        let (dst_parent, leaf) = parent_and_name(dst_path);
        let dst_parent_enc =
            ensure_dest_parent_enc(state, dst_storage.as_ref(), dst_ds, dst_parent).await?;
        return copy_foreign_node(
            state,
            src_ds,
            &src_enc,
            entry.is_dir,
            entry.size,
            dst_ds,
            &join_enc(&dst_parent_enc, leaf),
            overwrite,
            &progress,
        )
        .await;
    }

    let mut hashes = HashCache::default();
    copy_node(
        state,
        src_ds,
        src_path,
        dst_ds,
        dst_path,
        entry.is_dir,
        overwrite,
        &mut hashes,
        &progress,
    )
    .await
}

/// 递归复制。Box::pin 是因为 async fn 的自递归需要装箱的 future。
#[allow(clippy::too_many_arguments)]
fn copy_node<'a>(
    state: &'a AppState,
    src_ds: &'a str,
    src_path: &'a str,
    dst_ds: &'a str,
    dst_path: &'a str,
    is_dir: bool,
    overwrite: bool,
    hashes: &'a mut HashCache,
    progress: &'a Arc<engine::UploadProgress>,
) -> std::pin::Pin<Box<dyn Future<Output = ApiResult<CopyReport>> + Send + 'a>> {
    Box::pin(async move {
        if !is_dir {
            return copy_file(
                state, src_ds, src_path, dst_ds, dst_path, overwrite, hashes, progress,
            )
            .await;
        }

        let src_storage = state.adapter_arc(src_ds)?;
        let dst_storage = state.adapter_arc(dst_ds)?;
        mkdir_path(state, dst_storage.as_ref(), dst_ds, dst_path).await?;
        let children = list_dir(state, src_storage.as_ref(), src_ds, src_path).await?;
        let mut report = CopyReport {
            dirs: 1,
            ..Default::default()
        };
        for child in children {
            if child.foreign {
                // 受管目录里夹带的外来（明文）子对象：按字面存储路径直传，
                // 落地仍是外来条目（受管子对象才递归走信封搬运）。
                let src_dir_enc =
                    match locate_any(state, src_storage.as_ref(), src_ds, src_path).await? {
                        Located::Managed(n) => n.enc_path,
                        Located::Foreign { enc_path, .. } => enc_path,
                    };
                let dst_dir_enc =
                    ensure_dest_parent_enc(state, dst_storage.as_ref(), dst_ds, dst_path).await?;
                let child_report = copy_foreign_node(
                    state,
                    src_ds,
                    &join_enc(&src_dir_enc, &child.name),
                    child.is_dir,
                    child.size,
                    dst_ds,
                    &join_enc(&dst_dir_enc, &child.name),
                    overwrite,
                    progress,
                )
                .await?;
                report.merge(child_report);
                continue;
            }
            let child_report = copy_node(
                state,
                src_ds,
                &join_enc(src_path, &child.name),
                dst_ds,
                &join_enc(dst_path, &child.name),
                child.is_dir,
                overwrite,
                hashes,
                progress,
            )
            .await?;
            report.merge(child_report);
        }
        Ok(report)
    })
}

/// 目标父目录的字面存储路径：受管数据源建/取加密目录返回其 enc_path，明文
/// 数据源建普通目录返回明文路径本身（根为空串）。外来对象按字面名落进这里。
async fn ensure_dest_parent_enc(
    state: &AppState,
    storage: &dyn Storage,
    ds: &str,
    path: &str,
) -> ApiResult<String> {
    if path.is_empty() {
        return Ok(String::new());
    }
    if state.datasource(ds)?.encryption_enabled {
        Ok(ensure_dir(state, storage, ds, path).await?.enc_path)
    } else {
        ensure_plain_dir(storage, path).await?;
        Ok(path.to_owned())
    }
}

/// 复制外来（明文）对象：源与目标都用**字面存储路径**，逐字节直传（能秒传
/// 就秒传），落地仍是明文——在加密目标数据源里即「外来条目」。全程不碰任何
/// 加解密，也不写信封缓存。
#[allow(clippy::too_many_arguments)]
fn copy_foreign_node<'a>(
    state: &'a AppState,
    src_ds: &'a str,
    src_enc: &'a str,
    is_dir: bool,
    size: u64,
    dst_ds: &'a str,
    dst_enc: &'a str,
    overwrite: bool,
    progress: &'a Arc<engine::UploadProgress>,
) -> std::pin::Pin<Box<dyn Future<Output = ApiResult<CopyReport>> + Send + 'a>> {
    Box::pin(async move {
        let src_storage = state.adapter_arc(src_ds)?;
        let dst_storage = state.adapter_arc(dst_ds)?;
        let (dst_parent_enc, leaf) = parent_and_name(dst_enc);
        let existing = dst_storage
            .list(dst_parent_enc)
            .await?
            .into_iter()
            .find(|e| e.name == leaf);

        if is_dir {
            match &existing {
                Some(e) if e.is_dir => {} // 复用已存在的同名外来目录
                Some(_) => {
                    return Err(ApiError::BadRequest(format!(
                        "目标已存在且不是目录: {dst_enc}"
                    )));
                }
                None => dst_storage.mkdir(dst_enc).await?,
            }
            let mut report = CopyReport {
                dirs: 1,
                ..Default::default()
            };
            for child in src_storage.list(src_enc).await? {
                let child_report = copy_foreign_node(
                    state,
                    src_ds,
                    &join_enc(src_enc, &child.name),
                    child.is_dir,
                    child.size,
                    dst_ds,
                    &join_enc(dst_enc, &child.name),
                    overwrite,
                    progress,
                )
                .await?;
                report.merge(child_report);
            }
            return Ok(report);
        }

        // 文件：先按 overwrite 处理目标同名对象，再逐字节直传。
        if existing.is_some() {
            if !overwrite {
                return Err(ApiError::BadRequest(format!("已存在同名条目: {dst_enc}")));
            }
            match dst_storage.delete(dst_enc).await {
                Ok(()) | Err(ApiError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        let rapid = copy_object(
            &src_storage,
            src_enc,
            dst_storage.as_ref(),
            dst_enc,
            size,
            ContentHashes::default(),
            progress,
        )
        .await?;
        let mut report = CopyReport {
            files: 1,
            ..Default::default()
        };
        if rapid {
            report.rapid_volumes = 1;
            report.rapid_bytes = size;
        } else {
            report.transferred_volumes = 1;
            report.transferred_bytes = size;
        }
        Ok(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::HashKind;
    use crate::registry::DataSource;
    use crate::state::AppState;

    fn datasource(id: &str, root: &str, encrypted: bool, split: bool) -> DataSource {
        DataSource {
            id: id.into(),
            name: id.into(),
            ds_type: "localfs".into(),
            config: serde_json::json!({ "root": root }),
            encryption_enabled: encrypted,
            // 两个数据源用**不同**根密码：目标信封必须用目标自己的 FK 重编，
            // 而卷内容仍然逐字节相同 —— 这正是保密钥复制要证明的事。
            password: if encrypted {
                format!("pw-{id}")
            } else {
                String::new()
            },
            prev_password: None,
            volume_enabled: split,
            volume_size: 64 * 1024,
            volume_strategy: "fixed".into(),
            volume_name_format: "{s}_{i}.bin".into(),
            cache_enabled: false,
            created_at: 1,
        }
    }

    /// 两个 localfs 数据源 + 一个 AppState。
    fn setup(specs: &[(&str, bool, bool)]) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(dir.path().join("data"), None).unwrap();
        for (id, encrypted, split) in specs {
            let root = dir.path().join(id);
            std::fs::create_dir_all(&root).unwrap();
            state
                .registry
                .create(datasource(id, root.to_str().unwrap(), *encrypted, *split))
                .unwrap();
        }
        (state, dir)
    }

    fn payload(len: usize) -> bytes::Bytes {
        // 可复现的伪随机，够长以跨越 64 KiB 卷界。
        let mut out = Vec::with_capacity(len);
        let mut x = 0x2545_f491_4f6c_dd1du64;
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(len);
        bytes::Bytes::from(out)
    }

    async fn put(state: &AppState, ds: &str, path: &str, data: &bytes::Bytes) {
        let size = data.len() as u64;
        let chunk = data.clone();
        let body = futures_util::stream::once(async move { Ok(chunk) });
        upload_file(
            state,
            ds,
            path,
            size,
            true,
            Box::pin(body),
            Arc::new(engine::UploadProgress::new(size)),
        )
        .await
        .unwrap();
    }

    async fn read_back(state: &AppState, ds: &str, path: &str) -> bytes::Bytes {
        use http_body_util::BodyExt;
        let response = crate::routes::files::stream_file(
            state,
            ds,
            path,
            true,
            Method::GET,
            &HeaderMap::new(),
        )
        .await
        .unwrap();
        response.into_body().collect().await.unwrap().to_bytes()
    }

    /// 存储端实际落地的对象（相对数据源根，目录以 / 结尾），排序后返回。
    fn tree(root: &std::path::Path) -> Vec<String> {
        fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                if path.is_dir() {
                    out.push(format!("{rel}/"));
                    walk(base, &path, out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// 加密 → 加密（两个数据源根密码不同）：分卷必须逐字节相同、卷名相同，
    /// 只有最外层信封名不同。这是秒传能成立的全部前提。
    #[tokio::test]
    async fn encrypted_copy_preserves_volume_bytes_and_names() {
        let (state, dir) = setup(&[("src", true, true), ("dst", true, true)]);
        let data = payload(150 * 1024); // 跨 3 卷
        put(&state, "src", "片子/a.mkv", &data).await;

        let report = copy_path(
            &state,
            "src",
            "片子/a.mkv",
            "dst",
            "别的/b.mkv",
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.files, 1);
        assert_eq!(report.transferred_volumes, 3);
        assert_eq!(report.reencrypted_files, 0);
        assert_eq!(report.mode(), "transfer"); // localfs 不支持秒传

        // 明文读回一致（说明目标信封里的 pw 与源一致）。
        assert_eq!(read_back(&state, "dst", "别的/b.mkv").await, data);

        // 卷名 + 卷内容逐字节相同。
        let src_volumes = volume_files(&dir.path().join("src"));
        let dst_volumes = volume_files(&dir.path().join("dst"));
        assert_eq!(src_volumes.len(), 3);
        assert_eq!(
            src_volumes.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            dst_volumes.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            "卷名必须一致（同一个 pw 派生的 PRP）"
        );
        assert_eq!(
            src_volumes.iter().map(|(_, b)| b).collect::<Vec<_>>(),
            dst_volumes.iter().map(|(_, b)| b).collect::<Vec<_>>(),
            "卷内容必须逐字节相同"
        );
    }

    /// 收集数据源根下所有普通文件的 (文件名, 内容)，按名排序。
    fn volume_files(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for rel in tree(root) {
            if rel.ends_with('/') {
                continue;
            }
            let name = rel.rsplit('/').next().unwrap().to_string();
            out.push((name, std::fs::read(root.join(&rel)).unwrap()));
        }
        out.sort();
        out
    }

    /// 明文 → 明文：分卷切分跟随源，卷名按目标模板重排。
    #[tokio::test]
    async fn plain_split_copy_follows_source_layout() {
        let (state, dir) = setup(&[("src", false, true), ("dst", false, true)]);
        let data = payload(150 * 1024);
        put(&state, "src", "a.bin", &data).await;

        let report = copy_path(&state, "src", "a.bin", "dst", "sub/b.bin", false, None)
            .await
            .unwrap();
        assert_eq!(report.transferred_volumes, 3);
        assert_eq!(read_back(&state, "dst", "sub/b.bin").await, data);
        assert_eq!(
            tree(&dir.path().join("dst")),
            vec![
                "sub/".to_string(),
                format!("sub/b.bin{PLAIN_VOLUME_SUFFIX}/"),
                format!("sub/b.bin{PLAIN_VOLUME_SUFFIX}/b.bin_01.bin"),
                format!("sub/b.bin{PLAIN_VOLUME_SUFFIX}/b.bin_02.bin"),
                format!("sub/b.bin{PLAIN_VOLUME_SUFFIX}/b.bin_03.bin"),
            ]
        );
    }

    /// 加密 ↔ 明文：内容本身不同，只能解密重加密，报告里如实标注。
    #[tokio::test]
    async fn encryption_mismatch_falls_back_to_reencrypt() {
        let (state, _dir) = setup(&[("src", true, true), ("dst", false, false)]);
        let data = payload(80 * 1024);
        put(&state, "src", "a.bin", &data).await;

        let report = copy_path(&state, "src", "a.bin", "dst", "a.bin", false, None)
            .await
            .unwrap();
        assert_eq!(report.reencrypted_files, 1);
        assert_eq!(report.rapid_volumes, 0);
        assert_eq!(read_back(&state, "dst", "a.bin").await, data);
    }

    /// 目录递归 + overwrite 语义。
    #[tokio::test]
    async fn directory_copy_recurses_and_respects_overwrite() {
        let (state, _dir) = setup(&[("src", true, true), ("dst", true, true)]);
        let a = payload(1024);
        let b = payload(2048);
        put(&state, "src", "顶层/a.bin", &a).await;
        put(&state, "src", "顶层/里层/b.bin", &b).await;

        let report = copy_path(&state, "src", "顶层", "dst", "拷贝", false, None)
            .await
            .unwrap();
        assert_eq!((report.files, report.dirs), (2, 2));
        assert_eq!(read_back(&state, "dst", "拷贝/a.bin").await, a);
        assert_eq!(read_back(&state, "dst", "拷贝/里层/b.bin").await, b);

        // 同名再来一次：overwrite=false 必须拒绝，=true 必须成功。
        let again = copy_path(
            &state,
            "src",
            "顶层/a.bin",
            "dst",
            "拷贝/a.bin",
            false,
            None,
        )
        .await;
        assert!(matches!(again, Err(ApiError::BadRequest(_))));
        copy_path(&state, "src", "顶层/a.bin", "dst", "拷贝/a.bin", true, None)
            .await
            .unwrap();
        assert_eq!(read_back(&state, "dst", "拷贝/a.bin").await, a);
    }

    /// 复制到自身或自己的子目录必须直接拒绝，别把源吃掉。
    #[tokio::test]
    async fn self_copy_is_rejected() {
        let (state, _dir) = setup(&[("src", true, true)]);
        put(&state, "src", "d/a.bin", &payload(64)).await;
        for dest in ["d", "d/inner"] {
            assert!(matches!(
                copy_path(&state, "src", "d", "src", dest, true, None).await,
                Err(ApiError::BadRequest(_))
            ));
        }
    }

    /// 同一数据源内换个目录复制：同样是保密钥搬运，两份副本各自可独立读回。
    /// 卷名由 pw 派生所以两边同名，但它们在各自的信封目录里，不会撞车。
    #[tokio::test]
    async fn same_datasource_copy_keeps_both_copies_readable() {
        let (state, _dir) = setup(&[("src", true, true)]);
        let data = payload(150 * 1024);
        put(&state, "src", "d/a.bin", &data).await;

        let report = copy_path(&state, "src", "d/a.bin", "src", "e/b.bin", false, None)
            .await
            .unwrap();
        assert_eq!((report.files, report.transferred_volumes), (1, 3));
        assert_eq!(read_back(&state, "src", "d/a.bin").await, data);
        assert_eq!(read_back(&state, "src", "e/b.bin").await, data);
    }

    /// 外来（明文）对象在加密数据源里搬来搬去，身份不能变味：
    /// 复制/移动后仍是外来条目、字节不变；删除能清掉；复制进明文数据源
    /// 则落成普通明文对象。这条正是「外来还是外来，受管走受管」的锁。
    #[tokio::test]
    async fn foreign_objects_stay_foreign_across_copy_move_delete() {
        let (state, dir) = setup(&[("enc", true, false), ("plain", false, false)]);
        let enc_root = dir.path().join("enc");
        let file_bytes = payload(3000);
        let inner_bytes = payload(5000);
        // 直接往加密数据源存储根塞明文对象：名字解不开信封 → 外来条目。
        std::fs::write(enc_root.join("外来.txt"), &file_bytes).unwrap();
        std::fs::create_dir(enc_root.join("外来夹")).unwrap();
        std::fs::write(enc_root.join("外来夹").join("inner.bin"), &inner_bytes).unwrap();

        let storage = state.adapter("enc").unwrap();
        let root = list_dir(&state, storage.as_ref(), "enc", "").await.unwrap();
        assert!(
            root.iter()
                .any(|e| e.name == "外来.txt" && e.foreign && !e.is_dir),
            "外来文件应被识别为外来条目"
        );
        assert!(
            root.iter()
                .any(|e| e.name == "外来夹" && e.foreign && e.is_dir),
            "外来目录应被识别为外来条目"
        );

        // 复制外来文件到受管子目录：落地仍是外来，字节原样。
        copy_path(
            &state,
            "enc",
            "外来.txt",
            "enc",
            "受管夹/外来.txt",
            false,
            None,
        )
        .await
        .unwrap();
        let managed = list_dir(&state, storage.as_ref(), "enc", "受管夹")
            .await
            .unwrap();
        let copied = managed.iter().find(|e| e.name == "外来.txt").unwrap();
        assert!(copied.foreign, "复制进受管目录后仍是外来条目");
        assert_eq!(copied.size, 3000);
        assert_eq!(
            read_back(&state, "enc", "受管夹/外来.txt").await,
            file_bytes
        );

        // 复制整棵外来目录：子对象也保持外来，字节原样。
        copy_path(&state, "enc", "外来夹", "enc", "受管夹/外来夹", false, None)
            .await
            .unwrap();
        let sub = list_dir(&state, storage.as_ref(), "enc", "受管夹/外来夹")
            .await
            .unwrap();
        let inner = sub.iter().find(|e| e.name == "inner.bin").unwrap();
        assert!(inner.foreign, "外来目录的子文件仍是外来条目");
        assert_eq!(
            read_back(&state, "enc", "受管夹/外来夹/inner.bin").await,
            inner_bytes
        );

        // 复制进明文数据源：落成普通明文对象（明文源永不标外来）。
        copy_path(&state, "enc", "外来夹", "plain", "落地", false, None)
            .await
            .unwrap();
        assert!(dir.path().join("plain/落地/inner.bin").is_file());
        let plain_storage = state.adapter("plain").unwrap();
        let plain_root = list_dir(&state, plain_storage.as_ref(), "plain", "落地")
            .await
            .unwrap();
        assert!(
            plain_root
                .iter()
                .any(|e| e.name == "inner.bin" && !e.foreign),
            "明文数据源里落地的是普通明文对象"
        );

        // 移动（rename）外来文件：仍是外来，旧名消失。
        crate::routes::files::rename_path(
            &state,
            storage.as_ref(),
            "enc",
            "外来.txt",
            "外来改.txt",
        )
        .await
        .unwrap();
        let root = list_dir(&state, storage.as_ref(), "enc", "").await.unwrap();
        assert!(
            root.iter().any(|e| e.name == "外来改.txt" && e.foreign),
            "重命名后仍是外来条目"
        );
        assert!(!root.iter().any(|e| e.name == "外来.txt"));

        // 删除外来文件：真删掉。
        crate::routes::files::delete_path(&state, storage.as_ref(), "enc", "外来改.txt")
            .await
            .unwrap();
        assert!(!enc_root.join("外来改.txt").exists());
        let root = list_dir(&state, storage.as_ref(), "enc", "").await.unwrap();
        assert!(!root.iter().any(|e| e.name == "外来改.txt"));
    }

    /// 假的「支持秒传」目标：记录每次调用，永远宣称命中。
    struct RapidSink {
        inner: Arc<dyn Storage>,
        kinds: &'static [HashKind],
        /// 预检返回值。
        precheck: bool,
        /// 秒传是否命中。
        hit: bool,
        log: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Storage for RapidSink {
        async fn list(&self, path: &str) -> ApiResult<Vec<crate::adapters::Entry>> {
            self.inner.list(path).await
        }
        async fn mkdir(&self, path: &str) -> ApiResult<()> {
            self.inner.mkdir(path).await
        }
        async fn delete(&self, path: &str) -> ApiResult<()> {
            self.inner.delete(path).await
        }
        async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
            self.inner.rename(from, to).await
        }
        async fn get(&self, path: &str) -> ApiResult<(Option<u64>, crate::adapters::ByteStream)> {
            self.inner.get(path).await
        }
        async fn put(&self, path: &str, body: crate::adapters::ByteStream) -> ApiResult<()> {
            self.log.lock().unwrap().push(format!("put {path}"));
            self.inner.put(path, body).await
        }
        fn rapid_hash_kinds(&self) -> &'static [HashKind] {
            self.kinds
        }
        async fn rapid_precheck(&self, path: &str, source: &dyn RapidSource) -> ApiResult<bool> {
            // 真去取一次头部样本，顺带验证 ObjectSource 的区间读。
            let head = source.read_at(0, 16.min(source.size())).await?;
            self.log
                .lock()
                .unwrap()
                .push(format!("precheck {path} head={}", head.len()));
            Ok(self.precheck)
        }
        async fn rapid_put(&self, path: &str, source: &dyn RapidSource) -> ApiResult<bool> {
            let sha1 = source.hashes().sha1.clone().unwrap_or_default();
            self.log
                .lock()
                .unwrap()
                .push(format!("rapid {path} sha1={sha1}"));
            Ok(self.hit)
        }
    }

    async fn run_copy_object(
        precheck: bool,
        hit: bool,
        kinds: &'static [HashKind],
    ) -> (bool, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let src_root = dir.path().join("src");
        let dst_root = dir.path().join("dst");
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();
        let data = payload(4096);
        std::fs::write(src_root.join("v1.bin"), &data).unwrap();

        let src: Arc<dyn Storage> = Arc::from(Box::new(
            crate::adapters::localfs::LocalFs::from_config(
                &serde_json::json!({"root": src_root.to_str().unwrap()}),
            )
            .unwrap(),
        ) as Box<dyn Storage>);
        let sink = RapidSink {
            inner: Arc::from(Box::new(
                crate::adapters::localfs::LocalFs::from_config(
                    &serde_json::json!({"root": dst_root.to_str().unwrap()}),
                )
                .unwrap(),
            ) as Box<dyn Storage>),
            kinds,
            precheck,
            hit,
            log: std::sync::Mutex::new(Vec::new()),
        };
        let progress = Arc::new(engine::UploadProgress::new(data.len() as u64));
        let rapid = copy_object(
            &src,
            "v1.bin",
            &sink,
            "v1.bin",
            data.len() as u64,
            ContentHashes::default(),
            &progress,
        )
        .await
        .unwrap();
        // 无论走哪条路，落地的字节都必须一致。
        assert_eq!(
            std::fs::read(dst_root.join("v1.bin"))
                .unwrap_or_default()
                .len() as u64,
            if rapid { 0 } else { data.len() as u64 }
        );
        assert_eq!(
            progress.uploaded.load(std::sync::atomic::Ordering::Relaxed),
            data.len() as u64,
            "进度条必须走完，秒传也不例外"
        );
        let log = sink.log.lock().unwrap().clone();
        (rapid, log)
    }

    /// 摘要缺失但源侧读免费（localfs）时，补算 sha1 后秒传命中。
    #[tokio::test]
    async fn rapid_path_backfills_hashes_and_short_circuits() {
        let (rapid, log) = run_copy_object(true, true, &[HashKind::Sha1]).await;
        assert!(rapid);
        assert!(log[0].starts_with("precheck v1.bin head=16"), "{log:?}");
        // sha1 是补算出来的，40 位十六进制，不是空串。
        let sha1 = log[1].strip_prefix("rapid v1.bin sha1=").expect("秒传调用");
        assert!(
            sha1.len() == 40 && sha1.chars().all(|c| c.is_ascii_hexdigit()),
            "{log:?}"
        );
        assert!(!log.iter().any(|line| line.starts_with("put ")), "{log:?}");
    }

    /// 预检说必然落空 → 直接真实传输，不浪费一次全量摘要。
    #[tokio::test]
    async fn failed_precheck_skips_hashing_entirely() {
        let (rapid, log) = run_copy_object(false, true, &[HashKind::Sha1]).await;
        assert!(!rapid);
        assert!(
            !log.iter().any(|line| line.starts_with("rapid ")),
            "{log:?}"
        );
        assert!(log.iter().any(|line| line.starts_with("put ")), "{log:?}");
    }

    /// 秒传落空（云端没这份内容）→ 无缝降级为真实传输。
    #[tokio::test]
    async fn rapid_miss_degrades_to_transfer() {
        let (rapid, log) = run_copy_object(true, false, &[HashKind::Sha1]).await;
        assert!(!rapid);
        assert!(log.iter().any(|line| line.starts_with("rapid ")), "{log:?}");
        assert!(log.iter().any(|line| line.starts_with("put ")), "{log:?}");
    }

    /// 目标不支持秒传（空 kinds）→ 连预检都不发。
    #[tokio::test]
    async fn unsupported_target_never_prechecks() {
        let (rapid, log) = run_copy_object(true, true, &[]).await;
        assert!(!rapid);
        assert_eq!(log, vec!["put v1.bin".to_string()]);
    }
}
