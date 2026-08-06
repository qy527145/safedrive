//! 明文路径文件 API + 流式代理（模仿 hydraria 的 /stream 数据平面）。
//!
//! v5 密钥架构（cryptree 信封链）：每个条目的秘密装在自己的加密名里，
//! 用父目录 FK 派生的密钥加密。路径解析 = 从数据源根钥逐层 list + 解名
//! 下钻；服务端用纯内存缓存加速（云端为准，miss 按需重建）。
//! 云端数据 + 根钥 = 完整可恢复，没有「先记密码本再传字节」的顺序问题。
//!
//! 走不走信封由 `DataSource::managed()` 决定 —— 加密和伪装都要。信封同时
//! 是「这个存储对象是不是 SafeDrive 写的」的判据：解得开就按受管条目处理
//! （该解密解密、该脱伪装脱伪装），解不开就是外来对象，一个字节都不动。

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::TryStreamExt;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::adapters::sanitize;
use crate::crypto::names::{NameMeta, decode_name, encode_name};
use crate::crypto::{SECRET_LEN, gen_secret};
use crate::disguise::Disguise;
use crate::engine::{self, RangeSpec, StreamMode, StreamParams};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vault::CachedNode;

pub(crate) fn parent_and_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// 把 `total` 字节明文切成若干卷，每卷**落地之后**都不超过 `max`。
///
/// `max` 是用户配置的「最大分卷大小」，它约束的是**实际存储对象**：伪装会给
/// 每个对象额外套一层 `header` 字节的头部，所以数据区的上限是 `max - header`。
fn volume_plan(total: u64, enabled: bool, max: u64, header: u64, strategy: &str) -> Vec<u64> {
    if total == 0 {
        return Vec::new();
    }
    if !enabled {
        return vec![total];
    }
    // 头部也算在「最大分卷大小」里 —— 那是对落地对象的硬限制。
    let max = max.saturating_sub(header).max(1);
    let count = total.div_ceil(max) as usize;
    if strategy != "random" || count <= 1 {
        return (0..count)
            .map(|i| max.min(total - i as u64 * max))
            .collect();
    }
    // 切点法：把总松弛量 slack = count*max - total（恒 < max）均匀随机分成
    // count 份 d_i，每卷大小 = max - d_i。这等价于在「卷数固定、单卷 ≤ max、
    // 总和 = total」的全部可行方案上均匀采样；而逐卷贪心会在前几卷耗尽
    // 松弛量，导致后面的分卷全部顶格等于 max。
    let slack = count as u64 * max - total;
    let mut cuts: Vec<u64> = (0..count - 1)
        .map(|_| {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).expect("系统随机数不可用");
            u64::from_le_bytes(random) % (slack + 1)
        })
        .collect();
    cuts.push(0);
    cuts.push(slack);
    cuts.sort_unstable();
    (0..count).map(|i| max - (cuts[i + 1] - cuts[i])).collect()
}

/// 非受管数据源里定位一个字面对象：存储端就是明文原样，一个文件就是一个对象。
pub(crate) async fn plain_locate(
    storage: &dyn crate::adapters::Storage,
    path: &str,
) -> ApiResult<(crate::adapters::Entry, String)> {
    let (parent, name) = parent_and_name(path);
    storage
        .list(parent)
        .await?
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| (e, path.to_string()))
        .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {path}")))
}

pub(crate) async fn ensure_plain_dir(
    storage: &dyn crate::adapters::Storage,
    path: &str,
) -> ApiResult<()> {
    if path.is_empty() {
        return Ok(());
    }
    let mut current = String::new();
    for seg in path.split('/') {
        let next = join_enc(&current, seg);
        match plain_locate(storage, &next).await {
            Ok((e, _)) if e.is_dir => {}
            Ok(_) => return Err(ApiError::BadRequest(format!("{next} 已存在且不是目录"))),
            Err(ApiError::NotFound(_)) => storage.mkdir(&next).await?,
            Err(e) => return Err(e),
        }
        current = next;
    }
    Ok(())
}

pub fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/files/{ds}/list", get(list))
        .route("/files/{ds}/mkdir", post(mkdir))
        .route("/files/{ds}/rename", post(rename))
        .route("/files/{ds}/delete", post(delete))
        .route("/files/{ds}/delete-foreign", post(delete_foreign))
        .route("/files/{ds}/adopt-foreign", post(adopt_foreign))
        .route(
            "/files/{ds}/cache",
            get(file_cache_status)
                .post(file_cache_warm)
                .delete(file_cache_clear),
        )
        .route(
            "/files/{ds}/cache/warm",
            axum::routing::delete(file_cache_warm_stop),
        )
        .route("/files/{ds}/upload", put(upload))
        .route("/uploads/{id}/progress", get(upload_progress))
}

/// /stream 挂在 /api 之外：供 <video>/VLC/下载器直接消费，鉴权走 ?token=。
pub fn stream_routes() -> Router<AppState> {
    Router::new().route("/stream/{ds}/{*path}", get(stream).head(stream))
}

// ---------------- 信封链解析 ----------------

/// 解析结果：一个已定位的节点。
#[derive(Clone)]
pub(crate) struct Resolved {
    /// 该节点自己的秘密（文件 pw / 目录 FK）。
    pub(crate) secret: [u8; SECRET_LEN],
    /// 加密它名字的父钥（重命名/移动/重编码时需要）。
    pub(crate) parent_key: [u8; SECRET_LEN],
    /// 存储端密文全路径。
    pub(crate) enc_path: String,
    pub(crate) nc: String,
    pub(crate) dir: bool,
    /// 解码本目录条目名的备选密钥（仅根目录在换密码过渡期非空：
    /// 旧密码信封尚未迁移完时读路径回退用）。
    pub(crate) alt_keys: Vec<[u8; SECRET_LEN]>,
}

impl Resolved {
    /// 解码子条目名的密钥优先级列表：主钥在前。
    fn decode_keys(&self) -> Vec<[u8; SECRET_LEN]> {
        let mut keys = vec![self.secret];
        keys.extend(self.alt_keys.iter().copied());
        keys
    }
}

/// 根「节点」：数据源根目录（无 nc，秘密即 FK_root）。
pub(crate) fn resolve_root(state: &AppState, ds: &str) -> ApiResult<Resolved> {
    let mut candidates = state.root_key_candidates_of(ds)?;
    let fk = candidates.remove(0);
    Ok(Resolved {
        secret: fk,
        parent_key: [0u8; SECRET_LEN], // 根没有父钥，永不用于编码
        enc_path: String::new(),
        nc: String::new(),
        dir: true,
        alt_keys: candidates,
    })
}

/// 在目录里查找名为 `seg` 的受管条目。同名多条（并发竞态遗留的副本）时
/// 取 **nc 字典序最小者** 为规范条目 —— 规则确定性，所有请求收敛到同一个。
async fn find_child(
    storage: &dyn crate::adapters::Storage,
    parent_enc: &str,
    parent_keys: &[[u8; SECRET_LEN]],
    seg: &str,
) -> ApiResult<Option<(String, NameMeta)>> {
    let entries = storage.list(parent_enc).await?;
    let mut found: Option<(String, NameMeta)> = None;
    for e in entries {
        if !e.is_dir {
            continue; // 受管条目必然是存储端目录
        }
        if let Some(meta) = decode_multi(parent_keys, &e.name)
            && meta.name == seg
        {
            match &found {
                Some((nc, _)) if *nc <= e.name => {}
                _ => found = Some((e.name, meta)),
            }
        }
    }
    Ok(found)
}

/// 依候选密钥顺序解码（主钥优先；过渡期旧钥回退）。
fn decode_multi(keys: &[[u8; SECRET_LEN]], enc: &str) -> Option<NameMeta> {
    keys.iter().find_map(|k| decode_name(k, enc))
}

/// 明文路径 → 节点。缓存只加速**祖先**定位；**最后一段永远向存储端
/// 现场核实** —— 云端被外部改动（手动删除、别的工具写入）时以云端为准，
/// 顺带清退失效缓存。祖先缓存失效（云端 list 不到）会整链回退重解析。
pub(crate) async fn resolve(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<Resolved> {
    if path.is_empty() {
        return resolve_root(state, ds);
    }
    let segs: Vec<&str> = path.split('/').collect();

    // 祖先（不含最后一段）优先走缓存；miss/失效则从更浅处下钻
    let parent = match segs.len() {
        1 => resolve_root(state, ds)?,
        _ => resolve_cached_dir(state, storage, ds, &segs[..segs.len() - 1]).await?,
    };
    if !parent.dir {
        return Err(ApiError::NotFound(format!(
            "{} 不是目录",
            segs[..segs.len() - 1].join("/")
        )));
    }

    // 叶子：现场 list 核实（这是防缓存幻觉的关键——upload 判存、
    // stream 取数都依赖这里的真实性）
    let seg = segs[segs.len() - 1];
    match find_child(storage, &parent.enc_path, &parent.decode_keys(), seg).await? {
        Some((nc, meta)) => {
            state.cache.put(
                ds,
                path,
                CachedNode {
                    secret: meta.secret,
                    nc: nc.clone(),
                    dir: meta.is_dir,
                },
            );
            Ok(Resolved {
                secret: meta.secret,
                parent_key: parent.secret,
                enc_path: join_enc(&parent.enc_path, &nc),
                nc,
                dir: meta.is_dir,
                alt_keys: Vec::new(),
            })
        }
        None => {
            state.cache.evict_subtree(ds, path); // 清退幻觉
            Err(ApiError::NotFound(format!("路径不存在: {path}")))
        }
    }
}

/// 定位结果：受管节点，或落在外来（不受管、明文）子树里的存储端对象。
pub(crate) enum Located {
    Managed(Resolved),
    /// 外来对象：一旦某段路径解不开信封（如转存进来的他人明文分享），
    /// 该段起的所有路径都按字面存储名处理，内容不解密、不合卷。
    Foreign {
        enc_path: String,
        is_dir: bool,
        size: u64,
    },
}

/// 明文路径 → 受管节点或外来对象。先按信封链解析（命中缓存走快路径）；
/// 解不开的那一段起，剩余路径当作字面存储名逐层核实 —— 让外来目录也能
/// 进入、其中的明文文件也能取用。
pub(crate) async fn locate_any(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<Located> {
    match resolve(state, storage, ds, path).await {
        Ok(node) => return Ok(Located::Managed(node)),
        Err(ApiError::NotFound(_)) => {} // 可能是外来子树，继续按字面名下钻
        Err(e) => return Err(e),
    }
    let segs: Vec<&str> = path.split('/').collect();
    // 尽可能深地按信封链下钻，直到某段解不开
    let mut node = resolve_root(state, ds)?;
    let mut depth = 0;
    while depth < segs.len() && node.dir {
        match find_child(storage, &node.enc_path, &node.decode_keys(), segs[depth]).await? {
            Some((nc, meta)) => {
                node = Resolved {
                    secret: meta.secret,
                    parent_key: node.secret,
                    enc_path: join_enc(&node.enc_path, &nc),
                    nc,
                    dir: meta.is_dir,
                    alt_keys: Vec::new(),
                };
                depth += 1;
            }
            None => break,
        }
    }
    if depth == segs.len() {
        // 全程可解但 resolve 报了 NotFound：并发竞态，按不存在处理
        return Err(ApiError::NotFound(format!("路径不存在: {path}")));
    }
    if !node.dir {
        return Err(ApiError::NotFound(format!(
            "{} 不是目录",
            segs[..depth].join("/")
        )));
    }
    locate_foreign(storage, &node.enc_path, path, &segs[depth..]).await
}

/// 从受管祖先的 `enc_parent` 起，按字面存储名逐层核实外来路径。
async fn locate_foreign(
    storage: &dyn crate::adapters::Storage,
    enc_parent: &str,
    full_path: &str,
    segs: &[&str],
) -> ApiResult<Located> {
    let mut enc = enc_parent.to_string();
    for (i, seg) in segs.iter().enumerate() {
        let entry = storage
            .list(&enc)
            .await?
            .into_iter()
            .find(|e| e.name == *seg)
            .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {full_path}")))?;
        enc = join_enc(&enc, seg);
        if i + 1 == segs.len() {
            return Ok(Located::Foreign {
                enc_path: enc,
                is_dir: entry.is_dir,
                size: entry.size,
            });
        }
        if !entry.is_dir {
            return Err(ApiError::NotFound(format!("{seg} 不是目录")));
        }
    }
    // segs 非空，循环必在末段返回
    Err(ApiError::NotFound(format!("路径不存在: {full_path}")))
}

/// 祖先目录解析：缓存命中即用（这里**不**逐层验证云端 —— 祖先失效时
/// 后续 list 会报 NotFound，我们捕获后清退缓存整链重试一次）。
async fn resolve_cached_dir(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    segs: &[&str],
) -> ApiResult<Resolved> {
    match resolve_cached_dir_inner(state, storage, ds, segs).await {
        Ok(n) => Ok(n),
        Err(ApiError::NotFound(_)) => {
            // 缓存可能整链失效（云端外部变更）：全部清退后纯下钻重试
            state.cache.evict_subtree(ds, segs[0]);
            resolve_cached_dir_inner(state, storage, ds, segs).await
        }
        Err(e) => Err(e),
    }
}

async fn resolve_cached_dir_inner(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    segs: &[&str],
) -> ApiResult<Resolved> {
    // 从最深的已缓存前缀开始（parent_key 需要上一层的 secret，所以缓存
    // 命中要求父层也可得——逐层向上回退直到根）。
    let mut depth = segs.len();
    let mut cur: Option<Resolved> = None;
    while depth > 0 {
        let prefix = segs[..depth].join("/");
        if let Some(hit) = state.cache.get(ds, &prefix) {
            let parent_key = if depth == 1 {
                state.root_key_of(ds)?
            } else {
                match state.cache.get(ds, &segs[..depth - 1].join("/")) {
                    Some(p) => p.secret,
                    None => {
                        depth -= 1;
                        continue;
                    }
                }
            };
            let enc_parent = enc_path_of(state, ds, &segs[..depth - 1])?;
            cur = Some(Resolved {
                secret: hit.secret,
                parent_key,
                enc_path: join_enc(&enc_parent, &hit.nc),
                nc: hit.nc,
                dir: hit.dir,
                alt_keys: Vec::new(),
            });
            break;
        }
        depth -= 1;
    }
    let mut node = match cur {
        Some(n) => n,
        None => resolve_root(state, ds)?,
    };

    // 从 depth 层继续向下钻
    for (i, seg) in segs.iter().enumerate().skip(depth) {
        if !node.dir {
            return Err(ApiError::NotFound(format!(
                "{} 不是目录",
                segs[..i].join("/")
            )));
        }
        let (nc, meta) = find_child(storage, &node.enc_path, &node.decode_keys(), seg)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {}", segs[..=i].join("/"))))?;
        let prefix = segs[..=i].join("/");
        state.cache.put(
            ds,
            &prefix,
            CachedNode {
                secret: meta.secret,
                nc: nc.clone(),
                dir: meta.is_dir,
            },
        );
        node = Resolved {
            secret: meta.secret,
            parent_key: node.secret,
            enc_path: join_enc(&node.enc_path, &nc),
            nc,
            dir: meta.is_dir,
            alt_keys: Vec::new(),
        };
    }
    Ok(node)
}

/// 由缓存拼出前缀的密文路径（调用方保证各段已缓存）。
fn enc_path_of(state: &AppState, ds: &str, segs: &[&str]) -> ApiResult<String> {
    let mut parts = Vec::with_capacity(segs.len());
    for i in 0..segs.len() {
        let prefix = segs[..=i].join("/");
        let n = state
            .cache
            .get(ds, &prefix)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("缓存缺失: {prefix}")))?;
        parts.push(n.nc);
    }
    Ok(parts.join("/"))
}

pub(crate) fn join_enc(parent_enc: &str, nc: &str) -> String {
    if parent_enc.is_empty() {
        nc.to_string()
    } else {
        format!("{parent_enc}/{nc}")
    }
}

// ---------------- 列目录 ----------------

#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

/// 列目录核心的产出：一条明文视角的目录项（Web API 与 WebDAV 共用）。
#[derive(Clone)]
pub(crate) struct ListedEntry {
    /// 明文名（外来条目为存储端原始名）。
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
    pub(crate) mtime: u64,
    /// 解不开信封的外来条目（或同名非规范副本）。
    pub(crate) foreign: bool,
    /// 文件内容的密文缓存身份（存储端路径）；目录与外来条目为 None。
    pub(crate) identity: Option<String>,
}

/// 列目录核心：解名、同名副本归一、明文分卷容器合并。排序：目录在前，名字升序。
pub(crate) async fn list_dir(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<Vec<ListedEntry>> {
    let mut entries = if !state.datasource(ds)?.managed() {
        // 非受管数据源（加密 / 分卷 / 伪装全关）：存储端就是明文原样，一个
        // 文件一个对象，名字与大小直接取用。
        storage
            .list(path)
            .await?
            .into_iter()
            .map(|e| ListedEntry {
                identity: (!e.is_dir).then(|| join_enc(path, &e.name)),
                name: e.name,
                is_dir: e.is_dir,
                size: e.size,
                mtime: e.mtime,
                foreign: false,
            })
            .collect()
    } else {
        let node = match locate_any(state, storage, ds, path).await? {
            Located::Managed(node) => {
                if !node.dir {
                    return Err(ApiError::BadRequest(format!("{path} 不是目录")));
                }
                node
            }
            // 外来目录（如转存进来的他人明文分享）：里面全是不受管的字面对象，
            // 原样列出并标为外来，不尝试解名/合卷。
            Located::Foreign {
                enc_path,
                is_dir: true,
                ..
            } => {
                let raw = storage.list(&enc_path).await?;
                let mut out = Vec::with_capacity(raw.len());
                for e in raw {
                    out.push(ListedEntry {
                        name: e.name,
                        is_dir: e.is_dir,
                        size: e.size,
                        mtime: e.mtime,
                        foreign: true,
                        identity: None,
                    });
                }
                out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
                return Ok(out);
            }
            Located::Foreign { .. } => {
                return Err(ApiError::BadRequest(format!("{path} 不是目录")));
            }
        };
        let raw = storage.list(&node.enc_path).await?;

        // 第一遍：解名并按明文名分组，同名多条（并发竞态遗留副本）时
        // nc 最小者为规范条目 —— 与 resolve/find_child 的选择规则一致。
        let decode_keys = node.decode_keys();
        let mut decoded: Vec<(crate::adapters::Entry, Option<NameMeta>)> = raw
            .into_iter()
            .map(|e| {
                let meta = if e.is_dir {
                    decode_multi(&decode_keys, &e.name)
                } else {
                    None
                };
                (e, meta)
            })
            .collect();
        let mut canonical: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (e, meta) in &decoded {
            if let Some(m) = meta {
                canonical
                    .entry(m.name.clone())
                    .and_modify(|nc| {
                        if e.name < *nc {
                            *nc = e.name.clone();
                        }
                    })
                    .or_insert_with(|| e.name.clone());
            }
        }

        let mut out = Vec::with_capacity(decoded.len());
        for (e, meta) in decoded.drain(..) {
            match meta {
                Some(m) if canonical.get(&m.name) == Some(&e.name) => {
                    // 顺手回填缓存，后续 resolve 免下钻
                    let child_path = join_enc(path, &m.name);
                    state.cache.put(
                        ds,
                        &child_path,
                        CachedNode {
                            secret: m.secret,
                            nc: e.name.clone(),
                            dir: m.is_dir,
                        },
                    );
                    let identity = (!m.is_dir).then(|| join_enc(&node.enc_path, &e.name));
                    out.push(ListedEntry {
                        name: m.name,
                        is_dir: m.is_dir,
                        size: m.size,
                        mtime: e.mtime,
                        foreign: false,
                        identity,
                    });
                }
                // 非规范副本：按外来条目暴露（原始存储名），可用 delete-foreign 清理
                Some(m) => {
                    tracing::warn!(
                        "发现同名副本（解密名 {}，存储名 {}），已按外来条目暴露",
                        m.name,
                        e.name
                    );
                    out.push(ListedEntry {
                        name: e.name,
                        is_dir: e.is_dir,
                        size: e.size,
                        mtime: e.mtime,
                        foreign: true,
                        identity: None,
                    });
                }
                None => out.push(ListedEntry {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    mtime: e.mtime,
                    foreign: true,
                    identity: None,
                }),
            }
        }
        out
    };
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    Ok(entries)
}

/// 单条目元数据（PROPFIND depth 0 等）：列父目录后按名匹配，与 list_dir
/// 的视角一致（明文分卷容器同样合并成单文件）。`""` = 数据源根。
pub(crate) async fn stat_path(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<ListedEntry> {
    if path.is_empty() {
        return Ok(ListedEntry {
            name: String::new(),
            is_dir: true,
            size: 0,
            mtime: 0,
            foreign: false,
            identity: None,
        });
    }
    let (parent, name) = parent_and_name(path);
    list_dir(state, storage, ds, parent)
        .await?
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {path}")))
}

async fn list(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&q.path)?;
    let storage = state.adapter(&ds)?;
    let live_speeds = state.transfers.snapshot().file_download_speeds;
    let entries: Vec<serde_json::Value> = list_dir(&state, storage.as_ref(), &ds, &path)
        .await?
        .into_iter()
        .map(|e| {
            if e.foreign {
                json!({
                    "name": e.name,
                    "isDir": e.is_dir,
                    "size": e.size,
                    "mtime": e.mtime,
                    "foreign": true,
                })
            } else {
                let child_path = join_enc(&path, &e.name);
                let cache = e
                    .identity
                    .as_ref()
                    .map(|id| state.content_cache.status(&crate::cache::CacheStore::key(&ds, id)));
                json!({
                    "name": e.name,
                    "isDir": e.is_dir,
                    "size": e.size,
                    "mtime": e.mtime,
                    "foreign": false,
                    "cache": cache,
                    "downloadSpeed": live_speeds.get(&format!("{ds}:{child_path}")).copied().unwrap_or(0),
                })
            }
        })
        .collect();
    Ok(Json(json!({ "entries": entries })))
}

// ---------------- 新建目录 ----------------

#[derive(Deserialize)]
struct MkdirBody {
    path: String,
}

async fn mkdir(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<MkdirBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&body.path)?;
    if path.is_empty() {
        return Err(ApiError::BadRequest("目录名不能为空".into()));
    }
    let storage = state.adapter(&ds)?;
    mkdir_path(&state, storage.as_ref(), &ds, &path).await?;
    Ok(Json(json!({ "ok": true })))
}

/// 建目录核心（含全部缺失祖先；已存在幂等成功）。API 与 WebDAV MKCOL 共用。
pub(crate) async fn mkdir_path(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<()> {
    if !state.datasource(ds)?.managed() {
        ensure_plain_dir(storage, path).await
    } else {
        ensure_dir(state, storage, ds, path).await.map(|_| ())
    }
}

/// 确保明文目录 `path` 及其所有祖先存在。
/// 全程持有数据源级 mkdir 锁：「云端判存 → mkdir」必须互斥，否则并发
/// 上传同一文件夹会各自判到「不存在」、各建一个解密后同名的加密目录。
/// 判存走 find_child（fresh list），不信缓存。
pub(crate) async fn ensure_dir(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<Resolved> {
    let lock = state.mkdir_lock(ds);
    let _guard = lock.lock().await;

    let segs: Vec<&str> = path.split('/').collect();
    let mut node = resolve_root(state, ds)?;
    for (i, seg) in segs.iter().enumerate() {
        let sub_path = segs[..=i].join("/");
        // 锁内 fresh list 判存（同名多条时取规范条目，与 resolve 一致）
        if let Some((nc, meta)) =
            find_child(storage, &node.enc_path, &node.decode_keys(), seg).await?
        {
            if !meta.is_dir {
                return Err(ApiError::BadRequest(format!("{sub_path} 已存在且是文件")));
            }
            state.cache.put(
                ds,
                &sub_path,
                CachedNode {
                    secret: meta.secret,
                    nc: nc.clone(),
                    dir: true,
                },
            );
            node = Resolved {
                secret: meta.secret,
                parent_key: node.secret,
                enc_path: join_enc(&node.enc_path, &nc),
                nc,
                dir: true,
                alt_keys: Vec::new(),
            };
            continue;
        }
        // 创建这一段
        let meta = NameMeta {
            name: seg.to_string(),
            size: 0,
            is_dir: true,
            secret: gen_secret(),
        };
        let nc = encode_name(&node.secret, &meta)
            .ok_or_else(|| ApiError::BadRequest(format!("目录名过长: {seg}")))?;
        let enc_path = join_enc(&node.enc_path, &nc);
        storage.mkdir(&enc_path).await?;
        state.cache.put(
            ds,
            &sub_path,
            CachedNode {
                secret: meta.secret,
                nc: nc.clone(),
                dir: true,
            },
        );
        node = Resolved {
            secret: meta.secret,
            parent_key: node.secret,
            enc_path,
            nc,
            dir: true,
            alt_keys: Vec::new(),
        };
    }
    Ok(node)
}

// ---------------- 重命名 / 移动 ----------------

#[derive(Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

async fn rename(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<RenameBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let from = sanitize(&body.from)?;
    let to = sanitize(&body.to)?;
    let storage = state.adapter(&ds)?;
    rename_path(&state, storage.as_ref(), &ds, &from, &to).await?;
    Ok(Json(json!({ "ok": true })))
}

/// 重命名/移动核心（目标已存在会拒绝）。API 与 WebDAV MOVE 共用。
pub(crate) async fn rename_path(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    from: &str,
    to: &str,
) -> ApiResult<()> {
    if from.is_empty() || to.is_empty() {
        return Err(ApiError::BadRequest("非法重命名路径".into()));
    }
    if to == from || to.starts_with(&format!("{from}/")) {
        return Err(ApiError::BadRequest("不能移动到自身或其子目录".into()));
    }
    if !state.datasource(ds)?.managed() {
        let (_, actual_from) = plain_locate(storage, from).await?;
        let (to_parent, _) = parent_and_name(to);
        ensure_plain_dir(storage, to_parent).await?;
        if plain_locate(storage, to).await.is_ok() {
            return Err(ApiError::BadRequest("目标名称已存在".into()));
        }
        storage.rename(&actual_from, to).await?;
        return Ok(());
    }
    // 受管数据源：外来对象只按字面存储名整体搬运，仍保持外来身份；只有受管
    // 条目才走「换父钥重编码信封」的零重加密 rename。
    let node = match locate_any(state, storage, ds, from).await? {
        Located::Managed(node) => node,
        Located::Foreign { enc_path, .. } => {
            let (to_parent, to_name) = parent_and_name(to);
            let (parent_enc, parent_is_dir) =
                match locate_any(state, storage, ds, to_parent).await? {
                    Located::Managed(n) => (n.enc_path, n.dir),
                    Located::Foreign {
                        enc_path, is_dir, ..
                    } => (enc_path, is_dir),
                };
            if !parent_is_dir {
                return Err(ApiError::BadRequest(format!("{to_parent} 不是目录")));
            }
            if storage
                .list(&parent_enc)
                .await?
                .iter()
                .any(|entry| entry.name == to_name)
            {
                return Err(ApiError::BadRequest("目标名称已存在".into()));
            }
            storage
                .rename(&enc_path, &join_enc(&parent_enc, to_name))
                .await?;
            state.cache.evict_subtree(ds, from);
            return Ok(());
        }
    };
    // size 缓存路径下拿不到，从 nc 解出（decode 必然成功——刚 resolve 过）
    let old_meta = decode_name(&node.parent_key, &node.nc)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法解码 {from} 的密文名")))?;

    // 目标父目录必须已存在且是目录
    let to_parent = to.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let target_parent = resolve(state, storage, ds, to_parent).await?;
    if !target_parent.dir {
        return Err(ApiError::BadRequest(format!("{to_parent} 不是目录")));
    }
    // 目标名不能已存在
    if resolve(state, storage, ds, to).await.is_ok() {
        return Err(ApiError::BadRequest("目标名称已存在".into()));
    }

    // 密钥入名的核心收益：换父钥重编码信封（secret 原样带走），
    // 一次存储端 rename，子孙锚在 secret 上完全不动。
    let new_last = to.rsplit('/').next().expect("非空路径必有末段");
    let new_meta = NameMeta {
        name: new_last.to_string(),
        size: old_meta.size,
        is_dir: node.dir,
        secret: node.secret,
    };
    let new_nc = encode_name(&target_parent.secret, &new_meta)
        .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {new_last}")))?;
    let enc_to = join_enc(&target_parent.enc_path, &new_nc);

    storage.rename(&node.enc_path, &enc_to).await?;
    // 缓存：旧子树全部失效（enc 路径变了），新位置回填根节点
    state.cache.evict_subtree(ds, from);
    state.cache.put(
        ds,
        to,
        CachedNode {
            secret: node.secret,
            nc: new_nc,
            dir: node.dir,
        },
    );
    Ok(())
}

// ---------------- 删除 ----------------

#[derive(Deserialize)]
struct DeleteBody {
    path: String,
}

async fn delete(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<DeleteBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&body.path)?;
    let storage = state.adapter(&ds)?;
    delete_path(&state, storage.as_ref(), &ds, &path).await?;
    Ok(Json(json!({ "ok": true })))
}

/// 删除核心（文件或整棵目录）。API 与 WebDAV DELETE 共用。
pub(crate) async fn delete_path(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<()> {
    if path.is_empty() {
        return Err(ApiError::BadRequest("不允许删除根目录".into()));
    }
    if !state.datasource(ds)?.managed() {
        let (_, actual) = plain_locate(storage, path).await?;
        storage.delete(&actual).await?;
        return Ok(());
    }
    // 受管条目走信封解析后按 enc_path 删；外来对象按字面存储名删。
    match locate_any(state, storage, ds, path).await? {
        Located::Managed(node) => {
            match storage.delete(&node.enc_path).await {
                Ok(()) | Err(ApiError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
            state.cache.evict_subtree(ds, path);
        }
        Located::Foreign { enc_path, .. } => match storage.delete(&enc_path).await {
            Ok(()) | Err(ApiError::NotFound(_)) => {}
            Err(e) => return Err(e),
        },
    }
    Ok(())
}

#[derive(Deserialize)]
struct DeleteForeignBody {
    /// 外来条目所在的明文目录（"" = 根）。
    path: String,
    /// 存储端原始名字。
    name: String,
}

async fn delete_foreign(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<DeleteForeignBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = sanitize(&body.path)?;
    let name = body.name.trim();
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(ApiError::BadRequest("非法名称".into()));
    }
    let storage = state.adapter(&ds)?;
    match locate_any(&state, storage.as_ref(), &ds, &dir).await? {
        Located::Managed(parent) => {
            if !parent.dir {
                return Err(ApiError::BadRequest(format!("{dir} 不是目录")));
            }
            // 允许删除：解不开的真外来条目，或解得开但非规范的同名副本；
            // 只保护规范条目本身（请走常规删除）。
            if let Some(m) = decode_multi(&parent.decode_keys(), name) {
                let canonical = find_child(
                    storage.as_ref(),
                    &parent.enc_path,
                    &parent.decode_keys(),
                    &m.name,
                )
                .await?
                .map(|(nc, _)| nc);
                if canonical.as_deref() == Some(name) {
                    return Err(ApiError::BadRequest(
                        "该条目是受管数据，请用常规删除".into(),
                    ));
                }
            }
            storage.delete(&join_enc(&parent.enc_path, name)).await?;
        }
        // 外来目录里全是不受管的字面对象，按名直删即可。
        Located::Foreign {
            enc_path,
            is_dir: true,
            ..
        } => {
            storage.delete(&join_enc(&enc_path, name)).await?;
        }
        Located::Foreign { .. } => {
            return Err(ApiError::BadRequest(format!("{dir} 不是目录")));
        }
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AdoptForeignBody {
    /// 外来条目所在的明文目录（"" = 根）。
    path: String,
    /// 存储端原始名字。
    name: String,
    /// 该条目原加密链路的密码（原数据源密码；或 base64 的 16 字节目录 FK）。
    password: String,
}

/// 解密外来条目并纳入当前链路：用输入密码（f_key）解开信封拿到明文名
/// 与节点 secret，再换当前目录的链路密钥重编码名字 —— 一次存储端
/// rename，secret 原样带走，内容零重加密（与跨目录移动同一机制）。
/// 典型场景：手动转存他人分享的加密文件后按外来条目显示，输入对方
/// 密码即可在本数据源正常呈现。密码不对 → 400，不做任何 rename。
async fn adopt_foreign(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Json(body): Json<AdoptForeignBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = sanitize(&body.path)?;
    let name = body.name.trim();
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(ApiError::BadRequest("非法名称".into()));
    }
    let password = body.password.trim();
    if password.is_empty() {
        return Err(ApiError::BadRequest("请输入该条目的加密密码".into()));
    }
    let storage = state.adapter(&ds)?;
    let parent = resolve(&state, storage.as_ref(), &ds, &dir).await?;
    if !parent.dir {
        return Err(ApiError::BadRequest(format!("{dir} 不是目录")));
    }
    let parent_keys = parent.decode_keys();
    let entries = storage.list(&parent.enc_path).await?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| ApiError::NotFound(format!("外来条目不存在: {name}")))?;
    if !entry.is_dir {
        return Err(ApiError::BadRequest(
            "该条目不是受管加密格式（缺少分卷文件夹），无法解密".into(),
        ));
    }
    if decode_multi(&parent_keys, name).is_some() {
        return Err(ApiError::BadRequest(
            "该条目已可用当前链路密码解密，无需操作".into(),
        ));
    }

    // 输入密码 → 候选密钥：按数据源根密码派生；若输入本身是 base64 的
    // 16 字节密钥（分享包 secret 的格式，对应非根目录的 FK）也直接试。
    let mut keys = vec![crate::crypto::derive_root_key(password.as_bytes())];
    if let Some(fk) = B64
        .decode(password)
        .ok()
        .and_then(|bytes| <[u8; SECRET_LEN]>::try_from(bytes).ok())
    {
        keys.push(fk);
    }
    let meta = decode_multi(&keys, name)
        .ok_or_else(|| ApiError::BadRequest("密码不正确，无法解密该条目".into()))?;

    // 解密名与现有受管条目冲突则拒绝（rename 后两条会争同一明文名）
    if entries
        .iter()
        .filter(|e| e.is_dir)
        .any(|e| decode_multi(&parent_keys, &e.name).is_some_and(|m| m.name == meta.name))
    {
        return Err(ApiError::BadRequest(format!(
            "当前目录已存在同名条目: {}",
            meta.name
        )));
    }

    // 换父钥重编码信封（secret 不变）→ 一次 rename 纳入当前链路
    let new_nc = encode_name(&parent.secret, &meta)
        .ok_or_else(|| ApiError::BadRequest(format!("名称过长: {}", meta.name)))?;
    storage
        .rename(
            &join_enc(&parent.enc_path, name),
            &join_enc(&parent.enc_path, &new_nc),
        )
        .await?;
    state.cache.put(
        &ds,
        &join_enc(&dir, &meta.name),
        CachedNode {
            secret: meta.secret,
            nc: new_nc,
            dir: meta.is_dir,
        },
    );
    Ok(Json(
        json!({ "ok": true, "name": meta.name, "isDir": meta.is_dir }),
    ))
}

async fn cache_identity(
    state: &AppState,
    storage: &dyn crate::adapters::Storage,
    ds: &str,
    path: &str,
) -> ApiResult<(String, u64)> {
    let cfg = state.datasource(ds)?;
    if cfg.managed() {
        let node = resolve(state, storage, ds, path).await?;
        if node.dir {
            return Err(ApiError::BadRequest("目录没有文件缓存".into()));
        }
        let meta = decode_name(&node.parent_key, &node.nc)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法读取文件元数据")))?;
        Ok((node.enc_path, meta.size))
    } else {
        let (entry, actual) = plain_locate(storage, path).await?;
        if entry.is_dir {
            return Err(ApiError::BadRequest("目录没有文件缓存".into()));
        }
        Ok((actual, entry.size))
    }
}

async fn file_cache_status(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<crate::cache::FileCacheStatus>> {
    let path = sanitize(&q.path)?;
    let storage = state.adapter(&ds)?;
    let (identity, _) = cache_identity(&state, storage.as_ref(), &ds, &path).await?;
    Ok(Json(
        state
            .content_cache
            .status(&crate::cache::CacheStore::key(&ds, &identity)),
    ))
}

async fn file_cache_clear(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&q.path)?;
    let storage = state.adapter(&ds)?;
    let (identity, _) = cache_identity(&state, storage.as_ref(), &ds, &path).await?;
    let freed = state
        .content_cache
        .clear(&crate::cache::CacheStore::key(&ds, &identity))?;
    Ok(Json(json!({"ok":true,"freed":freed})))
}

async fn file_cache_warm(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&q.path)?;
    let cfg = state.datasource(&ds)?;
    let transfer = state.settings.get();
    if !cfg.cache_enabled || !transfer.cache_enabled {
        return Err(ApiError::BadRequest("该数据源或全局缓存当前已关闭".into()));
    }
    let storage = state.adapter_arc(&ds)?;
    let disguise = Disguise::of(&cfg);
    let (folder, secret, encrypted, layout, identity) = if cfg.managed() {
        let node = resolve(&state, storage.as_ref(), &ds, &path).await?;
        if node.dir {
            return Err(ApiError::BadRequest("目录不能加入文件缓存".into()));
        }
        let meta = decode_name(&node.parent_key, &node.nc)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法读取文件元数据")))?;
        let identity = node.enc_path.clone();
        let layout_key = crate::cache::CacheStore::key(&ds, &identity);
        let layout = load_stream_layout(
            &state,
            &layout_key,
            storage.as_ref(),
            &node.enc_path,
            engine::LeafNaming {
                format: &cfg.leaf_name_format,
                source: &meta.name,
                pw: &node.secret,
                disguise,
            },
            meta.size,
        )
        .await?;
        // 预热会把拉到的密文写进持久缓存，错位的数据一旦落盘就会长期生效 ——
        // 这里必须和 stream_file 用同一把尺子。
        check_layout_total(&layout, meta.size, disguise)?;
        (
            node.enc_path.clone(),
            node.secret,
            cfg.encryption_enabled,
            layout,
            identity,
        )
    } else {
        let (entry, actual) = plain_locate(storage.as_ref(), &path).await?;
        if entry.is_dir {
            return Err(ApiError::BadRequest("目录不能加入文件缓存".into()));
        }
        let (parent, name) = parent_and_name(&actual);
        let layout = Arc::new(engine::FileLayout {
            total: entry.size,
            volumes: vec![engine::VolumeMeta {
                name: name.into(),
                size: entry.size,
                offset: 0,
            }],
        });
        (parent.to_string(), [0u8; SECRET_LEN], false, layout, actual)
    };
    let total = layout.total;
    let key = crate::cache::CacheStore::key(&ds, &identity);
    let cache = state.content_cache.open(&key, total)?;
    if total == 0 || state.content_cache.status(&key).complete {
        return Ok(Json(json!({"ok":true,"complete":true})));
    }
    // 注册预热任务；同文件已有任务在跑则幂等返回，避免重复拉流。
    let Some(guard) = state.content_cache.begin_warm(&key) else {
        return Ok(Json(json!({"ok":true,"complete":false,"warming":true})));
    };
    let tracker = Arc::clone(&state.transfers);
    let transfer_key = format!("{ds}:{path}");
    let progress: crate::adapters::ProgressFn = Arc::new(move |n| {
        tracker.download(transfer_key.clone(), n);
    });
    let mut rx = engine::stream_range_cached_mode(
        storage,
        folder,
        secret,
        encrypted,
        disguise,
        layout,
        0,
        total - 1,
        false,
        &StreamParams {
            max_split: transfer.max_split,
            max_threads: transfer.max_threads,
            max_per_volume: transfer.max_per_volume,
            mode: StreamMode::CacheWarm,
        },
        Some(cache),
        Some(progress),
    );
    tokio::spawn(async move {
        // guard 随任务结束（含被停止）Drop，注销 warming 状态。
        loop {
            tokio::select! {
                _ = guard.cancelled() => {
                    // 丢弃 rx 即模拟客户端断开：serializer 发送失败 → 通知
                    // 调度器 abort 所有 in-flight fetcher，下载立即停止。
                    tracing::info!("停止后台缓存: ds={ds} path={path}");
                    break;
                }
                item = rx.recv() => match item {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        tracing::warn!("后台缓存文件失败: ds={ds} path={path} err={error}");
                        break;
                    }
                    None => break,
                }
            }
        }
    });
    Ok(Json(json!({"ok":true,"complete":false,"warming":true})))
}

/// 停止手动触发的文件缓存（预热）任务。只关掉「主动预热」这一个触发条件：
/// 已缓存数据保留、可再次触发续传；播放/下载经过服务器代理时（缓存开关
/// 开启的前提下）仍会继续写透缓存。
async fn file_cache_warm_stop(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<PathQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&q.path)?;
    let storage = state.adapter(&ds)?;
    let (identity, _) = cache_identity(&state, storage.as_ref(), &ds, &path).await?;
    let stopped = state
        .content_cache
        .stop_warm(&crate::cache::CacheStore::key(&ds, &identity));
    Ok(Json(json!({"ok":true,"stopped":stopped})))
}

// ---------------- 上传 ----------------

#[derive(Deserialize)]
struct UploadQuery {
    /// 明文全路径（含文件名），如 "电影/2026/a.mp4"。
    path: String,
    /// 明文总字节数（分卷计划需要预知）。
    size: u64,
    /// 进度 ID（前端生成的随机串）；提供后可轮询
    /// GET /api/uploads/{id}/progress 获取加密/上传双维度进度。
    #[serde(default)]
    progress: Option<String>,
}

/// 查询进行中上传的双维度进度。上传结束（成功或失败）后条目即移除，
/// 此后返回 404 —— 前端以上传请求本身的结束为准。
async fn upload_progress(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let progress = state
        .upload_progress
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("上传进度不存在: {id}")))?;
    Ok(Json(json!({
        "total": progress.total,
        "encrypted": progress.encrypted.load(std::sync::atomic::Ordering::Relaxed),
        "uploaded": progress.uploaded.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

async fn upload(
    State(state): State<AppState>,
    Path(ds): Path<String>,
    Query(q): Query<UploadQuery>,
    request: Request,
) -> ApiResult<Json<serde_json::Value>> {
    let path = sanitize(&q.path)?;
    if path.is_empty() {
        return Err(ApiError::BadRequest("文件路径不能为空".into()));
    }

    // 双维度进度：注册到 state 供 /api/uploads/{id}/progress 轮询
    let progress = Arc::new(engine::UploadProgress::tracked(
        q.size,
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
    let progress_id = q
        .progress
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    if let Some(id) = progress_id {
        state
            .upload_progress
            .lock()
            .unwrap()
            .insert(id.to_string(), Arc::clone(&progress));
    }
    let _progress_guard = ProgressGuard(&state, progress_id.map(str::to_owned));

    let body = request
        .into_body()
        .into_data_stream()
        .map_err(std::io::Error::other);
    let volumes = upload_file(&state, &ds, &path, q.size, false, Box::pin(body), progress).await?;
    Ok(Json(json!({ "ok": true, "volumes": volumes })))
}

/// 上传核心：并发防线、建缺失目录、判存（`overwrite` 为 true 时先删同名
/// 旧文件——WebDAV PUT 语义）、分卷（加密）写入，失败尽力清理半成品。
/// 返回分卷数。API 上传与 WebDAV PUT/COPY 共用。
pub(crate) async fn upload_file<S>(
    state: &AppState,
    ds: &str,
    path: &str,
    size: u64,
    overwrite: bool,
    body: S,
    progress: Arc<engine::UploadProgress>,
) -> ApiResult<usize>
where
    S: futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Unpin + Send,
{
    let datasource = state.datasource(ds)?;
    let storage = state.adapter_arc(ds)?;

    let (parent, file_name) = match path.rsplit_once('/') {
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), path.to_string()),
    };

    // 并发防线：同一路径同时只允许一个上传
    let upload_key = format!("{ds}:{path}");
    if !state.uploading.lock().unwrap().insert(upload_key.clone()) {
        return Err(ApiError::BadRequest(format!("该文件正在上传中: {path}")));
    }
    struct UploadingGuard<'a>(&'a AppState, String);
    impl Drop for UploadingGuard<'_> {
        fn drop(&mut self) {
            self.0.uploading.lock().unwrap().remove(&self.1);
        }
    }
    let _uploading_guard = UploadingGuard(state, upload_key);

    if !datasource.managed() {
        // 非受管：一个文件就是一个明文名对象，没有容器也没有分卷。
        ensure_plain_dir(storage.as_ref(), &parent).await?;
        match plain_locate(storage.as_ref(), path).await {
            Ok((entry, actual)) => {
                if !overwrite {
                    return Err(ApiError::BadRequest(format!("已存在同名条目: {path}")));
                }
                if entry.is_dir {
                    return Err(ApiError::BadRequest(format!("已存在同名目录: {path}")));
                }
                storage.delete(&actual).await?;
            }
            Err(ApiError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        let result = engine::upload_stream_planned(
            Arc::clone(&storage),
            &parent,
            &[0u8; SECRET_LEN],
            false,
            Disguise::None,
            size,
            &[size],
            std::slice::from_ref(&file_name),
            body,
            Arc::clone(&progress),
        )
        .await;
        if let Err(e) = result {
            let _ = storage.delete(path).await;
            return Err(e);
        }
        return Ok(1);
    }

    // 文件夹上传：自动创建缺失的中间目录
    let parent_node = if parent.is_empty() {
        resolve_root(state, ds)?
    } else {
        ensure_dir(state, storage.as_ref(), ds, &parent).await?
    };
    // 同名检查（云端为准）；覆盖模式下先删旧文件
    match resolve(state, storage.as_ref(), ds, path).await {
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

    // v5：秘密装在名字里，mkdir 即自洽 —— 无「先记密码本」顺序问题，
    // 失败清理也只需删存储端文件夹（没有会变孤儿的密钥记录）。
    let pw = gen_secret();
    let nc = encode_name(
        &parent_node.secret,
        &NameMeta {
            name: file_name.clone(),
            size,
            is_dir: false,
            secret: pw,
        },
    )
    .ok_or_else(|| ApiError::BadRequest(format!("文件名过长: {file_name}")))?;
    let enc_folder = join_enc(&parent_node.enc_path, &nc);

    let disguise = Disguise::of(&datasource);
    let sizes = volume_plan(
        size,
        datasource.volume_enabled,
        datasource.volume_size,
        disguise.header_len(),
        &datasource.volume_strategy,
    );
    // 叶子名由数据源模版决定：`{s}` 明文名、`{e}` 文件密钥派生的索引凭据、
    // `{i}` 等宽序号（见 crate::naming）。
    let names =
        crate::naming::leaf_names(&datasource.leaf_name_format, &file_name, &pw, sizes.len());

    let result: ApiResult<()> = async {
        storage.mkdir(&enc_folder).await?;
        engine::upload_stream_planned(
            Arc::clone(&storage),
            &enc_folder,
            &pw,
            datasource.encryption_enabled,
            disguise,
            size,
            &sizes,
            &names,
            body,
            Arc::clone(&progress),
        )
        .await
    }
    .await;

    if let Err(e) = result {
        // 锚点日志：适配器层已记录请求参数与原始响应，这里给出任务全貌
        tracing::error!(
            "上传失败: ds={ds} path={path} size={size} max_volume_size={} 分卷数={} 已加密={} 已确认上传={} err={e}",
            datasource.volume_size,
            names.len(),
            progress
                .encrypted
                .load(std::sync::atomic::Ordering::Relaxed),
            progress.uploaded.load(std::sync::atomic::Ordering::Relaxed),
        );
        // 失败/取消：尽力清掉半成品（清不掉也只是留下可再删的密文垃圾）
        if let Err(del_err) = storage.delete(&enc_folder).await
            && !matches!(del_err, ApiError::NotFound(_))
        {
            tracing::warn!("上传失败后清理 {enc_folder} 也失败: {del_err}");
        }
        return Err(e);
    }
    state.cache.put(
        ds,
        path,
        CachedNode {
            secret: pw,
            nc,
            dir: false,
        },
    );
    Ok(names.len())
}

// ---------------- 流式下载 / 播放 ----------------

#[derive(Deserialize)]
struct StreamQuery {
    #[serde(default)]
    dl: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// /stream 鉴权：免登录模式直接放行；否则 Bearer 头或 ?token= 任一有效。
fn check_stream_auth(state: &AppState, headers: &HeaderMap, token: Option<&str>) -> ApiResult<()> {
    if state.admin_password.is_none() {
        return Ok(());
    }
    let header_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let candidate = header_token.or(token).unwrap_or("");
    if !candidate.is_empty() && state.sessions.read().unwrap().contains(candidate) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

async fn stream(
    State(state): State<AppState>,
    Path((ds, path)): Path<(String, String)>,
    Query(q): Query<StreamQuery>,
    method: Method,
    headers: HeaderMap,
) -> ApiResult<Response> {
    check_stream_auth(&state, &headers, q.token.as_deref())?;
    let path = sanitize(&path)?;
    stream_file(&state, &ds, &path, q.dl.is_some(), method, &headers).await
}

/// 流式下载核心（Range/HEAD/写透缓存）。/stream 与 WebDAV GET 共用；
/// 调用方负责鉴权与路径 sanitize。
pub(crate) async fn stream_file(
    state: &AppState,
    ds: &str,
    path: &str,
    download: bool,
    method: Method,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let storage = state.adapter_arc(ds)?;
    let datasource = state.datasource(ds)?;
    if !datasource.managed() {
        return stream_plain(state, storage, ds, path, download, method, headers).await;
    }
    let node = match resolve(state, storage.as_ref(), ds, path).await {
        Ok(node) => node,
        // 解不开信封的明文外来文件（如转存进来的他人明文分享）按字节直传，照常可用。
        Err(ApiError::NotFound(_)) => {
            return stream_foreign_plain(state, storage, ds, path, download, method, headers).await;
        }
        Err(e) => return Err(e),
    };
    if node.dir {
        return Err(ApiError::BadRequest("不能下载目录".into()));
    }
    let meta = decode_name(&node.parent_key, &node.nc)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("无法解码 {path} 的密文名")))?;
    let transfer = state.settings.get();
    let disguise = Disguise::of(&datasource);
    let enc_folder = node.enc_path.clone();

    // PotPlayer 起播和 seek 会连续建立 Range 连接。布局探测需要一次云端
    // list，复用 Hydraria 的 probe-cache 思路，避免缓存命中时仍卡在探测上。
    let layout_key = crate::cache::CacheStore::key(ds, &enc_folder);
    let layout = load_stream_layout(
        state,
        &layout_key,
        storage.as_ref(),
        &enc_folder,
        engine::LeafNaming {
            format: &datasource.leaf_name_format,
            source: &meta.name,
            pw: &node.secret,
            disguise,
        },
        meta.size,
    )
    .await?;
    check_layout_total(&layout, meta.size, disguise)?;
    let total = layout.total;

    let file_name = meta.name;
    let mime = mime_guess::from_path(&file_name).first_or_octet_stream();
    let disposition = if download { "attachment" } else { "inline" };
    let encoded_name = utf8_percent_encode(&file_name, NON_ALPHANUMERIC).to_string();

    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let (spec, open_ended) = engine::parse_range(range_header, total);

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, mime.essence_str())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("{disposition}; filename*=UTF-8''{encoded_name}"),
        );

    let (status, start, end) = match spec {
        RangeSpec::Unsatisfiable => {
            return builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{total}"))
                .body(Body::empty())
                .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)));
        }
        RangeSpec::Full => (StatusCode::OK, 0, total.saturating_sub(1)),
        RangeSpec::Slice { start, end } => {
            builder = builder.header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total}"),
            );
            (StatusCode::PARTIAL_CONTENT, start, end)
        }
    };
    let length = if total == 0 { 0 } else { end - start + 1 };
    builder = builder
        .status(status)
        .header(header::CONTENT_LENGTH, length);

    if method == Method::HEAD || total == 0 {
        return builder
            .body(Body::empty())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)));
    }

    let content_cache = if transfer.cache_enabled && datasource.cache_enabled {
        let key = crate::cache::CacheStore::key(ds, &enc_folder);
        match state.content_cache.open(&key, total) {
            Ok(cache) => Some(cache),
            Err(e) => {
                tracing::warn!("打开全局密文缓存失败，本次直接回源: {e}");
                None
            }
        }
    } else {
        None
    };
    let tracker = Arc::clone(&state.transfers);
    let transfer_key = format!("{ds}:{path}");
    let network_progress: crate::adapters::ProgressFn = Arc::new(move |n| {
        tracker.download(transfer_key.clone(), n);
    });
    let rx = engine::stream_range_cached_mode(
        storage,
        enc_folder,
        node.secret,
        datasource.encryption_enabled,
        disguise,
        layout,
        start,
        end,
        open_ended,
        &StreamParams {
            max_split: transfer.max_split,
            max_threads: transfer.max_threads,
            max_per_volume: transfer.max_per_volume,
            mode: if download {
                StreamMode::BulkDownload
            } else {
                StreamMode::Playback
            },
        },
        content_cache,
        Some(network_progress),
    );
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    builder
        .body(body)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))
}

#[allow(clippy::too_many_arguments)]
/// 校验云端分卷总大小与信封里记录的明文大小一致。
///
/// 差值恰好是「卷数 × 伪装头部长度」时，说明这些卷根本没有本数据源的伪装
/// 头部（多半是外部直接写入、或从没开伪装的地方搬来的）—— 指名道姓报出来，
/// 别让用户拿着「数据可能被外部修改」去猜。
pub(crate) fn check_layout_total(
    layout: &engine::FileLayout,
    expected: u64,
    disguise: Disguise,
) -> ApiResult<()> {
    if layout.total == expected {
        return Ok(());
    }
    let missing = disguise.header_len() * layout.volumes.len() as u64;
    if missing > 0 && layout.total + missing == expected {
        return Err(ApiError::Upstream(format!(
            "该文件的 {} 个分卷没有本数据源的伪装头部（少了 {missing} 字节），无法按伪装解析；它多半来自未启用伪装的数据源，或被外部工具直接写入",
            layout.volumes.len(),
        )));
    }
    Err(ApiError::Upstream(format!(
        "云端分卷总大小 {} 与记录 {expected} 不符（数据可能被外部修改）",
        layout.total,
    )))
}

async fn load_stream_layout(
    state: &AppState,
    key: &str,
    storage: &dyn crate::adapters::Storage,
    enc_folder: &str,
    naming: engine::LeafNaming<'_>,
    expected_total: u64,
) -> ApiResult<Arc<engine::FileLayout>> {
    if let Some(layout) = state.cached_layout(key)
        && layout.total == expected_total
    {
        tracing::debug!("stream layout cache HIT key={key}");
        return Ok(layout);
    }

    // Double-check under a per-file lock: PotPlayer commonly sends several
    // initial Range probes concurrently and only the first one should list.
    let probe_lock = state.layout_probe_lock(key);
    let _guard = probe_lock.lock().await;
    if let Some(layout) = state.cached_layout(key)
        && layout.total == expected_total
    {
        tracing::debug!("stream layout cache HIT after inflight wait key={key}");
        return Ok(layout);
    }

    let layout = Arc::new(engine::load_layout(storage, enc_folder, naming).await?);
    state.put_cached_layout(key.to_string(), Arc::clone(&layout));
    tracing::debug!(
        "stream layout cache MISS key={key} total={} volumes={}",
        layout.total,
        layout.volumes.len()
    );
    Ok(layout)
}

async fn stream_plain(
    state: &AppState,
    storage: Arc<dyn crate::adapters::Storage>,
    ds: &str,
    path: &str,
    download: bool,
    method: Method,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let (entry, actual) = plain_locate(storage.as_ref(), path).await?;
    if entry.is_dir {
        return Err(ApiError::BadRequest("不能下载目录".into()));
    }
    // 走到这里的数据源必然非受管（`stream_file` 已按 managed 分流）：存储端就是
    // 明文原样的单个对象，没有容器、没有分卷、也没有伪装头部可剥。
    let (parent, name) = parent_and_name(&actual);
    let enc_folder = parent.to_string();
    let layout = Arc::new(engine::FileLayout {
        volumes: vec![engine::VolumeMeta {
            name: name.to_string(),
            size: entry.size,
            offset: 0,
        }],
        total: entry.size,
    });
    serve_object(
        state,
        storage,
        ds,
        ServeObject {
            cache_key: &actual,
            enc_folder,
            layout,
            secret: [0u8; SECRET_LEN],
            encrypted: false,
            disguise: Disguise::None,
            display_name: parent_and_name(path).1,
            transfer_key: format!("{ds}:{path}"),
            download,
        },
        method,
        headers,
    )
    .await
}

/// 受管数据源里解不开信封的**外来文件**（例如转存进来的他人明文分享，可能
/// 还嵌在外来目录里）：定位存储端原始对象后按字节直传 —— 不解密、也不脱
/// 伪装（它不是 SafeDrive 写的），照常支持 Range / 预览 / 下载。
async fn stream_foreign_plain(
    state: &AppState,
    storage: Arc<dyn crate::adapters::Storage>,
    ds: &str,
    path: &str,
    download: bool,
    method: Method,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let (enc_path, size) = match locate_any(state, storage.as_ref(), ds, path).await? {
        Located::Foreign {
            enc_path,
            is_dir: false,
            size,
        } => (enc_path, size),
        Located::Foreign { is_dir: true, .. } => {
            return Err(ApiError::BadRequest("不能下载目录".into()));
        }
        // resolve 已失败才会走到这里；受管对象不应再落到外来分支
        Located::Managed(_) => {
            return Err(ApiError::NotFound(format!("路径不存在: {path}")));
        }
    };
    let (parent_enc, raw_name) = parent_and_name(&enc_path);
    let layout = Arc::new(engine::FileLayout {
        volumes: vec![engine::VolumeMeta {
            name: raw_name.to_string(),
            size,
            offset: 0,
        }],
        total: size,
    });
    serve_object(
        state,
        storage,
        ds,
        ServeObject {
            cache_key: &enc_path,
            enc_folder: parent_enc.to_string(),
            layout,
            secret: [0u8; SECRET_LEN],
            encrypted: false,
            // 外来对象不是 SafeDrive 写的，没有伪装头部可剥。
            disguise: Disguise::None,
            display_name: parent_and_name(path).1,
            transfer_key: format!("{ds}:{path}"),
            download,
        },
        method,
        headers,
    )
    .await
}

/// 单对象服务参数：把「哪个对象、怎么解密、怎么展示」打成一包，避免函数入参过多。
struct ServeObject<'a> {
    /// 内容缓存身份（存储端路径）。
    cache_key: &'a str,
    /// 分卷所在的存储端文件夹。
    enc_folder: String,
    layout: Arc<engine::FileLayout>,
    /// 解密密钥；明文 / 外来对象传全零并配 `encrypted=false`。
    secret: [u8; SECRET_LEN],
    encrypted: bool,
    /// 存储对象上的伪装头部；外来对象传 `Disguise::None`。
    disguise: Disguise,
    /// 展示名（决定 MIME 与下载文件名）。
    display_name: &'a str,
    /// 下行进度上报键。
    transfer_key: String,
    download: bool,
}

/// 按既定分卷布局把一个存储端对象作为 HTTP 响应吐出（Range/HEAD/写透缓存）。
/// 明文直传与外来明文文件共用；`secret` / `encrypted` 决定引擎是否解密。
async fn serve_object(
    state: &AppState,
    storage: Arc<dyn crate::adapters::Storage>,
    ds: &str,
    serve: ServeObject<'_>,
    method: Method,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let total = serve.layout.total;
    let mime = mime_guess::from_path(serve.display_name).first_or_octet_stream();
    let disposition = if serve.download {
        "attachment"
    } else {
        "inline"
    };
    let encoded_name = utf8_percent_encode(serve.display_name, NON_ALPHANUMERIC).to_string();
    let (spec, open_ended) = engine::parse_range(
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
        total,
    );
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, mime.essence_str())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("{disposition}; filename*=UTF-8''{encoded_name}"),
        );
    let (status, start, end) = match spec {
        RangeSpec::Unsatisfiable => {
            return builder
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{total}"))
                .body(Body::empty())
                .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)));
        }
        RangeSpec::Full => (StatusCode::OK, 0, total.saturating_sub(1)),
        RangeSpec::Slice { start, end } => {
            builder = builder.header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total}"),
            );
            (StatusCode::PARTIAL_CONTENT, start, end)
        }
    };
    let length = if total == 0 { 0 } else { end - start + 1 };
    builder = builder
        .status(status)
        .header(header::CONTENT_LENGTH, length);
    if method == Method::HEAD || total == 0 {
        return builder
            .body(Body::empty())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)));
    }
    let transfer = state.settings.get();
    let ds_cfg = state.datasource(ds)?;
    let cache = if transfer.cache_enabled && ds_cfg.cache_enabled {
        let key = crate::cache::CacheStore::key(ds, serve.cache_key);
        state.content_cache.open(&key, total).ok()
    } else {
        None
    };
    let tracker = Arc::clone(&state.transfers);
    let transfer_key = serve.transfer_key;
    let progress: crate::adapters::ProgressFn = Arc::new(move |n| {
        tracker.download(transfer_key.clone(), n);
    });
    let rx = engine::stream_range_cached_mode(
        storage,
        serve.enc_folder,
        serve.secret,
        serve.encrypted,
        serve.disguise,
        serve.layout,
        start,
        end,
        open_ended,
        &StreamParams {
            max_split: transfer.max_split,
            max_threads: transfer.max_threads,
            max_per_volume: transfer.max_per_volume,
            mode: if serve.download {
                StreamMode::BulkDownload
            } else {
                StreamMode::Playback
            },
        },
        cache,
        Some(progress),
    );
    builder
        .body(Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn random_plan_keeps_fixed_count_and_maximum() {
        let total = 10 * 1024 * 1024 + 7;
        let max = 3 * 1024 * 1024;
        for _ in 0..32 {
            let plan = volume_plan(total, true, max, 0, "random");
            assert_eq!(plan.len(), total.div_ceil(max) as usize);
            assert_eq!(plan.iter().sum::<u64>(), total);
            assert!(plan.iter().all(|size| *size > 0 && *size <= max));
        }
    }

    /// 「最大分卷大小」是对**实际存储对象**的硬限制：开了伪装时，数据区上限
    /// 相应缩到 `max - 54`，落地对象才恰好不超过用户配置的值。
    #[test]
    fn disguise_header_counts_against_the_volume_limit() {
        const HEADER: u64 = 54;
        let max = 100 * 1024 * 1024;
        let total = 250 * 1024 * 1024 + 12_345;
        for strategy in ["fixed", "random"] {
            let plan = volume_plan(total, true, max, HEADER, strategy);
            assert_eq!(plan.iter().sum::<u64>(), total, "{strategy}");
            assert!(
                plan.iter().all(|data| data + HEADER <= max),
                "{strategy}: 落地对象必须不超过 {max}: {plan:?}"
            );
            // 数据区上限缩小 54 字节 → 卷数按 max-54 算
            assert_eq!(
                plan.len(),
                total.div_ceil(max - HEADER) as usize,
                "{strategy}"
            );
        }
        // 不伪装时行为不变：数据区可以顶到 max
        let plan = volume_plan(total, true, max, 0, "fixed");
        assert_eq!(plan[0], max);
    }

    #[test]
    fn random_plan_spreads_slack_instead_of_pinning_at_max() {
        // 2900M / 300M：卷数恒为 10，松弛量 100M 应摊到全部分卷上，
        // 而不是被前几卷耗尽导致后面的卷全部顶格 300M。
        let mb = 1024 * 1024;
        let total = 2900 * mb;
        let max = 300 * mb;
        for _ in 0..32 {
            let plan = volume_plan(total, true, max, 0, "random");
            assert_eq!(plan.len(), 10);
            assert_eq!(plan.iter().sum::<u64>(), total);
            assert!(plan.iter().all(|size| *size > 0 && *size <= max));
            let pinned = plan.iter().filter(|size| **size == max).count();
            assert!(pinned < plan.len() / 2, "顶格分卷过多: {plan:?}");
        }
    }
}

#[cfg(test)]
mod disguise_tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    /// 加密 + 分卷 + 伪装三开的数据源 + 已挂好的路由。
    fn setup() -> (axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cloud = dir.path().join("cloud");
        std::fs::create_dir_all(&cloud).unwrap();
        let state = AppState::new(dir.path().join("data"), None).unwrap();
        state
            .registry
            .create(crate::registry::DataSource {
                id: "ds1".into(),
                name: "cloud".into(),
                ds_type: "localfs".into(),
                config: serde_json::json!({ "root": cloud.to_str().unwrap() }),
                encryption_enabled: true,
                password: "pw".into(),
                prev_password: None,
                volume_enabled: true,
                volume_size: 64 * 1024,
                volume_strategy: "fixed".into(),
                leaf_name_format: "{e}.bmp".into(),
                disguise_enabled: true,
                disguise_algorithm: "bmp".into(),
                cache_enabled: false,
                created_at: 1,
            })
            .unwrap();
        (crate::routes::router(state), dir)
    }

    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        range: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(range) = range {
            builder = builder.header(header::RANGE, range);
        }
        let resp = app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, bytes)
    }

    /// 代理 Range 下载必须修正分片：客户端的区间是明文坐标，响应头报的是
    /// 明文大小，伪装头部既不出现在响应体里、也不参与区间计算。
    #[tokio::test]
    async fn range_download_skips_the_disguise_header() {
        let (app, dir) = setup();
        // 跨 3 个 64 KiB 分卷，边界落在 65536 / 131072。
        let data: Vec<u8> = (0..150_000u32).map(|i| (i * 13 % 251) as u8).collect();
        let (status, _, _) = send(
            &app,
            "PUT",
            &format!("/api/files/ds1/upload?path=a.bin&size={}", data.len()),
            None,
            data.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // 存储侧：每个分卷都是「54 字节 BMP 头 + 密文」。
        let mut stored = 0u64;
        let mut volumes = 0;
        for entry in walkdir(&dir.path().join("cloud")) {
            let raw = std::fs::read(&entry).unwrap();
            assert_eq!(&raw[..2], b"BM", "{}", entry.display());
            stored += raw.len() as u64;
            volumes += 1;
        }
        assert_eq!(volumes, 3);
        assert_eq!(stored, data.len() as u64 + 3 * 54);

        // HEAD：报明文大小。
        let (status, headers, _) = send(&app, "HEAD", "/stream/ds1/a.bin", None, Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[header::CONTENT_LENGTH],
            data.len().to_string().as_str()
        );

        // 全量与各种区间（含跨卷、卷边界、末字节、开区间）都逐字节一致。
        let (status, _, body) = send(&app, "GET", "/stream/ds1/a.bin", None, Vec::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, data);

        for (range, start, end) in [
            ("bytes=0-0", 0usize, 0usize),
            ("bytes=65535-65536", 65_535, 65_536),
            ("bytes=131071-131072", 131_071, 131_072),
            ("bytes=100-99999", 100, 99_999),
            ("bytes=149999-", 149_999, 149_999),
            ("bytes=-10", 149_990, 149_999),
        ] {
            let (status, headers, body) =
                send(&app, "GET", "/stream/ds1/a.bin", Some(range), Vec::new()).await;
            assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{range}");
            assert_eq!(
                headers[header::CONTENT_RANGE],
                format!("bytes {start}-{end}/{}", data.len()).as_str(),
                "{range}"
            );
            assert_eq!(body, data[start..=end], "{range}");
        }
    }

    /// 受管文件的分卷没有伪装头部（外部写入 / 从没开伪装的地方搬来）时，
    /// 必须指名道姓报出来，而不是让用户拿着「数据可能被外部修改」去猜。
    #[test]
    fn missing_disguise_header_is_named_in_the_error() {
        let layout = engine::FileLayout {
            volumes: vec![
                engine::VolumeMeta {
                    name: "a".into(),
                    size: 1_000,
                    offset: 0,
                },
                engine::VolumeMeta {
                    name: "b".into(),
                    size: 946,
                    offset: 1_000,
                },
            ],
            total: 1_946,
        };
        // 少的正好是 2 × 54：这些卷根本没有伪装头部。
        let error = check_layout_total(&layout, 2_054, Disguise::Bmp).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("没有本数据源的伪装头部"), "{message}");
        assert!(message.contains("108"), "{message}");
        // 差值对不上头部长度 → 仍按「可能被外部修改」报。
        let error = check_layout_total(&layout, 3_000, Disguise::Bmp).unwrap_err();
        assert!(error.to_string().contains("外部修改"), "{error}");
        // 对得上就放行。
        assert!(check_layout_total(&layout, 1_946, Disguise::Bmp).is_ok());
    }

    /// 递归收集数据源根下所有普通文件。
    fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod adopt_foreign_tests {
    use super::*;
    use crate::crypto::{apply_content_keystream, derive_root_key, gen_secret};
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn setup() -> (AppState, axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cloud = dir.path().join("cloud");
        std::fs::create_dir_all(&cloud).unwrap();
        let state = AppState::new(dir.path().join("data"), None).unwrap();
        state
            .registry
            .create(crate::registry::DataSource {
                id: "ds1".into(),
                name: "cloud".into(),
                ds_type: "localfs".into(),
                config: serde_json::json!({ "root": cloud.to_str().unwrap() }),
                encryption_enabled: true,
                password: "mine".into(),
                prev_password: None,
                volume_enabled: true,
                volume_size: 64 * 1024,
                volume_strategy: "fixed".into(),
                leaf_name_format: "{e}".into(),
                disguise_enabled: false,
                disguise_algorithm: "bmp".into(),
                cache_enabled: false,
                created_at: 1,
            })
            .unwrap();
        (state.clone(), crate::routes::router(state), dir)
    }

    /// 模拟手动转存：按「别人的链路密钥」编码的受管文件直接落进云端根。
    /// 返回存储名。
    fn plant_foreign(cloud: &std::path::Path, key: &[u8], name: &str, content: &[u8]) -> String {
        let pw = gen_secret();
        let nc = encode_name(
            key,
            &NameMeta {
                name: name.into(),
                size: content.len() as u64,
                is_dir: false,
                secret: pw,
            },
        )
        .unwrap();
        let folder = cloud.join(&nc);
        std::fs::create_dir_all(&folder).unwrap();
        let mut ct = content.to_vec();
        apply_content_keystream(&pw, 0, &mut ct);
        let leaf = crate::naming::leaf_names(crate::naming::ENVELOPE, name, &pw, 1)[0].clone();
        std::fs::write(folder.join(&leaf), ct).unwrap();
        nc
    }

    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value, Vec<u8>) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        let body = match body {
            Some(v) => {
                builder = builder.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&v).unwrap())
            }
            None => Body::empty(),
        };
        let resp = app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (parts.status, json, bytes)
    }

    async fn list_root(app: &axum::Router) -> Vec<serde_json::Value> {
        let (st, json, _) = send(app, "GET", "/api/files/ds1/list?path=", None).await;
        assert_eq!(st, StatusCode::OK);
        json["entries"].as_array().unwrap().clone()
    }

    /// 端到端：转存文件按外来显示 → 错密码 400 且不 rename → 对密码
    /// 解密纳管 → 正常列出并可流式解密内容。
    #[tokio::test]
    async fn adopt_foreign_with_sharer_password() {
        let (_state, app, dir) = setup();
        let cloud = dir.path().join("cloud");
        let foreign_key = derive_root_key(b"theirs");
        let nc = plant_foreign(&cloud, &foreign_key, "movie.mp4", b"hello");

        // 转存落地后按外来条目显示
        let entries = list_root(&app).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], nc);
        assert_eq!(entries[0]["foreign"], true);

        // 错误密码：400 提示，不得 rename
        let (st, json, _) = send(
            &app,
            "POST",
            "/api/files/ds1/adopt-foreign",
            Some(serde_json::json!({ "path": "", "name": nc, "password": "wrong" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("密码不正确"));
        assert!(cloud.join(&nc).exists(), "错误密码不能触发 rename");

        // 正确密码：解密并纳入当前链路
        let (st, json, _) = send(
            &app,
            "POST",
            "/api/files/ds1/adopt-foreign",
            Some(serde_json::json!({ "path": "", "name": nc, "password": "theirs" })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{json}");
        assert_eq!(json["name"], "movie.mp4");
        assert!(!cloud.join(&nc).exists(), "信封已换当前链路密钥重编码");

        let entries = list_root(&app).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "movie.mp4");
        assert_eq!(entries[0]["foreign"], false);
        assert_eq!(entries[0]["size"], 5);

        // secret 原样带走：内容零重加密即可解密
        let (st, _, bytes) = send(&app, "GET", "/stream/ds1/movie.mp4", None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(bytes, b"hello");
    }

    /// base64 直贴目录 FK（非根目录分享的场景）也可解密。
    #[tokio::test]
    async fn adopt_foreign_with_base64_fk() {
        let (_state, app, dir) = setup();
        let fk = gen_secret();
        let nc = plant_foreign(&dir.path().join("cloud"), &fk, "报告.pdf", b"x");
        let (st, json, _) = send(
            &app,
            "POST",
            "/api/files/ds1/adopt-foreign",
            Some(serde_json::json!({ "path": "", "name": nc, "password": B64.encode(fk) })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{json}");
        assert_eq!(json["name"], "报告.pdf");
    }

    /// 解密名与现有条目冲突 / 条目本就受管 → 拒绝且不 rename。
    #[tokio::test]
    async fn adopt_foreign_rejects_conflict_and_managed() {
        let (_state, app, dir) = setup();
        let cloud = dir.path().join("cloud");
        // 现有受管条目 movie.mp4（当前链路密钥编码）
        let mine = plant_foreign(&cloud, &derive_root_key(b"mine"), "movie.mp4", b"a");
        // 外来条目解密后同名
        let nc = plant_foreign(&cloud, &derive_root_key(b"theirs"), "movie.mp4", b"b");

        let (st, json, _) = send(
            &app,
            "POST",
            "/api/files/ds1/adopt-foreign",
            Some(serde_json::json!({ "path": "", "name": nc, "password": "theirs" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap().contains("同名条目"),
            "{json}"
        );
        assert!(cloud.join(&nc).exists());

        // 受管条目本身不允许走 adopt
        let (st, json, _) = send(
            &app,
            "POST",
            "/api/files/ds1/adopt-foreign",
            Some(serde_json::json!({ "path": "", "name": mine, "password": "mine" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap().contains("无需操作"),
            "{json}"
        );
    }
}
