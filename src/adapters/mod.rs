pub mod aliyun_apps;
pub mod aliyun_web;
pub mod aliyundrive;
pub mod baidupan;
pub mod localfs;
pub mod quark;
pub mod webdav;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{ApiError, ApiResult};
use crate::registry::DataSource;

/// 存储侧目录条目。服务端只见密文名与字节数，对加密完全无意识。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// 上游数据源的稳定对象 ID（不支持的数据源为 None）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// 毫秒时间戳；未知时为 0。
    pub mtime: u64,
}

/// 云盘原生分享结果。标准 `sd://` 封装由路由层统一完成。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudShare {
    pub url: String,
    pub password: String,
}

/// 云盘转存后的名称映射。`source_name` 是分享中的存储名，`name` 是目标目录
/// 实际落地名（上游使用 newcopy 时两者可能不同）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedEntry {
    pub source_name: String,
    pub name: String,
}

pub type ByteStream = BoxStream<'static, std::io::Result<bytes::Bytes>>;

pub struct RangeRead {
    pub stream: ByteStream,
    timeout_feedback: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl RangeRead {
    pub fn new(stream: ByteStream) -> Self {
        Self {
            stream,
            timeout_feedback: None,
        }
    }

    pub fn with_timeout_feedback(
        stream: ByteStream,
        feedback: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            stream,
            timeout_feedback: Some(feedback),
        }
    }

    pub fn report_timeout(&self) {
        if let Some(feedback) = &self.timeout_feedback {
            feedback();
        }
    }
}

/// 上传进度回调：报告「已确认写入上游」的**增量**字节数。
pub type ProgressFn = std::sync::Arc<dyn Fn(u64) + Send + Sync>;

/// 适配器把运行期轮换出来的凭证原子写回注册表。键就是 `datasources.json`
/// 里 `config` 的字段名（accessToken / refreshToken / cookie …）。
pub type CredentialPersister =
    Arc<dyn Fn(Vec<(String, serde_json::Value)>) -> ApiResult<()> + Send + Sync>;

/// 秒传要用的内容摘要种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Sha1,
    Md5,
}

/// 对象内容摘要（小写十六进制）。跨数据源秒传的唯一凭据。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentHashes {
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

impl ContentHashes {
    pub fn get(&self, kind: HashKind) -> Option<&str> {
        match kind {
            HashKind::Sha1 => self.sha1.as_deref(),
            HashKind::Md5 => self.md5.as_deref(),
        }
    }

    /// 是否已经凑齐 `kinds` 要求的全部摘要。
    pub fn covers(&self, kinds: &[HashKind]) -> bool {
        !kinds.is_empty() && kinds.iter().all(|kind| self.get(*kind).is_some())
    }
}

/// 秒传取数口：目标适配器只按需读极少量原文（pre_hash 头 1 KiB、
/// proof_code 8 字节），全量字节永远不经过它。
#[async_trait]
pub trait RapidSource: Send + Sync {
    fn size(&self) -> u64;
    /// 已知摘要；缺的那部分由调用方在真正需要时补算。
    fn hashes(&self) -> &ContentHashes;
    /// 读取 `[offset, offset+len)`，必须恰好返回 `len` 字节。
    async fn read_at(&self, offset: u64, len: u64) -> ApiResult<bytes::Bytes>;
}

/// Per-client-stream diagnostics populated by adapters while Range requests
/// are active. The engine snapshots these counters in its final summary log.
#[derive(Default)]
pub struct RangeTransferMetrics {
    hedges: AtomicU64,
    candidate_failures: AtomicU64,
    body_bytes: AtomicU64,
    body_completions: AtomicU64,
}

impl RangeTransferMetrics {
    pub fn record_hedge(&self) {
        self.hedges.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_candidate_failure(&self) {
        self.candidate_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_body_bytes(&self, bytes: u64) {
        self.body_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn record_body_completion(&self) {
        self.body_completions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.hedges.load(Ordering::Relaxed),
            self.candidate_failures.load(Ordering::Relaxed),
            self.body_bytes.load(Ordering::Relaxed),
            self.body_completions.load(Ordering::Relaxed),
        )
    }
}

/// 数据源适配器：纯粹的 I/O 驱动。路径为数据源根内的相对路径（"a/b/c"，根为 ""）。
#[async_trait]
pub trait Storage: Send + Sync {
    /// 上游单次 Range 请求的硬上限；下载规划器会自动取全局 split 与它的较小值。
    fn max_range_size(&self) -> Option<u64> {
        None
    }
    /// Stable, non-secret key for reusing recently learned download
    /// concurrency. This is advisory only and never acts as a global limiter.
    fn download_profile_key(&self) -> Option<String> {
        None
    }
    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>>;
    async fn mkdir(&self, path: &str) -> ApiResult<()>;
    /// 递归删除文件或目录。
    async fn delete(&self, path: &str) -> ApiResult<()>;
    /// 重命名/移动（同一数据源内）。
    async fn rename(&self, from: &str, to: &str) -> ApiResult<()>;
    /// 使用数据源的原生能力创建分享。`paths` 是存储端相对路径；`password`
    /// 为 `Some` 时用作自定义提取码（走官网原生渠道分享时可用），`None` 则由
    /// 适配器随机生成。
    async fn share(&self, _paths: &[String], _password: Option<&str>) -> ApiResult<CloudShare> {
        Err(ApiError::BadRequest("该数据源不支持分享".into()))
    }
    /// 解析并转存原生分享到 `dest`，返回转存后在目标目录下的存储名。
    async fn import_share(
        &self,
        _share: &CloudShare,
        _dest: &str,
    ) -> ApiResult<Vec<ImportedEntry>> {
        Err(ApiError::BadRequest("该数据源不支持导入分享".into()))
    }
    /// 流式读取整个对象，返回 (大小(若已知), 字节流)。
    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)>;
    /// 读取对象的字节区间 [start, end]（含端点）。下载引擎的 fetcher 用它并行拉取分片。
    /// 默认实现：整读后丢弃区间外字节（不支持区间读的适配器兜底）。
    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        use futures_util::StreamExt;
        if end < start {
            return Err(ApiError::BadRequest("非法字节区间".into()));
        }
        let (_, stream) = self.get(path).await?;
        let mut skipped = 0u64;
        let mut remaining = end - start + 1;
        let filtered = stream.filter_map(move |item| {
            let out = match item {
                Err(e) => Some(Err(e)),
                Ok(b) => {
                    let mut b = b;
                    if skipped < start {
                        let drop_n = ((start - skipped).min(b.len() as u64)) as usize;
                        skipped += drop_n as u64;
                        b = b.slice(drop_n..);
                    }
                    if b.is_empty() || remaining == 0 {
                        None
                    } else {
                        let take = (b.len() as u64).min(remaining) as usize;
                        remaining -= take as u64;
                        Some(Ok(b.slice(..take)))
                    }
                }
            };
            async move { out }
        });
        Ok(filtered.boxed())
    }
    /// Range read with optional adapter-level diagnostics. Providers can
    /// override this to report hedges and response-body outcomes.
    async fn get_range_tracked(
        &self,
        path: &str,
        start: u64,
        end: u64,
        _metrics: Arc<RangeTransferMetrics>,
    ) -> ApiResult<RangeRead> {
        Ok(RangeRead::new(self.get_range(path, start, end).await?))
    }
    /// 流式写入对象（覆盖）。
    async fn put(&self, path: &str, body: ByteStream) -> ApiResult<()>;
    /// 已知长度的流式写入。需要 multipart Content-Length 的上游可覆盖此方法。
    async fn put_sized(&self, path: &str, _size: u64, body: ByteStream) -> ApiResult<()> {
        self.put(path, body).await
    }
    /// 带进度的已知长度写入。默认实现按 body 被消费的速率上报 ——
    /// 流式直传的适配器（localfs/WebDAV）背压即真实上传进度；先本地
    /// 落盘再上传的适配器（百度网盘）必须覆盖，否则上报的是缓冲进度。
    async fn put_sized_tracked(
        &self,
        path: &str,
        size: u64,
        body: ByteStream,
        progress: ProgressFn,
    ) -> ApiResult<()> {
        use futures_util::StreamExt;
        let counted = body.map(move |item| {
            if let Ok(b) = &item {
                progress(b.len() as u64);
            }
            item
        });
        self.put_sized(path, size, counted.boxed()).await
    }

    // ---- 秒传（跨数据源复制专用；不支持的适配器用默认实现即可） ----

    /// 读取该对象是否零成本（本地磁盘）。为 true 时调用方可以放心地
    /// 直接读全量算摘要，不必先落盘缓存。
    fn reads_are_free(&self) -> bool {
        false
    }
    /// 目录内各对象的内容摘要 —— 一次 list 全拿到（阿里云盘列表自带
    /// content_hash）。拿得到就等于免费凑齐了秒传凭据。键是存储端条目名。
    async fn dir_content_hashes(
        &self,
        _dir: &str,
    ) -> ApiResult<std::collections::HashMap<String, ContentHashes>> {
        Ok(std::collections::HashMap::new())
    }
    /// 秒传需要的摘要种类；**空切片 = 该数据源不支持秒传**。
    fn rapid_hash_kinds(&self) -> &'static [HashKind] {
        &[]
    }
    /// 廉价预检（阿里云盘 pre_hash：只看头 1 KiB）。返回 `Ok(false)` 表示
    /// 秒传必然落空，调用方可以省掉全量摘要计算直接走真实传输。
    async fn rapid_precheck(&self, _path: &str, _source: &dyn RapidSource) -> ApiResult<bool> {
        Ok(true)
    }
    /// 凭摘要把 `path` 秒传出来。`Ok(false)` = 云端没有该内容，未写入任何
    /// 东西，调用方降级为真实传输。
    async fn rapid_put(&self, _path: &str, _source: &dyn RapidSource) -> ApiResult<bool> {
        Ok(false)
    }
}

/// 上传落盘缓冲：必须先算全量摘要、或需要可重放分片的上游，用它把请求体
/// 写到临时文件；析构即删除。
pub(crate) struct TempSpool {
    pub(crate) path: std::path::PathBuf,
}

impl TempSpool {
    pub(crate) fn new(tag: &str) -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "safedrive-{tag}-{}.upload",
                uuid::Uuid::new_v4().simple()
            )),
        }
    }
}

impl Drop for TempSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 把流落盘并顺带算出秒传要的摘要（只算 `kinds` 里点名的那几种）。
pub(crate) async fn spool_with_hashes(
    tag: &str,
    size: u64,
    mut body: ByteStream,
    kinds: &[HashKind],
) -> ApiResult<(TempSpool, ContentHashes)> {
    use futures_util::StreamExt;
    use md5::Digest as _;
    use tokio::io::AsyncWriteExt;

    let spool = TempSpool::new(tag);
    let file = tokio::fs::File::create(&spool.path).await?;
    let mut file = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    let mut sha1 = kinds.contains(&HashKind::Sha1).then(sha1::Sha1::new);
    let mut md5 = kinds.contains(&HashKind::Md5).then(md5::Md5::new);
    let mut received = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        received = received.saturating_add(chunk.len() as u64);
        if received > size {
            return Err(ApiError::BadRequest("上传数据超过声明大小".into()));
        }
        file.write_all(&chunk).await?;
        if let Some(hasher) = sha1.as_mut() {
            hasher.update(&chunk);
        }
        if let Some(hasher) = md5.as_mut() {
            hasher.update(&chunk);
        }
    }
    file.flush().await?;
    drop(file);
    if received != size {
        return Err(ApiError::BadRequest(format!(
            "上传数据大小不匹配: 声明 {size}，实际 {received}"
        )));
    }
    Ok((
        spool,
        ContentHashes {
            sha1: sha1.map(|h| hex::encode(h.finalize())),
            md5: md5.map(|h| hex::encode(h.finalize())),
        },
    ))
}

/// 读取落盘缓冲的一个区间（分片上传 / proof_code 取样）。
pub(crate) async fn read_spool(
    path: &std::path::Path,
    offset: u64,
    len: usize,
) -> ApiResult<bytes::Bytes> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).await?;
    Ok(bytes::Bytes::from(buf))
}

/// 流式算摘要，字节读完即丢。跨数据源复制在「源侧读廉价」时用它补齐
/// 秒传凭据。
pub(crate) async fn hash_stream(mut body: ByteStream, kinds: &[HashKind]) -> ApiResult<ContentHashes> {
    use futures_util::StreamExt;
    use md5::Digest as _;

    let mut sha1 = kinds.contains(&HashKind::Sha1).then(sha1::Sha1::new);
    let mut md5 = kinds.contains(&HashKind::Md5).then(md5::Md5::new);
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if let Some(hasher) = sha1.as_mut() {
            hasher.update(&chunk);
        }
        if let Some(hasher) = md5.as_mut() {
            hasher.update(&chunk);
        }
    }
    Ok(ContentHashes {
        sha1: sha1.map(|h| hex::encode(h.finalize())),
        md5: md5.map(|h| hex::encode(h.finalize())),
    })
}

pub fn make_with_token_persister(
    ds: &DataSource,
    http: reqwest::Client,
    persist_tokens: Option<CredentialPersister>,
) -> ApiResult<Box<dyn Storage>> {
    match ds.ds_type.as_str() {
        "localfs" => Ok(Box::new(localfs::LocalFs::from_config(&ds.config)?)),
        "webdav" => Ok(Box::new(webdav::WebdavFs::from_config(&ds.config, http)?)),
        "baidupan" => Ok(Box::new(baidupan::BaiduPanFs::from_config_with_persister(
            &ds.config,
            http,
            persist_tokens,
        )?)),
        "aliyundrive" => Ok(Box::new(
            aliyundrive::AliyunDriveFs::from_config_with_persister(
                &ds.config,
                http,
                persist_tokens,
            )?,
        )),
        "quark" => Ok(Box::new(quark::QuarkFs::from_config_with_persister(
            &ds.config,
            http,
            persist_tokens,
        )?)),
        other => Err(ApiError::BadRequest(format!("未知数据源类型: {other}"))),
    }
}

pub fn make_arc_with_token_persister(
    ds: &DataSource,
    http: reqwest::Client,
    persist_tokens: Option<CredentialPersister>,
) -> ApiResult<std::sync::Arc<dyn Storage>> {
    Ok(std::sync::Arc::from(make_with_token_persister(
        ds,
        http,
        persist_tokens,
    )?))
}

/// 排查日志用：把响应头拼成一行（Set-Cookie 脱敏——可能含会话凭据）。
pub(crate) fn log_headers(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| {
            let v = if k == reqwest::header::SET_COOKIE {
                "…(已脱敏)".into()
            } else {
                String::from_utf8_lossy(v.as_bytes()).into_owned()
            };
            format!("{k}: {v}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// 规范化并校验相对路径：拒绝 `..`、空段、反斜杠与控制字符，返回 "a/b/c" 或 ""（根）。
pub fn sanitize(path: &str) -> ApiResult<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains('\\') || seg.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(ApiError::BadRequest(format!("非法路径: {path}")));
        }
        parts.push(seg);
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sanitize_normalizes_and_rejects() {
        assert_eq!(sanitize("").unwrap(), "");
        assert_eq!(sanitize("/").unwrap(), "");
        assert_eq!(sanitize("a/b/c").unwrap(), "a/b/c");
        assert_eq!(sanitize("/a//b/./c/").unwrap(), "a/b/c");
        assert!(sanitize("a/../b").is_err());
        assert!(sanitize("..").is_err());
        assert!(sanitize("a\\b").is_err());
        assert!(sanitize("a/\u{0}b").is_err());
    }
}
