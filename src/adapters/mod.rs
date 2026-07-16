pub mod baidupan;
pub mod localfs;
pub mod webdav;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};

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

/// 上传进度回调：报告「已确认写入上游」的**增量**字节数。
pub type ProgressFn = std::sync::Arc<dyn Fn(u64) + Send + Sync>;

/// 数据源适配器：纯粹的 I/O 驱动。路径为数据源根内的相对路径（"a/b/c"，根为 ""）。
#[async_trait]
pub trait Storage: Send + Sync {
    /// 上游单次 Range 请求的硬上限；下载规划器会自动取全局 split 与它的较小值。
    fn max_range_size(&self) -> Option<u64> {
        None
    }
    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>>;
    async fn mkdir(&self, path: &str) -> ApiResult<()>;
    /// 递归删除文件或目录。
    async fn delete(&self, path: &str) -> ApiResult<()>;
    /// 重命名/移动（同一数据源内）。
    async fn rename(&self, from: &str, to: &str) -> ApiResult<()>;
    /// 使用数据源的原生能力创建分享。`paths` 是存储端相对路径。
    async fn share(&self, _paths: &[String]) -> ApiResult<CloudShare> {
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
}

pub fn make_with_token_persister(
    ds: &DataSource,
    http: reqwest::Client,
    persist_tokens: Option<baidupan::TokenPersister>,
) -> ApiResult<Box<dyn Storage>> {
    match ds.ds_type.as_str() {
        "localfs" => Ok(Box::new(localfs::LocalFs::from_config(&ds.config)?)),
        "webdav" => Ok(Box::new(webdav::WebdavFs::from_config(&ds.config, http)?)),
        "baidupan" => Ok(Box::new(baidupan::BaiduPanFs::from_config_with_persister(
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
    persist_tokens: Option<baidupan::TokenPersister>,
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
