pub mod localfs;
pub mod webdav;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use serde::Serialize;

use crate::error::{ApiError, ApiResult};
use crate::registry::DataSource;

/// 存储侧目录条目。服务端只见密文名与字节数，对加密完全无意识。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// 毫秒时间戳；未知时为 0。
    pub mtime: u64,
}

pub type ByteStream = BoxStream<'static, std::io::Result<bytes::Bytes>>;

/// 数据源适配器：纯粹的 I/O 驱动。路径为数据源根内的相对路径（"a/b/c"，根为 ""）。
#[async_trait]
pub trait Storage: Send + Sync {
    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>>;
    async fn mkdir(&self, path: &str) -> ApiResult<()>;
    /// 递归删除文件或目录。
    async fn delete(&self, path: &str) -> ApiResult<()>;
    /// 重命名/移动（同一数据源内）。
    async fn rename(&self, from: &str, to: &str) -> ApiResult<()>;
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
}

/// 由数据源配置实例化适配器。
pub fn make(ds: &DataSource, http: reqwest::Client) -> ApiResult<Box<dyn Storage>> {
    match ds.ds_type.as_str() {
        "localfs" => Ok(Box::new(localfs::LocalFs::from_config(&ds.config)?)),
        "webdav" => Ok(Box::new(webdav::WebdavFs::from_config(&ds.config, http)?)),
        other => Err(ApiError::BadRequest(format!("未知数据源类型: {other}"))),
    }
}

/// `Arc` 版本 —— 下载引擎的多个 fetcher 需要共享适配器。
pub fn make_arc(ds: &DataSource, http: reqwest::Client) -> ApiResult<std::sync::Arc<dyn Storage>> {
    Ok(std::sync::Arc::from(make(ds, http)?))
}

/// 规范化并校验相对路径：拒绝 `..`、空段、反斜杠与控制字符，返回 "a/b/c" 或 ""（根）。
pub fn sanitize(path: &str) -> ApiResult<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".."
            || seg.contains('\\')
            || seg.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
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
