use std::path::{Path, PathBuf};

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

use super::{ByteStream, Entry, Storage};
use crate::error::{ApiError, ApiResult};

/// 本地文件系统适配器：以 root 为囚笼目录，所有相对路径都被限制在其内。
pub struct LocalFs {
    root: PathBuf,
}

impl LocalFs {
    pub fn from_config(config: &serde_json::Value) -> ApiResult<Self> {
        let root = config
            .get("root")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::BadRequest("localfs 配置缺少 root".into()))?;
        Ok(Self {
            root: PathBuf::from(root),
        })
    }

    /// 相对路径（已经过 sanitize）→ 囚笼内绝对路径。
    fn resolve(&self, rel: &str) -> PathBuf {
        let mut p = self.root.clone();
        for seg in rel.split('/').filter(|s| !s.is_empty()) {
            p.push(seg);
        }
        p
    }
}

#[async_trait]
impl Storage for LocalFs {
    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        let dir = self.resolve(path);
        let mut rd = tokio::fs::read_dir(&dir).await?;
        let mut entries = Vec::new();
        while let Some(item) = rd.next_entry().await? {
            let Ok(meta) = item.metadata().await else {
                continue;
            };
            let name = item.file_name().to_string_lossy().into_owned();
            // 跳过写入中的临时文件
            if name.starts_with(".sd-tmp-") {
                continue;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            entries.push(Entry {
                id: None,
                name,
                is_dir: meta.is_dir(),
                size: if meta.is_dir() { 0 } else { meta.len() },
                mtime,
            });
        }
        Ok(entries)
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        tokio::fs::create_dir_all(self.resolve(path)).await?;
        Ok(())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        let p = self.resolve(path);
        let meta = tokio::fs::metadata(&p).await?;
        if meta.is_dir() {
            tokio::fs::remove_dir_all(&p).await?;
        } else {
            tokio::fs::remove_file(&p).await?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法重命名路径".into()));
        }
        let dst = self.resolve(to);
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if tokio::fs::metadata(&dst).await.is_ok() {
            return Err(ApiError::BadRequest("目标已存在".into()));
        }
        tokio::fs::rename(self.resolve(from), dst).await?;
        Ok(())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        let p = self.resolve(path);
        let file = tokio::fs::File::open(&p).await?;
        let size = file.metadata().await.ok().map(|m| m.len());
        let stream = ReaderStream::with_capacity(file, 256 * 1024);
        Ok((size, stream.boxed()))
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        use tokio::io::AsyncSeekExt;
        if end < start {
            return Err(ApiError::BadRequest("非法字节区间".into()));
        }
        let p = self.resolve(path);
        let mut file = tokio::fs::File::open(&p).await?;
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let limited = file.take(end - start + 1);
        Ok(ReaderStream::with_capacity(limited, 256 * 1024).boxed())
    }

    async fn put(&self, path: &str, mut body: ByteStream) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("非法对象路径".into()));
        }
        let dst = self.resolve(path);
        let parent = dst
            .parent()
            .ok_or_else(|| ApiError::BadRequest("非法对象路径".into()))?
            .to_path_buf();
        // 原子写：同目录临时文件 + rename
        let tmp = parent.join(format!(".sd-tmp-{}", uuid::Uuid::new_v4()));
        let result: ApiResult<()> = async {
            // HTTP body 往往由许多较小的数据帧组成；先聚合成较大的顺序写，
            // 避免每帧都向 Tokio 的文件 I/O 后端提交一次操作。
            let file = tokio::fs::File::create(&tmp).await?;
            let mut file = tokio::io::BufWriter::with_capacity(256 * 1024, file);
            while let Some(chunk) = body.next().await {
                let chunk = chunk?;
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            // 上传成功要求原子可见，不要求每个分卷都强制物理落盘。逐卷
            // sync_all 会在 Windows/SSD 上引入明显停顿；系统仍会正常回写缓存。
            drop(file.into_inner());
            tokio::fs::rename(&tmp, &dst).await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result
    }
}

#[allow(dead_code)]
fn _assert_send(_: &dyn Storage) {}

#[allow(unused)]
fn _root_check(root: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    fn adapter(dir: &Path) -> LocalFs {
        LocalFs::from_config(&serde_json::json!({ "root": dir.to_str().unwrap() })).unwrap()
    }

    fn body_of(data: &[u8]) -> ByteStream {
        let owned = bytes::Bytes::copy_from_slice(data);
        stream::iter(vec![Ok(owned)]).boxed()
    }

    async fn read_all(mut s: ByteStream) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn full_object_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let fs = adapter(dir.path());

        fs.mkdir("enc-folder").await.unwrap();
        fs.put("enc-folder/0001.bin", body_of(b"cipher-bytes"))
            .await
            .unwrap();

        let entries = fs.list("enc-folder").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "0001.bin");
        assert_eq!(entries[0].size, 12);
        assert!(!entries[0].is_dir);

        let (size, stream) = fs.get("enc-folder/0001.bin").await.unwrap();
        assert_eq!(size, Some(12));
        assert_eq!(read_all(stream).await, b"cipher-bytes");

        fs.rename("enc-folder", "renamed-folder").await.unwrap();
        assert!(fs.list("enc-folder").await.is_err());
        assert_eq!(fs.list("renamed-folder").await.unwrap().len(), 1);

        fs.delete("renamed-folder").await.unwrap();
        assert!(fs.list("renamed-folder").await.is_err());
    }

    #[tokio::test]
    async fn rename_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let fs = adapter(dir.path());
        fs.put("a.bin", body_of(b"a")).await.unwrap();
        fs.put("b.bin", body_of(b"b")).await.unwrap();
        assert!(fs.rename("a.bin", "b.bin").await.is_err());
    }

    #[tokio::test]
    async fn delete_root_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fs = adapter(dir.path());
        assert!(fs.delete("").await.is_err());
    }

    #[tokio::test]
    async fn list_hides_tmp_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".sd-tmp-abc"), b"x").unwrap();
        std::fs::write(dir.path().join("real.bin"), b"x").unwrap();
        let fs = adapter(dir.path());
        let entries = fs.list("").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real.bin");
    }
}
