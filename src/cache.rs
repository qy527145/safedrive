//! 全局密文分块缓存，设计取自 hydraria 的稀疏文件 + 完整块位图。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::error::ApiResult;

pub const BLOCK_SIZE: u64 = 1024 * 1024;

#[cfg(unix)]
fn pread_exact(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn pread_exact(file: &std::fs::File, mut buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "cache positional read reached EOF",
            ));
        }
        let rest = buf;
        buf = &mut rest[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn pwrite_all(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
fn pwrite_all(file: &std::fs::File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "cache positional write returned zero",
            ));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CacheMeta {
    total_size: u64,
    block_size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub entries: usize,
    pub bytes_cached: u64,
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileCacheStatus {
    pub cached: bool,
    pub bytes_cached: u64,
    pub total_size: u64,
    pub complete: bool,
    /// 手动触发的后台预热是否进行中（可通过 stop 接口取消）。
    /// 注意这只是缓存的触发条件之一：播放/下载的服务器代理流也会写透
    /// 缓存，不受此标志影响；bytes_cached / bitmap_summary 始终反映
    /// 所有触发来源合并后的真实缓存状态。
    pub warming: bool,
    /// 块位图降采样：≤128 个桶，每桶为该区段已缓存块的百分比 0-100。
    /// 前端据此渲染「哪些部分已缓存」的热力条（取自 hydraria）。
    pub bitmap_summary: Vec<u8>,
}

pub struct CacheEntry {
    root: PathBuf,
    meta: CacheMeta,
    file: Mutex<std::fs::File>,
    bitmap: Mutex<Vec<u8>>,
    /// 每块已经写入的半开区间并集；只有完整覆盖后才设置持久位图。
    partial: Mutex<Vec<Vec<(u32, u32)>>>,
    bytes_cached: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CacheEntry {
    fn block_len(&self, block: u64) -> u64 {
        let start = block * self.meta.block_size;
        (self.meta.total_size - start).min(self.meta.block_size)
    }

    fn has_block(&self, block: u64) -> bool {
        let bitmap = self.bitmap.lock().unwrap();
        bitmap
            .get((block / 8) as usize)
            .is_some_and(|byte| byte & (1 << (block % 8)) != 0)
    }

    pub fn has_range(&self, start: u64, end: u64) -> bool {
        if end < start || end >= self.meta.total_size {
            return false;
        }
        let first = start / self.meta.block_size;
        let last = end / self.meta.block_size;
        (first..=last).all(|block| self.has_block(block))
    }

    pub fn read_range(&self, start: u64, end: u64) -> std::io::Result<Bytes> {
        let len = usize::try_from(end - start + 1)
            .map_err(|_| std::io::Error::other("cache range too large"))?;
        let mut bytes = vec![0u8; len];
        pread_exact(&self.file.lock().unwrap(), &mut bytes, start)?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Ok(Bytes::from(bytes))
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn write_range(&self, start: u64, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = start
            .checked_add(data.len() as u64 - 1)
            .ok_or_else(|| std::io::Error::other("cache range overflow"))?;
        if end >= self.meta.total_size {
            return Err(std::io::Error::other("cache write exceeds file size"));
        }
        pwrite_all(&self.file.lock().unwrap(), data, start)?;

        let first = start / self.meta.block_size;
        let last = end / self.meta.block_size;
        let mut completed = Vec::new();
        {
            let bitmap = self.bitmap.lock().unwrap();
            let mut partial = self.partial.lock().unwrap();
            for block in first..=last {
                let byte_index = (block / 8) as usize;
                let bit = 1 << (block % 8);
                if bitmap.get(byte_index).is_some_and(|byte| byte & bit != 0) {
                    continue;
                }
                let block_start = block * self.meta.block_size;
                let block_end = block_start + self.block_len(block);
                let lo = (start.max(block_start) - block_start) as u32;
                let hi = (end.saturating_add(1).min(block_end) - block_start) as u32;
                let intervals = &mut partial[block as usize];
                merge_interval(intervals, lo, hi);
                if intervals.len() == 1
                    && intervals[0].0 == 0
                    && intervals[0].1 >= self.block_len(block) as u32
                {
                    completed.push(block);
                }
            }
        }

        if !completed.is_empty() {
            let mut newly_cached = 0;
            let mut bitmap = self.bitmap.lock().unwrap();
            let mut partial = self.partial.lock().unwrap();
            for block in completed {
                let byte_index = (block / 8) as usize;
                let bit = 1 << (block % 8);
                if bitmap[byte_index] & bit == 0 {
                    bitmap[byte_index] |= bit;
                    newly_cached += self.block_len(block);
                    partial[block as usize].clear();
                }
            }
            if newly_cached > 0 {
                self.bytes_cached.fetch_add(newly_cached, Ordering::Relaxed);
                std::fs::write(self.root.join("bitmap.bin"), &*bitmap)?;
            }
        }
        Ok(())
    }
}

pub struct CacheStore {
    root: PathBuf,
    entries: RwLock<HashMap<String, Arc<CacheEntry>>>,
    /// 进行中的文件触发预热任务：key -> 取消信号。守卫 Drop 时注销。
    warming: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
}

/// 预热任务守卫：任务结束（完成/失败/被停止）时 Drop 注销 warming 状态。
pub struct WarmGuard {
    warming: Arc<Mutex<HashMap<String, Arc<Notify>>>>,
    key: String,
    cancel: Arc<Notify>,
}

impl WarmGuard {
    /// 等待停止信号；信号在未被等待时到达也不会丢（Notify 存 permit）。
    pub async fn cancelled(&self) {
        self.cancel.notified().await;
    }
}

impl Drop for WarmGuard {
    fn drop(&mut self) {
        self.warming.lock().unwrap().remove(&self.key);
    }
}

impl CacheStore {
    pub fn new(root: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            entries: RwLock::new(HashMap::new()),
            warming: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 注册一个预热任务；同 key 已有进行中的任务时返回 None（幂等去重）。
    pub fn begin_warm(&self, key: &str) -> Option<WarmGuard> {
        let mut warming = self.warming.lock().unwrap();
        if warming.contains_key(key) {
            return None;
        }
        let cancel = Arc::new(Notify::new());
        warming.insert(key.to_string(), Arc::clone(&cancel));
        Some(WarmGuard {
            warming: Arc::clone(&self.warming),
            key: key.to_string(),
            cancel,
        })
    }

    /// 请求停止进行中的预热任务；返回是否确有任务在跑。
    pub fn stop_warm(&self, key: &str) -> bool {
        match self.warming.lock().unwrap().get(key) {
            Some(cancel) => {
                cancel.notify_one();
                true
            }
            None => false,
        }
    }

    fn is_warming(&self, key: &str) -> bool {
        self.warming.lock().unwrap().contains_key(key)
    }

    pub fn key(datasource: &str, encrypted_path: &str) -> String {
        let mut datasource_hash = Sha256::new();
        datasource_hash.update(datasource.as_bytes());
        let prefix = hex::encode(&datasource_hash.finalize()[..8]);
        let mut hash = Sha256::new();
        hash.update(datasource.as_bytes());
        hash.update([0]);
        hash.update(encrypted_path.as_bytes());
        format!("{prefix}-{}", hex::encode(&hash.finalize()[..16]))
    }

    pub fn open(&self, key: &str, total_size: u64) -> ApiResult<Arc<CacheEntry>> {
        if let Some(entry) = self.entries.read().unwrap().get(key)
            && entry.meta.total_size == total_size
        {
            return Ok(Arc::clone(entry));
        }
        let mut entries = self.entries.write().unwrap();
        if let Some(entry) = entries.get(key) {
            if entry.meta.total_size == total_size {
                return Ok(Arc::clone(entry));
            }
            entries.remove(key);
        }

        let root = self.root.join(key);
        let meta_path = root.join("meta.json");
        let wanted = CacheMeta {
            total_size,
            block_size: BLOCK_SIZE,
        };
        let existing = std::fs::read(&meta_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CacheMeta>(&bytes).ok());
        if existing.as_ref() != Some(&wanted) {
            if root.exists() {
                std::fs::remove_dir_all(&root)?;
            }
            std::fs::create_dir_all(&root)?;
            std::fs::write(&meta_path, serde_json::to_vec_pretty(&wanted).unwrap())?;
            std::fs::write(root.join("bitmap.bin"), vec![0; bitmap_len(total_size)])?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(root.join("file.bin"))?;
            file.set_len(total_size)?;
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("file.bin"))?;
        let mut bitmap = std::fs::read(root.join("bitmap.bin"))?;
        bitmap.resize(bitmap_len(total_size), 0);
        let blocks = total_size.div_ceil(BLOCK_SIZE) as usize;
        let bytes_cached = bytes_from_bitmap(&wanted, &bitmap);
        let entry = Arc::new(CacheEntry {
            root,
            meta: wanted,
            file: Mutex::new(file),
            bitmap: Mutex::new(bitmap),
            partial: Mutex::new(vec![Vec::new(); blocks]),
            bytes_cached: AtomicU64::new(bytes_cached),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        });
        entries.insert(key.to_string(), Arc::clone(&entry));
        Ok(entry)
    }

    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read().unwrap();
        let mut seen: HashSet<String> = entries.keys().cloned().collect();
        let mut stats = CacheStats {
            entries: entries.len(),
            bytes_cached: entries
                .values()
                .map(|e| e.bytes_cached.load(Ordering::Relaxed))
                .sum(),
            hits: entries
                .values()
                .map(|e| e.hits.load(Ordering::Relaxed))
                .sum(),
            misses: entries
                .values()
                .map(|e| e.misses.load(Ordering::Relaxed))
                .sum(),
        };
        drop(entries);
        // 重启后尚未被访问的持久条目也计入全局统计。
        if let Ok(children) = std::fs::read_dir(&self.root) {
            for child in children.flatten() {
                let path = child.path();
                let Some(key) = path.file_name().and_then(|v| v.to_str()).map(str::to_owned) else {
                    continue;
                };
                if !path.is_dir() || !seen.insert(key) {
                    continue;
                }
                let meta = std::fs::read(path.join("meta.json"))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<CacheMeta>(&bytes).ok());
                let bitmap = std::fs::read(path.join("bitmap.bin")).ok();
                if let (Some(meta), Some(bitmap)) = (meta, bitmap) {
                    stats.entries += 1;
                    stats.bytes_cached += bytes_from_bitmap(&meta, &bitmap);
                }
            }
        }
        stats
    }

    pub fn status(&self, key: &str) -> FileCacheStatus {
        let warming = self.is_warming(key);
        if let Some(entry) = self.entries.read().unwrap().get(key) {
            let bytes = entry.bytes_cached.load(Ordering::Relaxed);
            let bitmap_summary = {
                let bitmap = entry.bitmap.lock().unwrap();
                downsample_bitmap(&bitmap, &entry.meta)
            };
            return FileCacheStatus {
                cached: bytes > 0,
                bytes_cached: bytes,
                total_size: entry.meta.total_size,
                complete: bytes == entry.meta.total_size,
                warming,
                bitmap_summary,
            };
        }
        let root = self.root.join(key);
        let meta = std::fs::read(root.join("meta.json"))
            .ok()
            .and_then(|v| serde_json::from_slice::<CacheMeta>(&v).ok());
        let bitmap = std::fs::read(root.join("bitmap.bin")).ok();
        match (meta, bitmap) {
            (Some(meta), Some(bitmap)) => {
                let bytes = bytes_from_bitmap(&meta, &bitmap);
                FileCacheStatus {
                    cached: bytes > 0,
                    bytes_cached: bytes,
                    total_size: meta.total_size,
                    complete: bytes == meta.total_size,
                    warming,
                    bitmap_summary: downsample_bitmap(&bitmap, &meta),
                }
            }
            _ => FileCacheStatus {
                cached: false,
                bytes_cached: 0,
                total_size: 0,
                complete: false,
                warming,
                bitmap_summary: Vec::new(),
            },
        }
    }

    pub fn clear(&self, key: &str) -> ApiResult<u64> {
        self.stop_warm(key); // 正在预热时先请求停止，避免任务向已删除目录写入
        let bytes = self.status(key).bytes_cached;
        self.entries.write().unwrap().remove(key);
        let root = self.root.join(key);
        if root.exists() {
            std::fs::remove_dir_all(root)?;
        }
        Ok(bytes)
    }

    pub fn clear_datasource(&self, datasource: &str) -> ApiResult<u64> {
        let probe = Self::key(datasource, "");
        let prefix = probe
            .split_once('-')
            .map(|(prefix, _)| format!("{prefix}-"))
            .expect("缓存键始终包含数据源前缀");
        let loaded: Vec<String> = self
            .entries
            .read()
            .unwrap()
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        let mut freed = 0;
        for key in loaded {
            freed += self.clear(&key)?;
        }
        if let Ok(children) = std::fs::read_dir(&self.root) {
            for child in children.flatten() {
                let name = child.file_name().to_string_lossy().into_owned();
                if name.starts_with(&prefix) && child.path().is_dir() {
                    freed += self.status(&name).bytes_cached;
                    std::fs::remove_dir_all(child.path())?;
                }
            }
        }
        Ok(freed)
    }

    pub fn clear_all(&self) -> ApiResult<u64> {
        for cancel in self.warming.lock().unwrap().values() {
            cancel.notify_one();
        }
        let bytes = self.stats().bytes_cached;
        self.entries.write().unwrap().clear();
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root)?;
        }
        std::fs::create_dir_all(&self.root)?;
        Ok(bytes)
    }
}

fn bitmap_len(total_size: u64) -> usize {
    total_size.div_ceil(BLOCK_SIZE).div_ceil(8) as usize
}

/// 位图降采样：压成 ≤`MAX_SUMMARY_BUCKETS` 个桶，每桶为该区段已完成块的
/// 百分比 0-100；块数少于桶数时一桶对应一块（取自 hydraria）。
const MAX_SUMMARY_BUCKETS: usize = 128;

fn downsample_bitmap(bitmap: &[u8], meta: &CacheMeta) -> Vec<u8> {
    let blocks_total = meta.total_size.div_ceil(meta.block_size) as usize;
    if blocks_total == 0 {
        return Vec::new();
    }
    let buckets = blocks_total.min(MAX_SUMMARY_BUCKETS).max(1);
    let mut out = Vec::with_capacity(buckets);
    for i in 0..buckets {
        let lo = (i * blocks_total) / buckets;
        let hi = (((i + 1) * blocks_total) / buckets).min(blocks_total);
        if hi <= lo {
            out.push(0);
            continue;
        }
        let filled = (lo..hi)
            .filter(|block| {
                bitmap
                    .get(block / 8)
                    .is_some_and(|byte| byte & (1 << (block % 8)) != 0)
            })
            .count();
        out.push(((filled * 100) / (hi - lo)) as u8);
    }
    out
}

fn bytes_from_bitmap(meta: &CacheMeta, bitmap: &[u8]) -> u64 {
    let blocks = meta.total_size.div_ceil(meta.block_size);
    bitmap
        .iter()
        .enumerate()
        .map(|(byte_index, byte)| {
            (0..8)
                .filter(|bit| byte & (1 << bit) != 0)
                .map(|bit| {
                    let block = (byte_index * 8 + bit) as u64;
                    if block < blocks {
                        (meta.total_size - block * meta.block_size).min(meta.block_size)
                    } else {
                        0
                    }
                })
                .sum::<u64>()
        })
        .sum()
}

fn merge_interval(intervals: &mut Vec<(u32, u32)>, lo: u32, hi: u32) {
    if hi <= lo {
        return;
    }
    intervals.push((lo, hi));
    intervals.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals.drain(..) {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    *intervals = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_writes_only_complete_true_union() {
        let mut intervals = Vec::new();
        merge_interval(&mut intervals, 0, 700);
        merge_interval(&mut intervals, 300, 1000);
        assert_eq!(intervals, vec![(0, 1000)]);
        assert!(intervals[0].1 < 1024);
        merge_interval(&mut intervals, 1000, 1024);
        assert_eq!(intervals, vec![(0, 1024)]);
    }

    #[test]
    fn persistent_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = CacheStore::new(dir.path().join("cache")).unwrap();
        let entry = store.open("k", 2 * BLOCK_SIZE).unwrap();
        let data = vec![0x5a; BLOCK_SIZE as usize];
        entry.write_range(0, &data).unwrap();
        assert!(entry.has_range(10, BLOCK_SIZE - 1));
        assert!(!entry.has_range(BLOCK_SIZE, 2 * BLOCK_SIZE - 1));
        assert_eq!(entry.read_range(5, 10).unwrap().as_ref(), &[0x5a; 6]);
        assert_eq!(store.stats().bytes_cached, BLOCK_SIZE);
        // 位图摘要：块数 < 128 时一桶一块，前块已满、后块为空
        assert_eq!(store.status("k").bitmap_summary, vec![100, 0]);

        drop(entry);
        drop(store);
        let reopened = CacheStore::new(dir.path().join("cache")).unwrap();
        assert_eq!(reopened.stats().bytes_cached, BLOCK_SIZE);
        // 未加载的持久条目也能给出摘要（读 bitmap.bin）
        assert_eq!(reopened.status("k").bitmap_summary, vec![100, 0]);
        let entry = reopened.open("k", 2 * BLOCK_SIZE).unwrap();
        assert!(entry.has_range(0, BLOCK_SIZE - 1));
    }

    #[test]
    fn bitmap_summary_caps_at_128_buckets() {
        let meta = CacheMeta {
            total_size: 300 * BLOCK_SIZE,
            block_size: BLOCK_SIZE,
        };
        // 前半部分全缓存：300 块 → 128 桶，前面的桶接近 100，后面的为 0
        let mut bitmap = vec![0u8; (300u64.div_ceil(8)) as usize];
        for block in 0..150usize {
            bitmap[block / 8] |= 1 << (block % 8);
        }
        let summary = downsample_bitmap(&bitmap, &meta);
        assert_eq!(summary.len(), 128);
        assert_eq!(summary[0], 100);
        assert_eq!(*summary.last().unwrap(), 0);
        assert!(summary.iter().take(60).all(|&pct| pct == 100));
        assert!(summary.iter().skip(66).all(|&pct| pct == 0));
    }

    #[test]
    fn cache_key_uses_stable_server_object_identity() {
        let key = CacheStore::key("datasource-1", "encrypted/folder");
        assert_eq!(key, CacheStore::key("datasource-1", "encrypted/folder"));
        assert_ne!(key, CacheStore::key("datasource-2", "encrypted/folder"));
        assert_ne!(key, CacheStore::key("datasource-1", "encrypted/other"));
        // 下载直链不参与 API，也不进入 key；直链刷新不会改变服务器侧缓存身份。
        assert_eq!(key.len(), 49);
    }

    #[test]
    fn datasource_cache_can_be_cleared_without_touching_others() {
        let dir = tempfile::tempdir().unwrap();
        let store = CacheStore::new(dir.path().join("cache")).unwrap();
        let a = CacheStore::key("a", "file");
        let b = CacheStore::key("b", "file");
        store
            .open(&a, BLOCK_SIZE)
            .unwrap()
            .write_range(0, &vec![1; BLOCK_SIZE as usize])
            .unwrap();
        store
            .open(&b, BLOCK_SIZE)
            .unwrap()
            .write_range(0, &vec![2; BLOCK_SIZE as usize])
            .unwrap();
        assert_eq!(store.clear_datasource("a").unwrap(), BLOCK_SIZE);
        assert!(!store.status(&a).cached);
        assert!(store.status(&b).complete);
    }

    #[tokio::test]
    async fn warm_guard_registers_stops_and_unregisters() {
        let dir = tempfile::tempdir().unwrap();
        let store = CacheStore::new(dir.path().join("cache")).unwrap();
        assert!(!store.status("k").warming);
        assert!(!store.stop_warm("k")); // 没有任务时 stop 返回 false

        let guard = store.begin_warm("k").unwrap();
        assert!(store.status("k").warming);
        assert!(store.begin_warm("k").is_none()); // 同 key 幂等去重

        assert!(store.stop_warm("k"));
        // 信号在等待前发出也不丢（Notify 存 permit）
        tokio::time::timeout(std::time::Duration::from_secs(1), guard.cancelled())
            .await
            .expect("应收到停止信号");
        drop(guard);
        assert!(!store.status("k").warming); // Drop 注销

        // 停止后可重新触发续传
        assert!(store.begin_warm("k").is_some());
    }
}
