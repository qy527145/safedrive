//! 下载/上传引擎 —— 模仿 hydraria 的 engine.rs（简化版）。
//!
//! 下载：一次客户端请求被按 **分卷边界 + max_split** 切成 chunk 计划，
//! 由受 `max_threads` / `max_per_volume` 约束的 fetcher 并行从存储拉取
//! 密文区间，按合并偏移解密后交给 serializer 按计划顺序拼回连续字节流。
//! 客户端断开（seek/关播放器）时 abort 所有 in-flight fetcher，立即释放
//! 上游带宽。开区间请求（`Range: X-` 或无 Range，播放器起播）对前几个
//! chunk 削小分片，加速首帧（hydraria 的 head-zone 优化）。
//!
//! 上传：明文流按运行偏移一次性过 ChaCha20，再按分卷大小切开流式写入
//! 存储（内存占用 ≈ 通道缓冲，与文件大小无关）。

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use bytes::{Bytes, BytesMut};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;

use crate::adapters::{RangeTransferMetrics, Storage};
use crate::crypto::{ChunkPrp, content_cipher_params};
use crate::error::{ApiError, ApiResult};

/// 开区间请求的首块小分片（加速播放器起播/seek 响应）。
const HEAD_SMALL_SPLIT: u64 = 256 * 1024;
const HEAD_SMALL_COUNT: usize = 4;
const OUTPUT_BATCH: usize = 64 * 1024;
const CACHE_READ_BATCH: u64 = 256 * 1024;
/// Cache writes arrive from reqwest in small TLS/body frames. Writing every frame
/// synchronously serializes all download workers on the cache file lock and can
/// stall Tokio's I/O workers. Coalesce ciphertext to cache-block sized batches
/// and perform the blocking positional write on the blocking pool.
const CACHE_WRITE_BATCH: usize = crate::cache::BLOCK_SIZE as usize;

// ---------------- 布局（≈ hydraria probe） ----------------

#[derive(Debug, Clone)]
pub struct VolumeMeta {
    /// 分卷在存储端的文件名（随机名，字典序 = 分卷顺序）。
    pub name: String,
    pub size: u64,
    /// 该卷首字节在合并文件中的偏移。
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct FileLayout {
    pub volumes: Vec<VolumeMeta>,
    pub total: u64,
}

/// 列出文件夹内的分卷并建立合并坐标系。
/// 分卷名是文件密码派生的 PRP：把每个存储条目名 O(1) 反解回卷序号，
/// 卷号必须恰好构成 0..n 无空洞 —— 缺卷/多卷都能精确报出，而不是
/// 顺序扫描在断链处静默截断。
pub async fn load_layout(
    storage: &dyn Storage,
    enc_folder: &str,
    pw: &[u8],
) -> ApiResult<FileLayout> {
    let entries = storage.list(enc_folder).await?;
    let prp = ChunkPrp::new(pw);
    let mut indexed: Vec<(usize, String, u64)> = entries
        .into_iter()
        .filter(|e| !e.is_dir)
        .filter_map(|e| prp.index_of(&e.name).map(|i| (i, e.name, e.size)))
        .collect();
    indexed.sort_by_key(|(i, ..)| *i);
    for (pos, (i, ..)) in indexed.iter().enumerate() {
        if *i != pos {
            return Err(ApiError::Upstream(format!(
                "云端分卷不完整：缺第 {pos} 卷（共发现 {} 卷）",
                indexed.len()
            )));
        }
    }
    let mut volumes = Vec::with_capacity(indexed.len());
    let mut offset = 0u64;
    for (_, name, size) in indexed {
        volumes.push(VolumeMeta { name, size, offset });
        offset += size;
    }
    Ok(FileLayout {
        volumes,
        total: offset,
    })
}

// ---------------- Range 解析 ----------------

#[derive(Debug, PartialEq, Eq)]
pub enum RangeSpec {
    /// 无 Range 或格式非法（忽略）→ 200 全量。
    Full,
    /// 合法区间 → 206。
    Slice { start: u64, end: u64 },
    /// start 越界 → 416。
    Unsatisfiable,
}

/// 解析 Range 头。返回 (spec, open_ended)；open_ended = 无 Range 或
/// `bytes=X-`（播放器很可能马上 seek 的请求形态）。
pub fn parse_range(header: Option<&str>, total: u64) -> (RangeSpec, bool) {
    let Some(h) = header else {
        return (RangeSpec::Full, true);
    };
    let h = h.trim();
    let Some(spec) = h.strip_prefix("bytes=") else {
        return (RangeSpec::Full, true);
    };
    if spec.contains(',') {
        // 多区间不支持，按整文件处理
        return (RangeSpec::Full, true);
    }
    let Some((a, b)) = spec.split_once('-') else {
        return (RangeSpec::Full, true);
    };
    let (a, b) = (a.trim(), b.trim());
    if total == 0 {
        return (RangeSpec::Full, false);
    }
    match (a.is_empty(), b.is_empty()) {
        (false, false) => {
            let (Ok(s), Ok(e)) = (a.parse::<u64>(), b.parse::<u64>()) else {
                return (RangeSpec::Full, true);
            };
            if s >= total || s > e {
                return (RangeSpec::Unsatisfiable, false);
            }
            (
                RangeSpec::Slice {
                    start: s,
                    end: e.min(total - 1),
                },
                false,
            )
        }
        (false, true) => {
            let Ok(s) = a.parse::<u64>() else {
                return (RangeSpec::Full, true);
            };
            if s >= total {
                return (RangeSpec::Unsatisfiable, false);
            }
            (
                RangeSpec::Slice {
                    start: s,
                    end: total - 1,
                },
                true,
            )
        }
        (true, false) => {
            let Ok(n) = b.parse::<u64>() else {
                return (RangeSpec::Full, true);
            };
            if n == 0 {
                return (RangeSpec::Unsatisfiable, false);
            }
            let start = total.saturating_sub(n);
            (
                RangeSpec::Slice {
                    start,
                    end: total - 1,
                },
                false,
            )
        }
        (true, true) => (RangeSpec::Full, true),
    }
}

// ---------------- chunk 计划 ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChunk {
    /// 首字节的合并偏移。
    pub merged_start: u64,
    pub len: u64,
    /// 所属分卷下标。
    pub vol: usize,
    /// 在该分卷内的起始偏移。
    pub vol_off: u64,
}

/// 测试用便捷包装：以默认头部小分片数（HEAD_SMALL_COUNT）规划分片。
/// 生产路径按并发线程数调 plan_chunks_with_head_count。
#[cfg(test)]
fn plan_chunks(
    layout: &FileLayout,
    start: u64,
    end: u64,
    max_split: u64,
    open_ended: bool,
) -> Vec<PlannedChunk> {
    plan_chunks_with_head_count(layout, start, end, max_split, open_ended, HEAD_SMALL_COUNT)
}

/// 把合并区间 [start, end] 先按分卷边界、再按 split 切开；开区间请求的
/// 前 head_count 个 chunk 用更小的分片（HEAD_SMALL_SPLIT）。
/// 每个 chunk 只落在一个分卷内 —— fetcher 只需向单个对象发一次区间读。
fn plan_chunks_with_head_count(
    layout: &FileLayout,
    start: u64,
    end: u64,
    max_split: u64,
    open_ended: bool,
    head_count: usize,
) -> Vec<PlannedChunk> {
    let split = max_split.max(1); // 下限由设置校验保证，这里只防 0
    let head: usize = if open_ended && split > HEAD_SMALL_SPLIT {
        head_count
    } else {
        0
    };
    let mut plan = Vec::new();
    let mut cur = start;
    let mut vol_idx = 0usize;
    while cur <= end && vol_idx < layout.volumes.len() {
        let v = &layout.volumes[vol_idx];
        if v.size == 0 || cur >= v.offset + v.size {
            vol_idx += 1;
            continue;
        }
        let this_split = if plan.len() < head {
            HEAD_SMALL_SPLIT
        } else {
            split
        };
        let vol_last = v.offset + v.size - 1;
        let chunk_end = (cur + this_split - 1).min(vol_last).min(end);
        plan.push(PlannedChunk {
            merged_start: cur,
            len: chunk_end - cur + 1,
            vol: vol_idx,
            vol_off: cur - v.offset,
        });
        cur = chunk_end + 1;
    }
    plan
}

// ---------------- 下载：并行拉取 + 按序拼接 ----------------

pub struct StreamParams {
    pub max_split: u64,
    pub max_threads: usize,
    pub max_per_volume: usize,
    pub mode: StreamMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    /// Low-latency, playback-point-centered scheduling for inline media and Range seeks.
    Playback,
    /// Throughput-first scheduling for an explicit attachment download.
    BulkDownload,
    /// Background cache population; throughput-oriented but separately observable.
    CacheWarm,
}

impl StreamMode {
    fn head_count(self, open_ended: bool) -> usize {
        if self == Self::Playback && open_ended {
            HEAD_SMALL_COUNT
        } else {
            0
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Playback => "playback",
            Self::BulkDownload => "bulk",
            Self::CacheWarm => "cache_warm",
        }
    }

    fn first_byte_timeout(self) -> std::time::Duration {
        if cfg!(test) {
            return std::time::Duration::from_millis(120);
        }
        match self {
            Self::Playback => std::time::Duration::from_secs(3),
            Self::BulkDownload => std::time::Duration::from_secs(8),
            Self::CacheWarm => std::time::Duration::from_secs(15),
        }
    }

    fn idle_timeout(self) -> std::time::Duration {
        if cfg!(test) {
            return std::time::Duration::from_millis(150);
        }
        match self {
            Self::Playback => std::time::Duration::from_secs(5),
            Self::BulkDownload => std::time::Duration::from_secs(10),
            Self::CacheWarm => std::time::Duration::from_secs(20),
        }
    }
}

#[derive(Debug, Clone)]
struct FetchStats {
    index: usize,
    volume: usize,
    bytes: u64,
    cache_bytes: u64,
    elapsed: std::time::Duration,
    attempts: usize,
    retries: usize,
    timeouts: usize,
    cache_hit: bool,
    success: bool,
}

#[derive(Clone)]
struct FetchContext {
    mode: StreamMode,
    storage: Arc<dyn Storage>,
    obj_path: String,
    pw: [u8; crate::crypto::SECRET_LEN],
    encrypted: bool,
    cache: Option<Arc<crate::cache::CacheEntry>>,
    cache_writeback: Option<CacheWriteback>,
    network_progress: Option<crate::adapters::ProgressFn>,
    transfer_metrics: Arc<RangeTransferMetrics>,
}

struct AdaptiveConcurrency {
    current: usize,
    cap: usize,
    delivered_bytes: u64,
    delivery_started: std::time::Instant,
    baseline_bps: Option<f64>,
    cooldown_epochs: usize,
    probing: bool,
}

struct LearnedConcurrency {
    value: usize,
    updated: std::time::Instant,
}

static LEARNED_DOWNLOAD_CONCURRENCY: LazyLock<Mutex<HashMap<String, LearnedConcurrency>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn load_learned_concurrency(key: Option<&str>, cap: usize, mode: StreamMode) -> usize {
    if mode == StreamMode::Playback {
        return cap.clamp(1, 4);
    }
    let Some(key) = key else {
        return cap.clamp(1, 4);
    };
    let mut profiles = LEARNED_DOWNLOAD_CONCURRENCY.lock().unwrap();
    profiles.retain(|_, value| value.updated.elapsed() < std::time::Duration::from_secs(10 * 60));
    profiles
        .get(key)
        .map_or(cap.clamp(1, 4), |value| value.value.clamp(1, cap.max(1)))
}

fn save_learned_concurrency(key: Option<&str>, value: usize) {
    let Some(key) = key else {
        return;
    };
    let mut profiles = LEARNED_DOWNLOAD_CONCURRENCY.lock().unwrap();
    if profiles.len() > 128 {
        profiles
            .retain(|_, value| value.updated.elapsed() < std::time::Duration::from_secs(10 * 60));
    }
    profiles.insert(
        key.to_owned(),
        LearnedConcurrency {
            value: value.max(1),
            updated: std::time::Instant::now(),
        },
    );
}

struct CacheWrite {
    start: u64,
    data: Bytes,
}

#[derive(Clone)]
struct CacheWriteback {
    tx: mpsc::Sender<CacheWrite>,
    queue_wait_micros: Arc<AtomicU64>,
}

impl CacheWriteback {
    fn new(cache: Arc<crate::cache::CacheEntry>, capacity: usize) -> (Self, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<CacheWrite>(capacity.max(2));
        // One dedicated blocking consumer avoids a spawn_blocking round-trip
        // for every MiB while keeping all filesystem work off Tokio workers.
        let handle = tokio::task::spawn_blocking(move || {
            while let Some(write) = rx.blocking_recv() {
                if let Err(error) = cache.write_range(write.start, &write.data) {
                    tracing::warn!("写入密文缓存失败（不影响本次下载）: {error}");
                }
            }
            if let Err(error) = cache.persist_bitmap(true) {
                tracing::warn!("缓存位图最终落盘失败: {error}");
            }
        });
        (
            Self {
                tx,
                queue_wait_micros: Arc::new(AtomicU64::new(0)),
            },
            handle,
        )
    }

    async fn enqueue(&self, start: u64, data: Bytes) {
        let started = std::time::Instant::now();
        if self.tx.send(CacheWrite { start, data }).await.is_err() {
            tracing::warn!("密文缓存写回队列已关闭");
        }
        self.queue_wait_micros.fetch_add(
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
}

impl AdaptiveConcurrency {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(cap: usize) -> Self {
        Self::new_with_initial(cap, cap.clamp(1, 4))
    }

    fn new_with_initial(cap: usize, initial: usize) -> Self {
        Self {
            current: initial.clamp(1, cap.max(1)),
            cap: cap.max(1),
            delivered_bytes: 0,
            delivery_started: std::time::Instant::now(),
            baseline_bps: None,
            cooldown_epochs: 0,
            probing: false,
        }
    }

    fn observe_failure(&mut self, stats: &FetchStats) -> Option<(usize, usize, &'static str)> {
        if stats.cache_hit || (stats.success && stats.timeouts == 0) {
            return None;
        }
        let old = self.current;
        self.current = (self.current / 2).max(1);
        self.delivered_bytes = 0;
        self.delivery_started = std::time::Instant::now();
        self.baseline_bps = None;
        self.cooldown_epochs = 2;
        self.probing = false;
        (old != self.current).then_some((old, self.current, "timeout_or_failure"))
    }

    fn delivered(
        &mut self,
        bytes: u64,
        allow_upward_probe: bool,
    ) -> Option<(usize, usize, &'static str)> {
        self.delivered_bytes = self.delivered_bytes.saturating_add(bytes);
        let elapsed = self.delivery_started.elapsed();
        if elapsed < std::time::Duration::from_secs(10) {
            return None;
        }
        let bps = self.delivered_bytes as f64 / elapsed.as_secs_f64().max(0.001);
        self.delivered_bytes = 0;
        self.delivery_started = std::time::Instant::now();
        self.observe_delivery_rate(bps, allow_upward_probe)
    }

    fn observe_delivery_rate(
        &mut self,
        bps: f64,
        allow_upward_probe: bool,
    ) -> Option<(usize, usize, &'static str)> {
        if self.cooldown_epochs > 0 {
            self.cooldown_epochs -= 1;
            self.baseline_bps = Some(bps);
            return None;
        }
        if self.baseline_bps.is_none() {
            self.baseline_bps = Some(bps);
            return None;
        }

        let old = self.current;
        if self.probing {
            self.probing = false;
            if self
                .baseline_bps
                .is_some_and(|baseline| bps < baseline * 1.03)
            {
                self.current = self.current.saturating_sub(1).max(1);
                self.cooldown_epochs = 2;
                self.baseline_bps = None;
                return (old != self.current).then_some((
                    old,
                    self.current,
                    "throughput_probe_no_gain",
                ));
            }
        }
        self.baseline_bps = Some(bps);
        if allow_upward_probe && self.current < self.cap {
            self.current += 1;
            self.probing = true;
            return Some((old, self.current, "throughput_probe"));
        }
        None
    }

    fn stable_value(&self) -> usize {
        if self.probing {
            self.current.saturating_sub(1).max(1)
        } else {
            self.current
        }
    }
}

/// 按合并区间 [start, end] 流式产出解密后的明文字节，可选持久密文缓存。
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub fn stream_range_cached(
    storage: Arc<dyn Storage>,
    enc_folder: String,
    pw: [u8; crate::crypto::SECRET_LEN],
    layout: Arc<FileLayout>,
    start: u64,
    end: u64,
    open_ended: bool,
    params: &StreamParams,
    cache: Option<Arc<crate::cache::CacheEntry>>,
) -> mpsc::Receiver<io::Result<Bytes>> {
    stream_range_cached_mode(
        storage, enc_folder, pw, true, layout, start, end, open_ended, params, cache, None,
    )
}

/// 未加密自定义卷名使用定宽 `{i}`，因此按文件名字典序即可恢复卷序。
pub async fn load_layout_ordered(storage: &dyn Storage, folder: &str) -> ApiResult<FileLayout> {
    let mut entries: Vec<_> = storage
        .list(folder)
        .await?
        .into_iter()
        .filter(|entry| !entry.is_dir)
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut offset = 0u64;
    let volumes = entries
        .into_iter()
        .map(|entry| {
            let volume = VolumeMeta {
                name: entry.name,
                size: entry.size,
                offset,
            };
            offset += entry.size;
            volume
        })
        .collect();
    Ok(FileLayout {
        volumes,
        total: offset,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn stream_range_cached_mode(
    storage: Arc<dyn Storage>,
    enc_folder: String,
    pw: [u8; crate::crypto::SECRET_LEN],
    encrypted: bool,
    layout: Arc<FileLayout>,
    start: u64,
    end: u64,
    open_ended: bool,
    params: &StreamParams,
    cache: Option<Arc<crate::cache::CacheEntry>>,
    network_progress: Option<crate::adapters::ProgressFn>,
) -> mpsc::Receiver<io::Result<Bytes>> {
    let max_split = storage
        .max_range_size()
        .map_or(params.max_split, |limit| params.max_split.min(limit));
    let max_threads = params.max_threads.max(1);
    let max_per_volume = params.max_per_volume.max(1);
    let mode = params.mode;
    let profile_key = storage.download_profile_key();
    let initial_concurrency = load_learned_concurrency(profile_key.as_deref(), max_threads, mode);
    let adapter_metrics = Arc::new(RangeTransferMetrics::default());
    // One current serializer chunk plus one outstanding chunk per configured
    // worker is enough to keep every connection busy. A larger completed
    // prefetch window only inflates the working set when upstream outruns the
    // client.
    let max_buffered_chunks = max_threads.saturating_add(1);
    // Playback alone uses the tiny head zone; bulk/cache modes keep full-size
    // ranges while the scheduler below enforces their memory and volume caps.
    let plan = plan_chunks_with_head_count(
        &layout,
        start,
        end,
        max_split,
        open_ended,
        params.mode.head_count(open_ended),
    );
    let total_chunks = plan.len();

    tracing::debug!(
        "stream_range mode={} [{start},{end}] chunks={total_chunks} split={} threads={max_threads} per_vol={max_per_volume} open_ended={open_ended} buffered_chunks={max_buffered_chunks}",
        params.mode.as_str(),
        max_split,
    );

    // 每 chunk 一条通道，缓冲足以吸收整个 chunk —— fetcher 不必等
    // serializer 消费即可跑完并释放并发额度（hydraria 的教训：缓冲不足
    // 会让预取的下一卷首块把上游带宽压成 0）。
    let item_estimate = OUTPUT_BATCH as u64;
    let chan_buffer = ((max_split / item_estimate) as usize).clamp(8, 128);
    let mut senders: Vec<Option<mpsc::Sender<io::Result<Bytes>>>> =
        Vec::with_capacity(total_chunks);
    let mut receivers: Vec<mpsc::Receiver<io::Result<Bytes>>> = Vec::with_capacity(total_chunks);
    for _ in 0..total_chunks {
        let (tx, rx) = mpsc::channel(chan_buffer);
        senders.push(Some(tx));
        receivers.push(rx);
    }

    let (out_tx, out_rx) = mpsc::channel::<io::Result<Bytes>>(8);
    let (cache_writeback, cache_writer) = match cache.as_ref() {
        Some(entry) => {
            let (writer, task) =
                CacheWriteback::new(Arc::clone(entry), max_threads.saturating_mul(2));
            (Some(writer), Some(task))
        }
        None => (None, None),
    };
    let cache_queue_wait = cache_writeback
        .as_ref()
        .map(|writer| Arc::clone(&writer.queue_wait_micros));

    // Completion-driven scheduler + serializer. Playback only scans the near
    // window; bulk/cache modes may skip saturated volumes and fill the global
    // request budget from later volumes while the serializer still emits in order.
    tokio::spawn(async move {
        let stream_started = std::time::Instant::now();
        let plan = Arc::new(plan);
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<FetchStats>();
        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(total_chunks);
        let mut spawned = vec![false; total_chunks];
        let mut active = 0usize;
        let mut outstanding = 0usize;
        let mut active_per_volume = vec![0usize; layout.volumes.len()];
        let mut adaptive = AdaptiveConcurrency::new_with_initial(max_threads, initial_concurrency);
        let peak_active = AtomicUsize::new(0);
        let peak_outstanding = AtomicUsize::new(0);
        let mut delivered_total = 0u64;
        let mut first_byte_ms = None;
        let mut network_total = 0u64;
        let mut cache_total = 0u64;
        let mut retry_total = 0usize;
        let mut timeout_total = 0usize;
        let mut fetch_failures = 0usize;

        let spawn_one = |idx: usize, tx: mpsc::Sender<io::Result<Bytes>>| -> JoinHandle<()> {
            let c = plan[idx].clone();
            let vol_name = layout.volumes[c.vol].name.clone();
            let obj_path = if enc_folder.is_empty() {
                vol_name
            } else {
                format!("{enc_folder}/{vol_name}")
            };
            let context = FetchContext {
                mode,
                storage: Arc::clone(&storage),
                obj_path,
                pw,
                encrypted,
                cache: cache.clone(),
                cache_writeback: cache_writeback.clone(),
                network_progress: network_progress.clone(),
                transfer_metrics: Arc::clone(&adapter_metrics),
            };
            let done = done_tx.clone();
            tokio::spawn(async move {
                let stats = fetch_chunk(context, idx, c, tx).await;
                let _ = done.send(stats);
            })
        };
        let fill_window = |current: usize,
                           active: &mut usize,
                           outstanding: &mut usize,
                           active_per_volume: &mut [usize],
                           global_limit: usize,
                           per_volume_limit: usize,
                           spawned: &mut [bool],
                           senders: &mut [Option<mpsc::Sender<io::Result<Bytes>>>],
                           handles: &mut Vec<JoinHandle<()>>| {
            let scan_end = if mode == StreamMode::Playback {
                total_chunks.min(current.saturating_add(max_threads))
            } else {
                total_chunks
            };
            while *active < global_limit && *outstanding < max_buffered_chunks {
                let Some(idx) = (current..scan_end).find(|&idx| {
                    !spawned[idx] && active_per_volume[plan[idx].vol] < per_volume_limit
                }) else {
                    break;
                };
                let vol = plan[idx].vol;
                let tx = senders[idx].take().expect("chunk sender 仅使用一次");
                spawned[idx] = true;
                *active += 1;
                *outstanding += 1;
                peak_active.fetch_max(*active, Ordering::Relaxed);
                peak_outstanding.fetch_max(*outstanding, Ordering::Relaxed);
                active_per_volume[vol] += 1;
                handles.push(spawn_one(idx, tx));
            }
        };
        let abort_all = |handles: &[JoinHandle<()>]| {
            for handle in handles {
                handle.abort();
            }
        };

        // Client-facing modes start the exact requested chunk alone for low TTFB
        // and strict position priority. Cache warming has no client latency and
        // may fill its initial budget immediately.
        if total_chunks > 0 && mode != StreamMode::CacheWarm {
            let tx = senders[0].take().expect("首块 sender 仅使用一次");
            spawned[0] = true;
            active = 1;
            outstanding = 1;
            peak_active.store(1, Ordering::Relaxed);
            peak_outstanding.store(1, Ordering::Relaxed);
            active_per_volume[plan[0].vol] = 1;
            handles.push(spawn_one(0, tx));
        } else {
            fill_window(
                0,
                &mut active,
                &mut outstanding,
                &mut active_per_volume,
                adaptive.current,
                max_per_volume,
                &mut spawned,
                &mut senders,
                &mut handles,
            );
        }
        let mut client_window_opened = mode == StreamMode::CacheWarm;

        'outer: for (i, mut rx) in receivers.into_iter().enumerate() {
            let expect = plan[i].len;
            let mut got = 0u64;
            while got < expect {
                let item = loop {
                    tokio::select! {
                        biased;
                        _ = out_tx.closed() => {
                            tracing::debug!(
                                "客户端在 chunk {i} 等待期间断开，abort {} 个 fetcher",
                                handles.len()
                            );
                            abort_all(&handles);
                            break 'outer;
                        }
                        Some(stats) = done_rx.recv() => {
                            active = active.saturating_sub(1);
                            active_per_volume[stats.volume] = active_per_volume[stats.volume].saturating_sub(1);
                            network_total = network_total.saturating_add(stats.bytes);
                            cache_total = cache_total.saturating_add(stats.cache_bytes);
                            retry_total = retry_total.saturating_add(stats.retries);
                            timeout_total = timeout_total.saturating_add(stats.timeouts);
                            fetch_failures += usize::from(!stats.success);
                            if let Some((old, new, reason)) = adaptive.observe_failure(&stats) {
                                tracing::info!(
                                    "adaptive download concurrency mode={} {}->{} reason={reason}",
                                    mode.as_str(), old, new,
                                );
                            }
                            tracing::debug!(
                                "fetch chunk={} vol={} mode={} network_bytes={} cache_bytes={} elapsed_ms={} attempts={} timeouts={} cache_hit={} success={}",
                                stats.index,
                                stats.volume,
                                mode.as_str(),
                                stats.bytes,
                                stats.cache_bytes,
                                stats.elapsed.as_millis(),
                                stats.attempts,
                                stats.timeouts,
                                stats.cache_hit,
                                stats.success,
                            );
                            if client_window_opened {
                                fill_window(
                                    i,
                                    &mut active,
                                    &mut outstanding,
                                    &mut active_per_volume,
                                    adaptive.current,
                                    max_per_volume,
                                    &mut spawned,
                                    &mut senders,
                                    &mut handles,
                                );
                            }
                        },
                        item = rx.recv() => break item,
                    }
                };
                match item {
                    Some(Ok(b)) => {
                        got += b.len() as u64;
                        let delivered = b.len() as u64;
                        if out_tx.send(Ok(b)).await.is_err() {
                            tracing::debug!(
                                "客户端在 chunk {i} 输出期间断开，abort {} 个 fetcher",
                                handles.len()
                            );
                            abort_all(&handles);
                            break 'outer;
                        }
                        delivered_total = delivered_total.saturating_add(delivered);
                        first_byte_ms.get_or_insert_with(|| stream_started.elapsed().as_millis());
                        if let Some((old, new, reason)) =
                            adaptive.delivered(delivered, mode != StreamMode::Playback)
                        {
                            tracing::info!(
                                "adaptive download concurrency mode={} {}->{} reason={reason}",
                                mode.as_str(),
                                old,
                                new,
                            );
                            fill_window(
                                i,
                                &mut active,
                                &mut outstanding,
                                &mut active_per_volume,
                                adaptive.current,
                                max_per_volume,
                                &mut spawned,
                                &mut senders,
                                &mut handles,
                            );
                        }
                        if !client_window_opened {
                            client_window_opened = true;
                            fill_window(
                                i,
                                &mut active,
                                &mut outstanding,
                                &mut active_per_volume,
                                adaptive.current,
                                max_per_volume,
                                &mut spawned,
                                &mut senders,
                                &mut handles,
                            );
                        }
                    }
                    Some(Err(e)) => {
                        let _ = out_tx.send(Err(e)).await;
                        abort_all(&handles);
                        break 'outer;
                    }
                    None => {
                        let _ = out_tx
                            .send(Err(io::Error::other(format!(
                                "分片 {i} 提前结束（{got}/{expect} 字节）"
                            ))))
                            .await;
                        abort_all(&handles);
                        break 'outer;
                    }
                }
            }

            outstanding = outstanding.saturating_sub(1);
            fill_window(
                i.saturating_add(1),
                &mut active,
                &mut outstanding,
                &mut active_per_volume,
                adaptive.current,
                max_per_volume,
                &mut spawned,
                &mut senders,
                &mut handles,
            );
        }
        // Drain completion records that raced with the final ordered send.
        while let Ok(stats) = done_rx.try_recv() {
            network_total = network_total.saturating_add(stats.bytes);
            cache_total = cache_total.saturating_add(stats.cache_bytes);
            retry_total = retry_total.saturating_add(stats.retries);
            timeout_total = timeout_total.saturating_add(stats.timeouts);
            fetch_failures += usize::from(!stats.success);
        }
        let response_elapsed = stream_started.elapsed();
        // The HTTP body may finish as soon as the final ordered byte is sent;
        // cache metadata/writeback draining must not extend client-visible EOF.
        drop(out_tx);
        for handle in handles {
            let _ = handle.await;
        }
        while let Ok(stats) = done_rx.try_recv() {
            network_total = network_total.saturating_add(stats.bytes);
            cache_total = cache_total.saturating_add(stats.cache_bytes);
            retry_total = retry_total.saturating_add(stats.retries);
            timeout_total = timeout_total.saturating_add(stats.timeouts);
            fetch_failures += usize::from(!stats.success);
        }
        drop(cache_writeback);
        if let Some(writer) = cache_writer {
            let _ = writer.await;
        }
        if mode != StreamMode::Playback {
            save_learned_concurrency(profile_key.as_deref(), adaptive.stable_value());
        }
        let (hedges, candidate_failures, adapter_body_bytes, body_completions) =
            adapter_metrics.snapshot();
        let elapsed_secs = response_elapsed.as_secs_f64().max(0.001);
        tracing::info!(
            "stream summary mode={} delivered={} network={} cache={} cache_ratio_pct={:.1} first_byte_ms={} elapsed_ms={} client_mib_s={:.2} concurrency_start={} concurrency_final={} peak_active={} peak_outstanding={} retries={} timeouts={} failures={} hedges={} candidate_failures={} adapter_body_bytes={} body_completions={} cache_queue_wait_ms={}",
            mode.as_str(),
            delivered_total,
            network_total,
            cache_total,
            if delivered_total == 0 {
                0.0
            } else {
                cache_total as f64 * 100.0 / delivered_total as f64
            },
            first_byte_ms.unwrap_or(0),
            response_elapsed.as_millis(),
            delivered_total as f64 / 1024.0 / 1024.0 / elapsed_secs,
            initial_concurrency,
            adaptive.current,
            peak_active.load(Ordering::Relaxed),
            peak_outstanding.load(Ordering::Relaxed),
            retry_total,
            timeout_total,
            fetch_failures,
            hedges,
            candidate_failures,
            adapter_body_bytes,
            body_completions,
            cache_queue_wait
                .as_ref()
                .map_or(0, |value| value.load(Ordering::Relaxed) / 1_000),
        );
    });

    out_rx
}

/// 拉取单个 chunk 的密文区间并按合并偏移解密。完整缓存块和缺失区间可以
/// 在同一 chunk 内交替出现；输出仍严格按合并文件偏移连续解密。
async fn fetch_chunk(
    context: FetchContext,
    index: usize,
    c: PlannedChunk,
    tx: mpsc::Sender<io::Result<Bytes>>,
) -> FetchStats {
    let FetchContext {
        mode,
        storage,
        obj_path,
        pw,
        encrypted,
        cache,
        cache_writeback,
        network_progress,
        transfer_metrics,
    } = context;
    let started = std::time::Instant::now();
    let mut attempts = 0usize;
    let mut retries = 0usize;
    let mut timeouts = 0usize;
    let mut network_bytes = 0u64;
    let mut cache_bytes = 0u64;
    let merged_end = c.merged_start + c.len - 1;
    let cached_ranges = cache.as_ref().map_or_else(Vec::new, |entry| {
        entry.cached_ranges(c.merged_start, merged_end)
    });
    let segments = split_cache_segments(c.merged_start, merged_end, &cached_ranges);

    let (key, nonce) = content_cipher_params(&pw);
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    if encrypted && cipher.try_seek(c.merged_start).is_err() {
        let _ = tx.send(Err(io::Error::other("keystream 偏移越界"))).await;
        return failed_fetch_stats((index, c.vol), 0, 0, started, attempts, retries, timeouts);
    }
    let mut output_batch = BytesMut::with_capacity(OUTPUT_BATCH);
    let mut miss_recorded = false;

    for segment in segments {
        let mut network_start = segment.start;
        if segment.cached {
            let cache_entry = cache.as_ref().expect("cached segment requires cache");
            let mut cache_rx =
                stream_cached_range(Arc::clone(cache_entry), segment.start, segment.end);
            let mut cached_until = segment.start;
            while let Some(item) = cache_rx.recv().await {
                let bytes = match item {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        tracing::warn!(
                            "读取密文缓存区间 {}-{} 失败，剩余部分回源: {error}",
                            segment.start,
                            segment.end,
                        );
                        break;
                    }
                };
                let take =
                    (bytes.len() as u64).min(segment.end.saturating_sub(cached_until) + 1) as usize;
                if take == 0 {
                    continue;
                }
                cache_bytes += take as u64;
                cached_until += take as u64;
                if !append_output(
                    &tx,
                    &mut output_batch,
                    &mut cipher,
                    encrypted,
                    &bytes[..take],
                )
                .await
                {
                    return failed_fetch_stats(
                        (index, c.vol),
                        network_bytes,
                        cache_bytes,
                        started,
                        attempts,
                        retries,
                        timeouts,
                    );
                }
            }
            if cached_until > segment.end {
                continue;
            }
            network_start = cached_until;
        }

        if !miss_recorded {
            if let Some(cache) = &cache {
                cache.record_miss();
            }
            miss_recorded = true;
        }
        let segment_len = segment.end - network_start + 1;
        let mut remaining = segment_len;
        let mut segment_attempts = 0usize;
        let mut last_error = String::new();
        let mut cache_batch = if cache_writeback.is_some() {
            BytesMut::with_capacity(CACHE_WRITE_BATCH)
        } else {
            BytesMut::new()
        };
        let mut cache_batch_start = network_start;

        while remaining > 0 && segment_attempts < 4 {
            retries += usize::from(segment_attempts > 0);
            segment_attempts += 1;
            attempts += 1;
            let done = segment_len - remaining;
            let merged_position = network_start + done;
            let range_start = c.vol_off + (merged_position - c.merged_start);
            let range_end = c.vol_off + (segment.end - c.merged_start);
            let mut range_read = match tokio::time::timeout(
                mode.first_byte_timeout(),
                storage.get_range_tracked(
                    &obj_path,
                    range_start,
                    range_end,
                    Arc::clone(&transfer_metrics),
                ),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    last_error = error.to_string();
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(_) => {
                    timeouts += 1;
                    last_error = format!("建立 Range 请求超时: {range_start}-{range_end}");
                    continue;
                }
            };
            let before = remaining;
            let mut first_body = true;
            loop {
                let wait = if first_body {
                    mode.first_byte_timeout()
                } else {
                    mode.idle_timeout()
                };
                let item = match tokio::time::timeout(wait, range_read.stream.next()).await {
                    Ok(Some(item)) => item,
                    Ok(None) => break,
                    Err(_) => {
                        range_read.report_timeout();
                        timeouts += 1;
                        last_error = format!(
                            "Range 数据{}超时: {range_start}-{range_end}",
                            if first_body { "首字节" } else { "空闲" }
                        );
                        break;
                    }
                };
                first_body = false;
                let item = match item {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        last_error = error.to_string();
                        break;
                    }
                };
                if item.is_empty() {
                    continue;
                }
                let take = (item.len() as u64).min(remaining) as usize;
                if let Some(progress) = &network_progress {
                    progress(take as u64);
                }
                network_bytes += take as u64;
                let cache_offset = network_start + (segment_len - remaining);
                if let Some(writeback) = &cache_writeback {
                    if cache_batch.is_empty() {
                        cache_batch_start = cache_offset;
                    }
                    cache_batch.extend_from_slice(&item[..take]);
                    if cache_batch.len() >= CACHE_WRITE_BATCH {
                        flush_cache_batch(writeback, cache_batch_start, &mut cache_batch).await;
                    }
                }
                if !append_output(
                    &tx,
                    &mut output_batch,
                    &mut cipher,
                    encrypted,
                    &item[..take],
                )
                .await
                {
                    return failed_fetch_stats(
                        (index, c.vol),
                        network_bytes,
                        cache_bytes,
                        started,
                        attempts,
                        retries,
                        timeouts,
                    );
                }
                remaining -= take as u64;
                if remaining == 0 {
                    break;
                }
            }
            if let Some(writeback) = &cache_writeback {
                flush_cache_batch(writeback, cache_batch_start, &mut cache_batch).await;
            }
            if remaining == 0 {
                break;
            }
            if !flush_output_batch(&tx, &mut output_batch, true).await {
                return failed_fetch_stats(
                    (index, c.vol),
                    network_bytes,
                    cache_bytes,
                    started,
                    attempts,
                    retries,
                    timeouts,
                );
            }
            if last_error.is_empty() {
                last_error = if remaining == before {
                    format!("上游未返回 range {range_start}-{range_end}")
                } else {
                    format!("上游提前结束 range {range_start}-{range_end}")
                };
            }
            tracing::debug!(
                "分片网络区间重试 {segment_attempts}/4: path={obj_path} range={range_start}-{range_end} 剩余={remaining} err={last_error}",
            );
            tokio::task::yield_now().await;
        }
        if remaining > 0 {
            let _ = tx
                .send(Err(io::Error::other(format!(
                    "上游重试 {segment_attempts} 次后仍少 {remaining} 字节: {last_error}"
                ))))
                .await;
            return failed_fetch_stats(
                (index, c.vol),
                network_bytes,
                cache_bytes,
                started,
                attempts,
                retries,
                timeouts,
            );
        }
    }

    let success = flush_output_batch(&tx, &mut output_batch, true).await;
    FetchStats {
        index,
        volume: c.vol,
        bytes: network_bytes,
        cache_bytes,
        elapsed: started.elapsed(),
        attempts,
        retries,
        timeouts,
        cache_hit: cache_bytes == c.len,
        success,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheSegment {
    start: u64,
    end: u64,
    cached: bool,
}

fn split_cache_segments(start: u64, end: u64, cached: &[(u64, u64)]) -> Vec<CacheSegment> {
    if end < start {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut cursor = start;
    for &(cached_start, cached_end) in cached {
        let cached_start = cached_start.max(start);
        let cached_end = cached_end.min(end);
        if cached_end < cached_start || cached_end < cursor {
            continue;
        }
        if cursor < cached_start {
            result.push(CacheSegment {
                start: cursor,
                end: cached_start - 1,
                cached: false,
            });
        }
        let lo = cursor.max(cached_start);
        result.push(CacheSegment {
            start: lo,
            end: cached_end,
            cached: true,
        });
        cursor = cached_end.saturating_add(1);
        if cursor > end {
            break;
        }
    }
    if cursor <= end {
        result.push(CacheSegment {
            start: cursor,
            end,
            cached: false,
        });
    }
    result
}

fn stream_cached_range(
    cache: Arc<crate::cache::CacheEntry>,
    start: u64,
    end: u64,
) -> mpsc::Receiver<io::Result<Bytes>> {
    let (tx, rx) = mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let mut cursor = start;
        while cursor <= end {
            let chunk_end = end.min(cursor.saturating_add(CACHE_READ_BATCH - 1));
            let item = cache.read_range_untracked(cursor, chunk_end);
            let failed = item.is_err();
            if tx.blocking_send(item).is_err() || failed {
                return;
            }
            cursor = chunk_end.saturating_add(1);
        }
        cache.record_hit();
    });
    rx
}

async fn append_output(
    tx: &mpsc::Sender<io::Result<Bytes>>,
    output: &mut BytesMut,
    cipher: &mut ChaCha20,
    encrypted: bool,
    ciphertext: &[u8],
) -> bool {
    let offset = output.len();
    output.extend_from_slice(ciphertext);
    if encrypted {
        cipher.apply_keystream(&mut output[offset..]);
    }
    flush_output_batch(tx, output, false).await
}

fn failed_fetch_stats(
    identity: (usize, usize),
    bytes: u64,
    cache_bytes: u64,
    started: std::time::Instant,
    attempts: usize,
    retries: usize,
    timeouts: usize,
) -> FetchStats {
    let (index, volume) = identity;
    FetchStats {
        index,
        volume,
        bytes,
        cache_bytes,
        elapsed: started.elapsed(),
        attempts,
        retries,
        timeouts,
        cache_hit: false,
        success: false,
    }
}

async fn flush_output_batch(
    tx: &mpsc::Sender<io::Result<Bytes>>,
    batch: &mut BytesMut,
    flush_partial: bool,
) -> bool {
    while batch.len() >= OUTPUT_BATCH || (flush_partial && !batch.is_empty()) {
        let take = batch.len().min(OUTPUT_BATCH);
        if tx.send(Ok(batch.split_to(take).freeze())).await.is_err() {
            return false;
        }
    }
    true
}

async fn flush_cache_batch(writeback: &CacheWriteback, start: u64, batch: &mut BytesMut) {
    if batch.is_empty() {
        return;
    }
    let data = batch.split().freeze();
    writeback.enqueue(start, data).await;
}

// ---------------- 上传：流式加密 + 分卷切写 ----------------

/// 上传双维度进度：`encrypted` 是本地已加密并切入分卷的字节（受通道
/// 缓冲与 pending 上传数影响，会领先于真实上传）；`uploaded` 是存储端
/// 已确认接收的字节（由适配器上报，见 `Storage::put_sized_tracked`）。
pub struct UploadProgress {
    pub total: u64,
    pub encrypted: AtomicU64,
    pub uploaded: AtomicU64,
    network: Option<Arc<crate::transfer::TransferTracker>>,
}

impl UploadProgress {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(total: u64) -> Self {
        Self {
            total,
            encrypted: AtomicU64::new(0),
            uploaded: AtomicU64::new(0),
            network: None,
        }
    }
    pub fn tracked(total: u64, network: Arc<crate::transfer::TransferTracker>) -> Self {
        Self {
            total,
            encrypted: AtomicU64::new(0),
            uploaded: AtomicU64::new(0),
            network: Some(network),
        }
    }
}

/// 已封口但仍在等待存储端响应的最大分卷数。允许少量重叠可隐藏 WebDAV
/// 每次 PUT 的响应延迟，同时限制临时任务与连接占用。
const MAX_PENDING_UPLOADS: usize = 4;
type UploadTask = (mpsc::Sender<io::Result<Bytes>>, JoinHandle<ApiResult<()>>);
type PendingUploads = FuturesUnordered<JoinHandle<ApiResult<()>>>;

/// 把明文流加密并按分卷写入 `enc_folder/names[i]`。
/// `names` 必须来自 `gen_chunk_names(pw, chunk_count(total, volume_size))`。
/// 实际字节数与 `total` 不符即报错（调用方负责清理）。
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub async fn upload_stream<S>(
    storage: Arc<dyn Storage>,
    enc_folder: &str,
    pw: &[u8],
    total: u64,
    volume_size: u64,
    names: &[String],
    body: S,
    progress: Arc<UploadProgress>,
) -> ApiResult<()>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let sizes = (0..names.len())
        .map(|idx| {
            let start = idx as u64 * volume_size;
            volume_size.min(total.saturating_sub(start))
        })
        .collect::<Vec<_>>();
    upload_stream_planned(
        storage, enc_folder, pw, true, total, &sizes, names, body, progress,
    )
    .await
}

/// 按显式卷大小计划上传；`encrypted=false` 时原样写入，供未加密数据源使用。
#[allow(clippy::too_many_arguments)]
pub async fn upload_stream_planned<S>(
    storage: Arc<dyn Storage>,
    enc_folder: &str,
    pw: &[u8],
    encrypted: bool,
    total: u64,
    volume_sizes: &[u64],
    names: &[String],
    mut body: S,
    progress: Arc<UploadProgress>,
) -> ApiResult<()>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    if names.len() != volume_sizes.len() || volume_sizes.iter().sum::<u64>() != total {
        return Err(ApiError::BadRequest("分卷计划与文件大小不一致".into()));
    }
    if total == 0 {
        if let Some(name) = names.first() {
            let path = if enc_folder.is_empty() {
                name.clone()
            } else {
                format!("{enc_folder}/{name}")
            };
            return storage
                .put_sized(&path, 0, futures_util::stream::empty().boxed())
                .await;
        }
        return Ok(());
    }
    let (key, nonce) = content_cipher_params(pw);
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());

    let vol_cap = |idx: usize| -> u64 { volume_sizes[idx] };

    let mut vol_idx = 0usize;
    let mut sent_in_vol = 0u64;
    let mut received = 0u64;
    let mut current: Option<UploadTask> = None;
    let mut pending = PendingUploads::new();

    async fn close_current(cur: &mut Option<UploadTask>, pending: &mut PendingUploads) {
        let Some((tx, handle)) = cur.take() else {
            return;
        };
        drop(tx); // 关闭写端 → put 的输入流结束
        pending.push(handle);
    }

    async fn wait_one(pending: &mut PendingUploads) -> ApiResult<()> {
        let Some(handle) = pending.next().await else {
            return Ok(());
        };
        handle.map_err(|e| ApiError::Internal(anyhow::anyhow!("上传任务 panic: {e}")))?
    }

    async fn wait_all(pending: &mut PendingUploads) -> ApiResult<()> {
        let mut first_error = None;
        while let Some(handle) = pending.next().await {
            let result = handle
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("上传任务 panic: {e}")))
                .and_then(|result| result);
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    while let Some(item) = body.next().await {
        let item = match item {
            Ok(item) => item,
            Err(e) => {
                close_current(&mut current, &mut pending).await;
                let _ = wait_all(&mut pending).await;
                return Err(ApiError::BadRequest(format!("请求体读取失败: {e}")));
            }
        };
        if item.is_empty() {
            continue;
        }
        received += item.len() as u64;
        if received > total {
            close_current(&mut current, &mut pending).await;
            let _ = wait_all(&mut pending).await;
            return Err(ApiError::BadRequest("实际字节数超过声明大小".into()));
        }
        // Axum/Hyper 通常会交付独占 Bytes，此时可直接取得其底层缓冲并原地
        // 加密；只有共享缓冲才回退到复制。
        let mut buf = item
            .try_into_mut()
            .unwrap_or_else(|shared| bytes::BytesMut::from(shared.as_ref()));
        if encrypted {
            cipher.apply_keystream(&mut buf);
        }
        progress
            .encrypted
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
        let mut b = buf.freeze();

        while !b.is_empty() {
            if current.is_none() {
                let cap = vol_cap(vol_idx);
                let name = names
                    .get(vol_idx)
                    .ok_or_else(|| ApiError::BadRequest("分卷数超出计划".into()))?;
                let obj_path = if enc_folder.is_empty() {
                    name.clone()
                } else {
                    format!("{enc_folder}/{name}")
                };
                let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(8);
                let st = Arc::clone(&storage);
                let uploaded = Arc::clone(&progress);
                let on_upload: crate::adapters::ProgressFn = Arc::new(move |n| {
                    uploaded.uploaded.fetch_add(n, Ordering::Relaxed);
                    if let Some(network) = &uploaded.network {
                        network.upload(n);
                    }
                });
                let handle = tokio::spawn(async move {
                    st.put_sized_tracked(&obj_path, cap, ReceiverStream::new(rx).boxed(), on_upload)
                        .await
                });
                current = Some((tx, handle));
                sent_in_vol = 0;
            }
            let cap = vol_cap(vol_idx);
            let take = (cap - sent_in_vol).min(b.len() as u64) as usize;
            let piece = b.split_to(take);
            let send_ok = {
                let (tx, _) = current.as_ref().expect("上面刚建立");
                tx.send(Ok(piece)).await.is_ok()
            };
            if !send_ok {
                // put 任务提前退出（必然带错）→ 取回真实错误
                close_current(&mut current, &mut pending).await;
                wait_all(&mut pending).await?;
                return Err(ApiError::Upstream("分卷写入提前中断".into()));
            }
            sent_in_vol += take as u64;
            if sent_in_vol == cap {
                close_current(&mut current, &mut pending).await;
                vol_idx += 1;
                if pending.len() >= MAX_PENDING_UPLOADS
                    && let Err(e) = wait_one(&mut pending).await
                {
                    let _ = wait_all(&mut pending).await;
                    return Err(e);
                }
            }
        }
    }

    if received != total {
        // 尽力收尾（忽略其结果，尺寸不符已是致命错误）
        close_current(&mut current, &mut pending).await;
        let _ = wait_all(&mut pending).await;
        return Err(ApiError::BadRequest(format!(
            "实际字节数 {received} 与声明大小 {total} 不符"
        )));
    }
    // total>0 时最后一卷在 received==total 时恰好收口；防御性检查
    close_current(&mut current, &mut pending).await;
    wait_all(&mut pending).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::localfs::LocalFs;
    use crate::adapters::{ByteStream, Entry};
    use crate::crypto::{chunk_count, gen_chunk_names, gen_secret};
    use futures_util::stream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FlakyRangeStorage {
        encrypted: Bytes,
        calls: AtomicUsize,
    }

    struct SlowFirstFinalizeStorage;

    #[async_trait::async_trait]
    impl Storage for SlowFirstFinalizeStorage {
        async fn list(&self, _: &str) -> ApiResult<Vec<Entry>> {
            unreachable!()
        }
        async fn mkdir(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn rename(&self, _: &str, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn get(&self, _: &str) -> ApiResult<(Option<u64>, ByteStream)> {
            unreachable!()
        }
        async fn put(&self, path: &str, mut body: ByteStream) -> ApiResult<()> {
            while let Some(item) = body.next().await {
                item?;
            }
            if path.ends_with("/v0") {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl Storage for FlakyRangeStorage {
        async fn list(&self, _: &str) -> ApiResult<Vec<Entry>> {
            unreachable!()
        }
        async fn mkdir(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn rename(&self, _: &str, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn get(&self, _: &str) -> ApiResult<(Option<u64>, ByteStream)> {
            unreachable!()
        }

        async fn get_range(&self, _: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let bytes = self.encrypted.slice(start as usize..=end as usize);
            if call == 0 {
                let half = bytes.len() / 2;
                Ok(stream::iter(vec![
                    Ok(bytes.slice(..half)),
                    Err(io::Error::other("模拟中途断流")),
                ])
                .boxed())
            } else {
                Ok(stream::iter(vec![Ok(bytes)]).boxed())
            }
        }

        async fn put(&self, _: &str, _: ByteStream) -> ApiResult<()> {
            unreachable!()
        }
    }

    fn layout(sizes: &[u64]) -> FileLayout {
        let mut offset = 0;
        let volumes = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| {
                let v = VolumeMeta {
                    name: format!("vol{i:02}.bin"),
                    size,
                    offset,
                };
                offset += size;
                v
            })
            .collect();
        FileLayout {
            volumes,
            total: offset,
        }
    }

    /// 记录每次区间请求的存储：验证 seek 后哪些区间真的被请求了。
    struct RecordingRangeStorage {
        volumes: std::collections::HashMap<String, Bytes>,
        requests: std::sync::Mutex<Vec<(String, u64, u64)>>,
    }

    #[async_trait::async_trait]
    impl Storage for RecordingRangeStorage {
        async fn list(&self, _: &str) -> ApiResult<Vec<Entry>> {
            unreachable!()
        }
        async fn mkdir(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn rename(&self, _: &str, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn get(&self, _: &str) -> ApiResult<(Option<u64>, ByteStream)> {
            unreachable!()
        }
        async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
            self.requests
                .lock()
                .unwrap()
                .push((path.to_string(), start, end));
            let bytes = self.volumes[path].slice(start as usize..=end as usize);
            Ok(stream::iter(vec![Ok(bytes)]).boxed())
        }
        async fn put(&self, _: &str, _: ByteStream) -> ApiResult<()> {
            unreachable!()
        }
    }

    /// 慢速无限流存储：单个 chunk 在测试窗口内不可能拉完，用于验证
    /// 客户端断开后 in-flight fetcher 被 abort、不再发起新请求。
    struct SlowEndlessStorage {
        calls: AtomicUsize,
    }

    struct HangingRangeStorage;

    #[async_trait::async_trait]
    impl Storage for SlowEndlessStorage {
        async fn list(&self, _: &str) -> ApiResult<Vec<Entry>> {
            unreachable!()
        }
        async fn mkdir(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn rename(&self, _: &str, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn get(&self, _: &str) -> ApiResult<(Option<u64>, ByteStream)> {
            unreachable!()
        }
        async fn get_range(&self, _: &str, _: u64, _: u64) -> ApiResult<ByteStream> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(stream::unfold((), |()| async {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                Some((Ok(Bytes::from(vec![0u8; 4096])), ()))
            })
            .boxed())
        }
        async fn put(&self, _: &str, _: ByteStream) -> ApiResult<()> {
            unreachable!()
        }
    }

    #[async_trait::async_trait]
    impl Storage for HangingRangeStorage {
        async fn list(&self, _: &str) -> ApiResult<Vec<Entry>> {
            unreachable!()
        }
        async fn mkdir(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn delete(&self, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn rename(&self, _: &str, _: &str) -> ApiResult<()> {
            unreachable!()
        }
        async fn get(&self, _: &str) -> ApiResult<(Option<u64>, ByteStream)> {
            unreachable!()
        }
        async fn get_range(&self, _: &str, _: u64, _: u64) -> ApiResult<ByteStream> {
            Ok(stream::pending().boxed())
        }
        async fn put(&self, _: &str, _: ByteStream) -> ApiResult<()> {
            unreachable!()
        }
    }

    /// 播放器 seek（Range: bytes=X-）必须直接从 X 开始拉取：
    /// seek 点之前的分卷与字节永远不会被请求。
    #[tokio::test]
    async fn seek_starts_at_target_without_fetching_gap() {
        let vol_size = 1_000_000u64;
        let all: Vec<u8> = (0..2 * vol_size).map(|i| (i % 251) as u8).collect();
        let mut volumes = std::collections::HashMap::new();
        volumes.insert(
            "vol00.bin".to_string(),
            Bytes::copy_from_slice(&all[..vol_size as usize]),
        );
        volumes.insert(
            "vol01.bin".to_string(),
            Bytes::copy_from_slice(&all[vol_size as usize..]),
        );
        let storage = Arc::new(RecordingRangeStorage {
            volumes,
            requests: std::sync::Mutex::new(Vec::new()),
        });
        let seek = 1_200_000u64; // 第二卷内 200_000 处
        let mut rx = stream_range_cached_mode(
            Arc::clone(&storage) as Arc<dyn Storage>,
            String::new(),
            [0u8; crate::crypto::SECRET_LEN],
            false,
            Arc::new(layout(&[vol_size, vol_size])),
            seek,
            2 * vol_size - 1,
            true, // bytes=X- 的请求形态
            &StreamParams {
                max_split: 256 * 1024,
                max_threads: 4,
                max_per_volume: 2,
                mode: StreamMode::Playback,
            },
            None,
            None,
        );
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item.unwrap());
        }
        assert_eq!(out, &all[seek as usize..]);
        let requests = storage.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert_eq!(
            requests[0].1,
            seek - vol_size,
            "同一分卷必须让播放点对应的首块最先进入上游"
        );
        for (path, start, _) in requests.iter() {
            assert_eq!(path, "vol01.bin", "seek 点之前的分卷不应被请求");
            assert!(
                *start >= seek - vol_size,
                "不应回头补 seek 点之前的空档: 请求了卷内偏移 {start}"
            );
        }
        // 所有请求的最小偏移也必须恰好落在 seek 点上。
        let min_start = requests.iter().map(|(_, start, _)| *start).min().unwrap();
        assert_eq!(min_start, seek - vol_size);
    }

    #[tokio::test]
    async fn bulk_mode_fills_global_budget_across_volumes() {
        let volume_size = 4 * 1024 * 1024usize;
        let mut volumes = std::collections::HashMap::new();
        for index in 0..4 {
            volumes.insert(
                format!("vol{index:02}.bin"),
                Bytes::from(vec![index as u8; volume_size]),
            );
        }
        let storage = Arc::new(RecordingRangeStorage {
            volumes,
            requests: std::sync::Mutex::new(Vec::new()),
        });
        let rx = stream_range_cached_mode(
            Arc::clone(&storage) as Arc<dyn Storage>,
            String::new(),
            [0u8; crate::crypto::SECRET_LEN],
            false,
            Arc::new(layout(&[volume_size as u64; 4])),
            0,
            volume_size as u64 * 4 - 1,
            true,
            &StreamParams {
                max_split: 1024 * 1024,
                max_threads: 4,
                max_per_volume: 1,
                mode: StreamMode::BulkDownload,
            },
            None,
            None,
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let requested_volumes = storage
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|(path, ..)| path.clone())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            requested_volumes.len(),
            4,
            "bulk 模式应跳过单卷满额状态并从后续分卷补满总并发"
        );
        drop(rx);
    }

    #[test]
    fn adaptive_concurrency_probes_then_backs_off() {
        let mut adaptive = AdaptiveConcurrency::new(8);
        let stats = |elapsed_secs: u64, timeouts: usize| FetchStats {
            index: 0,
            volume: 0,
            bytes: 1_000_000,
            cache_bytes: 0,
            elapsed: std::time::Duration::from_secs(elapsed_secs),
            attempts: 1,
            retries: 0,
            timeouts,
            cache_hit: false,
            success: timeouts == 0,
        };
        assert!(adaptive.observe_delivery_rate(10_000_000.0, true).is_none());
        assert_eq!(
            adaptive.observe_delivery_rate(10_200_000.0, true),
            Some((4, 5, "throughput_probe"))
        );
        assert_eq!(
            adaptive.observe_delivery_rate(10_100_000.0, true),
            Some((5, 4, "throughput_probe_no_gain"))
        );
        assert_eq!(
            adaptive.observe_failure(&stats(1, 1)),
            Some((4, 2, "timeout_or_failure"))
        );

        let mut capped = AdaptiveConcurrency::new(4);
        for rate in [10_000_000.0, 4_000_000.0, 12_000_000.0] {
            assert!(
                capped.observe_delivery_rate(rate, true).is_none(),
                "硬上限处的普通吞吐波动不应触发降档"
            );
        }
        assert_eq!(capped.current, 4);
    }

    #[test]
    fn learned_concurrency_is_reused_but_playback_stays_conservative() {
        let key = "test-learned-concurrency";
        LEARNED_DOWNLOAD_CONCURRENCY.lock().unwrap().remove(key);
        save_learned_concurrency(Some(key), 7);
        assert_eq!(
            load_learned_concurrency(Some(key), 16, StreamMode::BulkDownload),
            7
        );
        assert_eq!(
            load_learned_concurrency(Some(key), 16, StreamMode::Playback),
            4
        );
        assert_eq!(
            load_learned_concurrency(Some(key), 5, StreamMode::CacheWarm),
            5
        );
        LEARNED_DOWNLOAD_CONCURRENCY.lock().unwrap().remove(key);
    }

    #[test]
    fn cache_segments_cover_only_true_gaps() {
        assert_eq!(
            split_cache_segments(100, 499, &[(100, 199), (300, 399)]),
            vec![
                CacheSegment {
                    start: 100,
                    end: 199,
                    cached: true
                },
                CacheSegment {
                    start: 200,
                    end: 299,
                    cached: false
                },
                CacheSegment {
                    start: 300,
                    end: 399,
                    cached: true
                },
                CacheSegment {
                    start: 400,
                    end: 499,
                    cached: false
                },
            ]
        );
    }

    #[tokio::test]
    async fn mixed_cache_hit_fetches_only_missing_blocks() {
        let total = 3 * crate::cache::BLOCK_SIZE;
        let plaintext = Bytes::from(
            (0..total)
                .map(|offset| (offset % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let pw = [0x42; crate::crypto::SECRET_LEN];
        let mut encrypted = plaintext.to_vec();
        crate::crypto::apply_content_keystream(&pw, 0, &mut encrypted);
        let source = Bytes::from(encrypted);
        let storage = Arc::new(RecordingRangeStorage {
            volumes: std::collections::HashMap::from([("vol00.bin".to_owned(), source.clone())]),
            requests: std::sync::Mutex::new(Vec::new()),
        });
        let dir = tempfile::tempdir().unwrap();
        let cache_store = crate::cache::CacheStore::new(dir.path().join("cache")).unwrap();
        let cache = cache_store.open("mixed", total).unwrap();
        cache
            .write_range(0, &source[..crate::cache::BLOCK_SIZE as usize])
            .unwrap();
        cache
            .write_range(
                2 * crate::cache::BLOCK_SIZE,
                &source[(2 * crate::cache::BLOCK_SIZE) as usize..],
            )
            .unwrap();

        let mut rx = stream_range_cached_mode(
            storage.clone(),
            String::new(),
            pw,
            true,
            Arc::new(layout(&[total])),
            0,
            total - 1,
            false,
            &StreamParams {
                max_split: total,
                max_threads: 1,
                max_per_volume: 1,
                mode: StreamMode::BulkDownload,
            },
            Some(cache),
            None,
        );
        let mut output = Vec::new();
        while let Some(item) = rx.recv().await {
            output.extend_from_slice(&item.unwrap());
        }
        assert_eq!(output, plaintext.as_ref());
        assert_eq!(
            storage.requests.lock().unwrap().as_slice(),
            &[(
                "vol00.bin".to_owned(),
                crate::cache::BLOCK_SIZE,
                2 * crate::cache::BLOCK_SIZE - 1,
            )]
        );
    }

    /// 客户端断开（播放器 seek 会立即弃掉旧请求）后，所有 in-flight
    /// fetcher 被 abort，不再向上游发起新的区间请求 —— 与 hydraria 的
    /// bandwidth claw-back 行为一致，保证 seek 不与遗留流量抢带宽。
    #[tokio::test]
    async fn dropping_receiver_aborts_inflight_fetchers() {
        let storage = Arc::new(SlowEndlessStorage {
            calls: AtomicUsize::new(0),
        });
        let total = 64 * 1024 * 1024u64;
        let mut rx = stream_range_cached_mode(
            Arc::clone(&storage) as Arc<dyn Storage>,
            String::new(),
            [0u8; crate::crypto::SECRET_LEN],
            false,
            Arc::new(layout(&[total])),
            0,
            total - 1,
            true,
            &StreamParams {
                max_split: 1024 * 1024,
                max_threads: 4,
                max_per_volume: 2,
                mode: StreamMode::Playback,
            },
            None,
            None,
        );
        // 收到首个数据块后模拟播放器 seek：断开旧连接
        let first = rx.recv().await.unwrap().unwrap();
        assert!(!first.is_empty());
        drop(rx);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let after_drop = storage.calls.load(Ordering::SeqCst);
        assert!(
            after_drop <= 2,
            "断开前的在途请求数不应超过单卷并发上限: {after_drop}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            storage.calls.load(Ordering::SeqCst),
            after_drop,
            "断开后不应再发起新的区间请求"
        );
    }

    #[tokio::test]
    async fn stalled_range_body_times_out_and_reports_diagnostics() {
        let (tx, mut rx) = mpsc::channel(8);
        let task = tokio::spawn(fetch_chunk(
            FetchContext {
                mode: StreamMode::Playback,
                storage: Arc::new(HangingRangeStorage),
                obj_path: "volume".into(),
                pw: [0u8; crate::crypto::SECRET_LEN],
                encrypted: false,
                cache: None,
                cache_writeback: None,
                network_progress: None,
                transfer_metrics: Arc::new(RangeTransferMetrics::default()),
            },
            7,
            PlannedChunk {
                merged_start: 0,
                len: 1024,
                vol: 0,
                vol_off: 0,
            },
            tx,
        ));
        let error = rx.recv().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("超时"), "{error}");
        let stats = task.await.unwrap();
        assert_eq!(stats.index, 7);
        assert_eq!(stats.attempts, 4);
        assert_eq!(stats.timeouts, 4);
        assert!(!stats.success);
    }

    #[test]
    fn parse_range_cases() {
        assert_eq!(parse_range(None, 100), (RangeSpec::Full, true));
        assert_eq!(
            parse_range(Some("bytes=0-49"), 100),
            (RangeSpec::Slice { start: 0, end: 49 }, false)
        );
        assert_eq!(
            parse_range(Some("bytes=10-"), 100),
            (RangeSpec::Slice { start: 10, end: 99 }, true),
            "开区间 → open_ended"
        );
        assert_eq!(
            parse_range(Some("bytes=-30"), 100),
            (RangeSpec::Slice { start: 70, end: 99 }, false)
        );
        assert_eq!(
            parse_range(Some("bytes=0-999"), 100),
            (RangeSpec::Slice { start: 0, end: 99 }, false),
            "end 截断"
        );
        assert_eq!(
            parse_range(Some("bytes=100-"), 100),
            (RangeSpec::Unsatisfiable, false)
        );
        assert_eq!(
            parse_range(Some("bytes=5-2"), 100),
            (RangeSpec::Unsatisfiable, false)
        );
        assert_eq!(parse_range(Some("bytes=abc"), 100), (RangeSpec::Full, true));
        assert_eq!(
            parse_range(Some("bytes=0-1,5-6"), 100),
            (RangeSpec::Full, true)
        );
    }

    #[test]
    fn plan_respects_volume_boundaries_and_split() {
        let l = layout(&[1000, 1000, 500]);
        let plan = plan_chunks(&l, 0, l.total - 1, 400, false);
        // 卷0: 400+400+200; 卷1: 400+400+200; 卷2: 400+100
        assert_eq!(plan.len(), 8);
        for c in &plan {
            let v = &l.volumes[c.vol];
            assert!(c.vol_off + c.len <= v.size, "chunk 不跨卷");
            assert_eq!(c.merged_start, v.offset + c.vol_off);
        }
        // 连续无缝
        let mut cur = 0;
        for c in &plan {
            assert_eq!(c.merged_start, cur);
            cur += c.len;
        }
        assert_eq!(cur, 2500);
    }

    #[test]
    fn plan_head_zone_for_open_ended() {
        let l = layout(&[10_000_000]);
        let plan = plan_chunks(&l, 0, l.total - 1, 5_000_000, true);
        assert_eq!(plan[0].len, HEAD_SMALL_SPLIT);
        assert_eq!(plan[3].len, HEAD_SMALL_SPLIT);
        assert!(plan[4].len > HEAD_SMALL_SPLIT);
        // 非开区间不削
        let plan2 = plan_chunks(&l, 0, l.total - 1, 5_000_000, false);
        assert_eq!(plan2[0].len, 5_000_000);
    }

    #[test]
    fn open_ended_uses_fixed_small_head_zone_then_full_splits() {
        let threads = 16;
        let l = layout(&[256 * 1024 * 1024]);
        let plan = plan_chunks_with_head_count(
            &l,
            0,
            l.total - 1,
            5 * 1024 * 1024,
            true,
            HEAD_SMALL_COUNT,
        );
        assert!(plan.len() > threads);
        assert!(
            plan[..HEAD_SMALL_COUNT]
                .iter()
                .all(|chunk| chunk.len == HEAD_SMALL_SPLIT),
            "播放头部区必须使用小分片"
        );
        assert_eq!(
            plan[HEAD_SMALL_COUNT].len,
            5 * 1024 * 1024,
            "头部区之后应立即恢复大分片以维持吞吐"
        );
    }

    #[test]
    fn plan_mid_range_starts_in_right_volume() {
        let l = layout(&[1000, 1000, 500]);
        let plan = plan_chunks(&l, 1500, 2200, 10_000, false);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan[0],
            PlannedChunk {
                merged_start: 1500,
                len: 500,
                vol: 1,
                vol_off: 500
            }
        );
        assert_eq!(
            plan[1],
            PlannedChunk {
                merged_start: 2000,
                len: 201,
                vol: 2,
                vol_off: 0
            }
        );
    }

    #[tokio::test]
    async fn upload_waits_for_any_finished_volume_not_oldest() {
        let storage: Arc<dyn Storage> = Arc::new(SlowFirstFinalizeStorage);
        let progress = Arc::new(UploadProgress::new(5));
        let sizes = vec![1; MAX_PENDING_UPLOADS + 1];
        let names = (0..sizes.len())
            .map(|index| format!("v{index}"))
            .collect::<Vec<_>>();
        let task_progress = Arc::clone(&progress);
        let task = tokio::spawn(async move {
            upload_stream_planned(
                storage,
                "folder",
                &[0; crate::crypto::SECRET_LEN],
                false,
                5,
                &sizes,
                &names,
                stream::iter([Ok(Bytes::from_static(b"12345"))]),
                task_progress,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            progress.encrypted.load(Ordering::Relaxed),
            5,
            "后续卷已完成时，不应被最早卷的收尾响应阻塞前置处理"
        );
        task.await.unwrap().unwrap();
    }

    /// 端到端：上传（加密+分卷）→ 存储形态断言 → 全量/区间下载解密一致。
    #[tokio::test]
    async fn upload_then_stream_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::from(Box::new(
            LocalFs::from_config(&serde_json::json!({"root": dir.path().to_str().unwrap()}))
                .unwrap(),
        ) as Box<dyn Storage>);

        let pw = gen_secret();
        let plain: Vec<u8> = (0..700_000u32).map(|i| (i * 31 % 256) as u8).collect();
        let total = plain.len() as u64;
        let volume_size = 256 * 1024u64;
        let names = gen_chunk_names(&pw, chunk_count(total, volume_size));

        storage.mkdir("ENCFOLDER").await.unwrap();
        let body = stream::iter(
            plain
                .chunks(17_000)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        );
        let progress = Arc::new(UploadProgress::new(total));
        upload_stream(
            Arc::clone(&storage),
            "ENCFOLDER",
            &pw,
            total,
            volume_size,
            &names,
            body,
            Arc::clone(&progress),
        )
        .await
        .unwrap();
        assert_eq!(progress.encrypted.load(Ordering::Relaxed), total);
        assert_eq!(
            progress.uploaded.load(Ordering::Relaxed),
            total,
            "localfs 直写：消费即上传"
        );

        // 存储形态：3 个随机名分卷，大小 = 明文分段大小（流密码无膨胀），内容 ≠ 明文
        let entries = storage.list("ENCFOLDER").await.unwrap();
        assert_eq!(entries.len(), 3);
        let disk_total: u64 = entries.iter().map(|e| e.size).sum();
        assert_eq!(disk_total, total);
        // 名字确定性可再生成，2 字符 hex
        for e in &entries {
            assert!(names.contains(&e.name), "{}", e.name);
            assert_eq!(e.name.len(), 2);
        }
        let raw = std::fs::read(dir.path().join("ENCFOLDER").join(&names[0])).unwrap();
        assert_ne!(&raw[..], &plain[..raw.len()], "磁盘上必须是密文");

        // 布局
        let l = Arc::new(
            load_layout(storage.as_ref(), "ENCFOLDER", &pw)
                .await
                .unwrap(),
        );
        // 布局顺序 = 派生顺序
        assert_eq!(
            l.volumes.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
            names
        );
        assert_eq!(l.total, total);
        assert_eq!(l.volumes.len(), 3);

        let params = StreamParams {
            max_split: 100_000,
            max_threads: 8,
            max_per_volume: 2,
            mode: StreamMode::BulkDownload,
        };
        let cache_store = crate::cache::CacheStore::new(dir.path().join(".cache")).unwrap();
        let cache = cache_store.open("roundtrip", total).unwrap();

        // 全量回源并填充缓存
        let mut rx = stream_range_cached(
            Arc::clone(&storage),
            "ENCFOLDER".into(),
            pw,
            Arc::clone(&l),
            0,
            total - 1,
            false,
            &params,
            Some(Arc::clone(&cache)),
        );
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item.unwrap());
        }
        assert_eq!(out, plain, "全量下载解密一致");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while cache_store.stats().bytes_cached != total {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP 输出结束后缓存写回应很快独立排空");
        assert_eq!(cache_store.stats().bytes_cached, total);
        storage.delete("ENCFOLDER").await.unwrap();

        // 删除上游后，跨卷任意区间仍必须从全局密文缓存正确解密。
        for (s, e) in [
            (0u64, 0u64),
            (262_143, 262_144),
            (100_000, 550_000),
            (699_999, 699_999),
        ] {
            let mut rx = stream_range_cached(
                Arc::clone(&storage),
                "ENCFOLDER".into(),
                pw,
                Arc::clone(&l),
                s,
                e,
                true,
                &params,
                Some(Arc::clone(&cache)),
            );
            let mut out = Vec::new();
            while let Some(item) = rx.recv().await {
                out.extend_from_slice(&item.unwrap());
            }
            assert_eq!(out, &plain[s as usize..=e as usize], "区间 [{s},{e}]");
        }
    }

    #[tokio::test]
    async fn upload_size_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::from(Box::new(
            LocalFs::from_config(&serde_json::json!({"root": dir.path().to_str().unwrap()}))
                .unwrap(),
        ) as Box<dyn Storage>);
        storage.mkdir("F").await.unwrap();
        let pw = gen_secret();

        // 少给
        let names = gen_chunk_names(&pw, 1);
        let body = stream::iter(vec![Ok(Bytes::from_static(b"short"))]);
        let progress = || Arc::new(UploadProgress::new(100));
        assert!(
            upload_stream(
                Arc::clone(&storage),
                "F",
                &pw,
                100,
                1024,
                &names,
                body,
                progress()
            )
            .await
            .is_err()
        );
        // 多给
        let body = stream::iter(vec![Ok(Bytes::from(vec![0u8; 200]))]);
        assert!(
            upload_stream(
                Arc::clone(&storage),
                "F",
                &pw,
                100,
                1024,
                &names,
                body,
                progress()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn empty_file_uploads_no_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::from(Box::new(
            LocalFs::from_config(&serde_json::json!({"root": dir.path().to_str().unwrap()}))
                .unwrap(),
        ) as Box<dyn Storage>);
        storage.mkdir("E").await.unwrap();
        let pw = gen_secret();
        let body = stream::iter(Vec::<io::Result<Bytes>>::new());
        upload_stream(
            Arc::clone(&storage),
            "E",
            &pw,
            0,
            1024,
            &[],
            body,
            Arc::new(UploadProgress::new(0)),
        )
        .await
        .unwrap();
        let l = load_layout(storage.as_ref(), "E", &pw).await.unwrap();
        assert_eq!(l.total, 0);
        assert!(l.volumes.is_empty());
    }

    #[tokio::test]
    async fn fetch_chunk_resumes_after_midstream_failure() {
        let pw = gen_secret();
        let plain = Bytes::from((0..100_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let mut encrypted = plain.to_vec();
        crate::crypto::apply_content_keystream(&pw, 0, &mut encrypted);
        let storage = Arc::new(FlakyRangeStorage {
            encrypted: Bytes::from(encrypted),
            calls: AtomicUsize::new(0),
        });
        let (tx, mut rx) = mpsc::channel(16);
        fetch_chunk(
            FetchContext {
                mode: StreamMode::BulkDownload,
                storage: storage.clone(),
                obj_path: "v".into(),
                pw,
                encrypted: true,
                cache: None,
                cache_writeback: None,
                network_progress: None,
                transfer_metrics: Arc::new(RangeTransferMetrics::default()),
            },
            0,
            PlannedChunk {
                merged_start: 0,
                len: plain.len() as u64,
                vol: 0,
                vol_off: 0,
            },
            tx,
        )
        .await;
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item.unwrap());
        }
        assert_eq!(out, plain);
        assert_eq!(storage.calls.load(Ordering::SeqCst), 2);
    }
}
