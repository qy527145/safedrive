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

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use futures_util::{Stream, StreamExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;

use crate::adapters::Storage;
use crate::crypto::{ChunkPrp, content_cipher_params};
use crate::error::{ApiError, ApiResult};

/// 开区间请求的首块小分片（加速播放器起播/seek 响应）。
const HEAD_SMALL_SPLIT: u64 = 512 * 1024;
const HEAD_SMALL_COUNT: usize = 4;

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
    Ok(FileLayout { volumes, total: offset })
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
            (RangeSpec::Slice { start: s, end: e.min(total - 1) }, false)
        }
        (false, true) => {
            let Ok(s) = a.parse::<u64>() else {
                return (RangeSpec::Full, true);
            };
            if s >= total {
                return (RangeSpec::Unsatisfiable, false);
            }
            (RangeSpec::Slice { start: s, end: total - 1 }, true)
        }
        (true, false) => {
            let Ok(n) = b.parse::<u64>() else {
                return (RangeSpec::Full, true);
            };
            if n == 0 {
                return (RangeSpec::Unsatisfiable, false);
            }
            let start = total.saturating_sub(n);
            (RangeSpec::Slice { start, end: total - 1 }, false)
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

/// 把合并区间 [start, end] 先按分卷边界、再按 split 切开；开区间请求的
/// 前几个 chunk 用更小的分片（HEAD_SMALL_SPLIT）。
/// 每个 chunk 只落在一个分卷内 —— fetcher 只需向单个对象发一次区间读。
pub fn plan_chunks(
    layout: &FileLayout,
    start: u64,
    end: u64,
    max_split: u64,
    open_ended: bool,
) -> Vec<PlannedChunk> {
    let split = max_split.max(1); // 下限由策略校验保证，这里只防 0
    let head: usize =
        if open_ended && split > HEAD_SMALL_SPLIT { HEAD_SMALL_COUNT } else { 0 };
    let mut plan = Vec::new();
    let mut cur = start;
    let mut vol_idx = 0usize;
    while cur <= end && vol_idx < layout.volumes.len() {
        let v = &layout.volumes[vol_idx];
        if v.size == 0 || cur >= v.offset + v.size {
            vol_idx += 1;
            continue;
        }
        let this_split = if plan.len() < head { HEAD_SMALL_SPLIT } else { split };
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
}

/// fetcher 退出（成功/失败/被 abort）时自动归还并发额度。
struct ReleaseGuard {
    tx: mpsc::UnboundedSender<usize>,
    vol: usize,
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(self.vol);
    }
}

/// 按合并区间 [start, end] 流式产出解密后的明文字节。
pub fn stream_range(
    storage: Arc<dyn Storage>,
    enc_folder: String,
    pw: [u8; crate::crypto::SECRET_LEN],
    layout: Arc<FileLayout>,
    start: u64,
    end: u64,
    open_ended: bool,
    params: &StreamParams,
) -> mpsc::Receiver<io::Result<Bytes>> {
    let plan = plan_chunks(&layout, start, end, params.max_split, open_ended);
    let max_threads = params.max_threads.max(1);
    let max_per_volume = params.max_per_volume.max(1);
    let total_chunks = plan.len();
    let vol_count = layout.volumes.len().max(1);

    tracing::debug!(
        "stream_range [{start},{end}] chunks={total_chunks} split={} threads={max_threads} per_vol={max_per_volume} open_ended={open_ended}",
        params.max_split,
    );

    // 每 chunk 一条通道，缓冲足以吸收整个 chunk —— fetcher 不必等
    // serializer 消费即可跑完并释放并发额度（hydraria 的教训：缓冲不足
    // 会让预取的下一卷首块把上游带宽压成 0）。
    let item_estimate = 16 * 1024u64;
    let chan_buffer =
        ((params.max_split / item_estimate) as usize).clamp(8, 512);
    let mut senders: Vec<Option<mpsc::Sender<io::Result<Bytes>>>> =
        Vec::with_capacity(total_chunks);
    let mut receivers: Vec<mpsc::Receiver<io::Result<Bytes>>> =
        Vec::with_capacity(total_chunks);
    for _ in 0..total_chunks {
        let (tx, rx) = mpsc::channel(chan_buffer);
        senders.push(Some(tx));
        receivers.push(rx);
    }

    let (out_tx, out_rx) = mpsc::channel::<io::Result<Bytes>>(8);
    let (release_tx, mut release_rx) = mpsc::unbounded_channel::<usize>();
    let cancel = Arc::new(Notify::new());

    // 调度器：按计划顺序在额度允许时孵化 fetcher。计划本身按合并偏移
    // 有序，队头受限时后面的 chunk 几乎必然同卷，所以队头阻塞即正确。
    let sched_plan = plan.clone();
    let sched_cancel = Arc::clone(&cancel);
    let sched_storage = Arc::clone(&storage);
    let sched_layout = Arc::clone(&layout);
    tokio::spawn(async move {
        let mut next = 0usize;
        let mut inflight = 0usize;
        let mut inflight_vol = vec![0usize; vol_count];
        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(total_chunks);
        loop {
            while next < total_chunks
                && inflight < max_threads
                && inflight_vol[sched_plan[next].vol] < max_per_volume
            {
                let c = sched_plan[next].clone();
                let tx = senders[next].take().expect("每个 chunk 只孵化一次");
                let guard = ReleaseGuard { tx: release_tx.clone(), vol: c.vol };
                inflight += 1;
                inflight_vol[c.vol] += 1;
                let vol_name = sched_layout.volumes[c.vol].name.clone();
                let obj_path = if enc_folder.is_empty() {
                    vol_name
                } else {
                    format!("{enc_folder}/{vol_name}")
                };
                let st = Arc::clone(&sched_storage);
                handles.push(tokio::spawn(async move {
                    let _guard = guard;
                    fetch_chunk(st, obj_path, pw, c, tx).await;
                }));
                next += 1;
            }
            if next >= total_chunks && inflight == 0 {
                break;
            }
            tokio::select! {
                _ = sched_cancel.notified() => {
                    tracing::debug!("客户端断开，abort {} 个 in-flight fetcher", inflight);
                    for h in &handles {
                        h.abort();
                    }
                    break;
                }
                got = release_rx.recv() => {
                    match got {
                        Some(v) => {
                            inflight -= 1;
                            inflight_vol[v] -= 1;
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // serializer：按计划顺序转发到输出通道。
    let ser_cancel = Arc::clone(&cancel);
    tokio::spawn(async move {
        'outer: for (i, mut rx) in receivers.into_iter().enumerate() {
            let expect = plan[i].len;
            let mut got = 0u64;
            while got < expect {
                match rx.recv().await {
                    Some(Ok(b)) => {
                        got += b.len() as u64;
                        if out_tx.send(Ok(b)).await.is_err() {
                            // 客户端断开
                            ser_cancel.notify_one();
                            break 'outer;
                        }
                    }
                    Some(Err(e)) => {
                        let _ = out_tx.send(Err(e)).await;
                        ser_cancel.notify_one();
                        break 'outer;
                    }
                    None => {
                        let _ = out_tx
                            .send(Err(io::Error::other(format!(
                                "分片 {i} 提前结束（{got}/{expect} 字节）"
                            ))))
                            .await;
                        ser_cancel.notify_one();
                        break 'outer;
                    }
                }
            }
        }
    });

    out_rx
}

/// 拉取单个 chunk 的密文区间并按合并偏移解密。
async fn fetch_chunk(
    storage: Arc<dyn Storage>,
    obj_path: String,
    pw: [u8; crate::crypto::SECRET_LEN],
    c: PlannedChunk,
    tx: mpsc::Sender<io::Result<Bytes>>,
) {
    let mut stream = match storage.get_range(&obj_path, c.vol_off, c.vol_off + c.len - 1).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(Err(io::Error::other(e.to_string()))).await;
            return;
        }
    };
    // 每 chunk 建一次 cipher，seek 到合并偏移后连续吐 keystream。
    let (key, nonce) = content_cipher_params(&pw);
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    if cipher.try_seek(c.merged_start).is_err() {
        let _ = tx.send(Err(io::Error::other("keystream 偏移越界"))).await;
        return;
    }
    let mut remaining = c.len;
    while let Some(item) = stream.next().await {
        let item = match item {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        if item.is_empty() {
            continue;
        }
        // 上游多给的字节直接截掉（区间读语义以我们的计划为准）
        let take = (item.len() as u64).min(remaining) as usize;
        let mut buf = item[..take].to_vec();
        cipher.apply_keystream(&mut buf);
        remaining -= take as u64;
        if tx.send(Ok(Bytes::from(buf))).await.is_err() {
            return; // serializer 已放弃
        }
        if remaining == 0 {
            return;
        }
    }
    if remaining > 0 {
        let _ = tx
            .send(Err(io::Error::other(format!("上游少给 {remaining} 字节"))))
            .await;
    }
}

// ---------------- 上传：流式加密 + 分卷切写 ----------------

/// 已封口但仍在等待存储端响应的最大分卷数。允许少量重叠可隐藏 WebDAV
/// 每次 PUT 的响应延迟，同时限制临时任务与连接占用。
const MAX_PENDING_UPLOADS: usize = 2;
type UploadTask = (mpsc::Sender<io::Result<Bytes>>, JoinHandle<ApiResult<()>>);

/// 把明文流加密并按分卷写入 `enc_folder/names[i]`。
/// `names` 必须来自 `gen_chunk_names(pw, chunk_count(total, volume_size))`。
/// 实际字节数与 `total` 不符即报错（调用方负责清理）。
pub async fn upload_stream<S>(
    storage: Arc<dyn Storage>,
    enc_folder: &str,
    pw: &[u8],
    total: u64,
    volume_size: u64,
    names: &[String],
    mut body: S,
) -> ApiResult<()>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    let (key, nonce) = content_cipher_params(pw);
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());

    let vol_cap = |idx: usize| -> u64 {
        let start = idx as u64 * volume_size;
        volume_size.min(total - start)
    };

    let mut vol_idx = 0usize;
    let mut sent_in_vol = 0u64;
    let mut received = 0u64;
    let mut current: Option<UploadTask> = None;
    let mut pending = std::collections::VecDeque::<JoinHandle<ApiResult<()>>>::new();

    async fn close_current(
        cur: &mut Option<UploadTask>,
        pending: &mut std::collections::VecDeque<JoinHandle<ApiResult<()>>>,
    ) {
        let Some((tx, handle)) = cur.take() else { return };
        drop(tx); // 关闭写端 → put 的输入流结束
        pending.push_back(handle);
    }

    async fn wait_one(
        pending: &mut std::collections::VecDeque<JoinHandle<ApiResult<()>>>,
    ) -> ApiResult<()> {
        let Some(handle) = pending.pop_front() else { return Ok(()) };
        handle
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("上传任务 panic: {e}")))?
    }

    async fn wait_all(
        pending: &mut std::collections::VecDeque<JoinHandle<ApiResult<()>>>,
    ) -> ApiResult<()> {
        let mut first_error = None;
        while let Some(handle) = pending.pop_front() {
            let result = handle
                .await
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
        cipher.apply_keystream(&mut buf);
        let mut b = buf.freeze();

        while !b.is_empty() {
            if current.is_none() {
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
                let handle = tokio::spawn(async move {
                    st.put(&obj_path, ReceiverStream::new(rx).boxed()).await
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
    use crate::crypto::{chunk_count, gen_chunk_names, gen_secret};
    use futures_util::stream;

    fn layout(sizes: &[u64]) -> FileLayout {
        let mut offset = 0;
        let volumes = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| {
                let v = VolumeMeta { name: format!("vol{i:02}.bin"), size, offset };
                offset += size;
                v
            })
            .collect();
        FileLayout { volumes, total: offset }
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
        assert_eq!(parse_range(Some("bytes=100-"), 100), (RangeSpec::Unsatisfiable, false));
        assert_eq!(parse_range(Some("bytes=5-2"), 100), (RangeSpec::Unsatisfiable, false));
        assert_eq!(parse_range(Some("bytes=abc"), 100), (RangeSpec::Full, true));
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), (RangeSpec::Full, true));
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
    fn plan_mid_range_starts_in_right_volume() {
        let l = layout(&[1000, 1000, 500]);
        let plan = plan_chunks(&l, 1500, 2200, 10_000, false);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], PlannedChunk { merged_start: 1500, len: 500, vol: 1, vol_off: 500 });
        assert_eq!(plan[1], PlannedChunk { merged_start: 2000, len: 201, vol: 2, vol_off: 0 });
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
            plain.chunks(17_000).map(|c| Ok(Bytes::copy_from_slice(c))).collect::<Vec<_>>(),
        );
        upload_stream(Arc::clone(&storage), "ENCFOLDER", &pw, total, volume_size, &names, body)
            .await
            .unwrap();

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
        let l = Arc::new(load_layout(storage.as_ref(), "ENCFOLDER", &pw).await.unwrap());
        // 布局顺序 = 派生顺序
        assert_eq!(l.volumes.iter().map(|v| v.name.clone()).collect::<Vec<_>>(), names);
        assert_eq!(l.total, total);
        assert_eq!(l.volumes.len(), 3);

        let params =
            StreamParams { max_split: 100_000, max_threads: 8, max_per_volume: 2 };

        // 全量
        let mut rx = stream_range(
            Arc::clone(&storage),
            "ENCFOLDER".into(),
            pw,
            Arc::clone(&l),
            0,
            total - 1,
            false,
            &params,
        );
        let mut out = Vec::new();
        while let Some(item) = rx.recv().await {
            out.extend_from_slice(&item.unwrap());
        }
        assert_eq!(out, plain, "全量下载解密一致");

        // 跨卷任意区间（模拟 seek）
        for (s, e) in [(0u64, 0u64), (262_143, 262_144), (100_000, 550_000), (699_999, 699_999)] {
            let mut rx = stream_range(
                Arc::clone(&storage),
                "ENCFOLDER".into(),
                pw,
                Arc::clone(&l),
                s,
                e,
                true,
                &params,
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
        assert!(
            upload_stream(Arc::clone(&storage), "F", &pw, 100, 1024, &names, body).await.is_err()
        );
        // 多给
        let body = stream::iter(vec![Ok(Bytes::from(vec![0u8; 200]))]);
        assert!(
            upload_stream(Arc::clone(&storage), "F", &pw, 100, 1024, &names, body).await.is_err()
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
        upload_stream(Arc::clone(&storage), "E", &pw, 0, 1024, &[], body).await.unwrap();
        let l = load_layout(storage.as_ref(), "E", &pw).await.unwrap();
        assert_eq!(l.total, 0);
        assert!(l.volumes.is_empty());
    }

}
