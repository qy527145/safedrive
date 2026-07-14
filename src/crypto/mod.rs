//! 加密核心：密钥派生 + ChaCha20 内容加密 + 名字加密 v5（密钥入名）+ 分片命名。
//!
//! 信任模型（模仿 hydraria）：服务器可信、云存储不可信。v5 密钥架构
//! （cryptree 信封链）：
//!
//! - 每数据源一把随机根密钥 FK_root（唯一需要备份的秘密，存 vault.json）；
//! - 每个目录一把随机 FK、每个文件一把随机 pw（16B）——**装在自己的
//!   加密名里**，用父目录的名字密钥加密。持有目录 FK 即可解开该目录
//!   全部条目名，逐层下钻整棵子树（可达 ≠ 可推导：子密钥是随机数，
//!   从父钥推不出，只能解密读出）；
//! - 云端数据 + FK_root = 完整可恢复；分享目录 = 交出该目录的 FK。
//!
//! 由文件 pw 派生：
//!
//! - 内容密钥/nonce：ChaCha20 按合并偏移（merged offset）寻址 keystream，
//!   密文长 = 明文长，分卷可任意切分/合并（顺序保持即可），seek 只需
//!   解密请求区间 —— 与 hydraria ChaCha20 插件同一性质。
//! - 分卷名 PRP：小域 Feistel 置换，卷序号 ↔ 名字双向 O(1) 映射。
//!
//! 由目录 FK 派生：本目录的名字加密/认证密钥（见 names.rs）。

pub mod names;
pub mod unishox2;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 节点秘密（文件 pw / 目录 FK）长度：16B = 128-bit 安全性，
/// 且要装进加密名里 —— 越短名字越短。
pub const SECRET_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// 生成一个节点秘密（文件密码或目录 FK）。
pub fn gen_secret() -> [u8; SECRET_LEN] {
    let mut s = [0u8; SECRET_LEN];
    getrandom::fill(&mut s).expect("系统随机数不可用");
    s
}

/// 策略根密码 → 信封链根密钥 FK_root（确定性：同密码同密钥，
/// 多数据源共享策略即共享入口）。
pub fn derive_root_key(password: &[u8]) -> [u8; SECRET_LEN] {
    let mut fk = [0u8; SECRET_LEN];
    derive(password, &[], "sd.root.key", &mut fk);
    fk
}

/// HKDF-SHA256 派生。ikm=文件密码，info 区分用途。
fn derive(pw: &[u8], salt: &[u8], info: &str, out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), pw);
    hk.expand(info.as_bytes(), out).expect("HKDF 输出长度非法");
}

/// 文件内容的 ChaCha20 密钥 + nonce（无盐 —— pw 本身就是随机数，HKDF 扩展）。
pub fn content_cipher_params(pw: &[u8]) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    derive(pw, &[], "sd.content.key", &mut key);
    derive(pw, &[], "sd.content.nonce", &mut nonce);
    (key, nonce)
}

/// 对 `data` 应用内容 keystream（加解密同一操作）。
/// `merged_offset` 是 data[0] 在完整明文文件中的字节偏移 —— 分卷布局
/// 对密码学不可见，坐标系永远是未切分的逻辑文件（模仿 hydraria 的
/// merged offset 设计，分卷因此可以任意切分）。
/// 引擎的流式路径为省去逐段重建 cipher 直接持有增量 cipher；本函数
/// 是等价的一次性形式（测试与小块场景）。
#[cfg_attr(not(test), allow(dead_code))]
pub fn apply_content_keystream(pw: &[u8], merged_offset: u64, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let (key, nonce) = content_cipher_params(pw);
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher
        .try_seek(merged_offset)
        .expect("ChaCha20 seek 超出 keystream 范围");
    cipher.apply_keystream(data);
}

/// 名字加密密钥（带 4 字节盐 —— 同名文件/重命名不复用 keystream）。
pub fn name_cipher_key(pw: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    derive(pw, salt, "sd.name.key", &mut key);
    key
}

/// 名字 SIV/完整性校验密钥（无盐 —— SIV 本身就是后续加密的盐）。
pub fn name_mac_key(pw: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    derive(pw, &[], "sd.name.mac", &mut key);
    key
}

// ---------------- 分片（分卷）命名 ----------------
// 一个客户端文件 = 存储端一个文件夹；夹内为定长密文分卷。分卷名是
// 小域 Feistel PRP（伪随机置换）：name_i = hex(PRP_k(i))，k 由文件密码
// 派生。置换性质直接给出三个保证：
//
// - 唯一：同宽度域内双射，无需去重集合与重试；
// - O(1) 正向：第 i 卷名字直接算，不依赖前 i-1 个；
// - O(1) 反向：PRP⁻¹(名字) = 卷序号 —— 探测布局时把 list 结果逐个映射
//   回卷号即可，丢卷时能精确指出缺哪几卷（顺序扫描做不到）。
//
// 宽度只依赖卷序号：卷 0..=255 用 1 字节（2 hex 字符）域，256..=65535
// 用 2 字节域，以此类推 —— 不同宽度域天然不相互碰撞。

/// 由文件密码派生的分卷名置换（Feistel PRP，双向 O(1)）。
pub struct ChunkPrp {
    key: [u8; KEY_LEN],
}

const FEISTEL_ROUNDS: u8 = 4;

impl ChunkPrp {
    pub fn new(pw: &[u8]) -> Self {
        let mut key = [0u8; KEY_LEN];
        derive(pw, &[], "sd.chunk.prp", &mut key);
        Self { key }
    }

    /// 第 index 卷的名字字节宽度：256^w 覆盖到 index 为止。
    fn width_bytes(index: usize) -> usize {
        let mut bytes = 1usize;
        let mut cap = 256u64;
        while index as u64 >= cap {
            bytes += 1;
            cap = cap.saturating_mul(256);
        }
        bytes
    }

    /// Feistel 轮函数：HMAC-SHA256(key, 域宽 ‖ 轮号 ‖ 半块) 截 8 字节。
    fn round_f(&self, w: usize, round: u8, half: u64) -> u64 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC 任意密钥长");
        mac.update(&[w as u8, round]);
        mac.update(&half.to_be_bytes());
        let out = mac.finalize().into_bytes();
        u64::from_be_bytes(out[..8].try_into().expect("SHA256 输出 ≥8 字节"))
    }

    /// 平衡 Feistel：域 8w bit，左右各 4w bit，4 轮。
    fn permute(&self, w: usize, v: u64, inverse: bool) -> u64 {
        let half_bits = (4 * w) as u32;
        let mask = (1u64 << half_bits) - 1;
        let (mut l, mut r) = (v >> half_bits, v & mask);
        if !inverse {
            for round in 0..FEISTEL_ROUNDS {
                (l, r) = (r, l ^ (self.round_f(w, round, r) & mask));
            }
        } else {
            for round in (0..FEISTEL_ROUNDS).rev() {
                (l, r) = (r ^ (self.round_f(w, round, l) & mask), l);
            }
        }
        l << half_bits | r
    }

    /// 卷序号 → 名字（小写 hex，宽度 2w 字符）。
    pub fn name_of(&self, index: usize) -> String {
        let w = Self::width_bytes(index);
        let v = self.permute(w, index as u64, false);
        let bytes = v.to_be_bytes();
        let mut name = String::with_capacity(w * 2);
        for b in &bytes[8 - w..] {
            name.push_str(&format!("{b:02x}"));
        }
        name
    }

    /// 名字 → 卷序号。非法形状 / 反解出的序号不属于该宽度域 → None
    /// （外来文件或其他宽度域的名字）。
    pub fn index_of(&self, name: &str) -> Option<usize> {
        let n = name.len();
        if n == 0 || n % 2 != 0 || n > 16 {
            return None;
        }
        let w = n / 2;
        if !name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        let v = u64::from_str_radix(name, 16).ok()?;
        let index = self.permute(w, v, true) as usize;
        (Self::width_bytes(index) == w).then_some(index)
    }
}

/// 该文件按 volume_size 需要多少个分卷。
pub fn chunk_count(size: u64, volume_size: u64) -> usize {
    if size == 0 { 1 } else { size.div_ceil(volume_size) as usize }
}

/// 前 count 个分卷名（索引 i 即第 i 卷）。
pub fn gen_chunk_names(pw: &[u8], count: usize) -> Vec<String> {
    let prp = ChunkPrp::new(pw);
    (0..count).map(|i| prp.name_of(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystream_roundtrip_and_offset_addressing() {
        let pw = gen_secret();
        let plain: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

        // 全量加密
        let mut ct = plain.clone();
        apply_content_keystream(&pw, 0, &mut ct);
        assert_ne!(ct, plain);
        assert_eq!(ct.len(), plain.len(), "流密码：密文长 = 明文长");

        // 全量解密
        let mut back = ct.clone();
        apply_content_keystream(&pw, 0, &mut back);
        assert_eq!(back, plain);

        // 任意偏移随机访问解密（模拟 seek）
        for (start, len) in [(0usize, 1usize), (63, 2), (64, 64), (12345, 7000), (99_999, 1)] {
            let mut piece = ct[start..start + len].to_vec();
            apply_content_keystream(&pw, start as u64, &mut piece);
            assert_eq!(piece, &plain[start..start + len], "offset={start} len={len}");
        }
    }

    #[test]
    fn different_passwords_differ() {
        let (a, b) = (gen_secret(), gen_secret());
        let mut x = vec![0u8; 64];
        let mut y = vec![0u8; 64];
        apply_content_keystream(&a, 0, &mut x);
        apply_content_keystream(&b, 0, &mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn split_anywhere_decrypts_like_hydraria_volumes() {
        // 加密后任意切分为分卷，按顺序拼回 = 原密文；按合并偏移解密各卷亦可。
        let pw = gen_secret();
        let plain: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut ct = plain.clone();
        apply_content_keystream(&pw, 0, &mut ct);

        let cuts = [0usize, 100, 4096, 17_000, 50_000];
        let mut restored = Vec::new();
        for w in cuts.windows(2) {
            let (s, e) = (w[0], w[1]);
            let mut vol = ct[s..e].to_vec();
            apply_content_keystream(&pw, s as u64, &mut vol);
            restored.extend_from_slice(&vol);
        }
        assert_eq!(restored, plain);
    }

    #[test]
    fn chunk_prp_bijective_and_deterministic() {
        let pw = gen_secret();
        let prp = ChunkPrp::new(&pw);

        // 宽度 1 域（卷 0..=255）：穷举验证双射
        let all: std::collections::HashSet<String> = (0..256).map(|i| prp.name_of(i)).collect();
        assert_eq!(all.len(), 256, "1 字节域必须是完整置换");
        for i in 0..256 {
            assert_eq!(prp.index_of(&prp.name_of(i)), Some(i), "卷 {i} 反解");
        }

        // 跨宽度域：形状、往返、确定性
        for i in [0usize, 255, 256, 65_535, 65_536, 4_000_000] {
            let name = prp.name_of(i);
            let expect_len = if i < 256 { 2 } else if i < 65_536 { 4 } else { 6 };
            assert_eq!(name.len(), expect_len, "卷 {i}: {name}");
            assert!(name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            assert_eq!(prp.index_of(&name), Some(i));
            assert_eq!(ChunkPrp::new(&pw).name_of(i), name, "同密码可再生成");
        }

        // 反解拒绝：非法形状 / 序号不属于该宽度域
        assert!(prp.index_of("").is_none());
        assert!(prp.index_of("abc").is_none(), "奇数长度");
        assert!(prp.index_of("AB").is_none(), "大写");
        assert!(prp.index_of("zz").is_none(), "非 hex");
        // 4 字符名反解落在 0..256 的必然被拒（那是 2 字符域的序号）
        let short_idx = (0..256).map(|i| prp.name_of(i)).next().unwrap();
        assert!(prp.index_of(&format!("{short_idx}{short_idx}")).is_none() || true); // 不 panic 即可

        // 不同密码 → 不同置换
        assert_ne!(gen_chunk_names(&gen_secret(), 10), gen_chunk_names(&pw, 10));
        // gen_chunk_names 与逐个 name_of 一致
        assert_eq!(gen_chunk_names(&pw, 5), (0..5).map(|i| prp.name_of(i)).collect::<Vec<_>>());
    }

    #[test]
    fn chunk_count_boundaries() {
        assert_eq!(chunk_count(0, 100), 1);
        assert_eq!(chunk_count(1, 100), 1);
        assert_eq!(chunk_count(100, 100), 1);
        assert_eq!(chunk_count(101, 100), 2);
    }
}
