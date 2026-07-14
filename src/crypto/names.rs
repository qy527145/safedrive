//! 名字加密 v5 —— 密钥入名（cryptree 信封）：加密名既藏明文名字，
//! 也藏该节点自己的秘密（文件 pw / 目录 FK）。
//!
//! 线格式：
//!
//! ```text
//! cjk14( [siv 4B] ‖ ChaCha20( [flags 1B][secret 16B][varint size][名字字节] ) )
//! ```
//!
//! - **加密密钥锚在父目录**：nameKey/macKey 由**父目录的 FK** 派生
//!   （根目录由数据源 FK_root）。持有目录 FK → list + 解全部条目名 →
//!   读出各文件 pw 与子目录 FK → 递归下钻。跨目录移动 = 换父钥重编码
//!   信封（一次 rename），secret 不变 → 内容零重加密。
//! - **cjk14**：14-bit → CJK 统一表意区编码（0x4E00 起 16384 字符，
//!   7 字节 ↔ 4 汉字；尾部余数用 0x8E01..0x8E06 单字标记）。输出无
//!   固定特征 —— 首字符即 SIV 随机高位。
//! - **SIV 模式**：`siv = HMAC-SHA256(macKey, 明文负载)[..4]`，既是认证
//!   标签又是名字加密密钥的派生盐 —— 同父钥同明文同密文（确定性），
//!   不同明文 keystream 必不相同；解码后重算比对，解不开/密钥不符/
//!   篡改都失败 → 识别为外来文件。
//! - flags：bit0=目录，bit1=名字经 unishox2 压缩（压不小则存原文）；
//!   `size` LEB128 varint（目录恒 0）—— 一次 list 即见名字与大小。
//!
//! 固定开销 21 字节（siv 4 + flags 1 + secret 16）≈ 12 汉字 + 名字本体。
//! 「测试视频.mp4」约 25 字。存储名 ≤255 字节（85 汉字）→ 纯中文原名
//! 上限约 50 字（unishox2 压缩后）。

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{SECRET_LEN, name_cipher_key, name_mac_key, unishox2};

const SIV_LEN: usize = 4;
const FLAG_DIR: u8 = 0b01;
const FLAG_COMPRESSED: u8 = 0b10;
/// cjk14 数据字符区：CJK 统一表意文字 0x4E00..0x8DFF（16384 = 2^14 个）。
const CJK_BASE: u32 = 0x4E00;
const CJK_SIZE: u32 = 1 << 14;
/// 余数标记字符区：0x8E01..=0x8E06（仍是普通汉字，标记尾组字节数）。
const MARK_BASE: u32 = 0x8E00;
/// 常见文件系统的单文件名字节上限。
pub const MAX_STORAGE_NAME: usize = 255;
/// 明文名字节上限（解压缓冲上界，防异常输入撑爆）。
const MAX_PLAIN_NAME: usize = 1024;

/// 解码出的名字元数据（含节点自己的秘密：文件 pw / 目录 FK）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameMeta {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// 该节点的秘密：文件为内容密码，目录为其 FK（解开子条目名的钥匙）。
    pub secret: [u8; SECRET_LEN],
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        if shift >= 64 {
            return None;
        }
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
}

/// 名字加密 keystream：密钥由 siv 作盐派生，nonce 恒 0 ——
/// 不同明文 siv 必不同 → keystream 天然不重复。
fn name_keystream_apply(pw: &[u8], siv: &[u8], data: &mut [u8]) {
    let key = name_cipher_key(pw, siv);
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(data);
}

/// SIV = HMAC-SHA256(mac_key, 明文负载)[..4]。flags 在负载内，一并覆盖。
fn siv4(pw: &[u8], plain_payload: &[u8]) -> [u8; SIV_LEN] {
    let key = name_mac_key(pw);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC 任意密钥长");
    mac.update(plain_payload);
    let out = mac.finalize().into_bytes();
    let mut short = [0u8; SIV_LEN];
    short.copy_from_slice(&out[..SIV_LEN]);
    short
}

// ---------------- cjk14 编码 ----------------
// 7 字节（56 bit）↔ 4 个 14-bit 值 ↔ 4 个汉字；尾部不足 7 字节的 r 字节
// 编码为 ceil(8r/14) 个字符，再追加一个标记字符（MARK_BASE + r）。
// 每个汉字 UTF-8 占 3 字节：信息密度按字符算 14 bit/字，接近原始中文名。

fn cjk_encode(raw: &[u8]) -> String {
    fn ch(v: u32) -> char {
        char::from_u32(CJK_BASE + v).expect("14bit 值必在 CJK 区内")
    }
    let mut out = String::with_capacity(raw.len() / 7 * 12 + 16);
    let mut groups = raw.chunks_exact(7);
    for g in groups.by_ref() {
        let mut acc = 0u64;
        for &b in g {
            acc = acc << 8 | b as u64;
        }
        for shift in [42u32, 28, 14, 0] {
            out.push(ch(((acc >> shift) & 0x3FFF) as u32));
        }
    }
    let rem = groups.remainder();
    let r = rem.len();
    if r > 0 {
        let c = (r * 8).div_ceil(14);
        let mut acc = 0u64;
        for &b in rem {
            acc = acc << 8 | b as u64;
        }
        acc <<= (c * 14 - r * 8) as u32; // 低位补零
        for i in (0..c).rev() {
            out.push(ch(((acc >> (i as u32 * 14)) & 0x3FFF) as u32));
        }
        out.push(char::from_u32(MARK_BASE + r as u32).expect("标记字符必在 CJK 区内"));
    }
    out
}

fn cjk_decode(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<u32> = s.chars().map(|c| c as u32).collect();
    if chars.is_empty() {
        return None;
    }
    let (data, r) = match *chars.last().unwrap() {
        m if (MARK_BASE + 1..=MARK_BASE + 6).contains(&m) => {
            (&chars[..chars.len() - 1], (m - MARK_BASE) as usize)
        }
        _ => (&chars[..], 0),
    };
    let mut vals = Vec::with_capacity(data.len());
    for &c in data {
        if !(CJK_BASE..CJK_BASE + CJK_SIZE).contains(&c) {
            return None;
        }
        vals.push((c - CJK_BASE) as u64);
    }
    let tail = if r == 0 { 0 } else { (r * 8).div_ceil(14) };
    if vals.len() < tail || (vals.len() - tail) % 4 != 0 {
        return None;
    }
    let full = (vals.len() - tail) / 4;
    let mut out = Vec::with_capacity(full * 7 + r);
    for g in vals[..full * 4].chunks_exact(4) {
        let mut acc = 0u64;
        for &v in g {
            acc = acc << 14 | v;
        }
        for shift in [48u32, 40, 32, 24, 16, 8, 0] {
            out.push((acc >> shift) as u8);
        }
    }
    if r > 0 {
        let mut acc = 0u64;
        for &v in &vals[full * 4..] {
            acc = acc << 14 | v;
        }
        let pad = (tail * 14 - r * 8) as u32;
        if acc & ((1u64 << pad) - 1) != 0 {
            return None; // 填充位必须为零（规范编码唯一）
        }
        acc >>= pad;
        for i in (0..r).rev() {
            out.push((acc >> (i as u32 * 8)) as u8);
        }
    }
    Some(out)
}

/// 编码：明文名 + 大小 + 目录标记 + 节点秘密 → 密文存储名（一串随机汉字）。
/// `parent_key` 是父目录的 FK（根目录条目用数据源 FK_root）。超长返回 None。
pub fn encode_name(parent_key: &[u8], meta: &NameMeta) -> Option<String> {
    let mut flags = if meta.is_dir { FLAG_DIR } else { 0 };
    let name_bytes = match unishox2::compress(&meta.name) {
        Some(c) => {
            flags |= FLAG_COMPRESSED;
            c
        }
        None => meta.name.as_bytes().to_vec(),
    };

    let mut payload = Vec::with_capacity(1 + SECRET_LEN + 10 + name_bytes.len());
    payload.push(flags);
    payload.extend_from_slice(&meta.secret);
    write_varint(&mut payload, if meta.is_dir { 0 } else { meta.size });
    payload.extend_from_slice(&name_bytes);

    let siv = siv4(parent_key, &payload);
    name_keystream_apply(parent_key, &siv, &mut payload);

    let mut raw = Vec::with_capacity(SIV_LEN + payload.len());
    raw.extend_from_slice(&siv);
    raw.extend_from_slice(&payload);

    let encoded = cjk_encode(&raw);
    (encoded.len() <= MAX_STORAGE_NAME).then_some(encoded)
}

/// 解码：密文存储名 → 明文元数据（含节点秘密）。
/// 格式不符 / SIV 校验失败 → None（外来文件）。
pub fn decode_name(parent_key: &[u8], enc: &str) -> Option<NameMeta> {
    let raw = cjk_decode(enc)?;
    if raw.len() < SIV_LEN + 1 + SECRET_LEN + 1 {
        return None;
    }
    let (siv, ct) = raw.split_at(SIV_LEN);
    let mut payload = ct.to_vec();
    name_keystream_apply(parent_key, siv, &mut payload);
    if siv4(parent_key, &payload) != siv {
        return None;
    }

    let flags = payload[0];
    if flags & !(FLAG_DIR | FLAG_COMPRESSED) != 0 {
        return None; // 未知 flag（未来版本或随机碰撞）
    }
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&payload[1..1 + SECRET_LEN]);
    let mut pos = 1 + SECRET_LEN;
    let size = read_varint(&payload, &mut pos)?;
    let name_bytes = &payload[pos..];
    let name = if flags & FLAG_COMPRESSED != 0 {
        unishox2::decompress(name_bytes, MAX_PLAIN_NAME)?
    } else {
        String::from_utf8(name_bytes.to_vec()).ok()?
    };
    if name.is_empty() || name.len() > MAX_PLAIN_NAME || name.contains('/') || name == "." || name == ".." {
        return None;
    }
    let is_dir = flags & FLAG_DIR != 0;
    Some(NameMeta { name, size: if is_dir { 0 } else { size }, is_dir, secret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::gen_secret;

    fn meta(name: &str, size: u64, is_dir: bool) -> NameMeta {
        NameMeta { name: name.into(), size, is_dir, secret: gen_secret() }
    }

    #[test]
    fn cjk14_roundtrip_all_remainders() {
        // 覆盖所有尾组长度 1..=6（实际 raw 恒 ≥ SIV+18 字节，空输入无需支持）
        for n in 1..=40usize {
            let raw: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let enc = cjk_encode(&raw);
            assert!(enc.chars().all(|c| {
                let v = c as u32;
                (CJK_BASE..CJK_BASE + CJK_SIZE).contains(&v)
                    || (MARK_BASE + 1..=MARK_BASE + 6).contains(&v)
            }));
            assert_eq!(cjk_decode(&enc).as_deref(), Some(&raw[..]), "len={n}");
        }
        assert!(cjk_decode("").is_none());
        assert!(cjk_decode("abc").is_none());
    }

    #[test]
    fn roundtrip_file_and_dir_with_secret() {
        let fk = gen_secret();
        for m in [
            meta("测试视频 [2026].mkv", 4_294_967_296, false),
            meta("电影", 0, true),
            meta("a", 0, false),
            meta("空格 与.多.点.txt", 1, false),
            meta("🎬 movie night 🍿.mp4", 42, false),
        ] {
            let enc = encode_name(&fk, &m).unwrap();
            assert!(!enc.contains('/'));
            let dec = decode_name(&fk, &enc).unwrap();
            assert_eq!(dec, m, "secret 必须原样带回");
        }
    }

    #[test]
    fn envelope_chain_walk() {
        // 模拟信封链：FK_root → 解出目录 FK → 解出文件 pw
        let fk_root = gen_secret();
        let dir = meta("电影", 0, true);
        let dir_nc = encode_name(&fk_root, &dir).unwrap();
        let file = meta("a.mp4", 700_000, false);
        let file_nc = encode_name(&dir.secret, &file).unwrap();

        // 持有 fk_root 的接收方：
        let d = decode_name(&fk_root, &dir_nc).unwrap();
        assert!(d.is_dir);
        let f = decode_name(&d.secret, &file_nc).unwrap();
        assert_eq!(f.secret, file.secret, "文件 pw 从信封链读出");
        // 父钥解不开孙辈（密钥锚定父目录）
        assert!(decode_name(&fk_root, &file_nc).is_none());
        // 单文件泄露不上溯：file.secret 解不开兄弟目录名
        assert!(decode_name(&file.secret, &dir_nc).is_none());
    }

    #[test]
    fn move_reencode_keeps_secret() {
        // 跨目录移动 = 换父钥重编码，secret 不变（内容零重加密的根基）
        let (fk_a, fk_b) = (gen_secret(), gen_secret());
        let m = meta("报告.pdf", 1024, false);
        let nc_a = encode_name(&fk_a, &m).unwrap();
        let got = decode_name(&fk_a, &nc_a).unwrap();
        let nc_b = encode_name(&fk_b, &got).unwrap();
        assert_ne!(nc_a, nc_b, "不同父钥必然不同名");
        assert_eq!(decode_name(&fk_b, &nc_b).unwrap().secret, m.secret);
        assert!(decode_name(&fk_a, &nc_b).is_none(), "旧父钥失效");
    }

    #[test]
    fn encoding_is_cjk_deterministic_and_featureless() {
        let fk = gen_secret();
        let m = meta("测试视频.mp4", 716_800, false);
        let a = encode_name(&fk, &m).unwrap();
        let b = encode_name(&fk, &m).unwrap();
        assert_eq!(a, b, "SIV 模式：同父钥同明文同密文");
        assert!(a.chars().all(|c| ('\u{4E00}'..='\u{8E06}').contains(&c)), "{a}");
        // 21B 开销 + varint 3B + unishox ~15B ≈ 39B → ⌈39*8/14⌉+1 ≈ 24 字
        assert!(a.chars().count() <= 26, "过长: {} 字 ({a})", a.chars().count());

        let firsts: std::collections::HashSet<char> = (0..40)
            .map(|i| encode_name(&fk, &meta(&format!("文件{i}.txt"), i, false)).unwrap()
                .chars().next().unwrap())
            .collect();
        assert!(firsts.len() > 30, "首字符应接近均匀分布: {firsts:?}");
    }

    #[test]
    fn wrong_key_or_tamper_rejected() {
        let fk = gen_secret();
        let enc = encode_name(&fk, &meta("秘密.txt", 5, false)).unwrap();
        assert!(decode_name(&gen_secret(), &enc).is_none(), "错误密钥");

        let chars: Vec<char> = enc.chars().collect();
        for i in 0..chars.len() {
            let mut broken = chars.clone();
            broken[i] = char::from_u32(broken[i] as u32 ^ 1).unwrap();
            let tampered: String = broken.iter().collect();
            assert_ne!(
                decode_name(&fk, &tampered).map(|m| m.name),
                Some("秘密.txt".to_string()),
                "篡改字符 {i} 未被检测"
            );
        }
        assert!(decode_name(&fk, "random-junk").is_none());
        assert!(decode_name(&fk, "汉字太短").is_none());
    }

    #[test]
    fn long_cjk_names_fit_with_compression() {
        let fk = gen_secret();
        let name: String = "加密数据源管理服务的超长中文文件名压缩能力测试"
            .chars().cycle().take(50).collect();
        let m = NameMeta { name: name.clone(), size: 4 * 1024 * 1024 * 1024, is_dir: false, secret: gen_secret() };
        let enc = encode_name(&fk, &m).unwrap();
        assert!(enc.len() <= MAX_STORAGE_NAME, "{}", enc.len());
        assert_eq!(decode_name(&fk, &enc).unwrap().name, name);

        let huge: String = (0..2000u32)
            .map(|i| char::from_u32(0x4E00 + (i % 20000)).unwrap())
            .collect();
        assert!(encode_name(&fk, &NameMeta { name: huge, size: 0, is_dir: false, secret: gen_secret() }).is_none());
    }
}

#[cfg(test)]
mod length_report {
    use super::*;
    use crate::crypto::gen_secret;

    /// 非断言测试：打印典型名字的编码长度（cargo test -- --nocapture length_report）。
    #[test]
    fn print_typical_lengths() {
        let fk = gen_secret();
        for (name, size) in [
            ("测试视频.mp4", 716_800u64),
            ("我的家庭相册2026年春节.zip", 3_221_225_472),
            ("Annual Report FY2026 Final v3.pdf", 1_048_576),
            ("IMG_20260713_182233.jpg", 4_194_304),
            ("电影", 0),
        ] {
            let m = NameMeta { name: name.into(), size, is_dir: size == 0, secret: gen_secret() };
            let enc = encode_name(&fk, &m).unwrap();
            println!(
                "{:>2} chars ({:>3}B)  {name} ({} chars)",
                enc.chars().count(), enc.len(), name.chars().count(),
            );
        }
    }
}
