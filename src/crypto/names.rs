//! 名字加密 v5 —— 密钥入名（cryptree 信封）：加密名既藏明文名字，
//! 也藏该节点自己的秘密（文件 pw / 目录 FK）。
//!
//! 线格式：
//!
//! ```text
//! CJK-radix( [siv 4B] ‖ ChaCha20( [tagged-size varint][secret 16B][名字字节] ) )
//! ```
//!
//! - **加密密钥锚在父目录**：nameKey/macKey 由**父目录的 FK** 派生
//!   （根目录由数据源 FK_root）。持有目录 FK → list + 解全部条目名 →
//!   读出各文件 pw 与子目录 FK → 递归下钻。跨目录移动 = 换父钥重编码
//!   信封（一次 rename），secret 不变 → 内容零重加密。
//! - **CJK radix**：以 CJK 扩展 A + 统一表意区共 27584 个汉字作进制，
//!   每个存储字符承载约 14.75 bit；原始长度由 SIV 认证结果消歧。输出无
//!   固定特征 —— 首字符即 SIV 随机高位。
//! - **SIV 模式**：`siv = HMAC-SHA256(macKey, 明文负载)[..4]`，既是认证
//!   标签又是名字加密密钥的派生盐 —— 同父钥同明文同密文（确定性），
//!   不同明文 keystream 必不相同；解码后重算比对，解不开/密钥不符/
//!   篡改都失败 → 识别为外来文件。
//! - tagged-size 首字节携带目录/压缩两位及 size 的低 5 bit，后续按 7 bit
//!   续写（目录 size 恒 0）—— flags 不再单独占字节，一次 list 即见名字与大小。
//!
//! 固定开销 20 字节（siv 4 + secret 16）+ tagged-size ≈ 12 汉字 + 名字本体。
//! 「测试视频.mp4」约 25 字。存储名 ≤255 字节（85 汉字）→ 纯中文原名
//! 上限约 50 字（短文本压缩后）。

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{SECRET_LEN, name_cipher_key, name_mac_key, short_text};

const SIV_LEN: usize = 4;
const FLAG_DIR: u8 = 0b01;
const FLAG_COMPRESSED: u8 = 0b10;
/// 两段均为稳定的 BMP 汉字：UTF-8 固定 3B、Unicode 字符计数固定为 1，
/// 且不像兼容字符或 Hangul 那样存在常见的文件系统规范化分解。
const CJK_EXT_A_BASE: u32 = 0x3400;
const CJK_EXT_A_COUNT: u32 = 0x19c0; // U+3400..U+4DBF，共 6592
const CJK_UNIFIED_BASE: u32 = 0x4e00;
const CJK_UNIFIED_COUNT: u32 = 0x5200; // U+4E00..U+9FFF，共 20992
const CJK_RADIX: u32 = CJK_EXT_A_COUNT + CJK_UNIFIED_COUNT;
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

fn write_tagged_size(out: &mut Vec<u8>, mut size: u64, flags: u8) {
    debug_assert!(flags < 4);
    let mut first = (flags << 5) | (size as u8 & 0x1f);
    size >>= 5;
    if size != 0 {
        first |= 0x80;
    }
    out.push(first);
    while size != 0 {
        let mut byte = size as u8 & 0x7f;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

fn read_tagged_size(data: &[u8], pos: &mut usize) -> Option<(u64, u8)> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let flags = (first >> 5) & 0x03;
    let mut size = (first & 0x1f) as u128;
    let mut shift = 5u32;
    let mut more = first & 0x80 != 0;
    while more {
        let byte = *data.get(*pos)?;
        *pos += 1;
        let part = (byte & 0x7f) as u128;
        more = byte & 0x80 != 0;
        if !more && part == 0 {
            return None; // 拒绝非最短 varint
        }
        size |= part.checked_shl(shift)?;
        shift += 7;
        if shift > 75 {
            return None;
        }
    }
    Some((u64::try_from(size).ok()?, flags))
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

// ---------------- CJK 大进制编码 ----------------

fn cjk_char(digit: u32) -> Option<char> {
    let cp = if digit < CJK_EXT_A_COUNT {
        CJK_EXT_A_BASE + digit
    } else if digit < CJK_RADIX {
        CJK_UNIFIED_BASE + digit - CJK_EXT_A_COUNT
    } else {
        return None;
    };
    char::from_u32(cp)
}

fn cjk_digit(ch: char) -> Option<u32> {
    let cp = ch as u32;
    if (CJK_EXT_A_BASE..CJK_EXT_A_BASE + CJK_EXT_A_COUNT).contains(&cp) {
        Some(cp - CJK_EXT_A_BASE)
    } else if (CJK_UNIFIED_BASE..CJK_UNIFIED_BASE + CJK_UNIFIED_COUNT).contains(&cp) {
        Some(CJK_EXT_A_COUNT + cp - CJK_UNIFIED_BASE)
    } else {
        None
    }
}

fn cjk_encoded_chars(raw_len: usize) -> usize {
    if raw_len == 0 {
        return 0;
    }
    ((raw_len as f64 * 8.0) / (CJK_RADIX as f64).log2()).ceil() as usize
}

fn cjk_leading_mask(digits: &[u32]) -> u32 {
    digits.iter().fold(0u32, |acc, &digit| {
        ((acc as u64 * 257 + digit as u64) % CJK_RADIX as u64) as u32
    })
}

fn cjk_encode(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    // 小端大进制数组：逐个吸收 base-256 输入字节。
    let mut digits = vec![0u32];
    for &byte in raw {
        let mut carry = byte as u32;
        for digit in &mut digits {
            let value = *digit * 256 + carry;
            *digit = value % CJK_RADIX;
            carry = value / CJK_RADIX;
        }
        while carry > 0 {
            digits.push(carry % CJK_RADIX);
            carry /= CJK_RADIX;
        }
    }

    // 固定宽度保留开头的零字节；同一字符宽度可能对应两个原始长度，
    // 解码时枚举后由 SIV 认证选出唯一正确项。
    let width = cjk_encoded_chars(raw.len());
    debug_assert!(digits.len() <= width);
    let mut fixed = vec![0u32; width - digits.len()];
    fixed.extend(digits.iter().rev());
    // 固定宽度大进制的最高位取值范围较窄；用后续随机密文数字可逆地
    // 扰动首位，避免存储名第一个汉字集中在很小的字符区间。
    let mask = cjk_leading_mask(&fixed[1..]);
    fixed[0] = (fixed[0] + mask) % CJK_RADIX;

    let mut out = String::with_capacity(width * 3);
    for digit in fixed {
        out.push(cjk_char(digit).expect("进制数字必在 CJK 字母表内"));
    }
    out
}

fn cjk_decode_candidates(s: &str) -> Option<Vec<Vec<u8>>> {
    if s.is_empty() || s.len() > MAX_STORAGE_NAME {
        return None;
    }
    let mut digits: Vec<u32> = s.chars().map(cjk_digit).collect::<Option<_>>()?;
    let width = digits.len();
    let mask = cjk_leading_mask(&digits[1..]);
    digits[0] = (digits[0] + CJK_RADIX - mask) % CJK_RADIX;

    // 将大端 CJK 进制数还原为小端 base-256 数组。
    let mut bytes_le = vec![0u8];
    for digit in digits {
        let mut carry = digit;
        for byte in &mut bytes_le {
            let value = *byte as u32 * CJK_RADIX + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            bytes_le.push(carry as u8);
            carry >>= 8;
        }
    }
    while bytes_le.last() == Some(&0) {
        bytes_le.pop();
    }

    let max_raw_len = SIV_LEN + 1 + SECRET_LEN + 10 + MAX_PLAIN_NAME;
    let mut candidates = Vec::with_capacity(2);
    for byte_len in 1..=max_raw_len {
        if cjk_encoded_chars(byte_len) != width || bytes_le.len() > byte_len {
            continue;
        }
        let mut raw = vec![0u8; byte_len - bytes_le.len()];
        raw.extend(bytes_le.iter().rev());
        candidates.push(raw);
    }
    (!candidates.is_empty()).then_some(candidates)
}

/// 编码：明文名 + 大小 + 目录标记 + 节点秘密 → 密文存储名（一串随机汉字）。
/// `parent_key` 是父目录的 FK（根目录条目用数据源 FK_root）。超长返回 None。
pub fn encode_name(parent_key: &[u8], meta: &NameMeta) -> Option<String> {
    let mut flags = if meta.is_dir { FLAG_DIR } else { 0 };
    let size = if meta.is_dir { 0 } else { meta.size };
    let mut tagged_size = Vec::with_capacity(10);
    write_tagged_size(&mut tagged_size, size, flags);
    let fixed_len = SIV_LEN + SECRET_LEN + tagged_size.len();
    let plain_name = meta.name.as_bytes();
    let name_bytes = match short_text::compress(&meta.name).filter(|compressed| {
        cjk_encoded_chars(fixed_len + compressed.len())
            < cjk_encoded_chars(fixed_len + plain_name.len())
    }) {
        Some(compressed) => {
            flags |= FLAG_COMPRESSED;
            compressed
        }
        None => plain_name.to_vec(),
    };

    tagged_size.clear();
    write_tagged_size(&mut tagged_size, size, flags);
    let mut payload = Vec::with_capacity(tagged_size.len() + SECRET_LEN + name_bytes.len());
    payload.extend_from_slice(&tagged_size);
    payload.extend_from_slice(&meta.secret);
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
    cjk_decode_candidates(enc)?
        .into_iter()
        .find_map(|raw| decode_raw_name(parent_key, &raw))
}

fn decode_raw_name(parent_key: &[u8], raw: &[u8]) -> Option<NameMeta> {
    if raw.len() < SIV_LEN + 1 + SECRET_LEN + 1 {
        return None;
    }
    let (siv, ct) = raw.split_at(SIV_LEN);
    let mut payload = ct.to_vec();
    name_keystream_apply(parent_key, siv, &mut payload);
    if siv4(parent_key, &payload) != siv {
        return None;
    }

    let mut pos = 0;
    let (size, flags) = read_tagged_size(&payload, &mut pos)?;
    if flags & !(FLAG_DIR | FLAG_COMPRESSED) != 0 {
        return None; // 未知 flag（未来版本或随机碰撞）
    }
    if pos.checked_add(SECRET_LEN)? >= payload.len() {
        return None;
    }
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&payload[pos..pos + SECRET_LEN]);
    pos += SECRET_LEN;
    let name_bytes = &payload[pos..];
    let name = if flags & FLAG_COMPRESSED != 0 {
        short_text::decompress(name_bytes, MAX_PLAIN_NAME)?
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
    fn cjk_radix_roundtrip_lengths_and_leading_zeros() {
        for n in 1..=150usize {
            for raw in [
                (0..n).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>(),
                vec![0; n],
                vec![0xff; n],
            ] {
                let enc = cjk_encode(&raw);
                assert!(enc.chars().all(|c| cjk_digit(c).is_some()));
                assert_eq!(enc.chars().count(), cjk_encoded_chars(n));
                assert!(
                    cjk_decode_candidates(&enc).unwrap().iter().any(|v| v == &raw),
                    "len={n}"
                );
            }
        }
        assert!(cjk_decode_candidates("").is_none());
        assert!(cjk_decode_candidates("abc").is_none());
    }

    #[test]
    fn tagged_size_roundtrip_boundaries() {
        for size in [0, 1, 31, 32, 4_294_967_296, u64::MAX] {
            for flags in 0..4u8 {
                let mut encoded = Vec::new();
                write_tagged_size(&mut encoded, size, flags);
                let mut pos = 0;
                assert_eq!(read_tagged_size(&encoded, &mut pos), Some((size, flags)));
                assert_eq!(pos, encoded.len());
            }
        }
        let mut pos = 0;
        assert!(read_tagged_size(&[0x80, 0], &mut pos).is_none());
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
        assert!(a.chars().all(|c| cjk_digit(c).is_some()), "{a}");
        // CJK 大进制每个字符约承载 14.75 bit。
        assert!(a.chars().count() <= 26, "过长: {} 字 ({a})", a.chars().count());

        let firsts: std::collections::HashSet<char> = (0..40)
            .map(|i| encode_name(&fk, &meta(&format!("文件{i}.txt"), i, false)).unwrap()
                .chars().next().unwrap())
            .collect();
        assert!(firsts.len() > 30, "首字符应接近均匀分布: {firsts:?}");
    }

    #[test]
    fn compression_uses_final_storage_length() {
        let fk = gen_secret();
        let short = encode_name(&fk, &meta("电影", 0, true)).unwrap();
        // 文件名词典与更密的 CJK 进制共同缩短最终名称。
        assert!(short.chars().count() < 16);
        assert_eq!(decode_name(&fk, &short).unwrap().name, "电影");
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
            ("日本語のファイル名.mkv", 42),
            ("русский файл.txt", 42),
            ("🎬 movie night 🍿.mp4", 42),
            ("读书笔记 - Designing Data-Intensive Applications.md", 42),
            ("加密数据源管理服务的超长中文文件名压缩能力测试加密数据源管理服务", 42),
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
