//! Compact, authenticated `sd://` share payloads.
//!
//! Wire format:
//! `base64url(AES-128-SIV(binary payload) || encrypted-pad:4 || version:4)`.
//! The clear version nibble is authenticated as AES-SIV associated data. The
//! binary payload starts with the 4-bit datasource type; all payload bits are
//! encrypted. The alignment nibble repeats ciphertext bits instead of exposing
//! a fixed marker. AES-SIV adds one 16-byte synthetic IV and needs no nonce.

use aes_siv::KeyInit;
use aes_siv::siv::Aes128Siv;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::bits::{BitReader, BitWriter, MAX_STRING_BYTES, validate_string};
use crate::disguise::Disguise;

pub(super) use super::bits::DecodeError;

const VERSION: u8 = 1;
const DISGUISE_BMP: u64 = 1;
const SOURCE_BAIDUPAN: u8 = 1;
const SOURCE_ALIYUNDRIVE: u8 = 2;
const SOURCE_QUARK: u8 = 3;
const MAX_ITEMS: usize = 100;
const PASSWORD_ALPHABET: &[u8; 31] = b"abcdefghjkmnpqrstuvwxyz23456789";

// Protocol key for v1. This is deliberately protocol-wide: it obscures the
// payload from generic clients, but is not an access-control secret because it
// necessarily ships in every compatible SafeDrive client.
const V1_KEY: [u8; 32] = [
    0x7d, 0x0e, 0xd7, 0x78, 0x71, 0x63, 0x35, 0x5d, 0x85, 0x6f, 0x87, 0xb9, 0x88, 0xf1, 0xb9, 0x0d,
    0x90, 0xba, 0x65, 0x46, 0xde, 0x3c, 0x43, 0xf0, 0x8b, 0x1b, 0x1e, 0x64, 0xa6, 0xc9, 0xa2, 0x72,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pack {
    pub source_type: String,
    pub share_id: String,
    pub password: String,
    /// 分享方的**内容**是否加密。受管但不加密 = 只伪装。
    pub encrypted: bool,
    /// 分享方存储侧的伪装形态。转存的是云端原样对象，两端伪装必须一致，
    /// 否则落地的分卷前面多/少一层头部，内容读不回来。
    pub disguise: Disguise,
    pub item_count: usize,
    /// 分享中走受管信封的根条目数量，其余是按字面存储名分享的外来条目。
    /// 0 = 纯外来分享，等于 `item_count` = 纯受管分享，之间 = 混合分享。
    pub managed_count: usize,
    /// Keys which decrypt the shared roots' storage names. Multiple selected
    /// roots from the same parent share one key.
    pub parent_keys: Vec<[u8; 16]>,
}

impl Pack {
    /// 是否带受管条目（等价于「带上了 `parent_keys`」）。转存后重编信封需要它。
    pub(super) fn managed(&self) -> bool {
        self.managed_count != 0
    }
}

/// 从云盘原生分享短链里取出要打包进 `sd://` 的分享 ID。
pub(super) fn share_id(ds_type: &str, url: &str) -> Option<String> {
    let id = match ds_type {
        // 百度短链固定是 `/s/1xxxx`，前导 1 是固定前缀，不进包。
        "baidupan" => {
            let url = reqwest::Url::parse(url).ok()?;
            url.path_segments()?
                .collect::<Vec<_>>()
                .windows(2)
                .find(|parts| parts[0] == "s")
                .map(|parts| parts[1].strip_prefix('1').unwrap_or(parts[1]).to_owned())?
        }
        "aliyundrive" => crate::adapters::aliyun_web::share_id_from_url(url)?,
        "quark" => crate::adapters::quark::share_id_from_url(url)?,
        _ => return None,
    };
    (!id.is_empty() && id.len() <= MAX_STRING_BYTES).then_some(id)
}

/// 分享 ID 还原成云盘原生短链（转存时交给适配器）。
pub(super) fn share_url(ds_type: &str, share_id: &str) -> Option<String> {
    match ds_type {
        "baidupan" => Some(format!("https://pan.baidu.com/s/1{share_id}")),
        "aliyundrive" => Some(crate::adapters::aliyun_web::share_url(share_id)),
        "quark" => Some(crate::adapters::quark::share_url(share_id)),
        _ => None,
    }
}

/// 识别一条云盘**原生**分享短链属于哪种数据源 —— 导入时据此自动兼容
/// `sd://` 之外的官网分享链接。认得出且确实是分享短链才返回类型。
pub(super) fn native_source(url: &str) -> Option<&'static str> {
    let host = reqwest::Url::parse(url.trim()).ok()?.host_str()?.to_owned();
    let ds_type = if host == "baidu.com" || host.ends_with(".baidu.com") {
        "baidupan"
    } else if host == "alipan.com"
        || host == "aliyundrive.com"
        || host.ends_with(".alipan.com")
        || host.ends_with(".aliyundrive.com")
    {
        "aliyundrive"
    } else if host == "quark.cn" || host.ends_with(".quark.cn") {
        "quark"
    } else {
        return None;
    };
    // 用各自的短链解析确认这确实是一条分享链接（而非首页/文件页等）。
    share_id(ds_type, url).map(|_| ds_type)
}

/// 取出原生分享短链里内嵌的提取码：百度 `?pwd=xxxx`、阿里 `?pwd=xxxx`、
/// 夸克 `?passcode=xxxx` 都用查询参数承载。没有则返回 None（由用户手填）。
pub(super) fn native_password(url: &str) -> Option<String> {
    reqwest::Url::parse(url.trim())
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == "pwd" || key == "passcode")
        .map(|(_, value)| value.into_owned())
        .filter(|pwd| !pwd.is_empty())
}

pub(super) fn encode(pack: &Pack) -> Result<String, &'static str> {
    let source = match pack.source_type.as_str() {
        "baidupan" => SOURCE_BAIDUPAN,
        "aliyundrive" => SOURCE_ALIYUNDRIVE,
        "quark" => SOURCE_QUARK,
        _ => return Err("unsupported datasource type"),
    };
    if pack.item_count == 0 || pack.item_count > MAX_ITEMS || pack.managed_count > pack.item_count {
        return Err("invalid item count");
    }
    if pack.managed() == pack.parent_keys.is_empty() || pack.parent_keys.len() > pack.managed_count
    {
        return Err("parent keys do not match managed entries");
    }
    if pack.encrypted && !pack.managed() {
        return Err("encrypted content requires managed envelopes");
    }
    validate_string(&pack.share_id)?;

    let mut bits = BitWriter::default();
    bits.write_bits(source as u64, 4);
    bits.write_bit(pack.encrypted);
    bits.write_bit(pack.disguise != Disguise::None);
    match pack.disguise {
        Disguise::None => {}
        Disguise::Bmp => bits.write_bits(DISGUISE_BMP, 4),
    }
    bits.write_string(&pack.share_id)?;
    write_password(&mut bits, &pack.password)?;
    bits.write_varint(pack.item_count as u64);
    bits.write_varint(pack.managed_count as u64);
    bits.write_varint(pack.parent_keys.len() as u64);
    for key in &pack.parent_keys {
        bits.write_bytes(key);
    }

    let plain = bits.finish();
    let mut cipher = Aes128Siv::new_from_slice(&V1_KEY).map_err(|_| "invalid protocol key")?;
    let version_bytes = [VERSION];
    let ciphertext = cipher
        .encrypt(
            [b"safedrive-share".as_slice(), version_bytes.as_slice()],
            &plain,
        )
        .map_err(|_| "share encryption failed")?;

    let mut wire = ciphertext;
    let encrypted_pad = wire.first().ok_or("empty ciphertext")? & 0xf0;
    wire.push(encrypted_pad | VERSION);
    Ok(format!("sd://{}", URL_SAFE_NO_PAD.encode(wire)))
}

pub(super) fn decode(link: &str) -> Result<Pack, DecodeError> {
    let encoded = link
        .trim()
        .strip_prefix("sd://")
        .ok_or(DecodeError::Invalid)?;
    let mut wire = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DecodeError::Invalid)?;
    let trailer = wire.pop().ok_or(DecodeError::Invalid)?;
    let version = trailer & 0x0f;
    let encrypted_pad = trailer & 0xf0;
    if wire.first().map(|byte| byte & 0xf0) != Some(encrypted_pad) {
        return Err(DecodeError::Invalid);
    }
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let mut cipher = Aes128Siv::new_from_slice(&V1_KEY).map_err(|_| DecodeError::Invalid)?;
    let version_bytes = [version];
    let plain = cipher
        .decrypt(
            [b"safedrive-share".as_slice(), version_bytes.as_slice()],
            &wire,
        )
        .map_err(|_| DecodeError::Invalid)?;
    decode_plain(&plain)
}

fn decode_plain(plain: &[u8]) -> Result<Pack, DecodeError> {
    let mut bits = BitReader::new(plain);
    let source_type = match bits.read_bits(4)? as u8 {
        SOURCE_BAIDUPAN => "baidupan".to_owned(),
        SOURCE_ALIYUNDRIVE => "aliyundrive".to_owned(),
        SOURCE_QUARK => "quark".to_owned(),
        _ => return Err(DecodeError::Invalid),
    };
    let encrypted = bits.read_bit()?;
    let mut disguise = Disguise::None;
    if bits.read_bit()? {
        disguise = match bits.read_bits(4)? {
            DISGUISE_BMP => Disguise::Bmp,
            _ => return Err(DecodeError::Invalid),
        };
    }
    let share_id = bits.read_string()?;
    if share_id.is_empty() {
        return Err(DecodeError::Invalid);
    }
    let password = read_password(&mut bits)?;
    let item_count = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    if item_count == 0 || item_count > MAX_ITEMS {
        return Err(DecodeError::Invalid);
    }
    let managed_count = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    // 加密内容必然走受管信封，否则接收方拿不到任何可解密的东西。
    if managed_count > item_count || (encrypted && managed_count == 0) {
        return Err(DecodeError::Invalid);
    }
    let key_count = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    if key_count > managed_count || (managed_count != 0) != (key_count != 0) {
        return Err(DecodeError::Invalid);
    }
    let mut parent_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let mut key = [0u8; 16];
        bits.read_bytes(&mut key)?;
        if parent_keys.contains(&key) {
            return Err(DecodeError::Invalid);
        }
        parent_keys.push(key);
    }
    bits.finish()?;
    Ok(Pack {
        source_type,
        share_id,
        password,
        encrypted,
        disguise,
        item_count,
        managed_count,
        parent_keys,
    })
}

fn write_password(bits: &mut BitWriter, password: &str) -> Result<(), &'static str> {
    let bytes = password.as_bytes();
    if bytes.len() != 4 {
        return Err("share password must contain four characters");
    }
    for byte in bytes {
        let index = PASSWORD_ALPHABET
            .iter()
            .position(|candidate| candidate == byte)
            .ok_or("share password contains an unsupported character")?;
        bits.write_bits(index as u64, 5);
    }
    Ok(())
}

fn read_password(bits: &mut BitReader<'_>) -> Result<String, DecodeError> {
    let mut password = String::with_capacity(4);
    for _ in 0..4 {
        let index = bits.read_bits(5)? as usize;
        let byte = *PASSWORD_ALPHABET.get(index).ok_or(DecodeError::Invalid)?;
        password.push(byte as char);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(encrypted: bool) -> Pack {
        Pack {
            source_type: "baidupan".into(),
            share_id: "qym_MmGtZhFrTpKqf_H0oQ".into(),
            password: "a2k9".into(),
            encrypted,
            disguise: Disguise::None,
            item_count: 8,
            managed_count: if encrypted { 8 } else { 0 },
            parent_keys: encrypted.then_some([0x5a; 16]).into_iter().collect(),
        }
    }

    /// 伪装形态、「受管但不加密」、混合分享的受管条目数都原样往返。
    #[test]
    fn managed_shape_survives_the_roundtrip() {
        // 加密 + 伪装
        let mut both = sample(true);
        both.disguise = Disguise::Bmp;
        assert_eq!(decode(&encode(&both).unwrap()), Ok(both));

        // 只伪装不加密：受管（带目录密钥）但内容是明文
        let mut disguise_only = sample(true);
        disguise_only.encrypted = false;
        disguise_only.disguise = Disguise::Bmp;
        assert_eq!(
            decode(&encode(&disguise_only).unwrap()),
            Ok(disguise_only.clone())
        );
        assert!(disguise_only.managed());

        // 混合分享：8 项里 3 项受管、5 项外来
        let mut mixed = sample(true);
        mixed.managed_count = 3;
        let decoded = decode(&encode(&mixed).unwrap()).unwrap();
        assert_eq!(decoded, mixed);
        assert_eq!((decoded.item_count, decoded.managed_count), (8, 3));
        assert!(decoded.managed());

        // 纯外来分享没有受管条目，也不带目录密钥
        let foreign = sample(false);
        assert_eq!(foreign.managed_count, 0);
        assert!(!foreign.managed());
        assert_eq!(decode(&encode(&foreign).unwrap()), Ok(foreign));

        // 加密必然受管：不带目录密钥的「加密」包非法
        let mut bogus = sample(false);
        bogus.encrypted = true;
        assert!(encode(&bogus).is_err());

        // 受管条目数不能超过总条目数
        let mut too_many = sample(true);
        too_many.managed_count = 9;
        assert!(encode(&too_many).is_err());

        // 目录密钥数不能超过受管条目数
        let mut extra_keys = sample(true);
        extra_keys.managed_count = 1;
        extra_keys.parent_keys = vec![[0x5a; 16], [0x5b; 16]];
        assert!(encode(&extra_keys).is_err());
    }

    #[test]
    fn encrypted_and_plain_roundtrip() {
        for pack in [sample(true), sample(false)] {
            let link = encode(&pack).unwrap();
            assert_eq!(decode(&link), Ok(pack));
        }
    }

    /// 每种云盘的分享 ID 都能在「短链 → 包 → 短链」之间无损往返。
    #[test]
    fn share_ids_survive_the_link_roundtrip() {
        for (ds_type, url, id) in [
            (
                "baidupan",
                "https://pan.baidu.com/s/1qym_MmGtZhFrTpKqf",
                "qym_MmGtZhFrTpKqf",
            ),
            (
                "aliyundrive",
                "https://www.alipan.com/s/3XCkDNb1Cfa",
                "3XCkDNb1Cfa",
            ),
            (
                "quark",
                "https://pan.quark.cn/s/3a5f8b2c1d0e",
                "3a5f8b2c1d0e",
            ),
        ] {
            assert_eq!(share_id(ds_type, url).as_deref(), Some(id), "{ds_type}");
            let rebuilt = share_url(ds_type, id).expect("支持的类型都能还原短链");
            assert_eq!(
                share_id(ds_type, &rebuilt).as_deref(),
                Some(id),
                "{ds_type}"
            );

            let mut pack = sample(true);
            pack.source_type = ds_type.into();
            pack.share_id = id.into();
            let decoded = decode(&encode(&pack).unwrap()).unwrap();
            assert_eq!(decoded, pack);
        }
        // 不支持原生分享的类型不该被塞进链接
        assert!(share_id("localfs", "https://x/s/1abc").is_none());
        assert!(share_url("localfs", "abc").is_none());
        let mut unsupported = sample(true);
        unsupported.source_type = "localfs".into();
        assert!(encode(&unsupported).is_err());
    }

    /// 原生分享短链能按域名自动识别数据源类型；非分享链接、陌生域名判 None。
    #[test]
    fn detects_native_source_from_url() {
        assert_eq!(
            native_source("https://pan.baidu.com/s/1qym_MmGtZhFrTpKqf"),
            Some("baidupan")
        );
        assert_eq!(
            native_source("https://www.alipan.com/s/3XCkDNb1Cfa"),
            Some("aliyundrive")
        );
        assert_eq!(
            native_source(" https://www.aliyundrive.com/s/3XCkDNb1Cfa?x=1 "),
            Some("aliyundrive")
        );
        assert_eq!(
            native_source("https://pan.quark.cn/s/3a5f8b2c1d0e"),
            Some("quark")
        );
        // 阿里云盘快传短链 `/t/{id}` 不在支持范围内
        assert!(native_source("https://www.alipan.com/t/aB12cd34").is_none());
        // 同域名但不是分享短链
        assert!(native_source("https://pan.baidu.com/disk/home").is_none());
        assert!(native_source("https://www.alipan.com/").is_none());
        // 陌生域名 / 非 URL
        assert!(native_source("https://example.com/s/1abc").is_none());
        assert!(native_source("sd://abcdef").is_none());
        // 域名后缀伪装不能蒙混（evil-baidu.com 不属于 baidu.com）
        assert!(native_source("https://evil-baidu.com/s/1abc").is_none());
    }

    /// 链接内嵌的 `?pwd=` 提取码能被取出；没有或为空则判 None。
    #[test]
    fn extracts_embedded_pwd_from_native_link() {
        assert_eq!(
            native_password("https://pan.baidu.com/s/17SPua3oIUyK_HYzxYbfN-Q?pwd=pnqv").as_deref(),
            Some("pnqv")
        );
        assert_eq!(
            native_password("https://www.alipan.com/s/3XCkDNb1Cfa?pwd=ab12").as_deref(),
            Some("ab12")
        );
        assert_eq!(
            native_password("https://pan.quark.cn/s/3a5f8b2c1d0e?passcode=cd34").as_deref(),
            Some("cd34")
        );
        assert!(native_password("https://pan.baidu.com/s/17SPua3oIUyK_HYzxYbfN-Q").is_none());
        assert!(native_password("https://pan.baidu.com/s/1abc?pwd=").is_none());
    }

    #[test]
    fn payload_has_no_obvious_plaintext_and_is_compact() {
        let pack = sample(true);
        let link = encode(&pack).unwrap();
        assert!(!link.contains(&pack.share_id));
        assert!(!link.contains(&pack.password));
        assert!(link.len() < 100, "unexpectedly long link: {link}");
    }

    #[test]
    fn items_from_one_parent_do_not_grow_the_link() {
        let mut one = sample(true);
        one.item_count = 1;
        one.managed_count = 1;
        let mut hundred = one.clone();
        hundred.item_count = 100;
        hundred.managed_count = 100;
        assert_eq!(encode(&one).unwrap().len(), encode(&hundred).unwrap().len());
    }

    #[test]
    fn tampering_is_rejected() {
        let link = encode(&sample(true)).unwrap();
        let mut wire = URL_SAFE_NO_PAD
            .decode(link.strip_prefix("sd://").unwrap())
            .unwrap();
        wire[8] ^= 0x40;
        let changed = format!("sd://{}", URL_SAFE_NO_PAD.encode(wire));
        assert_eq!(decode(&changed), Err(DecodeError::Invalid));
    }

    #[test]
    fn version_is_a_four_bit_trailer() {
        let link = encode(&sample(true)).unwrap();
        let mut wire = URL_SAFE_NO_PAD
            .decode(link.strip_prefix("sd://").unwrap())
            .unwrap();
        let encrypted_pad = *wire.last().unwrap() & 0xf0;
        assert_eq!(wire.last().unwrap() & 0x0f, VERSION);
        *wire.last_mut().unwrap() = encrypted_pad | 7;
        let changed = format!("sd://{}", URL_SAFE_NO_PAD.encode(wire));
        assert_eq!(decode(&changed), Err(DecodeError::UnsupportedVersion(7)));
    }

    #[test]
    fn uses_standard_unpadded_url_safe_base64() {
        assert_eq!(URL_SAFE_NO_PAD.encode([0xfb]), "-w");
        assert_eq!(URL_SAFE_NO_PAD.encode([0xff]), "_w");
        assert_eq!(URL_SAFE_NO_PAD.decode("-w"), Ok(vec![0xfb]));
        assert_eq!(URL_SAFE_NO_PAD.decode("_w"), Ok(vec![0xff]));
    }
}
