//! Compact, authenticated `sdds://` datasource-config share payloads.
//!
//! Wire format (protocol v1):
//! `base64url(AES-128-SIV(binary payload) || encrypted-pad:4 || version:4)`,
//! mirroring the `sd://` file-share envelope in [`super::share_codec`]. The
//! payload carries everything needed to recreate a datasource: connection
//! config, root password, volume and cache settings. Credentials dominate the
//! length, so strings whose bytes all fit the 64-symbol base64url alphabet
//! (BDUSS, generated passwords, tokens) are packed at 6 bits per character.
//!
//! The link is a bearer secret: anyone holding it gets the credentials and the
//! root password. The protocol key only keeps generic clients from reading it.

use aes_siv::KeyInit;
use aes_siv::siv::Aes128Siv;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::bits::{BitReader, BitWriter, DecodeError, MAX_STRING_BYTES, validate_string};

pub(super) const SCHEME: &str = "sdds://";

const VERSION: u8 = 1;
const SOURCE_LOCALFS: u8 = 1;
const SOURCE_WEBDAV: u8 = 2;
const SOURCE_BAIDUPAN: u8 = 3;
const COMPACT_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DEFAULT_VOLUME_NAME_FORMAT: &str = "{s}_{i}.bin";

// Protocol key for v1, deliberately protocol-wide: it obscures the payload
// from generic clients, but ships in every compatible SafeDrive client and so
// is not an access-control secret.
const V1_KEY: [u8; 32] = [
    0xc1, 0x4a, 0x92, 0x6b, 0x3f, 0x08, 0xd5, 0x17, 0xae, 0x74, 0x2c, 0x60, 0x9b, 0xe3, 0x51, 0x88,
    0x36, 0xdf, 0x0a, 0x7e, 0x45, 0xb2, 0x19, 0xcd, 0x63, 0x8f, 0xf4, 0x21, 0x5a, 0x97, 0xd0, 0x0b,
];

/// A datasource's shareable configuration. Baidu OAuth tokens are left out:
/// they are short-lived and the importing side re-derives them from BDUSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DsPack {
    pub ds_type: String,
    pub name: String,
    pub config: Value,
    pub encryption_enabled: bool,
    pub password: String,
    pub volume_enabled: bool,
    pub volume_size: u64,
    pub volume_strategy: String,
    pub volume_name_format: String,
    pub cache_enabled: bool,
}

pub(super) fn encode(pack: &DsPack) -> Result<String, &'static str> {
    let source = match pack.ds_type.as_str() {
        "localfs" => SOURCE_LOCALFS,
        "webdav" => SOURCE_WEBDAV,
        "baidupan" => SOURCE_BAIDUPAN,
        _ => return Err("unsupported datasource type"),
    };
    if pack.name.trim().is_empty() {
        return Err("datasource name must not be empty");
    }

    let mut bits = BitWriter::default();
    bits.write_bits(source as u64, 4);
    bits.write_bit(pack.encryption_enabled);
    bits.write_bit(pack.volume_enabled);
    bits.write_bit(pack.cache_enabled);
    write_compact(&mut bits, &pack.name)?;
    if pack.encryption_enabled {
        write_compact(&mut bits, &pack.password)?;
    }
    if pack.volume_enabled {
        write_size(&mut bits, pack.volume_size);
        bits.write_bit(match pack.volume_strategy.as_str() {
            "random" => false,
            "fixed" => true,
            _ => return Err("unsupported volume strategy"),
        });
        if !pack.encryption_enabled {
            // Encrypted datasources derive volume names from the file key, so
            // the template is meaningless there and stays out of the link.
            write_optional(
                &mut bits,
                (pack.volume_name_format != DEFAULT_VOLUME_NAME_FORMAT)
                    .then_some(pack.volume_name_format.as_str()),
            )?;
        }
    }

    let field = |key: &str| pack.config.get(key).and_then(Value::as_str).unwrap_or("");
    match source {
        SOURCE_LOCALFS => write_compact(&mut bits, field("root"))?,
        SOURCE_WEBDAV => {
            write_url(&mut bits, field("url"))?;
            write_optional(&mut bits, Some(field("username")).filter(|v| !v.is_empty()))?;
            write_optional(&mut bits, Some(field("password")).filter(|v| !v.is_empty()))?;
        }
        _ => {
            write_compact(&mut bits, field("root"))?;
            write_compact(&mut bits, field("bduss"))?;
            for key in ["userAgent", "clientId", "clientSecret"] {
                write_optional(&mut bits, Some(field(key)).filter(|v| !v.is_empty()))?;
            }
        }
    }

    let plain = bits.finish();
    let mut cipher = Aes128Siv::new_from_slice(&V1_KEY).map_err(|_| "invalid protocol key")?;
    let version = [VERSION];
    let mut wire = cipher
        .encrypt([b"safedrive-ds".as_slice(), version.as_slice()], &plain)
        .map_err(|_| "datasource share encryption failed")?;
    let encrypted_pad = wire.first().ok_or("empty ciphertext")? & 0xf0;
    wire.push(encrypted_pad | VERSION);
    Ok(format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(wire)))
}

pub(super) fn decode(link: &str) -> Result<DsPack, DecodeError> {
    let encoded = link
        .trim()
        .strip_prefix(SCHEME)
        .ok_or(DecodeError::Invalid)?;
    let mut wire = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DecodeError::Invalid)?;
    let trailer = wire.pop().ok_or(DecodeError::Invalid)?;
    let version = trailer & 0x0f;
    if wire.first().map(|byte| byte & 0xf0) != Some(trailer & 0xf0) {
        return Err(DecodeError::Invalid);
    }
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let mut cipher = Aes128Siv::new_from_slice(&V1_KEY).map_err(|_| DecodeError::Invalid)?;
    let version_bytes = [version];
    let plain = cipher
        .decrypt([b"safedrive-ds".as_slice(), version_bytes.as_slice()], &wire)
        .map_err(|_| DecodeError::Invalid)?;
    decode_plain(&plain)
}

fn decode_plain(plain: &[u8]) -> Result<DsPack, DecodeError> {
    let mut bits = BitReader::new(plain);
    let source = bits.read_bits(4)? as u8;
    let ds_type = match source {
        SOURCE_LOCALFS => "localfs",
        SOURCE_WEBDAV => "webdav",
        SOURCE_BAIDUPAN => "baidupan",
        _ => return Err(DecodeError::Invalid),
    };
    let encryption_enabled = bits.read_bit()?;
    let volume_enabled = bits.read_bit()?;
    let cache_enabled = bits.read_bit()?;
    let name = read_compact(&mut bits)?;
    if name.trim().is_empty() {
        return Err(DecodeError::Invalid);
    }
    let password = if encryption_enabled {
        read_compact(&mut bits)?
    } else {
        String::new()
    };
    let mut volume_size = crate::registry::DEFAULT_VOLUME_SIZE;
    let mut volume_strategy = "random";
    let mut volume_name_format = DEFAULT_VOLUME_NAME_FORMAT.to_owned();
    if volume_enabled {
        volume_size = read_size(&mut bits)?;
        volume_strategy = if bits.read_bit()? { "fixed" } else { "random" };
        if !encryption_enabled {
            if let Some(format) = read_optional(&mut bits)? {
                volume_name_format = format;
            }
        }
    }

    let config = match source {
        SOURCE_LOCALFS => json!({ "root": read_compact(&mut bits)? }),
        SOURCE_WEBDAV => json!({
            "url": read_url(&mut bits)?,
            "username": read_optional(&mut bits)?.unwrap_or_default(),
            "password": read_optional(&mut bits)?.unwrap_or_default(),
        }),
        _ => json!({
            "root": read_compact(&mut bits)?,
            "bduss": read_compact(&mut bits)?,
            "userAgent": read_optional(&mut bits)?.unwrap_or_default(),
            "clientId": read_optional(&mut bits)?.unwrap_or_default(),
            "clientSecret": read_optional(&mut bits)?.unwrap_or_default(),
        }),
    };
    bits.finish()?;
    Ok(DsPack {
        ds_type: ds_type.to_owned(),
        name,
        config,
        encryption_enabled,
        password,
        volume_enabled,
        volume_size,
        volume_strategy: volume_strategy.to_owned(),
        volume_name_format,
        cache_enabled,
    })
}

/// Volume sizes are almost always whole KiB, so a flag bit buys two bytes of
/// varint on the common path.
fn write_size(bits: &mut BitWriter, size: u64) {
    let kib = size % 1024 == 0;
    bits.write_bit(kib);
    bits.write_varint(if kib { size / 1024 } else { size });
}

fn read_size(bits: &mut BitReader<'_>) -> Result<u64, DecodeError> {
    let kib = bits.read_bit()?;
    let raw = bits.read_varint()?;
    if kib {
        raw.checked_mul(1024).ok_or(DecodeError::Invalid)
    } else {
        Ok(raw)
    }
}

/// `https://` and `http://` are the only accepted schemes, so one bit replaces
/// the prefix.
fn write_url(bits: &mut BitWriter, url: &str) -> Result<(), &'static str> {
    let rest = match url.strip_prefix("https://") {
        Some(rest) => {
            bits.write_bit(false);
            rest
        }
        None => {
            bits.write_bit(true);
            url.strip_prefix("http://").ok_or("webdav url needs http(s)")?
        }
    };
    write_compact(bits, rest)
}

fn read_url(bits: &mut BitReader<'_>) -> Result<String, DecodeError> {
    let plain = bits.read_bit()?;
    let rest = read_compact(bits)?;
    if rest.is_empty() {
        return Err(DecodeError::Invalid);
    }
    Ok(format!("{}{rest}", if plain { "http://" } else { "https://" }))
}

fn write_optional(bits: &mut BitWriter, value: Option<&str>) -> Result<(), &'static str> {
    bits.write_bit(value.is_some());
    match value {
        Some(value) => write_compact(bits, value),
        None => Ok(()),
    }
}

fn read_optional(bits: &mut BitReader<'_>) -> Result<Option<String>, DecodeError> {
    if bits.read_bit()? {
        Ok(Some(read_compact(bits)?))
    } else {
        Ok(None)
    }
}

/// Strings restricted to the 64-symbol base64url alphabet pack at 6 bits per
/// character — a 25% saving on the credentials that dominate these links.
fn write_compact(bits: &mut BitWriter, value: &str) -> Result<(), &'static str> {
    validate_string(value)?;
    let bytes = value.as_bytes();
    let packed = bytes.iter().all(|byte| COMPACT_ALPHABET.contains(byte));
    bits.write_bit(packed);
    bits.write_varint(bytes.len() as u64);
    if !packed {
        bits.write_bytes(bytes);
        return Ok(());
    }
    for byte in bytes {
        let index = COMPACT_ALPHABET
            .iter()
            .position(|candidate| candidate == byte)
            .ok_or("string is not packable")?;
        bits.write_bits(index as u64, 6);
    }
    Ok(())
}

fn read_compact(bits: &mut BitReader<'_>) -> Result<String, DecodeError> {
    let packed = bits.read_bit()?;
    let len = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    if len > MAX_STRING_BYTES {
        return Err(DecodeError::Invalid);
    }
    if !packed {
        let mut bytes = vec![0; len];
        bits.read_bytes(&mut bytes)?;
        return String::from_utf8(bytes).map_err(|_| DecodeError::Invalid);
    }
    let mut value = String::with_capacity(len);
    for _ in 0..len {
        let index = bits.read_bits(6)? as usize;
        value.push(COMPACT_ALPHABET[index] as char);
    }
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn baidu_pack() -> DsPack {
        DsPack {
            ds_type: "baidupan".into(),
            name: "我的网盘".into(),
            config: json!({
                "root": "/safedrive",
                "bduss": "0FBQWtOa1B-b2R6aUxXeUp4TFRZcVl3NUxIfjZDTkpqRHVsc3hYVn5CZkZDf0FBQUFBJCQAAAAAAAAAAAEAAAD",
                "userAgent": "",
                "clientId": "",
                "clientSecret": "",
            }),
            encryption_enabled: true,
            password: "kkPYxeNfrrn3nvTgQg9qtq3w".into(),
            volume_enabled: true,
            volume_size: 300 * 1024 * 1024,
            volume_strategy: "random".into(),
            volume_name_format: DEFAULT_VOLUME_NAME_FORMAT.into(),
            cache_enabled: true,
        }
    }

    fn webdav_pack() -> DsPack {
        DsPack {
            ds_type: "webdav".into(),
            name: "团队 WebDAV".into(),
            config: json!({
                "url": "https://dav.example.com/remote.php/dav",
                "username": "alice",
                "password": "s3cret!密码",
            }),
            encryption_enabled: false,
            password: String::new(),
            volume_enabled: true,
            volume_size: 12_345_678,
            volume_strategy: "fixed".into(),
            volume_name_format: "{s}.part{i}".into(),
            cache_enabled: false,
        }
    }

    fn localfs_pack() -> DsPack {
        DsPack {
            ds_type: "localfs".into(),
            name: "local".into(),
            config: json!({ "root": "/tmp/safedrive" }),
            encryption_enabled: true,
            password: "p@ss word".into(),
            volume_enabled: false,
            volume_size: crate::registry::DEFAULT_VOLUME_SIZE,
            volume_strategy: "random".into(),
            volume_name_format: DEFAULT_VOLUME_NAME_FORMAT.into(),
            cache_enabled: true,
        }
    }

    fn normalized(mut pack: DsPack) -> DsPack {
        // 与 decode 的输出对齐：不分卷时回落默认，加密时无名称模板。
        if !pack.volume_enabled {
            pack.volume_size = crate::registry::DEFAULT_VOLUME_SIZE;
            pack.volume_strategy = "random".into();
        }
        if pack.encryption_enabled {
            pack.volume_name_format = DEFAULT_VOLUME_NAME_FORMAT.into();
        }
        pack
    }

    #[test]
    fn all_types_roundtrip() {
        for pack in [baidu_pack(), webdav_pack(), localfs_pack()] {
            let link = encode(&pack).unwrap();
            assert!(link.starts_with(SCHEME), "{link}");
            assert_eq!(decode(&link), Ok(normalized(pack)));
        }
    }

    #[test]
    fn payload_has_no_obvious_plaintext_and_is_compact() {
        let pack = baidu_pack();
        let link = encode(&pack).unwrap();
        assert!(!link.contains("safedrive"));
        assert!(!link.contains(&pack.password));
        // BDUSS(87) + 密码(24) + 名称/根目录，6-bit 打包 + SIV 开销后应远小于
        // 直接 base64(JSON) 的长度（同配置约 500+ 字符）。
        assert!(link.len() < 200, "unexpectedly long link: {} {link}", link.len());
    }

    #[test]
    fn tampering_is_rejected() {
        let link = encode(&baidu_pack()).unwrap();
        let mut wire = URL_SAFE_NO_PAD
            .decode(link.strip_prefix(SCHEME).unwrap())
            .unwrap();
        wire[10] ^= 0x08;
        let changed = format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(wire));
        assert_eq!(decode(&changed), Err(DecodeError::Invalid));
    }

    #[test]
    fn unsupported_version_is_reported() {
        let link = encode(&baidu_pack()).unwrap();
        let mut wire = URL_SAFE_NO_PAD
            .decode(link.strip_prefix(SCHEME).unwrap())
            .unwrap();
        let pad = *wire.last().unwrap() & 0xf0;
        *wire.last_mut().unwrap() = pad | 7;
        let changed = format!("{SCHEME}{}", URL_SAFE_NO_PAD.encode(wire));
        assert_eq!(decode(&changed), Err(DecodeError::UnsupportedVersion(7)));
    }

    #[test]
    fn file_share_links_are_rejected() {
        assert_eq!(decode("sd://abcdef"), Err(DecodeError::Invalid));
    }

    #[test]
    fn baidu_tokens_are_not_carried() {
        let mut pack = baidu_pack();
        pack.config["accessToken"] = "live-token".into();
        pack.config["refreshToken"] = "live-refresh".into();
        let link = encode(&pack).unwrap();
        let decoded = decode(&link).unwrap();
        assert!(decoded.config.get("accessToken").is_none());
        assert!(decoded.config.get("refreshToken").is_none());
    }
}
