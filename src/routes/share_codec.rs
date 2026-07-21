//! Compact, authenticated `sd://` share payloads.
//!
//! Wire format (protocol v1):
//! `base64url(AES-128-SIV(binary payload) || encrypted-pad:4 || version:4)`.
//! The clear version nibble is authenticated as AES-SIV associated data. The
//! binary payload starts with the 4-bit datasource type; all payload bits are
//! encrypted. The alignment nibble repeats ciphertext bits instead of exposing
//! a fixed marker. AES-SIV adds one 16-byte synthetic IV and needs no nonce.

use aes_siv::KeyInit;
use aes_siv::siv::Aes128Siv;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const VERSION: u8 = 1;
const SOURCE_BAIDUPAN: u8 = 1;
const MAX_ITEMS: usize = 100;
const MAX_STRING_BYTES: usize = 16 * 1024;
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
    pub encrypted: bool,
    pub item_count: usize,
    /// Keys which decrypt the shared roots' storage names. Multiple selected
    /// roots from the same parent share one key.
    pub parent_keys: Vec<[u8; 16]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DecodeError {
    UnsupportedVersion(u8),
    Invalid,
}

pub(super) fn baidu_share_id(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    url.path_segments()?
        .collect::<Vec<_>>()
        .windows(2)
        .find(|parts| parts[0] == "s")
        .map(|parts| parts[1].strip_prefix('1').unwrap_or(parts[1]).to_owned())
        .filter(|id| !id.is_empty() && id.len() <= MAX_STRING_BYTES)
}

pub(super) fn encode(pack: &Pack) -> Result<String, &'static str> {
    let source = match pack.source_type.as_str() {
        "baidupan" => SOURCE_BAIDUPAN,
        _ => return Err("unsupported datasource type"),
    };
    if pack.item_count == 0 || pack.item_count > MAX_ITEMS {
        return Err("invalid item count");
    }
    if pack.parent_keys.len() > pack.item_count || pack.encrypted != !pack.parent_keys.is_empty() {
        return Err("parent keys do not match encryption flag");
    }
    validate_string(&pack.share_id)?;

    let mut bits = BitWriter::default();
    bits.write_bits(source as u64, 4);
    bits.write_bit(pack.encrypted);
    bits.write_string(&pack.share_id)?;
    write_password(&mut bits, &pack.password)?;
    bits.write_varint(pack.item_count as u64);
    bits.write_varint(pack.parent_keys.len() as u64);
    for key in &pack.parent_keys {
        bits.write_bytes(key);
    }

    let plain = bits.finish();
    let mut cipher = Aes128Siv::new_from_slice(&V1_KEY).map_err(|_| "invalid protocol key")?;
    let version = [VERSION];
    let ciphertext = cipher
        .encrypt([b"safedrive-share".as_slice(), version.as_slice()], &plain)
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
        _ => return Err(DecodeError::Invalid),
    };
    let encrypted = bits.read_bit()?;
    let share_id = bits.read_string()?;
    if share_id.is_empty() {
        return Err(DecodeError::Invalid);
    }
    let password = read_password(&mut bits)?;
    let item_count = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    if item_count == 0 || item_count > MAX_ITEMS {
        return Err(DecodeError::Invalid);
    }
    let key_count = usize::try_from(bits.read_varint()?).map_err(|_| DecodeError::Invalid)?;
    if key_count > item_count || encrypted != (key_count != 0) {
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
        item_count,
        parent_keys,
    })
}

fn validate_string(value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_STRING_BYTES {
        Err("string too long")
    } else {
        Ok(())
    }
}

fn write_password(bits: &mut BitWriter, password: &str) -> Result<(), &'static str> {
    let bytes = password.as_bytes();
    if bytes.len() != 4 {
        return Err("Baidu password must contain four characters");
    }
    for byte in bytes {
        let index = PASSWORD_ALPHABET
            .iter()
            .position(|candidate| candidate == byte)
            .ok_or("Baidu password contains an unsupported character")?;
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

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    used: u8,
}

impl BitWriter {
    fn write_bit(&mut self, bit: bool) {
        self.write_bits(bit as u64, 1);
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for shift in (0..count).rev() {
            if self.used == 0 {
                self.bytes.push(0);
            }
            let bit = ((value >> shift) & 1) as u8;
            let last = self.bytes.len() - 1;
            self.bytes[last] |= bit << (7 - self.used);
            self.used = (self.used + 1) & 7;
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_bits(*byte as u64, 8);
        }
    }

    fn write_varint(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.write_bits(byte as u64, 8);
            if value == 0 {
                break;
            }
        }
    }

    fn write_string(&mut self, value: &str) -> Result<(), &'static str> {
        validate_string(value)?;
        self.write_varint(value.len() as u64);
        self.write_bytes(value.as_bytes());
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_bit(&mut self) -> Result<bool, DecodeError> {
        Ok(self.read_bits(1)? != 0)
    }

    fn read_bits(&mut self, count: u8) -> Result<u64, DecodeError> {
        if count > 64 || self.position + count as usize > self.bytes.len() * 8 {
            return Err(DecodeError::Invalid);
        }
        let mut value = 0u64;
        for _ in 0..count {
            let byte = self.bytes[self.position / 8];
            let bit = (byte >> (7 - self.position % 8)) & 1;
            value = (value << 1) | bit as u64;
            self.position += 1;
        }
        Ok(value)
    }

    fn read_bytes(&mut self, output: &mut [u8]) -> Result<(), DecodeError> {
        for byte in output {
            *byte = self.read_bits(8)? as u8;
        }
        Ok(())
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.read_bits(8)? as u8;
            if shift == 63 && byte > 1 {
                return Err(DecodeError::Invalid);
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::Invalid)
    }

    fn read_string(&mut self) -> Result<String, DecodeError> {
        let len = usize::try_from(self.read_varint()?).map_err(|_| DecodeError::Invalid)?;
        if len > MAX_STRING_BYTES {
            return Err(DecodeError::Invalid);
        }
        let mut bytes = vec![0; len];
        self.read_bytes(&mut bytes)?;
        String::from_utf8(bytes).map_err(|_| DecodeError::Invalid)
    }

    fn finish(mut self) -> Result<(), DecodeError> {
        let remaining = self.bytes.len() * 8 - self.position;
        if remaining >= 8 {
            return Err(DecodeError::Invalid);
        }
        while self.position < self.bytes.len() * 8 {
            if self.read_bit()? {
                return Err(DecodeError::Invalid);
            }
        }
        Ok(())
    }
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
            item_count: 8,
            parent_keys: encrypted.then_some([0x5a; 16]).into_iter().collect(),
        }
    }

    #[test]
    fn encrypted_and_plain_roundtrip() {
        for pack in [sample(true), sample(false)] {
            let link = encode(&pack).unwrap();
            assert_eq!(decode(&link), Ok(pack));
        }
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
        let mut hundred = one.clone();
        hundred.item_count = 100;
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
        *wire.last_mut().unwrap() = encrypted_pad | 2;
        let changed = format!("sd://{}", URL_SAFE_NO_PAD.encode(wire));
        assert_eq!(decode(&changed), Err(DecodeError::UnsupportedVersion(2)));
    }
}
