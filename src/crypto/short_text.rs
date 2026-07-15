//! 文件名专用的纯 Rust 短文本压缩。
//!
//! 格式按 Unicode 标量编码，自动选择拉丁、CJK、西里尔或 emoji 码表，
//! 并用静态文件名词典和小回溯窗口压缩重复片段。它不参与保密；调用方
//! 会按最终存储名字符数决定是否采用压缩结果。

const COMMON: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz._- ()";
const CJK_BASE: u32 = 0x4e00;
const CJK_COUNT: u32 = 1 << 15;
const KANA_BASE: u32 = 0x3040;
const KANA_COUNT: u32 = 0xc0;
const CYRILLIC_BASE: u32 = 0x0400;
const CYRILLIC_COUNT: u32 = 0x140;
const EMOJI_BASE: u32 = 0x1f300;
const EMOJI_COUNT: u32 = 0x800;
const WINDOW: usize = 64;
const MIN_MATCH: usize = 2;
const MAX_MATCH: usize = 17;
const DICTIONARY: &[&str] = &[
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".mp3",
    ".mp4",
    ".mkv",
    ".avi",
    ".mov",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".md",
    "IMG_",
    "VID_",
    "DSC_",
    "Screenshot",
    "Screen Shot",
    "Report",
    "Final",
    "Draft",
    "Copy",
    "Backup",
    "Document",
    "Download",
    "Photo",
    "Video",
    "Audio",
    "Image",
    "Archive",
    "Application",
    "Data",
    "文件",
    "照片",
    "视频",
    "电影",
    "报告",
    "备份",
    "下载",
    "文档",
];

#[derive(Clone, Copy)]
enum Mode {
    Latin,
    Cjk,
    Cyrillic,
    Emoji,
}

impl Mode {
    const ALL: [Self; 4] = [Self::Latin, Self::Cjk, Self::Cyrillic, Self::Emoji];

    fn code(self) -> u32 {
        match self {
            Self::Latin => 0,
            Self::Cjk => 1,
            Self::Cyrillic => 2,
            Self::Emoji => 3,
        }
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_len: 0,
        }
    }

    fn push(&mut self, value: u32, width: usize) {
        debug_assert!(width <= 32 && (width == 32 || value < (1u32 << width)));
        for shift in (0..width).rev() {
            if self.bit_len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((value >> shift) & 1) as u8;
            let last = self.bytes.last_mut().expect("刚创建了输出字节");
            *last |= bit << (7 - self.bit_len % 8);
            self.bit_len += 1;
        }
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    fn read(&mut self, width: usize) -> Option<u32> {
        if width > self.bytes.len().checked_mul(8)?.checked_sub(self.bit_pos)? {
            return None;
        }
        let mut value = 0u32;
        for _ in 0..width {
            let byte = self.bytes[self.bit_pos / 8];
            value = (value << 1) | ((byte >> (7 - self.bit_pos % 8)) & 1) as u32;
            self.bit_pos += 1;
        }
        Some(value)
    }

    fn has_only_canonical_padding(&self) -> bool {
        let remaining = self.bytes.len() * 8 - self.bit_pos;
        remaining < 8
            && (self.bit_pos..self.bytes.len() * 8)
                .all(|pos| self.bytes[pos / 8] & (1 << (7 - pos % 8)) == 0)
    }
}

fn common_index(ch: char) -> Option<u32> {
    ch.is_ascii().then_some(())?;
    COMMON.iter().position(|&b| b == ch as u8).map(|i| i as u32)
}

fn scalar_bits(ch: char, mode: Mode) -> usize {
    let cp = ch as u32;
    match mode {
        Mode::Latin if common_index(ch).is_some() => 6,
        Mode::Latin if ch.is_ascii_uppercase() => 7,
        Mode::Latin if ch.is_ascii_digit() => 7,
        Mode::Latin if ch.is_ascii() => 11,
        Mode::Cjk if (CJK_BASE..CJK_BASE + CJK_COUNT).contains(&cp) => 16,
        Mode::Cjk if common_index(ch).is_some() => 7,
        Mode::Cjk if ch.is_ascii() => 10,
        Mode::Cjk if (KANA_BASE..KANA_BASE + KANA_COUNT).contains(&cp) => 12,
        Mode::Cyrillic if (CYRILLIC_BASE..CYRILLIC_BASE + CYRILLIC_COUNT).contains(&cp) => 10,
        Mode::Emoji if (EMOJI_BASE..EMOJI_BASE + EMOJI_COUNT).contains(&cp) => 12,
        Mode::Cyrillic | Mode::Emoji if common_index(ch).is_some() => 7,
        Mode::Cyrillic | Mode::Emoji if ch.is_ascii() => 10,
        _ => 28,
    }
}

fn write_scalar(out: &mut BitWriter, ch: char, mode: Mode) {
    let cp = ch as u32;
    match mode {
        Mode::Latin if common_index(ch).is_some() => {
            out.push(common_index(ch).unwrap(), 6);
        }
        Mode::Latin if ch.is_ascii_uppercase() => {
            out.push(0b10, 2);
            out.push(cp - 'A' as u32, 5);
        }
        Mode::Latin if ch.is_ascii_digit() => {
            out.push(0b110, 3);
            out.push(cp - '0' as u32, 4);
        }
        Mode::Latin if ch.is_ascii() => {
            out.push(0b1110, 4);
            out.push(cp, 7);
        }
        Mode::Cjk if (CJK_BASE..CJK_BASE + CJK_COUNT).contains(&cp) => {
            out.push(cp - CJK_BASE, 16);
        }
        Mode::Cjk if common_index(ch).is_some() => {
            out.push(0b10, 2);
            out.push(common_index(ch).unwrap(), 5);
        }
        Mode::Cjk if ch.is_ascii() => {
            out.push(0b110, 3);
            out.push(cp, 7);
        }
        Mode::Cjk if (KANA_BASE..KANA_BASE + KANA_COUNT).contains(&cp) => {
            out.push(0b1110, 4);
            out.push(cp - KANA_BASE, 8);
        }
        Mode::Cyrillic if (CYRILLIC_BASE..CYRILLIC_BASE + CYRILLIC_COUNT).contains(&cp) => {
            out.push(cp - CYRILLIC_BASE, 10);
        }
        Mode::Emoji if (EMOJI_BASE..EMOJI_BASE + EMOJI_COUNT).contains(&cp) => {
            out.push(cp - EMOJI_BASE, 12);
        }
        Mode::Cyrillic | Mode::Emoji if common_index(ch).is_some() => {
            out.push(0b10, 2);
            out.push(common_index(ch).unwrap(), 5);
        }
        Mode::Cyrillic | Mode::Emoji if ch.is_ascii() => {
            out.push(0b110, 3);
            out.push(cp, 7);
        }
        _ => {
            out.push(0b1111000, 7);
            out.push(cp, 21);
        }
    }
}

fn best_match(chars: &[char], pos: usize, mode: Mode) -> Option<(usize, usize, usize)> {
    let mut best = None;
    let mut best_saving = 0usize;
    for offset in 1..=WINDOW.min(pos) {
        let max_len = MAX_MATCH.min(chars.len() - pos);
        let mut len = 0;
        while len < max_len && chars[pos + len] == chars[pos + len - offset] {
            len += 1;
        }
        for candidate_len in MIN_MATCH..=len {
            let literal_bits: usize = chars[pos..pos + candidate_len]
                .iter()
                .map(|&ch| scalar_bits(ch, mode))
                .sum();
            let saving = literal_bits.saturating_sub(16);
            if saving > best_saving {
                best_saving = saving;
                best = Some((offset, candidate_len, saving));
            }
        }
    }
    best
}

fn best_dictionary(chars: &[char], pos: usize, mode: Mode) -> Option<(usize, usize, usize)> {
    debug_assert!(DICTIONARY.len() <= 64);
    let mut best = None;
    let mut best_saving = 0usize;
    for (index, token) in DICTIONARY.iter().enumerate() {
        let token_chars: Vec<char> = token.chars().collect();
        if !chars[pos..].starts_with(&token_chars) {
            continue;
        }
        let literal_bits: usize = token_chars.iter().map(|&ch| scalar_bits(ch, mode)).sum();
        let saving = literal_bits.saturating_sub(13);
        if saving > best_saving {
            best_saving = saving;
            best = Some((index, token_chars.len(), saving));
        }
    }
    best
}

fn encode_mode(chars: &[char], mode: Mode) -> Vec<u8> {
    let mut out = BitWriter::new();
    out.push(mode.code(), 2);
    let mut pos = 0;
    while pos < chars.len() {
        let backref = best_match(chars, pos, mode);
        let dictionary = best_dictionary(chars, pos, mode);
        if let Some((index, len, _)) = dictionary.filter(|&(_, _, saving)| {
            backref.is_none_or(|(_, _, back_saving)| saving >= back_saving)
        }) {
            out.push(0b1111001, 7);
            out.push(index as u32, 6);
            pos += len;
        } else if let Some((offset, len, _)) = backref {
            out.push(0b111101, 6);
            out.push((offset - 1) as u32, 6);
            out.push((len - MIN_MATCH) as u32, 4);
            pos += len;
        } else {
            write_scalar(&mut out, chars[pos], mode);
            pos += 1;
        }
    }
    out.push(0b11111, 5);
    out.bytes
}

/// 压缩 UTF-8 文件名。仅在结果严格短于原文时返回 `Some`。
pub fn compress(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    let chars: Vec<char> = s.chars().collect();
    let best = Mode::ALL
        .into_iter()
        .map(|mode| encode_mode(&chars, mode))
        .min_by_key(Vec::len)
        .expect("至少有一种短文本编码模式");
    (best.len() < s.len()).then_some(best)
}

fn push_checked(out: &mut String, chars: &mut Vec<char>, ch: char, max_out: usize) -> Option<()> {
    if out.len().checked_add(ch.len_utf8())? > max_out {
        return None;
    }
    out.push(ch);
    chars.push(ch);
    Some(())
}

/// 解压文件名；格式异常或 UTF-8 输出超过 `max_out` 字节时返回 `None`。
pub fn decompress(data: &[u8], max_out: usize) -> Option<String> {
    let mut bits = BitReader::new(data);
    let mode = match bits.read(2)? {
        0 => Mode::Latin,
        1 => Mode::Cjk,
        2 => Mode::Cyrillic,
        3 => Mode::Emoji,
        _ => unreachable!(),
    };
    let mut out = String::new();
    let mut chars = Vec::new();
    loop {
        let first = bits.read(1)?;
        let cp = if first == 0 {
            match mode {
                Mode::Latin => *COMMON.get(bits.read(5)? as usize)? as u32,
                Mode::Cjk => CJK_BASE + bits.read(15)?,
                Mode::Cyrillic => {
                    let i = bits.read(9)?;
                    if i >= CYRILLIC_COUNT {
                        return None;
                    }
                    CYRILLIC_BASE + i
                }
                Mode::Emoji => EMOJI_BASE + bits.read(11)?,
            }
        } else if bits.read(1)? == 0 {
            match mode {
                Mode::Latin => {
                    let i = bits.read(5)?;
                    if i >= 26 {
                        return None;
                    }
                    'A' as u32 + i
                }
                Mode::Cjk | Mode::Cyrillic | Mode::Emoji => {
                    *COMMON.get(bits.read(5)? as usize)? as u32
                }
            }
        } else if bits.read(1)? == 0 {
            match mode {
                Mode::Latin => {
                    let i = bits.read(4)?;
                    if i >= 10 {
                        return None;
                    }
                    '0' as u32 + i
                }
                Mode::Cjk | Mode::Cyrillic | Mode::Emoji => bits.read(7)?,
            }
        } else if bits.read(1)? == 0 {
            match mode {
                Mode::Latin => bits.read(7)?,
                Mode::Cjk => {
                    let i = bits.read(8)?;
                    if i >= KANA_COUNT {
                        return None;
                    }
                    KANA_BASE + i
                }
                Mode::Cyrillic | Mode::Emoji => return None,
            }
        } else if bits.read(1)? == 0 {
            if bits.read(1)? == 0 {
                if bits.read(1)? == 0 {
                    bits.read(21)?
                } else {
                    let token = *DICTIONARY.get(bits.read(6)? as usize)?;
                    for ch in token.chars() {
                        push_checked(&mut out, &mut chars, ch, max_out)?;
                    }
                    continue;
                }
            } else {
                let offset = bits.read(6)? as usize + 1;
                let len = bits.read(4)? as usize + MIN_MATCH;
                if offset > chars.len() {
                    return None;
                }
                for _ in 0..len {
                    let ch = chars[chars.len() - offset];
                    push_checked(&mut out, &mut chars, ch, max_out)?;
                }
                continue;
            }
        } else {
            if !bits.has_only_canonical_padding() || out.is_empty() {
                return None;
            }
            return Some(out);
        };
        let ch = char::from_u32(cp)?;
        push_checked(&mut out, &mut chars, ch, max_out)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_shrink_typical_names() {
        for s in [
            "测试视频.mp4",
            "我的家庭相册2026年春节.zip",
            "Annual Report FY2026 Final v3.pdf",
            "IMG_20260713_182233.jpg",
            "日本語のファイル名.mkv",
            "русский файл.txt",
            "🎬 movie night 🍿.mp4",
            "读书笔记 - Designing Data-Intensive Applications.md",
            "加密数据源管理服务的超长中文文件名压缩能力测试加密数据源管理服务",
        ] {
            if let Some(compressed) = compress(s) {
                assert!(compressed.len() < s.len(), "{s}");
                assert_eq!(decompress(&compressed, 1024).as_deref(), Some(s), "{s}");
            }
        }
    }

    #[test]
    fn short_or_incompressible_returns_none() {
        assert!(compress("").is_none());
        assert!(compress("a").is_none());
        assert_eq!(
            decompress(&compress("🎬").unwrap(), 4).as_deref(),
            Some("🎬")
        );
    }

    #[test]
    fn bounds_and_malformed_inputs_are_rejected() {
        let compressed = compress("我的家庭相册2026年春节.zip").unwrap();
        assert!(decompress(&compressed, 4).is_none());
        assert!(decompress(&[], 1024).is_none());
        assert!(decompress(&[0xff], 1024).is_none());
        let mut appended = compressed.clone();
        appended.push(0);
        assert!(decompress(&appended, 1024).is_none());
    }

    #[test]
    fn every_supported_category_roundtrips() {
        let source = "abc XYZ 019 !~ 测试 龍 日本語 カナ русский 🎬\u{10ffff}";
        for mode in Mode::ALL {
            let encoded = encode_mode(&source.chars().collect::<Vec<_>>(), mode);
            assert_eq!(decompress(&encoded, 1024).as_deref(), Some(source));
        }
    }
}
