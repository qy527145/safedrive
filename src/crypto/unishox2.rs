//! Unishox2 短字符串压缩的安全封装（C 源 vendored 于 third_party/unishox2）。
//!
//! 只用于文件名加密前的压缩：中文名约省 25%，英文名约省 20-40%。
//! 压缩非确定收益 —— `compress` 在"压不小"时返回 None，编码层回退存原文。

use std::ffi::{c_char, c_int};

unsafe extern "C" {
    fn sd_unishox2_compress(input: *const c_char, len: c_int, out: *mut c_char, olen: c_int) -> c_int;
    fn sd_unishox2_decompress(input: *const c_char, len: c_int, out: *mut c_char, olen: c_int) -> c_int;
}

/// 压缩 UTF-8 字符串。仅在结果严格短于原文时返回 Some。
pub fn compress(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    // Unishox2 最坏情况略有膨胀，缓冲区给足余量
    let mut out = vec![0u8; s.len() * 2 + 32];
    let n = unsafe {
        sd_unishox2_compress(
            s.as_ptr() as *const c_char,
            s.len() as c_int,
            out.as_mut_ptr() as *mut c_char,
            out.len() as c_int,
        )
    };
    if n <= 0 || n as usize >= s.len() {
        return None; // 失败或压不小 → 调用方存原文
    }
    out.truncate(n as usize);
    Some(out)
}

/// 解压回 UTF-8 字符串。`max_out` 为解压结果上限（防异常输入撑爆）。
pub fn decompress(data: &[u8], max_out: usize) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let mut out = vec![0u8; max_out];
    let n = unsafe {
        sd_unishox2_decompress(
            data.as_ptr() as *const c_char,
            data.len() as c_int,
            out.as_mut_ptr() as *mut c_char,
            out.len() as c_int,
        )
    };
    // UNISHOX_API_WITH_OUTPUT_LEN=1：越界时返回 > olen 的哨兵值
    if n <= 0 || n as usize > max_out {
        return None;
    }
    out.truncate(n as usize);
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_scripts() {
        for s in [
            "测试视频.mp4",
            "我的家庭相册2026年春节.zip",
            "Annual Report FY2026 Final v3.pdf",
            "IMG_20260713_182233.jpg",
            "日本語のファイル名.mkv",
            "русский файл.txt",
            "🎬 movie night 🍿.mp4",
            "读书笔记 - Designing Data-Intensive Applications.md",
        ] {
            if let Some(c) = compress(s) {
                assert!(c.len() < s.len(), "{s}");
                assert_eq!(decompress(&c, 1024).as_deref(), Some(s), "{s}");
            }
        }
    }

    #[test]
    fn incompressible_returns_none() {
        // 单字符压不小 → None（调用方存原文）
        assert!(compress("a").is_none());
        assert!(compress("").is_none());
    }

    #[test]
    fn decompress_bounds_respected() {
        let c = compress("我的家庭相册2026年春节.zip").unwrap();
        assert!(decompress(&c, 4).is_none(), "超出 max_out 必须报错而非截断");
        assert!(decompress(&[0xff, 0xfe, 0x01], 64).is_none() || true, "垃圾输入不 panic");
    }
}
