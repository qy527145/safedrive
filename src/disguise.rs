//! 存储侧文件伪装 —— 给写到云端的每个对象套一层「看起来像普通媒体文件」
//! 的固定头部。
//!
//! 与加密、分卷是三个正交开关：伪装**只作用于实际落地的存储对象**，永远是
//! 整条写入链路的最后一道。分卷时每个卷各自套一份头部；同时开了加密时顺序
//! 是「先加密、再对密文套头」——于是伪装对密钥体系与合并坐标系完全透明。
//!
//! 合并坐标系仍然是**明文坐标**：布局探测把每个存储对象的大小减去头部长度，
//! 只有真正向上游发 Range 请求、以及真正声明对象大小时才把头部长度加回去。
//! 这样 chunk 计划、keystream 偏移与密文块缓存都不需要知道伪装存在。

use bytes::Bytes;

/// 伪装算法。`None` = 不伪装（存储对象即数据本身）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disguise {
    #[default]
    None,
    /// 24 位 BMP：标准 54 字节头部（14 字节文件头 + 40 字节信息头），
    /// 宽高按数据大小动态推算。
    Bmp,
}

/// 勾选伪装但没指定算法时用的默认算法。
pub const DEFAULT_ALGORITHM: &str = "bmp";

/// 目前支持的伪装算法（前端下拉列表与服务端校验共用）。
pub const ALGORITHMS: &[&str] = &["bmp"];

const BMP_HEADER_LEN: u64 = 54;
/// 96 DPI，写进 bi{X,Y}PelsPerMeter。
const BMP_PELS_PER_METER: i32 = 3780;

impl Disguise {
    /// 按数据源配置取伪装算法。算法名认不出时退回默认算法 —— 存储侧字节
    /// 已经按某种算法写下去了，静默按「不伪装」读会把头部当数据吐给客户端。
    pub fn of(datasource: &crate::registry::DataSource) -> Self {
        if !datasource.disguise_enabled {
            return Self::None;
        }
        Self::from_algorithm(&datasource.disguise_algorithm).unwrap_or(Self::Bmp)
    }

    /// 算法名 → 算法；`None` 表示不认识这个名字。
    pub fn from_algorithm(algorithm: &str) -> Option<Self> {
        match algorithm.trim().to_ascii_lowercase().as_str() {
            "bmp" => Some(Self::Bmp),
            _ => None,
        }
    }

    /// 伪装算法对应的文件扩展名 —— 叶子名默认模版会带上它，让存储侧的对象
    /// 连名字带内容都像那么回事。
    pub fn extension(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Bmp => Some("bmp"),
        }
    }

    /// 每个存储对象额外占用的头部字节数。
    pub fn header_len(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Bmp => BMP_HEADER_LEN,
        }
    }

    /// 按数据区大小生成头部。`Disguise::None` 返回空。
    pub fn header(self, data_len: u64) -> Bytes {
        match self {
            Self::None => Bytes::new(),
            Self::Bmp => Bytes::copy_from_slice(&bmp_header(data_len)),
        }
    }

    /// 存储对象大小 → 数据区大小。
    pub fn data_len(self, stored_len: u64) -> u64 {
        stored_len.saturating_sub(self.header_len())
    }

    /// 数据区大小 → 存储对象大小。
    pub fn stored_len(self, data_len: u64) -> u64 {
        data_len.saturating_add(self.header_len())
    }
}

/// 由数据区大小推出一组自洽的 BMP 宽高：宽取 4 的倍数（于是 24bpp 的行跨距
/// 恰好等于 `width * 3`，不需要行填充），高取数据能铺满的行数。像素数据比
/// 声明的少一点（末尾不足一行的尾字节）对查看器无害，但反过来会被判为截断，
/// 所以只向下取整。
fn bmp_geometry(data_len: u64) -> (i32, i32) {
    /// i32 能表示的最大 4 的倍数。
    const MAX_WIDTH: u64 = 0x7fff_fffc;
    let width = ((data_len / 3).isqrt() & !3).clamp(4, MAX_WIDTH);
    let height = (data_len / (width * 3)).clamp(1, i32::MAX as u64);
    (width as i32, height as i32)
}

/// 标准 54 字节 BMP 头部（小端）：BITMAPFILEHEADER + BITMAPINFOHEADER。
fn bmp_header(data_len: u64) -> [u8; BMP_HEADER_LEN as usize] {
    let (width, height) = bmp_geometry(data_len);
    let image = (width as u64 * 3).saturating_mul(height as u64);
    let u32_of = |value: u64| (value.min(u32::MAX as u64) as u32).to_le_bytes();

    let mut out = [0u8; BMP_HEADER_LEN as usize];
    // BITMAPFILEHEADER
    out[0..2].copy_from_slice(b"BM");
    out[2..6].copy_from_slice(&u32_of(BMP_HEADER_LEN + data_len)); // bfSize
    // 6..10 bfReserved1 / bfReserved2 = 0
    out[10..14].copy_from_slice(&u32_of(BMP_HEADER_LEN)); // bfOffBits
    // BITMAPINFOHEADER
    out[14..18].copy_from_slice(&40u32.to_le_bytes()); // biSize
    out[18..22].copy_from_slice(&width.to_le_bytes());
    out[22..26].copy_from_slice(&height.to_le_bytes());
    out[26..28].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
    out[28..30].copy_from_slice(&24u16.to_le_bytes()); // biBitCount
    // 30..34 biCompression = BI_RGB(0)
    out[34..38].copy_from_slice(&u32_of(image)); // biSizeImage
    out[38..42].copy_from_slice(&BMP_PELS_PER_METER.to_le_bytes());
    out[42..46].copy_from_slice(&BMP_PELS_PER_METER.to_le_bytes());
    // 46..54 biClrUsed / biClrImportant = 0
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_transparent() {
        let none = Disguise::None;
        assert_eq!(none.header_len(), 0);
        assert!(none.header(1234).is_empty());
        assert_eq!(none.data_len(1000), 1000);
        assert_eq!(none.stored_len(1000), 1000);
    }

    #[test]
    fn algorithm_names_are_recognized_case_insensitively() {
        assert_eq!(Disguise::from_algorithm("bmp"), Some(Disguise::Bmp));
        assert_eq!(Disguise::from_algorithm(" BMP "), Some(Disguise::Bmp));
        assert_eq!(Disguise::from_algorithm("png"), None);
        assert!(ALGORITHMS.contains(&DEFAULT_ALGORITHM));
    }

    #[test]
    fn bmp_header_is_54_bytes_and_self_consistent() {
        for data_len in [0u64, 1, 3, 54, 4095, 700_000, 300 * 1024 * 1024] {
            let header = Disguise::Bmp.header(data_len);
            assert_eq!(header.len(), 54, "data_len={data_len}");
            assert_eq!(&header[..2], b"BM");
            let u32_at =
                |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap()) as u64;
            let i32_at = |at: usize| i32::from_le_bytes(header[at..at + 4].try_into().unwrap());
            assert_eq!(u32_at(2), 54 + data_len, "bfSize");
            assert_eq!(u32_at(10), 54, "bfOffBits");
            assert_eq!(u32_at(14), 40, "biSize");
            assert_eq!(
                u16::from_le_bytes(header[26..28].try_into().unwrap()),
                1,
                "biPlanes"
            );
            assert_eq!(
                u16::from_le_bytes(header[28..30].try_into().unwrap()),
                24,
                "biBitCount"
            );
            assert_eq!(u32_at(30), 0, "biCompression = BI_RGB");
            let (width, height) = (i32_at(18), i32_at(22));
            assert!(width > 0 && height > 0, "data_len={data_len}");
            assert_eq!(width % 4, 0, "宽为 4 的倍数，24bpp 无需行填充");
            // 声明的像素字节数 = 行跨距 * 行数，且不超过数据区（除了不足一行的极小文件）。
            assert_eq!(u32_at(34), width as u64 * 3 * height as u64);
            assert!(
                u32_at(34) <= data_len.max(width as u64 * 3),
                "data_len={data_len}"
            );
        }
    }

    #[test]
    fn bmp_geometry_grows_squarish() {
        // 300 MiB 恰好铺满 10240x10240 的 24bpp 图像。
        let (width, height) = bmp_geometry(300 * 1024 * 1024);
        assert_eq!((width, height), (10240, 10240));
    }

    #[test]
    fn stored_and_data_len_are_inverse() {
        let bmp = Disguise::Bmp;
        assert_eq!(bmp.header_len(), 54);
        for data_len in [0u64, 1, 12_345, u64::from(u32::MAX)] {
            assert_eq!(bmp.data_len(bmp.stored_len(data_len)), data_len);
        }
        // 外部截断/篡改导致对象比头部还短时退化为 0，而不是绕回天文数字。
        assert_eq!(bmp.data_len(10), 0);
    }
}
