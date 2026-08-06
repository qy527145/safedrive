//! 存储端叶子对象的命名策略。
//!
//! **受管数据源**（加密 / 分卷 / 伪装任一开启）里，客户端眼中的一个文件在存储
//! 端是一个**信封目录** —— 目录名由根密码派生的密钥链加密，里面装着明文文件
//! 名、明文大小和该文件自己的密钥（见 [`crate::crypto::names`]）。信封目录下
//! 是若干**叶子对象**：分卷时一卷一个，未分卷就一个。
//!
//! 叶子名由数据源的模版决定，五个占位符：
//!
//! | 占位符 | 含义 | 可用条件 |
//! | --- | --- | --- |
//! | `{s}` | 原始文件名（含扩展名） | 任何时候 |
//! | `{n}` | 原始文件名（不含扩展名） | 任何时候 |
//! | `{x}` | 原始扩展名（不含点；没有扩展名则展开成空） | 任何时候 |
//! | `{e}` | 文件密钥派生的可逆索引凭据（小写十六进制） | 仅加密，且必填 |
//! | `{i}` | 等宽十进制序号（从 1 起） | 仅分卷；未加密时必填 |
//!
//! 默认值由三个开关推出：加密 → `{e}`；未加密分卷 → `{s}.{i}`；两者皆无 →
//! `{s}`。开了伪装再在末尾补上算法扩展名（BMP → `.bmp`）。
//!
//! `{e}` 之所以在加密时必填：它既是索引又不泄露任何明文信息。`{i}` 之所以在
//! 未加密分卷时必填：没有 `{e}` 时它是唯一能确定卷序的东西。
//!
//! 读取时不去「解析」文件名，而是**按模版生成候选名再查表**：命中的就是本文件
//! 的卷，其余条目一概静默忽略 —— 手动往信封目录里塞进来的文件既不会被当成卷，
//! 也不会影响读取。

use std::collections::HashMap;

use crate::crypto::ChunkPrp;
use crate::disguise::Disguise;

pub const SOURCE: &str = "{s}";
pub const STEM: &str = "{n}";
pub const EXTENSION: &str = "{x}";
pub const ENVELOPE: &str = "{e}";
pub const INDEX: &str = "{i}";

/// `{i}` 的最小宽度。两位起步，卷数上百再自动加宽。
const MIN_INDEX_WIDTH: usize = 2;
/// 读取时探测 `{i}` 宽度的上限（10^8 卷，远超任何真实文件）。
const MAX_INDEX_WIDTH: usize = 8;
/// 反解时的叶子数硬上限，纯粹是防跑飞的兜底。
const MAX_LEAVES: usize = 1 << 20;

/// 数据源默认模版：加密用 `{e}`（不泄露明文名），否则用 `{s}`；分卷再带等宽
/// 序号；开了伪装则在末尾加上算法对应的扩展名（BMP → `.bmp`）。
pub fn default_format(encrypted: bool, volume: bool, disguise: Disguise) -> String {
    let base = if encrypted {
        ENVELOPE.to_owned()
    } else if volume {
        format!("{SOURCE}.{INDEX}")
    } else {
        SOURCE.to_owned()
    };
    match disguise.extension() {
        Some(extension) => format!("{base}.{extension}"),
        None => base,
    }
}

/// 校验模版是否与开关自洽。错误信息直接面向用户。
pub fn validate_format(format: &str, encrypted: bool, volume: bool) -> Result<(), String> {
    if format.trim().is_empty() {
        return Err("叶子文件名模版不能为空".into());
    }
    let has_envelope = format.contains(ENVELOPE);
    let has_index = format.contains(INDEX);
    if encrypted && !has_envelope {
        return Err(format!(
            "加密数据源的模版必须包含 {ENVELOPE}（可逆索引凭据，同时避免泄露明文名）"
        ));
    }
    if !encrypted && has_envelope {
        return Err(format!("{ENVELOPE} 只在启用加密时可用"));
    }
    if volume && !encrypted && !has_index {
        return Err(format!(
            "未加密的分卷数据源必须包含 {INDEX}，否则无法确定分卷序号"
        ));
    }
    if !volume && has_index {
        return Err(format!("{INDEX} 只在启用分卷时可用"));
    }
    // 占位符替换掉之后不该再剩下花括号 —— 拼错的 `{x}` 会静默变成字面量，
    // 那就会写出一批名字全一样的叶子。
    let residue = format
        .replace(SOURCE, "")
        .replace(STEM, "")
        .replace(EXTENSION, "")
        .replace(ENVELOPE, "")
        .replace(INDEX, "");
    if residue.contains('{') || residue.contains('}') {
        return Err(format!(
            "模版里有无法识别的占位符；只支持 {SOURCE} / {STEM} / {EXTENSION} / {ENVELOPE} / {INDEX}"
        ));
    }
    // 两个取样：带扩展名与不带扩展名。`{x}` 对后者展开成空，只有两种都站得住
    // 的模版才是安全的（否则某类文件会落出一个空名字或纯 `.` 的叶子）。
    for source in ["sample.bin", "sample"] {
        let sample = render(
            format,
            source,
            &ChunkPrp::new(&[0u8; 16]),
            0,
            MIN_INDEX_WIDTH,
        );
        if sample.contains('/') || sample.contains('\\') || sample == "." || sample == ".." {
            return Err("模版展开后包含非法路径字符".into());
        }
        if sample.is_empty() {
            return Err(format!(
                "模版对没有扩展名的文件会展开成空名字；请至少再带上 {STEM} / {SOURCE} / {ENVELOPE} / {INDEX} 或固定文字"
            ));
        }
    }
    Ok(())
}

/// `{i}` 的宽度：卷数决定，至少两位（定宽才能保证字典序 = 卷序）。
fn index_width(count: usize) -> usize {
    count.max(1).to_string().len().max(MIN_INDEX_WIDTH)
}

/// 拆出「主名 / 扩展名」。最后一个点之前是主名，之后是扩展名；没有点、或点
/// 就在开头（`.gitignore` 这类隐藏文件）时整串都算主名，扩展名为空。
fn split_extension(source: &str) -> (&str, &str) {
    match source.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, extension),
        _ => (source, ""),
    }
}

fn render(format: &str, source: &str, prp: &ChunkPrp, index: usize, width: usize) -> String {
    let mut out = format.to_owned();
    if out.contains(SOURCE) {
        out = out.replace(SOURCE, source);
    }
    if out.contains(STEM) || out.contains(EXTENSION) {
        let (stem, extension) = split_extension(source);
        out = out.replace(STEM, stem).replace(EXTENSION, extension);
    }
    if out.contains(ENVELOPE) {
        out = out.replace(ENVELOPE, &prp.name_of(index));
    }
    if out.contains(INDEX) {
        out = out.replace(INDEX, &format!("{:0width$}", index + 1, width = width));
    }
    out
}

/// 前 `count` 个叶子名（下标 i 即第 i 卷）。上传时用它决定写到哪些对象。
pub fn leaf_names(format: &str, source: &str, pw: &[u8], count: usize) -> Vec<String> {
    let prp = ChunkPrp::new(pw);
    let width = index_width(count);
    (0..count)
        .map(|index| render(format, source, &prp, index, width))
        .collect()
}

/// 模版能表达多少个不同的叶子名：既没有 `{e}` 也没有 `{i}` 时只有一个。
fn max_leaves(format: &str) -> usize {
    if format.contains(ENVELOPE) || format.contains(INDEX) {
        MAX_LEAVES
    } else {
        1
    }
}

/// 从存储端条目里认出属于本文件的叶子，返回**从第 0 卷起连续的一段**
/// `(名字, 字节数)`。
///
/// 生成候选名再查表，所以：不匹配的条目（手动上传的文件、子目录、别的文件的
/// 卷）一概静默忽略；中间缺卷则在缺口处停下 —— 调用方拿信封里记录的明文大小
/// 一比就能发现少了东西。
pub fn resolve_leaves(
    format: &str,
    source: &str,
    pw: &[u8],
    entries: &[crate::adapters::Entry],
) -> Vec<(String, u64)> {
    let listed: HashMap<&str, u64> = entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| (entry.name.as_str(), entry.size))
        .collect();
    let prp = ChunkPrp::new(pw);
    let cap = max_leaves(format);
    // `{i}` 的宽度由卷数决定，而卷数正是我们要查的东西 —— 逐个宽度试，命中
    // 最长的那个即为真。定宽保证了不同宽度的名字互不相同，不会认错。
    let widths: Vec<usize> = if format.contains(INDEX) {
        (MIN_INDEX_WIDTH..=MAX_INDEX_WIDTH).collect()
    } else {
        vec![MIN_INDEX_WIDTH]
    };
    let mut best: Vec<(String, u64)> = Vec::new();
    for width in widths {
        let mut found: Vec<(String, u64)> = Vec::new();
        while found.len() < cap {
            let name = render(format, source, &prp, found.len(), width);
            match listed.get(name.as_str()) {
                Some(size) => found.push((name, *size)),
                None => break,
            }
        }
        if found.len() > best.len() {
            best = found;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(names: &[(&str, u64)]) -> Vec<crate::adapters::Entry> {
        names
            .iter()
            .map(|(name, size)| crate::adapters::Entry {
                id: None,
                name: (*name).to_owned(),
                is_dir: false,
                size: *size,
                mtime: 0,
            })
            .collect()
    }

    #[test]
    fn defaults_follow_the_switches() {
        // 加密 → {e}（不泄露明文名）；未加密分卷 → 明文名 + 等宽序号；都没有 → 明文名
        assert_eq!(default_format(true, true, Disguise::None), "{e}");
        assert_eq!(default_format(true, false, Disguise::None), "{e}");
        assert_eq!(default_format(false, true, Disguise::None), "{s}.{i}");
        assert_eq!(default_format(false, false, Disguise::None), "{s}");
        // 伪装只是在默认模版尾部加上算法扩展名
        assert_eq!(default_format(true, true, Disguise::Bmp), "{e}.bmp");
        assert_eq!(default_format(false, true, Disguise::Bmp), "{s}.{i}.bmp");
        assert_eq!(default_format(false, false, Disguise::Bmp), "{s}.bmp");
    }

    #[test]
    fn validation_matches_the_rules() {
        // 默认模版永远自洽
        for encrypted in [false, true] {
            for volume in [false, true] {
                for disguise in [Disguise::None, Disguise::Bmp] {
                    let format = default_format(encrypted, volume, disguise);
                    validate_format(&format, encrypted, volume)
                        .unwrap_or_else(|e| panic!("{format} ({encrypted},{volume}): {e}"));
                }
            }
        }
        // {e}：加密必填、未加密禁用
        assert!(
            validate_format("{s}_{i}.bin", true, true)
                .unwrap_err()
                .contains("{e}")
        );
        assert!(
            validate_format("{e}", false, false)
                .unwrap_err()
                .contains("只在启用加密")
        );
        // {i}：未加密分卷必填、未分卷禁用
        assert!(
            validate_format("{s}.bin", false, true)
                .unwrap_err()
                .contains("分卷序号")
        );
        assert!(
            validate_format("{e}", true, true).is_ok(),
            "加密时 {{i}} 可省"
        );
        assert!(
            validate_format("{e}_{i}", true, true).is_ok(),
            "加密时也可带 {{i}}"
        );
        assert!(
            validate_format("{s}_{i}", false, false)
                .unwrap_err()
                .contains("只在启用分卷")
        );
        // 其它拦截
        assert!(validate_format("  ", false, false).is_err());
        assert!(
            validate_format("{q}{s}", false, false)
                .unwrap_err()
                .contains("无法识别")
        );
        assert!(
            validate_format("../{s}", false, false)
                .unwrap_err()
                .contains("非法路径")
        );
        assert!(
            validate_format("a/{s}", false, false)
                .unwrap_err()
                .contains("非法路径")
        );
    }

    /// `{n}` 是不含扩展名的主名，`{x}` 是扩展名 —— 两者与 `{s}` 各取所需。
    #[test]
    fn stem_and_extension_split_the_source_name() {
        let pw = [4u8; 16];
        let render_one = |format: &str, source: &str| leaf_names(format, source, &pw, 1)[0].clone();

        assert_eq!(render_one("{s}", "电影.mkv"), "电影.mkv");
        assert_eq!(render_one("{n}", "电影.mkv"), "电影");
        assert_eq!(render_one("{x}", "电影.mkv"), "mkv");
        // 主名 + 序号 + 原扩展名：分卷后仍是一个 .mkv
        assert_eq!(
            leaf_names("{n}.{i}.{x}", "电影.mkv", &pw, 2),
            ["电影.01.mkv", "电影.02.mkv"]
        );
        // 多重扩展名只切最后一段
        assert_eq!(render_one("{n}", "备份.tar.gz"), "备份.tar");
        assert_eq!(render_one("{x}", "备份.tar.gz"), "gz");
        // 没有扩展名：{n} 即全名，{x} 为空
        assert_eq!(render_one("{n}_{x}", "README"), "README_");
        // 前导点是隐藏文件的一部分，不是扩展名分隔符
        assert_eq!(render_one("{n}", ".gitignore"), ".gitignore");
        assert_eq!(render_one("{n}|{x}", ".gitignore"), ".gitignore|");

        // 新占位符同样能按模版反查回来
        let names = leaf_names("{n}_{i}.{x}", "电影.mkv", &pw, 3);
        let listed = entries(
            &names
                .iter()
                .map(|name| (name.as_str(), 100u64))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            resolve_leaves("{n}_{i}.{x}", "电影.mkv", &pw, &listed)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            names
        );
    }

    /// 只有 `{x}` 的模版遇上没有扩展名的文件会展开成空名字 —— 建源时就拦下。
    #[test]
    fn a_format_that_can_render_empty_is_rejected() {
        assert!(
            validate_format("{x}", false, false)
                .unwrap_err()
                .contains("空名字")
        );
        // 带上别的占位符或固定文字就没问题
        assert!(validate_format("{n}.{x}", false, false).is_ok());
        assert!(validate_format("vol.{x}", false, false).is_ok());
    }

    #[test]
    fn generated_names_round_trip_through_resolve() {
        let pw = [7u8; 16];
        for format in [
            "{e}",
            "{e}.bmp",
            "{s}_{i}.bin",
            "{s}_{i}.bin.bmp",
            "{s}",
            "{s}.bmp",
            "{e}_{i}.dat",
        ] {
            let count = if format.contains(ENVELOPE) || format.contains(INDEX) {
                3
            } else {
                1
            };
            let names = leaf_names(format, "片子.mkv", &pw, count);
            assert_eq!(names.len(), count, "{format}");
            let listed = entries(
                &names
                    .iter()
                    .map(|name| (name.as_str(), 100u64))
                    .collect::<Vec<_>>(),
            );
            let resolved = resolve_leaves(format, "片子.mkv", &pw, &listed);
            assert_eq!(
                resolved.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                names,
                "{format} 应按卷序还原"
            );
        }
    }

    /// `{i}` 的宽度随卷数变化，反解要能自己探出来。
    #[test]
    fn index_width_is_recovered_for_any_volume_count() {
        let pw = [3u8; 16];
        for count in [1usize, 9, 10, 99, 100, 101, 1000] {
            let names = leaf_names("{s}_{i}.bin", "a", &pw, count);
            assert_eq!(names[0], format!("a_{:0w$}.bin", 1, w = index_width(count)));
            let listed = entries(
                &names
                    .iter()
                    .map(|name| (name.as_str(), 1u64))
                    .collect::<Vec<_>>(),
            );
            let resolved = resolve_leaves("{s}_{i}.bin", "a", &pw, &listed);
            assert_eq!(resolved.len(), count, "count={count}");
        }
    }

    /// 手动塞进信封目录的东西一概静默忽略：不匹配模版的名字、子目录、
    /// 以及别的文件密钥派生的卷名。
    #[test]
    fn intruders_are_silently_ignored() {
        let pw = [1u8; 16];
        let names = leaf_names("{e}", "a.mkv", &pw, 3);
        let mut listed = entries(
            &names
                .iter()
                .map(|name| (name.as_str(), 100u64))
                .collect::<Vec<_>>(),
        );
        listed.extend(entries(&[
            ("readme.txt", 10),
            ("AB", 10),
            ("我的备注.docx", 10),
            // 另一个文件密钥派生的卷名：十六进制、形状完全合法，但不属于本文件
            (leaf_names("{e}", "a.mkv", &[2u8; 16], 1)[0].as_str(), 10),
        ]));
        listed.push(crate::adapters::Entry {
            id: None,
            name: "子目录".into(),
            is_dir: true,
            size: 0,
            mtime: 0,
        });
        let resolved = resolve_leaves("{e}", "a.mkv", &pw, &listed);
        assert_eq!(
            resolved.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            names,
            "只认自己的卷"
        );
    }

    /// 中间缺卷就在缺口处停下，让调用方用信封里的明文大小发现少了东西。
    #[test]
    fn a_missing_volume_truncates_instead_of_skipping() {
        let pw = [9u8; 16];
        let names = leaf_names("{s}_{i}.bin", "a", &pw, 4);
        let listed = entries(&[
            (names[0].as_str(), 100),
            (names[1].as_str(), 100),
            // 少了第 3 卷
            (names[3].as_str(), 100),
        ]);
        let resolved = resolve_leaves("{s}_{i}.bin", "a", &pw, &listed);
        assert_eq!(resolved.len(), 2, "在缺口处停下，不跳过");
    }

    /// 没有 `{e}` 也没有 `{i}` 的模版只能表达一个叶子 —— 反解不能死循环。
    #[test]
    fn a_constant_format_yields_at_most_one_leaf() {
        let pw = [5u8; 16];
        let listed = entries(&[("a.mkv", 100)]);
        assert_eq!(resolve_leaves("{s}", "a.mkv", &pw, &listed).len(), 1);
        let listed = entries(&[("固定名", 100)]);
        assert_eq!(resolve_leaves("固定名", "a.mkv", &pw, &listed).len(), 1);
    }
}
