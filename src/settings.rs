//! 全局传输设置：下载分片大小 / 总并发 / 单分卷并发。
//! 与策略解耦 —— 这些是服务器资源参数，不随数据映射方式变化。

use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

pub const MIN_SPLIT: u64 = 64 * 1024;

/// 解析人类可读的大小字符串（参考 hydraria parse_size）：
/// "300M"、"1.5GB"、"512K"、"64KB"、纯数字（字节）。
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("大小不能为空".to_string());
    }
    let (num_part, unit) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map(|i| (&s[..i], &s[i..]))
        .unwrap_or((s, ""));
    let num: f64 = num_part
        .trim()
        .parse()
        .map_err(|_| format!("无法解析数字: {num_part}"))?;
    if num < 0.0 {
        return Err("大小不能为负".to_string());
    }
    let mult: f64 = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("未知单位: {other}（支持 K/KB/M/MB/G/GB）")),
    };
    Ok((num * mult) as u64)
}

/// serde 辅助：数字或 "300M" 字符串均可。
pub fn de_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use serde::de::Error;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| Error::custom("非法数字")),
        serde_json::Value::String(s) => parse_size(&s).map_err(Error::custom),
        _ => Err(Error::custom("大小需为数字或字符串（如 300M）")),
    }
}

/// serde 辅助：可空版本（null → None）。
pub fn de_opt_size<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use serde::de::Error;
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => {
            n.as_u64().map(Some).ok_or_else(|| Error::custom("非法数字"))
        }
        serde_json::Value::String(s) => parse_size(&s).map(Some).map_err(Error::custom),
        _ => Err(Error::custom("大小需为数字、字符串（如 300M）或 null")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// 最大分片大小（字节）：下载时单线程一次拉取的上限 —— 有些云盘
    /// 下载 API 限制单请求最大字节数（hydraria max_split）。可传 "5M" 字符串。
    #[serde(deserialize_with = "de_size")]
    pub max_split: u64,
    /// 下载总并发线程数（hydraria max_threads）。
    pub max_threads: usize,
    /// 单个分卷内的最大并发（hydraria max_per_volume）。
    pub max_per_volume: usize,
    /// 是否启用所有数据源共享的持久密文块缓存。
    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,
}

fn default_cache_enabled() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_split: 5 * 1024 * 1024,
            max_threads: 16,
            max_per_volume: 4,
            cache_enabled: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> ApiResult<()> {
        if self.max_split < MIN_SPLIT {
            return Err(ApiError::BadRequest("下载分片大小至少 64KiB".into()));
        }
        if self.max_threads == 0 || self.max_threads > 128 {
            return Err(ApiError::BadRequest("下载线程数需在 1..128".into()));
        }
        if self.max_per_volume == 0 || self.max_per_volume > 64 {
            return Err(ApiError::BadRequest("单分卷线程数需在 1..64".into()));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SettingsFile {
    version: u32,
    settings: Settings,
}

/// 设置存储，落盘 data_dir/settings.json（原子写）。
pub struct SettingsStore {
    path: PathBuf,
    inner: RwLock<Settings>,
}

impl SettingsStore {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let settings = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<SettingsFile>(&bytes)?.settings,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, inner: RwLock::new(settings) })
    }

    pub fn get(&self) -> Settings {
        self.inner.read().unwrap().clone()
    }

    pub fn set(&self, s: Settings) -> ApiResult<Settings> {
        s.validate()?;
        let mut guard = self.inner.write().unwrap();
        *guard = s.clone();
        let file = SettingsFile { version: 1, settings: s.clone() };
        let data = serde_json::to_vec_pretty(&file).map_err(|e| anyhow::anyhow!(e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("300M").unwrap(), 300 * 1024 * 1024);
        assert_eq!(parse_size("300 MB").unwrap(), 300 * 1024 * 1024);
        assert_eq!(parse_size("1.5G").unwrap(), (1.5 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_size("512k").unwrap(), 512 * 1024);
        assert_eq!(parse_size("64KB").unwrap(), 64 * 1024);
        assert_eq!(parse_size("1048576").unwrap(), 1048576);
        assert_eq!(parse_size("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("5T").is_err(), "未支持单位明确报错");
        assert!(parse_size("-5M").is_err());
    }

    #[test]
    fn settings_accepts_string_sizes() {
        let s: Settings = serde_json::from_str(
            r#"{"maxSplit":"5M","maxThreads":16,"maxPerVolume":4}"#,
        )
        .unwrap();
        assert_eq!(s.max_split, 5 * 1024 * 1024);
        assert!(s.cache_enabled, "旧配置缺省时缓存默认开启");
    }

    #[test]
    fn defaults_persist_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let st = SettingsStore::load(path.clone()).unwrap();
        assert_eq!(st.get().max_threads, 16, "默认值");

        let mut s = st.get();
        s.max_threads = 32;
        st.set(s).unwrap();
        let st2 = SettingsStore::load(path).unwrap();
        assert_eq!(st2.get().max_threads, 32, "落盘生效");

        let mut bad = st2.get();
        bad.max_split = 1024;
        assert!(st2.set(bad).is_err());
        assert_eq!(st2.get().max_split, 5 * 1024 * 1024, "非法值不落地");
    }
}
