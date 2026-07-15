//! 数据映射策略 = 根密码 + 分卷大小。
//!
//! 根密码是该策略下所有数据源的信封链入口（FK_root 由它派生）——
//! 多个数据源共享同一策略即共享同一根密码，无需独立的 roots.json。
//! **strategies.json 因此是唯一需要备份的秘密文件。**
//! 传输参数（下载分片/并发）是全局设置（settings.rs）。

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

pub const MIN_VOLUME_SIZE: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Strategy {
    pub id: String,
    pub name: String,
    /// 上传分卷大小（字节）。None = 不分卷，整个文件一个分卷。
    pub volume_size: Option<u64>,
    /// 根密码：该策略下所有数据源的信封链入口。丢失 = 数据永久不可解。
    /// （旧文件缺失时 load() 会补生成并落盘。）
    #[serde(default)]
    pub password: String,
    /// 换密码过渡期保留的旧密码：根层信封重命名是逐条的，中断/失败后
    /// 旧信封仍可用它解开（读路径回退），重试完成迁移后清除。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_password: Option<String>,
    pub created_at: u64,
}

impl Strategy {
    /// 校验参考 hydraria（只设下限，不设武断的上限）。
    pub fn validate(&self) -> ApiResult<()> {
        if self.name.trim().is_empty() {
            return Err(ApiError::BadRequest("策略名称不能为空".into()));
        }
        if let Some(v) = self.volume_size
            && v < MIN_VOLUME_SIZE
        {
            return Err(ApiError::BadRequest("分卷大小至少 64KiB".into()));
        }
        if self.password.trim().is_empty() {
            return Err(ApiError::BadRequest("根密码不能为空".into()));
        }
        Ok(())
    }

    /// 由根密码派生信封链根密钥 FK_root。
    pub fn root_key(&self) -> [u8; crate::crypto::SECRET_LEN] {
        crate::crypto::derive_root_key(self.password.as_bytes())
    }

    /// 根密钥候选列表：主密钥在前，过渡期旧密钥在后（读路径回退用）。
    pub fn root_key_candidates(&self) -> Vec<[u8; crate::crypto::SECRET_LEN]> {
        let mut keys = vec![self.root_key()];
        if let Some(prev) = &self.prev_password {
            keys.push(crate::crypto::derive_root_key(prev.as_bytes()));
        }
        keys
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StrategiesFile {
    version: u32,
    strategies: Vec<Strategy>,
}

/// 策略存储，落盘 data_dir/strategies.json（原子写）。
pub struct Strategies {
    path: PathBuf,
    inner: Mutex<Vec<Strategy>>,
}

impl Strategies {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let mut list = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<StrategiesFile>(&bytes)?.strategies,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        // 归一化：旧文件补生成根密码；同时重写文件抹掉历史残留字段
        let needs_rewrite = !list.is_empty();
        for s in &mut list {
            if s.password.trim().is_empty() {
                s.password = gen_share_password();
            }
        }
        let store = Self { path, inner: Mutex::new(list) };
        if needs_rewrite {
            let guard = store.inner.lock().unwrap();
            store.save(&guard)?;
        }
        Ok(store)
    }

    pub fn list(&self) -> Vec<Strategy> {
        self.inner.lock().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<Strategy> {
        self.inner.lock().unwrap().iter().find(|s| s.id == id).cloned()
    }

    pub fn create(&self, s: Strategy) -> ApiResult<Strategy> {
        s.validate()?;
        let mut guard = self.inner.lock().unwrap();
        guard.push(s.clone());
        self.save(&guard)?;
        Ok(s)
    }

    pub fn update(&self, id: &str, s: Strategy) -> ApiResult<Strategy> {
        s.validate()?;
        let mut guard = self.inner.lock().unwrap();
        let slot = guard
            .iter_mut()
            .find(|x| x.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("策略不存在: {id}")))?;
        *slot = Strategy { id: id.to_string(), created_at: slot.created_at, ..s };
        let saved = slot.clone();
        self.save(&guard)?;
        Ok(saved)
    }

    pub fn remove(&self, id: &str) -> ApiResult<()> {
        let mut guard = self.inner.lock().unwrap();
        let before = guard.len();
        guard.retain(|s| s.id != id);
        if guard.len() == before {
            return Err(ApiError::NotFound(format!("策略不存在: {id}")));
        }
        self.save(&guard)?;
        Ok(())
    }

    /// 导出为 JSON 字节（即落盘格式；含根密码，务必妥善保管）。
    pub fn export_json(&self) -> ApiResult<Vec<u8>> {
        let guard = self.inner.lock().unwrap();
        let file = StrategiesFile { version: 2, strategies: guard.to_vec() };
        serde_json::to_vec_pretty(&file).map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))
    }

    /// 导入合并：按 id 并集，**本地优先**（覆盖会让本地数据失锁）。返回新增数。
    pub fn import_merge(&self, data: &[u8]) -> ApiResult<usize> {
        let file: StrategiesFile = serde_json::from_slice(data)
            .map_err(|e| ApiError::BadRequest(format!("策略备份格式无效: {e}")))?;
        let mut guard = self.inner.lock().unwrap();
        let mut added = 0;
        for s in file.strategies {
            if guard.iter().any(|x| x.id == s.id) || s.validate().is_err() {
                continue;
            }
            guard.push(s);
            added += 1;
        }
        if added > 0 {
            self.save(&guard)?;
        }
        Ok(added)
    }

    fn save(&self, list: &[Strategy]) -> ApiResult<()> {
        let file = StrategiesFile { version: 2, strategies: list.to_vec() };
        let data = serde_json::to_vec_pretty(&file).map_err(|e| anyhow::anyhow!(e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// 生成一个可读的随机根密码（base64，24 字符 ≈ 144-bit）。
pub fn gen_share_password() -> String {
    use base64::Engine;
    let mut raw = [0u8; 18];
    getrandom::fill(&mut raw).expect("系统随机数不可用");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn default_strategy(name: &str) -> Strategy {
    Strategy {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        volume_size: Some(300 * 1024 * 1024),
        password: gen_share_password(),
        prev_password: None,
        created_at: crate::registry::now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crud_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strategies.json");
        let st = Strategies::load(path.clone()).unwrap();

        let s = default_strategy("默认");
        st.create(s.clone()).unwrap();
        assert!(st.get(&s.id).is_some());

        let mut bad = default_strategy("x");
        bad.volume_size = Some(1024); // < 64K
        assert!(st.create(bad).is_err());
        let mut nopw = default_strategy("y");
        nopw.password = "  ".into();
        assert!(st.create(nopw).is_err());

        let mut upd = s.clone();
        upd.volume_size = None; // 不分卷合法
        st.update(&s.id, upd).unwrap();

        let st2 = Strategies::load(path).unwrap();
        assert_eq!(st2.get(&s.id).unwrap().volume_size, None);
        assert_eq!(st2.get(&s.id).unwrap().password, s.password, "重载后密码不变");
        assert_eq!(st2.get(&s.id).unwrap().root_key(), s.root_key());
        st2.remove(&s.id).unwrap();
        assert!(st2.remove(&s.id).is_err());
    }
}
