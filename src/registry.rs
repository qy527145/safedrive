use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

/// 数据源记录。`config` 由类型决定（localfs / webdav / baidupan）。
/// `strategy_id` 是客户端密码本中映射策略的不透明指针，服务端不知晓其内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSource {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ds_type: String,
    pub config: serde_json::Value,
    pub strategy_id: String,
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    datasources: Vec<DataSource>,
}

/// 数据源注册表，落盘为 data_dir/datasources.json（原子写）。
pub struct Registry {
    path: PathBuf,
    inner: Mutex<Vec<DataSource>>,
}

impl Registry {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let list = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<RegistryFile>(&bytes)?.datasources,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            inner: Mutex::new(list),
        })
    }

    pub fn list(&self) -> Vec<DataSource> {
        self.inner.lock().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<DataSource> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|d| d.id == id)
            .cloned()
    }

    pub fn create(&self, ds: DataSource) -> ApiResult<DataSource> {
        let mut guard = self.inner.lock().unwrap();
        guard.push(ds.clone());
        self.save(&guard)?;
        Ok(ds)
    }

    pub fn update(&self, id: &str, ds: DataSource) -> ApiResult<DataSource> {
        let mut guard = self.inner.lock().unwrap();
        let slot = guard
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
        *slot = DataSource {
            id: id.to_string(),
            ..ds
        };
        let saved = slot.clone();
        self.save(&guard)?;
        Ok(saved)
    }

    /// 百度开放平台刷新令牌后原子更新凭证，避免服务重启后退回已经轮换的 refresh token。
    pub fn update_baidu_tokens(
        &self,
        id: &str,
        access_token: &str,
        refresh_token: &str,
    ) -> ApiResult<()> {
        let mut guard = self.inner.lock().unwrap();
        let datasource = guard
            .iter_mut()
            .find(|datasource| datasource.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
        if datasource.ds_type != "baidupan" {
            return Err(ApiError::BadRequest("数据源不是百度网盘".into()));
        }
        let config = datasource
            .config
            .as_object_mut()
            .ok_or_else(|| ApiError::BadRequest("百度网盘配置不是对象".into()))?;
        config.insert("accessToken".into(), access_token.into());
        config.insert("refreshToken".into(), refresh_token.into());
        self.save(&guard)
    }

    pub fn remove(&self, id: &str) -> ApiResult<()> {
        let mut guard = self.inner.lock().unwrap();
        let before = guard.len();
        guard.retain(|d| d.id != id);
        if guard.len() == before {
            return Err(ApiError::NotFound(format!("数据源不存在: {id}")));
        }
        self.save(&guard)?;
        Ok(())
    }

    /// 原子写：临时文件 + rename；权限 0600（配置内含 WebDAV 凭证）。
    fn save(&self, list: &[DataSource]) -> ApiResult<()> {
        let file = RegistryFile {
            version: 1,
            datasources: list.to_vec(),
        };
        let data = serde_json::to_vec_pretty(&file).map_err(|e| anyhow::anyhow!(e))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ds(id: &str) -> DataSource {
        DataSource {
            id: id.into(),
            name: format!("ds-{id}"),
            ds_type: "localfs".into(),
            config: serde_json::json!({"root": "/tmp/x"}),
            strategy_id: "s1".into(),
            created_at: 1,
        }
    }

    #[test]
    fn crud_roundtrip_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let reg = Registry::load(path.clone()).unwrap();
        reg.create(ds("a")).unwrap();
        reg.create(ds("b")).unwrap();
        reg.update(
            "a",
            DataSource {
                name: "renamed".into(),
                ..ds("a")
            },
        )
        .unwrap();
        reg.remove("b").unwrap();
        assert!(reg.remove("b").is_err());

        // 重新加载验证持久化
        let reg2 = Registry::load(path).unwrap();
        let list = reg2.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "renamed");
        assert_eq!(reg2.get("a").unwrap().id, "a");
    }

    #[test]
    fn refreshed_baidu_tokens_are_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("baidu");
        source.ds_type = "baidupan".into();
        source.config = serde_json::json!({
            "accessToken": "old-access",
            "refreshToken": "old-refresh"
        });
        registry.create(source).unwrap();
        registry
            .update_baidu_tokens("baidu", "new-access", "new-refresh")
            .unwrap();

        let reloaded = Registry::load(path).unwrap();
        let config = reloaded.get("baidu").unwrap().config;
        assert_eq!(config["accessToken"], "new-access");
        assert_eq!(config["refreshToken"], "new-refresh");
    }
}
