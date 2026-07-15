use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::adapters::{self, Storage};
use crate::error::{ApiError, ApiResult};
use crate::registry::Registry;
use crate::settings::SettingsStore;
use crate::vault::PathCache;

/// 全局应用状态。加解密全部在服务端完成（信任模型：服务器可信、云存储不可信）。
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub registry: Registry,
    /// 全局传输设置（下载分片/并发）。
    pub settings: SettingsStore,
    /// 纯内存路径缓存（云端为准）。根密钥由数据源根密码派生。
    pub cache: PathCache,
    /// 全数据源共享的持久密文块缓存。
    pub content_cache: Arc<crate::cache::CacheStore>,
    pub transfers: Arc<crate::transfer::TransferTracker>,
    /// 登录会话 token（内存态，重启后失效）。
    pub sessions: RwLock<HashSet<String>>,
    /// 正在上传中的 "dsId:明文路径"（内存态）——同路径并发上传串行化。
    pub uploading: Mutex<HashSet<String>>,
    /// 进行中上传的双维度进度（key = 前端生成的进度 ID，上传结束即移除）。
    pub upload_progress: Mutex<HashMap<String, Arc<crate::engine::UploadProgress>>>,
    /// 每数据源一把目录创建锁：ensure_dir 的「云端判存 + mkdir」必须
    /// 互斥，否则并发上传同一文件夹会各建一个同名加密目录。
    pub mkdir_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub admin_password: Option<String>,
    pub http: reqwest::Client,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(data_dir: PathBuf, admin_password: Option<String>) -> anyhow::Result<Self> {
        let registry = Registry::load(data_dir.join("datasources.json"))?;
        let settings = SettingsStore::load(data_dir.join("settings.json"))?;
        let content_cache = Arc::new(crate::cache::CacheStore::new(data_dir.join("cache"))?);
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self(Arc::new(Inner {
            registry,
            settings,
            cache: PathCache::default(),
            content_cache,
            transfers: Arc::new(crate::transfer::TransferTracker::default()),
            sessions: RwLock::new(HashSet::new()),
            uploading: Mutex::new(HashSet::new()),
            upload_progress: Mutex::new(HashMap::new()),
            mkdir_locks: Mutex::new(HashMap::new()),
            admin_password,
            http,
        })))
    }

    /// 按数据源 ID 实例化存储适配器。
    pub fn adapter(&self, ds_id: &str) -> ApiResult<Box<dyn Storage>> {
        let ds = self
            .registry
            .get(ds_id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {ds_id}")))?;
        adapters::make_with_token_persister(&ds, self.http.clone(), self.baidu_token_persister(&ds))
    }

    /// `Arc` 版本（下载/上传引擎多任务共享）。
    pub fn adapter_arc(&self, ds_id: &str) -> ApiResult<Arc<dyn Storage>> {
        let ds = self
            .registry
            .get(ds_id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {ds_id}")))?;
        adapters::make_arc_with_token_persister(
            &ds,
            self.http.clone(),
            self.baidu_token_persister(&ds),
        )
    }

    fn baidu_token_persister(
        &self,
        datasource: &crate::registry::DataSource,
    ) -> Option<crate::adapters::baidupan::TokenPersister> {
        if datasource.ds_type != "baidupan" {
            return None;
        }
        let state = self.clone();
        let id = datasource.id.clone();
        Some(Arc::new(
            move |access_token, refresh_token, access_expires_at| {
                state.registry.update_baidu_tokens(
                    &id,
                    access_token,
                    refresh_token,
                    access_expires_at,
                )
            },
        ))
    }

    /// 数据源级目录创建锁（惰性创建）。
    pub fn mkdir_lock(&self, ds: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.mkdir_locks.lock().unwrap();
        Arc::clone(locks.entry(ds.to_string()).or_default())
    }

    /// 数据源的信封链根密钥。
    pub fn root_key_of(&self, ds_id: &str) -> ApiResult<[u8; crate::crypto::SECRET_LEN]> {
        let ds = self.datasource(ds_id)?;
        if !ds.encryption_enabled {
            return Err(ApiError::BadRequest("该数据源未启用加密".into()));
        }
        Ok(crate::crypto::derive_root_key(ds.password.as_bytes()))
    }

    /// 根密钥候选（主密钥 + 换密码过渡期的旧密钥，读路径回退用）。
    pub fn root_key_candidates_of(
        &self,
        ds_id: &str,
    ) -> ApiResult<Vec<[u8; crate::crypto::SECRET_LEN]>> {
        let ds = self.datasource(ds_id)?;
        if !ds.encryption_enabled {
            return Err(ApiError::BadRequest("该数据源未启用加密".into()));
        }
        let mut keys = vec![crate::crypto::derive_root_key(ds.password.as_bytes())];
        if let Some(prev) = ds.prev_password {
            keys.push(crate::crypto::derive_root_key(prev.as_bytes()));
        }
        Ok(keys)
    }

    pub fn datasource(&self, ds_id: &str) -> ApiResult<crate::registry::DataSource> {
        self.registry
            .get(ds_id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {ds_id}")))
    }
}
