use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::adapters::{self, Storage};
use crate::error::{ApiError, ApiResult};
use crate::registry::Registry;
use crate::settings::SettingsStore;
use crate::strategies::Strategies;
use crate::vault::PathCache;

/// 全局应用状态。加解密全部在服务端完成（信任模型：服务器可信、云存储不可信）。
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub registry: Registry,
    pub strategies: Strategies,
    /// 全局传输设置（下载分片/并发）。
    pub settings: SettingsStore,
    /// 纯内存路径缓存（云端为准）。根密钥由策略根密码派生，无本地密钥文件。
    pub cache: PathCache,
    /// 全数据源共享的持久密文块缓存。
    pub content_cache: Arc<crate::cache::CacheStore>,
    /// 登录会话 token（内存态，重启后失效）。
    pub sessions: RwLock<HashSet<String>>,
    /// 正在上传中的 "dsId:明文路径"（内存态）——同路径并发上传串行化。
    pub uploading: Mutex<HashSet<String>>,
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
        let strategies = Strategies::load(data_dir.join("strategies.json"))?;
        let settings = SettingsStore::load(data_dir.join("settings.json"))?;
        let content_cache = Arc::new(crate::cache::CacheStore::new(data_dir.join("cache"))?);
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self(Arc::new(Inner {
            registry,
            strategies,
            settings,
            cache: PathCache::default(),
            content_cache,
            sessions: RwLock::new(HashSet::new()),
            uploading: Mutex::new(HashSet::new()),
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
        Some(Arc::new(move |access_token, refresh_token| {
            state
                .registry
                .update_baidu_tokens(&id, access_token, refresh_token)
        }))
    }

    /// 数据源级目录创建锁（惰性创建）。
    pub fn mkdir_lock(&self, ds: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.mkdir_locks.lock().unwrap();
        Arc::clone(locks.entry(ds.to_string()).or_default())
    }

    /// 数据源的信封链根密钥（由其绑定策略的根密码派生）。
    pub fn root_key_of(&self, ds_id: &str) -> ApiResult<[u8; crate::crypto::SECRET_LEN]> {
        Ok(self.strategy_of(ds_id)?.root_key())
    }

    /// 根密钥候选（主密钥 + 换密码过渡期的旧密钥，读路径回退用）。
    pub fn root_key_candidates_of(
        &self,
        ds_id: &str,
    ) -> ApiResult<Vec<[u8; crate::crypto::SECRET_LEN]>> {
        Ok(self.strategy_of(ds_id)?.root_key_candidates())
    }

    /// 数据源绑定的策略（缺失时报错）。
    pub fn strategy_of(&self, ds_id: &str) -> ApiResult<crate::strategies::Strategy> {
        let ds = self
            .registry
            .get(ds_id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {ds_id}")))?;
        self.strategies
            .get(&ds.strategy_id)
            .ok_or_else(|| ApiError::BadRequest("数据源绑定的策略已不存在".into()))
    }
}
