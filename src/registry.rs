use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

/// 数据源记录。`config` 由类型决定（localfs / webdav / baidupan / aliyundrive / quark）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSource {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ds_type: String,
    pub config: serde_json::Value,
    /// 加密模式只能在创建时决定；更新接口会拒绝翻转该值。
    #[serde(default = "default_encryption_enabled")]
    pub encryption_enabled: bool,
    /// 数据源自己的根密码。未加密数据源为空字符串。
    #[serde(default)]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_password: Option<String>,
    #[serde(default = "default_volume_enabled")]
    pub volume_enabled: bool,
    #[serde(default = "default_volume_size")]
    pub volume_size: u64,
    #[serde(default = "default_volume_strategy")]
    pub volume_strategy: String,
    /// 存储端**叶子对象**的名字模版（仅受管数据源有意义）。支持 `{s}` 原始
    /// 文件名、`{e}` 文件密钥派生的可逆索引凭据、`{i}` 等宽序号，详见
    /// [`crate::naming`]。与三个开关一样在创建后不可更改 —— 读取靠按模版生成
    /// 候选名再查表，改了模版已写下去的叶子就再也认不出来。
    #[serde(default = "default_leaf_name_format", alias = "volumeNameFormat")]
    pub leaf_name_format: String,
    /// 存储侧文件伪装。与加密、分卷并列的第三个开关，同样只能在创建时决定
    /// （它改变落地字节，翻转会让已有对象读不回来）。
    #[serde(default)]
    pub disguise_enabled: bool,
    #[serde(default = "default_disguise_algorithm")]
    pub disguise_algorithm: String,
    /// 数据源级缓存开关；还会受全局缓存总开关约束。
    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,
    pub created_at: u64,
}

impl DataSource {
    /// 是否走「受管信封」链路：一个文件在存储端是一个**信封目录**，目录名由
    /// 根密码派生的密钥链加密，装着明文文件名、明文大小和该文件自己的密钥；
    /// 目录里是按模版命名的若干叶子对象。
    ///
    /// 加密、分卷、伪装任一开启即受管，理由各不相同但都刚性：
    /// - **加密**要藏起文件名与密钥；
    /// - **伪装**改变了落地字节，读回来前必须先确认「这个对象确实是 SafeDrive
    ///   写的」，否则外部上传的普通文件、乃至一张真的 BMP，都会被砍掉头部；
    /// - **分卷**要把若干卷收在一处，并记住合起来的明文大小。
    ///
    /// 于是判据统一成一句话：**解得开信封就是受管对象**（该解密解密、该脱伪装
    /// 脱伪装、该合卷合卷），解不开就是外来对象，一个字节都不动。
    pub fn managed(&self) -> bool {
        self.encryption_enabled || self.volume_enabled || self.disguise_enabled
    }
}

pub const DEFAULT_VOLUME_SIZE: u64 = 300 * 1024 * 1024;
pub const MIN_VOLUME_SIZE: u64 = 64 * 1024;
pub fn gen_password() -> String {
    use base64::Engine;
    let mut raw = [0u8; 18];
    getrandom::fill(&mut raw).expect("系统随机数不可用");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}
fn default_encryption_enabled() -> bool {
    true
}
fn default_volume_enabled() -> bool {
    true
}
fn default_volume_size() -> u64 {
    DEFAULT_VOLUME_SIZE
}
fn default_volume_strategy() -> String {
    "random".into()
}
fn default_leaf_name_format() -> String {
    // 注册表里缺这一项的老配置只可能是「未加密 + 分卷」（那时只有这种组合有
    // 模版），回落到当年的默认值 —— 它与现在的默认值不同，所以写死。
    "{s}_{i}.bin".into()
}
fn default_disguise_algorithm() -> String {
    crate::disguise::DEFAULT_ALGORITHM.into()
}
fn default_cache_enabled() -> bool {
    true
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
        let mut ds = ds;
        seed_rotating_secrets(&mut ds);
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
        let mut replacement = DataSource {
            id: id.to_string(),
            ..ds
        };
        preserve_live_credentials(slot, &mut replacement);
        seed_rotating_secrets(&mut replacement);
        *slot = replacement;
        let saved = slot.clone();
        self.save(&guard)?;
        Ok(saved)
    }

    /// 切换阿里云盘盘位：写入新的 `driveType` 并丢弃缓存的 `driveId`
    /// （否则会继续读写上一个盘）。返回更新后的数据源。
    pub fn set_drive_type(&self, id: &str, drive_type: &str) -> ApiResult<DataSource> {
        let mut guard = self.inner.lock().unwrap();
        let datasource = guard
            .iter_mut()
            .find(|datasource| datasource.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
        if datasource.ds_type != "aliyundrive" {
            return Err(ApiError::BadRequest("只有阿里云盘支持切换盘位".into()));
        }
        let config = datasource
            .config
            .as_object_mut()
            .ok_or_else(|| ApiError::BadRequest("数据源配置不是对象".into()))?;
        config.insert("driveType".into(), drive_type.into());
        config.remove("driveId");
        let saved = datasource.clone();
        self.save(&guard)?;
        Ok(saved)
    }

    /// 适配器轮换凭证后原子写回 `config`，避免服务重启退回已作废的旧令牌。
    /// 键即 config 字段名，由适配器自己决定（accessToken / cookie / …）。
    pub fn update_credentials(
        &self,
        id: &str,
        fields: Vec<(String, serde_json::Value)>,
    ) -> ApiResult<()> {
        let mut guard = self.inner.lock().unwrap();
        let datasource = guard
            .iter_mut()
            .find(|datasource| datasource.id == id)
            .ok_or_else(|| ApiError::NotFound(format!("数据源不存在: {id}")))?;
        let config = datasource
            .config
            .as_object_mut()
            .ok_or_else(|| ApiError::BadRequest("数据源配置不是对象".into()))?;
        for (key, value) in fields {
            config.insert(key, value);
        }
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

/// 一组同进退的凭证：
/// - `identity`：改动即代表换账号，本组运行期缓存的令牌必须作废；
/// - `rotating`：既是用户填的初值、又会被后台轮换（阿里云盘 refreshToken、
///   夸克 cookie）。表单回填的可能是轮换后的值，也可能是最初的种子值，
///   两者都算「没改」，因此额外记一份 `<字段>Seed`；
/// - `live`：纯运行期产物，跟随本组 identity 一起保留或丢弃。
struct CredentialGroup {
    identity: &'static [&'static str],
    rotating: &'static [&'static str],
    live: &'static [&'static str],
}

/// 每种数据源的凭证分组。分组是必要的：阿里云盘的开放平台令牌与官网令牌
/// 各自独立轮换，编辑其中一个不能把另一个回退成表单里的旧值。
fn credential_spec(ds_type: &str) -> Option<&'static [CredentialGroup]> {
    match ds_type {
        "baidupan" => Some(&[CredentialGroup {
            identity: &["bduss", "clientId", "clientSecret"],
            rotating: &[],
            live: &["accessToken", "refreshToken", "accessTokenExpiresAt"],
        }]),
        "aliyundrive" => Some(&[
            // 开放平台：日常读写
            CredentialGroup {
                identity: &["app", "clientId", "clientSecret"],
                rotating: &["refreshToken"],
                live: &["accessToken", "accessTokenExpiresAt", "driveId"],
            },
            // 官网（PDS）：仅分享与转存，可以不配
            CredentialGroup {
                identity: &[],
                rotating: &["webRefreshToken"],
                live: &["webAccessToken", "webAccessTokenExpiresAt"],
            },
        ]),
        "quark" => Some(&[CredentialGroup {
            identity: &[],
            rotating: &["cookie"],
            live: &[],
        }]),
        _ => None,
    }
}

fn seed_field(field: &str) -> String {
    format!("{field}Seed")
}

/// 新建/保存时把轮换字段的当前值记为种子，供后续「用户到底改没改」的判定。
fn seed_rotating_secrets(datasource: &mut DataSource) {
    let Some(groups) = credential_spec(&datasource.ds_type) else {
        return;
    };
    let Some(config) = datasource.config.as_object_mut() else {
        return;
    };
    for field in groups.iter().flat_map(|group| group.rotating) {
        let seed = seed_field(field);
        if !config.contains_key(&seed)
            && let Some(value) = config.get(*field).cloned()
        {
            config.insert(seed, value);
        }
    }
}

/// 阿里云盘的盘位（备份盘 / 资源库），缺省视为 default。
fn drive_type_of(config: &serde_json::Value) -> &str {
    config
        .get("driveType")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("default")
}

/// 保存数据源时保住后台已经轮换出来的凭证 —— 设置页可能是在轮换发生
/// 之前打开的，直接回写表单里的旧令牌会把账号打挂。
fn preserve_live_credentials(current: &DataSource, replacement: &mut DataSource) {
    if current.ds_type != replacement.ds_type {
        return;
    }
    let Some(groups) = credential_spec(&current.ds_type) else {
        return;
    };
    // driveId 是由 driveType 查出来的：换了盘就不能留旧 ID，否则会继续
    // 读写上一个盘。删掉即可，适配器下次会重新问一遍并回写。
    let drive_changed = current.ds_type == "aliyundrive"
        && drive_type_of(&current.config) != drive_type_of(&replacement.config);
    // 每组独立判定：动了官网令牌不该影响开放平台那组，反之亦然。
    let verdicts: Vec<bool> = groups
        .iter()
        .map(|group| {
            let same_identity = group
                .identity
                .iter()
                .all(|field| current.config.get(field) == replacement.config.get(field));
            // 轮换字段：等于当前值或等于种子值都说明用户没动过。
            let same_rotating = group.rotating.iter().all(|field| {
                let submitted = replacement.config.get(*field);
                submitted.is_none()
                    || submitted == current.config.get(*field)
                    || submitted == current.config.get(seed_field(field).as_str())
            });
            same_identity && same_rotating
        })
        .collect();
    let Some(target) = replacement.config.as_object_mut() else {
        return;
    };
    for (group, unchanged) in groups.iter().zip(verdicts) {
        if !unchanged {
            // 换账号了：连种子一起重置，别把旧账号的令牌带进来。
            for field in group.rotating {
                let seed = seed_field(field);
                match target.get(*field).cloned() {
                    Some(value) => target.insert(seed, value),
                    None => target.remove(&seed),
                };
            }
            continue;
        }
        for field in group.rotating.iter().chain(group.live.iter()) {
            if let Some(value) = current.config.get(field) {
                target.insert((*field).into(), value.clone());
            }
            let seed = seed_field(field);
            if let Some(value) = current.config.get(seed.as_str()) {
                target.insert(seed, value.clone());
            }
        }
    }
    if drive_changed {
        target.remove("driveId");
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
            encryption_enabled: true,
            password: "test-password".into(),
            prev_password: None,
            volume_enabled: true,
            volume_size: DEFAULT_VOLUME_SIZE,
            volume_strategy: "random".into(),
            leaf_name_format: "{e}".into(),
            disguise_enabled: false,
            disguise_algorithm: default_disguise_algorithm(),
            cache_enabled: true,
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

    fn baidu_tokens(
        access: &str,
        refresh: &str,
        expires_at: u64,
    ) -> Vec<(String, serde_json::Value)> {
        vec![
            ("accessToken".into(), access.into()),
            ("refreshToken".into(), refresh.into()),
            ("accessTokenExpiresAt".into(), expires_at.into()),
        ]
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
            .update_credentials("baidu", baidu_tokens("new-access", "new-refresh", 1234))
            .unwrap();

        let reloaded = Registry::load(path).unwrap();
        let config = reloaded.get("baidu").unwrap().config;
        assert_eq!(config["accessToken"], "new-access");
        assert_eq!(config["refreshToken"], "new-refresh");
        assert_eq!(config["accessTokenExpiresAt"], 1234);
    }

    #[test]
    fn datasource_update_does_not_overwrite_fresh_baidu_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("baidu");
        source.ds_type = "baidupan".into();
        source.config = serde_json::json!({
            "bduss": "same-account",
            "clientId": "same-client",
            "clientSecret": "same-secret",
            "accessToken": "old-access",
            "refreshToken": "old-refresh",
            "accessTokenExpiresAt": 100
        });
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials("baidu", baidu_tokens("new-access", "new-refresh", 1234))
            .unwrap();

        // Simulate a settings form that was opened before the refresh completed.
        source.name = "renamed".into();
        registry.update("baidu", source).unwrap();

        let reloaded = Registry::load(path).unwrap();
        let updated = reloaded.get("baidu").unwrap();
        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.config["accessToken"], "new-access");
        assert_eq!(updated.config["refreshToken"], "new-refresh");
        assert_eq!(updated.config["accessTokenExpiresAt"], 1234);
    }

    /// 阿里云盘的 refreshToken 每次刷新都会轮换：表单提交的是打开设置页
    /// 时的旧值（= 种子值），保存后必须仍然是后台轮换出来的新值。
    #[test]
    fn stale_form_cannot_revert_rotated_aliyun_refresh_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("ali");
        source.ds_type = "aliyundrive".into();
        source.config = serde_json::json!({
            "clientId": "app",
            "clientSecret": "secret",
            "refreshToken": "seed-refresh"
        });
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials(
                "ali",
                vec![
                    ("accessToken".into(), "fresh-access".into()),
                    ("refreshToken".into(), "rotated-refresh".into()),
                ],
            )
            .unwrap();

        source.name = "renamed".into();
        registry.update("ali", source).unwrap();

        let updated = Registry::load(path).unwrap().get("ali").unwrap();
        assert_eq!(updated.config["refreshToken"], "rotated-refresh");
        assert_eq!(updated.config["accessToken"], "fresh-access");
    }

    /// 但用户真的粘贴了一个新的 refreshToken（换账号）时，旧账号的
    /// access token 必须被丢掉。
    #[test]
    fn new_aliyun_refresh_token_discards_old_access_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("ali");
        source.ds_type = "aliyundrive".into();
        source.config = serde_json::json!({
            "clientId": "app",
            "clientSecret": "secret",
            "refreshToken": "seed-refresh"
        });
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials(
                "ali",
                vec![
                    ("accessToken".into(), "fresh-access".into()),
                    ("refreshToken".into(), "rotated-refresh".into()),
                ],
            )
            .unwrap();

        source.config = serde_json::json!({
            "clientId": "app",
            "clientSecret": "secret",
            "refreshToken": "another-account"
        });
        registry.update("ali", source).unwrap();

        let updated = Registry::load(path).unwrap().get("ali").unwrap();
        assert_eq!(updated.config["refreshToken"], "another-account");
        assert_eq!(updated.config["refreshTokenSeed"], "another-account");
        assert!(updated.config.get("accessToken").is_none());
    }

    /// 阿里云盘的开放平台令牌与官网令牌各自独立：只改其中一个，另一个
    /// 后台轮换出来的值必须原样留住。
    #[test]
    fn aliyun_web_and_open_tokens_rotate_independently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("ali");
        source.ds_type = "aliyundrive".into();
        source.config = serde_json::json!({
            "app": "tv",
            "refreshToken": "seed-refresh",
            "webRefreshToken": "seed-web",
        });
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials(
                "ali",
                vec![
                    ("accessToken".into(), "fresh-access".into()),
                    ("refreshToken".into(), "rotated-refresh".into()),
                    ("webAccessToken".into(), "fresh-web-access".into()),
                    ("webRefreshToken".into(), "rotated-web".into()),
                ],
            )
            .unwrap();

        // 用户只换了官网令牌（表单里的开放平台令牌还是最初的种子值）
        source.config = serde_json::json!({
            "app": "tv",
            "refreshToken": "seed-refresh",
            "webRefreshToken": "pasted-new-web",
        });
        registry.update("ali", source.clone()).unwrap();
        let updated = Registry::load(path.clone()).unwrap().get("ali").unwrap();
        assert_eq!(updated.config["refreshToken"], "rotated-refresh");
        assert_eq!(updated.config["accessToken"], "fresh-access");
        assert_eq!(updated.config["webRefreshToken"], "pasted-new-web");
        assert_eq!(updated.config["webRefreshTokenSeed"], "pasted-new-web");
        assert!(updated.config.get("webAccessToken").is_none());

        // 反向：只换开放平台令牌，官网那组照旧
        registry
            .update_credentials(
                "ali",
                vec![("webAccessToken".into(), "web-access-2".into())],
            )
            .unwrap();
        source.config = serde_json::json!({
            "app": "tv",
            "refreshToken": "pasted-new-open",
            "webRefreshToken": "pasted-new-web",
        });
        registry.update("ali", source).unwrap();
        let updated = Registry::load(path).unwrap().get("ali").unwrap();
        assert_eq!(updated.config["refreshToken"], "pasted-new-open");
        assert!(updated.config.get("accessToken").is_none());
        assert_eq!(updated.config["webAccessToken"], "web-access-2");
        assert_eq!(updated.config["webRefreshToken"], "pasted-new-web");
    }

    /// 夸克的 __puus 每次请求都可能轮换，同样不能被设置页回写覆盖。
    #[test]
    fn stale_form_cannot_revert_rotated_quark_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("quark");
        source.ds_type = "quark".into();
        source.config = serde_json::json!({"cookie": "__puus=old"});
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials("quark", vec![("cookie".into(), "__puus=new".into())])
            .unwrap();

        source.name = "renamed".into();
        registry.update("quark", source).unwrap();

        let updated = Registry::load(path).unwrap().get("quark").unwrap();
        assert_eq!(updated.config["cookie"], "__puus=new");
    }

    /// 换盘位（备份盘 → 资源库）时缓存的 driveId 必须作废，否则会继续
    /// 读写上一个盘；轮换出来的令牌则照旧保留（账号没变）。
    #[test]
    fn switching_aliyun_drive_type_drops_cached_drive_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("ali");
        source.ds_type = "aliyundrive".into();
        source.config = serde_json::json!({
            "clientId": "app",
            "clientSecret": "secret",
            "refreshToken": "seed-refresh",
            "driveType": "default"
        });
        registry.create(source.clone()).unwrap();
        registry
            .update_credentials(
                "ali",
                vec![
                    ("accessToken".into(), "fresh-access".into()),
                    ("driveId".into(), "drive-of-default".into()),
                ],
            )
            .unwrap();

        source.config["driveType"] = "resource".into();
        registry.update("ali", source).unwrap();

        let updated = Registry::load(path).unwrap().get("ali").unwrap();
        assert!(updated.config.get("driveId").is_none());
        assert_eq!(updated.config["accessToken"], "fresh-access");
    }

    /// 药丸切盘走的 `set_drive_type`：写入新盘位、丢弃旧 driveId，非阿里源拒绝。
    #[test]
    fn set_drive_type_updates_drive_and_drops_cached_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("datasources.json");
        let registry = Registry::load(path.clone()).unwrap();
        let mut source = ds("ali");
        source.ds_type = "aliyundrive".into();
        source.config = serde_json::json!({
            "clientId": "app",
            "clientSecret": "secret",
            "refreshToken": "seed-refresh",
            "driveType": "resource",
            "driveId": "drive-of-resource"
        });
        registry.create(source).unwrap();

        let saved = registry.set_drive_type("ali", "backup").unwrap();
        assert_eq!(saved.config["driveType"], "backup");
        assert!(saved.config.get("driveId").is_none());

        // 落盘后重新加载仍是新盘位、无旧 driveId。
        let reloaded = Registry::load(path).unwrap().get("ali").unwrap();
        assert_eq!(reloaded.config["driveType"], "backup");
        assert!(reloaded.config.get("driveId").is_none());

        // 非阿里云盘不支持切盘。
        registry.create(ds("local")).unwrap();
        assert!(registry.set_drive_type("local", "backup").is_err());
    }
}
