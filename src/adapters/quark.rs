//! 夸克网盘适配器（Cookie 鉴权 + upHash 秒传）。
//!
//! 与阿里云盘同为「ID 寻址」，同样用进程级 `路径 → fid` 缓存桥接到
//! SafeDrive 的路径寻址 Storage 抽象。
//!
//! 秒传：`/file/upload/pre` 拿 task_id，再用 md5+sha1 调 `/file/update/hash`，
//! `data.finish == true` 即命中。夸克列表**不返回内容摘要**，所以夸克作为
//! 复制源时凑不齐秒传凭据；作为目标时，只要调用方能给出 md5+sha1
//! （本地数据源读全量是免费的），就能省掉整条上传。
//!
//! Cookie 里的 `__puus` 每次响应都会轮换，必须原子写回注册表，否则重启后
//! 会退回作废的旧 Cookie。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{StreamExt, TryStreamExt};
use md5::Digest as _;
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;

use super::{
    ByteStream, CredentialPersister, Entry, HashKind, ProgressFn, RapidSource, Storage, read_spool,
    sanitize, spool_with_hashes,
};
use crate::error::{ApiError, ApiResult};

const API_BASE: &str = "https://drive.quark.cn/1/clouddrive";
const REFERER: &str = "https://pan.quark.cn";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch";
/// 分片上传走的是阿里 OSS，签名里的 UA 必须与夸克前端完全一致。
const OSS_UA: &str = "aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit";
const ROOT_FID: &str = "0";
const LIST_PAGE_SIZE: u32 = 100;
const DEFAULT_PART_SIZE: u64 = 4 * 1024 * 1024;
const PATH_ID_TTL: Duration = Duration::from_secs(300);
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(600);

/// 进程级 `账号\u{1}明文路径 → fid`。
static PATH_IDS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 进程级 `账号\u{1}fid → 下载直链`。
static DOWNLOAD_URLS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// 进程级活 Cookie。适配器是每请求新建的，轮换后的 `__puus` 必须挂在进程上。
static COOKIES: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_key(account: &str, path: &str) -> String {
    format!("{account}\u{1}{path}")
}

fn evict_path_ids(account: &str, path: &str) {
    let exact = cache_key(account, path);
    let prefix = format!("{exact}/");
    PATH_IDS
        .lock()
        .unwrap()
        .retain(|key, _| key != &exact && !key.starts_with(&prefix));
}

fn cookie_get(cookie: &str, name: &str) -> Option<String> {
    cookie.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

fn cookie_set(cookie: &str, name: &str, value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut replaced = false;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let key = pair.split_once('=').map_or(pair, |(k, _)| k.trim());
        if key == name {
            parts.push(format!("{name}={value}"));
            replaced = true;
        } else {
            parts.push(pair.to_owned());
        }
    }
    if !replaced {
        parts.push(format!("{name}={value}"));
    }
    parts.join("; ")
}

/// 账号标识：抹掉会轮换的 `__puus` / `__pus` 后取指纹，Cookie 轮换不会
/// 把缓存整体作废。
fn account_of(cookie: &str) -> String {
    let mut stable: Vec<&str> = cookie
        .split(';')
        .map(str::trim)
        .filter(|pair| {
            !pair.is_empty() && !pair.starts_with("__puus=") && !pair.starts_with("__pus=")
        })
        .collect();
    stable.sort_unstable();
    hex::encode(&Sha1::digest(stable.join(";").as_bytes())[..8])
}

/// 夸克返回的文件名是 HTML 转义过的，列目录时必须还原。
fn html_unescape(value: &str) -> String {
    if !value.contains('&') {
        return value.to_owned();
    }
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[derive(Debug, Clone, Deserialize)]
struct QuarkFile {
    fid: String,
    #[serde(default)]
    file_name: String,
    #[serde(default)]
    size: u64,
    /// true = 文件，false = 目录。
    #[serde(default)]
    file: bool,
    #[serde(default)]
    updated_at: u64,
}

/// `/file/upload/pre` 的结果：秒传与分片上传都要用。
#[derive(Debug, Clone, Default)]
struct UpPre {
    task_id: String,
    upload_id: String,
    obj_key: String,
    upload_url: String,
    bucket: String,
    auth_info: String,
    /// 原样保留的 callback 对象，upCommit 时要 base64 后进签名。
    callback: Value,
    part_size: u64,
}

enum Call {
    Ok(Value),
    Failed { message: String },
}

pub struct QuarkFs {
    api_base: String,
    /// 明文根目录（相对网盘根，已 sanitize）。
    root: String,
    account: String,
    persist: Option<CredentialPersister>,
    http: Client,
}

impl QuarkFs {
    pub fn from_config_with_persister(
        config: &Value,
        http: Client,
        persist: Option<CredentialPersister>,
    ) -> ApiResult<Self> {
        let text = |key: &str| {
            config
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let cookie = text("cookie")
            .ok_or_else(|| ApiError::BadRequest("夸克网盘配置缺少 cookie".into()))?;
        let root = sanitize(text("root").as_deref().unwrap_or(""))?;
        let account = account_of(&cookie);
        COOKIES
            .lock()
            .unwrap()
            .entry(account.clone())
            .or_insert(cookie);
        Ok(Self {
            api_base: text("apiBase").unwrap_or_else(|| API_BASE.to_owned()),
            root,
            account,
            persist,
            http,
        })
    }

    fn cookie(&self) -> String {
        COOKIES
            .lock()
            .unwrap()
            .get(&self.account)
            .cloned()
            .unwrap_or_default()
    }

    /// 响应里带了新的 `__puus` 就地轮换并落盘。
    fn absorb_cookies(&self, headers: &reqwest::header::HeaderMap) {
        let mut rotated = None;
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(text) = value.to_str() else { continue };
            let pair = text.split(';').next().unwrap_or_default();
            let Some((name, fresh)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() != "__puus" {
                continue;
            }
            let mut cookies = COOKIES.lock().unwrap();
            let current = cookies.get(&self.account).cloned().unwrap_or_default();
            if cookie_get(&current, "__puus").as_deref() == Some(fresh.trim()) {
                continue;
            }
            let updated = cookie_set(&current, "__puus", fresh.trim());
            cookies.insert(self.account.clone(), updated.clone());
            rotated = Some(updated);
        }
        if let (Some(cookie), Some(persist)) = (rotated, &self.persist)
            && let Err(e) = persist(vec![("cookie".into(), cookie.into())])
        {
            tracing::warn!("夸克网盘 Cookie 轮换写回失败: {e}");
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        what: &str,
    ) -> ApiResult<Call> {
        let url = format!("{}{path}", self.api_base.trim_end_matches('/'));
        let mut request = self
            .http
            .request(method, &url)
            .query(&[("pr", "ucpro"), ("fr", "pc")])
            .query(query)
            .header(reqwest::header::COOKIE, self.cookie())
            .header(reqwest::header::ACCEPT, "application/json, text/plain, */*")
            .header(reqwest::header::REFERER, REFERER)
            .header(reqwest::header::USER_AGENT, UA);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("夸克网盘{what}请求失败: {e}")))?;
        let status = response.status();
        self.absorb_cookies(response.headers());
        let text = response.text().await.unwrap_or_default();
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(ApiError::BadRequest(
                "夸克网盘 Cookie 已失效，请重新登录后更新配置".into(),
            ));
        }
        let code = value.get("code").and_then(Value::as_i64).unwrap_or(0);
        let api_status = value.get("status").and_then(Value::as_i64).unwrap_or(0);
        if code == 0 && api_status < 400 && status.is_success() {
            return Ok(Call::Ok(value));
        }
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("HTTP {status} {}", text.chars().take(200).collect::<String>()));
        Ok(Call::Failed { message })
    }

    async fn post(&self, path: &str, body: &Value, what: &str) -> ApiResult<Value> {
        match self.call(Method::POST, path, &[], Some(body), what).await? {
            Call::Ok(value) => Ok(value),
            Call::Failed { message } => {
                Err(ApiError::Upstream(format!("夸克网盘{what}失败: {message}")))
            }
        }
    }

    async fn get(&self, path: &str, query: &[(&str, String)], what: &str) -> ApiResult<Value> {
        match self.call(Method::GET, path, query, None, what).await? {
            Call::Ok(value) => Ok(value),
            Call::Failed { message } => {
                Err(ApiError::Upstream(format!("夸克网盘{what}失败: {message}")))
            }
        }
    }

    /// 列一个目录 fid 下的全部条目（翻页），顺带把子项 fid 写进缓存。
    async fn list_folder(
        &self,
        parent_fid: &str,
        cache_prefix: Option<&str>,
    ) -> ApiResult<Vec<QuarkFile>> {
        let mut page = 1u32;
        let mut out: Vec<QuarkFile> = Vec::new();
        loop {
            let query = [
                ("pdir_fid", parent_fid.to_owned()),
                ("_page", page.to_string()),
                ("_size", LIST_PAGE_SIZE.to_string()),
                ("_fetch_total", "1".to_owned()),
                ("fetch_all_file", "1".to_owned()),
                ("fetch_risk_file_name", "1".to_owned()),
            ];
            let value = self.get("/file/sort", &query, "列目录").await?;
            let list = value
                .pointer("/data/list")
                .cloned()
                .unwrap_or_else(|| json!([]));
            let mut items: Vec<QuarkFile> = serde_json::from_value(list)
                .map_err(|e| ApiError::Upstream(format!("夸克网盘列目录响应解析失败: {e}")))?;
            for item in &mut items {
                item.file_name = html_unescape(&item.file_name);
            }
            let fetched = items.len();
            out.extend(items);
            let total = value
                .pointer("/metadata/_total")
                .and_then(Value::as_u64)
                .unwrap_or(out.len() as u64);
            if fetched == 0 || out.len() as u64 >= total {
                break;
            }
            page += 1;
        }
        if let Some(prefix) = cache_prefix {
            let now = Instant::now();
            let mut cache = PATH_IDS.lock().unwrap();
            for item in &out {
                let path = if prefix.is_empty() {
                    item.file_name.clone()
                } else {
                    format!("{prefix}/{}", item.file_name)
                };
                cache.insert(cache_key(&self.account, &path), (item.fid.clone(), now));
            }
        }
        Ok(out)
    }

    async fn find_child(&self, parent_fid: &str, name: &str) -> ApiResult<Option<QuarkFile>> {
        Ok(self
            .list_folder(parent_fid, None)
            .await?
            .into_iter()
            .find(|item| item.file_name == name))
    }

    async fn root_fid(&self) -> ApiResult<String> {
        if self.root.is_empty() {
            return Ok(ROOT_FID.into());
        }
        self.folder_fid_from(ROOT_FID, "", &self.root, true).await
    }

    async fn folder_fid(&self, path: &str, create: bool) -> ApiResult<String> {
        let root = self.root_fid().await?;
        if path.is_empty() {
            return Ok(root);
        }
        self.folder_fid_from(&root, "", path, create).await
    }

    async fn folder_fid_from(
        &self,
        base_fid: &str,
        base_path: &str,
        relative: &str,
        create: bool,
    ) -> ApiResult<String> {
        let mut parent = base_fid.to_owned();
        let mut prefix = base_path.to_owned();
        for seg in relative.split('/').filter(|s| !s.is_empty()) {
            prefix = if prefix.is_empty() {
                seg.to_owned()
            } else {
                format!("{prefix}/{seg}")
            };
            let key = cache_key(&self.account, &prefix);
            if let Some((fid, at)) = PATH_IDS.lock().unwrap().get(&key).cloned()
                && at.elapsed() < PATH_ID_TTL
            {
                parent = fid;
                continue;
            }
            let fid = match self.find_child(&parent, seg).await? {
                Some(item) if !item.file => item.fid,
                Some(_) => return Err(ApiError::BadRequest(format!("{prefix} 已存在且是文件"))),
                None if create => self.create_folder(&parent, seg).await?,
                None => return Err(ApiError::NotFound(format!("路径不存在: {prefix}"))),
            };
            PATH_IDS
                .lock()
                .unwrap()
                .insert(key, (fid.clone(), Instant::now()));
            parent = fid;
        }
        Ok(parent)
    }

    async fn create_folder(&self, parent_fid: &str, name: &str) -> ApiResult<String> {
        let body = json!({
            "dir_init_lock": false,
            "dir_path": "",
            "file_name": name,
            "pdir_fid": parent_fid,
        });
        match self.call(Method::POST, "/file", &[], Some(&body), "创建目录").await? {
            Call::Ok(value) => {
                if let Some(fid) = value.pointer("/data/fid").and_then(Value::as_str) {
                    return Ok(fid.to_owned());
                }
                // 建目录后云端有短暂可见性延迟，回查一次。
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.find_child(parent_fid, name)
                    .await?
                    .map(|item| item.fid)
                    .ok_or_else(|| ApiError::Upstream(format!("夸克网盘创建目录后找不到 {name}")))
            }
            // 同名冲突 = 已经有了，回查拿 fid（并发 mkdir 的正常路径）
            Call::Failed { message } if message.contains("同名冲突") => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                self.find_child(parent_fid, name)
                    .await?
                    .map(|item| item.fid)
                    .ok_or_else(|| ApiError::Upstream(format!("夸克网盘创建目录冲突且找不到 {name}")))
            }
            Call::Failed { message } => {
                Err(ApiError::Upstream(format!("夸克网盘创建目录失败: {message}")))
            }
        }
    }

    async fn stat(&self, path: &str) -> ApiResult<QuarkFile> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不能对数据源根目录取元数据".into()));
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_fid = self.folder_fid(parent, false).await?;
        self.find_child(&parent_fid, name)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("路径不存在: {path}")))
    }

    async fn remove_fids(&self, fids: &[String], what: &str) -> ApiResult<()> {
        let body = json!({ "action_type": 1, "exclude_fids": [], "filelist": fids });
        self.post("/file/delete", &body, what).await.map(|_| ())
    }

    async fn download_url(&self, fid: &str) -> ApiResult<String> {
        let key = cache_key(&self.account, fid);
        if let Some((url, at)) = DOWNLOAD_URLS.lock().unwrap().get(&key).cloned()
            && at.elapsed() < DOWNLOAD_URL_TTL
        {
            return Ok(url);
        }
        let body = json!({ "fids": [fid] });
        let value = self.post("/file/download", &body, "获取下载直链").await?;
        let url = value
            .pointer("/data/0/download_url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("夸克网盘下载直链为空".into()))?
            .to_owned();
        DOWNLOAD_URLS
            .lock()
            .unwrap()
            .insert(key, (url.clone(), Instant::now()));
        Ok(url)
    }

    async fn fetch(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> ApiResult<(Option<u64>, ByteStream)> {
        let file = self.stat(path).await?;
        if !file.file {
            return Err(ApiError::BadRequest(format!("{path} 是目录")));
        }
        let url = self.download_url(&file.fid).await?;
        // 夸克直链校验 Cookie/Referer/UA，缺一个就 403。
        let mut request = self
            .http
            .get(&url)
            .header(reqwest::header::COOKIE, self.cookie())
            .header(reqwest::header::REFERER, format!("{REFERER}/"))
            .header(reqwest::header::USER_AGENT, UA);
        if let Some((start, end)) = range {
            request = request.header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
        }
        let response = request
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("夸克网盘下载失败: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            DOWNLOAD_URLS
                .lock()
                .unwrap()
                .remove(&cache_key(&self.account, &file.fid));
            return Err(ApiError::Upstream(format!("夸克网盘下载失败: HTTP {status}")));
        }
        let size = response.content_length();
        let stream = response.bytes_stream().map_err(std::io::Error::other);
        Ok((size, stream.boxed()))
    }

    fn mime_of(name: &str) -> String {
        mime_guess::from_path(name)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_owned()
    }

    async fn up_pre(&self, parent_fid: &str, name: &str, size: u64) -> ApiResult<UpPre> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let body = json!({
            "ccp_hash_update": true,
            "dir_name": "",
            "file_name": name,
            "format_type": Self::mime_of(name),
            "l_created_at": now_ms,
            "l_updated_at": now_ms,
            "pdir_fid": parent_fid,
            "size": size,
        });
        let value = self.post("/file/upload/pre", &body, "预创建上传").await?;
        let text = |pointer: &str| {
            value
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        Ok(UpPre {
            task_id: text("/data/task_id"),
            upload_id: text("/data/upload_id"),
            obj_key: text("/data/obj_key"),
            upload_url: text("/data/upload_url"),
            bucket: text("/data/bucket"),
            auth_info: text("/data/auth_info"),
            callback: value
                .pointer("/data/callback")
                .cloned()
                .unwrap_or_else(|| json!({})),
            part_size: value
                .pointer("/metadata/part_size")
                .and_then(Value::as_u64)
                .filter(|size| *size > 0)
                .unwrap_or(DEFAULT_PART_SIZE),
        })
    }

    /// 秒传：报摘要，云端有同内容就直接完成。
    async fn up_hash(&self, task_id: &str, md5: &str, sha1: &str) -> ApiResult<bool> {
        let body = json!({ "md5": md5, "sha1": sha1, "task_id": task_id });
        let value = self.post("/file/update/hash", &body, "秒传").await?;
        Ok(value
            .pointer("/data/finish")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    /// 换取一次 OSS 请求的 Authorization。
    async fn oss_auth(&self, pre: &UpPre, auth_meta: &str) -> ApiResult<String> {
        let body = json!({
            "auth_info": pre.auth_info,
            "auth_meta": auth_meta,
            "task_id": pre.task_id,
        });
        let value = self.post("/file/upload/auth", &body, "换取上传签名").await?;
        value
            .pointer("/data/auth_key")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream("夸克网盘上传签名为空".into()))
    }

    /// `http://oss-cn-xx.aliyuncs.com` → `https://{bucket}.oss-cn-xx.aliyuncs.com/{obj_key}`
    fn oss_url(pre: &UpPre) -> ApiResult<String> {
        let host = pre
            .upload_url
            .split_once("://")
            .map(|(_, host)| host)
            .filter(|host| !host.is_empty())
            .ok_or_else(|| ApiError::Upstream("夸克网盘上传地址非法".into()))?;
        Ok(format!(
            "https://{}.{host}/{}",
            pre.bucket, pre.obj_key
        ))
    }

    async fn up_part(
        &self,
        pre: &UpPre,
        mime: &str,
        part_number: u64,
        chunk: bytes::Bytes,
    ) -> ApiResult<String> {
        let now = httpdate::fmt_http_date(std::time::SystemTime::now());
        let auth_meta = format!(
            "PUT\n\n{mime}\n{now}\nx-oss-date:{now}\nx-oss-user-agent:{OSS_UA}\n/{}/{}?partNumber={part_number}&uploadId={}",
            pre.bucket, pre.obj_key, pre.upload_id
        );
        let auth_key = self.oss_auth(pre, &auth_meta).await?;
        let response = self
            .http
            .put(Self::oss_url(pre)?)
            .query(&[
                ("partNumber", part_number.to_string()),
                ("uploadId", pre.upload_id.clone()),
            ])
            .header(reqwest::header::AUTHORIZATION, auth_key)
            .header(reqwest::header::CONTENT_TYPE, mime)
            .header(reqwest::header::REFERER, format!("{REFERER}/"))
            .header("x-oss-date", &now)
            .header("x-oss-user-agent", OSS_UA)
            .body(chunk)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("夸克网盘上传分片失败: {e}")))?;
        if !response.status().is_success() {
            return Err(ApiError::Upstream(format!(
                "夸克网盘上传第 {part_number} 片失败: HTTP {}",
                response.status()
            )));
        }
        response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream(format!("夸克网盘第 {part_number} 片缺少 ETag")))
    }

    async fn up_commit(&self, pre: &UpPre, etags: &[String]) -> ApiResult<()> {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>\n",
        );
        for (index, etag) in etags.iter().enumerate() {
            body.push_str(&format!(
                "<Part>\n<PartNumber>{}</PartNumber>\n<ETag>{etag}</ETag>\n</Part>\n",
                index + 1
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let content_md5 = B64.encode(md5::Md5::digest(body.as_bytes()));
        // 与夸克前端保持完全一致的字段序：签名与回执都按这个串算。
        let callback = format!(
            "{{\"callbackUrl\":{},\"callbackBody\":{}}}",
            serde_json::to_string(
                pre.callback
                    .get("callbackUrl")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            )
            .unwrap_or_else(|_| "\"\"".into()),
            serde_json::to_string(
                pre.callback
                    .get("callbackBody")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            )
            .unwrap_or_else(|_| "\"\"".into()),
        );
        let callback_b64 = B64.encode(callback.as_bytes());
        let now = httpdate::fmt_http_date(std::time::SystemTime::now());
        let auth_meta = format!(
            "POST\n{content_md5}\napplication/xml\n{now}\nx-oss-callback:{callback_b64}\nx-oss-date:{now}\nx-oss-user-agent:{OSS_UA}\n/{}/{}?uploadId={}",
            pre.bucket, pre.obj_key, pre.upload_id
        );
        let auth_key = self.oss_auth(pre, &auth_meta).await?;
        let response = self
            .http
            .post(Self::oss_url(pre)?)
            .query(&[("uploadId", pre.upload_id.clone())])
            .header(reqwest::header::AUTHORIZATION, auth_key)
            .header("Content-MD5", content_md5)
            .header(reqwest::header::CONTENT_TYPE, "application/xml")
            .header(reqwest::header::REFERER, format!("{REFERER}/"))
            .header("x-oss-callback", callback_b64)
            .header("x-oss-date", &now)
            .header("x-oss-user-agent", OSS_UA)
            .body(body)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("夸克网盘合并分片失败: {e}")))?;
        if !response.status().is_success() {
            return Err(ApiError::Upstream(format!(
                "夸克网盘合并分片失败: HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn up_finish(&self, pre: &UpPre) -> ApiResult<()> {
        let body = json!({ "obj_key": pre.obj_key, "task_id": pre.task_id });
        self.post("/file/upload/finish", &body, "完成上传").await?;
        // 夸克需要一点时间把对象挂到目录树上，否则紧接着的 list 看不到。
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(())
    }
}

#[async_trait]
impl Storage for QuarkFs {
    fn download_profile_key(&self) -> Option<String> {
        Some(format!("quark:{}", self.account))
    }

    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        let parent_fid = self.folder_fid(path, false).await?;
        Ok(self
            .list_folder(&parent_fid, Some(path))
            .await?
            .into_iter()
            .map(|item| Entry {
                id: None,
                name: item.file_name,
                is_dir: !item.file,
                size: if item.file { item.size } else { 0 },
                mtime: item.updated_at,
            })
            .collect())
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        self.folder_fid(path, true).await.map(|_| ())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        let file = self.stat(path).await?;
        self.remove_fids(&[file.fid], "删除").await?;
        evict_path_ids(&self.account, path);
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法重命名路径".into()));
        }
        let file = self.stat(from).await?;
        let (from_parent, from_name) = from.rsplit_once('/').unwrap_or(("", from));
        let (to_parent, to_name) = to.rsplit_once('/').unwrap_or(("", to));
        // 夸克的 move 不支持同时改名，跨目录改名要两步。
        if from_parent != to_parent {
            let target_fid = self.folder_fid(to_parent, true).await?;
            let body = json!({
                "action_type": 1,
                "exclude_fids": [],
                "filelist": [file.fid],
                "to_pdir_fid": target_fid,
            });
            self.post("/file/move", &body, "移动").await?;
        }
        if from_name != to_name {
            let body = json!({ "fid": file.fid, "file_name": to_name });
            self.post("/file/rename", &body, "重命名").await?;
        }
        evict_path_ids(&self.account, from);
        evict_path_ids(&self.account, to);
        Ok(())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        self.fetch(path, None).await
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        if end < start {
            return Err(ApiError::BadRequest("非法字节区间".into()));
        }
        self.fetch(path, Some((start, end))).await.map(|(_, s)| s)
    }

    async fn put(&self, path: &str, body: ByteStream) -> ApiResult<()> {
        // 未知长度：先落盘量出大小，再走正常上传。
        let spool = super::TempSpool::new("quark");
        let mut body = body;
        let mut file = tokio::fs::File::create(&spool.path).await?;
        let mut size = 0u64;
        {
            use tokio::io::AsyncWriteExt as _;
            while let Some(chunk) = body.next().await {
                let chunk = chunk?;
                size += chunk.len() as u64;
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
        }
        drop(file);
        let reopened = tokio::fs::File::open(&spool.path).await?;
        let stream = tokio_util::io::ReaderStream::with_capacity(reopened, 256 * 1024);
        self.put_sized(path, size, stream.boxed()).await
    }

    async fn put_sized(&self, path: &str, size: u64, body: ByteStream) -> ApiResult<()> {
        self.put_sized_tracked(path, size, body, Arc::new(|_| {}))
            .await
    }

    async fn put_sized_tracked(
        &self,
        path: &str,
        size: u64,
        body: ByteStream,
        progress: ProgressFn,
    ) -> ApiResult<()> {
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_fid = self.folder_fid(parent, true).await?;

        // 夸克秒传要 md5+sha1 两个摘要，只能先落盘算出来。
        let (spool, hashes) =
            spool_with_hashes("quark", size, body, &[HashKind::Md5, HashKind::Sha1]).await?;
        let md5 = hashes.md5.clone().unwrap_or_default();
        let sha1 = hashes.sha1.clone().unwrap_or_default();

        // 覆盖语义：同名先删（夸克允许同名共存，留着会让路径解析二义）。
        if let Some(existing) = self.find_child(&parent_fid, name).await? {
            self.remove_fids(&[existing.fid], "覆盖前删除同名对象").await?;
        }

        let pre = self.up_pre(&parent_fid, name, size).await?;
        evict_path_ids(&self.account, path);
        if self.up_hash(&pre.task_id, &md5, &sha1).await? {
            tracing::debug!("夸克网盘秒传命中: {path} ({size} 字节)");
            progress(size);
            return Ok(());
        }

        let mime = Self::mime_of(name);
        let parts = size.div_ceil(pre.part_size).max(1);
        let mut etags = Vec::with_capacity(parts as usize);
        for index in 0..parts {
            let offset = index * pre.part_size;
            let length = pre.part_size.min(size.saturating_sub(offset)) as usize;
            let chunk = read_spool(&spool.path, offset, length).await?;
            let mut last_error = None;
            let mut etag = None;
            for attempt in 1..=3u32 {
                match self.up_part(&pre, &mime, index + 1, chunk.clone()).await {
                    Ok(value) => {
                        etag = Some(value);
                        break;
                    }
                    Err(e) => last_error = Some(e),
                }
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
                }
            }
            match etag {
                Some(etag) => etags.push(etag),
                None => {
                    return Err(last_error
                        .unwrap_or_else(|| ApiError::Upstream("夸克网盘上传分片失败".into())));
                }
            }
            progress(length as u64);
        }
        self.up_commit(&pre, &etags).await?;
        self.up_finish(&pre).await
    }

    // ---- 秒传 ----
    //
    // 夸克列表不返回内容摘要，所以 `dir_content_hashes` 用默认空实现：
    // 夸克作为复制源时凑不齐凭据，作为目标时靠调用方提供摘要。

    fn rapid_hash_kinds(&self) -> &'static [HashKind] {
        &[HashKind::Md5, HashKind::Sha1]
    }

    async fn rapid_put(&self, path: &str, source: &dyn RapidSource) -> ApiResult<bool> {
        let (Some(md5), Some(sha1)) = (
            source.hashes().md5.clone(),
            source.hashes().sha1.clone(),
        ) else {
            return Ok(false);
        };
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_fid = self.folder_fid(parent, true).await?;
        if let Some(existing) = self.find_child(&parent_fid, name).await? {
            self.remove_fids(&[existing.fid], "秒传前删除同名对象").await?;
        }
        let pre = self.up_pre(&parent_fid, name, source.size()).await?;
        evict_path_ids(&self.account, path);
        // 没命中也不留痕：pre 只是一个上传任务，不会在目录里生成对象。
        self.up_hash(&pre.task_id, &md5, &sha1).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trip() {
        let cookie = "a=1; __puus=old; b=2";
        assert_eq!(cookie_get(cookie, "__puus").as_deref(), Some("old"));
        assert_eq!(cookie_set(cookie, "__puus", "new"), "a=1; __puus=new; b=2");
        assert_eq!(cookie_set("a=1", "__puus", "new"), "a=1; __puus=new");
        assert_eq!(cookie_get("a=1", "__puus"), None);
    }

    #[test]
    fn account_survives_puus_rotation() {
        let before = account_of("__uid=42; __puus=old; __pus=x");
        let after = account_of("__puus=new; __uid=42; __pus=y");
        assert_eq!(before, after);
        assert_ne!(before, account_of("__uid=43; __puus=old"));
    }

    #[test]
    fn html_names_are_unescaped() {
        assert_eq!(html_unescape("a&amp;b"), "a&b");
        assert_eq!(html_unescape("&lt;x&gt;"), "<x>");
        assert_eq!(html_unescape("&amp;lt;"), "&lt;");
        assert_eq!(html_unescape("plain"), "plain");
    }

    #[test]
    fn oss_url_strips_scheme() {
        let pre = UpPre {
            bucket: "bkt".into(),
            obj_key: "k/1".into(),
            upload_url: "http://oss-cn-hangzhou.aliyuncs.com".into(),
            ..Default::default()
        };
        assert_eq!(
            QuarkFs::oss_url(&pre).unwrap(),
            "https://bkt.oss-cn-hangzhou.aliyuncs.com/k/1"
        );
    }
}
