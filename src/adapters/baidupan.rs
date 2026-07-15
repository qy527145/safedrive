//! 百度网盘开放平台适配器。
//!
//! 目录、写操作和上传使用 OAuth `xpan` 开放平台 API；Cookie 只用于 onepan
//! `get_download_url1` 对应的 Android `locatedownload` 下载链路。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, TryStreamExt, stream};
use md5::{Digest, Md5};
use reqwest::header::{CONTENT_RANGE, COOKIE, HeaderValue, RANGE, USER_AGENT};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use super::{ByteStream, Entry, Storage};
use crate::error::{ApiError, ApiResult};

const XPAN_API: &str = "https://pan.baidu.com/rest/2.0/";
const OAUTH_TOKEN_API: &str = "https://openapi.baidu.com/oauth/2.0/token";
const PCS_FILE_API: &str = "https://pcs.baidu.com/rest/2.0/pcs/file";
const PCS_UPLOAD_API: &str = "https://d.pcs.baidu.com/rest/2.0/pcs/superfile2";
const PAN_APP_ID: &str = "250528";
const DEFAULT_DOWNLOAD_UA: &str = "netdisk;P2SP;2.2.61.31;android";
const DEFAULT_WEB_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const MAX_PREVIEW_RANGE: u64 = 5 * 1024 * 1024;
const UPLOAD_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const MAX_UPLOAD_BLOCKS: usize = 2048;
const UPLOAD_CONCURRENCY: usize = 3;
const LINK_TTL: Duration = Duration::from_secs(120);

pub type TokenPersister = Arc<dyn Fn(&str, &str) -> ApiResult<()> + Send + Sync>;

#[derive(Clone)]
struct CachedLinks {
    inserted: Instant,
    urls: Vec<String>,
}

struct OAuthTokens {
    access_token: String,
    refresh_token: String,
    expires_at: Option<Instant>,
}

struct TempUpload {
    path: PathBuf,
}

impl TempUpload {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "safedrive-baidu-{}.upload",
                uuid::Uuid::new_v4().simple()
            )),
        }
    }
}

impl Drop for TempUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct BaiduPanFs {
    root: String,
    xpan_api_base: Url,
    oauth_token_api: Url,
    pcs_api_base: Url,
    upload_api_base: Url,
    client_id: String,
    client_secret: String,
    tokens: Mutex<OAuthTokens>,
    persist_tokens: Option<TokenPersister>,
    download_cookie: HeaderValue,
    web_user_agent: HeaderValue,
    download_user_agent: HeaderValue,
    http: Client,
    links: Mutex<HashMap<String, CachedLinks>>,
    link_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

#[derive(Debug, Deserialize)]
struct BaiduListItem {
    server_filename: String,
    #[serde(default)]
    isdir: i8,
    #[serde(default)]
    size: u64,
    #[serde(default, alias = "mtime")]
    server_mtime: u64,
}

struct SpooledUpload {
    temp: TempUpload,
    block_md5: Vec<String>,
    content_md5: String,
    slice_md5: String,
}

impl BaiduPanFs {
    pub fn from_config_with_persister(
        config: &Value,
        http: Client,
        persist_tokens: Option<TokenPersister>,
    ) -> ApiResult<Self> {
        let required = |name: &str| -> ApiResult<String> {
            config
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| ApiError::BadRequest(format!("百度网盘配置缺少 {name}")))
        };
        let cookie_text = required("cookie")?;
        let bduss = cookie_value(&cookie_text, "BDUSS")
            .ok_or_else(|| ApiError::BadRequest("百度网盘 cookie 中缺少 BDUSS".into()))?;
        let download_cookie = HeaderValue::from_str(&format!("BDUSS={bduss}"))
            .map_err(|_| ApiError::BadRequest("百度网盘 BDUSS 含非法字符".into()))?;
        let download_user_agent = HeaderValue::from_str(
            config
                .get("userAgent")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_DOWNLOAD_UA),
        )
        .map_err(|_| ApiError::BadRequest("百度网盘下载 User-Agent 含非法字符".into()))?;
        let root = normalize_root(
            config
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or("/safedrive"),
        )?;
        let parse_url = |field: &str, default: &str| -> ApiResult<Url> {
            let url = Url::parse(config.get(field).and_then(Value::as_str).unwrap_or(default))
                .map_err(|e| ApiError::BadRequest(format!("百度网盘 {field} 无效: {e}")))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ApiError::BadRequest(format!(
                    "百度网盘 {field} 必须是 http(s)"
                )));
            }
            Ok(url)
        };
        Ok(Self {
            root,
            xpan_api_base: parse_url("openApiBase", XPAN_API)?,
            oauth_token_api: parse_url("oauthTokenUrl", OAUTH_TOKEN_API)?,
            pcs_api_base: parse_url("pcsApiBase", PCS_FILE_API)?,
            upload_api_base: parse_url("uploadApiBase", PCS_UPLOAD_API)?,
            client_id: required("clientId")?,
            client_secret: required("clientSecret")?,
            tokens: Mutex::new(OAuthTokens {
                access_token: config
                    .get("accessToken")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned(),
                refresh_token: required("refreshToken")?,
                expires_at: None,
            }),
            persist_tokens,
            download_cookie,
            web_user_agent: HeaderValue::from_static(DEFAULT_WEB_UA),
            download_user_agent,
            http,
            links: Mutex::new(HashMap::new()),
            link_locks: Mutex::new(HashMap::new()),
        })
    }

    fn remote_path(&self, rel: &str) -> String {
        if rel.is_empty() {
            return self.root.clone();
        }
        if self.root == "/" {
            format!("/{rel}")
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    fn xpan_url(&self, endpoint: &str) -> ApiResult<Url> {
        self.xpan_api_base
            .join(endpoint)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("构造百度开放平台地址失败: {e}")))
    }

    fn web_request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(USER_AGENT, self.web_user_agent.clone())
    }

    async fn response_json(resp: reqwest::Response, what: &str) -> ApiResult<Value> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ApiError::Upstream(format!("读取百度网盘{what}响应失败: {e}")))?;
        let value = if text.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&text).map_err(|e| {
                ApiError::Upstream(format!("解析百度网盘{what}响应失败: {e}; {text}"))
            })?
        };
        if !status.is_success() {
            return Err(ApiError::Upstream(format!(
                "百度网盘{what}失败 ({status}): {}",
                text.chars().take(300).collect::<String>()
            )));
        }
        Ok(value)
    }

    fn api_code(value: &Value) -> i64 {
        value
            .get("errno")
            .or_else(|| value.get("error_code"))
            .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
            .unwrap_or(0)
    }

    fn ensure_api_ok(value: &Value, what: &str, allowed: &[i64]) -> ApiResult<()> {
        let code = Self::api_code(value);
        if code == 0 || allowed.contains(&code) {
            return Ok(());
        }
        let message = value
            .get("errmsg")
            .or_else(|| value.get("error_msg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        if matches!(code, -9 | 31066) {
            return Err(ApiError::NotFound(format!("百度网盘{what}: 不存在")));
        }
        Err(ApiError::Upstream(format!(
            "百度网盘{what}失败: code={code}, {message}"
        )))
    }

    async fn access_token(&self) -> ApiResult<String> {
        let needs_refresh = {
            let tokens = self.tokens.lock().await;
            tokens.access_token.is_empty()
                || tokens
                    .expires_at
                    .is_some_and(|expires| expires <= Instant::now())
        };
        if needs_refresh {
            self.refresh_access_token(None).await
        } else {
            Ok(self.tokens.lock().await.access_token.clone())
        }
    }

    async fn refresh_access_token(&self, invalid_token: Option<&str>) -> ApiResult<String> {
        let mut tokens = self.tokens.lock().await;
        if let Some(invalid) = invalid_token
            && !tokens.access_token.is_empty()
            && tokens.access_token != invalid
        {
            return Ok(tokens.access_token.clone());
        }
        let mut url = self.oauth_token_api.clone();
        url.query_pairs_mut()
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &tokens.refresh_token)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret);
        let resp = self
            .web_request(Method::GET, url)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("刷新百度开放平台令牌失败: {e}")))?;
        let value = Self::response_json(resp, "刷新开放平台令牌").await?;
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            let description = value
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            return Err(ApiError::Upstream(format!(
                "刷新百度开放平台令牌失败: {error}: {description}"
            )));
        }
        let access = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("刷新令牌响应缺少 access_token".into()))?
            .to_owned();
        let refresh = value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&tokens.refresh_token)
            .to_owned();
        if let Some(persist) = &self.persist_tokens {
            persist(&access, &refresh)?;
        }
        let expires = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(30 * 24 * 60 * 60)
            .saturating_sub(60);
        tokens.access_token = access.clone();
        tokens.refresh_token = refresh;
        tokens.expires_at = Some(Instant::now() + Duration::from_secs(expires));
        Ok(access)
    }

    async fn xpan_request(
        &self,
        method: Method,
        endpoint: &str,
        query: &[(&str, String)],
        form: Option<&[(String, String)]>,
        what: &str,
        allowed: &[i64],
    ) -> ApiResult<Value> {
        let mut token = self.access_token().await?;
        for attempt in 0..2 {
            let mut url = self.xpan_url(endpoint)?;
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("access_token", &token);
                for (key, value) in query {
                    pairs.append_pair(key, value);
                }
            }
            let mut request = self.web_request(method.clone(), url);
            if let Some(form) = form {
                request = request.form(form);
            }
            let resp = request
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("百度网盘{what}请求失败: {e}")))?;
            let value = Self::response_json(resp, what).await?;
            if matches!(Self::api_code(&value), 111 | -6) && attempt == 0 {
                token = self.refresh_access_token(Some(&token)).await?;
                continue;
            }
            Self::ensure_api_ok(&value, what, allowed)?;
            return Ok(value);
        }
        unreachable!()
    }

    async fn locatedownload(&self, remote_path: &str, force: bool) -> ApiResult<Vec<String>> {
        if !force {
            let links = self.links.lock().await;
            if let Some(hit) = links.get(remote_path)
                && hit.inserted.elapsed() < LINK_TTL
            {
                return Ok(hit.urls.clone());
            }
        }
        let path_lock = {
            let mut locks = self.link_locks.lock().await;
            Arc::clone(
                locks
                    .entry(remote_path.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = path_lock.lock().await;
        if !force {
            let links = self.links.lock().await;
            if let Some(hit) = links.get(remote_path)
                && hit.inserted.elapsed() < LINK_TTL
            {
                return Ok(hit.urls.clone());
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let random = uuid::Uuid::new_v4().simple().to_string();
        let mut url = self.pcs_api_base.clone();
        {
            let mut q = url.query_pairs_mut();
            for (key, value) in [
                ("app_id", PAN_APP_ID),
                ("method", "locatedownload"),
                ("check_blue", "1"),
                ("es", "1"),
                ("esl", "1"),
                ("path", remote_path),
                ("ver", "4.0"),
                ("dtype", "1"),
                ("err_ver", "1.0"),
                ("ehps", "1"),
                ("eck", "1"),
                ("vip", "0"),
                ("clienttype", "17"),
                ("version", "2.2.61.31"),
                ("time", &now),
                ("rand", &random),
                ("devuid", "E8E43120BC3C98E0EAAEA7BF7749C465|VJXGDD546"),
                ("channel", "0"),
                ("version_app", "9999"),
                ("apn_id", "1.0"),
                ("freeisp", "0"),
                ("queryfree", "0"),
                ("cuid", "12345620BC3C98E0EAAEA7BF7749C465|VJXGDD547"),
                ("use", "1"),
            ] {
                q.append_pair(key, value);
            }
        }
        let resp = self
            .http
            .get(url)
            .header(USER_AGENT, self.download_user_agent.clone())
            .header(COOKIE, self.download_cookie.clone())
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("百度网盘获取下载链接失败: {e}")))?;
        let value = Self::response_json(resp, "获取下载链接").await?;
        Self::ensure_api_ok(&value, "获取下载链接", &[])?;
        let urls = value
            .get("urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("url").and_then(Value::as_str))
            .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if urls.is_empty() {
            return Err(ApiError::Upstream(format!(
                "百度网盘下载链接响应中没有 urls: {value}"
            )));
        }
        self.links.lock().await.insert(
            remote_path.to_owned(),
            CachedLinks {
                inserted: Instant::now(),
                urls: urls.clone(),
            },
        );
        Ok(urls)
    }

    async fn download_response(
        &self,
        remote_path: &str,
        range: Option<(u64, u64)>,
    ) -> ApiResult<reqwest::Response> {
        for force in [false, true] {
            let urls = self.locatedownload(remote_path, force).await?;
            let pick =
                range.map_or(0, |(start, _)| (start / MAX_PREVIEW_RANGE) as usize) % urls.len();
            let url = Url::parse(&urls[pick])
                .map_err(|e| ApiError::Upstream(format!("百度返回非法下载链接: {e}")))?;
            let mut request = self
                .http
                .get(url)
                .header(USER_AGENT, self.download_user_agent.clone())
                .header(COOKIE, self.download_cookie.clone());
            if let Some((start, end)) = range {
                request = request.header(RANGE, format!("bytes={start}-{end}"));
            }
            let resp = request
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("百度网盘下载请求失败: {e}")))?;
            if resp.status().is_success() {
                return Ok(resp);
            }
            if !force && matches!(resp.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
                self.links.lock().await.remove(remote_path);
                continue;
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Upstream(format!(
                "百度网盘下载失败 ({status}): {}",
                body.chars().take(300).collect::<String>()
            )));
        }
        unreachable!()
    }

    async fn spool_upload(&self, size: u64, mut body: ByteStream) -> ApiResult<SpooledUpload> {
        if size == 0 {
            return Err(ApiError::BadRequest("百度网盘开放平台不支持空文件".into()));
        }
        let block_count = size.div_ceil(UPLOAD_BLOCK_SIZE as u64) as usize;
        if block_count > MAX_UPLOAD_BLOCKS {
            return Err(ApiError::BadRequest(format!(
                "单个百度网盘分卷超过开放平台上限: {block_count} 块"
            )));
        }
        let temp = TempUpload::new();
        let mut file = tokio::fs::File::create(&temp.path).await?;
        let mut content = Md5::new();
        let mut slice = Md5::new();
        let mut block = Md5::new();
        let mut block_bytes = 0usize;
        let mut slice_bytes = 0usize;
        let mut received = 0u64;
        let mut block_md5 = Vec::with_capacity(block_count);
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            received = received.saturating_add(chunk.len() as u64);
            if received > size {
                return Err(ApiError::BadRequest("上传数据超过声明大小".into()));
            }
            file.write_all(&chunk).await?;
            content.update(&chunk);
            if slice_bytes < 256 * 1024 {
                let take = (256 * 1024 - slice_bytes).min(chunk.len());
                slice.update(&chunk[..take]);
                slice_bytes += take;
            }
            let mut offset = 0usize;
            while offset < chunk.len() {
                let take = (UPLOAD_BLOCK_SIZE - block_bytes).min(chunk.len() - offset);
                block.update(&chunk[offset..offset + take]);
                block_bytes += take;
                offset += take;
                if block_bytes == UPLOAD_BLOCK_SIZE {
                    block_md5.push(hex::encode(block.finalize_reset()));
                    block_bytes = 0;
                }
            }
        }
        file.flush().await?;
        drop(file);
        if received != size {
            return Err(ApiError::BadRequest(format!(
                "上传数据大小不匹配: 声明 {size}，实际 {received}"
            )));
        }
        if block_bytes != 0 {
            block_md5.push(hex::encode(block.finalize()));
        }
        Ok(SpooledUpload {
            temp,
            block_md5,
            content_md5: hex::encode(content.finalize()),
            slice_md5: hex::encode(slice.finalize()),
        })
    }

    async fn read_upload_block(path: &Path, part_seq: usize, size: u64) -> ApiResult<Bytes> {
        let offset = part_seq as u64 * UPLOAD_BLOCK_SIZE as u64;
        let length = (size - offset).min(UPLOAD_BLOCK_SIZE as u64) as usize;
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).await?;
        Ok(Bytes::from(bytes))
    }

    async fn upload_block_once(
        &self,
        remote: &str,
        upload_id: &str,
        part_seq: usize,
        block: Bytes,
        token: &str,
    ) -> ApiResult<Value> {
        let mut url = self.upload_api_base.clone();
        url.query_pairs_mut()
            .append_pair("method", "upload")
            .append_pair("access_token", token)
            .append_pair("type", "tmpfile")
            .append_pair("path", remote)
            .append_pair("uploadid", upload_id)
            .append_pair("partseq", &part_seq.to_string());
        let len = block.len() as u64;
        let part = Part::stream_with_length(reqwest::Body::from(block), len)
            .file_name("blob")
            .mime_str("application/octet-stream")
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
        let resp = self
            .web_request(Method::POST, url)
            .multipart(Form::new().part("file", part))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("百度网盘上传第 {part_seq} 块失败: {e}")))?;
        Self::response_json(resp, "上传文件块").await
    }

    async fn upload_block(
        &self,
        remote: &str,
        upload_id: &str,
        part_seq: usize,
        block: Bytes,
    ) -> ApiResult<()> {
        let mut token = self.access_token().await?;
        for attempt in 0..2 {
            let value = self
                .upload_block_once(remote, upload_id, part_seq, block.clone(), &token)
                .await?;
            if matches!(Self::api_code(&value), 111 | -6) && attempt == 0 {
                token = self.refresh_access_token(Some(&token)).await?;
                continue;
            }
            Self::ensure_api_ok(&value, "上传文件块", &[])?;
            return Ok(());
        }
        unreachable!()
    }

    async fn upload_sized(&self, path: &str, size: u64, body: ByteStream) -> ApiResult<()> {
        let remote = self.remote_path(path);
        let spooled = self.spool_upload(size, body).await?;
        let block_list = serde_json::to_string(&spooled.block_md5).unwrap();
        let precreate = self
            .xpan_request(
                Method::POST,
                "xpan/file",
                &[("method", "precreate".into())],
                Some(&[
                    ("path".into(), remote.clone()),
                    ("size".into(), size.to_string()),
                    ("isdir".into(), "0".into()),
                    ("autoinit".into(), "1".into()),
                    ("rtype".into(), "3".into()),
                    ("block_list".into(), block_list.clone()),
                    ("content-md5".into(), spooled.content_md5),
                    ("slice-md5".into(), spooled.slice_md5),
                ]),
                "预创建上传",
                &[],
            )
            .await?;
        if precreate
            .get("return_type")
            .and_then(Value::as_i64)
            .is_some_and(|kind| kind == 2)
        {
            return Ok(());
        }
        let upload_id = precreate
            .get("uploadid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ApiError::Upstream(format!("预创建未返回 uploadid: {precreate}")))?
            .to_owned();
        let missing = precreate
            .get("block_list")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_u64)
                    .map(|index| index as usize)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| (0..spooled.block_md5.len()).collect());
        let block_count = spooled.block_md5.len();
        let temp_path = spooled.temp.path.clone();
        stream::iter(missing)
            .map(|part_seq| {
                let remote = remote.clone();
                let upload_id = upload_id.clone();
                let path = temp_path.clone();
                async move {
                    if part_seq >= block_count {
                        return Err(ApiError::Upstream(format!(
                            "百度返回非法上传分片序号: {part_seq}"
                        )));
                    }
                    let block = Self::read_upload_block(&path, part_seq, size).await?;
                    self.upload_block(&remote, &upload_id, part_seq, block)
                        .await
                }
            })
            .buffer_unordered(UPLOAD_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "create".into())],
            Some(&[
                ("path".into(), remote),
                ("size".into(), size.to_string()),
                ("isdir".into(), "0".into()),
                ("rtype".into(), "3".into()),
                ("uploadid".into(), upload_id),
                ("block_list".into(), block_list),
            ]),
            "合并上传文件",
            &[],
        )
        .await
        .map(|_| ())
    }
}

#[async_trait]
impl Storage for BaiduPanFs {
    fn max_range_size(&self) -> Option<u64> {
        Some(MAX_PREVIEW_RANGE)
    }

    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        let remote = self.remote_path(path);
        const LIMIT: usize = 1000;
        let mut entries = Vec::new();
        for start in (0..10_000_000usize).step_by(LIMIT) {
            let value = self
                .xpan_request(
                    Method::GET,
                    "xpan/file",
                    &[
                        ("method", "list".into()),
                        ("dir", remote.clone()),
                        ("web", "web".into()),
                        ("order", "name".into()),
                        ("desc", "0".into()),
                        ("start", start.to_string()),
                        ("limit", LIMIT.to_string()),
                    ],
                    None,
                    "列目录",
                    &[],
                )
                .await?;
            let items: Vec<BaiduListItem> =
                serde_json::from_value(value.get("list").cloned().unwrap_or_else(|| json!([])))
                    .map_err(|e| ApiError::Upstream(format!("解析百度网盘目录条目失败: {e}")))?;
            let count = items.len();
            entries.extend(items.into_iter().map(|item| Entry {
                name: item.server_filename,
                is_dir: item.isdir == 1,
                size: item.size,
                mtime: item.server_mtime.saturating_mul(1000),
            }));
            if count < LIMIT {
                return Ok(entries);
            }
        }
        Err(ApiError::Upstream("百度网盘列目录分页超过安全上限".into()))
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        let remote = self.remote_path(path);
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "create".into())],
            Some(&[
                ("path".into(), remote),
                ("size".into(), "0".into()),
                ("isdir".into(), "1".into()),
                ("rtype".into(), "3".into()),
            ]),
            "创建目录",
            &[-8, 31061],
        )
        .await
        .map(|_| ())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        let file_list = serde_json::to_string(&[self.remote_path(path)]).unwrap();
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[("method", "filemanager".into()), ("opera", "delete".into())],
            Some(&[
                ("async".into(), "0".into()),
                ("filelist".into(), file_list),
                ("ondup".into(), "fail".into()),
            ]),
            "删除",
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法移动或重命名路径".into()));
        }
        let from = self.remote_path(from);
        let to = self.remote_path(to);
        let (from_parent, _) = from
            .rsplit_once('/')
            .ok_or_else(|| ApiError::BadRequest("非法来源路径".into()))?;
        let (to_parent, new_name) = to
            .rsplit_once('/')
            .ok_or_else(|| ApiError::BadRequest("非法目标路径".into()))?;
        let (operation, file_list) = if from_parent == to_parent {
            (
                "rename",
                json!([{"path": from, "newname": new_name}]).to_string(),
            )
        } else {
            let destination = if to_parent.is_empty() { "/" } else { to_parent };
            (
                "move",
                json!([{"path": from, "dest": destination, "newname": new_name}]).to_string(),
            )
        };
        self.xpan_request(
            Method::POST,
            "xpan/file",
            &[
                ("method", "filemanager".into()),
                ("opera", operation.into()),
            ],
            Some(&[
                ("async".into(), "0".into()),
                ("filelist".into(), file_list),
                ("ondup".into(), "fail".into()),
            ]),
            "移动或重命名",
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        let resp = self
            .download_response(&self.remote_path(path), None)
            .await?;
        let size = resp.content_length();
        Ok((
            size,
            resp.bytes_stream().map_err(std::io::Error::other).boxed(),
        ))
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        if end < start || end - start + 1 > MAX_PREVIEW_RANGE {
            return Err(ApiError::BadRequest(
                "百度网盘单个下载分片必须在 1..=5MiB".into(),
            ));
        }
        let resp = self
            .download_response(&self.remote_path(path), Some((start, end)))
            .await?;
        if resp.status() != StatusCode::PARTIAL_CONTENT {
            return Err(ApiError::Upstream(format!(
                "百度网盘忽略 Range 请求，返回 {}",
                resp.status()
            )));
        }
        let expected = format!("bytes {start}-{end}/");
        let actual = resp
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !actual.starts_with(&expected) {
            return Err(ApiError::Upstream(format!(
                "百度网盘 Content-Range 不匹配: 期望 {expected}*, 实际 {actual}"
            )));
        }
        Ok(resp.bytes_stream().map_err(std::io::Error::other).boxed())
    }

    async fn put(&self, path: &str, mut body: ByteStream) -> ApiResult<()> {
        const MAX_BUFFERED: usize = 512 * 1024 * 1024;
        let mut bytes = BytesMut::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > MAX_BUFFERED {
                return Err(ApiError::BadRequest(
                    "百度网盘未知长度上传超过 512MiB".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let size = bytes.len() as u64;
        self.upload_sized(
            path,
            size,
            stream::once(async move { Ok(bytes.freeze()) }).boxed(),
        )
        .await
    }

    async fn put_sized(&self, path: &str, size: u64, body: ByteStream) -> ApiResult<()> {
        self.upload_sized(path, size, body).await
    }
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value)
    })
}

fn normalize_root(root: &str) -> ApiResult<String> {
    let root = root.trim().replace('\\', "/");
    if root.contains("..") || root.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(ApiError::BadRequest("百度网盘根目录非法".into()));
    }
    let normalized = format!("/{}", root.trim_matches('/'));
    Ok(if normalized == "/" {
        normalized
    } else {
        normalized.trim_end_matches('/').to_owned()
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;
    use axum::body::Body;
    use axum::extract::{Form as AxumForm, Query, State};
    use axum::http::{HeaderMap, Response};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};

    fn config(base: &str) -> Value {
        json!({
            "cookie": "BDUSS=test; BAIDUID=must-not-be-sent",
            "clientId": "client-id",
            "clientSecret": "client-secret",
            "accessToken": "expired-token",
            "refreshToken": "refresh-old",
            "root": "/safe",
            "userAgent": "download-android-test",
            "openApiBase": format!("{base}/rest/2.0/"),
            "oauthTokenUrl": format!("{base}/oauth/token"),
            "pcsApiBase": format!("{base}/rest/2.0/pcs/file"),
            "uploadApiBase": format!("{base}/rest/2.0/pcs/superfile2")
        })
    }

    #[test]
    fn validates_config_and_paths() {
        let base = "http://127.0.0.1:1";
        let fs =
            BaiduPanFs::from_config_with_persister(&config(base), Client::new(), None).unwrap();
        assert_eq!(fs.remote_path(""), "/safe");
        assert_eq!(fs.remote_path("a/b"), "/safe/a/b");
        assert_eq!(fs.max_range_size(), Some(5 * 1024 * 1024));
        let mut invalid = config(base);
        invalid.as_object_mut().unwrap().remove("refreshToken");
        assert!(BaiduPanFs::from_config_with_persister(&invalid, Client::new(), None).is_err());
        assert!(normalize_root("/a/../b").is_err());
    }

    #[tokio::test]
    async fn spooling_uses_real_openlist_compatible_hashes_and_cleans_up() {
        let fs = BaiduPanFs::from_config_with_persister(
            &config("http://127.0.0.1:1"),
            Client::new(),
            None,
        )
        .unwrap();
        let data = (0..UPLOAD_BLOCK_SIZE + 37)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let chunks = vec![
            Bytes::copy_from_slice(&data[..123_457]),
            Bytes::copy_from_slice(&data[123_457..3_500_001]),
            Bytes::copy_from_slice(&data[3_500_001..]),
        ];
        let spooled = fs
            .spool_upload(
                data.len() as u64,
                stream::iter(chunks.into_iter().map(Ok)).boxed(),
            )
            .await
            .unwrap();
        assert_eq!(spooled.block_md5.len(), 2);
        assert_eq!(
            spooled.block_md5[0],
            hex::encode(Md5::digest(&data[..UPLOAD_BLOCK_SIZE]))
        );
        assert_eq!(
            spooled.block_md5[1],
            hex::encode(Md5::digest(&data[UPLOAD_BLOCK_SIZE..]))
        );
        assert_eq!(spooled.content_md5, hex::encode(Md5::digest(&data)));
        assert_eq!(
            spooled.slice_md5,
            hex::encode(Md5::digest(&data[..256 * 1024]))
        );
        let temp_path = spooled.temp.path.clone();
        assert!(temp_path.exists());
        drop(spooled);
        assert!(!temp_path.exists());
    }

    fn assert_open_headers(headers: &HeaderMap) {
        assert!(headers.get(COOKIE).is_none(), "开放平台请求不得携带 Cookie");
        let ua = headers.get(USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.starts_with("Mozilla/5.0"));
        assert!(!ua.to_ascii_lowercase().contains("android"));
    }

    async fn oauth_token(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(
            query.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            query.get("refresh_token").map(String::as_str),
            Some("refresh-old")
        );
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("client-id")
        );
        Json(json!({
            "access_token": "fresh-token",
            "refresh_token": "refresh-new",
            "expires_in": 3600
        }))
    }

    async fn xpan_get(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(query.get("method").map(String::as_str), Some("list"));
        if query.get("access_token").map(String::as_str) == Some("expired-token") {
            return Json(json!({"errno": 111}));
        }
        assert_eq!(
            query.get("access_token").map(String::as_str),
            Some("fresh-token")
        );
        assert_eq!(query.get("dir").map(String::as_str), Some("/safe"));
        Json(json!({
            "errno": 0,
            "list": [{
                "server_filename": "cipher-dir",
                "isdir": 1,
                "size": 0,
                "server_mtime": 123
            }]
        }))
    }

    async fn xpan_post(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
        AxumForm(form): AxumForm<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(
            query.get("access_token").map(String::as_str),
            Some("fresh-token")
        );
        match query.get("method").map(String::as_str) {
            Some("precreate") => {
                assert_eq!(form.get("path").map(String::as_str), Some("/safe/volume"));
                assert_eq!(form.get("size").map(String::as_str), Some("4"));
                assert_eq!(
                    form.get("content-md5").map(String::as_str),
                    Some("8d777f385d3dfec8815d20f7496026dc")
                );
                Json(
                    json!({"errno": 0, "return_type": 1, "uploadid": "upload-1", "block_list": [0]}),
                )
            }
            Some("create") | Some("filemanager") => Json(json!({"errno": 0})),
            other => panic!("unexpected xpan operation: {other:?}"),
        }
    }

    async fn upload_block(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_open_headers(&headers);
        assert_eq!(
            query.get("access_token").map(String::as_str),
            Some("fresh-token")
        );
        assert_eq!(query.get("uploadid").map(String::as_str), Some("upload-1"));
        Json(json!({"errno": 0, "md5": "8d777f385d3dfec8815d20f7496026dc"}))
    }

    async fn locatedownload(
        State(download_url): State<String>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(
            query.get("method").map(String::as_str),
            Some("locatedownload")
        );
        assert_eq!(headers.get(USER_AGENT).unwrap(), "download-android-test");
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
        Json(json!({"urls": [{"url": download_url}]}))
    }

    async fn download(headers: HeaderMap) -> Response<Body> {
        assert_eq!(headers.get(RANGE).unwrap(), "bytes=2-5");
        assert_eq!(headers.get(USER_AGENT).unwrap(), "download-android-test");
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(CONTENT_RANGE, "bytes 2-5/10")
            .body(Body::from("2345"))
            .unwrap()
    }

    #[tokio::test]
    async fn oauth_crud_upload_and_cookie_download_work_end_to_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let app = Router::new()
            .route("/oauth/token", get(oauth_token))
            .route("/rest/2.0/xpan/file", get(xpan_get).post(xpan_post))
            .route("/rest/2.0/pcs/superfile2", post(upload_block))
            .route("/rest/2.0/pcs/file", get(locatedownload))
            .route("/download", get(download))
            .with_state(format!("{base}/download"));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let persisted = Arc::new(StdMutex::new(None));
        let persisted_for_callback = Arc::clone(&persisted);
        let persister: TokenPersister = Arc::new(move |access, refresh| {
            *persisted_for_callback.lock().unwrap() = Some((access.to_owned(), refresh.to_owned()));
            Ok(())
        });
        let fs =
            BaiduPanFs::from_config_with_persister(&config(&base), Client::new(), Some(persister))
                .unwrap();
        let entries = fs.list("").await.unwrap();
        assert_eq!(entries[0].name, "cipher-dir");
        assert_eq!(entries[0].mtime, 123_000);
        assert_eq!(
            *persisted.lock().unwrap(),
            Some(("fresh-token".into(), "refresh-new".into()))
        );
        fs.mkdir("new").await.unwrap();
        fs.rename("new", "renamed").await.unwrap();
        fs.delete("renamed").await.unwrap();
        fs.put_sized(
            "volume",
            4,
            stream::once(async { Ok(Bytes::from_static(b"data")) }).boxed(),
        )
        .await
        .unwrap();

        let mut stream = fs.get_range("volume", 2, 5).await.unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"2345");
    }
}
