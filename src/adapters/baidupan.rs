//! 百度网盘 Cookie 适配器。
//!
//! 列目录使用网页版 Pan API（完整 Cookie + 浏览器 UA），写操作沿用
//! BaiduPCS-Go 的 Cookie 版 PCS API（同样使用浏览器 UA）。只有下载链接和
//! CDN 请求采用 onepan `get_download_url1` 的 Android UA。该链接单次 Range
//! 可靠上限为 5 MiB，下载引擎会据此自动缩小分片。

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::header::{CONTENT_RANGE, COOKIE, HeaderValue, RANGE, USER_AGENT};
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::{ByteStream, Entry, Storage};
use crate::error::{ApiError, ApiResult};

const PCS_FILE_API: &str = "https://pcs.baidu.com/rest/2.0/pcs/file";
const PAN_API: &str = "https://pan.baidu.com/api/";
const PCS_UPLOAD_API: &str = "https://d.pcs.baidu.com/rest/2.0/pcs/superfile2";
const PAN_APP_ID: &str = "250528";
const DEFAULT_DOWNLOAD_UA: &str = "netdisk;P2SP;2.2.61.31;android";
const DEFAULT_WEB_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const MAX_PREVIEW_RANGE: u64 = 5 * 1024 * 1024;
const LINK_TTL: Duration = Duration::from_secs(120);
const TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
const UPLOAD_BLOCK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Clone)]
struct CachedLinks {
    inserted: Instant,
    urls: Vec<String>,
}

#[derive(Clone)]
struct CachedToken {
    inserted: Instant,
    value: String,
}

pub struct BaiduPanFs {
    root: String,
    pcs_api_base: Url,
    pan_api_base: Url,
    upload_api_base: Url,
    cookie: HeaderValue,
    download_cookie: HeaderValue,
    web_user_agent: HeaderValue,
    download_user_agent: HeaderValue,
    http: Client,
    links: Mutex<HashMap<String, CachedLinks>>,
    link_locks: Mutex<HashMap<String, std::sync::Arc<Mutex<()>>>>,
    bdstoken: Mutex<Option<CachedToken>>,
}

#[derive(Debug, Deserialize)]
struct BaiduListItem {
    server_filename: String,
    #[serde(default)]
    isdir: i8,
    #[serde(default)]
    size: u64,
    #[serde(default, alias = "server_mtime")]
    mtime: u64,
}

impl BaiduPanFs {
    pub fn from_config(config: &Value, http: Client) -> ApiResult<Self> {
        let cookie_text = config
            .get("cookie")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::BadRequest("百度网盘配置缺少 cookie".into()))?;
        let bduss = cookie_value(cookie_text, "BDUSS")
            .ok_or_else(|| ApiError::BadRequest("百度网盘 cookie 中缺少 BDUSS".into()))?;
        let cookie = HeaderValue::from_str(cookie_text)
            .map_err(|_| ApiError::BadRequest("百度网盘 cookie 含非法字符".into()))?;
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
        .map_err(|_| ApiError::BadRequest("百度网盘 User-Agent 含非法字符".into()))?;
        let root = normalize_root(
            config
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or("/safedrive"),
        )?;
        let legacy_api_base = config.get("apiBase").and_then(Value::as_str);
        let pcs_api_base = Url::parse(
            config
                .get("pcsApiBase")
                .and_then(Value::as_str)
                .or(legacy_api_base)
                .unwrap_or(PCS_FILE_API),
        )
        .map_err(|e| ApiError::BadRequest(format!("百度网盘 pcsApiBase 无效: {e}")))?;
        let pan_api_base = Url::parse(
            config
                .get("panApiBase")
                .and_then(Value::as_str)
                .or(legacy_api_base)
                .unwrap_or(PAN_API),
        )
        .map_err(|e| ApiError::BadRequest(format!("百度网盘 panApiBase 无效: {e}")))?;
        let upload_api_base = Url::parse(
            config
                .get("uploadApiBase")
                .and_then(Value::as_str)
                .or(legacy_api_base)
                .unwrap_or(PCS_UPLOAD_API),
        )
        .map_err(|e| ApiError::BadRequest(format!("百度网盘 uploadApiBase 无效: {e}")))?;
        if !matches!(pcs_api_base.scheme(), "http" | "https")
            || !matches!(pan_api_base.scheme(), "http" | "https")
            || !matches!(upload_api_base.scheme(), "http" | "https")
        {
            return Err(ApiError::BadRequest(
                "百度网盘 API 地址必须是 http(s)".into(),
            ));
        }
        Ok(Self {
            root,
            pcs_api_base,
            pan_api_base,
            upload_api_base,
            cookie,
            download_cookie,
            web_user_agent: HeaderValue::from_static(DEFAULT_WEB_UA),
            download_user_agent,
            http,
            links: Mutex::new(HashMap::new()),
            link_locks: Mutex::new(HashMap::new()),
            bdstoken: Mutex::new(None),
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

    fn pan_url(&self, endpoint: &str) -> ApiResult<Url> {
        self.pan_api_base
            .join(endpoint)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("构造百度网盘 API 地址失败: {e}")))
    }

    fn web_request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(USER_AGENT, self.web_user_agent.clone())
            .header(COOKIE, self.cookie.clone())
    }

    fn add_web_query(url: &mut Url, bdstoken: Option<&str>) {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("clienttype", "0")
            .append_pair("app_id", PAN_APP_ID)
            .append_pair("web", "1");
        if let Some(token) = bdstoken {
            query.append_pair("bdstoken", token);
        }
    }

    async fn response_json(resp: reqwest::Response, what: &str) -> ApiResult<Value> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ApiError::Upstream(format!("读取百度网盘{what}响应失败: {e}")))?;
        if !status.is_success() {
            return Err(ApiError::Upstream(format!(
                "百度网盘{what}失败 ({status}): {}",
                text.chars().take(300).collect::<String>()
            )));
        }
        if text.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&text)
            .map_err(|e| ApiError::Upstream(format!("解析百度网盘{what}响应失败: {e}; {text}")))
    }

    fn ensure_api_ok(value: &Value, what: &str, allowed: &[i64]) -> ApiResult<()> {
        let code = value
            .get("error_code")
            .or_else(|| value.get("errno"))
            .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
            .unwrap_or(0);
        if code == 0 || allowed.contains(&code) {
            return Ok(());
        }
        let message = value
            .get("error_msg")
            .or_else(|| value.get("errmsg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        if matches!(code, 31066 | -9) {
            return Err(ApiError::NotFound(format!("百度网盘{what}: 不存在")));
        }
        Err(ApiError::Upstream(format!(
            "百度网盘{what}失败: code={code}, {message}"
        )))
    }

    async fn bdstoken(&self) -> ApiResult<String> {
        let mut cached = self.bdstoken.lock().await;
        if let Some(hit) = cached.as_ref()
            && hit.inserted.elapsed() < TOKEN_TTL
        {
            return Ok(hit.value.clone());
        }
        let mut url = self.pan_url("gettemplatevariable")?;
        Self::add_web_query(&mut url, None);
        url.query_pairs_mut()
            .append_pair("fields", r#"["bdstoken"]"#);
        let resp = self
            .web_request(Method::GET, url)
            .header("X-Requested-With", "XMLHttpRequest")
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("百度网盘获取 bdstoken 失败: {e}")))?;
        let value = Self::response_json(resp, "获取 bdstoken").await?;
        Self::ensure_api_ok(&value, "获取 bdstoken", &[])?;
        let token = value
            .pointer("/result/bdstoken")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ApiError::Upstream("百度网盘未返回 bdstoken，请更新 Cookie".into()))?
            .to_owned();
        *cached = Some(CachedToken {
            inserted: Instant::now(),
            value: token.clone(),
        });
        Ok(token)
    }

    async fn web_form_api(
        &self,
        endpoint: &str,
        operation: &str,
        extra_query: &[(&str, &str)],
        form: &[(String, String)],
        allowed: &[i64],
    ) -> ApiResult<Value> {
        let token = self.bdstoken().await?;
        let mut url = self.pan_url(endpoint)?;
        Self::add_web_query(&mut url, Some(&token));
        url.query_pairs_mut()
            .extend_pairs(extra_query.iter().copied());
        let resp = self
            .web_request(Method::POST, url)
            .header("X-Requested-With", "XMLHttpRequest")
            .form(form)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("百度网盘{operation}请求失败: {e}")))?;
        let value = Self::response_json(resp, operation).await?;
        Self::ensure_api_ok(&value, operation, allowed)?;
        Ok(value)
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
            std::sync::Arc::clone(
                locks
                    .entry(remote_path.to_string())
                    .or_insert_with(|| std::sync::Arc::new(Mutex::new(()))),
            )
        };
        let _path_guard = path_lock.lock().await;
        if !force {
            let links = self.links.lock().await;
            if let Some(hit) = links.get(remote_path)
                && hit.inserted.elapsed() < LINK_TTL
            {
                return Ok(hit.urls.clone());
            }
        }

        let mut url = self.pcs_api_base.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let random = uuid::Uuid::new_v4().simple().to_string();
        {
            // 与 onepan File.get_download_url1 保持一致；time/rand 改为动态值。
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
            remote_path.to_string(),
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
                .map_err(|e| ApiError::Upstream(format!("百度网盘返回了非法下载链接: {e}")))?;
            let mut req = self
                .http
                .get(url)
                .header(USER_AGENT, self.download_user_agent.clone())
                .header(COOKIE, self.download_cookie.clone());
            if let Some((start, end)) = range {
                req = req.header(RANGE, format!("bytes={start}-{end}"));
            }
            let resp = req
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

    async fn upload_block(
        &self,
        remote: &str,
        upload_id: &str,
        part_seq: usize,
        block: bytes::Bytes,
    ) -> ApiResult<String> {
        let mut url = self.upload_api_base.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("method", "upload")
                .append_pair("app_id", PAN_APP_ID)
                .append_pair("type", "tmpfile")
                .append_pair("path", remote)
                .append_pair("uploadid", upload_id)
                .append_pair("partseq", &part_seq.to_string());
        }
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
        let value = Self::response_json(resp, "上传文件块").await?;
        Self::ensure_api_ok(&value, "上传文件块", &[])?;
        value
            .get("md5")
            .and_then(Value::as_str)
            .filter(|md5| md5.len() == 32)
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Upstream(format!("百度网盘上传文件块未返回 md5: {value}")))
    }

    async fn upload_sized(&self, path: &str, size: u64, mut body: ByteStream) -> ApiResult<()> {
        let remote = self.remote_path(path);
        let block_count = size.div_ceil(UPLOAD_BLOCK_SIZE as u64) as usize;
        // precreate 只需要合法的 MD5 形状来取得 uploadid；真正提交时使用各块上传响应的 MD5。
        let placeholders = (0..block_count)
            .map(|index| format!("{:032x}", index + 1))
            .collect::<Vec<_>>();
        let precreate = self
            .web_form_api(
                "precreate",
                "预创建上传",
                &[],
                &[
                    ("path".into(), remote.clone()),
                    ("size".into(), size.to_string()),
                    ("isdir".into(), "0".into()),
                    ("autoinit".into(), "1".into()),
                    ("rtype".into(), "3".into()),
                    (
                        "block_list".into(),
                        serde_json::to_string(&placeholders).unwrap(),
                    ),
                ],
                &[],
            )
            .await?;
        let upload_id = precreate
            .get("uploadid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ApiError::Upstream(format!("百度网盘预创建未返回 uploadid: {precreate}"))
            })?
            .to_owned();

        let mut received = 0u64;
        let mut part_seq = 0usize;
        let mut pending = BytesMut::with_capacity(UPLOAD_BLOCK_SIZE);
        let mut block_md5 = Vec::with_capacity(block_count);
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            received = received.saturating_add(chunk.len() as u64);
            if received > size {
                return Err(ApiError::BadRequest("上传数据超过声明大小".into()));
            }
            let mut offset = 0usize;
            while offset < chunk.len() {
                let take = (UPLOAD_BLOCK_SIZE - pending.len()).min(chunk.len() - offset);
                pending.extend_from_slice(&chunk[offset..offset + take]);
                offset += take;
                if pending.len() == UPLOAD_BLOCK_SIZE {
                    let block = pending.split().freeze();
                    block_md5.push(
                        self.upload_block(&remote, &upload_id, part_seq, block)
                            .await?,
                    );
                    part_seq += 1;
                }
            }
        }
        if received != size {
            return Err(ApiError::BadRequest(format!(
                "上传数据大小不匹配: 声明 {size}，实际 {received}"
            )));
        }
        if !pending.is_empty() {
            block_md5.push(
                self.upload_block(&remote, &upload_id, part_seq, pending.freeze())
                    .await?,
            );
        }
        if block_md5.len() != block_count {
            return Err(ApiError::Upstream(format!(
                "百度网盘上传块数不匹配: 预期 {block_count}，实际 {}",
                block_md5.len()
            )));
        }
        let target_path = remote.rsplit_once('/').map_or_else(
            || "/".to_owned(),
            |(parent, _)| {
                if parent.is_empty() {
                    "/".to_owned()
                } else {
                    parent.to_owned()
                }
            },
        );
        self.web_form_api(
            "create",
            "合并上传文件",
            &[("a", "commit")],
            &[
                ("uploadid".into(), upload_id),
                ("path".into(), remote),
                ("size".into(), size.to_string()),
                ("isdir".into(), "0".into()),
                ("rtype".into(), "3".into()),
                (
                    "block_list".into(),
                    serde_json::to_string(&block_md5).unwrap(),
                ),
                ("target_path".into(), target_path),
            ],
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
        const PAGE_SIZE: usize = 1000;
        let mut entries = Vec::new();
        for page in 1..=10_000usize {
            let mut url = self.pan_url("list")?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("clienttype", "0")
                    .append_pair("app_id", PAN_APP_ID)
                    .append_pair("web", "1")
                    .append_pair("dir", &remote)
                    .append_pair("order", "name")
                    .append_pair("desc", "0")
                    .append_pair("num", &PAGE_SIZE.to_string())
                    .append_pair("page", &page.to_string());
            }
            let resp = self
                .web_request(Method::GET, url)
                .header("X-Requested-With", "XMLHttpRequest")
                .send()
                .await
                .map_err(|e| ApiError::Upstream(format!("百度网盘列目录请求失败: {e}")))?;
            let value = Self::response_json(resp, "列目录").await?;
            Self::ensure_api_ok(&value, "列目录", &[])?;
            let items: Vec<BaiduListItem> =
                serde_json::from_value(value.get("list").cloned().unwrap_or_else(|| json!([])))
                    .map_err(|e| ApiError::Upstream(format!("解析百度网盘目录条目失败: {e}")))?;
            let item_count = items.len();
            entries.extend(items.into_iter().map(|item| Entry {
                name: item.server_filename,
                is_dir: item.isdir == 1,
                size: item.size,
                mtime: item.mtime.saturating_mul(1000),
            }));
            let has_more = value
                .get("has_more")
                .and_then(Value::as_i64)
                .is_some_and(|v| v != 0);
            if !has_more && item_count < PAGE_SIZE {
                return Ok(entries);
            }
        }
        Err(ApiError::Upstream("百度网盘列目录分页超过安全上限".into()))
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        let remote = self.remote_path(path);
        self.web_form_api(
            "create",
            "创建目录",
            &[("a", "commit")],
            &[
                ("path".into(), remote),
                ("isdir".into(), "1".into()),
                ("size".into(), "0".into()),
                ("block_list".into(), "[]".into()),
                ("rtype".into(), "3".into()),
            ],
            // 目录已存在；连接测试会在并发初始化时容忍该结果。
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
        self.web_form_api(
            "filemanager",
            "删除",
            &[
                ("opera", "delete"),
                ("async", "2"),
                ("onnest", "fail"),
                ("newVerify", "1"),
            ],
            &[("filelist".into(), file_list)],
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法重命名路径".into()));
        }
        let from = self.remote_path(from);
        let to = self.remote_path(to);
        let (dest, new_name) = to
            .rsplit_once('/')
            .ok_or_else(|| ApiError::BadRequest("百度网盘目标路径缺少文件名".into()))?;
        let dest = if dest.is_empty() {
            "/".to_owned()
        } else {
            format!("{dest}/")
        };
        let file_list = json!([{
            "path": from,
            "dest": dest,
            "newname": new_name,
            "ondup": "fail"
        }])
        .to_string();
        self.web_form_api(
            "filemanager",
            "移动或重命名",
            &[
                ("opera", "move"),
                ("async", "2"),
                ("onnest", "fail"),
                ("newVerify", "1"),
            ],
            &[("filelist".into(), file_list)],
            &[],
        )
        .await
        .map(|_| ())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        let remote = self.remote_path(path);
        let resp = self.download_response(&remote, None).await?;
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
        let remote = self.remote_path(path);
        let resp = self.download_response(&remote, Some((start, end))).await?;
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
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !actual.starts_with(&expected) {
            return Err(ApiError::Upstream(format!(
                "百度网盘 Content-Range 不匹配: 期望 {expected}*, 实际 {actual}"
            )));
        }
        Ok(resp.bytes_stream().map_err(std::io::Error::other).boxed())
    }

    async fn put(&self, path: &str, mut body: ByteStream) -> ApiResult<()> {
        // 非引擎调用没有长度信息，只用于兼容 Storage 接口；限制内存上界。
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
        let len = bytes.len() as u64;
        self.upload_sized(
            path,
            len,
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
    if root.contains("..") || root.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ApiError::BadRequest("百度网盘根目录非法".into()));
    }
    let normalized = format!("/{}", root.trim_matches('/'));
    Ok(if normalized == "/" {
        normalized
    } else {
        normalized.trim_end_matches('/').to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, Response};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Form as AxumForm, Json, Router};

    #[test]
    fn parses_cookie_and_normalizes_root() {
        assert_eq!(
            cookie_value("BAIDUID=x; BDUSS=abc=; STOKEN=y", "BDUSS"),
            Some("abc=")
        );
        assert_eq!(
            normalize_root(" /apps/safedrive/ ").unwrap(),
            "/apps/safedrive"
        );
        assert_eq!(normalize_root("/").unwrap(), "/");
        assert!(normalize_root("/a/../b").is_err());
    }

    #[test]
    fn validates_config_and_remote_paths() {
        let http = Client::new();
        let fs = BaiduPanFs::from_config(
            &json!({"cookie": "BDUSS=test; BAIDUID=x", "root": "/safe"}),
            http,
        )
        .unwrap();
        assert_eq!(fs.remote_path(""), "/safe");
        assert_eq!(fs.remote_path("a/b"), "/safe/a/b");
        assert_eq!(fs.max_range_size(), Some(5 * 1024 * 1024));
        assert!(BaiduPanFs::from_config(&json!({"cookie": "BAIDUID=x"}), Client::new()).is_err());
    }

    async fn mock_pan_list(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        let ua = headers.get(USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.starts_with("Mozilla/5.0"));
        assert!(!ua.to_ascii_lowercase().contains("android"));
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test; BAIDUID=x");
        assert_eq!(headers.get("X-Requested-With").unwrap(), "XMLHttpRequest");
        assert_eq!(query.get("dir").map(String::as_str), Some("/safe"));
        assert_eq!(query.get("app_id").map(String::as_str), Some(PAN_APP_ID));
        assert_eq!(query.get("clienttype").map(String::as_str), Some("0"));
        assert_eq!(query.get("web").map(String::as_str), Some("1"));
        assert_eq!(query.get("page").map(String::as_str), Some("1"));
        Json(json!({
            "errno": 0,
            "has_more": 0,
            "list": [{
                "server_filename": "cipher-dir",
                "isdir": 1,
                "size": 0,
                "server_mtime": 123
            }]
        }))
    }

    fn assert_web_headers(headers: &HeaderMap) {
        let ua = headers.get(USER_AGENT).unwrap().to_str().unwrap();
        assert!(ua.starts_with("Mozilla/5.0"));
        assert!(!ua.to_ascii_lowercase().contains("android"));
        assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test; BAIDUID=x");
    }

    async fn mock_token(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_web_headers(&headers);
        assert_eq!(
            query.get("fields").map(String::as_str),
            Some(r#"["bdstoken"]"#)
        );
        Json(json!({"errno": 0, "result": {"bdstoken": "web-token"}}))
    }

    async fn mock_web_write(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
        AxumForm(form): AxumForm<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_web_headers(&headers);
        assert_eq!(query.get("bdstoken").map(String::as_str), Some("web-token"));
        assert!(form.contains_key("path") || form.contains_key("filelist"));
        Json(json!({"errno": 0}))
    }

    async fn mock_precreate(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
        AxumForm(form): AxumForm<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_web_headers(&headers);
        assert_eq!(query.get("bdstoken").map(String::as_str), Some("web-token"));
        assert_eq!(form.get("path").map(String::as_str), Some("/safe/volume"));
        assert_eq!(form.get("size").map(String::as_str), Some("4"));
        Json(json!({"errno": 0, "uploadid": "upload-1"}))
    }

    async fn mock_upload(
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_web_headers(&headers);
        assert_eq!(query.get("method").map(String::as_str), Some("upload"));
        assert_eq!(query.get("uploadid").map(String::as_str), Some("upload-1"));
        Json(json!({"error_code": 0, "md5": "0123456789abcdef0123456789abcdef"}))
    }

    async fn mock_pcs_api(
        State(download_url): State<String>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        match query.get("method").map(String::as_str) {
            Some("locatedownload") => {
                assert_eq!(headers.get(USER_AGENT).unwrap(), "download-android-test");
                assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test");
                Json(json!({"urls": [{"url": download_url}]}))
            }
            _ => {
                let ua = headers.get(USER_AGENT).unwrap().to_str().unwrap();
                assert!(ua.starts_with("Mozilla/5.0"));
                assert!(!ua.to_ascii_lowercase().contains("android"));
                assert_eq!(headers.get(COOKIE).unwrap(), "BDUSS=test; BAIDUID=x");
                Json(json!({}))
            }
        }
    }

    async fn mock_download(headers: HeaderMap) -> Response<Body> {
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
    async fn cookie_api_and_preview_range_work_end_to_end() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let app = Router::new()
            .route("/api/list", get(mock_pan_list))
            .route("/api/gettemplatevariable", get(mock_token))
            .route("/api/create", axum::routing::post(mock_web_write))
            .route("/api/filemanager", axum::routing::post(mock_web_write))
            .route("/api/precreate", axum::routing::post(mock_precreate))
            .route("/upload", axum::routing::post(mock_upload))
            .route("/rest/2.0/pcs/file", get(mock_pcs_api).post(mock_pcs_api))
            .route("/download", get(mock_download))
            .with_state(format!("{base}/download"));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let fs = BaiduPanFs::from_config(
            &json!({
                "cookie": "BDUSS=test; BAIDUID=x",
                "root": "/safe",
                "userAgent": "download-android-test",
                "panApiBase": format!("{base}/api/"),
                "pcsApiBase": format!("{base}/rest/2.0/pcs/file"),
                "uploadApiBase": format!("{base}/upload")
            }),
            Client::new(),
        )
        .unwrap();
        let entries = fs.list("").await.unwrap();
        assert_eq!(entries[0].name, "cipher-dir");
        assert_eq!(entries[0].mtime, 123_000);
        fs.mkdir("new").await.unwrap();
        fs.rename("new", "renamed").await.unwrap();
        fs.delete("renamed").await.unwrap();
        fs.put_sized(
            "volume",
            4,
            stream::once(async { Ok(bytes::Bytes::from_static(b"data")) }).boxed(),
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
