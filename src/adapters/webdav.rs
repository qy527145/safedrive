use async_trait::async_trait;
use futures_util::{StreamExt, TryStreamExt};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqwest::{Client, Method, StatusCode};

use super::{ByteStream, Entry, Storage};
use crate::error::{ApiError, ApiResult};

/// RFC 3986 unreserved 之外全部转义（段内不含 '/'）。
const SEG_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// WebDAV 适配器：服务端代理转发（免浏览器 CORS），仅 Basic 认证。
pub struct WebdavFs {
    /// 形如 https://host[:port]/dav（无尾斜杠）
    base: String,
    /// base 的路径部分（用于剥离 PROPFIND href 前缀）
    base_path: String,
    username: Option<String>,
    password: String,
    http: Client,
}

impl WebdavFs {
    pub fn from_config(config: &serde_json::Value, http: Client) -> ApiResult<Self> {
        let url = config
            .get("url")
            .and_then(|v| v.as_str())
            .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
            .ok_or_else(|| ApiError::BadRequest("webdav 配置缺少合法 url".into()))?;
        let base = url.trim_end_matches('/').to_string();
        let base_path = reqwest::Url::parse(&base)
            .map_err(|e| ApiError::BadRequest(format!("webdav url 无效: {e}")))?
            .path()
            .trim_end_matches('/')
            .to_string();
        let username = config
            .get("username")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let password = config
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Self {
            base,
            base_path,
            username,
            password,
            http,
        })
    }

    fn url_for(&self, rel: &str) -> String {
        if rel.is_empty() {
            return format!("{}/", self.base);
        }
        let encoded: Vec<String> = rel
            .split('/')
            .map(|seg| utf8_percent_encode(seg, SEG_ENCODE).to_string())
            .collect();
        format!("{}/{}", self.base, encoded.join("/"))
    }

    fn request(&self, method: Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.request(method, url);
        if let Some(user) = &self.username {
            req = req.basic_auth(user, Some(&self.password));
        }
        req
    }

    async fn expect_ok(resp: reqwest::Response, what: &str) -> ApiResult<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        if status == StatusCode::NOT_FOUND {
            // 判存走这里属常态，不打错误日志
            return Err(ApiError::NotFound(format!("{what}: 不存在")));
        }
        // 凭据在 Basic 头里，URL 可整体落日志
        let url = resp.url().clone();
        let headers = super::log_headers(resp.headers());
        let body = resp.text().await.unwrap_or_default();
        let body_log = if body.trim().is_empty() {
            "(空)".to_string()
        } else {
            body.chars().take(4096).collect()
        };
        tracing::error!(
            "WebDAV {what}失败: {status} url={url} 响应头: {headers} 原始响应: {body_log}"
        );
        let snippet: String = if body.trim().is_empty() {
            "(空响应体，详见日志文件)".to_string()
        } else {
            body.chars().take(200).collect()
        };
        Err(ApiError::Upstream(format!(
            "{what} 失败 ({status}): {snippet}"
        )))
    }
}

#[async_trait]
impl Storage for WebdavFs {
    fn download_profile_key(&self) -> Option<String> {
        let url = reqwest::Url::parse(&self.base).ok()?;
        Some(format!(
            "webdav:{}:{}",
            url.host_str()?,
            url.port_or_known_default().unwrap_or(0)
        ))
    }

    async fn list(&self, path: &str) -> ApiResult<Vec<Entry>> {
        const BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop>
<D:resourcetype/><D:getcontentlength/><D:getlastmodified/>
</D:prop></D:propfind>"#;
        let url = self.url_for(path);
        let resp = self
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .header("Depth", "1")
            .header("Content-Type", "application/xml")
            .body(BODY)
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("PROPFIND 请求失败: {e}")))?;
        let resp = Self::expect_ok(resp, "列目录").await?;
        let xml = resp
            .text()
            .await
            .map_err(|e| ApiError::Upstream(format!("读取 PROPFIND 响应失败: {e}")))?;

        let self_path = normalize_path(&format!("{}/{}", self.base_path, path));
        let items = parse_multistatus(&xml)
            .map_err(|e| ApiError::Upstream(format!("解析 PROPFIND 响应失败: {e}")))?;
        let mut entries = Vec::new();
        for item in items {
            if normalize_path(&item.path) == self_path {
                continue; // 集合自身
            }
            let name = item
                .path
                .rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            entries.push(Entry {
                id: None,
                name,
                is_dir: item.is_dir,
                size: item.size,
                mtime: item.mtime,
            });
        }
        Ok(entries)
    }

    async fn mkdir(&self, path: &str) -> ApiResult<()> {
        let resp = self
            .request(Method::from_bytes(b"MKCOL").unwrap(), &self.url_for(path))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("MKCOL 请求失败: {e}")))?;
        // 405 = 已存在，视为幂等成功
        if resp.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Ok(());
        }
        Self::expect_ok(resp, "创建目录").await.map(|_| ())
    }

    async fn delete(&self, path: &str) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("不允许删除数据源根目录".into()));
        }
        let resp = self
            .request(Method::DELETE, &self.url_for(path))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("DELETE 请求失败: {e}")))?;
        Self::expect_ok(resp, "删除").await.map(|_| ())
    }

    async fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        if from.is_empty() || to.is_empty() {
            return Err(ApiError::BadRequest("非法重命名路径".into()));
        }
        let resp = self
            .request(Method::from_bytes(b"MOVE").unwrap(), &self.url_for(from))
            .header("Destination", self.url_for(to))
            .header("Overwrite", "F")
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("MOVE 请求失败: {e}")))?;
        Self::expect_ok(resp, "重命名/移动").await.map(|_| ())
    }

    async fn get(&self, path: &str) -> ApiResult<(Option<u64>, ByteStream)> {
        let resp = self
            .request(Method::GET, &self.url_for(path))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("GET 请求失败: {e}")))?;
        let resp = Self::expect_ok(resp, "下载对象").await?;
        let size = resp.content_length();
        let stream = resp.bytes_stream().map_err(std::io::Error::other).boxed();
        Ok((size, stream))
    }

    async fn get_range(&self, path: &str, start: u64, end: u64) -> ApiResult<ByteStream> {
        if end < start {
            return Err(ApiError::BadRequest("非法字节区间".into()));
        }
        let resp = self
            .request(Method::GET, &self.url_for(path))
            .header("Range", format!("bytes={start}-{end}"))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("Range GET 请求失败: {e}")))?;
        let status = resp.status();
        // 206 = 正常；200 = 上游忽略 Range（整文件返回），必须拒绝而非静默错拼
        if status == StatusCode::OK {
            return Err(ApiError::Upstream("WebDAV 服务器不支持 Range 请求".into()));
        }
        let resp = Self::expect_ok(resp, "Range 下载").await?;
        Ok(resp.bytes_stream().map_err(std::io::Error::other).boxed())
    }

    async fn put(&self, path: &str, body: ByteStream) -> ApiResult<()> {
        if path.is_empty() {
            return Err(ApiError::BadRequest("非法对象路径".into()));
        }
        let resp = self
            .request(Method::PUT, &self.url_for(path))
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .map_err(|e| ApiError::Upstream(format!("PUT 请求失败: {e}")))?;
        Self::expect_ok(resp, "上传对象").await.map(|_| ())
    }
}

struct DavItem {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: u64,
}

/// 去掉首尾斜杠、连续斜杠，统一比较形态。
fn normalize_path(p: &str) -> String {
    p.split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// href 可能是绝对 URL 或绝对路径，统一取 percent-decode 后的路径。
fn href_to_path(href: &str) -> String {
    let raw = if href.starts_with("http://") || href.starts_with("https://") {
        reqwest::Url::parse(href)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| href.to_string())
    } else {
        href.to_string()
    };
    percent_decode_str(&raw).decode_utf8_lossy().into_owned()
}

/// 解析 207 multistatus。宽容处理命名空间前缀（D: / d: / 无前缀）。
fn parse_multistatus(xml: &str) -> Result<Vec<DavItem>, quick_xml::Error> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut cur: Option<DavItem> = None;
    let mut text_target: Option<&'static str> = None;
    let mut in_resourcetype = false;

    loop {
        match reader.read_event()? {
            Event::Start(e) | Event::Empty(e) => {
                let local = e.local_name();
                let name = local.as_ref();
                match name {
                    b"response" => {
                        cur = Some(DavItem {
                            path: String::new(),
                            is_dir: false,
                            size: 0,
                            mtime: 0,
                        });
                    }
                    b"href" => text_target = Some("href"),
                    b"getcontentlength" => text_target = Some("size"),
                    b"getlastmodified" => text_target = Some("mtime"),
                    b"resourcetype" => in_resourcetype = true,
                    b"collection" if in_resourcetype => {
                        if let Some(item) = cur.as_mut() {
                            item.is_dir = true;
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                if let (Some(target), Some(item)) = (text_target, cur.as_mut()) {
                    let text = t.unescape().unwrap_or_default();
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    match target {
                        "href" => item.path = href_to_path(text),
                        "size" => {
                            if let Ok(v) = text.parse::<u64>() {
                                item.size = v;
                            }
                        }
                        "mtime" => {
                            if let Ok(t) = httpdate::parse_http_date(text) {
                                item.mtime = t
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::End(e) => {
                let local = e.local_name();
                match local.as_ref() {
                    b"response" => {
                        if let Some(item) = cur.take()
                            && !item.path.is_empty()
                        {
                            items.push(item);
                        }
                    }
                    b"href" | b"getcontentlength" | b"getlastmodified" => text_target = None,
                    b"resourcetype" => in_resourcetype = false,
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/enc%20dir/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:getlastmodified>Mon, 13 Jul 2026 03:00:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/enc%20dir/sub-folder/</D:href>
    <D:propstat>
      <D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>http://example.com/dav/enc%20dir/0001.bin</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>8388624</D:getcontentlength>
        <D:getlastmodified>Mon, 13 Jul 2026 03:10:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    #[test]
    fn parses_multistatus_with_mixed_hrefs() {
        let items = parse_multistatus(FIXTURE).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].path, "/dav/enc dir/");
        assert!(items[0].is_dir);
        assert!(items[1].is_dir);
        assert_eq!(items[2].path, "/dav/enc dir/0001.bin");
        assert!(!items[2].is_dir);
        assert_eq!(items[2].size, 8388624);
        assert!(items[2].mtime > 0);
    }

    #[test]
    fn parses_lowercase_and_default_namespace() {
        let xml = r#"<multistatus xmlns="DAV:"><response>
            <href>/f.bin</href>
            <propstat><prop><resourcetype/><getcontentlength>7</getcontentlength></prop>
            <status>HTTP/1.1 200 OK</status></propstat>
        </response></multistatus>"#;
        let items = parse_multistatus(xml).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].size, 7);
        assert!(!items[0].is_dir);
    }

    #[test]
    fn normalize_and_href_helpers() {
        assert_eq!(normalize_path("/a//b/"), "a/b");
        assert_eq!(href_to_path("/x/%E4%B8%AD%E6%96%87/"), "/x/中文/");
        assert_eq!(href_to_path("https://h.com/dav/a%20b"), "/dav/a b");
    }
}
