//! WebDAV 服务端：把全部数据源以 `/dav/<数据源名>/<明文路径>` 暴露成一棵
//! 标准 WebDAV 树，供 Finder / Windows 网络位置 / rclone / Infuse 等客户端
//! 直接挂载。列目录（解密信封）、流式读（Range）、加密分卷上传全部复用
//! files.rs 的明文路径核心。
//!
//! 鉴权：HTTP Basic（用户名任意 + 管理密码）或 Bearer 会话 token；未设
//! 管理密码时免鉴权（与其余 API 一致）。LOCK/UNLOCK 是假锁 —— 只为满足
//! class 2 客户端（Finder/Windows/Office）写入前的加锁探测，不真正互斥；
//! 并发写入仍由上传核心的同路径串行化防线兜底。

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::TryStreamExt;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

use crate::adapters::sanitize;
use crate::engine;
use crate::error::{ApiError, ApiResult};
use crate::registry::DataSource;
use crate::state::AppState;

use super::files;

pub fn routes() -> Router<AppState> {
    // 注意不能用 nest：axum 0.8 下 nest 的 "/" 只匹配 /dav，不匹配 /dav/，
    // 而 WebDAV 客户端习惯以尾斜杠请求集合。
    Router::new()
        .route("/dav", any(dav_root))
        .route("/dav/", any(dav_root))
        .route("/dav/{*path}", any(dav_entry))
}

// ---------------- 开关与鉴权 ----------------

/// WebDAV 服务关闭时整个 /dav 按不存在处理（404，不暴露开关状态）。
fn disabled(state: &AppState) -> bool {
    !state.settings.get().webdav_enabled
}

/// 鉴权失败时返回拒绝响应（401 + Basic 挑战）；放行返回 None。
/// 优先级：设置了 WebDAV 专用密码 → 校验专用账号（用户名留空 = 任意）；
/// 否则沿用管理密码（用户名任意）；两者都没有 → 免鉴权。
/// Bearer 会话 token（已登录管理界面）恒放行。
fn auth_reject(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let settings = state.settings.get();
    let (expect_user, expect_pass) = if !settings.webdav_password.is_empty() {
        (settings.webdav_username, settings.webdav_password)
    } else if let Some(admin) = &state.admin_password {
        (String::new(), admin.clone())
    } else {
        return None;
    };
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(b64) = auth.strip_prefix("Basic ")
        && let Ok(bytes) = B64.decode(b64.trim())
        && let Ok(text) = String::from_utf8(bytes)
        && let Some((user, password)) = text.split_once(':')
        && (expect_user.is_empty() || crate::auth::ct_eq(user, &expect_user))
        && crate::auth::ct_eq(password, &expect_pass)
    {
        return None;
    }
    if let Some(token) = auth.strip_prefix("Bearer ")
        && state.sessions.read().unwrap().contains(token)
    {
        return None;
    }
    Some(
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                header::WWW_AUTHENTICATE,
                r#"Basic realm="safedrive", charset="UTF-8""#,
            )
            .body(Body::empty())
            .expect("固定响应构造不会失败"),
    )
}

// ---------------- 路由入口 ----------------

async fn dav_root(State(state): State<AppState>, req: Request) -> Response {
    if disabled(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let method = req.method().clone();
    if method == Method::OPTIONS {
        return options_response();
    }
    if let Some(resp) = auth_reject(&state, req.headers()) {
        return resp;
    }
    match method.as_str() {
        "PROPFIND" => {
            let mut xml = prop_response("/dav/", "safedrive", true, 0, 0);
            if depth_of(req.headers()) > 0 {
                for ds in state.registry.list() {
                    xml.push_str(&prop_response(
                        &href_of(&ds.name, "", true),
                        &ds.name,
                        true,
                        0,
                        ds.created_at,
                    ));
                }
            }
            multistatus(xml)
        }
        "PROPPATCH" => multistatus(fake_proppatch("/dav/")),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn dav_entry(
    State(state): State<AppState>,
    Path(raw): Path<String>,
    req: Request,
) -> Response {
    if disabled(&state) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (parts, req_body) = req.into_parts();
    let (method, headers) = (parts.method, parts.headers);
    if method == Method::OPTIONS {
        return options_response();
    }
    if let Some(resp) = auth_reject(&state, &headers) {
        return resp;
    }
    let (seg, rest) = raw.split_once('/').unwrap_or((raw.as_str(), ""));
    let Some(ds) = find_ds(&state, seg) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let rel = match sanitize(rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let result = match method.as_str() {
        "PROPFIND" => propfind(&state, &ds, &rel, depth_of(&headers)).await,
        "GET" | "HEAD" => get_entry(&state, &ds, &rel, method.clone(), &headers).await,
        "PUT" => put_entry(&state, &ds, &rel, &headers, req_body).await,
        "MKCOL" => mkcol(&state, &ds, &rel).await,
        "DELETE" => delete_entry(&state, &ds, &rel).await,
        "MOVE" => move_copy(&state, &ds, &rel, &headers, true).await,
        "COPY" => move_copy(&state, &ds, &rel, &headers, false).await,
        "PROPPATCH" => Ok(multistatus(fake_proppatch(&href_of(&ds.name, &rel, false)))),
        "LOCK" => Ok(lock_response(&href_of(&ds.name, &rel, false))),
        "UNLOCK" => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    };
    result.unwrap_or_else(|e| e.into_response())
}

/// 数据源定位：先按名字、再按 ID（名字可自由改，ID 永远可用）。
fn find_ds(state: &AppState, seg: &str) -> Option<DataSource> {
    let list = state.registry.list();
    list.iter()
        .find(|d| d.name == seg)
        .or_else(|| list.iter().find(|d| d.id == seg))
        .cloned()
}

// ---------------- 各方法实现 ----------------

async fn propfind(state: &AppState, ds: &DataSource, rel: &str, depth: u8) -> ApiResult<Response> {
    let storage = state.adapter(&ds.id)?;
    let me = files::stat_path(state, storage.as_ref(), &ds.id, rel).await?;
    let display = if rel.is_empty() { &ds.name } else { &me.name };
    let mut xml = prop_response(
        &href_of(&ds.name, rel, me.is_dir),
        display,
        me.is_dir,
        me.size,
        me.mtime,
    );
    if me.is_dir && depth > 0 {
        for e in files::list_dir(state, storage.as_ref(), &ds.id, rel).await? {
            // 解不开信封的外来条目不在 WebDAV 暴露（GET 它们必然失败）
            if e.foreign {
                continue;
            }
            let child_rel = if rel.is_empty() {
                e.name.clone()
            } else {
                format!("{rel}/{}", e.name)
            };
            xml.push_str(&prop_response(
                &href_of(&ds.name, &child_rel, e.is_dir),
                &e.name,
                e.is_dir,
                e.size,
                e.mtime,
            ));
        }
    }
    Ok(multistatus(xml))
}

async fn get_entry(
    state: &AppState,
    ds: &DataSource,
    rel: &str,
    method: Method,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    if rel.is_empty() {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    files::stream_file(state, &ds.id, rel, false, method, headers).await
}

async fn put_entry(
    state: &AppState,
    ds: &DataSource,
    rel: &str,
    headers: &HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    if rel.is_empty() {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    // 分卷计划需要预知总大小：Content-Length，或 Finder 分块传输时的
    // X-Expected-Entity-Length。两者都没有则无法上传。
    let size = header_u64(headers, header::CONTENT_LENGTH.as_str())
        .or_else(|| header_u64(headers, "x-expected-entity-length"));
    let Some(size) = size else {
        return Ok(StatusCode::LENGTH_REQUIRED.into_response());
    };
    let progress = Arc::new(engine::UploadProgress::tracked(
        size,
        Arc::clone(&state.transfers),
    ));
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    files::upload_file(state, &ds.id, rel, size, true, Box::pin(stream), progress).await?;
    Ok(StatusCode::CREATED.into_response())
}

async fn mkcol(state: &AppState, ds: &DataSource, rel: &str) -> ApiResult<Response> {
    if rel.is_empty() {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    let storage = state.adapter(&ds.id)?;
    match files::stat_path(state, storage.as_ref(), &ds.id, rel).await {
        // RFC 4918：目标已存在 → 405
        Ok(_) => return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
        Err(ApiError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    files::mkdir_path(state, storage.as_ref(), &ds.id, rel).await?;
    Ok(StatusCode::CREATED.into_response())
}

async fn delete_entry(state: &AppState, ds: &DataSource, rel: &str) -> ApiResult<Response> {
    if rel.is_empty() {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let storage = state.adapter(&ds.id)?;
    files::delete_path(state, storage.as_ref(), &ds.id, rel).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn move_copy(
    state: &AppState,
    ds: &DataSource,
    rel: &str,
    headers: &HeaderMap,
    is_move: bool,
) -> ApiResult<Response> {
    if rel.is_empty() {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let to = destination_rel(state, ds, headers)?;
    // Overwrite 头缺省为 T（RFC 4918）
    let overwrite = headers
        .get("overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.eq_ignore_ascii_case("f"))
        .unwrap_or(true);
    let storage = state.adapter(&ds.id)?;
    let existed = match files::stat_path(state, storage.as_ref(), &ds.id, &to).await {
        Ok(_) => true,
        Err(ApiError::NotFound(_)) => false,
        Err(e) => return Err(e),
    };
    if existed {
        if !overwrite {
            return Ok(StatusCode::PRECONDITION_FAILED.into_response());
        }
        if to != rel {
            files::delete_path(state, storage.as_ref(), &ds.id, &to).await?;
        }
    }
    if is_move {
        files::rename_path(state, storage.as_ref(), &ds.id, rel, &to).await?;
    } else {
        // COPY：只支持文件 —— 服务端解密回源再重加密写入（目录递归复制
        // 对分卷云端过重，客户端可自行递归）。
        let src = files::stat_path(state, storage.as_ref(), &ds.id, rel).await?;
        if src.is_dir {
            return Ok(StatusCode::FORBIDDEN.into_response());
        }
        let resp =
            files::stream_file(state, &ds.id, rel, false, Method::GET, &HeaderMap::new()).await?;
        let stream = resp
            .into_body()
            .into_data_stream()
            .map_err(std::io::Error::other);
        let progress = Arc::new(engine::UploadProgress::tracked(
            src.size,
            Arc::clone(&state.transfers),
        ));
        files::upload_file(
            state,
            &ds.id,
            &to,
            src.size,
            true,
            Box::pin(stream),
            progress,
        )
        .await?;
    }
    Ok(if existed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::CREATED.into_response()
    })
}

/// 解析 Destination 头 → 同数据源内的明文相对路径。
fn destination_rel(state: &AppState, ds: &DataSource, headers: &HeaderMap) -> ApiResult<String> {
    let raw = headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("缺少 Destination 头".into()))?;
    // 绝对 URI → 只取 path 部分
    let path = match raw.find("://") {
        Some(i) => raw[i + 3..]
            .find('/')
            .map(|j| &raw[i + 3 + j..])
            .unwrap_or("/"),
        None => raw,
    };
    let path = path.split('?').next().unwrap_or(path);
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| ApiError::BadRequest("Destination 编码无效".into()))?;
    let rest = decoded
        .strip_prefix("/dav/")
        .ok_or_else(|| ApiError::BadRequest("Destination 必须位于 /dav/ 下".into()))?;
    let (seg, to) = rest.split_once('/').unwrap_or((rest, ""));
    if find_ds(state, seg).map(|d| d.id) != Some(ds.id.clone()) {
        return Err(ApiError::BadRequest("不支持跨数据源移动/复制".into()));
    }
    let to = sanitize(to)?;
    if to.is_empty() {
        return Err(ApiError::BadRequest("Destination 不能是数据源根".into()));
    }
    Ok(to)
}

// ---------------- 响应构造 ----------------

/// href 段编码：控制符、空格与 XML/URL 敏感符号百分号转义（非 ASCII
/// 字节 percent_encoding 恒定转义，中文名天然安全）。
const SEG: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn encode_seg(seg: &str) -> String {
    utf8_percent_encode(seg, SEG).to_string()
}

fn href_of(ds_name: &str, rel: &str, is_dir: bool) -> String {
    let mut href = format!("/dav/{}", encode_seg(ds_name));
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        href.push('/');
        href.push_str(&encode_seg(seg));
    }
    if is_dir {
        href.push('/');
    }
    href
}

fn xml_escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}

fn depth_of(headers: &HeaderMap) -> u8 {
    match headers.get("depth").and_then(|v| v.to_str().ok()) {
        Some("0") => 0,
        // 1 / infinity / 缺省都按 1 处理（不做无限递归展开）
        _ => 1,
    }
}

fn header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

/// 单个 `<D:response>`：标准活属性（displayname / resourcetype /
/// getcontentlength / getcontenttype / getlastmodified）。
fn prop_response(href: &str, display: &str, is_dir: bool, size: u64, mtime: u64) -> String {
    let mut props = format!("<D:displayname>{}</D:displayname>", xml_escape(display));
    if is_dir {
        props.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        props.push_str("<D:resourcetype/>");
        props.push_str(&format!("<D:getcontentlength>{size}</D:getcontentlength>"));
        let mime = mime_guess::from_path(display).first_or_octet_stream();
        props.push_str(&format!(
            "<D:getcontenttype>{}</D:getcontenttype>",
            mime.essence_str()
        ));
    }
    if mtime > 0 {
        let when = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(mtime));
        props.push_str(&format!("<D:getlastmodified>{when}</D:getlastmodified>"));
    }
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(href)
    )
}

fn multistatus(inner: String) -> Response {
    Response::builder()
        .status(StatusCode::MULTI_STATUS)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(format!(
            r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">{inner}</D:multistatus>"#
        )))
        .expect("固定响应构造不会失败")
}

/// PROPPATCH 假成功：客户端（Finder 设时间戳等）拿到 207 即继续，属性
/// 实际不落存储（云端没有可写的元数据位）。
fn fake_proppatch(href: &str) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop/>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(href)
    )
}

fn lock_response(href: &str) -> Response {
    let token = format!("opaquelocktoken:{}", uuid::Uuid::new_v4());
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth><D:timeout>Second-3600</D:timeout><D:locktoken><D:href>{token}</D:href></D:locktoken><D:lockroot><D:href>{}</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>"#,
        xml_escape(href)
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("Lock-Token", format!("<{token}>"))
        .body(Body::from(body))
        .expect("固定响应构造不会失败")
}

fn options_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("DAV", "1, 2")
        .header("MS-Author-Via", "DAV")
        .header(
            header::ALLOW,
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, MOVE, COPY, LOCK, UNLOCK",
        )
        .body(Body::empty())
        .expect("固定响应构造不会失败")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    fn datasource(encrypted: bool, root: &str) -> DataSource {
        DataSource {
            id: "ds1".into(),
            name: "cloud".into(),
            ds_type: "localfs".into(),
            config: serde_json::json!({ "root": root }),
            encryption_enabled: encrypted,
            password: if encrypted {
                "test-pw".into()
            } else {
                String::new()
            },
            prev_password: None,
            volume_enabled: encrypted,
            volume_size: 64 * 1024,
            volume_strategy: "fixed".into(),
            volume_name_format: "{s}_{i}.bin".into(),
            cache_enabled: false,
            created_at: 1,
        }
    }

    fn setup(
        encrypted: bool,
        admin_password: Option<&str>,
    ) -> (crate::state::AppState, axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cloud = dir.path().join("cloud");
        std::fs::create_dir_all(&cloud).unwrap();
        let state =
            crate::state::AppState::new(dir.path().join("data"), admin_password.map(str::to_owned))
                .unwrap();
        state
            .registry
            .create(datasource(encrypted, cloud.to_str().unwrap()))
            .unwrap();
        // WebDAV 默认关闭；测试统一显式开启（默认关闭本身由
        // webdav_disabled_by_default_and_toggleable 覆盖）。
        let mut settings = state.settings.get();
        settings.webdav_enabled = true;
        state.settings.set(settings).unwrap();
        (state.clone(), crate::routes::router(state), dir)
    }

    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = app
            .clone()
            .oneshot(builder.body(Body::from(body.to_vec())).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, bytes)
    }

    /// 端到端（加密数据源）：OPTIONS → 根 PROPFIND → MKCOL → PUT（跨
    /// 分卷）→ PROPFIND 列表 → GET 全量/Range → PUT 覆盖 → MOVE →
    /// COPY → DELETE。路径含中文（URI 百分号编码）。
    #[tokio::test]
    async fn webdav_roundtrip_encrypted() {
        let (_state, app, _dir) = setup(true, None);
        let movies = "/dav/cloud/%E5%BD%B1%E7%89%87"; // 影片

        let (st, hs, _) = send(&app, "OPTIONS", "/dav/", &[], b"").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(hs.get("DAV").unwrap(), "1, 2");

        let (st, _, body) = send(&app, "PROPFIND", "/dav/", &[("Depth", "1")], b"").await;
        assert_eq!(st, StatusCode::MULTI_STATUS);
        assert!(String::from_utf8(body).unwrap().contains("cloud"));

        let (st, ..) = send(&app, "MKCOL", movies, &[], b"").await;
        assert_eq!(st, StatusCode::CREATED);
        // 已存在 → 405
        let (st, ..) = send(&app, "MKCOL", movies, &[], b"").await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);

        // 跨两个分卷（volume_size = 64K）的上传
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let uri = format!("{movies}/a.bin");
        let (st, ..) = send(
            &app,
            "PUT",
            &uri,
            &[("Content-Length", &data.len().to_string())],
            &data,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        let (st, _, body) = send(&app, "PROPFIND", movies, &[("Depth", "1")], b"").await;
        assert_eq!(st, StatusCode::MULTI_STATUS);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("a.bin"));
        assert!(text.contains(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            data.len()
        )));

        let (st, _, body) = send(&app, "GET", &uri, &[], b"").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, data, "全量下载解密一致");

        let (st, _, body) = send(&app, "GET", &uri, &[("Range", "bytes=65000-66000")], b"").await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, &data[65_000..=66_000], "跨卷 Range 读取一致");

        // PUT 覆盖（WebDAV 语义）
        let (st, ..) = send(&app, "PUT", &uri, &[("Content-Length", "3")], b"xyz").await;
        assert_eq!(st, StatusCode::CREATED);
        let (_, _, body) = send(&app, "GET", &uri, &[], b"").await;
        assert_eq!(body, b"xyz");

        // MOVE（Destination 带主机前缀 + 百分号编码）
        let dest = format!("http://127.0.0.1:5266{movies}/b.bin");
        let (st, ..) = send(&app, "MOVE", &uri, &[("Destination", &dest)], b"").await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, ..) = send(&app, "GET", &uri, &[], b"").await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // COPY 到数据源根
        let src = format!("{movies}/b.bin");
        let (st, ..) = send(
            &app,
            "COPY",
            &src,
            &[("Destination", "/dav/cloud/c.bin")],
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (_, _, body) = send(&app, "GET", "/dav/cloud/c.bin", &[], b"").await;
        assert_eq!(body, b"xyz");

        let (st, ..) = send(&app, "DELETE", movies, &[], b"").await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, ..) = send(&app, "PROPFIND", movies, &[("Depth", "0")], b"").await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    /// 未加密（关闭分卷）数据源的基本读写。
    #[tokio::test]
    async fn webdav_roundtrip_plain() {
        let (_state, app, dir) = setup(false, None);
        let (st, ..) = send(
            &app,
            "PUT",
            "/dav/cloud/note.txt",
            &[("Content-Length", "5")],
            b"hello",
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        // 云端就是明文原名文件
        assert_eq!(
            std::fs::read(dir.path().join("cloud/note.txt")).unwrap(),
            b"hello"
        );
        let (st, _, body) = send(&app, "GET", "/dav/cloud/note.txt", &[], b"").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"hello");
    }

    /// 设了管理密码时：无凭证 → 401 + WWW-Authenticate；Basic 密码正确 → 放行。
    #[tokio::test]
    async fn webdav_requires_basic_auth() {
        let (_state, app, _dir) = setup(true, Some("secret"));
        let (st, hs, _) = send(&app, "PROPFIND", "/dav/", &[("Depth", "0")], b"").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(hs.contains_key(header::WWW_AUTHENTICATE));

        let cred = B64.encode("anyuser:secret");
        let auth = format!("Basic {cred}");
        let (st, ..) = send(
            &app,
            "PROPFIND",
            "/dav/",
            &[("Depth", "0"), ("Authorization", &auth)],
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::MULTI_STATUS);

        let bad = format!("Basic {}", B64.encode("anyuser:wrong"));
        let (st, ..) = send(
            &app,
            "PROPFIND",
            "/dav/",
            &[("Depth", "0"), ("Authorization", &bad)],
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // OPTIONS 免鉴权（挂载探测）
        let (st, ..) = send(&app, "OPTIONS", "/dav/", &[], b"").await;
        assert_eq!(st, StatusCode::OK);
    }

    /// 安全默认：未动过设置时 WebDAV 关闭，/dav 整体 404；设置页开关
    /// 打开后立即可用，再关闭（含 OPTIONS）立即回到 404。
    #[tokio::test]
    async fn webdav_disabled_by_default_and_toggleable() {
        // 不走 setup（它为其余测试显式开启了 WebDAV），验证出厂默认
        let dir = tempfile::tempdir().unwrap();
        let cloud = dir.path().join("cloud");
        std::fs::create_dir_all(&cloud).unwrap();
        let state = crate::state::AppState::new(dir.path().join("data"), None).unwrap();
        state
            .registry
            .create(datasource(true, cloud.to_str().unwrap()))
            .unwrap();
        assert!(!state.settings.get().webdav_enabled, "默认必须关闭");
        let app = crate::routes::router(state.clone());

        for (method, uri) in [
            ("OPTIONS", "/dav/"),
            ("PROPFIND", "/dav/"),
            ("GET", "/dav/cloud/a.bin"),
        ] {
            let (st, ..) = send(&app, method, uri, &[], b"").await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{method} {uri}");
        }

        let mut settings = state.settings.get();
        settings.webdav_enabled = true;
        state.settings.set(settings).unwrap();
        let (st, ..) = send(&app, "PROPFIND", "/dav/", &[("Depth", "0")], b"").await;
        assert_eq!(st, StatusCode::MULTI_STATUS);

        let mut settings = state.settings.get();
        settings.webdav_enabled = false;
        state.settings.set(settings).unwrap();
        let (st, ..) = send(&app, "OPTIONS", "/dav/", &[], b"").await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    /// 设置了 WebDAV 专用账号后：专用账号放行、管理密码不再放行、
    /// 用户名必须匹配；Bearer 会话 token 恒放行。
    #[tokio::test]
    async fn webdav_dedicated_account_overrides_admin_password() {
        let (state, app, _dir) = setup(true, Some("admin-pw"));
        let mut settings = state.settings.get();
        settings.webdav_username = "dav".into();
        settings.webdav_password = "dav-pw".into();
        state.settings.set(settings).unwrap();

        let ok = format!("Basic {}", B64.encode("dav:dav-pw"));
        let (st, ..) = send(
            &app,
            "PROPFIND",
            "/dav/",
            &[("Depth", "0"), ("Authorization", &ok)],
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::MULTI_STATUS);

        for cred in ["anyuser:admin-pw", "wrong:dav-pw", "dav:wrong"] {
            let bad = format!("Basic {}", B64.encode(cred));
            let (st, ..) = send(
                &app,
                "PROPFIND",
                "/dav/",
                &[("Depth", "0"), ("Authorization", &bad)],
                b"",
            )
            .await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{cred}");
        }

        state.sessions.write().unwrap().insert("tok123".into());
        let (st, ..) = send(
            &app,
            "PROPFIND",
            "/dav/",
            &[("Depth", "0"), ("Authorization", "Bearer tok123")],
            b"",
        )
        .await;
        assert_eq!(st, StatusCode::MULTI_STATUS);

        // 账号设置但密码为空 → 校验拒绝
        let mut settings = state.settings.get();
        settings.webdav_password = String::new();
        assert!(state.settings.set(settings).is_err());
    }
}
