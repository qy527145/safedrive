//! 百度网盘扫码登录：代理 passport.baidu.com 的网页版二维码登录协议，
//! 用户手机扫码确认后从 Set-Cookie 中提取 BDUSS 返回给前端自动填入，
//! 免去手动打开浏览器开发者工具查 Cookie。
//!
//! 协议与 pan.baidu.com 登录页一致：
//! getqrcode 取二维码 → channel/unicast 轮询扫码事件 →
//! qrbdusslogin 用扫码返回的临时凭证换取正式 Cookie（含 BDUSS）。

use std::sync::OnceLock;
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use reqwest::header::{REFERER, SET_COOKIE, USER_AGENT};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::registry::now_ms;
use crate::state::AppState;

const PASSPORT_BASE: &str = "https://passport.baidu.com";
const WEB_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
/// 与网盘登录页一致的业务线标识。
const TPL: &str = "netdisk";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/baidu/qrcode", post(create_qrcode))
        .route("/baidu/qrcode/poll", post(poll_qrcode))
}

/// 扫码登录专用客户端：qrbdusslogin 的 Set-Cookie 挂在首个响应上，
/// 不能跟随重定向；unicast 是服务端长轮询，需要独立的整体超时。
fn passport_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(35))
            .build()
            .expect("初始化百度扫码登录 HTTP 客户端失败")
    })
}

async fn passport_json(url: String, query: &[(&str, &str)], what: &str) -> ApiResult<Value> {
    let response = passport_client()
        .get(url)
        .query(query)
        .header(USER_AGENT, WEB_UA)
        .header(REFERER, "https://pan.baidu.com/")
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("{what}失败: {e}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ApiError::Upstream(format!("{what}读取响应失败: {e}")))?;
    if !status.is_success() {
        return Err(ApiError::Upstream(format!("{what}失败: HTTP {status}")));
    }
    // passport 接口 Content-Type 为 text/html，body 实为 JSON。
    serde_json::from_str(&text)
        .map_err(|_| ApiError::Upstream(format!("{what}返回了无法解析的响应")))
}

/// 生成登录二维码。二维码图片以 base64 返回，前端同源展示，
/// 不依赖浏览器直连百度域名。
async fn create_qrcode() -> ApiResult<Json<Value>> {
    let gid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let tt = now_ms().to_string();
    let body = passport_json(
        format!("{PASSPORT_BASE}/v2/api/getqrcode"),
        &[
            ("lp", "pc"),
            ("qrloginfrom", "pc"),
            ("apiver", "v3"),
            ("tpl", TPL),
            ("tt", &tt),
            ("gid", &gid),
        ],
        "获取百度登录二维码",
    )
    .await?;
    let sign = body
        .get("sign")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Upstream(format!("百度未返回二维码签名: {body}")))?;
    let imgurl = body
        .get("imgurl")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Upstream(format!("百度未返回二维码图片地址: {body}")))?;
    let imgurl = if imgurl.starts_with("http") {
        imgurl.to_owned()
    } else {
        format!("https://{imgurl}")
    };
    let image = passport_client()
        .get(&imgurl)
        .header(USER_AGENT, WEB_UA)
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("下载二维码图片失败: {e}")))?
        .bytes()
        .await
        .map_err(|e| ApiError::Upstream(format!("下载二维码图片失败: {e}")))?;
    Ok(Json(json!({
        "sign": sign,
        "gid": gid,
        "img": base64::engine::general_purpose::STANDARD.encode(&image),
    })))
}

#[derive(Deserialize)]
struct PollBody {
    sign: String,
    gid: String,
}

/// 轮询一次扫码状态。返回 status：
/// waiting（等待扫码）/ scanned（已扫码待手机确认）/
/// confirmed（已确认，附 bduss）/ expired（二维码失效或被取消）。
async fn poll_qrcode(Json(body): Json<PollBody>) -> ApiResult<Json<Value>> {
    let tt = now_ms().to_string();
    let response = passport_client()
        .get(format!("{PASSPORT_BASE}/channel/unicast"))
        .query(&[
            ("channel_id", body.sign.as_str()),
            ("gid", body.gid.as_str()),
            ("tpl", TPL),
            ("apiver", "v3"),
            ("tt", &tt),
        ])
        .header(USER_AGENT, WEB_UA)
        .header(REFERER, "https://pan.baidu.com/")
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        // unicast 为长轮询，客户端超时等价于「本轮无事件」
        Err(e) if e.is_timeout() => return Ok(Json(json!({ "status": "waiting" }))),
        Err(e) => return Err(ApiError::Upstream(format!("查询扫码状态失败: {e}"))),
    };
    let text = response
        .text()
        .await
        .map_err(|e| ApiError::Upstream(format!("查询扫码状态读取响应失败: {e}")))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| ApiError::Upstream("扫码状态响应无法解析".into()))?;
    match value.get("errno").and_then(Value::as_i64) {
        Some(0) => {}
        Some(1) => return Ok(Json(json!({ "status": "waiting" }))),
        _ => return Ok(Json(json!({ "status": "expired" }))),
    }
    let channel_v: Value = value
        .get("channel_v")
        .and_then(Value::as_str)
        .and_then(|inner| serde_json::from_str(inner).ok())
        .ok_or_else(|| ApiError::Upstream("扫码事件内容无法解析".into()))?;
    match channel_v.get("status").and_then(Value::as_i64) {
        Some(1) => Ok(Json(json!({ "status": "scanned" }))),
        Some(2) => Ok(Json(json!({ "status": "expired" }))),
        Some(0) => {
            let tmp = channel_v
                .get("v")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ApiError::Upstream("扫码确认事件缺少临时凭证".into()))?;
            let bduss = exchange_bduss(tmp).await?;
            Ok(Json(json!({ "status": "confirmed", "bduss": bduss })))
        }
        _ => Ok(Json(json!({ "status": "waiting" }))),
    }
}

/// 用扫码确认返回的临时凭证换取正式登录 Cookie，提取其中的 BDUSS。
async fn exchange_bduss(tmp: &str) -> ApiResult<String> {
    let now = now_ms();
    let tt = now.to_string();
    let time = (now / 1000).to_string();
    let response = passport_client()
        .get(format!("{PASSPORT_BASE}/v3/login/main/qrbdusslogin"))
        .query(&[
            ("v", tt.as_str()),
            ("bduss", tmp),
            ("u", "https://pan.baidu.com/disk/home"),
            ("loginVersion", "v4"),
            ("qrcode", "1"),
            ("tpl", TPL),
            ("apiver", "v3"),
            ("tt", &tt),
            ("time", &time),
            ("alg", "v3"),
        ])
        .header(USER_AGENT, WEB_UA)
        .header(REFERER, "https://pan.baidu.com/")
        .send()
        .await
        .map_err(|e| ApiError::Upstream(format!("换取登录 Cookie 失败: {e}")))?;
    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    bduss_from_set_cookies(cookies.iter().map(String::as_str)).ok_or_else(|| {
        ApiError::Upstream("扫码登录成功，但百度响应未携带 BDUSS，请重试".into())
    })
}

/// 从若干 Set-Cookie 头中提取 BDUSS（注意区分 BDUSS_BFESS 等同前缀 Cookie）。
fn bduss_from_set_cookies<'a>(cookies: impl Iterator<Item = &'a str>) -> Option<String> {
    for cookie in cookies {
        let pair = cookie.split(';').next().unwrap_or("").trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == "BDUSS"
            && !value.is_empty()
            && value != "deleted"
        {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::bduss_from_set_cookies;

    #[test]
    fn extracts_bduss_and_skips_lookalikes() {
        let cookies = [
            "BAIDUID=abc123; path=/; domain=.baidu.com",
            "BDUSS_BFESS=not-this-one; path=/; domain=.baidu.com; httponly",
            "BDUSS=the-real-value; path=/; domain=.baidu.com; httponly",
        ];
        assert_eq!(
            bduss_from_set_cookies(cookies.iter().copied()).as_deref(),
            Some("the-real-value")
        );
    }

    #[test]
    fn rejects_empty_or_deleted() {
        let cookies = ["BDUSS=deleted; path=/", "BDUSS=; path=/"];
        assert_eq!(bduss_from_set_cookies(cookies.iter().copied()), None);
    }
}
