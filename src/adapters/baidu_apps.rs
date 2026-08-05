//! 百度网盘开放平台的「第三方应用」。
//!
//! 百度开放平台的 xpan API 需要一对 API Key / Secret Key（client_id /
//! client_secret）。个人很难申请到带网盘权限的应用，社区通行做法是复用
//! 已上架第三方应用的公开密钥 —— 这里内置 ES 文件管理器：用户扫码拿到
//! BDUSS 后，用它跑设备码授权换取 refresh/access token，不必自建应用。
//! 也可选「自定义应用」自填 API Key / Secret Key，配置形式与阿里云盘一致。
//!
//! 与阿里云盘不同：百度内置应用的密钥就在本机（直连开放平台，没有中转
//! 服务），BDUSS 也不是 JWT、令牌里没有可反查归属的字段 —— 用哪个应用
//! 完全由下拉框显式决定，不做自动识别。

use serde::Serialize;

use crate::error::{ApiError, ApiResult};

/// 扫码授权默认用 ES 文件管理器（密钥公开，直连开放平台）。
pub const DEFAULT_APP: &str = "es";
/// 用户自备 API Key / Secret Key 的伪应用键（与阿里云盘保持一致）。
pub const CUSTOM_APP: &str = "custom";

/// 内置应用。密钥直接内联（百度这几个都是公开可查的应用密钥，不像阿里那样
/// 藏在中转服务后面），`client_secret` 不下发前端。
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltinApp {
    pub key: &'static str,
    pub name: &'static str,
    pub client_id: &'static str,
    #[serde(skip)]
    client_secret: &'static str,
    /// 提示文案：这个应用的密钥怎么来的。
    pub note: &'static str,
}

/// 内置的第三方应用名单，顺序即前端下拉框顺序（默认项排最前）。
const BUILTINS: &[BuiltinApp] = &[BuiltinApp {
    key: "es",
    name: "ES 文件管理器",
    client_id: "NqOMXF6XGhGRIGemsQ9nG0Na",
    client_secret: "SVT6xpMdLcx6v4aCR4wT8BBOTbzFO8LM",
    note: "密钥公开，直连百度开放平台（默认）",
}];

pub fn builtins() -> &'static [BuiltinApp] {
    BUILTINS
}

pub fn find(key: &str) -> Option<&'static BuiltinApp> {
    BUILTINS.iter().find(|app| app.key == key)
}

/// 解析出这次要用的开放平台应用凭据 `(client_id, client_secret)`：
/// 1. 明确指定了内置应用键 → 用它内置的密钥；
/// 2. `custom` → 用户自填的 API Key / Secret Key（必须成对）；
/// 3. 未指定：填了自定义凭据按自定义应用，否则用默认内置应用（ES 文件管理器）。
pub fn resolve(
    app_key: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> ApiResult<(String, String)> {
    let id = client_id.map(str::trim).filter(|value| !value.is_empty());
    let secret = client_secret
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let custom = || -> ApiResult<(String, String)> {
        match (id, secret) {
            (Some(id), Some(secret)) => Ok((id.to_owned(), secret.to_owned())),
            (None, None) => Err(ApiError::BadRequest(
                "请选择内置的第三方应用，或填写自有应用的 API Key 与 Secret Key".into(),
            )),
            _ => Err(ApiError::BadRequest(
                "百度开放平台 API Key 与 Secret Key 必须同时填写或同时留空".into(),
            )),
        }
    };
    let builtin =
        |app: &'static BuiltinApp| (app.client_id.to_owned(), app.client_secret.to_owned());

    match app_key.map(str::trim).filter(|key| !key.is_empty()) {
        Some(CUSTOM_APP) => custom(),
        Some(key) => find(key)
            .map(builtin)
            .ok_or_else(|| ApiError::BadRequest(format!("未知的百度网盘第三方应用: {key}"))),
        // 未指定应用键：兼容没有 `app` 字段的老配置 —— 填过自定义凭据的按自定义
        // 应用，否则一律回落到默认内置应用。
        None => {
            if id.is_some() || secret.is_some() {
                custom()
            } else {
                Ok(builtin(find(DEFAULT_APP).expect("ES 内置应用必然存在")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_keys_and_secrets_are_present_and_unique() {
        assert!(find(DEFAULT_APP).is_some(), "默认应用必须在名单里");
        for (index, app) in BUILTINS.iter().enumerate() {
            assert!(!app.client_id.is_empty(), "{} 缺 client_id", app.key);
            assert!(
                !app.client_secret.is_empty(),
                "{} 缺 client_secret（百度内置应用密钥直连，不能留空）",
                app.key
            );
            for other in &BUILTINS[index + 1..] {
                assert_ne!(app.key, other.key);
                assert_ne!(app.client_id, other.client_id);
            }
        }
    }

    #[test]
    fn resolve_prefers_explicit_builtin() {
        let es = find("es").unwrap();
        // 指定内置应用：用内置密钥，用户填的凭据不参与。
        assert_eq!(
            resolve(Some("es"), Some("cid"), Some("csec")).unwrap(),
            (es.client_id.to_owned(), es.client_secret.to_owned())
        );
        assert!(resolve(Some("nope"), None, None).is_err());
    }

    #[test]
    fn resolve_custom_needs_both_credentials() {
        assert_eq!(
            resolve(Some(CUSTOM_APP), Some("cid"), Some("csec")).unwrap(),
            ("cid".to_owned(), "csec".to_owned())
        );
        // custom 必须成对填写。
        assert!(resolve(Some(CUSTOM_APP), Some("cid"), None).is_err());
        assert!(resolve(Some(CUSTOM_APP), None, None).is_err());
    }

    #[test]
    fn resolve_defaults_and_stays_backward_compatible() {
        let es = find("es").unwrap();
        let default = (es.client_id.to_owned(), es.client_secret.to_owned());
        // 什么都不填 → 默认内置应用。
        assert_eq!(resolve(None, None, None).unwrap(), default);
        assert_eq!(resolve(Some(""), Some(""), Some("")).unwrap(), default);
        // 老配置只填了 client 凭据（没有 app 字段）→ 当作自定义应用。
        assert_eq!(
            resolve(None, Some("cid"), Some("csec")).unwrap(),
            ("cid".to_owned(), "csec".to_owned())
        );
        // 只填一半仍然报错（保留旧的成对校验）。
        assert!(resolve(None, Some("cid"), None).is_err());
    }
}
