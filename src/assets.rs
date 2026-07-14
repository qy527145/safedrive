use axum::http::{Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

/// 前端构建产物，编译期嵌入二进制（debug 构建下动态读盘，便于开发）。
#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // 未匹配的 API 路径明确返回 404，避免误回 SPA 页面
    if path.starts_with("api/") {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "接口不存在" })),
        )
            .into_response();
    }
    let candidate = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = Assets::get(candidate) {
        return serve(candidate, file);
    }
    // SPA 路由回退到 index.html（/api 前缀不会走到这里）
    if let Some(index) = Assets::get("index.html") {
        return serve("index.html", index);
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        "前端未构建：请先在 web/ 目录执行 pnpm install && pnpm build",
    )
        .into_response()
}

fn serve(path: &str, file: rust_embed::EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // index.html 与 sw.js 必须实时更新；带 hash 的静态资源可长缓存
    let cache = if path == "index.html" || path == "sw.js" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        file.data,
    )
        .into_response()
}
