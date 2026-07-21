pub mod ds;
pub mod files;
pub mod share;
mod share_codec;
mod system;
pub mod webdav;

use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde_json::json;

use crate::state::AppState;
use crate::{assets, auth};

pub fn router(state: AppState) -> Router {
    let open = Router::new()
        .route("/health", get(health))
        .route("/login", post(auth::login));

    let protected = Router::new()
        .merge(ds::routes())
        .merge(system::routes())
        .merge(files::api_routes())
        .merge(share::routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .nest("/api", open.merge(protected))
        // 数据平面：外部播放器/下载器可直接消费（鉴权 ?token=，见 files::stream）
        .merge(files::stream_routes())
        // WebDAV 数据平面：/dav/<数据源名>/<路径>，Basic 鉴权（管理密码），
        // Finder / Windows / rclone / Infuse 等客户端可直接挂载
        .merge(webdav::routes())
        .fallback(assets::static_handler)
        // 上传走流式消费，不受内存缓冲限制
        .layer(DefaultBodyLimit::disable())
        .layer(tower_http_trace())
        .with_state(state)
}

fn tower_http_trace() -> tower_http::trace::TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
> {
    tower_http::trace::TraceLayer::new_for_http()
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "name": "safedrive",
        "version": env!("CARGO_PKG_VERSION"),
        "auth": state.admin_password.is_some(),
    }))
}
