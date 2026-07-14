use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// 统一 API 错误：全部序列化为 `{ "error": "..." }`。
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("未登录或凭证无效")]
    Unauthorized,
    #[error("{0}")]
    NotFound(String),
    #[error("上游存储错误: {0}")]
    Upstream(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => ApiError::NotFound("文件或目录不存在".into()),
            _ => ApiError::Upstream(e.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Upstream(_) => StatusCode::BAD_GATEWAY,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!("internal error: {self:?}");
        }
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}
