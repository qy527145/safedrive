mod adapters;
mod assets;
mod auth;
mod cache;
mod crypto;
mod engine;
mod error;
mod registry;
mod routes;
mod settings;
mod state;
mod transfer;
mod vault;

use clap::Parser;

/// 端到端加密的数据源管理 Web 客户端（信任模型同 hydraria：服务器可信、
/// 云存储不可信）。加解密、密码本、流式代理全部在服务端；云端只见
/// 随机密文分卷与加密目录名。
#[derive(Parser)]
#[command(name = "safedrive", version, about)]
struct Cli {
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1:5266")]
    bind: String,
    /// 数据目录（数据源注册表、缓存与设置），默认 ~/.safedrive
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,
    /// 管理密码；不设置则免登录（仅建议本机使用）
    #[arg(long, env = "SAFEDRIVE_ADMIN_PASSWORD")]
    admin_password: Option<String>,
    /// 上游 HTTP/HTTPS 代理，例如 http://127.0.0.1:8080
    #[arg(long, env = "SAFEDRIVE_HTTP_PROXY")]
    http_proxy: Option<String>,
    /// 额外信任的 PEM/DER CA 证书（mitmproxy 通常使用 mitmproxy-ca-cert.pem）
    #[arg(long, env = "SAFEDRIVE_HTTP_CA_CERT")]
    http_ca_cert: Option<std::path::PathBuf>,
    /// 跳过上游 HTTPS 证书校验；仅限临时抓包调试
    #[arg(long, env = "SAFEDRIVE_INSECURE_TLS", default_value_t = false)]
    insecure_tls: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| ".".into())
            .join(".safedrive")
    });
    std::fs::create_dir_all(&data_dir)?;

    // 日志双写：stdout + <data_dir>/logs/safedrive.log.YYYY-MM-DD（按天滚动）。
    // 上游报错细节（请求参数、原始响应）都打在 error 级，落盘可事后排查。
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let (file_writer, _log_guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::daily(&log_dir, "safedrive.log"));
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "safedrive=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(file_writer),
        )
        .init();

    if cli.admin_password.is_none() {
        tracing::warn!(
            "未设置 --admin-password / SAFEDRIVE_ADMIN_PASSWORD，API 免登录（仅建议本机使用）"
        );
    }

    if cli.http_proxy.is_some() {
        tracing::info!("已为上游数据源请求启用显式 HTTP 代理");
    }
    if let Some(path) = &cli.http_ca_cert {
        tracing::info!("已加载上游 HTTP 附加 CA: {}", path.display());
    }
    if cli.insecure_tls {
        tracing::warn!("已禁用上游 HTTPS 证书校验；仅应在临时抓包调试时使用");
    }
    let state = state::AppState::new_with_http_options(
        data_dir,
        cli.admin_password,
        state::HttpClientOptions {
            proxy: cli.http_proxy,
            ca_cert: cli.http_ca_cert,
            insecure_tls: cli.insecure_tls,
        },
    )?;
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
    tracing::info!("safedrive 已启动: http://{}", cli.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
