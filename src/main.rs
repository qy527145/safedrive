mod adapters;
mod assets;
mod auth;
mod crypto;
mod engine;
mod error;
mod registry;
mod routes;
mod settings;
mod state;
mod strategies;
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
    /// 数据目录（数据源注册表、策略、密码本），默认 ~/.safedrive
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,
    /// 管理密码；不设置则免登录（仅建议本机使用）
    #[arg(long, env = "SAFEDRIVE_ADMIN_PASSWORD")]
    admin_password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "safedrive=info,tower_http=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| ".".into()).join(".safedrive"));
    std::fs::create_dir_all(&data_dir)?;

    if cli.admin_password.is_none() {
        tracing::warn!("未设置 --admin-password / SAFEDRIVE_ADMIN_PASSWORD，API 免登录（仅建议本机使用）");
    }

    let state = state::AppState::new(data_dir, cli.admin_password)?;
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
    tracing::info!("safedrive 已启动: http://{}", cli.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
