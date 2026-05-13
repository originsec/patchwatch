pub mod csrf;
pub mod highlight;
pub mod jobs;
pub mod markdown;
pub mod router;
pub mod views;

use crate::config::Config;
use crate::http::build_client;
use crate::storage::Db;
use anyhow::Result;
use router::AppState;
use std::sync::Arc;
use tracing::{info, warn};

pub async fn run(cfg: Config) -> Result<()> {
    let bind: std::net::SocketAddr = cfg.web.bind_addr.parse()?;

    if !bind.ip().is_loopback() && !cfg.web.allow_non_loopback {
        anyhow::bail!(
            "bind_addr {} is non-loopback but web.allow_non_loopback is false; \
             refusing to expose. Set allow_non_loopback: true to override.",
            bind
        );
    }
    if !bind.ip().is_loopback() {
        warn!(%bind, "binding to non-loopback address -- ensure auth/TLS are in place");
    }

    let db_path = cfg.storage.base_dir.join("patchwatch.db");
    std::fs::create_dir_all(&cfg.storage.base_dir)?;
    let db = Arc::new(Db::open(&db_path, cfg.web.db_pool_size)?);
    let stale = db.fail_stale_diff_jobs("process_restart").await?;
    if stale > 0 {
        warn!(stale, "failed stale diff_jobs from previous run");
    }

    let csrf_secret = std::env::var(&cfg.web.csrf_secret_env).unwrap_or_else(|_| {
        warn!(
            env = %cfg.web.csrf_secret_env,
            "CSRF secret env var not set; using insecure default (localhost dev only)"
        );
        "dev-insecure-csrf-secret".to_string()
    });

    let http = build_client("patchwatch/0.1.0 (+web)")?;
    let analyze_svc = jobs::AnalyzeService::spawn(Arc::new(cfg.clone()), db.clone(), http);

    let state = AppState {
        cfg: Arc::new(cfg),
        db,
        analyze: Arc::new(analyze_svc),
        csrf_secret,
    };

    let app = router::build_router(state);

    info!(%bind, "patchwatch web listening");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
