use clap::Parser;
use patchwatch::cli::Command;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cli = patchwatch::cli::Cli::parse();
    let cfg = patchwatch::config::Config::load(&cli.config)?;

    let log_dir = cfg.storage.base_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "patchwatch.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = || {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("patchwatch=info"))
    };
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(env_filter()))
        .with(fmt::layer().with_ansi(false).with_writer(non_blocking).with_filter(env_filter()))
        .init();

    match cli.command {
        Command::Validate { what } => {
            patchwatch::validate::dispatch_validate(&cfg, what).await?;
        }
        Command::Poll { n, release } => {
            patchwatch::commands::poll::run(&cfg, n, release.as_deref()).await?;
        }
        Command::Analyze { cve, binary } => {
            patchwatch::commands::analyze::run(&cfg, &cve, binary.as_deref()).await?;
        }
        Command::Web => {
            patchwatch::web::run(cfg).await?;
        }
        Command::ExportPocContext { cve, out } => {
            let report_dir = cfg.storage.base_dir.join("reports").join(&cve);
            let enrichment = {
                let db_path = cfg.storage.base_dir.join("patchwatch.db");
                if db_path.exists() {
                    let db = patchwatch::storage::Db::open(&db_path, 2)?;
                    db.get_cve(&cve).await?.map(|d| {
                        patchwatch::commands::export_poc_context::CveEnrichment {
                            cvss: d.cvss_score,
                            cvss_vector: d.cvss_vector,
                        }
                    })
                } else {
                    None
                }
            };
            patchwatch::commands::export_poc_context::export_poc_context(
                &report_dir,
                &out,
                enrichment.as_ref(),
            )?;
            println!("wrote workspace to {}", out.join(&cve).display());
        }
    }
    Ok(())
}
