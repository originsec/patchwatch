use crate::analyze::orchestrator::analyze_cve;
use crate::config::Config;
use crate::http::build_client;
use crate::storage::Db;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tracing::info;

/// Run diff + LLM analysis on a single ingested CVE.
/// Assumes `patchwatch poll` has already ingested the CVE.
pub async fn run(cfg: &Config, cve_id: &str, override_binary: Option<&str>) -> Result<()> {
    let db_path = cfg.storage.base_dir.join("patchwatch.db");
    if !db_path.exists() {
        anyhow::bail!("DB not found at {}; run `patchwatch poll` first", db_path.display());
    }
    let db = Arc::new(Db::open(&db_path, 8)?);

    // Verify CVE exists
    let detail = db.get_cve(cve_id).await?
        .ok_or_else(|| anyhow!("CVE {} not found in DB; run `patchwatch poll` first", cve_id))?;
    info!(%cve_id, kb = ?detail.kb_id, "starting analysis");

    let http = build_client("patchwatch/0.1.0 (+analyze)")?;
    let http = Arc::new(http);

    let job_id = db.create_diff_job(cve_id).await?;
    let result = analyze_cve(cfg, &db, &http, cve_id, job_id, override_binary).await?;

    println!("[+] analysis complete: job_id={} diffed={} findings={}", result.job_id, result.n_diffed, result.n_findings);
    println!("    report: {}", cfg.storage.base_dir.join("reports").join(cve_id).join("report.md").display());
    Ok(())
}
