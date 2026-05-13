use crate::analyze::ingest::ingest_cve;
use crate::config::Config;
use crate::http::build_client;
use crate::storage::Db;
use crate::sug::SugClient;
use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

/// Ingest the most recent N SUG releases, skipping CVEs already present at the same revision.
pub async fn run(cfg: &Config, n: usize, release_filter: Option<&str>) -> Result<()> {
    let http = build_client("patchwatch/0.1.0 (+poll)")?;
    let sug = SugClient::new(&cfg.msrc.sug_base_url, &cfg.msrc.language, http.clone());

    let db_path = cfg.storage.base_dir.join("patchwatch.db");
    std::fs::create_dir_all(&cfg.storage.base_dir)?;
    let db = Arc::new(Db::open(&db_path, 8)?);

    let releases = sug.list_releases().await?;
    let candidates: Vec<_> = releases
        .into_iter()
        .filter(|r| {
            if let Some(filter) = release_filter {
                r.release_number.eq_ignore_ascii_case(filter)
            } else {
                true
            }
        })
        .take(n)
        .collect();

    if candidates.is_empty() {
        println!("[!] No matching releases found");
        return Ok(());
    }

    let mut total_ingested = 0usize;
    for release in &candidates {
        info!(release = %release.release_number, "polling release");
        let vulns = match sug.vulnerabilities_in_release(&release.release_number).await {
            Ok(v) => v,
            Err(e) => {
                warn!(release = %release.release_number, %e, "failed to list vulns, skipping");
                continue;
            }
        };

        let http_ref = &http;
        for vuln in &vulns {
            let cve_id = &vuln.cve_number;
            match ingest_cve(cfg, &db, http_ref, cve_id).await {
                Ok(r) => {
                    println!("[+] {} ingested: KB={} files={} triaged={}", cve_id, r.kb_id, r.n_files, r.n_triaged);
                    total_ingested += 1;
                }
                Err(e) => {
                    warn!(%cve_id, %e, "ingest failed, skipping");
                }
            }
        }
    }

    println!("[+] poll complete: {} CVEs ingested across {} release(s)", total_ingested, candidates.len());
    Ok(())
}
