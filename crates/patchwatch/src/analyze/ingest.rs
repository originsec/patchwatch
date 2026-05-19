use crate::config::Config;
use crate::kb::tier1::Tier1Client;
use crate::kb::tier2::CatalogClient;
use crate::sug::types::AffectedProduct;
use crate::sug::SugClient;
use crate::storage::Db;
use crate::triage::AnthropicClient;
use anyhow::{Result, anyhow};
use reqwest::Client;
use std::sync::Arc;
use tracing::{info, warn};

/// Returns true when a CVE meets the configured auto-triage threshold.
/// Used by `poll` to decide whether to run LLM triage during ingest.
pub fn is_triage_eligible(cfg: &Config, score: f64, exploited: bool) -> bool {
    score >= cfg.llm.min_cvss_score || (cfg.llm.triage_exploited && exploited)
}

/// Returns true when a CVE meets the configured auto-analyze threshold.
/// Used by `poll` to decide whether to run binary diff + deep analysis during ingest.
/// Explicit `patchwatch analyze` invocations and the web "Run Analysis" button do
/// NOT consult this — those always run regardless of severity.
pub fn is_analyze_eligible(cfg: &Config, score: f64, exploited: bool) -> bool {
    score >= cfg.llm.min_cvss_score_analyze || (cfg.llm.analyze_exploited && exploited)
}

pub struct IngestResult {
    pub cve_id: String,
    pub kb_id: String,
    pub n_files: usize,
    pub n_triaged: usize,
}

/// Returns true if `name` is a plain numeric KB number (digits only, optionally "KB"-prefixed).
/// Rejects non-KB strings like "Release Notes" or "Click to Run" that appear in Office/ASP.NET
/// affected-product rows and would otherwise produce bogus IDs like "KBRelease Notes".
fn is_numeric_kb(name: &str) -> bool {
    let digits = name.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Pick the KB for the highest-patched desktop x64 SKU from an affected-products list.
///
/// Returns `(kb_id, product_name)` so the caller can log which OS version was selected.
///
/// `windows_family` is matched case-insensitively against the product name (e.g. "windows 11").
/// `windows_version` further restricts to a specific release token (e.g. "26h1"). When `None`,
/// all qualifying products in the family are eligible and the highest `fixed_build_number` wins.
pub fn pick_desktop_kb(
    products: &[AffectedProduct],
    windows_family: &str,
    windows_version: Option<&str>,
) -> Option<(String, String)> {
    let family_token = windows_family.to_ascii_lowercase();
    let version_token = windows_version.map(|v| v.to_ascii_lowercase());

    let has_numeric_kb = |p: &AffectedProduct| -> bool {
        p.kb_articles
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|kb| kb.article_name.as_deref().map_or(false, is_numeric_kb))
    };

    let is_target_product = |p: &AffectedProduct| -> bool {
        let name = p.product.as_deref().unwrap_or("").to_ascii_lowercase();
        name.contains(&family_token)
            && version_token.as_deref().map_or(true, |v| name.contains(v))
            && !name.contains("server")
            && !name.contains("arm64")
            && !name.contains("arm-based")
            && !name.contains("iot")
            && !name.contains("mobile")
            && !name.contains(" rt ")
            && !name.ends_with(" rt")
    };

    let build_number = |p: &AffectedProduct| -> u32 {
        p.kb_articles
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find_map(|kb| {
                kb.fixed_build_number.as_deref().and_then(|s| {
                    s.split('.').nth(2).and_then(|n| n.parse().ok())
                })
            })
            .unwrap_or(0)
    };

    let best = products
        .iter()
        .filter(|p| is_target_product(p) && has_numeric_kb(p))
        .max_by_key(|p| build_number(p))?;

    let product_name = best.product.clone().unwrap_or_default();
    let kb_id = best
        .kb_articles
        .as_deref()
        .and_then(|kbs| kbs.iter().find(|kb| kb.article_name.as_deref().map_or(false, is_numeric_kb)))
        .and_then(|kb| kb.article_name.clone())?;

    Some((kb_id, product_name))
}

#[cfg(test)]
mod pick_desktop_kb_tests {
    use super::*;
    use crate::sug::types::KbArticle as SugKb;

    fn product(name: &str, article_name: &str) -> AffectedProduct {
        product_with_build(name, article_name, None)
    }

    fn product_with_build(
        name: &str,
        article_name: &str,
        fixed_build_number: Option<&str>,
    ) -> AffectedProduct {
        AffectedProduct {
            cve_number: "CVE-2026-00001".into(),
            product: Some(name.into()),
            kb_articles: Some(vec![SugKb {
                article_name: Some(article_name.into()),
                article_url: None,
                fixed_build_number: fixed_build_number.map(|s| s.into()),
                reboot_required: None,
            }]),
        }
    }

    #[test]
    fn picks_highest_build_when_unpinned() {
        // With no version pin, the product with the highest fixed_build_number wins,
        // regardless of which release it belongs to.
        let products = vec![
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090407",
                Some("10.0.27100.500"),
            ),
            product_with_build(
                "Windows 11 Version 24H2 for x64-based Systems",
                "5087429",
                Some("10.0.26100.100"),
            ),
            product("Windows Server 2025", "5040431"),
        ];
        let (kb, product_name) = pick_desktop_kb(&products, "windows 11", None).unwrap();
        assert_eq!(kb, "5090407");
        assert!(product_name.contains("26H1"), "should log the matched product");
    }

    #[test]
    fn version_pin_restricts_to_named_release() {
        let products = vec![
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090407",
                Some("10.0.27100.500"),
            ),
            product_with_build(
                "Windows 11 Version 24H2 for x64-based Systems",
                "5087429",
                Some("10.0.26100.100"),
            ),
        ];
        let (kb, _) = pick_desktop_kb(&products, "windows 11", Some("24h2")).unwrap();
        assert_eq!(kb, "5087429");
    }

    #[test]
    fn picks_highest_build_when_multiple_versions_of_same_release() {
        let products = vec![
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090400",
                Some("10.0.27000.100"),
            ),
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090407",
                Some("10.0.27100.500"),
            ),
        ];
        let (kb, _) = pick_desktop_kb(&products, "windows 11", None).unwrap();
        assert_eq!(kb, "5090407");
    }

    #[test]
    fn rejects_arm64_and_server() {
        let products = vec![
            product("Windows 11 Version 26H1 for ARM64-based Systems", "5090406"),
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090407",
                Some("10.0.27100.500"),
            ),
            product("Windows Server 2025", "5040431"),
        ];
        let (kb, _) = pick_desktop_kb(&products, "windows 11", None).unwrap();
        assert_eq!(kb, "5090407");
    }

    #[test]
    fn rejects_release_notes_article_name() {
        let products = vec![
            product("ASP.NET Core 8.0", "Release Notes"),
            product("Microsoft Office 2024", "Click to Run"),
        ];
        assert_eq!(pick_desktop_kb(&products, "windows 11", None), None);
    }

    #[test]
    fn skips_bogus_kb_names_when_real_kb_present() {
        let products = vec![
            product("ASP.NET Core 8.0", "Release Notes"),
            product_with_build(
                "Windows 11 Version 26H1 for x64-based Systems",
                "5090407",
                Some("10.0.27100.500"),
            ),
        ];
        let (kb, _) = pick_desktop_kb(&products, "windows 11", None).unwrap();
        assert_eq!(kb, "5090407");
    }
}

/// Ingest a single CVE: SUG fetch → KB enumeration → LLM triage → DB persist.
///
/// Idempotent at every step:
/// - If the CVE is already in the DB at the same revision, triage is skipped.
/// - If the KB file list is already enumerated, the download is skipped.
pub async fn ingest_cve(
    cfg: &Config,
    db: &Arc<Db>,
    http: &Client,
    cve_id: &str,
) -> Result<IngestResult> {
    // 1. SUG → CVE detail + KB list
    info!(%cve_id, "INGEST step 1: SUG fetch");
    let sug = SugClient::new(&cfg.msrc.sug_base_url, &cfg.msrc.language, http.clone());
    let cve = sug
        .vulnerability_detail(cve_id)
        .await?
        .ok_or_else(|| anyhow!("CVE {} not found in SUG", cve_id))?;
    let products = sug.affected_products(cve_id).await?;

    let raw_json = serde_json::to_string(&cve).unwrap_or_default();

    let (raw_kb, matched_product) =
        pick_desktop_kb(&products, &cfg.msrc.windows_family, cfg.msrc.windows_version.as_deref())
            .ok_or_else(|| anyhow!("no KB found in affectedProducts for {}", cve_id))?;
    let kb_id = if raw_kb.starts_with("KB") {
        raw_kb
    } else {
        format!("KB{}", raw_kb)
    };
    info!(%kb_id, product = %matched_product, "picked KB");

    // Check if revision changed since last ingest. If the CVE is already in the DB at the
    // same revision and already has triage rankings, we can skip steps 2 and 3.
    let existing = db.get_cve(cve_id).await.unwrap_or(None);
    let already_triaged = if let Some(ref ex) = existing {
        let same_revision = ex.revision.as_deref() == cve.revision_number.as_deref();
        if same_revision {
            !db.get_triage(cve_id).await.unwrap_or_default().is_empty()
        } else {
            false
        }
    } else {
        false
    };

    // Persist CVE + KB link (upsert — safe to repeat)
    db.upsert_cve(&cve, raw_json).await?;
    db.upsert_cve_kb(cve_id, &kb_id).await?;

    if already_triaged {
        info!(%cve_id, "already triaged at current revision, skipping KB enumeration + triage");
        let n_files = db.get_kb_files(&kb_id).await.map(|f| f.len()).unwrap_or(0);
        let n_triaged = db.get_triage(cve_id).await.map(|r| r.len()).unwrap_or(0);
        return Ok(IngestResult { cve_id: cve_id.to_owned(), kb_id, n_files, n_triaged });
    }

    // 2. KB enumeration — skip if already stored for this KB
    let kb_files = db.get_kb_files(&kb_id).await.unwrap_or_default();
    let enumeration = if !kb_files.is_empty() {
        info!(%kb_id, n_files = kb_files.len(), "KB already enumerated, skipping download");
        // Return a lightweight placeholder — files are already in the DB.
        None
    } else {
        info!(%cve_id, "INGEST step 2: KB enumeration");
        let t1 = Tier1Client::new(&cfg.kb_enumeration.support_base_url, http.clone());
        let e = match t1.enumerate(&kb_id).await {
            Ok(e) => {
                info!(n_files = e.files.len(), source = "csv", "enumerated");
                e
            }
            Err(e) => {
                warn!(%e, "Tier 1 failed, falling back to Tier 2 (MSU catalog)");
                let c2 = CatalogClient::new(&cfg.update_catalog.base_url, http.clone());
                let kb_dir = cfg.storage.base_dir.join("kb-msu").join(&kb_id);
                let e2 = c2.enumerate(&kb_id, &kb_dir).await?;
                info!(n_files = e2.files.len(), source = "msu", "enumerated");
                e2
            }
        };
        db.upsert_kb_enumeration(&e).await?;
        db.upsert_kb_files(&kb_id, &e.files).await?;
        Some(e)
    };

    let n_files = enumeration
        .as_ref()
        .map(|e| e.files.len())
        .unwrap_or(kb_files.len());

    // 3. LLM triage — gated by configurable CVSS threshold and exploited flag
    let score = cve.base_score.unwrap_or(0.0);
    let exploited = cve.exploited.as_deref()
        .map_or(false, |e| e.eq_ignore_ascii_case("yes"));

    if !is_triage_eligible(cfg, score, exploited) {
        info!(
            %cve_id, score, exploited,
            min_cvss = cfg.llm.min_cvss_score,
            triage_exploited = cfg.llm.triage_exploited,
            "skipping triage: does not meet configured auto-triage gate"
        );
        return Ok(IngestResult { cve_id: cve_id.to_owned(), kb_id, n_files, n_triaged: 0 });
    }

    info!(%cve_id, score, exploited, "INGEST step 3: triage");
    let api_key = std::env::var(&cfg.llm.api_key_env)
        .map_err(|_| anyhow!("env var {} not set", cfg.llm.api_key_env))?;
    let an = AnthropicClient::new(
        api_key,
        "https://api.anthropic.com",
        &cfg.llm.model_primary,
        http.clone(),
    );

    // For triage we need the actual file list. Use the freshly enumerated one, or reload from DB.
    let files_for_triage = match enumeration {
        Some(ref e) => e.files.clone(),
        None => db.get_kb_files(&kb_id).await?,
    };
    let source_str = match enumeration {
        Some(ref e) => format!("{:?}", e.source).to_lowercase(),
        None => "csv".to_string(),
    };

    let rankings = an
        .triage(&cve, &kb_id, &files_for_triage, &source_str)
        .await?;

    db.upsert_triage(cve_id, &rankings).await?;
    let n_triaged = rankings.len();

    Ok(IngestResult { cve_id: cve_id.to_owned(), kb_id, n_files, n_triaged })
}

/// If the CVE meets the configured auto-analyze gate and no terminal-success or
/// in-flight diff job exists yet, run `analyze_cve` synchronously.
///
/// Failures inside the orchestrator are logged and the job is marked `failed`;
/// they never propagate up to fail the surrounding poll.
pub async fn auto_analyze_if_eligible(
    cfg: &Config,
    db: &Arc<Db>,
    http: &Client,
    cve_id: &str,
) -> Result<()> {
    let detail = match db.get_cve(cve_id).await? {
        Some(d) => d,
        None => return Ok(()),
    };
    let score = detail.cvss_score.unwrap_or(0.0);
    if !is_analyze_eligible(cfg, score, detail.exploited) {
        return Ok(());
    }
    if let Some(job) = db.get_latest_diff_job(cve_id).await? {
        if job.status == "done" {
            info!(%cve_id, job_id = job.id, "skipping auto-analyze: previous job already complete");
            return Ok(());
        }
        if !job.is_terminal() {
            info!(%cve_id, job_id = job.id, status = %job.status, "skipping auto-analyze: job already in flight");
            return Ok(());
        }
    }
    info!(%cve_id, score, exploited = detail.exploited, "POLL step 4: auto-analyze");
    let job_id = db.create_diff_job(cve_id).await?;
    match crate::analyze::orchestrator::analyze_cve(cfg, db, http, cve_id, job_id, None).await {
        Ok(r) => {
            println!(
                "[+] {} auto-analyzed: job={} diffed={} findings={}",
                cve_id, r.job_id, r.n_diffed, r.n_findings
            );
        }
        Err(e) => {
            warn!(%cve_id, %e, "auto-analyze failed");
            let _ = db
                .update_diff_job_status(job_id, "failed", Some(&format!("{e}")))
                .await;
        }
    }
    Ok(())
}
