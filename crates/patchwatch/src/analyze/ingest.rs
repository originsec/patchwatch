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

/// Pick the KB for the most recent desktop x64 Windows SKU from an affected-products list.
pub fn pick_desktop_kb(products: &[AffectedProduct]) -> Option<String> {
    let has_numeric_kb = |p: &AffectedProduct| -> bool {
        p.kb_articles
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|kb| kb.article_name.as_deref().map_or(false, is_numeric_kb))
    };

    let is_win11_26h1_x64 = |p: &AffectedProduct| -> bool {
        let name = p.product.as_deref().unwrap_or("").to_ascii_lowercase();
        name.contains("windows 11")
            && name.contains("26h1")
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
        .filter(|p| is_win11_26h1_x64(p) && has_numeric_kb(p))
        .max_by_key(|p| build_number(p));

    best
        .and_then(|p| p.kb_articles.as_deref())
        .and_then(|kbs| {
            kbs.iter()
                .find(|kb| kb.article_name.as_deref().map_or(false, is_numeric_kb))
        })
        .and_then(|kb| kb.article_name.clone())
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
    fn picks_win11_26h1_x64_kb() {
        let products = vec![
            product("Windows 11 Version 26H1 for x64-based Systems", "5090407"),
            product("Windows 11 Version 24H2 for x64-based Systems", "5087429"),
            product("Windows Server 2025", "5040431"),
        ];
        assert_eq!(pick_desktop_kb(&products).as_deref(), Some("5090407"));
    }

    #[test]
    fn picks_higher_build_number_when_multiple_26h1_x64_present() {
        // Two qualifying products — pick must use build_number tie-break (3rd dot-separated component).
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
        assert_eq!(pick_desktop_kb(&products).as_deref(), Some("5090407"));
    }

    #[test]
    fn rejects_non_26h1_windows_versions() {
        let products = vec![
            product("Windows 10 Version 22H2 for x64-based Systems", "5040442"),
            product("Windows 11 Version 24H2 for x64-based Systems", "5087429"),
            product("Windows Server 2022", "5040431"),
        ];
        assert_eq!(pick_desktop_kb(&products), None);
    }

    #[test]
    fn rejects_26h1_arm64() {
        let products = vec![
            product("Windows 11 Version 26H1 for ARM64-based Systems", "5090406"),
            product("Windows 11 Version 26H1 for x64-based Systems", "5090407"),
        ];
        assert_eq!(pick_desktop_kb(&products).as_deref(), Some("5090407"));
    }

    #[test]
    fn rejects_release_notes_article_name() {
        let products = vec![
            product("ASP.NET Core 8.0", "Release Notes"),
            product("Microsoft Office 2024", "Click to Run"),
        ];
        assert_eq!(pick_desktop_kb(&products), None);
    }

    #[test]
    fn skips_bogus_kb_names_when_real_kb_present() {
        let products = vec![
            product("ASP.NET Core 8.0", "Release Notes"),
            product("Windows 11 Version 26H1 for x64-based Systems", "5090407"),
        ];
        assert_eq!(pick_desktop_kb(&products).as_deref(), Some("5090407"));
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

    let raw_kb = pick_desktop_kb(&products)
        .ok_or_else(|| anyhow!("no KB found in affectedProducts for {}", cve_id))?;
    let kb_id = if raw_kb.starts_with("KB") {
        raw_kb
    } else {
        format!("KB{}", raw_kb)
    };
    info!(%kb_id, "picked KB");

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

    // 3. LLM triage — only for high-severity or actively exploited CVEs
    let score = cve.base_score.unwrap_or(0.0);
    let exploited = cve.exploited.as_deref()
        .map_or(false, |e| e.eq_ignore_ascii_case("yes"));
    let triage_eligible = score >= 9.0 || exploited;

    if !triage_eligible {
        info!(%cve_id, score, "skipping triage: score < 9.0 and not exploited");
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
