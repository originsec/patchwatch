use crate::cache::Cache;
use crate::config::Config;
use crate::ghidra::{find_diff_json, parse_diff_json_full, run_ghidriff};
use crate::kb::types::Arch;
use crate::report::render::{AnalyzeReport, BinaryDiffResult, render_markdown};
use crate::storage::Db;
use crate::triage::{AnthropicClient, BinaryDiffInput, select_functions_for_deep_analysis};
use crate::winbindex::client::{WinbindexClient, select_pair};
use anyhow::{Result, anyhow};
use reqwest::Client;
use std::sync::Arc;
use tracing::{info, warn};

pub struct AnalyzeResult {
    pub job_id: i64,
    pub n_diffed: usize,
    pub n_findings: usize,
}

/// Build a unique label for a binary staged for ghidriff.
pub fn binary_label(stem: &str, ext: &str, version: Option<&str>, sha256_hex: &str) -> String {
    let id: String = version
        .map(|v| v.split_whitespace().next().unwrap_or(v).to_string())
        .unwrap_or_else(|| sha256_hex.chars().take(8).collect());
    format!("{}_{}{}", stem, id, ext)
}

/// Per-CVE diff orchestrator: Winbindex → ghidriff → LLM synthesis → deep analysis → DB writes.
///
/// The `job_id` must already exist in `diff_jobs` (created by the caller before enqueueing).
/// Status transitions: queued → fetching → diffing → synthesizing → deep_analyzing → done | failed.
pub async fn analyze_cve(
    cfg: &Config,
    db: &Arc<Db>,
    http: &Client,
    cve_id: &str,
    job_id: i64,
    override_binary: Option<&str>,
) -> Result<AnalyzeResult> {
    let set_status = |status: &'static str| {
        let db = db.clone();
        let status = status.to_owned();
        let job_id = job_id;
        async move { db.update_diff_job_status(job_id, &status, None).await }
    };

    // 4. Collect candidates and download binary pairs
    set_status("fetching").await?;
    info!(%cve_id, "ORCHESTRATOR step 4: winbindex fetch + ghidriff");

    let detail = db.get_cve(cve_id).await?
        .ok_or_else(|| anyhow!("CVE {} not found in DB (run ingest first)", cve_id))?;
    let kb_id = detail.kb_id.clone().unwrap_or_default();
    let kb_files = db.get_kb_files(&kb_id).await?;

    let api_key = std::env::var(&cfg.llm.api_key_env)
        .map_err(|_| anyhow!("env var {} not set", cfg.llm.api_key_env))?;
    // We need a fresh CVE struct for LLM prompts — pull from DB-stored raw JSON via SUG client
    // is expensive; instead, fetch it again (it's cached by reqwest).
    let sug = crate::sug::SugClient::new(&cfg.msrc.sug_base_url, &cfg.msrc.language, http.clone());
    let cve = sug.vulnerability_detail(cve_id).await?
        .ok_or_else(|| anyhow!("CVE {} not found in SUG", cve_id))?;

    let an = AnthropicClient::new(
        api_key,
        "https://api.anthropic.com",
        &cfg.llm.model_primary,
        http.clone(),
    );

    // Run triage on-demand if the CVE was skipped during poll (below threshold).
    let rankings = {
        let existing = db.get_triage(cve_id).await?;
        if existing.is_empty() {
            info!(%cve_id, "no triage rankings in DB, running on-demand triage");
            let r = an.triage(&cve, &kb_id, &kb_files, "db").await?;
            db.upsert_triage(cve_id, &r).await?;
            r
        } else {
            existing
        }
    };

    let wb = WinbindexClient::new(&cfg.winbindex.base_url, http.clone());
    let cache = Cache::new(&cfg.storage.base_dir);
    let max = cfg.llm.max_diff_candidates;

    let mut sorted_rankings = rankings.clone();
    sorted_rankings.sort_by(|a, b| {
        b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
    });

    let candidates: Vec<String> = if let Some(b) = override_binary {
        vec![b.to_string()]
    } else {
        // Deduplicate by lowercase filename — triage can rank the same binary twice
        // (e.g. d3d12.dll appeared twice in CVE-2026-40403), wasting a diff slot and
        // producing duplicate report entries. Rankings are sorted descending by
        // confidence, so the first (highest-confidence) occurrence wins.
        let mut seen = std::collections::HashSet::new();
        sorted_rankings.iter()
            .map(|r| r.filename.clone())
            .filter(|f| seen.insert(f.to_ascii_lowercase()))
            .collect()
    };

    let mut diffed: Vec<BinaryDiffResult> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    for filename in &candidates {
        if diffed.len() >= max {
            break;
        }
        info!(%filename, "trying winbindex");
        let map = match wb.fetch_file_data(filename).await {
            Ok(m) => m,
            Err(e) => {
                warn!(%filename, %e, "winbindex fetch failed, skipping");
                skipped.push(format!("{} (winbindex fetch failed: {})", filename, e));
                continue;
            }
        };

        let kb_version = kb_files
            .iter()
            .find(|f| f.filename.eq_ignore_ascii_case(filename))
            .map(|f| f.version.as_str());

        let pair = match select_pair(&map, &kb_id, Arch::X64, kb_version) {
            Some(p) => p,
            None => {
                warn!(%filename, "no pair in winbindex, skipping");
                skipped.push(format!("{} (no winbindex pair found)", filename));
                continue;
            }
        };
        info!(%filename, confidence = ?pair.confidence, "selected pair");

        let post = match wb.download_entry(filename, &pair.patched, &cache).await {
            Ok(b) => b,
            Err(e) => {
                warn!(%filename, %e, "download patched failed, skipping");
                skipped.push(format!("{} (download patched failed: {})", filename, e));
                continue;
            }
        };
        let pre = match wb.download_entry(filename, &pair.previous, &cache).await {
            Ok(b) => b,
            Err(e) => {
                warn!(%filename, %e, "download previous failed, skipping");
                skipped.push(format!("{} (download previous failed: {})", filename, e));
                continue;
            }
        };

        let stem = std::path::Path::new(filename)
            .file_stem().and_then(|s| s.to_str()).unwrap_or(filename.as_str());
        let ext = std::path::Path::new(filename)
            .extension().and_then(|s| s.to_str())
            .map(|e| format!(".{}", e)).unwrap_or_default();

        let pre_label = binary_label(stem, &ext, pre.version.as_deref(), &pre.sha256_hex);
        let post_label = binary_label(stem, &ext, post.version.as_deref(), &post.sha256_hex);

        set_status("diffing").await?;
        info!(%filename, %pre_label, %post_label, "running ghidriff");
        let diff_res = match run_ghidriff(&cfg.diff_engine, &pre.path, &post.path, stem, &pre_label, &post_label).await {
            Ok(r) => r,
            Err(e) => {
                warn!(%filename, %e, "ghidriff spawn failed");
                let ranking = sorted_rankings.iter().find(|r| r.filename.eq_ignore_ascii_case(filename));
                diffed.push(BinaryDiffResult {
                    filename: filename.clone(),
                    triage_confidence: ranking.map(|r| r.confidence).unwrap_or(0.0),
                    triage_reasoning: ranking.map(|r| r.reasoning.clone()).unwrap_or_default(),
                    pair_confidence: pair.confidence,
                    patched: post, previous: pre,
                    ghidriff_exit: None,
                    ghidriff_output_dir: std::path::PathBuf::new(),
                    diff_summary: None, diff_index: None, deep_analysis: None,
                });
                continue;
            }
        };

        let (diff_summary, diff_index) = match find_diff_json(&diff_res.output_dir)
            .and_then(|p| std::fs::read_to_string(&p).ok())
        {
            Some(json) => { let (s, i) = parse_diff_json_full(&json); (Some(s), Some(i)) }
            None => (None, None),
        };

        let ranking = sorted_rankings.iter().find(|r| r.filename.eq_ignore_ascii_case(filename));
        diffed.push(BinaryDiffResult {
            filename: filename.clone(),
            triage_confidence: ranking.map(|r| r.confidence).unwrap_or(0.0),
            triage_reasoning: ranking.map(|r| r.reasoning.clone()).unwrap_or_default(),
            pair_confidence: pair.confidence,
            patched: post, previous: pre,
            ghidriff_exit: diff_res.exit_code,
            ghidriff_output_dir: diff_res.output_dir,
            diff_summary, diff_index, deep_analysis: None,
        });
    }

    if diffed.is_empty() {
        let e = anyhow!("no winbindex pair found for any triage candidate for {}", cve_id);
        db.update_diff_job_status(job_id, "failed", Some(&e.to_string())).await?;
        return Err(e);
    }

    if !skipped.is_empty() {
        warn!(
            cve = %cve_id,
            n_diffed = diffed.len(),
            n_skipped = skipped.len(),
            skipped = ?skipped,
            "fetch loop complete: some triage candidates were skipped — \
             they are NOT in the diff set and their absence does not mean 'no changes'"
        );
    }

    // 5. Synthesis pass
    set_status("synthesizing").await?;
    info!(%cve_id, "ORCHESTRATOR step 5: synthesis");
    let synthesis_inputs: Vec<BinaryDiffInput<'_>> = diffed.iter().map(|d| BinaryDiffInput {
        filename: &d.filename,
        triage_confidence: d.triage_confidence,
        triage_reasoning: &d.triage_reasoning,
        diff_summary: d.diff_summary.as_ref(),
        diff_failed: d.diff_failed(),
    }).collect();

    let synthesis = match an.synthesize(&cve, &synthesis_inputs).await {
        Ok(s) => {
            info!(primary = ?s.primary_binaries, n_ranked = s.ranked_functions.len(), "synthesis complete");
            db.upsert_synthesis(cve_id, job_id, &s).await?;
            db.upsert_synthesis_binaries(cve_id, &s.per_binary).await?;
            Some(s)
        }
        Err(e) => {
            warn!(%e, "synthesis failed");
            None
        }
    };

    // 6. Deep analysis pass
    set_status("deep_analyzing").await?;
    info!(%cve_id, "ORCHESTRATOR step 6: deep analysis");
    let mut n_findings = 0usize;
    if let Some(syn) = &synthesis {
        for d in &mut diffed {
            if !syn.primary_binaries.iter().any(|p| p.eq_ignore_ascii_case(&d.filename)) {
                continue;
            }
            let index = match &d.diff_index {
                Some(idx) => idx,
                None => { info!(filename = %d.filename, "no diff index, skipping deep analysis"); continue; }
            };
            let functions = select_functions_for_deep_analysis(
                &d.filename, &syn.ranked_functions, index, cfg.llm.deep_analysis_top_n,
            );
            if functions.is_empty() { continue; }
            info!(filename = %d.filename, n = functions.len(), "deep analysis");
            match an.deep_analyze(&cve, &d.filename, &functions).await {
                Ok(da) => {
                    n_findings += da.findings.len();
                    db.upsert_findings(cve_id, &d.filename, &da).await?;
                    d.deep_analysis = Some(da);
                }
                Err(e) => { warn!(filename = %d.filename, %e, "deep analysis failed"); }
            }
        }
    }

    // 7. Write Markdown report for CLI/sharing use
    info!(%cve_id, "ORCHESTRATOR step 7: write markdown report");
    let report = AnalyzeReport {
        cve: &cve,
        kb_id: &kb_id,
        enumeration: &{
            // Build a minimal enumeration from what we have for the report renderer.
            // The real enumeration is in the DB; this is just for the legacy report path.
            let kb_detail = db.get_cve(cve_id).await?.and_then(|d| d.kb_id).unwrap_or_default();
            crate::kb::types::KbEnumeration {
                kb_id: kb_detail,
                source: crate::kb::types::KbSource::Csv,
                csv_url: None, msu_path: None, fallback_reason: None,
                files: kb_files,
            }
        },
        all_rankings: &sorted_rankings,
        diffed: &diffed,
        synthesis: synthesis.as_ref(),
    };
    let md = render_markdown(&report);
    let out_dir = cfg.storage.base_dir.join("reports").join(cve_id);
    std::fs::create_dir_all(&out_dir)?;
    let report_path = out_dir.join("report.md");
    std::fs::write(&report_path, &md)?;
    info!(report_path = %report_path.display(), "wrote report");

    let pc = crate::report::PocsmithContext::from_report(&report);
    let json_path = out_dir.join("report.json");
    let pc_json = serde_json::to_string_pretty(&pc)?;
    std::fs::write(&json_path, pc_json)?;
    info!(json_path = %json_path.display(), "wrote pocsmith context json");

    let n_diffed = diffed.len();
    db.update_diff_job_status(job_id, "done", None).await?;

    Ok(AnalyzeResult { job_id, n_diffed, n_findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_label_uses_version_when_available() {
        let label = binary_label("rpcrt4", ".dll", Some("10.0.26100.1882"), "aabbccdd11223344");
        assert_eq!(label, "rpcrt4_10.0.26100.1882.dll");
    }

    #[test]
    fn binary_label_strips_winbuild_suffix() {
        let ver = "10.0.26100.1882 (WinBuild.160101.0800)";
        let label = binary_label("rpcrt4", ".dll", Some(ver), "aabbccdd11223344");
        assert_eq!(label, "rpcrt4_10.0.26100.1882.dll");
    }

    #[test]
    fn binary_label_falls_back_to_sha_snippet() {
        let label = binary_label("rpcrt4", ".dll", None, "aabbccdd11223344");
        assert_eq!(label, "rpcrt4_aabbccdd.dll");
    }
}
