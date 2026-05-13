use crate::analyze::ingest::ingest_cve;
use crate::analyze::orchestrator::analyze_cve;
use crate::cli::Validate;
use crate::config::Config;
use crate::http::build_client;
use crate::kb::tier1::Tier1Client;
use crate::kb::tier2::CatalogClient;
use crate::kb::types::Arch;
use crate::storage::Db;
use crate::winbindex::client::{WinbindexClient, select_pair};
use crate::cache::Cache;
use anyhow::{Result, anyhow};
use std::sync::Arc;

pub async fn dispatch_validate(cfg: &Config, what: Validate) -> Result<()> {
    match what {
        Validate::Sug => {
            let http = build_client("patchwatch/0.0.1 (+validate)")?;
            let client = crate::sug::SugClient::new(&cfg.msrc.sug_base_url, &cfg.msrc.language, http);
            let releases = client.list_releases().await?;
            let recent: Vec<_> = releases.iter().filter(|r| r.release_number.starts_with("2026-")).collect();
            println!("[+] Got {} releases ({} are 2026)", releases.len(), recent.len());
            for r in recent.iter().take(5) {
                println!("    {} {}", r.release_number, r.release_date.as_deref().unwrap_or(""));
            }
        }
        Validate::KbCsv { kb } => {
            let http = build_client("patchwatch/0.0.1 (+validate)")?;
            let t1 = Tier1Client::new(&cfg.kb_enumeration.support_base_url, http);
            let enumeration = t1.enumerate(&kb).await?;
            println!("[+] KB {} enumerated via Tier 1; {} files", enumeration.kb_id, enumeration.files.len());
            println!("    csv_url: {}", enumeration.csv_url.as_deref().unwrap_or("(none)"));
            println!("    file_list_hash: {}", enumeration.file_list_hash());
            let mut by_arch = std::collections::BTreeMap::<Arch, usize>::new();
            for f in &enumeration.files { *by_arch.entry(f.arch).or_default() += 1; }
            println!("    breakdown by arch:");
            for (a, n) in &by_arch { println!("      {:?}: {}", a, n); }
            let x64: Vec<_> = enumeration.files.iter().filter(|f| f.arch == Arch::X64).collect();
            println!("    first 10 x64 entries:");
            for f in x64.iter().take(10) { println!("    - {} {}", f.filename, f.version); }
        }
        Validate::KbMsu { kb, cache_dir } => {
            let http = build_client(&cfg.update_catalog.user_agent)?;
            let c = CatalogClient::new(&cfg.update_catalog.base_url, http);
            let kb_dir = cache_dir.join(&kb);
            let enumeration = c.enumerate(&kb, &kb_dir).await?;
            println!("[+] KB {} enumerated via Tier 2; {} files", enumeration.kb_id, enumeration.files.len());
            println!("    msu_path: {:?}", enumeration.msu_path);
            println!("    file_list_hash: {}", enumeration.file_list_hash());
            for f in enumeration.files.iter().take(10) { println!("    - {} {} ({:?})", f.filename, f.version, f.arch); }
        }
        Validate::Winbindex { filename, kb } => {
            let http = build_client(&cfg.winbindex.user_agent)?;
            let c = WinbindexClient::new(&cfg.winbindex.base_url, http);
            let map = c.fetch_file_data(&filename).await?;
            println!("[+] Winbindex returned {} entries for {}", map.len(), filename);
            let pair = select_pair(&map, &kb, Arch::X64, None)
                .ok_or_else(|| anyhow!("no patched/previous pair for {} {}", filename, kb))?;
            println!("    patched : {} (sha256 {:?})", pair.patched.version().unwrap_or(""), pair.patched.sha256());
            println!("    previous: {} (sha256 {:?})", pair.previous.version().unwrap_or(""), pair.previous.sha256());
            let cache = Cache::new(&cfg.storage.base_dir);
            let http2 = build_client(&cfg.winbindex.user_agent)?;
            let c2 = WinbindexClient::new(&cfg.winbindex.base_url, http2);
            let post = c2.download_entry(&filename, &pair.patched, &cache).await?;
            let pre = c2.download_entry(&filename, &pair.previous, &cache).await?;
            println!("    fetched patched : {} ({} bytes)", post.path.display(), post.size);
            println!("    fetched previous: {} ({} bytes)", pre.path.display(), pre.size);
        }
        Validate::Ghidra { binary } => {
            let name = binary.file_name().and_then(|s| s.to_str()).unwrap_or("binary");
            let result = crate::ghidra::run_ghidriff(&cfg.diff_engine, &binary, &binary, "validate", name, name).await?;
            println!("[+] ghidriff exit={:?}", result.exit_code);
            println!("    output_dir: {}", result.output_dir.display());
            if result.exit_code != Some(0) { anyhow::bail!("ghidriff failed"); }
        }
        Validate::DryRun { cve, binary } => {
            let path = run_dry_run(cfg, &cve, binary.as_deref()).await?;
            println!("[+] dry run complete: {}", path);
        }
    }
    Ok(())
}

/// Dry-run: ingest + analyze in one shot against an in-memory DB, no
/// persistent state between runs. Used by `patchwatch validate dry-run <CVE>`.
pub async fn run_dry_run(
    cfg: &Config,
    cve_id: &str,
    override_binary: Option<&str>,
) -> Result<String> {
    let http = build_client("patchwatch/0.0.1 (+validate)")?;
    let http = Arc::new(http);

    // Use an in-memory DB so the dry-run doesn't write to the persistent store.
    let db = Arc::new(Db::open_in_memory_async().await?);

    ingest_cve(cfg, &db, &http, cve_id).await?;
    let job_id = db.create_diff_job(cve_id).await?;
    analyze_cve(cfg, &db, &http, cve_id, job_id, override_binary).await?;

    let report_path = cfg
        .storage
        .base_dir
        .join("reports")
        .join(cve_id)
        .join("report.md");
    Ok(report_path.display().to_string())
}

