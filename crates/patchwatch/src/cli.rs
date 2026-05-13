use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "patchwatch", version)]
pub struct Cli {
    /// Path to config.yaml
    #[arg(long, default_value = "crates/patchwatch/config.example.yaml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Smoke-test individual pipeline stages (SUG, KB enumeration, Winbindex, Ghidra, full dry run).
    Validate {
        #[command(subcommand)]
        what: Validate,
    },
    /// Ingest the most recent N SUG releases into SQLite (no analysis).
    Poll {
        /// How many recent releases to process
        #[arg(long, default_value = "1")]
        n: usize,
        /// Limit to a specific release-number, e.g. "2026-Apr"
        #[arg(long)]
        release: Option<String>,
    },
    /// Run diff + LLM analysis on a single ingested CVE.
    Analyze {
        cve: String,
        /// Optional: pin the picked filename (default: top triage ranking)
        #[arg(long)]
        binary: Option<String>,
    },
    /// Boot the local webapp on 127.0.0.1:8765 (or configured bind_addr).
    Web,
    /// Materialize a per-CVE workspace for the pocsmith driver.
    ExportPocContext {
        /// CVE ID (e.g. CVE-2026-23669)
        cve: String,
        /// Output root directory (workspace dirs are created as <out>/<CVE>/)
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum Validate {
    /// Smoke-test the SUG endpoint (lists releases)
    Sug,
    /// Smoke-test Tier 1 enumeration of a KB
    KbCsv { kb: String },
    /// Smoke-test Tier 2 enumeration of a KB (downloads MSU; needs `expand.exe`)
    KbMsu {
        kb: String,
        /// MSU cache directory
        #[arg(long)]
        cache_dir: PathBuf,
    },
    /// Smoke-test Winbindex query for a filename + KB
    Winbindex { filename: String, kb: String },
    /// Smoke-test Ghidra headless on an arbitrary input binary
    Ghidra { binary: PathBuf },
    /// Run the full one-CVE end-to-end dry run (in-memory DB, no persistence)
    DryRun {
        cve: String,
        /// Optional: pin the picked filename (default: top triage ranking)
        #[arg(long)]
        binary: Option<String>,
    },
}
