use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct MsrcConfig {
    pub sug_base_url: String,
    pub language: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WinbindexConfig {
    pub base_url: String,
    pub user_agent: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LlmConfig {
    pub model_primary: String,
    pub model_fallback: String,
    pub api_key_env: String,
    pub triage_top_n: u32,
    /// Maximum number of triage candidates to diff and feed into synthesis.
    #[serde(default = "default_max_diff_candidates")]
    pub max_diff_candidates: usize,
    /// Maximum number of ranked functions (per binary) to send to the Stage 2 deep analysis pass.
    #[serde(default = "default_deep_analysis_top_n")]
    pub deep_analysis_top_n: usize,
}

fn default_max_diff_candidates() -> usize {
    5
}

fn default_deep_analysis_top_n() -> usize {
    10
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DiffEngineConfig {
    /// Run ghidriff inside a Docker container (no local Ghidra required).
    Docker {
        /// Container image, e.g. "ghcr.io/clearbluejar/ghidriff:latest"
        image: String,
        /// Host directory mounted into the container as /ghidriffs (output + project cache)
        volume_root: PathBuf,
        /// Extra docker run flags, e.g. ["--cpus", "4"]
        #[serde(default)]
        extra_args: Vec<String>,
    },
    /// Run a locally-installed ghidriff (pip install ghidriff + GHIDRA_INSTALL_DIR set).
    Local {
        /// Path to the ghidriff executable or "ghidriff" if on PATH
        #[serde(default = "default_ghidriff_bin")]
        ghidriff_bin: String,
        /// Passed as GHIDRA_INSTALL_DIR; required for local mode
        ghidra_install_dir: PathBuf,
        /// Output/project root
        output_dir: PathBuf,
    },
}

fn default_ghidriff_bin() -> String {
    "ghidriff".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub base_dir: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpdateCatalogConfig {
    pub base_url: String,
    pub user_agent: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KbEnumerationConfig {
    /// Base URL for the support.microsoft.com topic pages. Tier 1 appends `/help/<kb>`
    /// and follows redirects to the rendered topic page.
    pub support_base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebConfig {
    /// TCP address to bind. Default: 127.0.0.1:8765.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Name of the env var holding the CSRF secret. Required for POST endpoints.
    #[serde(default = "default_csrf_secret_env")]
    pub csrf_secret_env: String,
    /// CVE list page size.
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    /// Allow binding to non-loopback addresses. Default false (loopback-only).
    #[serde(default)]
    pub allow_non_loopback: bool,
    /// deadpool-sqlite pool size.
    #[serde(default = "default_db_pool_size")]
    pub db_pool_size: usize,
}

fn default_bind_addr() -> String { "127.0.0.1:8765".into() }
fn default_csrf_secret_env() -> String { "PATCHWATCH_CSRF_SECRET".into() }
fn default_page_size() -> usize { 25 }
fn default_db_pool_size() -> usize { 8 }

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            csrf_secret_env: default_csrf_secret_env(),
            page_size: default_page_size(),
            allow_non_loopback: false,
            db_pool_size: default_db_pool_size(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub msrc: MsrcConfig,
    pub kb_enumeration: KbEnumerationConfig,
    pub update_catalog: UpdateCatalogConfig,
    pub winbindex: WinbindexConfig,
    pub llm: LlmConfig,
    pub diff_engine: DiffEngineConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub web: WebConfig,
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        if s == "~" {
            home
        } else {
            home.join(&s[2..])
        }
    } else {
        path
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("config file not found: {}", path.display()))?;
        let mut cfg: Self = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("failed to parse config: {}", path.display()))?;
        cfg.storage.base_dir = expand_tilde(cfg.storage.base_dir);
        cfg.diff_engine = match cfg.diff_engine {
            DiffEngineConfig::Docker { image, volume_root, extra_args } => DiffEngineConfig::Docker {
                image,
                volume_root: expand_tilde(volume_root),
                extra_args,
            },
            DiffEngineConfig::Local { ghidriff_bin, ghidra_install_dir, output_dir } => DiffEngineConfig::Local {
                ghidriff_bin,
                ghidra_install_dir: expand_tilde(ghidra_install_dir),
                output_dir: expand_tilde(output_dir),
            },
        };
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_example_config() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.yaml");
        let cfg = Config::load(&path).expect("load example");
        assert_eq!(cfg.msrc.language, "en-US");
        assert_eq!(cfg.llm.triage_top_n, 5);
    }
}
