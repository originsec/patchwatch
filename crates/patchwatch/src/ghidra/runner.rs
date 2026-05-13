use crate::config::DiffEngineConfig;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

#[derive(Debug, Clone)]
pub struct GhidriffResult {
    pub output_dir: PathBuf,
    pub exit_code: Option<i32>,
}

/// Run ghidriff against two binaries using either Docker or a local install.
///
/// `pre_label` / `post_label` are the filenames ghidriff will see (and use as report titles),
/// e.g. `rpcrt4_10.0.26100.1882.dll` and `rpcrt4_10.0.26100.2314.dll`.  They must include
/// the correct extension so Ghidra's PE loader recognises the file type.
///
/// `subdir` namespaces the output within the configured output root so multiple diffs can run
/// without clobbering each other.  Outputs land in `<output_root>/<subdir>/`.
pub async fn run_ghidriff(
    cfg: &DiffEngineConfig,
    pre: &Path,
    post: &Path,
    subdir: &str,
    pre_label: &str,
    post_label: &str,
) -> Result<GhidriffResult> {
    match cfg {
        DiffEngineConfig::Docker {
            image,
            volume_root,
            extra_args,
        } => run_docker(image, volume_root, extra_args, pre, post, subdir, pre_label, post_label).await,
        DiffEngineConfig::Local {
            ghidriff_bin,
            ghidra_install_dir,
            output_dir,
        } => run_local(ghidriff_bin, ghidra_install_dir, output_dir, pre, post, subdir, pre_label, post_label).await,
    }
}

async fn run_docker(
    image: &str,
    volume_root: &Path,
    extra_args: &[String],
    pre: &Path,
    post: &Path,
    subdir: &str,
    pre_label: &str,
    post_label: &str,
) -> Result<GhidriffResult> {
    let host_out = volume_root.join(subdir);

    // Skip if the diff JSON already exists from a previous run.
    let json_path = ghidriff_json_path(&host_out, pre_label, post_label);
    if json_path.exists() {
        info!(%subdir, "ghidriff JSON cache hit, skipping diff");
        return Ok(GhidriffResult { output_dir: host_out, exit_code: Some(0) });
    }

    std::fs::create_dir_all(&host_out)
        .with_context(|| format!("create output dir {}", host_out.display()))?;

    // Stage binaries with their label names so ghidriff's report title is meaningful.
    let pre_dest = host_out.join(pre_label);
    let post_dest = host_out.join(post_label);
    std::fs::copy(pre, &pre_dest)
        .with_context(|| format!("copy pre binary to {}", pre_dest.display()))?;
    std::fs::copy(post, &post_dest)
        .with_context(|| format!("copy post binary to {}", post_dest.display()))?;

    let pre_ctr = format!("/ghidriffs/{}/{}", subdir, pre_label);
    let post_ctr = format!("/ghidriffs/{}/{}", subdir, post_label);
    let out_ctr = format!("/ghidriffs/{}", subdir);
    let volume_arg = format!("{}:/ghidriffs", volume_root.display());

    let mut args: Vec<String> = vec!["run".into(), "--rm".into(), "-v".into(), volume_arg];
    args.extend_from_slice(extra_args);
    args.push(image.to_string());
    args.extend([pre_ctr, post_ctr, "-o".into(), out_ctr]);

    info!(?args, "spawning ghidriff via docker");
    let status = Command::new("docker")
        .args(&args)
        .status()
        .await
        .context("spawn docker")?;

    Ok(GhidriffResult {
        output_dir: host_out,
        exit_code: status.code(),
    })
}

async fn run_local(
    ghidriff_bin: &str,
    ghidra_install_dir: &Path,
    output_dir: &Path,
    pre: &Path,
    post: &Path,
    subdir: &str,
    pre_label: &str,
    post_label: &str,
) -> Result<GhidriffResult> {
    let out = output_dir.join(subdir);

    // Skip if the diff JSON already exists from a previous run.
    let json_path = ghidriff_json_path(&out, pre_label, post_label);
    if json_path.exists() {
        info!(%subdir, "ghidriff JSON cache hit, skipping diff");
        return Ok(GhidriffResult { output_dir: out, exit_code: Some(0) });
    }

    std::fs::create_dir_all(&out)
        .with_context(|| format!("create output dir {}", out.display()))?;

    let pre_dest = out.join(pre_label);
    let post_dest = out.join(post_label);
    std::fs::copy(pre, &pre_dest)
        .with_context(|| format!("copy pre binary to {}", pre_dest.display()))?;
    std::fs::copy(post, &post_dest)
        .with_context(|| format!("copy post binary to {}", post_dest.display()))?;

    let args: Vec<String> = vec![
        pre_dest.display().to_string(),
        post_dest.display().to_string(),
        "-o".into(),
        out.display().to_string(),
    ];

    info!(?args, "spawning ghidriff locally");
    let status = Command::new(ghidriff_bin)
        .env("GHIDRA_INSTALL_DIR", ghidra_install_dir)
        .args(&args)
        .status()
        .await
        .with_context(|| format!("spawn {}", ghidriff_bin))?;

    Ok(GhidriffResult {
        output_dir: out,
        exit_code: status.code(),
    })
}

/// Returns the expected path of the ghidriff JSON output file.
/// ghidriff names it `<pre_label>-<post_label>.ghidriff.json` inside a `json/` subdirectory.
fn ghidriff_json_path(output_dir: &Path, pre_label: &str, post_label: &str) -> PathBuf {
    output_dir
        .join("json")
        .join(format!("{}-{}.ghidriff.json", pre_label, post_label))
}

