use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Optional fields backfilled into the exported workspace from authoritative sources
/// (typically the patchwatch DB) when the cached `report.json` was written before
/// these fields were added to `PocsmithContext`.
#[derive(Debug, Default, Clone)]
pub struct CveEnrichment {
    pub cvss: Option<f64>,
    pub cvss_vector: Option<String>,
}

pub fn export_poc_context(
    report_dir: &Path,
    out_root: &Path,
    enrichment: Option<&CveEnrichment>,
) -> Result<()> {
    let json = fs::read_to_string(report_dir.join("report.json"))
        .with_context(|| format!("missing report.json in {}", report_dir.display()))?;
    let mut ctx: serde_json::Value = serde_json::from_str(&json)?;
    let cve_id = ctx["cve_id"].as_str().context("missing cve_id")?.to_string();
    let out = out_root.join(&cve_id);
    fs::create_dir_all(&out)?;

    let pre = rewrite_binary_paths(&ctx["prepatch_paths"], &out, "pre-patch")?;
    let post = rewrite_binary_paths(&ctx["postpatch_paths"], &out, "post-patch")?;
    ctx["prepatch_paths"] = serde_json::to_value(&pre)?;
    ctx["postpatch_paths"] = serde_json::to_value(&post)?;

    if let Some(e) = enrichment {
        if let Some(s) = e.cvss {
            if !ctx.get("cvss").map(|v| v.is_number()).unwrap_or(false) {
                ctx["cvss"] = serde_json::json!(s);
            }
        }
        if let Some(v) = &e.cvss_vector {
            if !ctx.get("cvss_vector").map(|v| v.is_string()).unwrap_or(false) {
                ctx["cvss_vector"] = serde_json::Value::String(v.clone());
            }
        }
    }

    let ghidriff_src = ctx["ghidriff_dir"].as_str().unwrap_or("").to_string();
    if !ghidriff_src.is_empty() {
        let ghidriff_dst = out.join("ghidriff");
        copy_or_link_dir(Path::new(&ghidriff_src), &ghidriff_dst)?;
        ctx["ghidriff_dir"] = serde_json::Value::String("ghidriff/".into());
    }

    let md = fs::read_to_string(report_dir.join("report.md"))
        .with_context(|| format!("missing report.md in {}", report_dir.display()))?;
    let md = patch_markdown_cvss_vector(&md, enrichment.and_then(|e| e.cvss_vector.as_deref()));
    fs::write(out.join("cve.md"), md)?;

    fs::write(out.join("context.json"), serde_json::to_string_pretty(&ctx)?)?;
    Ok(())
}

/// If `vector` is provided and the markdown doesn't already mention a CVSS vector line,
/// inject one immediately after the existing `**CVSS:**` line. Returns the (possibly
/// modified) markdown. If no `**CVSS:**` line is present we leave the doc alone — the
/// freshly-rendered report path will already include it.
fn patch_markdown_cvss_vector(md: &str, vector: Option<&str>) -> String {
    let Some(vector) = vector else { return md.to_string(); };
    if md.contains("**CVSS vector:**") {
        return md.to_string();
    }
    let mut out = String::with_capacity(md.len() + 64);
    let mut inserted = false;
    for line in md.split_inclusive('\n') {
        out.push_str(line);
        if !inserted && line.trim_start().starts_with("**CVSS:**") {
            out.push_str(&format!("**CVSS vector:** `{}`\n", vector));
            inserted = true;
        }
    }
    out
}

fn rewrite_binary_paths(
    src: &serde_json::Value,
    out: &Path,
    subdir: &str,
) -> Result<BTreeMap<String, String>> {
    let map = src.as_object().context("paths not an object")?;
    let mut new = BTreeMap::new();
    for (binary, path_v) in map {
        let src_path = PathBuf::from(path_v.as_str().context("path not a string")?);
        let sha_dir = src_path.parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".into());
        let rel = format!("{}/{}/{}", subdir, sha_dir, binary);
        let dst = out.join(&rel);
        if let Some(parent) = dst.parent() { fs::create_dir_all(parent)?; }
        if dst.exists() { fs::remove_file(&dst)?; }
        if fs::hard_link(&src_path, &dst).is_err() {
            fs::copy(&src_path, &dst)?;
        }
        new.insert(binary.clone(), rel);
    }
    Ok(new)
}

fn copy_or_link_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_or_link_dir(&entry.path(), &dst_path)?;
        } else {
            if dst_path.exists() { fs::remove_file(&dst_path)?; }
            if fs::hard_link(entry.path(), &dst_path).is_err() {
                fs::copy(entry.path(), &dst_path)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rewrites_paths_relative_to_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let in_dir = tmp.path().join("in");
        let cache = tmp.path().join("cache");
        let out = tmp.path().join("out");
        fs::create_dir_all(in_dir.join("CVE-X")).unwrap();
        fs::create_dir_all(cache.join("ab/abcd")).unwrap();
        fs::create_dir_all(in_dir.join("ghidriff/rpcrt4")).unwrap();
        fs::write(cache.join("ab/abcd/rpcrt4.dll"), b"PE").unwrap();
        fs::write(in_dir.join("CVE-X/report.md"), "# r").unwrap();
        let json = serde_json::json!({
            "cve_id": "CVE-X", "kb": "KB1", "title": "t", "description": "d",
            "primary_binaries": ["rpcrt4.dll"], "deep_analysis": [],
            "prepatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "postpatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "ghidriff_dir": in_dir.join("ghidriff").to_string_lossy(),
        });
        fs::write(in_dir.join("CVE-X/report.json"), json.to_string()).unwrap();

        export_poc_context(&in_dir.join("CVE-X"), &out, None).unwrap();

        let cj: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("CVE-X/context.json")).unwrap()).unwrap();
        assert_eq!(cj["prepatch_paths"]["rpcrt4.dll"], "pre-patch/abcd/rpcrt4.dll");
        assert!(out.join("CVE-X/pre-patch/abcd/rpcrt4.dll").exists());
        assert!(out.join("CVE-X/cve.md").exists());
        assert!(out.join("CVE-X/ghidriff").is_dir());
    }

    #[test]
    fn enrichment_backfills_missing_cvss_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let in_dir = tmp.path().join("in");
        let cache = tmp.path().join("cache");
        let out = tmp.path().join("out");
        fs::create_dir_all(in_dir.join("CVE-Y")).unwrap();
        fs::create_dir_all(cache.join("ab/abcd")).unwrap();
        fs::write(cache.join("ab/abcd/rpcrt4.dll"), b"PE").unwrap();
        fs::write(
            in_dir.join("CVE-Y/report.md"),
            "# r\n\n**Title:** Foo\n**CVSS:** 8.8\n**KB:** KB1\n",
        )
        .unwrap();
        // Stale report.json: no cvss_vector and no cvss.
        let json = serde_json::json!({
            "cve_id": "CVE-Y", "kb": "KB1", "title": "Foo", "description": "d",
            "primary_binaries": [], "deep_analysis": [],
            "prepatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "postpatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "ghidriff_dir": "",
        });
        fs::write(in_dir.join("CVE-Y/report.json"), json.to_string()).unwrap();

        let enrich = CveEnrichment {
            cvss: Some(8.8),
            cvss_vector: Some(
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C".into(),
            ),
        };
        export_poc_context(&in_dir.join("CVE-Y"), &out, Some(&enrich)).unwrap();

        let cj: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("CVE-Y/context.json")).unwrap()).unwrap();
        assert_eq!(
            cj["cvss_vector"],
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
        );
        assert_eq!(cj["cvss"], 8.8);

        let md = fs::read_to_string(out.join("CVE-Y/cve.md")).unwrap();
        assert!(md.contains("**CVSS vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C`"));
        let cvss_pos = md.find("**CVSS:**").unwrap();
        let vec_pos = md.find("**CVSS vector:**").unwrap();
        assert!(vec_pos > cvss_pos, "vector line should come after CVSS line");
    }

    #[test]
    fn enrichment_does_not_overwrite_existing_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let in_dir = tmp.path().join("in");
        let cache = tmp.path().join("cache");
        let out = tmp.path().join("out");
        fs::create_dir_all(in_dir.join("CVE-Z")).unwrap();
        fs::create_dir_all(cache.join("ab/abcd")).unwrap();
        fs::write(cache.join("ab/abcd/rpcrt4.dll"), b"PE").unwrap();
        fs::write(
            in_dir.join("CVE-Z/report.md"),
            "# r\n\n**CVSS:** 9.8\n**CVSS vector:** `CVSS:3.1/AV:N`\n",
        )
        .unwrap();
        let json = serde_json::json!({
            "cve_id": "CVE-Z", "kb": "KB1", "title": "Foo", "description": "d",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N",
            "primary_binaries": [], "deep_analysis": [],
            "prepatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "postpatch_paths": { "rpcrt4.dll": cache.join("ab/abcd/rpcrt4.dll").to_string_lossy() },
            "ghidriff_dir": "",
        });
        fs::write(in_dir.join("CVE-Z/report.json"), json.to_string()).unwrap();

        let enrich = CveEnrichment {
            cvss: Some(1.0),
            cvss_vector: Some("CVSS:3.1/STALE".into()),
        };
        export_poc_context(&in_dir.join("CVE-Z"), &out, Some(&enrich)).unwrap();

        let cj: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("CVE-Z/context.json")).unwrap()).unwrap();
        assert_eq!(cj["cvss"], 9.8);
        assert_eq!(cj["cvss_vector"], "CVSS:3.1/AV:N");

        let md = fs::read_to_string(out.join("CVE-Z/cve.md")).unwrap();
        assert!(md.contains("`CVSS:3.1/AV:N`"));
        assert!(!md.contains("STALE"));
    }
}
