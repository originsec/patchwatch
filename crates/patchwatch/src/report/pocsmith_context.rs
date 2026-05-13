use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct PocsmithContext {
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    pub kb: String,
    pub title: String,
    pub description: String,
    pub primary_binaries: Vec<String>,
    pub deep_analysis: Vec<PocsmithFunctionFinding>,
    pub prepatch_paths: BTreeMap<String, String>,
    pub postpatch_paths: BTreeMap<String, String>,
    pub ghidriff_dir: String,
    /// OS build where the CVE was fixed, e.g. "10.0.26100.1882".
    /// Derived from the patched binary's file version via Winbindex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patched_build: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PocsmithFunctionFinding {
    pub binary: String,
    pub function: String,
    pub relevance: f64,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_code: Option<String>,
}

use crate::report::render::AnalyzeReport;

impl PocsmithContext {
    pub fn from_report(r: &AnalyzeReport<'_>) -> Self {
        let primary = r.synthesis
            .map(|s| s.primary_binaries.clone())
            .unwrap_or_default();
        let deep = r.diffed.iter()
            .filter_map(|d| d.deep_analysis.as_ref().map(|da| (&d.filename, da)))
            .flat_map(|(bin, da)| da.findings.iter().map(move |f| PocsmithFunctionFinding {
                binary: bin.clone(),
                function: f.name.clone(),
                relevance: f.relevance,
                summary: f.summary.clone(),
                before_code: Some(f.old_snippet.clone()),
                after_code: Some(f.new_snippet.clone()),
            }))
            .collect();
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        for d in r.diffed {
            pre.insert(d.filename.clone(), d.previous.path.display().to_string());
            post.insert(d.filename.clone(), d.patched.path.display().to_string());
        }
        let patched_build = r.diffed.iter()
            .find_map(|d| d.patched.version.as_deref())
            .and_then(|v| v.split_ascii_whitespace().next())
            .map(str::to_string);

        Self {
            cve_id: r.cve.cve_number.clone(),
            cvss: r.cve.base_score,
            cvss_vector: r.cve.vector_string.clone(),
            kb: r.kb_id.to_string(),
            title: r.cve.cve_title.clone().unwrap_or_default(),
            description: r.cve.description.clone().unwrap_or_default(),
            primary_binaries: primary,
            deep_analysis: deep,
            prepatch_paths: pre,
            postpatch_paths: post,
            ghidriff_dir: r.diffed.first()
                .map(|d| d.ghidriff_output_dir.display().to_string())
                .unwrap_or_default(),
            patched_build,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pocsmith_context_serializes_expected_shape() {
        let pc = PocsmithContext {
            cve_id: "CVE-2026-23669".into(),
            cvss: Some(8.8),
            cvss_vector: Some(
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C".into(),
            ),
            kb: "KB5079466".into(),
            title: "RPC Runtime Library RCE".into(),
            description: "...".into(),
            primary_binaries: vec!["rpcrt4.dll".into()],
            deep_analysis: vec![PocsmithFunctionFinding {
                binary: "rpcrt4.dll".into(),
                function: "FinishUsingContextHandle".into(),
                relevance: 0.95,
                summary: "...".into(),
                before_code: Some("...".into()),
                after_code: Some("...".into()),
            }],
            prepatch_paths: [("rpcrt4.dll".into(), "pre-patch/abcd/rpcrt4.dll".into())].into(),
            postpatch_paths: [("rpcrt4.dll".into(), "post-patch/3565/rpcrt4.dll".into())].into(),
            ghidriff_dir: "ghidriff/".into(),
            patched_build: Some("10.0.26100.1882".into()),
        };
        let v = serde_json::to_value(&pc).unwrap();
        assert_eq!(v["cve_id"], "CVE-2026-23669");
        assert_eq!(v["primary_binaries"][0], "rpcrt4.dll");
        assert_eq!(v["deep_analysis"][0]["function"], "FinishUsingContextHandle");
        assert_eq!(
            v["cvss_vector"],
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
        );
    }
}
