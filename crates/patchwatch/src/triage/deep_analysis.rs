use crate::ghidra::{DiffIndex, FunctionDiff};
use crate::sug::types::Vulnerability;
use crate::triage::{AnthropicClient, synthesis::RankedFunction};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A single function's deep analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFinding {
    pub name: String,
    /// LLM relevance score: 0.0 = unrelated, 1.0 = highly likely fix location.
    pub relevance: f64,
    /// Explanation of what changed and why it is (or isn't) related to the CVE.
    pub summary: String,
    /// Key changed lines from the pre-patch decompilation.
    pub old_snippet: String,
    /// Key changed lines from the post-patch decompilation.
    pub new_snippet: String,
}

/// Result of the Stage 2 deep analysis pass for a single binary.
#[derive(Debug, Clone)]
pub struct DeepAnalysisResult {
    pub findings: Vec<FunctionFinding>,
    /// Consolidated description of the full patch for this binary.
    pub patch_summary: String,
}

#[derive(Deserialize)]
struct DeepAnalysisEnvelope {
    #[serde(default)]
    findings: Vec<FunctionFinding>,
    #[serde(default)]
    patch_summary: String,
}

const DEEP_ANALYSIS_SYSTEM_PROMPT: &str = "You are a Windows security researcher performing \
binary patch analysis. You will be given before/after decompiled function code for a set of \
changed functions and the CVE they relate to. For each function, assess whether it contains \
the security fix, explain what changed, and extract the key changed lines as snippets. \
Output strict JSON with no extra text.";

/// Select functions for deep analysis from the Stage 1 ranked list and the DiffIndex.
///
/// Priority order:
/// 1. Functions ranked by Stage 1 LLM (highest score first, filtered to `binary`).
/// 2. Fallback: functions with actual code changes from the index, sorted by ascending ratio
///    (most-changed first).
///
/// Returns at most `top_n` entries.
pub fn select_functions_for_deep_analysis<'a>(
    binary: &str,
    ranked: &[RankedFunction],
    index: &'a DiffIndex,
    top_n: usize,
) -> Vec<&'a FunctionDiff> {
    // Collect ranked names for this binary, highest score first.
    let mut ranked_names: Vec<&str> = ranked
        .iter()
        .filter(|r| r.binary.eq_ignore_ascii_case(binary))
        .map(|r| r.name.as_str())
        .collect();

    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    ranked_names.retain(|n| seen.insert(*n));

    let mut selected: Vec<&FunctionDiff> = ranked_names
        .iter()
        .filter_map(|name| index.modified.get(*name))
        .take(top_n)
        .collect();

    // Fill remaining slots from code-changed functions not already selected, by ascending ratio.
    if selected.len() < top_n {
        let already: std::collections::HashSet<&str> =
            selected.iter().map(|f| f.name.as_str()).collect();
        let mut extras: Vec<&FunctionDiff> = index
            .modified
            .values()
            .filter(|f| f.diff_types.iter().any(|t| t == "code") && !already.contains(f.name.as_str()))
            .collect();
        extras.sort_by(|a, b| a.ratio.partial_cmp(&b.ratio).unwrap_or(std::cmp::Ordering::Equal));
        let remaining = top_n - selected.len();
        selected.extend(extras.into_iter().take(remaining));
    }

    selected
}

pub fn build_deep_analysis_prompt(
    cve: &Vulnerability,
    binary: &str,
    functions: &[&FunctionDiff],
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "CVE: {}\nTitle: {}\nDescription: {}\nCWE: {}\nCVSS: {}\n\n",
        cve.cve_number,
        cve.cve_title.as_deref().unwrap_or("(none)"),
        cve.description.as_deref().unwrap_or("(none)"),
        cve.cwe_id().as_deref().unwrap_or("(unknown)"),
        cve.base_score.map(|v| v.to_string()).unwrap_or_else(|| "N/A".into()),
    ));

    s.push_str(&format!(
        "Binary: {}\n\
         Analyze the following {} changed functions. For each, determine whether it contains \
         or contributes to the security fix for this CVE.\n\n",
        binary,
        functions.len(),
    ));

    for fd in functions {
        s.push_str(&format!(
            "### {} (similarity={:.2}, change_types={})\n",
            fd.name,
            fd.ratio,
            fd.diff_types.join("+"),
        ));
        s.push_str("#### Before (pre-patch decompilation):\n```c\n");
        s.push_str(&fd.old_code);
        s.push_str("\n```\n");
        s.push_str("#### After (post-patch decompilation):\n```c\n");
        s.push_str(&fd.new_code);
        s.push_str("\n```\n\n");
    }

    s.push_str(
        "Respond with JSON:\n\
        {\n\
          \"findings\": [\n\
            {\n\
              \"name\": \"...\",\n\
              \"relevance\": 0.0,\n\
              \"summary\": \"...\",\n\
              \"old_snippet\": \"...\",\n\
              \"new_snippet\": \"...\"\n\
            }\n\
          ],\n\
          \"patch_summary\": \"...\"\n\
        }\n\
        findings: one entry per function, ordered by relevance descending.\n\
        old_snippet/new_snippet: the key changed lines only (not the full function).\n\
        patch_summary: a consolidated description of what this binary's patch does \
        in the context of the CVE.",
    );
    s
}

impl AnthropicClient {
    pub async fn deep_analyze(
        &self,
        cve: &Vulnerability,
        binary: &str,
        functions: &[&FunctionDiff],
    ) -> Result<DeepAnalysisResult> {
        if functions.is_empty() {
            return Ok(DeepAnalysisResult {
                findings: vec![],
                patch_summary: "No functions selected for deep analysis.".into(),
            });
        }
        let prompt = build_deep_analysis_prompt(cve, binary, functions);
        let raw = self.complete(DEEP_ANALYSIS_SYSTEM_PROMPT, &prompt, 8192).await?;
        let json_start = raw.find('{').unwrap_or(0);
        let json_end = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());
        let env: DeepAnalysisEnvelope = serde_json::from_str(&raw[json_start..json_end])?;
        Ok(DeepAnalysisResult {
            findings: env.findings,
            patch_summary: env.patch_summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::{DiffIndex, FunctionDiff};
    use crate::sug::types::Vulnerability;
    use std::collections::HashMap;

    fn make_cve() -> Vulnerability {
        Vulnerability {
            cve_number: "CVE-2026-23669".into(),
            cve_title: Some("RPC UAF".into()),
            description: Some("Use-after-free in RPC runtime.".into()),
            cwe_list: Some(vec!["CWE-416".into()]),
            base_score: Some(8.8),
            temporal_score: None,
            vector_string: None,
            severity: None,
            impact: None,
            issuing_cna: None,
            tag: None,
            exploited: None,
            publicly_disclosed: None,
            customer_action_required: None,
            is_mariner: None,
            release_number: None,
            release_date: None,
            revision_number: None,
        }
    }

    fn make_diff(name: &str, ratio: f64, has_code: bool) -> FunctionDiff {
        FunctionDiff {
            name: name.into(),
            old_code: format!("void {}() {{ old(); }}", name),
            new_code: format!("void {}() {{ new(); }}", name),
            ratio,
            diff_types: if has_code {
                vec!["code".into(), "address".into()]
            } else {
                vec!["address".into()]
            },
        }
    }

    #[test]
    fn deep_analysis_prompt_contains_function_code() {
        let cve = make_cve();
        let fd = make_diff("LRPC_CCALL::CleanupCall", 0.45, true);
        let prompt = build_deep_analysis_prompt(&cve, "rpcrt4.dll", &[&fd]);
        assert!(prompt.contains("LRPC_CCALL::CleanupCall"));
        assert!(prompt.contains("old()"));
        assert!(prompt.contains("new()"));
        assert!(prompt.contains("similarity=0.45"));
        assert!(prompt.contains("patch_summary"));
    }

    #[test]
    fn select_prefers_ranked_functions() {
        let mut modified = HashMap::new();
        for name in ["alpha", "beta", "gamma", "delta"] {
            modified.insert(name.to_string(), make_diff(name, 0.5, true));
        }
        let index = DiffIndex {
            modified,
            added_code: HashMap::new(),
            deleted_code: HashMap::new(),
        };
        let ranked = vec![
            RankedFunction { name: "beta".into(), binary: "foo.dll".into(), score: 0.9, reasoning: "".into() },
            RankedFunction { name: "alpha".into(), binary: "foo.dll".into(), score: 0.7, reasoning: "".into() },
        ];
        let selected = select_functions_for_deep_analysis("foo.dll", &ranked, &index, 3);
        assert_eq!(selected[0].name, "beta");
        assert_eq!(selected[1].name, "alpha");
        assert_eq!(selected.len(), 3); // beta + alpha from ranked, then one fallback
    }

    #[test]
    fn select_falls_back_to_code_changed_when_no_ranked() {
        let mut modified = HashMap::new();
        modified.insert("addr_only".to_string(), make_diff("addr_only", 0.9, false));
        modified.insert("code_changed".to_string(), make_diff("code_changed", 0.4, true));
        let index = DiffIndex {
            modified,
            added_code: HashMap::new(),
            deleted_code: HashMap::new(),
        };
        let selected = select_functions_for_deep_analysis("bar.dll", &[], &index, 5);
        // Should only select the code-changed function in fallback
        assert!(selected.iter().any(|f| f.name == "code_changed"));
        assert!(!selected.iter().any(|f| f.name == "addr_only"));
    }
}
