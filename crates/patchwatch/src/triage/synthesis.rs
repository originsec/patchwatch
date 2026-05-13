use crate::ghidra::DiffSummary;
use crate::sug::types::Vulnerability;
use crate::triage::AnthropicClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Input for one binary in the synthesis pass.
#[derive(Debug, Clone)]
pub struct BinaryDiffInput<'a> {
    pub filename: &'a str,
    pub triage_confidence: f64,
    pub triage_reasoning: &'a str,
    pub diff_summary: Option<&'a DiffSummary>,
    pub diff_failed: bool,
}

/// LLM assessment for a single binary.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BinaryAssessment {
    pub filename: String,
    pub security_relevant: bool,
    pub confidence: f64,
    pub reasoning: String,
}

/// A function ranked by the Stage 1 LLM as potentially containing the CVE fix.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RankedFunction {
    pub name: String,
    pub binary: String,
    pub score: f64,
    pub reasoning: String,
}

/// Overall synthesis result from the LLM.
#[derive(Debug, Clone)]
pub struct SynthesisResult {
    pub per_binary: Vec<BinaryAssessment>,
    pub primary_binaries: Vec<String>,
    pub overall_summary: String,
    /// Functions ranked by likelihood of containing the CVE fix, highest score first.
    pub ranked_functions: Vec<RankedFunction>,
}

#[derive(Deserialize)]
struct SynthesisEnvelope {
    per_binary: Vec<BinaryAssessment>,
    #[serde(default)]
    primary_binaries: Vec<String>,
    overall_summary: String,
    #[serde(default)]
    ranked_functions: Vec<RankedFunction>,
}

const SYNTHESIS_SYSTEM_PROMPT: &str = "You are a Windows security researcher. \
Given a CVE description and binary diff summaries (changed functions with similarity scores \
and change types), determine which binaries contain the actual security fix and rank the \
specific functions most likely to contain it. \
Output strict JSON with no extra text.";

pub fn build_synthesis_prompt(cve: &Vulnerability, inputs: &[BinaryDiffInput<'_>]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "CVE: {}\nTitle: {}\nDescription: {}\nCWE: {}\nCVSS: {}\n\n",
        cve.cve_number,
        cve.cve_title.as_deref().unwrap_or("(none)"),
        cve.description.as_deref().unwrap_or("(none)"),
        cve.cwe_id().as_deref().unwrap_or("(unknown)"),
        cve.base_score.map(|s| s.to_string()).unwrap_or_else(|| "N/A".into()),
    ));

    s.push_str("Binary diff summaries:\n\n");
    for inp in inputs {
        s.push_str(&format!(
            "## {} (triage confidence {:.2})\n",
            inp.filename, inp.triage_confidence
        ));
        s.push_str(&format!("Triage reasoning: {}\n", inp.triage_reasoning));

        if inp.diff_failed {
            s.push_str("Diff: FAILED (ghidriff error)\n\n");
            continue;
        }

        match inp.diff_summary {
            None => {
                s.push_str("Diff: not available\n\n");
            }
            Some(d) if d.parse_error.is_some() => {
                s.push_str(&format!(
                    "Diff: parse error — {}\n\n",
                    d.parse_error.as_deref().unwrap_or("")
                ));
            }
            Some(d) if d.is_trivial() => {
                s.push_str("Diff: no changed functions (trivial/version-only diff)\n\n");
            }
            Some(d) => {
                s.push_str(&format!(
                    "Changed functions: {} added, {} deleted, {} modified\n",
                    d.added_functions.len(),
                    d.deleted_functions.len(),
                    d.modified_functions.len(),
                ));

                if !d.added_functions.is_empty() {
                    s.push_str(&format!("Added: {}\n", d.added_functions.join(", ")));
                }

                if !d.deleted_functions.is_empty() {
                    s.push_str(&format!("Deleted: {}\n", d.deleted_functions.join(", ")));
                }

                if !d.modified_functions.is_empty() {
                    // Format: name (ratio=X, code) or name (ratio=X) for address-only changes.
                    // All functions included — no cap.
                    let formatted: Vec<String> = d
                        .modified_functions
                        .iter()
                        .map(|m| {
                            if m.has_code_change {
                                format!("{} (ratio={:.2}, code)", m.name, m.ratio)
                            } else {
                                format!("{} (ratio={:.2})", m.name, m.ratio)
                            }
                        })
                        .collect();
                    s.push_str(&format!("Modified: {}\n", formatted.join(", ")));
                }

                if !d.added_strings.is_empty() {
                    s.push_str(&format!("Added strings: {}\n", d.added_strings.join(", ")));
                }

                s.push('\n');
            }
        }
    }

    s.push_str(
        "Respond with JSON:\n\
        {\n\
          \"per_binary\": [\n\
            {\"filename\": \"...\", \"security_relevant\": true, \"confidence\": 0.0, \"reasoning\": \"...\"}\n\
          ],\n\
          \"primary_binaries\": [\"...\"],\n\
          \"overall_summary\": \"...\",\n\
          \"ranked_functions\": [\n\
            {\"name\": \"...\", \"binary\": \"...\", \"score\": 0.0, \"reasoning\": \"...\"}\n\
          ]\n\
        }\n\
        primary_binaries: all binaries with security-relevant changes.\n\
        ranked_functions: TOP 20 functions most likely to contain the CVE fix, \
        ordered by score descending. ONLY include functions marked with 'code' change type. \
        Omit functions with only address/refcount/length changes. \
        Score 0.0-1.0 based on name relevance to the CVE and degree of change.",
    );
    s
}

impl AnthropicClient {
    pub async fn synthesize(
        &self,
        cve: &Vulnerability,
        inputs: &[BinaryDiffInput<'_>],
    ) -> Result<SynthesisResult> {
        let prompt = build_synthesis_prompt(cve, inputs);
        let raw = self.complete(SYNTHESIS_SYSTEM_PROMPT, &prompt, 8192).await?;
        let json_start = raw.find('{').unwrap_or(0);
        let json_end = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());
        let env: SynthesisEnvelope = serde_json::from_str(&raw[json_start..json_end])?;
        Ok(SynthesisResult {
            per_binary: env.per_binary,
            primary_binaries: env.primary_binaries,
            overall_summary: env.overall_summary,
            ranked_functions: env.ranked_functions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::{DiffSummary, ModifiedFunctionInfo};
    use crate::sug::types::Vulnerability;

    fn empty_cve() -> Vulnerability {
        Vulnerability {
            cve_number: "CVE-2026-23670".into(),
            cve_title: Some("VBS SFB".into()),
            description: Some("Attacker can bypass VBS security feature.".into()),
            cwe_list: Some(vec!["CWE-693".into()]),
            base_score: Some(5.7),
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

    #[test]
    fn synthesis_prompt_includes_all_binaries() {
        let cve = empty_cve();
        let summary = DiffSummary {
            added_functions: vec!["new_check".into()],
            modified_functions: vec![ModifiedFunctionInfo {
                name: "validate_ptr".into(),
                ratio: 0.45,
                has_code_change: true,
            }],
            ..Default::default()
        };
        let inputs = vec![
            BinaryDiffInput {
                filename: "ntoskrnl.exe",
                triage_confidence: 0.55,
                triage_reasoning: "handles VBS syscalls",
                diff_summary: Some(&summary),
                diff_failed: false,
            },
            BinaryDiffInput {
                filename: "securekernel.exe",
                triage_confidence: 0.75,
                triage_reasoning: "VTL1 core",
                diff_summary: None,
                diff_failed: true,
            },
        ];
        let prompt = build_synthesis_prompt(&cve, &inputs);
        assert!(prompt.contains("ntoskrnl.exe"));
        assert!(prompt.contains("securekernel.exe"));
        assert!(prompt.contains("new_check"));
        assert!(prompt.contains("FAILED"));
        assert!(prompt.contains("validate_ptr"));
        assert!(prompt.contains("ratio=0.45"));
        assert!(prompt.contains("ranked_functions"));
    }

    #[test]
    fn synthesis_prompt_no_cap_on_functions() {
        let cve = empty_cve();
        let modified: Vec<ModifiedFunctionInfo> = (0..50)
            .map(|i| ModifiedFunctionInfo {
                name: format!("func_{}", i),
                ratio: 0.5,
                has_code_change: true,
            })
            .collect();
        let summary = DiffSummary {
            modified_functions: modified,
            ..Default::default()
        };
        let inputs = vec![BinaryDiffInput {
            filename: "big.dll",
            triage_confidence: 0.8,
            triage_reasoning: "primary",
            diff_summary: Some(&summary),
            diff_failed: false,
        }];
        let prompt = build_synthesis_prompt(&cve, &inputs);
        // All 50 functions should appear, not just 20.
        for i in 0..50 {
            assert!(prompt.contains(&format!("func_{}", i)));
        }
    }

    #[test]
    fn trivial_diff_reported_correctly() {
        let cve = empty_cve();
        let summary = DiffSummary::default();
        let inputs = vec![BinaryDiffInput {
            filename: "foo.dll",
            triage_confidence: 0.3,
            triage_reasoning: "unlikely",
            diff_summary: Some(&summary),
            diff_failed: false,
        }];
        let prompt = build_synthesis_prompt(&cve, &inputs);
        assert!(prompt.contains("trivial"));
    }
}
