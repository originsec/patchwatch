use crate::ghidra::{DiffIndex, DiffSummary};
use crate::kb::types::KbEnumeration;
use crate::sug::types::Vulnerability;
use crate::triage::{DeepAnalysisResult, Ranking, SynthesisResult};
use crate::winbindex::client::{DownloadedBinary, PairConfidence};
use std::fmt::Write;
use std::path::PathBuf;

/// Result for a single diffed binary.
#[derive(Debug)]
pub struct BinaryDiffResult {
    pub filename: String,
    pub triage_confidence: f64,
    pub triage_reasoning: String,
    pub pair_confidence: PairConfidence,
    pub patched: DownloadedBinary,
    pub previous: DownloadedBinary,
    pub ghidriff_exit: Option<i32>,
    pub ghidriff_output_dir: PathBuf,
    pub diff_summary: Option<DiffSummary>,
    pub diff_index: Option<DiffIndex>,
    pub deep_analysis: Option<DeepAnalysisResult>,
}

impl BinaryDiffResult {
    pub fn diff_failed(&self) -> bool {
        self.ghidriff_exit != Some(0)
    }
}

#[derive(Debug)]
pub struct AnalyzeReport<'a> {
    pub cve: &'a Vulnerability,
    pub kb_id: &'a str,
    pub enumeration: &'a KbEnumeration,
    pub all_rankings: &'a [Ranking],
    pub diffed: &'a [BinaryDiffResult],
    pub synthesis: Option<&'a SynthesisResult>,
}

/// Render the analyze pipeline's per-CVE report (`report.md`) as Markdown.
pub fn render_markdown(r: &AnalyzeReport<'_>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# PatchWatch report — {}", r.cve.cve_number);
    let _ = writeln!(s);
    let _ = writeln!(s, "**Title:** {}", r.cve.cve_title.as_deref().unwrap_or("(none)"));
    let _ = writeln!(
        s,
        "**CVSS:** {}",
        r.cve.base_score.map(|v| v.to_string()).unwrap_or_else(|| "N/A".into())
    );
    if let Some(v) = r.cve.vector_string.as_deref() {
        let _ = writeln!(s, "**CVSS vector:** `{}`", v);
    }
    let _ = writeln!(s, "**KB:** {}", r.kb_id);
    let _ = writeln!(s, "**Files in KB:** {}", r.enumeration.files.len());
    let _ = writeln!(s, "KB enumeration source: {:?}", r.enumeration.source);

    // ── Triage rankings ───────────────────────────────────────────────────────
    let _ = writeln!(s);
    let _ = writeln!(s, "## Triage rankings (top 10)");
    let _ = writeln!(s);
    for (i, rk) in r.all_rankings.iter().take(10).enumerate() {
        let _ = writeln!(s, "{}. **{}** — confidence {:.2}", i + 1, rk.filename, rk.confidence);
        let _ = writeln!(s, "   - {}", rk.reasoning);
    }

    // ── Synthesis ─────────────────────────────────────────────────────────────
    if let Some(syn) = r.synthesis {
        let _ = writeln!(s);
        let _ = writeln!(s, "## Patch synthesis");
        let _ = writeln!(s);
        if !syn.primary_binaries.is_empty() {
            let _ = writeln!(
                s,
                "**Primary patched binaries:** {}",
                syn.primary_binaries.join(", ")
            );
        }
        let _ = writeln!(s);
        let _ = writeln!(s, "{}", syn.overall_summary);
        let _ = writeln!(s);
        let _ = writeln!(s, "### Per-binary assessment");
        let _ = writeln!(s);
        for a in &syn.per_binary {
            let relevance = if a.security_relevant {
                "security-relevant"
            } else {
                "not security-relevant"
            };
            let _ = writeln!(
                s,
                "- **{}** ({}, confidence {:.2}): {}",
                a.filename, relevance, a.confidence, a.reasoning
            );
        }
    }

    // ── Deep analysis ─────────────────────────────────────────────────────────
    let has_deep = r.diffed.iter().any(|d| d.deep_analysis.is_some());
    if has_deep {
        let _ = writeln!(s);
        let _ = writeln!(s, "## Deep analysis");
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "Stage 2 analysis of specific changed functions against the CVE description."
        );

        for d in r.diffed {
            let da = match &d.deep_analysis {
                Some(da) => da,
                None => continue,
            };

            let _ = writeln!(s);
            let _ = writeln!(s, "### {}", d.filename);
            let _ = writeln!(s);
            let _ = writeln!(s, "{}", da.patch_summary);

            let relevant: Vec<_> = da
                .findings
                .iter()
                .filter(|f| f.relevance >= 0.3)
                .collect();

            if relevant.is_empty() {
                let _ = writeln!(s);
                let _ = writeln!(s, "*No functions with relevance >= 0.3 found.*");
                continue;
            }

            for finding in &relevant {
                let _ = writeln!(s);
                let _ = writeln!(
                    s,
                    "#### `{}` (relevance {:.2})",
                    finding.name, finding.relevance
                );
                let _ = writeln!(s);
                let _ = writeln!(s, "{}", finding.summary);

                if !finding.old_snippet.is_empty() || !finding.new_snippet.is_empty() {
                    let _ = writeln!(s);
                    let _ = writeln!(s, "**Before:**");
                    let _ = writeln!(s, "```c");
                    let _ = writeln!(s, "{}", finding.old_snippet);
                    let _ = writeln!(s, "```");
                    let _ = writeln!(s, "**After:**");
                    let _ = writeln!(s, "```c");
                    let _ = writeln!(s, "{}", finding.new_snippet);
                    let _ = writeln!(s, "```");
                }
            }
        }
    }

    // ── Per-binary diff details ───────────────────────────────────────────────
    let _ = writeln!(s);
    let _ = writeln!(s, "## Diffed binaries ({} total)", r.diffed.len());
    for d in r.diffed {
        let _ = writeln!(s);
        let _ = writeln!(s, "### {}", d.filename);
        let pair_label = match &d.pair_confidence {
            PairConfidence::ExactKb => "exact (KB match)",
            PairConfidence::VersionFallback => "version fallback",
            PairConfidence::Approximate => "APPROXIMATE (latest two revisions)",
        };
        let _ = writeln!(s, "- **Pair confidence:** {}", pair_label);
        let _ = writeln!(s, "- **Triage confidence:** {:.2}", d.triage_confidence);
        let _ = writeln!(
            s,
            "- **Patched:** {} ({} bytes)",
            d.patched.path.display(),
            d.patched.size
        );
        let _ = writeln!(
            s,
            "- **Previous:** {} ({} bytes)",
            d.previous.path.display(),
            d.previous.size
        );
        let _ = writeln!(s, "- **ghidriff exit:** {:?}", d.ghidriff_exit);
        let _ = writeln!(s, "- **Output:** {}", d.ghidriff_output_dir.display());

        match &d.diff_summary {
            None if d.diff_failed() => {
                let _ = writeln!(s, "- **Diff:** failed");
            }
            None => {
                let _ = writeln!(s, "- **Diff:** not parsed");
            }
            Some(ds) if ds.is_trivial() => {
                let _ = writeln!(s, "- **Diff:** trivial (no changed functions)");
            }
            Some(ds) => {
                let _ = writeln!(
                    s,
                    "- **Diff:** {} added, {} deleted, {} modified functions",
                    ds.added_functions.len(),
                    ds.deleted_functions.len(),
                    ds.modified_functions.len(),
                );
                if !ds.added_functions.is_empty() {
                    let _ = writeln!(
                        s,
                        "  - Added: {}",
                        ds.added_functions.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
                    );
                }
                if !ds.modified_functions.is_empty() {
                    let names: Vec<_> = ds
                        .modified_functions
                        .iter()
                        .take(10)
                        .map(|m| m.name.as_str())
                        .collect();
                    let _ = writeln!(s, "  - Modified (first 10): {}", names.join(", "));
                }
            }
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kb::types::{Arch, KbEnumeration, KbFile, KbSource};
    use crate::sug::types::Vulnerability;
    use crate::triage::Ranking;

    fn empty_cve() -> Vulnerability {
        Vulnerability {
            cve_number: "CVE-2026-1".into(),
            cve_title: Some("T".into()),
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
            description: None,
            cwe_list: None,
        }
    }

    #[test]
    fn renders_markdown_with_no_diffs() {
        let cve = empty_cve();
        let enumeration = KbEnumeration {
            kb_id: "KB1".into(),
            source: KbSource::Csv,
            csv_url: None,
            msu_path: None,
            fallback_reason: None,
            files: vec![KbFile {
                filename: "a.dll".into(),
                version: "1".into(),
                arch: Arch::X64,
                file_size: None,
                date_stamp: None,
            }],
        };
        let rankings = vec![Ranking {
            filename: "a.dll".into(),
            confidence: 0.9,
            reasoning: "x".into(),
        }];
        let r = AnalyzeReport {
            cve: &cve,
            kb_id: "KB1",
            enumeration: &enumeration,
            all_rankings: &rankings,
            diffed: &[],
            synthesis: None,
        };
        let md = render_markdown(&r);
        assert!(md.contains("CVE-2026-1"));
        assert!(md.contains("KB enumeration source: Csv"));
        assert!(md.contains("a.dll"));
        assert!(md.contains("Diffed binaries (0 total)"));
    }
}
