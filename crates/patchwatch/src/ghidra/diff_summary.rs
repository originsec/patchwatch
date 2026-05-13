use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Lightweight info about a modified function, used in Stage 1 synthesis prompt.
#[derive(Debug, Clone, Default)]
pub struct ModifiedFunctionInfo {
    pub name: String,
    /// Similarity ratio (0.0 = completely rewritten, 1.0 = identical).
    pub ratio: f64,
    /// True when "code" appears in the function's diff_type list.
    pub has_code_change: bool,
}

/// Compact representation of a ghidriff JSON output, used for Stage 1 LLM synthesis.
#[derive(Debug, Clone, Default)]
pub struct DiffSummary {
    pub added_functions: Vec<String>,
    pub deleted_functions: Vec<String>,
    pub modified_functions: Vec<ModifiedFunctionInfo>,
    pub added_strings: Vec<String>,
    pub deleted_strings: Vec<String>,
    /// Set when the JSON file was found but could not be fully parsed.
    pub parse_error: Option<String>,
}

impl DiffSummary {
    pub fn changed_function_count(&self) -> usize {
        self.added_functions.len() + self.deleted_functions.len() + self.modified_functions.len()
    }

    pub fn is_trivial(&self) -> bool {
        self.changed_function_count() == 0
    }
}

/// Full before/after data for a single modified function, used in Stage 2 deep analysis.
#[derive(Debug, Clone)]
pub struct FunctionDiff {
    pub name: String,
    pub old_code: String,
    pub new_code: String,
    /// Similarity ratio from ghidriff (lower = more changed).
    pub ratio: f64,
    pub diff_types: Vec<String>,
}

/// Full code index for all changed functions in a binary, loaded from the ghidriff JSON.
/// Only constructed when deep analysis is requested.
#[derive(Debug, Clone, Default)]
pub struct DiffIndex {
    /// Modified functions keyed by old (pre-patch) name.
    pub modified: HashMap<String, FunctionDiff>,
    /// Added functions (new in patched binary) keyed by name.
    pub added_code: HashMap<String, String>,
    /// Deleted functions (removed in patched binary) keyed by name.
    pub deleted_code: HashMap<String, String>,
}

// ── Serde types for ghidriff >= 1.0.0 schema ─────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct GhidriffJson {
    #[serde(default)]
    functions: GhidriffFunctions,
    #[serde(default)]
    strings: GhidriffStrings,
}

#[derive(Debug, Deserialize, Default)]
struct GhidriffFunctions {
    #[serde(default)]
    added: Vec<FuncEntry>,
    #[serde(default)]
    deleted: Vec<FuncEntry>,
    #[serde(default)]
    modified: Vec<ModifiedFuncEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct GhidriffStrings {
    #[serde(default)]
    added: Vec<StringEntry>,
    #[serde(default)]
    deleted: Vec<StringEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct FuncEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    code: String,
}

#[derive(Debug, Deserialize, Default)]
struct ModifiedFuncEntry {
    #[serde(default)]
    old: FuncEntry,
    #[serde(default)]
    new: FuncEntry,
    #[serde(default)]
    ratio: f64,
    #[serde(default)]
    diff_type: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct StringEntry {
    #[serde(default)]
    name: String,
}

// ── Parse functions ───────────────────────────────────────────────────────────

/// Parse a ghidriff JSON string into both a `DiffSummary` (Stage 1) and a
/// `DiffIndex` (Stage 2).  Prefer this over calling both individually.
pub fn parse_diff_json_full(json: &str) -> (DiffSummary, DiffIndex) {
    match serde_json::from_str::<GhidriffJson>(json) {
        Ok(raw) => {
            let summary = DiffSummary {
                added_functions: raw.functions.added.iter().map(|f| f.name.clone()).collect(),
                deleted_functions: raw.functions.deleted.iter().map(|f| f.name.clone()).collect(),
                modified_functions: raw
                    .functions
                    .modified
                    .iter()
                    .map(|m| ModifiedFunctionInfo {
                        name: m.old.name.clone(),
                        ratio: m.ratio,
                        has_code_change: m.diff_type.iter().any(|t| t == "code"),
                    })
                    .collect(),
                added_strings: raw.strings.added.iter().map(|s| s.name.clone()).collect(),
                deleted_strings: raw.strings.deleted.iter().map(|s| s.name.clone()).collect(),
                parse_error: None,
            };
            let index = DiffIndex {
                modified: raw
                    .functions
                    .modified
                    .into_iter()
                    .map(|m| {
                        let name = m.old.name.clone();
                        let fd = FunctionDiff {
                            name: m.old.name,
                            old_code: m.old.code,
                            new_code: m.new.code,
                            ratio: m.ratio,
                            diff_types: m.diff_type,
                        };
                        (name, fd)
                    })
                    .collect(),
                added_code: raw
                    .functions
                    .added
                    .into_iter()
                    .map(|f| (f.name, f.code))
                    .collect(),
                deleted_code: raw
                    .functions
                    .deleted
                    .into_iter()
                    .map(|f| (f.name, f.code))
                    .collect(),
            };
            (summary, index)
        }
        Err(e) => {
            let summary = DiffSummary {
                parse_error: Some(e.to_string()),
                ..Default::default()
            };
            (summary, DiffIndex::default())
        }
    }
}

/// Parse a ghidriff JSON string into a `DiffSummary` only.
/// Use `parse_diff_json_full` when deep analysis will also be run.
pub fn parse_diff_json(json: &str) -> DiffSummary {
    parse_diff_json_full(json).0
}

/// Find the ghidriff JSON output file inside `output_dir`.
///
/// ghidriff places the JSON in `<output_dir>/json/*.ghidriff.json`; older/alternate
/// invocations may write directly into `output_dir`.  We check both locations.
pub fn find_diff_json(output_dir: &Path) -> Option<std::path::PathBuf> {
    for dir in [output_dir.join("json"), output_dir.to_path_buf()] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".ghidriff.json") {
                    return Some(entry.path());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "functions": {
                "added": [{"name": "new_check", "fullname": "new_check", "code": "void new_check() {}"}],
                "deleted": [],
                "modified": [{
                    "old": {"name": "validate_ptr", "code": "void validate_ptr(void *p) { if (!p) return; }"},
                    "new": {"name": "validate_ptr", "code": "void validate_ptr(void *p) { if (!p) abort(); }"},
                    "ratio": 0.6,
                    "diff_type": ["code"]
                }]
            },
            "strings": {
                "added": [{"name": "VBS security violation"}],
                "deleted": []
            }
        }"#
    }

    #[test]
    fn parses_valid_ghidriff_json() {
        let s = parse_diff_json(sample_json());
        assert_eq!(s.added_functions, vec!["new_check"]);
        assert_eq!(s.modified_functions.len(), 1);
        assert_eq!(s.modified_functions[0].name, "validate_ptr");
        assert!((s.modified_functions[0].ratio - 0.6).abs() < 1e-9);
        assert!(s.modified_functions[0].has_code_change);
        assert_eq!(s.added_strings, vec!["VBS security violation"]);
        assert!(!s.is_trivial());
    }

    #[test]
    fn parse_full_populates_index() {
        let (summary, index) = parse_diff_json_full(sample_json());
        assert!(!summary.is_trivial());
        let fd = index.modified.get("validate_ptr").expect("validate_ptr in index");
        assert!(fd.old_code.contains("return"));
        assert!(fd.new_code.contains("abort"));
        assert!((fd.ratio - 0.6).abs() < 1e-9);
        assert_eq!(fd.diff_types, vec!["code"]);
        assert!(index.added_code.contains_key("new_check"));
    }

    #[test]
    fn empty_json_gives_trivial_summary() {
        let s = parse_diff_json("{}");
        assert!(s.is_trivial());
        assert!(s.parse_error.is_none());
    }

    #[test]
    fn bad_json_sets_parse_error() {
        let s = parse_diff_json("not json");
        assert!(s.parse_error.is_some());
    }

    #[test]
    fn non_code_change_flagged_correctly() {
        let json = r#"{
            "functions": {
                "added": [], "deleted": [],
                "modified": [{"old": {"name": "foo", "code": ""}, "new": {"name": "foo", "code": ""},
                               "ratio": 0.9, "diff_type": ["address", "refcount"]}]
            },
            "strings": {"added": [], "deleted": []}
        }"#;
        let s = parse_diff_json(json);
        assert!(!s.modified_functions[0].has_code_change);
    }
}
