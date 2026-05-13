pub mod diff_summary;
pub mod runner;

pub use diff_summary::{
    DiffIndex, DiffSummary, FunctionDiff, ModifiedFunctionInfo,
    find_diff_json, parse_diff_json, parse_diff_json_full,
};
pub use runner::{GhidriffResult, run_ghidriff};
