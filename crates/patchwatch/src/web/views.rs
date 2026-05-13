use crate::storage::{CveDetail, CveListRow, DiffJobRow, FindingRow, SynthesisRow};
use crate::triage::anthropic::Ranking;
use askama::Template;

// ---- template structs ----

#[derive(Template)]
#[template(path = "cve_list.html")]
pub struct CveListView {
    pub rows: Vec<CveListRow>,
    pub q: String,
    pub exploited_only: bool,
    pub sort: String,
    pub sort_dir: String,
    pub page: usize,
    pub page_size: usize,
    pub total: usize,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "cve_detail.html")]
pub struct CveDetailView {
    pub detail: CveDetail,
    pub rankings: Vec<Ranking>,
    pub latest_job: Option<DiffJobRow>,
    pub has_report: bool,
    pub triage_eligible: bool,
    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "_job_status.html")]
pub struct JobStatusView {
    pub job: DiffJobRow,
    pub csrf_token: String,
}

pub struct FindingViewRow {
    pub finding: FindingRow,
    pub old_html: String,
    pub new_html: String,
}

pub struct BinaryGroupView {
    pub filename: String,
    pub patch_summary: String,
    pub findings: Vec<FindingViewRow>,
}

#[derive(Template)]
#[template(path = "cve_report.html")]
pub struct CveReportView {
    pub cve_id: String,
    pub title: Option<String>,
    pub synthesis: Option<SynthesisRow>,
    pub binaries: Vec<BinaryGroupView>,
    pub report_html: Option<String>,
    pub csrf_token: String,
}
