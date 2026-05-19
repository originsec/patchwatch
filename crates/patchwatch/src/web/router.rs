use super::csrf::csrf_middleware;
use super::highlight::highlight_c;
use super::jobs::AnalyzeService;
use super::markdown::render_markdown;
use super::views::{
    BinaryGroupView, CveDetailView, CveListView, CveReportView, FindingViewRow, JobStatusView,
    MonthGroup,
};
use crate::config::Config;
use crate::storage::{CveFilter, Db};
use askama::Template;
use axum::{
    body::Body,
    extract::{Form, Path, Query, State},
    http::{HeaderValue, Request, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::warn;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Arc<Db>,
    pub analyze: Arc<AnalyzeService>,
    /// Resolved CSRF secret (read from env at startup).
    pub csrf_secret: String,
}

pub fn build_router(state: AppState) -> Router {
    let static_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/web/static");

    let secret = state.csrf_secret.clone();

    Router::new()
        .route("/", get(|| async { Response::builder().status(StatusCode::FOUND).header(header::LOCATION, "/cves").body(Body::empty()).unwrap() }))
        .route("/healthz", get(healthz))
        .route("/cves", get(cve_list))
        .route("/cves/{id}", get(cve_detail))
        .route("/cves/{id}/analyze", post(trigger_analyze))
        .route("/cves/{id}/abort", post(abort_analyze))
        .route("/cves/{id}/export-poc", post(export_poc))
        .route("/cves/{id}/report", get(cve_report))
        .route("/jobs/{id}/status", get(job_status))
        .nest_service("/static", ServeDir::new(static_dir))
        .layer(middleware::from_fn(move |req: Request<Body>, next: middleware::Next| {
            let s = secret.clone();
            async move {
                csrf_middleware(s, req, next).await.unwrap_or_else(|status| {
                    Response::builder()
                        .status(status)
                        .body(Body::from(status.as_str().to_owned()))
                        .unwrap()
                })
            }
        }))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn render_html<T: Template>(t: T) -> Result<Html<String>, StatusCode> {
    t.render()
        .map(Html)
        .map_err(|e| {
            tracing::error!("template render error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

fn get_csrf_cookie(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("csrf_token=").map(|v| v.to_owned())
            })
        })
        .unwrap_or_default()
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct CveListQuery {
    q: Option<String>,
    exploited: Option<String>,
    page: Option<usize>,
    sort: Option<String>,
    dir: Option<String>,
    group: Option<String>,
}

const MONTHS_PER_PAGE: usize = 3;

async fn cve_list(
    State(state): State<AppState>,
    Query(params): Query<CveListQuery>,
    req: Request<Body>,
) -> Result<impl IntoResponse, StatusCode> {
    let exploited_only = params.exploited.as_deref() == Some("1");
    let group_by_month = params.group.as_deref() == Some("month");
    let page_size = state.cfg.web.page_size;

    let search = params.q.as_ref().filter(|s| !s.is_empty()).cloned();
    let sort = params.sort.as_ref()
        .filter(|s| matches!(s.as_str(), "cve" | "cvss" | "kb"))
        .cloned();
    let sort_dir = params.dir.as_ref()
        .filter(|s| matches!(s.as_str(), "asc" | "desc"))
        .cloned()
        .unwrap_or_else(|| match sort.as_deref() {
            Some("cvss") => "desc".to_owned(),
            _ => "asc".to_owned(),
        });

    let csrf_token = get_csrf_cookie(req.headers());
    let q_str = params.q.unwrap_or_default();

    if group_by_month {
        // Fetch all matching rows so month groups are never split across pages.
        // Month-level pagination is applied after grouping.
        let filter = CveFilter {
            exploited_only,
            search,
            sort: sort.clone(),
            sort_dir: Some(sort_dir.clone()),
            limit: 10_000,
            offset: 0,
            ..CveFilter::default()
        };
        let all_rows = state.db.list_cves(filter).await.map_err(|e| {
            tracing::error!("list_cves: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let all_groups = build_month_groups(&all_rows);
        let total_months = all_groups.len();
        let month_page = params.page.unwrap_or(1).max(1);
        let month_offset = (month_page - 1) * MONTHS_PER_PAGE;
        let has_more = month_offset + MONTHS_PER_PAGE < total_months;

        let groups: Vec<MonthGroup> = all_groups
            .into_iter()
            .skip(month_offset)
            .take(MONTHS_PER_PAGE)
            .collect();

        render_html(CveListView {
            rows: vec![],
            groups,
            group_by_month: true,
            q: q_str,
            exploited_only,
            sort: sort.unwrap_or_default(),
            sort_dir,
            page: month_page,
            page_size: MONTHS_PER_PAGE,
            total: total_months,
            has_more,
            csrf_token,
        })
    } else {
        let page = params.page.unwrap_or(1).max(1);
        let filter = CveFilter {
            exploited_only,
            search,
            sort: sort.clone(),
            sort_dir: Some(sort_dir.clone()),
            limit: page_size + 1,
            offset: (page - 1) * page_size,
            ..CveFilter::default()
        };

        let mut rows = state.db.list_cves(filter).await.map_err(|e| {
            tracing::error!("list_cves: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let has_more = rows.len() > page_size;
        if has_more {
            rows.pop();
        }
        let total = rows.len();

        render_html(CveListView {
            rows,
            groups: vec![],
            group_by_month: false,
            q: q_str,
            exploited_only,
            sort: sort.unwrap_or_default(),
            sort_dir,
            page,
            page_size,
            total,
            has_more,
            csrf_token,
        })
    }
}

fn build_month_groups(rows: &[crate::storage::CveListRow]) -> Vec<MonthGroup> {
    use std::collections::BTreeMap;

    let mut map: BTreeMap<String, Vec<crate::storage::CveListRow>> = BTreeMap::new();
    for row in rows {
        let key = row.last_revised_at
            .as_deref()
            .and_then(|d| d.get(..7))
            .unwrap_or("unknown")
            .to_owned();
        map.entry(key).or_default().push(row.clone());
    }

    map.into_iter()
        .rev()
        .map(|(key, rows)| {
            let count = rows.len();
            MonthGroup {
                label: month_key_to_label(&key),
                key,
                count,
                rows,
            }
        })
        .collect()
}

fn month_key_to_label(key: &str) -> String {
    if key == "unknown" {
        return "Unknown".to_owned();
    }
    let mut parts = key.splitn(2, '-');
    let year = parts.next().unwrap_or(key);
    let month_num: u32 = parts.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    let name = match month_num {
        1 => "January", 2 => "February", 3 => "March", 4 => "April",
        5 => "May", 6 => "June", 7 => "July", 8 => "August",
        9 => "September", 10 => "October", 11 => "November", 12 => "December",
        _ => return key.to_owned(),
    };
    format!("{name} {year}")
}

async fn cve_detail(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
    req: Request<Body>,
) -> Result<impl IntoResponse, StatusCode> {
    let detail = state
        .db
        .get_cve(&cve_id)
        .await
        .map_err(|e| {
            tracing::error!("get_cve {cve_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let rankings = state.db.get_triage(&cve_id).await.unwrap_or_default();
    let latest_job = state.db.get_latest_diff_job(&cve_id).await.unwrap_or(None);
    let has_report = latest_job.as_ref().map_or(false, |j| j.status == "done");
    let triage_eligible = detail.cvss_score.unwrap_or(0.0) >= 9.0 || detail.exploited;
    let csrf_token = get_csrf_cookie(req.headers());

    render_html(CveDetailView { detail, rankings, latest_job, has_report, triage_eligible, csrf_token })
}

async fn trigger_analyze(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Response, StatusCode> {
    state
        .db
        .get_cve(&cve_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if let Some(job) = state.db.get_latest_diff_job(&cve_id).await.unwrap_or(None) {
        if !job.is_terminal() {
            return Ok((StatusCode::CONFLICT, "analysis already in progress").into_response());
        }
    }

    let job_id = state.db.create_diff_job(&cve_id).await.map_err(|e| {
        tracing::error!("create_diff_job: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    state.analyze.enqueue(cve_id.clone(), job_id, None).await.map_err(|e| {
        warn!("enqueue failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let redirect = format!("/cves/{}", cve_id);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    if let Ok(val) = HeaderValue::from_str(&redirect) {
        resp.headers_mut().insert("HX-Redirect", val);
    }
    Ok(resp)
}

async fn abort_analyze(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Response, StatusCode> {
    if let Some(job) = state.db.get_latest_diff_job(&cve_id).await.unwrap_or(None) {
        if !job.is_terminal() {
            let _ = state.db.update_diff_job_status(job.id, "failed", Some("aborted by user")).await;
        }
    }
    let redirect = format!("/cves/{}", cve_id);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    if let Ok(val) = HeaderValue::from_str(&redirect) {
        resp.headers_mut().insert("HX-Redirect", val);
    }
    Ok(resp)
}

async fn job_status(
    State(state): State<AppState>,
    Path(job_id): Path<i64>,
    req: Request<Body>,
) -> Result<impl IntoResponse, StatusCode> {
    let job = state
        .db
        .get_diff_job_by_id(job_id)
        .await
        .map_err(|e| {
            tracing::error!("get job {job_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let csrf_token = get_csrf_cookie(req.headers());
    render_html(JobStatusView { job, csrf_token })
}

#[derive(Deserialize)]
struct ExportPocForm {
    out: String,
}

async fn export_poc(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
    Form(form): Form<ExportPocForm>,
) -> Result<impl IntoResponse, StatusCode> {
    let detail = state
        .db
        .get_cve(&cve_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let report_dir = state.cfg.storage.base_dir.join("reports").join(&cve_id);
    let out_root = std::path::PathBuf::from(&form.out);
    let enrichment = crate::commands::export_poc_context::CveEnrichment {
        cvss: detail.cvss_score,
        cvss_vector: detail.cvss_vector,
    };

    match crate::commands::export_poc_context::export_poc_context(
        &report_dir,
        &out_root,
        Some(&enrichment),
    ) {
        Ok(()) => {
            let workspace = out_root.join(&cve_id);
            let path_escaped = html_escape(&workspace.display().to_string());
            Ok(Html(format!(
                r#"<p class="export-ok">Workspace written to <code>{path_escaped}</code></p>"#
            )))
        }
        Err(e) => {
            let err_escaped = html_escape(&e.to_string());
            Ok(Html(format!(
                r#"<p class="export-err">{err_escaped}</p>"#
            )))
        }
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn cve_report(
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
    req: Request<Body>,
) -> Result<impl IntoResponse, StatusCode> {
    let detail = state
        .db
        .get_cve(&cve_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let synthesis = state.db.get_synthesis(&cve_id).await.unwrap_or(None);

    let raw_findings = state.db.get_findings(&cve_id).await.unwrap_or_default();
    // Rows arrive ordered by filename then relevance desc; group consecutive rows
    // sharing a filename so the per-binary patch_summary is rendered once.
    let mut binaries: Vec<BinaryGroupView> = Vec::new();
    for f in raw_findings.into_iter().filter(|f| f.relevance >= 0.3) {
        let old_html = highlight_c(&f.old_snippet);
        let new_html = highlight_c(&f.new_snippet);
        let row = FindingViewRow { finding: f, old_html, new_html };
        match binaries.last_mut() {
            Some(g) if g.filename == row.finding.filename => g.findings.push(row),
            _ => binaries.push(BinaryGroupView {
                filename: row.finding.filename.clone(),
                patch_summary: row.finding.patch_summary.clone(),
                findings: vec![row],
            }),
        }
    }

    let report_path = state.cfg.storage.base_dir.join("reports").join(&cve_id).join("report.md");
    let report_html = std::fs::read_to_string(&report_path).ok().map(|md| render_markdown(&md));

    let csrf_token = get_csrf_cookie(req.headers());

    render_html(CveReportView {
        cve_id,
        title: detail.title,
        synthesis,
        binaries,
        report_html,
        csrf_token,
    })
}
