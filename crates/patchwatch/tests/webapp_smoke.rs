//! Integration tests for the axum webapp layer.
//! Uses in-memory SQLite + axum oneshot testing (no real TCP socket).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use patchwatch::storage::Db;
use patchwatch::web::jobs::AnalyzeService;
use patchwatch::web::router::{AppState, build_router};
use reqwest::Client;
use std::sync::Arc;

async fn make_state() -> AppState {
    let cfg = patchwatch::config::Config::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.yaml"),
    )
    .expect("load config");
    let db = Arc::new(Db::open_in_memory_async().await.expect("open db"));
    let http = Client::new();
    let analyze = Arc::new(AnalyzeService::spawn(
        Arc::new(cfg.clone()),
        db.clone(),
        http,
    ));
    AppState {
        cfg: Arc::new(cfg),
        db,
        analyze,
        csrf_secret: "test-csrf-secret".to_string(),
    }
}

async fn body_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn seed_cve(db: &Db) {
    use patchwatch::sug::types::Vulnerability;
    let cve = Vulnerability {
        cve_number: "CVE-2026-23670".into(),
        cve_title: Some("Test heap overflow".into()),
        base_score: Some(7.8),
        temporal_score: None,
        vector_string: Some("CVSS:3.1/AV:L/AC:L".into()),
        severity: None,
        impact: None,
        issuing_cna: None,
        tag: None,
        exploited: Some("Yes".into()),
        publicly_disclosed: None,
        customer_action_required: None,
        is_mariner: None,
        release_number: None,
        release_date: Some("2026-04-08".into()),
        revision_number: Some("1.0".into()),
        description: Some("A heap overflow in win32k.sys".into()),
        cwe_list: Some(vec!["CWE-122".into()]),
    };
    db.upsert_cve(&cve, "{}".to_string()).await.unwrap();
    db.upsert_cve_kb("CVE-2026-23670", "KB5083768").await.unwrap();
}

// ---- Tests ----

#[tokio::test]
async fn healthz_returns_200() {
    use tower::ServiceExt;
    let app = build_router(make_state().await);
    let resp = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_shows_seeded_cves() {
    use tower::ServiceExt;
    let state = make_state().await;
    seed_cve(&state.db).await;
    let app = build_router(state);
    let resp = app
        .oneshot(Request::get("/cves").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    assert!(body.contains("CVE-2026-23670"), "CVE id should appear in list");
}

#[tokio::test]
async fn detail_shows_cve_fields() {
    use tower::ServiceExt;
    let state = make_state().await;
    seed_cve(&state.db).await;
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::get("/cves/CVE-2026-23670")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    assert!(body.contains("CVE-2026-23670"));
    assert!(body.contains("heap overflow"));
}

#[tokio::test]
async fn analyze_without_csrf_is_403() {
    use tower::ServiceExt;
    let state = make_state().await;
    seed_cve(&state.db).await;
    let app = build_router(state);
    // POST with no CSRF token or cookie should be rejected.
    let resp = app
        .oneshot(
            Request::post("/cves/CVE-2026-23670/analyze")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn analyze_post_creates_diff_job() {
    use patchwatch::web::csrf::generate_token_for_test;
    use tower::ServiceExt;

    let state = make_state().await;
    seed_cve(&state.db).await;
    let db = state.db.clone();
    let secret = state.csrf_secret.clone();
    let app = build_router(state);

    let token = generate_token_for_test(&secret);
    let cookie = format!("csrf_token={}", token);

    let resp = app
        .oneshot(
            Request::post("/cves/CVE-2026-23670/analyze")
                .header("cookie", &cookie)
                .header("x-csrf-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "unexpected status: {}",
        resp.status()
    );

    let job = db.get_latest_diff_job("CVE-2026-23670").await.unwrap();
    assert!(job.is_some(), "diff_job should have been created");
    let job = job.unwrap();
    assert_eq!(job.cve_id, "CVE-2026-23670");
}

#[tokio::test]
async fn first_visit_csrf_token_round_trips_to_post() {
    // Regression: on the first GET, the server must render the same CSRF token
    // value that it sets in the Set-Cookie header, so that an immediate POST
    // (e.g. clicking "Run Analysis") matches and succeeds.
    use tower::ServiceExt;

    let state = make_state().await;
    seed_cve(&state.db).await;
    let app = build_router(state);

    let get_resp = app
        .clone()
        .oneshot(
            Request::get("/cves/CVE-2026-23670")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);

    let set_cookie = get_resp
        .headers()
        .get("set-cookie")
        .expect("Set-Cookie on first visit")
        .to_str()
        .unwrap()
        .to_owned();
    let cookie_token = set_cookie
        .split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("csrf_token=")
        .expect("csrf_token cookie")
        .to_owned();

    let body = body_string(get_resp.into_body()).await;
    let meta_marker = "<meta name=\"csrf-token\" content=\"";
    let start = body.find(meta_marker).expect("meta csrf-token tag") + meta_marker.len();
    let end = body[start..].find('"').expect("close quote") + start;
    let rendered_token = &body[start..end];

    assert_eq!(
        rendered_token, cookie_token,
        "rendered csrf-token meta must match Set-Cookie token on first visit"
    );

    let cookie_header = format!("csrf_token={}", cookie_token);
    let post_resp = app
        .oneshot(
            Request::post("/cves/CVE-2026-23670/analyze")
                .header("cookie", &cookie_header)
                .header("x-csrf-token", &cookie_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        post_resp.status().is_success() || post_resp.status().is_redirection(),
        "POST after first-visit GET should not be 403, got: {}",
        post_resp.status()
    );
}

#[tokio::test]
async fn report_shows_synthesis_when_present() {
    use patchwatch::triage::deep_analysis::{DeepAnalysisResult, FunctionFinding};
    use patchwatch::triage::synthesis::{BinaryAssessment, SynthesisResult};
    use tower::ServiceExt;

    let state = make_state().await;
    seed_cve(&state.db).await;

    let job_id = state.db.create_diff_job("CVE-2026-23670").await.unwrap();
    state.db.update_diff_job_status(job_id, "done", None).await.unwrap();

    let syn = SynthesisResult {
        per_binary: vec![BinaryAssessment {
            filename: "win32k.sys".into(),
            security_relevant: true,
            confidence: 0.9,
            reasoning: "Core kernel component".into(),
        }],
        primary_binaries: vec!["win32k.sys".into()],
        overall_summary: "Critical heap overflow in win32k.sys".into(),
        ranked_functions: vec![],
    };
    state.db.upsert_synthesis("CVE-2026-23670", job_id, &syn).await.unwrap();

    let da = DeepAnalysisResult {
        patch_summary: "Added bounds check".into(),
        findings: vec![FunctionFinding {
            name: "NtUserCreateWindow".into(),
            relevance: 0.95,
            summary: "Added size validation".into(),
            old_snippet: "void *p = alloc(size);".into(),
            new_snippet: "if (size > MAX) return; void *p = alloc(size);".into(),
        }],
    };
    state.db.upsert_findings("CVE-2026-23670", "win32k.sys", &da).await.unwrap();

    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::get("/cves/CVE-2026-23670/report")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    assert!(body.contains("Critical heap overflow"), "synthesis summary should appear");
    assert!(body.contains("NtUserCreateWindow"), "finding function name should appear");
}
