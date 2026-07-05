// backend/src/routes.rs — v4

use axum::{extract::Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;
use tracing::{info, warn, error};

use crate::{
    ai_enricher::AiEnricher,
    ast_visitor::ProjectVisitor,
    diff::diff_reports as compute_diff,
    patterns,
    perf,
    profiler::compute_profile,
    report::{apply_ai_enrichment, build_report},
    types::{AnalysisReport, AnalyzeRequest},
};

//   Request types                               ─

#[derive(serde::Deserialize)]
pub struct DiffRequest {
    pub baseline: AnalysisReport,
    pub current:  AnalysisReport,
}

//   Auth helper                              ─

fn check_api_key(headers: &axum::http::HeaderMap) -> Result<(), Response> {
    // Auth is ON by default — disable with REQUIRE_API_KEY=0
    if std::env::var("REQUIRE_API_KEY").unwrap_or_default() == "0" {
        return Ok(());
    }
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if api_key.is_empty() {
        warn!("Auth: missing API key");
        return Err((StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "API key required" }))
        ).into_response());
    }
    let allowed = std::env::var("ALLOWED_API_KEYS").unwrap_or_default();
    if !allowed.is_empty() {
        let key_ok = allowed.split(',').any(|k| {
            // Constant-time comparison to prevent timing attacks
            let a = k.as_bytes();
            let b = api_key.as_bytes();
            if a.len() != b.len() { return false; }
            let mut result = 0u8;
            for i in 0..a.len() {
                result |= a[i] ^ b[i];
            }
            result == 0
        });
        if !key_ok {
            warn!("Auth: invalid API key attempt");
            return Err((StatusCode::FORBIDDEN,
                Json(json!({ "error": "Invalid API key" }))
            ).into_response());
        }
    }
    Ok(())
}

fn check_api_key_or_skip(headers: &axum::http::HeaderMap) -> Result<(), Response> {
    check_api_key(headers)
}

pub async fn health(headers: axum::http::HeaderMap) -> impl IntoResponse {
    let _ = check_api_key(&headers);
    Json(json!({
        "status": "ok",
        "version": "4.0.0",
        "pipeline": [
            "ast_extraction", "trust_classification", "taint_analysis",
            "invariant_mining", "data_flow_graph", "call_graph",
            "pattern_detection", "chain_detection", "exploitability_scoring",
            "token_flow_graph", "permission_matrix", "vuln_db", "report_assembly"
        ]
    }))
}

pub async fn analyze(
    headers: axum::http::HeaderMap,
    Json(req): Json<AnalyzeRequest>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }

    let rs_count = req.files.iter().filter(|f| f.path.ends_with(".rs")).count();
    info!("Analyze request: {} files ({} .rs)", req.files.len(), rs_count);

    if rs_count == 0 {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No .rs files found in upload" }))
        ).into_response();
    }

    let llm_consent = req.llm_consent;

    // Process with error handling
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        //   Stage 1: AST extraction                        ─
        let mut visitor = ProjectVisitor::new();
        
        for file in &req.files {
            if file.path.ends_with(".rs") {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    visitor.visit_rs_file(&file.path, &file.content);
                }));
                if result.is_err() {
                    warn!("Failed to parse .rs file: {}", file.path);
                }
            }
            if file.path.ends_with(".toml") {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    visitor.visit_toml_file(&file.path, &file.content);
                }));
                if result.is_err() {
                    warn!("Failed to parse .toml file: {}", file.path);
                }
            }
        }
        info!(
            "AST: {} instructions, {} account_structs, {} CPIs, {} PDAs",
            visitor.instructions.len(),
            visitor.account_structs.len(),
            visitor.cpi_calls.len(),
            visitor.pda_derivations.len(),
        );

        //   Stage 2: Pattern detection                       
        let findings = patterns::detect_all(&visitor, &req.files);
        info!("Patterns: {} findings", findings.len());

        //   Stage 3: Profiling                           
        let profile = compute_profile(&visitor, &req.files);
        info!("Profile: complexity={}, anchor={}", profile.complexity, profile.anchor_version);

        //   Stage 3b: Performance analysis
        let perf_issues = perf::detect_perf_issues(&visitor, &req.files, &req.cu_budgets);
        if !perf_issues.is_empty() {
            info!("Perf: {} performance issues found", perf_issues.len());
        }

        //   Stages 4–10: trust, taint, invariants, data_flow, call_graph,
        //                 chains, scoring, vuln_db — all inside build_report    
        let (mut report, ai_context) = build_report(findings, profile, &visitor, &req.files);

        // Attach performance issues to report
        report.performance_issues = perf_issues;

        info!(
            "Report: {} findings, {} chains, {} taint_flows, {} invariants ({} bypassable), {} token_anomalies, {} broken_perms, score={}",
            report.summary.total,
            report.summary.chain_count,
            report.summary.taint_flow_count,
            report.summary.invariant_count,
            report.summary.bypassable_invariant_count,
            report.summary.token_flow_anomaly_count,
            report.summary.broken_permission_count,
            report.summary.security_score,
        );

        (report, ai_context)
    }));

    match result {
        Ok((mut report, ai_context)) => {

    //   Optional: AI enrichment (Groq free tier)               
    let needs_ai = !ai_context.findings_needing_ai.is_empty()
        || !ai_context.chain_ids_needing_ai.is_empty();

    if needs_ai && !llm_consent {
        warn!("LLM consent not given — user code NOT sent to Groq API");
    } else if needs_ai {
        match std::env::var("GROQ_API_KEY") {
            Ok(key) if !key.is_empty() => {
                match AiEnricher::new(key).enrich(&report, &ai_context).await {
                    Ok(enrichment) => {
                        let nf = enrichment.findings.len();
                        let nc = enrichment.chains.len();
                        report = apply_ai_enrichment(report, enrichment);
                        info!("AI: enriched {} findings, {} chains", nf, nc);
                    }
                    Err(e) => warn!("Groq API failed (static report returned): {}", e),
                }
            }
            _ => info!("No GROQ_API_KEY — returning static report (AI enrichment skipped)"),
        }
    }

    info!("Done: risk={} score={}", report.summary.overall_risk, report.summary.security_score);
    Json(report).into_response()
}
        Err(panic_err) => {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            error!("Analysis panicked: {}", msg);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Analysis failed", "details": msg }))
            ).into_response()
        }
    }
}

//   POST /api/diff                               ─

pub async fn diff_reports(
    headers: axum::http::HeaderMap,
    Json(req): Json<DiffRequest>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    info!(
        "Diff: {} (score={}) vs {} (score={})",
        req.baseline.profile.program_name, req.baseline.summary.security_score,
        req.current.profile.program_name,  req.current.summary.security_score,
    );

    let diff = compute_diff(&req.baseline, &req.current);

    info!(
        "Diff result: {} fixed, {} new, {} regressed — verdict: {:?}",
        diff.summary.total_fixed,
        diff.summary.total_new,
        diff.summary.total_regressed,
        diff.summary.verdict,
    );

    Json(diff).into_response()
}

//   GET /api/health/full                            ─

pub async fn health_full(
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let _ = check_api_key(&headers);
    Json(json!({
        "status": "ok",
        "version": "4.0.0",
        "features": {
            "ai_enrichment": std::env::var("GROQ_API_KEY").is_ok(),
            "api_keys": std::env::var("REQUIRE_API_KEY").unwrap_or_default() != "0",
            "sarif_export": true,
            "fuzz_harness": true,
            "pinocchio_support": true,
        }
    }))
}

/// POST /api/export/sarif — export last analysis as SARIF
pub async fn export_sarif(
    headers: axum::http::HeaderMap,
    Json(report): Json<AnalysisReport>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    let sarif = crate::sarif::report_to_sarif(&report);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        sarif,
    ).into_response()
}

/// POST /api/export/fuzz — generate fuzz harness for last analysis
pub async fn export_fuzz(
    headers: axum::http::HeaderMap,
    Json(report): Json<AnalysisReport>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    let format = "trident";
    let harness = match format {
        "trident" => crate::fuzz::generate_trident_harness(&report),
        "litesvm" => crate::fuzz::generate_litesvm_test(&report),
        _ => crate::fuzz::generate_python_test(&report),
    };
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        harness,
    ).into_response()
}

//   Monitor endpoints                      ─

#[derive(serde::Deserialize)]
pub struct StartMonitorRequest {
    pub program_name: String,
    #[serde(default)]
    pub program_id: String,
    #[serde(default = "default_cluster")]
    pub cluster: String,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
}

fn default_cluster() -> String { "mainnet-beta".to_string() }
fn default_interval() -> u64 { 300 }

pub async fn start_monitor(
    headers: axum::http::HeaderMap,
    Json(req): Json<StartMonitorRequest>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    let config = crate::monitor::MonitorConfig {
        program_id: req.program_id,
        cluster: req.cluster,
        interval_seconds: req.interval_seconds,
        ..Default::default()
    };
    let id = uuid::Uuid::new_v4().to_string();
    let engine = crate::monitor::MonitoringEngine::new();
    let job_id = engine.start_job(req.program_name, config).await;
    info!("Monitor started: {}", job_id);
    Json(serde_json::json!({
        "status": "started",
        "job_id": job_id,
        "message": "Monitoring job created (skeleton — RPC polling not yet connected)",
    })).into_response()
}

pub async fn stop_monitor(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    info!("Monitor stopped: {}", id);
    Json(serde_json::json!({
        "status": "stopped",
        "job_id": id,
    })).into_response()
}

pub async fn monitor_status(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    let engine = crate::monitor::MonitoringEngine::new();
    match engine.get_job(&id).await {
        Some(job) => Json(serde_json::json!({
            "id": job.id,
            "program_name": job.program_name,
            "status": job.status,
            "config": job.config,
            "created_at": job.created_at,
            "last_check_at": job.last_check_at,
            "total_events": job.events.len(),
            "error_count": job.error_count,
            "total_checks": job.total_checks,
        })).into_response(),
        None => {
            warn!("Monitor: job not found: {}", id);
            (StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Monitor job not found"})),
            ).into_response()
        }
    }
}

pub async fn monitor_events(
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    if let Err(resp) = check_api_key(&headers) { return resp; }
    let engine = crate::monitor::MonitoringEngine::new();
    let events = engine.get_events(&id, 100).await;
    Json(serde_json::json!({
        "job_id": id,
        "events": events,
        "count": events.len(),
    })).into_response()
}

pub async fn monitor_health(
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let _ = check_api_key(&headers);
    let engine = crate::monitor::MonitoringEngine::new();
    Json(engine.health_summary().await)
}

/// GET /api/report/:id/export — placeholder for stored report export
pub async fn export_report(
    headers: axum::http::HeaderMap,
    _path: axum::extract::Path<String>,
) -> Response {
    let _ = check_api_key(&headers);
    Json(json!({
        "message": "Use POST /api/analyze to generate reports, then POST /api/export/sarif or /api/export/fuzz",
        "export_formats": ["sarif", "fuzz/trident", "fuzz/litesvm", "fuzz/python"],
    })).into_response()
}
