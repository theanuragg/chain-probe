// backend/src/routes.rs — v4

use axum::{extract::Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;
use tracing::{info, warn, error};

use crate::{
    ai_enricher::AiEnricher,
    ast_visitor::ProjectVisitor,
    diff::diff_reports as compute_diff,
    patterns,
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

pub async fn health() -> impl IntoResponse {
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
    // Check API key if required
    if std::env::var("REQUIRE_API_KEY").unwrap_or_default() == "1" {
        let api_key = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if api_key.is_empty() {
            return (StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "API key required" }))
            ).into_response();
        }

        // Check against allowed keys (comma-separated in env)
        let allowed = std::env::var("ALLOWED_API_KEYS").unwrap_or_default();
        if !allowed.is_empty() && !allowed.split(',').any(|k| k == api_key) {
            return (StatusCode::FORBIDDEN,
                Json(json!({ "error": "Invalid API key" }))
            ).into_response();
        }
    }

    let rs_count = req.files.iter().filter(|f| f.path.ends_with(".rs")).count();
    info!("Analyze request: {} files ({} .rs)", req.files.len(), rs_count);

    if rs_count == 0 {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No .rs files found in upload" }))
        ).into_response();
    }

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

        //   Stages 4–10: trust, taint, invariants, data_flow, call_graph,
        //                 chains, scoring, vuln_db — all inside build_report    
        let (mut report, ai_context) = build_report(findings, profile, &visitor, &req.files);

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

    if needs_ai {
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

pub async fn diff_reports(Json(req): Json<DiffRequest>) -> Response {
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

//   GET /api/report/:id/export                         

pub async fn export_report(
    path: axum::extract::Path<String>,
) -> Response {
    // For now, return the full report as JSON for download
    // In production, this would load from database
    Json(json!({
        "message": "Use POST /api/analyze to generate reports",
        "export_format": "json",
    })).into_response()
}

//   GET /api/health/full                            ─

pub async fn health_full() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": "4.0.0",
        "features": {
            "ai_enrichment": std::env::var("GROQ_API_KEY").is_ok(),
            "api_keys": std::env::var("REQUIRE_API_KEY").unwrap_or_default() == "1",
        }
    }))
}
