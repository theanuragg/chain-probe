// backend/src/main.rs — ChainProbe v4

use axum::{Router, routing::{get, post}, http::Method, http::HeaderValue, extract::DefaultBodyLimit};
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;

// Core pipeline modules
mod types;
mod ast_visitor;
mod patterns;
mod profiler;
mod trust;
mod taint;
mod invariant;
mod data_flow;
mod call_graph;
mod chain_detector;
mod scoring;
mod vuln_db;
mod token_flow;
mod permission_model;
mod diff;           // NEW: audit regression comparison
mod report;
mod ai_enricher;
mod routes;
mod rate_limit;
mod storage;
mod pdf;
mod detectors;
mod exploits;
mod pro_audits;
mod framework;
mod pinocchio;
mod sarif;
mod fuzz;
mod monitor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "chainprobe=debug,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cors_origin = std::env::var("CORS_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".into());
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_origin(cors_origin.parse::<HeaderValue>().unwrap());

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/health/full", get(routes::health_full))
        .route("/api/analyze", post(routes::analyze))
        .route("/api/diff",    post(routes::diff_reports))
        .route("/api/export/:id", get(routes::export_report))
        .route("/api/export/sarif", post(routes::export_sarif))
        .route("/api/export/fuzz",  post(routes::export_fuzz))
        .route("/api/monitor/start", post(routes::start_monitor))
        .route("/api/monitor/:id/stop", post(routes::stop_monitor))
        .route("/api/monitor/:id/status", get(routes::monitor_status))
        .route("/api/monitor/:id/events", get(routes::monitor_events))
        .route("/api/monitor/health", get(routes::monitor_health))
        .layer(DefaultBodyLimit::max(25_000_000))  // 25MB limit
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3001".into())
        .parse()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("ChainProbe v4 on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
