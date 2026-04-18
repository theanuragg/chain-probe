// backend/src/main.rs — ChainProbe v4

use axum::{Router, routing::{get, post}, http::Method};
use tower_http::cors::{CorsLayer, Any};
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

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/health/full", get(routes::health_full))
        .route("/api/analyze", post(routes::analyze))
        .route("/api/diff",    post(routes::diff_reports))
        .route("/api/export/:id", get(routes::export_report))
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
