// backend/src/lib.rs
// Exposes the full ChainProbe analysis pipeline as a library.
// Used by: chainprobe-cli (so it runs without requiring the HTTP server).
// The HTTP server (main.rs) and the CLI both use these same modules.

pub mod types;
pub mod ast_visitor;
pub mod patterns;
pub mod profiler;
pub mod trust;
pub mod taint;
pub mod invariant;
pub mod data_flow;
pub mod call_graph;
pub mod chain_detector;
pub mod scoring;
pub mod vuln_db;
pub mod token_flow;
pub mod permission_model;
pub mod diff;
pub mod report;
pub mod ai_enricher;
pub mod detectors;
pub mod exploits;
pub mod pro_audits;

// Re-export the top-level entry points the CLI needs
pub use report::build_report;
pub use types::{AnalysisReport, AnalyzeRequest, InputFile};
