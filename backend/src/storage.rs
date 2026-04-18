// backend/src/storage.rs
// ClickHouse integration for scan history - simplified

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub program_name: String,
    pub program_hash: String,
    pub anchor_version: String,
    pub files_analyzed: u32,
    pub total_lines: u32,
    pub complexity: u32,
    pub score: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub chain_count: u32,
    pub taint_flow_count: u32,
    pub bypassable_invariant_count: u32,
    pub scanned_at: i64,
    pub report_json: String,
}

impl ScanRecord {
    pub fn new(id: String, report: &crate::types::AnalysisReport) -> Self {
        let summary = &report.summary;
        ScanRecord {
            id,
            program_name: report.profile.program_name.clone(),
            program_hash: simple_hash(&report.profile.program_name),
            anchor_version: report.profile.anchor_version.clone(),
            files_analyzed: report.profile.files_analyzed as u32,
            total_lines: report.profile.total_lines as u32,
            complexity: 0,
            score: summary.security_score,
            critical_count: summary.critical as u32,
            high_count: summary.high as u32,
            medium_count: summary.medium as u32,
            low_count: summary.low as u32,
            chain_count: summary.chain_count as u32,
            taint_flow_count: summary.taint_flow_count as u32,
            bypassable_invariant_count: summary.bypassable_invariant_count as u32,
            scanned_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
            report_json: serde_json::to_string(report).unwrap_or_default(),
        }
    }
}

fn simple_hash(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:x}", h.finish())
}

pub struct ClickHouseStorage {
    pub url: String,
    pub database: String,
}

impl ClickHouseStorage {
    pub fn new(url: &str, database: &str) -> Self {
        ClickHouseStorage {
            url: url.to_string(),
            database: database.to_string(),
        }
    }

    pub fn get_scans(&self, _program_name: &str, _limit: u32) -> Vec<ScanRecord> {
        vec![]
    }

    pub fn get_latest(&self, _program_name: &str) -> Option<ScanRecord> {
        None
    }
}