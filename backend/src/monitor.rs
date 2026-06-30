// backend/src/monitor.rs
// Post-deployment monitoring skeleton for deployed Solana programs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub program_id: String,
    pub cluster: String,
    pub interval_seconds: u64,
    pub alert_on_upgrade: bool,
    pub alert_on_large_transfer: bool,
    pub alert_on_new_authority: bool,
    pub large_transfer_threshold_lamports: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            program_id: String::new(),
            cluster: "mainnet-beta".to_string(),
            interval_seconds: 300,
            alert_on_upgrade: true,
            alert_on_large_transfer: false,
            alert_on_new_authority: false,
            large_transfer_threshold_lamports: 1_000_000_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorEventKind {
    ProgramUpgrade {
        old_slot: u64,
        new_slot: u64,
        authority: Option<String>,
    },
    LargeTransfer {
        amount: u64,
        from: String,
        to: String,
        slot: u64,
    },
    AuthorityChanged {
        previous_authority: Option<String>,
        new_authority: Option<String>,
        slot: u64,
    },
    AccountCreated {
        account: String,
        owner: String,
        slot: u64,
    },
    UnusualActivity {
        description: String,
        slot: u64,
        details: HashMap<String, String>,
    },
    HealthCheck {
        status: String,
        last_confirmed_slot: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub kind: MonitorEventKind,
    pub severity: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorJob {
    pub id: String,
    pub program_name: String,
    pub config: MonitorConfig,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub last_check_at: Option<DateTime<Utc>>,
    pub events: Vec<MonitorEvent>,
    pub error_count: u32,
    pub total_checks: u32,
}

impl MonitorJob {
    pub fn new(id: String, program_name: String, config: MonitorConfig) -> Self {
        MonitorJob {
            id,
            program_name,
            config,
            status: "active".to_string(),
            created_at: Utc::now(),
            last_check_at: None,
            events: Vec::new(),
            error_count: 0,
            total_checks: 0,
        }
    }
}

#[derive(Clone)]
pub struct MonitoringEngine {
    jobs: Arc<RwLock<HashMap<String, MonitorJob>>>,
}

impl MonitoringEngine {
    pub fn new() -> Self {
        MonitoringEngine {
            jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start_job(&self, program_name: String, config: MonitorConfig) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let job = MonitorJob::new(id.clone(), program_name, config);
        let mut jobs = self.jobs.write().await;
        jobs.insert(id.clone(), job);
        id
    }

    pub async fn stop_job(&self, id: &str) -> bool {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(id) {
            job.status = "stopped".to_string();
            true
        } else {
            false
        }
    }

    pub async fn get_job(&self, id: &str) -> Option<MonitorJob> {
        let jobs = self.jobs.read().await;
        jobs.get(id).cloned()
    }

    pub async fn list_jobs(&self) -> Vec<MonitorJob> {
        let jobs = self.jobs.read().await;
        jobs.values().cloned().collect()
    }

    pub async fn add_event(&self, job_id: &str, event: MonitorEvent) -> bool {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            job.events.push(event);
            job.last_check_at = Some(Utc::now());
            job.total_checks += 1;
            true
        } else {
            false
        }
    }

    pub async fn get_events(&self, job_id: &str, limit: usize) -> Vec<MonitorEvent> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id)
            .map(|j| {
                let mut events = j.events.clone();
                events.reverse();
                events.truncate(limit);
                events
            })
            .unwrap_or_default()
    }

    pub async fn acknowledge_event(&self, job_id: &str, event_id: &str) -> bool {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            if let Some(event) = job.events.iter_mut().find(|e| e.id == event_id) {
                event.acknowledged = true;
                return true;
            }
        }
        false
    }

    pub async fn health_summary(&self) -> serde_json::Value {
        let jobs = self.jobs.read().await;
        let active = jobs.values().filter(|j| j.status == "active").count();
        let total_events: usize = jobs.values().map(|j| j.events.len()).sum();
        let unacknowledged: usize = jobs.values()
            .flat_map(|j| j.events.iter())
            .filter(|e| !e.acknowledged)
            .count();
        serde_json::json!({
            "total_jobs": jobs.len(),
            "active_jobs": active,
            "total_events": total_events,
            "unacknowledged_events": unacknowledged,
        })
    }
}

impl Default for MonitoringEngine {
    fn default() -> Self {
        Self::new()
    }
}
