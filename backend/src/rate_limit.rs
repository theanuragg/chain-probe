// backend/src/rate_limit.rs
// Simple in-memory rate limiter for API protection

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

const MAX_REQUESTS_PER_MINUTE: usize = 10;
const WINDOW_SECS: u64 = 60;

pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_per_window: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_per_minute: usize) -> Self {
        RateLimiter {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_per_window: max_per_minute,
            window: Duration::from_secs(WINDOW_SECS),
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut requests = self.requests.write().await;
        
        let entries = requests.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Clean old entries
        entries.retain(|&t| now.duration_since(t) < self.window);
        
        // Check limit
        if entries.len() >= self.max_per_window {
            return false;
        }
        
        entries.push(now);
        true
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut requests = self.requests.write().await;
        
        for entries in requests.values_mut() {
            entries.retain(|&t| now.duration_since(t) < self.window);
        }
        
        requests.retain(|_, v| !v.is_empty());
    }
}

#[derive(Clone)]
pub struct ApiKeyManager {
    keys: Arc<RwLock<HashMap<String, ApiKey>>>,
}

#[derive(Clone)]
pub struct ApiKey {
    pub plan: String,
    pub scans_used: u32,
    pub scans_limit: u32,
    pub created_at: i64,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        ApiKeyManager {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_key(&self, key: String, plan: String, limit: u32) {
        let mut keys = self.keys.write().await;
        keys.insert(key, ApiKey {
            plan,
            scans_used: 0,
            scans_limit: limit,
            created_at: chrono::Utc::now().timestamp(),
        });
    }

    pub async fn validate(&self, key: &str) -> Option<ApiKey> {
        let keys = self.keys.read().await;
        keys.get(key).cloned()
    }

    pub async fn use_scan(&self, key: &str) -> bool {
        let mut keys = self.keys.write().await;
        if let Some(api_key) = keys.get_mut(key) {
            if api_key.scans_used < api_key.scans_limit {
                api_key.scans_used += 1;
                return true;
            }
        }
        false
    }

    pub async fn get_usage(&self, key: &str) -> Option<(String, u32, u32)> {
        let keys = self.keys.read().await;
        keys.get(key).map(|k| (k.plan.clone(), k.scans_used, k.scans_limit))
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}