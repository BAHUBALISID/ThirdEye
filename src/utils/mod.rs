use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use anyhow::Result;

pub struct ProgressTracker {
    start_time: Instant,
    processed: AtomicUsize,
    total: Option<usize>,
    running: Arc<AtomicBool>,
}

impl ProgressTracker {
    pub fn new(total: Option<usize>) -> Self {
        Self {
            start_time: Instant::now(),
            processed: AtomicUsize::new(0),
            total,
            running: Arc::new(AtomicBool::new(true)),
        }
    }
    
    pub fn increment(&self) {
        self.processed.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
    
    pub fn get_progress(&self) -> ProgressInfo {
        let processed = self.processed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        
        let rate = if elapsed.as_secs() > 0 {
            processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        let remaining = if let Some(total) = self.total {
            if processed > 0 {
                let estimated_total = (elapsed.as_secs_f64() / processed as f64) * total as f64;
                Duration::from_secs_f64(estimated_total - elapsed.as_secs_f64())
            } else {
                Duration::from_secs(0)
            }
        } else {
            Duration::from_secs(0)
        };
        
        ProgressInfo {
            processed,
            total: self.total,
            elapsed,
            rate,
            remaining,
            running: self.running.load(Ordering::Relaxed),
        }
    }
}

pub struct ProgressInfo {
    pub processed: usize,
    pub total: Option<usize>,
    pub elapsed: Duration,
    pub rate: f64,
    pub remaining: Duration,
    pub running: bool,
}

pub struct RateLimiter {
    interval: Duration,
    last_call: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_call: std::sync::Mutex::new(Instant::now() - interval),
        }
    }
    
    pub async fn wait(&self) {
        let mut last_call = self.last_call.lock().unwrap();
        let elapsed = last_call.elapsed();
        
        if elapsed < self.interval {
            tokio::time::sleep(self.interval - elapsed).await;
        }
        
        *last_call = Instant::now();
    }
}

pub fn validate_email(email: &str) -> bool {
    let re = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    re.is_match(email)
}

pub fn validate_domain(domain: &str) -> bool {
    let re = regex::Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap();
    re.is_match(domain)
}

pub fn parse_targets(input: &str) -> Vec<String> {
    input.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
}

pub fn calculate_hash(data: &[u8], algorithm: &str) -> String {
    match algorithm.to_lowercase().as_str() {
        "md5" => {
            let digest = md5::compute(data);
            format!("{:x}", digest)
        }
        "sha1" => {
            use sha1::{Sha1, Digest};
            let mut hasher = Sha1::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        "sha256" => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        _ => String::new(),
    }
}

pub struct SignalHandler {
    running: Arc<AtomicBool>,
}

impl SignalHandler {
    pub fn new() -> Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        
        ctrlc::set_handler(move || {
            eprintln!("\n[!] Received interrupt signal. Cleaning up...");
            running_clone.store(false, Ordering::Relaxed);
        })?;
        
        Ok(Self { running })
    }
    
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
