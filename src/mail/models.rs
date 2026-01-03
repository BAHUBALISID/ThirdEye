use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]  // Added Eq and Hash
pub struct EmailFinding {
    pub email: String,
    pub sources: Vec<BreachSource>,
    pub exposures: Vec<Exposure>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub password_hashes: Vec<PasswordHash>,
    pub raw_credentials: Option<Vec<String>>,
    pub risk_score: f32,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachSource {
    pub name: String,
    pub api_source: bool,
    pub local_file: Option<String>,
    pub breach_date: Option<DateTime<Utc>>,
    pub record_count: u64,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Exposure {
    PlaintextCredential,
    HashedCredential(HashType),
    PasswordOnly,
    EmailOnly,
    MetadataOnly,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]  // Added Eq and Hash
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    Bcrypt,
    NTLM,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHash {
    pub hash: String,
    pub hash_type: HashType,
    pub salt: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFindings {
    pub domain: String,
    pub emails: Vec<EmailFinding>,
    pub password_reuse: HashMap<String, Vec<String>>,
    pub unique_passwords: usize,
    pub risk_score: f32,
    pub employee_count_estimate: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachRecord {
    pub email: String,
    pub password: Option<String>,
    pub hash: Option<String>,
    pub hash_type: Option<HashType>,
    pub source: String,
    pub breach_date: Option<DateTime<Utc>>,
    pub additional_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalScanStats {
    pub file_path: String,
    pub bytes_scanned: u64,
    pub records_processed: u64,
    pub emails_found: u64,
    pub unique_emails: u64,
    pub scan_duration: std::time::Duration,
}
