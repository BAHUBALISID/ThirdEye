use crate::mail::models::*;
use crate::mail::parser::BreachParser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

#[derive(Clone)]  // Added Clone
pub struct BreachParser {
    email_regex: regex::Regex,
    md5_regex: regex::Regex,
    sha1_regex: regex::Regex,
    sha256_regex: regex::Regex,
}

impl BreachParser {
    pub fn new() -> Self {
        Self {
            email_regex: regex::Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap(),
            md5_regex: regex::Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
            sha1_regex: regex::Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
            sha256_regex: regex::Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(),
        }
    }
    
    pub fn parse_line(&self, line: &str) -> Result<Option<BreachRecord>> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }
        
        // Try different formats
        if let Some(record) = self.parse_email_password(trimmed) {
            return Ok(Some(record));
        }
        
        if let Some(record) = self.parse_json_line(trimmed) {
            return Ok(Some(record));
        }
        
        if let Some(record) = self.parse_hash_format(trimmed) {
            return Ok(Some(record));
        }
        
        Ok(None)
    }
    
    fn parse_email_password(&self, line: &str) -> Option<BreachRecord> {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let email = parts[0].trim().to_lowercase();
        let credential = parts[1].trim();
        
        if !self.email_regex.is_match(&email) {
            return None;
        }
        
        // Check if credential is a hash
        let (hash, hash_type, password) = if self.md5_regex.is_match(credential) {
            (Some(credential.to_string()), Some(HashType::MD5), None)
        } else if self.sha1_regex.is_match(credential) {
            (Some(credential.to_string()), Some(HashType::SHA1), None)
        } else if self.sha256_regex.is_match(credential) {
            (Some(credential.to_string()), Some(HashType::SHA256), None)
        } else {
            (None, None, Some(credential.to_string()))
        };
        
        Some(BreachRecord {
            email,
            password,
            hash,
            hash_type,
            source: "LocalFile".to_string(),
            breach_date: None,
            additional_data: std::collections::HashMap::from([
                ("format".to_string(), "email:password".to_string()),
            ]),
        })
    }
    
    fn parse_json_line(&self, line: &str) -> Option<BreachRecord> {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let email = json.get("email")
                .or_else(|| json.get("username"))
                .or_else(|| json.get("Email"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase());
            
            let password = json.get("password")
                .or_else(|| json.get("Password"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            
            let hash = json.get("hash")
                .or_else(|| json.get("Hash"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            
            let hash_type = json.get("hash_type")
                .and_then(|v| v.as_str())
                .map(|s| match s.to_lowercase().as_str() {
                    "md5" => HashType::MD5,
                    "sha1" => HashType::SHA1,
                    "sha256" => HashType::SHA256,
                    "bcrypt" => HashType::Bcrypt,
                    "ntlm" => HashType::NTLM,
                    _ => HashType::Unknown,
                });
            
            let breach_date = json.get("breach_date")
                .and_then(|v| v.as_str())
                .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .map(|d| chrono::DateTime::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0).unwrap(), chrono::Utc));
            
            if let Some(email) = email {
                return Some(BreachRecord {
                    email,
                    password,
                    hash,
                    hash_type,
                    source: "LocalJSON".to_string(),
                    breach_date,
                    additional_data: std::collections::HashMap::new(),
                });
            }
        }
        
        None
    }
    
    fn parse_hash_format(&self, line: &str) -> Option<BreachRecord> {
        if let Some(email_match) = self.email_regex.find(line) {
            let email = email_match.as_str().to_lowercase();
            
            let hash_candidates: Vec<&str> = line.split_whitespace().collect();
            
            for candidate in hash_candidates {
                if self.md5_regex.is_match(candidate) {
                    return Some(BreachRecord {
                        email,
                        password: None,
                        hash: Some(candidate.to_string()),
                        hash_type: Some(HashType::MD5),
                        source: "LocalHashFile".to_string(),
                        breach_date: None,
                        additional_data: std::collections::HashMap::new(),
                    });
                } else if self.sha1_regex.is_match(candidate) {
                    return Some(BreachRecord {
                        email,
                        password: None,
                        hash: Some(candidate.to_string()),
                        hash_type: Some(HashType::SHA1),
                        source: "LocalHashFile".to_string(),
                        breach_date: None,
                        additional_data: std::collections::HashMap::new(),
                    });
                } else if self.sha256_regex.is_match(candidate) {
                    return Some(BreachRecord {
                        email,
                        password: None,
                        hash: Some(candidate.to_string()),
                        hash_type: Some(HashType::SHA256),
                        source: "LocalHashFile".to_string(),
                        breach_date: None,
                        additional_data: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        None
    }
}

pub struct LocalScanner {
    parser: BreachParser,
    chunk_size: usize,
}

impl LocalScanner {
    pub fn new() -> Self {
        Self {
            parser: BreachParser::new(),
            chunk_size: 100_000,
        }
    }
    
    pub async fn scan_file(
        &self,
        file_path: &Path,
        target_email: Option<&str>,
        target_domain: Option<&str>,
    ) -> Result<LocalScanResult> {
        let file = File::open(file_path)?;
        
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        
        // Create progress bar for large files
        let pb = if file_size > 10_000_000 {
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(pb)
        } else {
            None
        };
        
        let reader = BufReader::new(file);
        let lines_read = Arc::new(AtomicU64::new(0));
        let bytes_read = Arc::new(AtomicU64::new(0));
        
        // Channel for found records
        let (tx, mut rx) = mpsc::channel::<BreachRecord>(1000);
        
        // Spawn parser task
        let parser = self.parser.clone();
        let target_email = target_email.map(|s| s.to_string());
        let target_domain = target_domain.map(|s| s.to_string());
        let lines_read_clone = lines_read.clone();
        let bytes_read_clone = bytes_read.clone();
        let pb_clone = pb.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut buffer = Vec::with_capacity(100_000);
            let mut current_pos = 0u64;
            
            for line in reader.lines() {
                match line {
                    Ok(line_content) {
                        current_pos += line_content.len() as u64 + 1;
                        
                        buffer.push(line_content);
                        
                        if buffer.len() >= 100_000 {
                            let batch = std::mem::take(&mut buffer);
                            let _ = process_batch_blocking(
                                batch,
                                &parser,
                                &target_email,
                                &target_domain,
                                &tx,
                            );
                        }
                        
                        lines_read_clone.fetch_add(1, Ordering::Relaxed);
                        bytes_read_clone.store(current_pos, Ordering::Relaxed);
                        
                        if let Some(pb) = &pb_clone {
                            pb.set_position(current_pos);
                        }
                    }
                    Err(e) => eprintln!("Line read error: {}", e),
                }
            }
            
            // Process remaining lines
            if !buffer.is_empty() {
                let _ = process_batch_blocking(
                    buffer,
                    &parser,
                    &target_email,
                    &target_domain,
                    &tx,
                );
            }
        });
        
        // Collect results
        let mut found_records = Vec::new();
        while let Some(record) = rx.recv().await {
            found_records.push(record);
        }
        
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
        
        Ok(LocalScanResult {
            file_path: file_path.to_string_lossy().to_string(),
            records_found: found_records,
            stats: LocalScanStats {
                file_path: file_path.to_string_lossy().to_string(),
                bytes_scanned: bytes_read.load(Ordering::Relaxed),
                records_processed: lines_read.load(Ordering::Relaxed),
                emails_found: found_records.len() as u64,
                unique_emails: 0,
                scan_duration: std::time::Duration::default(),
            },
        })
    }
}

fn process_batch_blocking(
    batch: Vec<String>,
    parser: &BreachParser,
    target_email: &Option<String>,
    target_domain: &Option<String>,
    tx: &mpsc::Sender<BreachRecord>,
) -> Result<()> {
    let records: Vec<_> = batch
        .par_iter()
        .filter_map(|line| parser.parse_line(line).transpose())
        .filter(|record| {
            match record {
                Ok(record) => {
                    if let Some(target_email) = target_email {
                        record.email == *target_email
                    } else if let Some(target_domain) = target_domain {
                        record.email.ends_with(&format!("@{}", target_domain))
                    } else {
                        true
                    }
                }
                Err(_) => false,
            }
        })
        .filter_map(|r| r.ok())
        .collect();
    
    // Send to channel (blocking send since we're in a blocking task)
    for record in records {
        if let Err(_) = tx.blocking_send(record) {
            break;
        }
    }
    
    Ok(())
}

pub struct LocalScanResult {
    pub file_path: String,
    pub records_found: Vec<BreachRecord>,
    pub stats: LocalScanStats,
}
