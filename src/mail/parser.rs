use crate::mail::models::{BreachRecord, HashType};
use regex::Regex;
use std::collections::HashMap;
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha256Digest};

pub struct BreachParser {
    email_regex: Regex,
    md5_regex: Regex,
    sha1_regex: Regex,
    sha256_regex: Regex,
}

impl BreachParser {
    pub fn new() -> Self {
        Self {
            email_regex: Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap(),
            md5_regex: Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
            sha1_regex: Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
            sha256_regex: Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(),
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
        // Format: email:password
        // Format: email:hash
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let email = parts[0].trim().to_lowercase();
        let credential = parts[1].trim();
        
        if !self.is_valid_email(&email) {
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
            additional_data: HashMap::from([
                ("format".to_string(), "email:password".to_string()),
            ]),
        })
    }
    
    fn parse_json_line(&self, line: &str) -> Option<BreachRecord> {
        // Try to parse as JSON
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
                .map(|d| DateTime::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0).unwrap(), Utc));
            
            if let Some(email) = email {
                return Some(BreachRecord {
                    email,
                    password,
                    hash,
                    hash_type,
                    source: "LocalJSON".to_string(),
                    breach_date,
                    additional_data: HashMap::new(),
                });
            }
        }
        
        None
    }
    
    fn parse_hash_format(&self, line: &str) -> Option<BreachRecord> {
        // Check if line contains an email
        if let Some(email_match) = self.email_regex.find(line) {
            let email = email_match.as_str().to_lowercase();
            
            // Look for hash in the line
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
                        additional_data: HashMap::new(),
                    });
                } else if self.sha1_regex.is_match(candidate) {
                    return Some(BreachRecord {
                        email,
                        password: None,
                        hash: Some(candidate.to_string()),
                        hash_type: Some(HashType::SHA1),
                        source: "LocalHashFile".to_string(),
                        breach_date: None,
                        additional_data: HashMap::new(),
                    });
                } else if self.sha256_regex.is_match(candidate) {
                    return Some(BreachRecord {
                        email,
                        password: None,
                        hash: Some(candidate.to_string()),
                        hash_type: Some(HashType::SHA256),
                        source: "LocalHashFile".to_string(),
                        breach_date: None,
                        additional_data: HashMap::new(),
                    });
                }
            }
        }
        
        None
    }
    
    pub fn compute_hash(&self, input: &str, hash_type: HashType) -> String {
        match hash_type {
            HashType::MD5 => {
                let digest = md5::compute(input);
                format!("{:x}", digest)
            }
            HashType::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.update(input.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            HashType::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(input.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            _ => input.to_string(),
        }
    }
    
    fn is_valid_email(&self, email: &str) -> bool {
        self.email_regex.is_match(email)
    }
}
