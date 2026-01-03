pub mod api;
pub mod local;
pub mod models;
pub mod parser;
pub mod risk;

use api::{ApiManager, HIBPClient, ProxyNovaClient};
use local::LocalScanner;
use models::{EmailFinding, DomainFindings, BreachRecord, BreachSource};
use risk::RiskAssessor;
use crate::output::Formatter;
use anyhow::Result;
use std::path::Path;
use std::collections::{HashMap, HashSet};
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct MailScanner {
    api_manager: ApiManager,
    local_scanner: LocalScanner,
    risk_assessor: RiskAssessor,
    concurrency_limiter: Arc<Semaphore>,
}

impl MailScanner {
    pub fn new() -> Self {
        let mut api_manager = ApiManager::new();
        
        // Add API clients if configured
        if let Ok(hibp_key) = std::env::var("HIBP_API_KEY") {
            api_manager.add_client(Box::new(HIBPClient::new(hibp_key)));
        }
        
        if std::env::var("PROXYNOVA_API_KEY").is_ok() {
            api_manager.add_client(Box::new(ProxyNovaClient::new(None)));
        }
        
        Self {
            api_manager,
            local_scanner: LocalScanner::new(),
            risk_assessor: RiskAssessor::new(),
            concurrency_limiter: Arc::new(Semaphore::new(10)),
        }
    }
    
    pub async fn scan_email(
        &mut self,
        email: &str,
        local_file: Option<&Path>,
        password_reuse: bool,
        limit: u32,
        json_output: bool,
        quiet: bool,
    ) -> Result<()> {
        if !quiet {
            eprintln!("Scanning email: {}", email);
        }
        
        let mut all_records = Vec::new();
        
        // Query APIs
        let api_records = self.api_manager.query_email(email).await?;
        all_records.extend(api_records);
        
        // Scan local file if provided
        if let Some(file_path) = local_file {
            let local_result = self.local_scanner.scan_file(file_path, Some(email), None).await?;
            all_records.extend(local_result.records_found);
            
            if !quiet {
                eprintln!("Local scan: processed {} records", local_result.stats.records_processed);
            }
        }
        
        // Deduplicate records
        let unique_records = self.deduplicate_records(all_records);
        
        // Create email finding
        let finding = self.create_email_finding(email, unique_records, password_reuse)?;
        
        // Output results
        let formatter = Formatter::new(json_output);
        formatter.print_email_finding(&finding, quiet);
        
        Ok(())
    }
    
    pub async fn scan_domain(
        &mut self,
        domain: &str,
        local_file: Option<&Path>,
        limit: u32,
        json_output: bool,
        quiet: bool,
    ) -> Result<()> {
        if !quiet {
            eprintln!("Scanning domain: {}", domain);
        }
        
        let mut all_records = Vec::new();
        
        // Query APIs for domain
        let api_records = self.api_manager.query_domain(domain).await?;
        all_records.extend(api_records);
        
        // Scan local file for domain
        if let Some(file_path) = local_file {
            let local_result = self.local_scanner.scan_file(file_path, None, Some(domain)).await?;
            all_records.extend(local_result.records_found);
            
            if !quiet {
                eprintln!("Local scan: found {} records for domain", local_result.records_found.len());
            }
        }
        
        // Group records by email
        let mut email_map: HashMap<String, Vec<BreachRecord>> = HashMap::new();
        for record in all_records {
            email_map.entry(record.email.clone()).or_default().push(record);
        }
        
        // Create findings for each email
        let mut email_findings = Vec::new();
        for (email, records) in email_map {
            if records.len() > limit as usize {
                continue; // Skip if too many results
            }
            
            let unique_records = self.deduplicate_records(records);
            if let Ok(finding) = self.create_email_finding(&email, unique_records, true) {
                email_findings.push(finding);
            }
        }
        
        // Create domain findings
        let domain_findings = self.create_domain_findings(domain, email_findings)?;
        
        // Output results
        let formatter = Formatter::new(json_output);
        formatter.print_domain_findings(&domain_findings, quiet);
        
        Ok(())
    }
    
    // Simplified versions for engine integration
    pub async fn scan_email_simple(&mut self, email: &str) -> Result<Vec<EmailFinding>> {
        let records = self.api_manager.query_email(email).await?;
        let unique_records = self.deduplicate_records(records);
        let finding = self.create_email_finding(email, unique_records, false)?;
        Ok(vec![finding])
    }
    
    pub async fn scan_domain_simple(&mut self, domain: &str) -> Result<DomainFindings> {
        let records = self.api_manager.query_domain(domain).await?;
        let mut email_map: HashMap<String, Vec<BreachRecord>> = HashMap::new();
        
        for record in records {
            email_map.entry(record.email.clone()).or_default().push(record);
        }
        
        let mut email_findings = Vec::new();
        for (email, records) in email_map {
            let unique_records = self.deduplicate_records(records);
            if let Ok(finding) = self.create_email_finding(&email, unique_records, true) {
                email_findings.push(finding);
            }
        }
        
        self.create_domain_findings(domain, email_findings)
    }
    
    fn deduplicate_records(&self, records: Vec<BreachRecord>) -> Vec<BreachRecord> {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();
        
        for record in records {
            let key = format!("{}:{:?}:{:?}", 
                record.email, 
                record.password, 
                record.hash);
            
            if !seen.contains(&key) {
                seen.insert(key);
                unique.push(record);
            }
        }
        
        unique
    }
    
    fn create_email_finding(
        &self,
        email: &str,
        records: Vec<BreachRecord>,
        analyze_reuse: bool,
    ) -> Result<EmailFinding> {
        let mut finding = EmailFinding {
            email: email.to_string(),
            sources: Vec::new(),
            exposures: Vec::new(),
            first_seen: None,
            last_seen: None,
            password_hashes: Vec::new(),
            raw_credentials: if analyze_reuse { Some(Vec::new()) } else { None },
            risk_score: 0.0,
            metadata: HashMap::new(),
        };
        
        // Process each breach record
        for record in records {
            // Add source
            finding.sources.push(BreachSource {
                name: record.source.clone(),
                api_source: true,
                local_file: None,
                breach_date: record.breach_date,
                record_count: 1,
                confidence: 0.8,
            });
            
            // Add exposure type
            if record.password.is_some() {
                finding.exposures.push(models::Exposure::PlaintextCredential);
                
                if analyze_reuse {
                    if let Some(passwords) = &mut finding.raw_credentials {
                        if let Some(pwd) = &record.password {
                            passwords.push(pwd.clone());
                        }
                    }
                }
            } else if record.hash.is_some() {
                finding.exposures.push(models::Exposure::HashedCredential(
                    record.hash_type.clone().unwrap_or(models::HashType::Unknown)
                ));
            } else {
                finding.exposures.push(models::Exposure::EmailOnly);
            }
            
            // Update timestamps
            if let Some(breach_date) = record.breach_date {
                if finding.first_seen.is_none() || breach_date < finding.first_seen.unwrap() {
                    finding.first_seen = Some(breach_date);
                }
                if finding.last_seen.is_none() || breach_date > finding.last_seen.unwrap() {
                    finding.last_seen = Some(breach_date);
                }
            }
            
            // Add password hashes
            if let Some(hash) = record.hash {
                finding.password_hashes.push(models::PasswordHash {
                    hash,
                    hash_type: record.hash_type.clone().unwrap_or(models::HashType::Unknown),
                    salt: None,
                    source: record.source.clone(),
                });
            }
            
            // Add metadata
            finding.metadata.extend(record.additional_data);
        }
        
        // Calculate risk score
        finding.risk_score = self.risk_assessor.assess_email_risk(&finding);
        
        Ok(finding)
    }
    
    fn create_domain_findings(
        &self,
        domain: &str,
        email_findings: Vec<EmailFinding>,
    ) -> Result<DomainFindings> {
        let mut password_map: HashMap<String, Vec<String>> = HashMap::new();
        
        // Collect password reuse data
        for finding in &email_findings {
            if let Some(passwords) = &finding.raw_credentials {
                for password in passwords {
                    password_map
                        .entry(password.clone())
                        .or_default()
                        .push(finding.email.clone());
                }
            }
        }
        
        // Filter to only passwords used by multiple accounts
        let password_reuse: HashMap<_, _> = password_map
            .into_iter()
            .filter(|(_, emails)| emails.len() > 1)
            .collect();
        
        let unique_passwords = password_reuse.len();
        
        // Calculate domain risk score
        let domain_risk = self.risk_assessor.assess_domain_risk(&email_findings);
        
        Ok(DomainFindings {
            domain: domain.to_string(),
            emails: email_findings,
            password_reuse,
            unique_passwords,
            risk_score: domain_risk,
            employee_count_estimate: None,
        })
    }
}
