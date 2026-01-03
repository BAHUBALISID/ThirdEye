use crate::engine::ScanResult;
use crate::mail::models::EmailFinding;

pub struct Correlator {
    patterns: Vec<CorrelationPattern>,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                CorrelationPattern::PasswordReuse,
                CorrelationPattern::DomainSubdomain,
                CorrelationPattern::TechnologyStack,
                CorrelationPattern::Temporal,
            ],
        }
    }
    
    pub fn correlate(&self, results: &ScanResult) -> CorrelationResult {
        let mut findings = Vec::new();
        
        // Check for password reuse across findings
        if let Some(mail_findings) = &results.mail_findings {
            if let Some(password_reuse) = self.detect_password_reuse(mail_findings) {
                findings.push(password_reuse);
            }
        }
        
        // Correlate mail findings with web technologies
        if let (Some(mail_findings), Some(web_data)) = (&results.mail_findings, &results.web_data) {
            if let Some(tech_correlation) = self.correlate_technologies(mail_findings, web_data) {
                findings.push(tech_correlation);
            }
        }
        
        // Correlate timestamps
        if let Some(temporal) = self.detect_temporal_patterns(results) {
            findings.push(temporal);
        }
        
        let confidence = self.calculate_confidence(&findings);
        
        CorrelationResult {
            target: results.target.clone(),
            findings,
            confidence,
        }
    }
    
    fn detect_password_reuse(&self, email_findings: &[EmailFinding]) -> Option<CorrelationFinding> {
        let mut password_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        
        for finding in email_findings {
            if let Some(passwords) = &finding.raw_credentials {
                for password in passwords {
                    password_map
                        .entry(password.clone())
                        .or_default()
                        .push(finding.email.clone());
                }
            }
        }
        
        // Find passwords used by multiple accounts
        let reuse_groups: Vec<_> = password_map
            .into_iter()
            .filter(|(_, emails)| emails.len() > 1)
            .collect();
        
        if !reuse_groups.is_empty() {
            let evidence: Vec<String> = reuse_groups.iter()
                .map(|(password, emails)| format!("Password '{}' used by: {}", password, emails.join(", ")))
                .collect();
            
            Some(CorrelationFinding {
                pattern: "PASSWORD_REUSE".to_string(),
                description: format!("Password reuse detected across {} accounts", reuse_groups.len()),
                severity: "MEDIUM".to_string(),
                evidence,
            })
        } else {
            None
        }
    }
    
    fn correlate_technologies(
        &self,
        email_findings: &[EmailFinding],
        web_data: &crate::engine::WebData,
    ) -> Option<CorrelationFinding> {
        // Extract technologies from web scan
        let web_techs: std::collections::HashSet<_> = web_data.technologies
            .iter()
            .map(|t| t.name.to_lowercase())
            .collect();
        
        // Look for technology mentions in breach data
        let mut tech_matches = Vec::new();
        
        for finding in email_findings {
            for tech in &web_techs {
                if finding.email.contains(tech) || 
                   finding.metadata.values().any(|v| v.contains(tech)) {
                    tech_matches.push(format!("Email {} contains technology reference: {}", finding.email, tech));
                }
            }
        }
        
        if !tech_matches.is_empty() {
            Some(CorrelationFinding {
                pattern: "TECHNOLOGY_CORRELATION".to_string(),
                description: format!("Breach data correlates with web technologies: {} matches", tech_matches.len()),
                severity: "LOW".to_string(),
                evidence: tech_matches,
            })
        } else {
            None
        }
    }
    
    fn detect_temporal_patterns(&self, results: &ScanResult) -> Option<CorrelationFinding> {
        // Check if breaches align with certificate expiration
        if let (Some(mail_findings), Some(recon_data)) = (&results.mail_findings, &results.recon_data) {
            let mut temporal_matches = Vec::new();
            
            for finding in mail_findings {
                if let Some(last_seen) = finding.last_seen {
                    for cert in &recon_data.certificates {
                        // Parse certificate dates
                        if let (Ok(cert_from), Ok(cert_to)) = (
                            chrono::NaiveDate::parse_from_str(&cert.valid_from, "%Y-%m-%d"),
                            chrono::NaiveDate::parse_from_str(&cert.valid_to, "%Y-%m-%d"),
                        ) {
                            let cert_from_dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                                cert_from.and_hms_opt(0, 0, 0).unwrap(), chrono::Utc);
                            let cert_to_dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                                cert_to.and_hms_opt(0, 0, 0).unwrap(), chrono::Utc);
                            
                            if last_seen >= cert_from_dt && last_seen <= cert_to_dt {
                                temporal_matches.push(format!(
                                    "Email {} breached during certificate validity ({}-{})",
                                    finding.email,
                                    cert.valid_from,
                                    cert.valid_to
                                ));
                            }
                        }
                    }
                }
            }
            
            if !temporal_matches.is_empty() {
                return Some(CorrelationFinding {
                    pattern: "TEMPORAL_CORRELATION".to_string(),
                    description: "Breach dates align with certificate validity periods".to_string(),
                    severity: "LOW".to_string(),
                    evidence: temporal_matches,
                });
            }
        }
        
        None
    }
    
    fn calculate_confidence(&self, findings: &[CorrelationFinding]) -> f32 {
        if findings.is_empty() {
            return 0.0;
        }
        
        let total_severity: f32 = findings.iter()
            .map(|f| match f.severity.as_str() {
                "HIGH" => 0.9,
                "MEDIUM" => 0.6,
                "LOW" => 0.3,
                _ => 0.1,
            })
            .sum();
        
        total_severity / findings.len() as f32
    }
}

pub struct CorrelationResult {
    pub target: String,
    pub findings: Vec<CorrelationFinding>,
    pub confidence: f32,
}

#[derive(Clone)]  // Added Clone
pub struct CorrelationFinding {
    pub pattern: String,
    pub description: String,
    pub severity: String,
    pub evidence: Vec<String>,  // Changed to Vec<String>
}

enum CorrelationPattern {
    PasswordReuse,
    DomainSubdomain,
    TechnologyStack,
    Temporal,
}
