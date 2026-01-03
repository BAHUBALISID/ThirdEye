use crate::mail::models::{EmailFinding, Exposure, HashType};
use crate::engine::scorer::RiskScorer;
use std::collections::{HashMap, HashSet};

pub struct RiskAssessor {
    scorer: RiskScorer,
    domain_risk_factors: DomainRiskFactors,
}

pub struct DomainRiskFactors {
    pub email_count_weight: f32,
    pub password_reuse_weight: f32,
    pub executive_emails_weight: f32,
    pub recent_breaches_weight: f32,
}

impl Default for RiskAssessor {
    fn default() -> Self {
        Self {
            scorer: RiskScorer::default(),
            domain_risk_factors: DomainRiskFactors {
                email_count_weight: 0.3,
                password_reuse_weight: 0.4,
                executive_emails_weight: 0.2,
                recent_breaches_weight: 0.1,
            },
        }
    }
}

impl RiskAssessor {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn assess_email_risk(&self, finding: &EmailFinding) -> f32 {
        self.scorer.score_email(finding)
    }
    
    pub fn assess_domain_risk(&self, email_findings: &[EmailFinding]) -> f32 {
        if email_findings.is_empty() {
            return 0.0;
        }
        
        let mut risk_score = 0.0;
        
        // Factor 1: Number of exposed emails
        let email_count = email_findings.len();
        let email_count_factor = (email_count as f32).log10() / 3.0; // Normalize
        risk_score += email_count_factor * self.domain_risk_factors.email_count_weight;
        
        // Factor 2: Password reuse
        let reuse_score = self.calculate_password_reuse_score(email_findings);
        risk_score += reuse_score * self.domain_risk_factors.password_reuse_weight;
        
        // Factor 3: Executive/sensitive emails
        let executive_score = self.calculate_executive_risk_score(email_findings);
        risk_score += executive_score * self.domain_risk_factors.executive_emails_weight;
        
        // Factor 4: Recency of breaches
        let recency_score = self.calculate_breach_recency_score(email_findings);
        risk_score += recency_score * self.domain_risk_factors.recent_breaches_weight;
        
        risk_score.min(1.0).max(0.0)
    }
    
    fn calculate_password_reuse_score(&self, findings: &[EmailFinding]) -> f32 {
        let mut password_counts: HashMap<String, usize> = HashMap::new();
        
        for finding in findings {
            if let Some(passwords) = &finding.raw_credentials {
                for password in passwords {
                    *password_counts.entry(password.clone()).or_default() += 1;
                }
            }
        }
        
        if password_counts.is_empty() {
            return 0.0;
        }
        
        let total_usage: usize = password_counts.values().sum();
        let unique_passwords = password_counts.len();
        let avg_reuse = total_usage as f32 / unique_passwords as f32;
        
        // Score based on average reuse rate
        (avg_reuse - 1.0).max(0.0) / 4.0 // Normalize to [0, 1]
    }
    
    fn calculate_executive_risk_score(&self, findings: &[EmailFinding]) -> f32 {
        let executive_patterns = [
            "ceo", "cfo", "cto", "cio", "coo",
            "director", "manager", "admin", "administrator",
            "root", "support", "helpdesk", "it",
        ];
        
        let mut executive_count = 0;
        
        for finding in findings {
            let email_local = finding.email.split('@').next().unwrap_or("");
            
            for pattern in &executive_patterns {
                if email_local.contains(pattern) {
                    executive_count += 1;
                    break;
                }
            }
        }
        
        if findings.is_empty() {
            return 0.0;
        }
        
        executive_count as f32 / findings.len() as f32
    }
    
    fn calculate_breach_recency_score(&self, findings: &[EmailFinding]) -> f32 {
        let mut most_recent = None;
        
        for finding in findings {
            if let Some(last_seen) = finding.last_seen {
                if most_recent.is_none() || last_seen > most_recent.unwrap() {
                    most_recent = Some(last_seen);
                }
            }
        }
        
        if let Some(recent) = most_recent {
            let days_ago = chrono::Utc::now()
                .signed_duration_since(recent)
                .num_days() as f32;
            
            // Recent breaches (within 90 days) get higher score
            if days_ago <= 90.0 {
                1.0 - (days_ago / 90.0)
            } else {
                0.1 // Very old breaches
            }
        } else {
            0.0
        }
    }
    
    pub fn get_risk_recommendations(&self, finding: &EmailFinding) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Check for plaintext exposures
        if finding.exposures.iter().any(|e| matches!(e, Exposure::PlaintextCredential)) {
            recommendations.push("Change password immediately - plaintext credentials exposed".to_string());
        }
        
        // Check for weak hashes
        let weak_hashes: HashSet<HashType> = [HashType::MD5, HashType::SHA1].into_iter().collect();
        if finding.password_hashes.iter().any(|h| weak_hashes.contains(&h.hash_type)) {
            recommendations.push("Password uses weak hash algorithm - consider password rotation".to_string());
        }
        
        // Check for password reuse
        if let Some(passwords) = &finding.raw_credentials {
            if passwords.len() > 1 {
                recommendations.push("Password reused across multiple breaches - use unique passwords".to_string());
            }
        }
        
        // Check breach recency
        if let Some(last_seen) = finding.last_seen {
            let days_ago = chrono::Utc::now()
                .signed_duration_since(last_seen)
                .num_days();
            
            if days_ago <= 180 {
                recommendations.push("Recent breach detected - monitor for suspicious activity".to_string());
            }
        }
        
        if recommendations.is_empty() {
            recommendations.push("Monitor for credential stuffing attacks".to_string());
        }
        
        recommendations
    }
}

