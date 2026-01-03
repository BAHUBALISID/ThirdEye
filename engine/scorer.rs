use crate::mail::models::*;
use std::collections::{HashMap, HashSet};

pub struct RiskScorer {
    weights: ScoreWeights,
    thresholds: RiskThresholds,
}

pub struct ScoreWeights {
    pub plaintext_exposure: f32,
    pub hashed_exposure: f32,
    pub password_reuse: f32,
    pub breach_recency: f32,
    pub source_confidence: f32,
    pub data_completeness: f32,
}

pub struct RiskThresholds {
    pub low: f32,
    pub medium: f32,
    pub high: f32,
    pub critical: f32,
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self {
            weights: ScoreWeights {
                plaintext_exposure: 0.3,
                hashed_exposure: 0.2,
                password_reuse: 0.25,
                breach_recency: 0.15,
                source_confidence: 0.05,
                data_completeness: 0.05,
            },
            thresholds: RiskThresholds {
                low: 0.25,
                medium: 0.5,
                high: 0.75,
                critical: 0.9,
            },
        }
    }
}

impl RiskScorer {
    pub fn score_email(&self, findings: &EmailFinding) -> f32 {
        let mut score = 0.0;
        
        // Check exposure types
        for exposure in &findings.exposures {
            score += match exposure {
                Exposure::PlaintextCredential => self.weights.plaintext_exposure,
                Exposure::HashedCredential(hash_type) => {
                    self.weights.hashed_exposure * self.hash_type_weight(hash_type)
                }
                Exposure::PasswordOnly => self.weights.hashed_exposure * 0.7,
                Exposure::EmailOnly => 0.05,
                Exposure::MetadataOnly => 0.02,
                Exposure::Partial => 0.1,
            };
        }
        
        // Password reuse penalty
        if let Some(credentials) = &findings.raw_credentials {
            if credentials.len() > 1 {
                score += self.weights.password_reuse;
            }
        }
        
        // Breach recency
        if let Some(last_seen) = findings.last_seen {
            let days_ago = chrono::Utc::now()
                .signed_duration_since(last_seen)
                .num_days() as f32;
            
            let recency_factor = (-days_ago / 365.0).exp(); // Exponential decay
            score += self.weights.breach_recency * recency_factor;
        }
        
        // Source confidence
        let avg_confidence: f32 = findings.sources
            .iter()
            .map(|s| s.confidence)
            .sum::<f32>() / findings.sources.len().max(1) as f32;
        
        score += self.weights.source_confidence * avg_confidence;
        
        // Clamp score to [0, 1]
        score.min(1.0).max(0.0)
    }
    
    pub fn score_domain(&self, findings: &DomainFindings) -> f32 {
        if findings.emails.is_empty() {
            return 0.0;
        }
        
        let mut scores: Vec<f32> = findings.emails
            .iter()
            .map(|email| email.risk_score)
            .collect();
        
        // Sort descending
        scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        
        // Domain score is weighted average of top 10% highest risk emails
        let top_count = (findings.emails.len() as f32 * 0.1).ceil() as usize;
        let top_count = top_count.max(1).min(scores.len());
        
        let top_sum: f32 = scores.iter().take(top_count).sum();
        let domain_score = top_sum / top_count as f32;
        
        // Apply password reuse multiplier
        let reuse_factor = if findings.password_reuse.len() > findings.emails.len() / 2 {
            1.2 // Significant reuse
        } else if !findings.password_reuse.is_empty() {
            1.1 // Some reuse
        } else {
            1.0 // No reuse
        };
        
        (domain_score * reuse_factor).min(1.0)
    }
    
    pub fn get_risk_level(&self, score: f32) -> RiskLevel {
        match score {
            s if s >= self.thresholds.critical => RiskLevel::Critical,
            s if s >= self.thresholds.high => RiskLevel::High,
            s if s >= self.thresholds.medium => RiskLevel::Medium,
            s if s >= self.thresholds.low => RiskLevel::Low,
            _ => RiskLevel::Info,
        }
    }
    
    fn hash_type_weight(&self, hash_type: &HashType) -> f32 {
        match hash_type {
            HashType::MD5 => 0.9,    // Easily crackable
            HashType::SHA1 => 0.8,   // Weak
            HashType::SHA256 => 0.6, // Stronger
            HashType::Bcrypt => 0.3, // Very strong
            HashType::NTLM => 0.7,   // Moderate
            HashType::Unknown => 0.5,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Info => "INFO",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}
