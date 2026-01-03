use crate::engine::ScanResult;
use crate::engine::scorer::RiskLevel;  // Fixed import
use serde_json::json;

pub struct Formatter {
    json_output: bool,
}

impl Formatter {
    pub fn new(json_output: bool) -> Self {
        Self { json_output }
    }
    
    pub fn print_email_finding(&self, finding: &crate::mail::models::EmailFinding, quiet: bool) {
        if self.json_output {
            self.print_email_json(finding);
        } else {
            self.print_email_text(finding, quiet);
        }
    }
    
    pub fn print_domain_findings(&self, findings: &crate::mail::models::DomainFindings, quiet: bool) {
        if self.json_output {
            self.print_domain_json(findings);
        } else {
            self.print_domain_text(findings, quiet);
        }
    }
    
    pub fn print_scan_results(&self, results: &ScanResult) {
        if self.json_output {
            self.print_scan_json(results);
        } else {
            self.print_scan_text(results);
        }
    }
    
    fn print_email_text(&self, finding: &crate::mail::models::EmailFinding, quiet: bool) {
        if quiet {
            println!("{}", finding.email);
            return;
        }
        
        let risk_level = RiskLevel::from_score(finding.risk_score);
        
        println!("┌─────────────────────────────────────────────────────┐");
        println!("│ EMAIL: {}", pad_right(&finding.email, 42));
        println!("├─────────────────────────────────────────────────────┤");
        println!("│ Sources: {}", pad_right(&format_sources(&finding.sources), 40));
        println!("│ Exposures: {}", pad_right(&format_exposures(&finding.exposures), 38));
        
        if let Some(first_seen) = finding.first_seen {
            println!("│ First seen: {}", first_seen.format("%Y-%m-%d"));
        }
        
        if let Some(last_seen) = finding.last_seen {
            println!("│ Last seen: {}", last_seen.format("%Y-%m-%d"));
        }
        
        println!("│ Risk: {} ({:.0}%)", risk_level.as_str(), finding.risk_score * 100.0);
        
        if let Some(passwords) = &finding.raw_credentials {
            if !passwords.is_empty() {
                println!("├─────────────────────────────────────────────────────┤");
                println!("│ Exposed Passwords: {}", passwords.len());
                for (i, pwd) in passwords.iter().enumerate().take(3) {
                    println!("│   {}. {}", i + 1, mask_password(pwd));
                }
                if passwords.len() > 3 {
                    println!("│   ... and {} more", passwords.len() - 3);
                }
            }
        }
        
        println!("└─────────────────────────────────────────────────────┘");
    }
    
    fn print_domain_text(&self, findings: &crate::mail::models::DomainFindings, quiet: bool) {
        if quiet {
            for email in &findings.emails {
                println!("{}", email.email);
            }
            return;
        }
        
        let risk_level = RiskLevel::from_score(findings.risk_score);
        
        println!("┌─────────────────────────────────────────────────────┐");
        println!("│ DOMAIN: {}", pad_right(&findings.domain, 42));
        println!("├─────────────────────────────────────────────────────┤");
        println!("│ Exposed emails: {}", findings.emails.len());
        println!("│ Unique passwords: {}", findings.unique_passwords);
        
        if !findings.password_reuse.is_empty() {
            println!("│ Password reuse groups: {}", findings.password_reuse.len());
            let top_reuse = findings.password_reuse.iter()
                .max_by_key(|(_, emails)| emails.len());
            
            if let Some((password, emails)) = top_reuse {
                println!("│ Most reused: '{}' across {} accounts", 
                    mask_password(password), emails.len());
            }
        }
        
        println!("│ Domain risk: {} ({:.0}%)", risk_level.as_str(), findings.risk_score * 100.0);
        
        if !findings.emails.is_empty() {
            println!("├─────────────────────────────────────────────────────┤");
            println!("│ Top exposed emails:");
            
            let mut sorted_emails: Vec<_> = findings.emails.iter()
                .collect();
            sorted_emails.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
            
            for (i, email) in sorted_emails.iter().take(5).enumerate() {
                let risk = RiskLevel::from_score(email.risk_score);
                println!("│   {}. {} [{}]", i + 1, email.email, risk.as_str());
            }
            
            if findings.emails.len() > 5 {
                println!("│   ... and {} more", findings.emails.len() - 5);
            }
        }
        
        println!("└─────────────────────────────────────────────────────┘");
    }
    
    fn print_scan_text(&self, results: &ScanResult) {
        let overall_risk = RiskLevel::from_score(results.overall_risk);
        
        println!("\nThirdEye Scan Results");
        println!("=====================");
        println!("Target: {}", results.target);
        println!("Timestamp: {}", results.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("Overall risk: {} ({:.1}%)", overall_risk.as_str(), results.overall_risk * 100.0);
        println!();
        
        // Mail findings
        if let Some(mail_findings) = &results.mail_findings {
            println!("[MAIL]");
            for finding in mail_findings {
                let risk = RiskLevel::from_score(finding.risk_score);
                println!("  {} - {} ({:.0}%)", finding.email, risk.as_str(), finding.risk_score * 100.0);
            }
            println!();
        }
        
        if let Some(domain_findings) = &results.domain_findings {
            println!("[DOMAIN] {} emails exposed", domain_findings.emails.len());
            println!();
        }
        
        // Recon findings
        if let Some(recon_data) = &results.recon_data {
            println!("[RECON]");
            if !recon_data.dns_records.is_empty() {
                println!("  DNS Records: {}", recon_data.dns_records.len());
            }
            if recon_data.whois_info.is_some() {
                println!("  WHOIS information available");
            }
            if !recon_data.certificates.is_empty() {
                println!("  Certificates: {}", recon_data.certificates.len());
            }
            println!();
        }
        
        // Web findings
        if let Some(web_data) = &results.web_data {
            println!("[WEB]");
            if !web_data.technologies.is_empty() {
                println!("  Technologies detected: {}", web_data.technologies.len());
                for tech in &web_data.technologies[..web_data.technologies.len().min(3)] {
                    println!("    - {} ({}%)", tech.name, tech.confidence);
                }
            }
            if !web_data.vulnerabilities.is_empty() {
                println!("  Vulnerabilities: {}", web_data.vulnerabilities.len());
                for vuln in &web_data.vulnerabilities {
                    println!("    - {}: {}", vuln.severity, vuln.id);
                }
            }
        }
    }
    
    fn print_email_json(&self, finding: &crate::mail::models::EmailFinding) {
        let json = json!({
            "type": "email_finding",
            "email": finding.email,
            "sources": finding.sources,
            "exposures": finding.exposures,
            "first_seen": finding.first_seen.map(|d| d.to_rfc3339()),
            "last_seen": finding.last_seen.map(|d| d.to_rfc3339()),
            "risk_score": finding.risk_score,
            "risk_level": RiskLevel::from_score(finding.risk_score).as_str(),
            "metadata": finding.metadata,
        });
        
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
    
    fn print_domain_json(&self, findings: &crate::mail::models::DomainFindings) {
        let json = json!({
            "type": "domain_findings",
            "domain": findings.domain,
            "email_count": findings.emails.len(),
            "unique_passwords": findings.unique_passwords,
            "password_reuse_groups": findings.password_reuse.len(),
            "risk_score": findings.risk_score,
            "risk_level": RiskLevel::from_score(findings.risk_score).as_str(),
            "emails": findings.emails.iter().map(|e| {
                json!({
                    "email": e.email,
                    "risk_score": e.risk_score,
                })
            }).collect::<Vec<_>>(),
        });
        
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
    
    fn print_scan_json(&self, results: &ScanResult) {
        let json = json!({
            "scan": {
                "target": results.target,
                "timestamp": results.timestamp.to_rfc3339(),
                "overall_risk": results.overall_risk,
                "risk_level": RiskLevel::from_score(results.overall_risk).as_str(),
                "modules": {
                    "mail": results.mail_findings.is_some(),
                    "recon": results.recon_data.is_some(),
                    "web": results.web_data.is_some(),
                }
            }
        });
        
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

fn pad_right(text: &str, width: usize) -> String {
    if text.len() >= width {
        text.to_string()
    } else {
        format!("{}{}", text, " ".repeat(width - text.len()))
    }
}

fn format_sources(sources: &[crate::mail::models::BreachSource]) -> String {
    let names: Vec<_> = sources.iter().map(|s| s.name.clone()).collect();
    names.join(", ")
}

fn format_exposures(exposures: &[crate::mail::models::Exposure]) -> String {
    exposures.iter()
        .map(|e| match e {
            crate::mail::models::Exposure::PlaintextCredential => "Plaintext",
            crate::mail::models::Exposure::HashedCredential(h) => 
                match h {
                    crate::mail::models::HashType::MD5 => "MD5",
                    crate::mail::models::HashType::SHA1 => "SHA1",
                    crate::mail::models::HashType::SHA256 => "SHA256",
                    crate::mail::models::HashType::Bcrypt => "Bcrypt",
                    crate::mail::models::HashType::NTLM => "NTLM",
                    crate::mail::models::HashType::Unknown => "Unknown Hash",
                },
            crate::mail::models::Exposure::PasswordOnly => "Password Only",
            crate::mail::models::Exposure::EmailOnly => "Email Only",
            crate::mail::models::Exposure::MetadataOnly => "Metadata",
            crate::mail::models::Exposure::Partial => "Partial",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn mask_password(password: &str) -> String {
    if password.len() <= 4 {
        "*".repeat(password.len())
    } else {
        format!("{}***{}", 
            &password[..2], 
            &password[password.len()-2..]
        )
    }
}
