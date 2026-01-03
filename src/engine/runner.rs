use crate::engine::scorer::RiskScorer;
use crate::engine::correlator::Correlator;
use crate::mail::MailScanner;
use crate::recon::ReconScanner;
use crate::web::WebScanner;
use crate::output::Formatter;
use anyhow::Result;

pub struct ScanRunner {
    mail_scanner: MailScanner,
    recon_scanner: ReconScanner,
    web_scanner: WebScanner,
    scorer: RiskScorer,
    correlator: Correlator,
}

impl ScanRunner {
    pub fn new() -> Self {
        Self {
            mail_scanner: MailScanner::new(),
            recon_scanner: ReconScanner::new(),
            web_scanner: WebScanner::new(),
            scorer: RiskScorer::default(),
            correlator: Correlator::new(),
        }
    }
    
    pub async fn scan(&self, target: &str, recon: bool, web: bool, mail: bool) -> Result<()> {
        let mut results = crate::engine::ScanResult {
            target: target.to_string(),
            mail_findings: None,
            domain_findings: None,
            recon_data: None,
            web_data: None,
            overall_risk: 0.0,
            timestamp: chrono::Utc::now(),
        };
        
        // Run mail scan if requested
        if mail {
            if target.contains('@') {
                if let Ok(email_findings) = self.mail_scanner.scan_email_simple(target).await {
                    results.mail_findings = Some(email_findings);
                }
            } else {
                if let Ok(domain_findings) = self.mail_scanner.scan_domain_simple(target).await {
                    results.domain_findings = Some(domain_findings);
                }
            }
        }
        
        // Run recon scan if requested
        if recon {
            if let Ok(recon_data) = self.recon_scanner.scan(target).await {
                results.recon_data = Some(recon_data);
            }
        }
        
        // Run web scan if requested
        if web {
            if let Ok(web_data) = self.web_scanner.scan(target).await {
                results.web_data = Some(web_data);
            }
        }
        
        // Calculate overall risk score
        results.overall_risk = self.scorer.calculate_overall_risk(&results);
        
        // Output results
        let formatter = Formatter::new(false); // Default to text output
        formatter.print_scan_results(&results);
        
        // Set exit code based on findings
        if results.overall_risk > 0.1 || 
           results.mail_findings.as_ref().map_or(false, |v| !v.is_empty()) ||
           results.recon_data.is_some() ||
           results.web_data.is_some() {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }
}
