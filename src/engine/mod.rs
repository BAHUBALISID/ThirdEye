pub mod runner;
pub mod scorer;
pub mod correlator;

use crate::mail::models::{EmailFinding, DomainFindings};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub target: String,
    pub mail_findings: Option<Vec<EmailFinding>>,
    pub domain_findings: Option<DomainFindings>,
    pub recon_data: Option<ReconData>,
    pub web_data: Option<WebData>,
    pub overall_risk: f32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ReconData {
    pub dns_records: Vec<DnsRecord>,
    pub whois_info: Option<WhoisInfo>,
    pub certificates: Vec<CertificateInfo>,
}

#[derive(Debug, Serialize)]
pub struct WebData {
    pub technologies: Vec<Technology>,
    pub headers: Vec<Header>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Serialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Serialize)]
pub struct WhoisInfo {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CertificateInfo {
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub sans: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: String,
    pub description: String,
}
