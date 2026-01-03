use crate::engine::ReconData;
use anyhow::Result;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use whois_rust::{Whois, WhoIsLookupOptions};

pub struct ReconScanner {
    dns_resolver: TokioAsyncResolver,
    whois_client: Whois,
}

impl ReconScanner {
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ).expect("Failed to create DNS resolver");
        
        let whois = Whois::from_string_safe(include_str!("../../assets/servers.json"))
            .expect("Failed to create WHOIS client");
        
        Self {
            dns_resolver: resolver,
            whois_client: whois,
        }
    }
    
    pub async fn scan(&self, target: &str) -> Result<ReconData> {
        let mut recon_data = ReconData {
            dns_records: Vec::new(),
            whois_info: None,
            certificates: Vec::new(),
        };
        
        // DNS resolution
        if let Ok(dns_records) = self.scan_dns(target).await {
            recon_data.dns_records = dns_records;
        }
        
        // WHOIS lookup
        if let Ok(whois_info) = self.scan_whois(target).await {
            recon_data.whois_info = Some(whois_info);
        }
        
        // Certificate transparency
        if let Ok(certificates) = self.scan_certificates(target).await {
            recon_data.certificates = certificates;
        }
        
        Ok(recon_data)
    }
    
    async fn scan_dns(&self, target: &str) -> Result<Vec<crate::engine::DnsRecord>> {
        let mut records = Vec::new();
        
        // A records
        if let Ok(response) = self.dns_resolver.lookup_ip(target).await {
            for ip in response.iter() {
                records.push(crate::engine::DnsRecord {
                    record_type: "A".to_string(),
                    value: ip.to_string(),
                    ttl: 300,
                });
            }
        }
        
        // MX records
        if let Ok(response) = self.dns_resolver.mx_lookup(target).await {
            for mx in response.iter() {
                records.push(crate::engine::DnsRecord {
                    record_type: "MX".to_string(),
                    value: format!("{} {}", mx.preference(), mx.exchange()),
                    ttl: 300,
                });
            }
        }
        
        // TXT records
        if let Ok(response) = self.dns_resolver.txt_lookup(target).await {
            for txt in response.iter() {
                records.push(crate::engine::DnsRecord {
                    record_type: "TXT".to_string(),
                    value: txt.to_string(),
                    ttl: 300,
                });
            }
        }
        
        Ok(records)
    }
    
    async fn scan_whois(&self, target: &str) -> Result<crate::engine::WhoisInfo> {
        let options = WhoIsLookupOptions::from_string(target)
            .expect("Failed to create WHOIS options");
        
        let result = self.whois_client.lookup_async(options).await?;
        
        Ok(crate::engine::WhoisInfo {
            registrar: extract_whois_field(&result, "Registrar"),
            creation_date: extract_whois_field(&result, "Creation Date"),
            expiration_date: extract_whois_field(&result, "Registry Expiry Date"),
            name_servers: extract_whois_list(&result, "Name Server"),
        })
    }
    
    async fn scan_certificates(&self, target: &str) -> Result<Vec<crate::engine::CertificateInfo>> {
        let mut certificates = Vec::new();
        
        // Use crt.sh API for certificate transparency
        let url = format!("https://crt.sh/json?q={}&output=json", target);
        let client = reqwest::Client::new();
        
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(certs) = response.json::<Vec<serde_json::Value>>().await {
                for cert in certs {
                    certificates.push(crate::engine::CertificateInfo {
                        issuer: cert.get("issuer_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        valid_from: cert.get("not_before")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        valid_to: cert.get("not_after")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        sans: cert.get("name_value")
                            .and_then(|v| v.as_str())
                            .map(|s| s.split('\n').map(|s| s.to_string()).collect())
                            .unwrap_or_default(),
                    });
                }
            }
        }
        
        Ok(certificates)
    }
}

fn extract_whois_field(whois_text: &str, field: &str) -> Option<String> {
    for line in whois_text.lines() {
        if line.starts_with(field) {
            return line.splitn(2, ':')
                .nth(1)
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn extract_whois_list(whois_text: &str, field: &str) -> Vec<String> {
    let mut servers = Vec::new();
    
    for line in whois_text.lines() {
        if line.starts_with(field) {
            if let Some(server) = line.splitn(2, ':')
                .nth(1)
                .map(|s| s.trim().to_string()) {
                servers.push(server);
            }
        }
    }
    
    servers
}
