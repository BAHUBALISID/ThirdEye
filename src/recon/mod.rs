use crate::engine::ReconData;
use anyhow::Result;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
// Remove whois_rust for now - use simpler implementation

pub struct ReconScanner {
    dns_resolver: TokioAsyncResolver,
}

impl ReconScanner {
    pub fn new() -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ).expect("Failed to create DNS resolver");
        
        Self {
            dns_resolver: resolver,
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
        
        // WHOIS lookup - simplified for now
        if let Ok(whois_info) = self.scan_whois_simple(target).await {
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
    
    async fn scan_whois_simple(&self, target: &str) -> Result<crate::engine::WhoisInfo> {
        // Simple WHOIS implementation using external service
        let client = reqwest::Client::new();
        let url = format!("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=demo&domainName={}&outputFormat=JSON", target);
        
        let response = client.get(&url).send().await;
        
        match response {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    let whois_info = crate::engine::WhoisInfo {
                        registrar: json.pointer("/WhoisRecord/registrarName")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        creation_date: json.pointer("/WhoisRecord/createdDate")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        expiration_date: json.pointer("/WhoisRecord/expiresDate")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        name_servers: json.pointer("/WhoisRecord/nameServers/hostNames")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect())
                            .unwrap_or_default(),
                    };
                    Ok(whois_info)
                } else {
                    Ok(crate::engine::WhoisInfo {
                        registrar: None,
                        creation_date: None,
                        expiration_date: None,
                        name_servers: Vec::new(),
                    })
                }
            }
            _ => Ok(crate::engine::WhoisInfo {
                registrar: None,
                creation_date: None,
                expiration_date: None,
                name_servers: Vec::new(),
            }),
        }
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
