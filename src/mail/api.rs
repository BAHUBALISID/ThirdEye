use crate::mail::models::*;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use tokio::time::{timeout, Duration};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};  // Added import

#[async_trait]
pub trait BreachApiClient {
    async fn query_email(&self, email: &str) -> Result<Vec<BreachRecord>>;
    async fn query_domain(&self, domain: &str) -> Result<Vec<BreachRecord>>;
    fn get_source_name(&self) -> &'static str;
}

pub struct ProxyNovaClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl ProxyNovaClient {
    pub fn new(api_key: Option<String>) -> Self {
        let client = Client::builder()
            .user_agent("ThirdEye/1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            client,
            base_url: "https://api.proxynova.com".to_string(),
            api_key,
        }
    }
}

#[async_trait]
impl BreachApiClient for ProxyNovaClient {
    async fn query_email(&self, email: &str) -> Result<Vec<BreachRecord>> {
    let url = format!("{}/combos", self.base_url); // https://api.proxynova.com/combos
    let params = [("query", email), ("format", "json"), ("limit", "100")];
    // ... sends HTTP request, parses JSON into BreachRecord structs
}
        
        let response = timeout(
            Duration::from_secs(15),
            self.client.get(&url).query(&params).send()
        ).await??;
        
        if response.status().is_success() {
            let text = response.text().await?;
            if let Ok(json) = serde_json::from_str::<Value>(&text) {
                records.extend(parse_proxynova_response(&json, email));
            }
        }
        
        Ok(records)
    }
    
    async fn query_domain(&self, _domain: &str) -> Result<Vec<BreachRecord>> {
        // ProxyNova doesn't support domain queries directly
        Ok(vec![])
    }
    
    fn get_source_name(&self) -> &'static str {
        "ProxyNova"
    }
}

pub struct HIBPClient {
    client: Client,
    api_key: String,
}

impl HIBPClient {
    pub fn new(api_key: String) -> Self {
        let client = Client::builder()
            .user_agent("ThirdEye/1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");
        
        Self { client, api_key }
    }
}

#[async_trait]
impl BreachApiClient for HIBPClient {
    async fn query_email(&self, email: &str) -> Result<Vec<BreachRecord>> {
        let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}", email);
        
        let response = timeout(
            Duration::from_secs(15),
            self.client.get(&url)
                .header("hibp-api-key", &self.api_key)
                .header("user-agent", "ThirdEye")
                .send()
        ).await??;
        
        let mut records = Vec::new();
        
        if response.status().is_success() {
            let breaches: Vec<Value> = response.json().await?;
            for breach in breaches {
                records.push(parse_hibp_breach(&breach, email));
            }
        }
        
        Ok(records)
    }
    
    async fn query_domain(&self, _domain: &str) -> Result<Vec<BreachRecord>> {
        // HIBP doesn't support domain queries directly
        Ok(vec![])
    }
    
    fn get_source_name(&self) -> &'static str {
        "HaveIBeenPwned"
    }
}

pub struct ApiManager {
    clients: Vec<Box<dyn BreachApiClient>>,
}

impl ApiManager {
    pub fn new() -> Self {
        Self {
            clients: Vec::new(),
        }
    }
    
    pub fn add_client(&mut self, client: Box<dyn BreachApiClient>) {
        self.clients.push(client);
    }
    
    pub async fn query_email(&self, email: &str) -> Result<Vec<BreachRecord>> {
        let mut all_records = Vec::new();
        
        for client in &self.clients {
            match client.query_email(email).await {
                Ok(records) => all_records.extend(records),
                Err(e) => eprintln!("API error from {}: {}", client.get_source_name(), e),
            }
            
            // Simple rate limiting
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        Ok(all_records)
    }
    
    pub async fn query_domain(&self, domain: &str) -> Result<Vec<BreachRecord>> {
        let mut all_records = Vec::new();
        
        for client in &self.clients {
            match client.query_domain(domain).await {
                Ok(records) => all_records.extend(records),
                Err(e) => eprintln!("API error from {}: {}", client.get_source_name(), e),
            }
            
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        Ok(all_records)
    }
}

fn parse_proxynova_response(json: &Value, email: &str) -> Vec<BreachRecord> {
    let mut records = Vec::new();
    
    if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
        for result in results {
            if let (Some(e), Some(p)) = (
                result.get("email").and_then(|v| v.as_str()),
                result.get("password").and_then(|v| v.as_str()),
            ) {
                if e == email {
                    records.push(BreachRecord {
                        email: e.to_string(),
                        password: Some(p.to_string()),
                        hash: None,
                        hash_type: None,
                        source: "ProxyNova".to_string(),
                        breach_date: None,
                        additional_data: HashMap::new(),
                    });
                }
            }
        }
    }
    
    records
}

fn parse_hibp_breach(breach: &Value, email: &str) -> BreachRecord {
    BreachRecord {
        email: email.to_string(),
        password: None,
        hash: None,
        hash_type: None,
        source: breach.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
        breach_date: breach.get("BreachDate")
            .and_then(|v| v.as_str())
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .map(|d| DateTime::from_naive_utc_and_offset(
                d.and_hms_opt(0, 0, 0).unwrap(), Utc
            )),
        additional_data: HashMap::from([
            ("Title".to_string(), breach.get("Title").and_then(|v| v.as_str()).unwrap_or("").to_string()),
            ("Domain".to_string(), breach.get("Domain").and_then(|v| v.as_str()).unwrap_or("").to_string()),
        ]),
    }
}

