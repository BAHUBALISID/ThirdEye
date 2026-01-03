use crate::engine::WebData;
use anyhow::Result;
use reqwest::Client;
use scraper::{Html, Selector};
use std::time::Duration;

pub struct WebScanner {
    client: Client,
    user_agent: String,
}

impl WebScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("ThirdEye/1.0")
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            client,
            user_agent: "ThirdEye/1.0".to_string(),
        }
    }
    
    pub async fn scan(&self, target: &str) -> Result<WebData> {
        let mut web_data = WebData {
            technologies: Vec::new(),
            headers: Vec::new(),
            vulnerabilities: Vec::new(),
        };
        
        // Normalize target URL
        let url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("https://{}", target)
        };
        
        // Fetch the page
        if let Ok(response) = self.client.get(&url).send().await {
            // Extract headers
            for (name, value) in response.headers() {
                web_data.headers.push(crate::engine::Header {
                    name: name.to_string(),
                    value: value.to_str().unwrap_or("").to_string(),
                });
            }
            
            // Extract technologies from headers
            self.extract_technologies_from_headers(&response.headers(), &mut web_data.technologies);
            
            // Parse HTML for technologies
            if let Ok(html) = response.text().await {
                self.extract_technologies_from_html(&html, &mut web_data.technologies);
            }
        }
        
        // Check for common vulnerabilities
        self.check_vulnerabilities(&url, &mut web_data.vulnerabilities).await;
        
        Ok(web_data)
    }
    
    fn extract_technologies_from_headers(
        &self,
        headers: &reqwest::header::HeaderMap,
        technologies: &mut Vec<crate::engine::Technology>,
    ) {
        // Check server header
        if let Some(server) = headers.get("server") {
            if let Ok(server_str) = server.to_str() {
                technologies.push(crate::engine::Technology {
                    name: server_str.to_string(),
                    version: None,
                    confidence: 90,
                });
            }
        }
        
        // Check powered-by headers
        for header_name in &["x-powered-by", "x-generator"] {
            if let Some(value) = headers.get(*header_name) {
                if let Ok(value_str) = value.to_str() {
                    technologies.push(crate::engine::Technology {
                        name: value_str.to_string(),
                        version: None,
                        confidence: 80,
                    });
                }
            }
        }
    }
    
    fn extract_technologies_from_html(
        &self,
        html: &str,
        technologies: &mut Vec<crate::engine::Technology>,
    ) {
        let document = Html::parse_document(html);
        
        // Check for common technology indicators
        let patterns = [
            (r"wp-content", "WordPress", 90),
            (r"jquery", "jQuery", 80),
            (r"react", "React", 85),
            (r"vue", "Vue.js", 85),
            (r"angular", "Angular", 85),
            (r"bootstrap", "Bootstrap", 80),
            (r"cdnjs", "Cloudflare CDN", 70),
        ];
        
        for (pattern, tech_name, confidence) in patterns {
            if html.contains(pattern) {
                technologies.push(crate::engine::Technology {
                    name: tech_name.to_string(),
                    version: None,
                    confidence,
                });
            }
        }
        
        // Check meta tags
        let meta_selector = Selector::parse("meta[name='generator']").unwrap();
        for element in document.select(&meta_selector) {
            if let Some(content) = element.value().attr("content") {
                technologies.push(crate::engine::Technology {
                    name: content.to_string(),
                    version: None,
                    confidence: 95,
                });
            }
        }
        
        // Check script tags
        let script_selector = Selector::parse("script[src]").unwrap();
        for element in document.select(&script_selector) {
            if let Some(src) = element.value().attr("src") {
                if src.contains("jquery") {
                    technologies.push(crate::engine::Technology {
                        name: "jQuery".to_string(),
                        version: extract_version(src),
                        confidence: 90,
                    });
                }
            }
        }
    }
    
    async fn check_vulnerabilities(
        &self,
        url: &str,
        vulnerabilities: &mut Vec<crate::engine::Vulnerability>,
    ) {
        // Check for common security headers
        let response = self.client.head(url).send().await;
        if let Ok(resp) = response {
            let headers = resp.headers();
            
            if !headers.contains_key("x-frame-options") {
                vulnerabilities.push(crate::engine::Vulnerability {
                    id: "MISCONFIG-001".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: "Missing X-Frame-Options header - clickjacking vulnerability".to_string(),
                });
            }
            
            if !headers.contains_key("x-content-type-options") {
                vulnerabilities.push(crate::engine::Vulnerability {
                    id: "MISCONFIG-002".to_string(),
                    severity: "LOW".to_string(),
                    description: "Missing X-Content-Type-Options header - MIME sniffing vulnerability".to_string(),
                });
            }
            
            if let Some(csp) = headers.get("content-security-policy") {
                if let Ok(csp_str) = csp.to_str() {
                    if csp_str.contains("unsafe-inline") || csp_str.contains("unsafe-eval") {
                        vulnerabilities.push(crate::engine::Vulnerability {
                            id: "MISCONFIG-003".to_string(),
                            severity: "MEDIUM".to_string(),
                            description: "CSP contains unsafe directives".to_string(),
                        });
                    }
                }
            } else {
                vulnerabilities.push(crate::engine::Vulnerability {
                    id: "MISCONFIG-004".to_string(),
                    severity: "MEDIUM".to_string(),
                    description: "Missing Content-Security-Policy header".to_string(),
                });
            }
        }
    }
}

fn extract_version(src: &str) -> Option<String> {
    let version_patterns = [
        r"jquery-([\d.]+)\.min\.js",
        r"jquery/([\d.]+)/jquery",
        r"jquery@([\d.]+)",
    ];
    
    for pattern in version_patterns {
        if let Ok(regex) = regex::Regex::new(pattern) {
            if let Some(captures) = regex.captures(src) {
                if let Some(version) = captures.get(1) {
                    return Some(version.as_str().to_string());
                }
            }
        }
    }
    
    None
}
