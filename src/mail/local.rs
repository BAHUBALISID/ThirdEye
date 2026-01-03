use crate::mail::models::*;
use crate::mail::parser::BreachParser;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

pub struct LocalScanner {
    parser: BreachParser,
    chunk_size: usize,
}

impl LocalScanner {
    pub fn new() -> Self {
        Self {
            parser: BreachParser::new(),
            chunk_size: 100_000,
        }
    }
    
    pub async fn scan_file(
        &self,
        file_path: &Path,
        target_email: Option<&str>,
        target_domain: Option<&str>,
    ) -> Result<LocalScanResult> {
        let file = File::open(file_path)?;
        
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        
        // Create progress bar for large files
        let pb = if file_size > 10_000_000 {
            let pb = ProgressBar::new(file_size);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(pb)
        } else {
            None
        };
        
        let reader = BufReader::new(file);
        let lines_read = Arc::new(AtomicU64::new(0));
        let bytes_read = Arc::new(AtomicU64::new(0));
        
        // Channel for found records
        let (tx, mut rx) = mpsc::channel::<BreachRecord>(1000);
        
        // Spawn parser task
        let parser = self.parser.clone();
        let target_email = target_email.map(|s| s.to_string());
        let target_domain = target_domain.map(|s| s.to_string());
        let lines_read_clone = lines_read.clone();
        let bytes_read_clone = bytes_read.clone();
        let pb_clone = pb.clone();
        
        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(100_000);
            let mut current_pos = 0u64;
            
            for line in reader.lines() {
                match line {
                    Ok(line_content) => {
                        current_pos += line_content.len() as u64 + 1;
                        
                        buffer.push(line_content);
                        
                        if buffer.len() >= 100_000 {
                            let batch = std::mem::take(&mut buffer);
                            let _ = process_batch(
                                batch,
                                &parser,
                                &target_email,
                                &target_domain,
                                &tx,
                            ).await;
                        }
                        
                        lines_read_clone.fetch_add(1, Ordering::Relaxed);
                        bytes_read_clone.store(current_pos, Ordering::Relaxed);
                        
                        if let Some(pb) = &pb_clone {
                            pb.set_position(current_pos);
                        }
                    }
                    Err(e) => eprintln!("Line read error: {}", e),
                }
            }
            
            // Process remaining lines
            if !buffer.is_empty() {
                let _ = process_batch(
                    buffer,
                    &parser,
                    &target_email,
                    &target_domain,
                    &tx,
                ).await;
            }
            
            drop(tx); // Close channel
        });
        
        // Collect results
        let mut found_records = Vec::new();
        while let Some(record) = rx.recv().await {
            found_records.push(record);
        }
        
        if let Some(pb) = pb {
            pb.finish_and_clear();
        }
        
        let records_found_len = found_records.len();
        
        Ok(LocalScanResult {
            file_path: file_path.to_string_lossy().to_string(),
            records_found: found_records,
            stats: LocalScanStats {
                file_path: file_path.to_string_lossy().to_string(),
                bytes_scanned: bytes_read.load(Ordering::Relaxed),
                records_processed: lines_read.load(Ordering::Relaxed),
                emails_found: records_found_len as u64,
                unique_emails: 0,
                scan_duration: std::time::Duration::default(),
            },
        })
    }
    
    pub fn stream_file(
        &self,
        file_path: &Path,
    ) -> Result<impl Iterator<Item = Result<BreachRecord>> + '_> {
        let file = File::open(file_path)?;
        
        let reader = BufReader::new(file);
        
        Ok(reader.lines()
            .filter_map(|line| line.ok())
            .filter_map(move |line| {
                self.parser.parse_line(&line).transpose()
            }))
    }
}

async fn process_batch(
    batch: Vec<String>,
    parser: &BreachParser,
    target_email: &Option<String>,
    target_domain: &Option<String>,
    tx: &mpsc::Sender<BreachRecord>,
) -> Result<()> {
    // Use Rayon for parallel processing
    let records: Vec<_> = batch
        .par_iter()
        .filter_map(|line| {
            parser.parse_line(line).transpose()
        })
        .filter(|record| {
            match record {
                Ok(record) => {
                    if let Some(target_email) = target_email {
                        record.email == *target_email
                    } else if let Some(target_domain) = target_domain {
                        record.email.ends_with(&format!("@{}", target_domain))
                    } else {
                        true
                    }
                }
                Err(_) => false,
            }
        })
        .filter_map(|r| r.ok())
        .collect();
    
    // Send to channel
    for record in records {
        if tx.send(record).await.is_err() {
            break; // Receiver dropped
        }
    }
    
    Ok(())
}

pub struct LocalScanResult {
    pub file_path: String,
    pub records_found: Vec<BreachRecord>,
    pub stats: LocalScanStats,
}
