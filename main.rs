mod cli;
mod engine;
mod mail;
mod recon;
mod web;
mod output;
mod utils;

use cli::{Cli, Commands};
use engine::runner::ScanRunner;
use mail::MailScanner;
use anyhow::Result;
use std::io::{self, BufRead};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Show disclaimer on first run
    if !cli.quiet && !std::env::var("THIRDEYE_SILENT").is_ok() {
        show_disclaimer();
    }
    
    match cli.command {
        Commands::Scan { target, recon, web, mail } => {
            let runner = ScanRunner::new();
            runner.scan(&target, recon, web, mail).await?;
        }
        Commands::Mail { target, file, domain, password_reuse, limit } => {
            let scanner = MailScanner::new();
            
            // Handle input from stdin, file, or direct argument
            let targets = if let Some(t) = target {
                vec![t]
            } else if atty::isnt(atty::Stream::Stdin) {
                // Read from stdin if piped
                let stdin = io::stdin();
                stdin.lock().lines()
                    .filter_map(Result::ok)
                    .filter(|line| !line.trim().is_empty())
                    .collect()
            } else {
                eprintln!("Error: No target provided");
                std::process::exit(1);
            };
            
            for target in targets {
                if domain {
                    scanner.scan_domain(&target, file.as_deref(), limit, cli.json, cli.quiet).await?;
                } else {
                    scanner.scan_email(&target, file.as_deref(), password_reuse, limit, cli.json, cli.quiet).await?;
                }
            }
        }
        Commands::Modules => {
            list_modules();
        }
        Commands::Version => {
            println!("ThirdEye v{}", env!("CARGO_PKG_VERSION"));
            println!("Build: {}", env!("CARGO_PKG_REPOSITORY"));
            println!("Passive security intelligence tool");
        }
    }
    
    Ok(())
}

fn show_disclaimer() {
    println!("┌─────────────────────────────────────────────┐");
    println!("│                THIRDEYE                      │");
    println!("│          Security Intelligence Tool          │");
    println!("├─────────────────────────────────────────────┤");
    println!("│ DISCLAIMER:                                 │");
    println!("│ • Passive intelligence only                 │");
    println!("│ • No credential validation                  │");
    println!("│ • No exploitation or unauthorized access    │");
    println!("│ • For authorized security assessments only  │");
    println!("│ • Use responsibly and ethically             │");
    println!("└─────────────────────────────────────────────┘");
    println!();
}

fn list_modules() {
    println!("ThirdEye Modules:");
    println!("  mail    - Email and domain breach intelligence");
    println!("  recon   - Passive reconnaissance (DNS, WHOIS)");
    println!("  web     - Web technology fingerprinting");
    println!("  engine  - Correlation and scoring engine");
    println!();
    println!("Use: thirdeye <module> --help for module-specific options");
}
