use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "thirdeye",
    version = "1.0.0",
    about = "Advanced passive security intelligence tool",
    long_about = "ThirdEye - Passive reconnaissance and breach intelligence tool\n\nEthical use only: This tool performs passive intelligence gathering only.\nNo active scanning, exploitation, or credential validation is performed."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, global = true)]
    /// Output results in JSON format
    pub json: bool,

    #[arg(long, short = 'q', global = true)]
    /// Suppress banners and non-essential output
    pub quiet: bool,

    #[arg(long, global = true)]
    /// Thread count for parallel operations
    pub threads: Option<usize>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Perform security intelligence scan
    Scan {
        /// Target domain or IP address
        target: String,

        #[arg(long)]
        /// Enable reconnaissance module
        recon: bool,

        #[arg(long)]
        /// Enable web intelligence module
        web: bool,

        #[arg(long)]
        /// Enable mail breach intelligence
        mail: bool,
    },

    /// Email and domain breach intelligence
    Mail {
        /// Target email or domain (or read from stdin)
        target: Option<String>,

        #[arg(long, short = 'f')]
        /// Local breach file to scan
        file: Option<PathBuf>,

        #[arg(long)]
        /// Search by domain instead of email
        domain: bool,

        #[arg(long)]
        /// Include password reuse analysis
        password_reuse: bool,

        #[arg(long, default_value = "10")]
        /// Maximum API results per source
        limit: u32,
    },

    /// List available modules and capabilities
    Modules,

    /// Display tool version and build info
    Version,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}
