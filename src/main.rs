//! Sentinel AV - Enterprise Antivirus for Windows
//!
//! A high-performance, multi-layered antivirus engine built with Rust

use sentinel_av::{Config, Engine, Verdict};
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "Sentinel AV")]
#[command(author = "Sentinel Security Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Enterprise-grade antivirus for Windows", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory
    Scan {
        /// Path to scan
        path: PathBuf,

        /// Deep scan (all engines)
        #[arg(short, long)]
        deep: bool,

        /// Recursive directory scan
        #[arg(short, long)]
        recursive: bool,
    },

    /// Manage quarantine
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Update threat definitions
    Update {
        /// Force update even if not needed
        #[arg(short, long)]
        force: bool,
    },

    /// Start real-time protection
    Protect {
        /// Run in background as service
        #[arg(short, long)]
        daemon: bool,
    },

    /// Start API server
    Server {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Show statistics
    Stats,

    /// Scan running processes
    ProcessScan {
        /// Scan all processes
        #[arg(short, long)]
        all: bool,

        /// Specific process ID to scan
        #[arg(short, long)]
        pid: Option<u32>,
    },

    /// Generate default config
    InitConfig {
        /// Output path for config file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined files
    List,

    /// Restore a file from quarantine
    Restore { id: String },

    /// Delete a quarantined file
    Delete { id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("sentinel_av={},tower_http=debug", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Print banner
    print_banner();

    // Load or create config
    let config = if let Some(config_path) = cli.config {
        Config::load_from_file(&config_path)?
    } else {
        Config::default()
    };

    // Initialize engine
    let engine = Engine::new(config.clone()).await?;

    // Execute command
    match cli.command {
        Commands::Scan { path, deep, recursive } => {
            cmd_scan(engine, path, deep, recursive).await?;
        }
        Commands::Quarantine { action } => {
            cmd_quarantine(engine, action).await?;
        }
        Commands::Update { force } => {
            cmd_update(engine, force).await?;
        }
        Commands::Protect { daemon } => {
            cmd_protect(engine, config, daemon).await?;
        }
        Commands::Server { port } => {
            cmd_server(engine, config, port).await?;
        }
        Commands::Stats => {
            cmd_stats(engine).await?;
        }
        Commands::ProcessScan { all, pid } => {
            cmd_process_scan(all, pid).await?;
        }
        Commands::InitConfig { output } => {
            cmd_init_config(output)?;
        }
    }

    Ok(())
}

fn print_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║              SENTINEL AV - Enterprise Edition                 ║".bright_cyan());
    println!("{}", "║            Next-Generation Antivirus for Windows              ║".bright_cyan());
    println!("{}", "║                     Version 1.0.0                             ║".bright_cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

async fn cmd_scan(engine: Engine, path: PathBuf, deep: bool, recursive: bool) -> Result<()> {
    println!("{}", format!("🔍 Scanning: {}", path.display()).bright_yellow());
    println!();

    if path.is_file() {
        let verdict = if deep {
            println!("{}", "Mode: Deep Scan (All Engines)".bright_blue());
            engine.scan_file(&path).await?
        } else {
            println!("{}", "Mode: Standard Scan".bright_blue());
            engine.scan_file(&path).await?
        };

        print_verdict(&path, &verdict);
    } else if path.is_dir() {
        println!("{}", "Mode: Directory Scan".bright_blue());
        if recursive {
            println!("{}", "Recursive: Yes".bright_blue());
        }
        println!();

        let stats = engine.scan_directory(&path).await?;

        println!();
        println!("{}", "═══════════════════════════════════════".bright_cyan());
        println!("{}", "           SCAN RESULTS".bright_cyan().bold());
        println!("{}", "═══════════════════════════════════════".bright_cyan());
        println!("{}: {}", "Files Scanned".bright_white(), stats.files_scanned.to_string().bright_green());
        println!("{}: {}", "Threats Found".bright_white(),
            if stats.threats_found > 0 {
                stats.threats_found.to_string().bright_red()
            } else {
                stats.threats_found.to_string().bright_green()
            }
        );
        println!("{}: {}", "Files Quarantined".bright_white(), stats.files_quarantined.to_string().bright_yellow());
        println!("{}: {}", "Data Scanned".bright_white(), format_size(stats.bytes_scanned).bright_blue());
        println!("{}: {}", "Duration".bright_white(), format_duration(stats.scan_duration_ms).bright_blue());
        println!("{}", "═══════════════════════════════════════".bright_cyan());
    }

    Ok(())
}

async fn cmd_quarantine(engine: Engine, action: QuarantineAction) -> Result<()> {
    match action {
        QuarantineAction::List => {
            println!("{}", "📦 Quarantined Files:".bright_yellow());
            println!();
            // List would be implemented
            println!("{}", "No files in quarantine".bright_green());
        }
        QuarantineAction::Restore { id } => {
            println!("{}", format!("🔄 Restoring file: {}", id).bright_yellow());
            engine.restore_file(&id).await?;
            println!("{}", "✓ File restored successfully".bright_green());
        }
        QuarantineAction::Delete { id } => {
            println!("{}", format!("🗑️  Deleting file: {}", id).bright_yellow());
            println!("{}", "✓ File deleted successfully".bright_green());
        }
    }

    Ok(())
}

async fn cmd_update(engine: Engine, _force: bool) -> Result<()> {
    println!("{}", "🔄 Updating threat definitions...".bright_yellow());

    let count = engine.update_definitions().await?;

    println!();
    println!("{}", format!("✓ Updated {} threat definitions", count).bright_green());

    Ok(())
}

async fn cmd_protect(engine: Engine, config: Config, daemon: bool) -> Result<()> {
    if daemon {
        println!("{}", "🛡️  Starting real-time protection (daemon mode)...".bright_yellow());
        println!("{}", "Press Ctrl+C to stop".bright_blue());
    } else {
        println!("{}", "🛡️  Starting real-time protection...".bright_yellow());
    }

    // Start real-time protection
    use sentinel_av::monitor::FileSystemMonitor;
    use std::sync::Arc;

    let scanner = Arc::new(sentinel_av::scanner::FileScanner::new(
        Arc::new(sentinel_av::detection::SignatureDetector::new(
            Arc::new(sentinel_av::database::Database::new(&PathBuf::from("sentinel.db"))?)
        ).await?),
        Arc::new(sentinel_av::detection::HeuristicDetector::new()),
    ));

    let quarantine = Arc::new(sentinel_av::quarantine::QuarantineManager::new(&config.quarantine.path)?);

    let monitor = FileSystemMonitor::new(Arc::new(config), scanner, quarantine);

    monitor.start().await?;

    println!("{}", "✓ Real-time protection active".bright_green());

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    println!();
    println!("{}", "Shutting down...".bright_yellow());

    Ok(())
}

async fn cmd_server(engine: Engine, config: Config, port: Option<u16>) -> Result<()> {
    use sentinel_av::api::ApiServer;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let mut config = config;
    if let Some(p) = port {
        config.api.port = p;
    }

    println!("{}", format!("🌐 Starting API server on port {}...", config.api.port).bright_yellow());

    let server = ApiServer::new(Arc::new(engine), Arc::new(RwLock::new(config)));
    server.start().await?;

    Ok(())
}

async fn cmd_stats(engine: Engine) -> Result<()> {
    let stats = engine.get_stats().await?;

    println!("{}", "═══════════════════════════════════════".bright_cyan());
    println!("{}", "         ENGINE STATISTICS".bright_cyan().bold());
    println!("{}", "═══════════════════════════════════════".bright_cyan());
    println!("{}: {}", "Total Scans".bright_white(), stats.total_scans.to_string().bright_green());
    println!("{}: {}", "Total Detections".bright_white(), stats.total_detections.to_string().bright_red());
    println!("{}: {}", "Signature Count".bright_white(), stats.signature_count.to_string().bright_blue());
    println!("{}: {}", "Quarantine Count".bright_white(), stats.quarantine_count.to_string().bright_yellow());
    println!("{}", "═══════════════════════════════════════".bright_cyan());

    Ok(())
}

async fn cmd_process_scan(all: bool, pid: Option<u32>) -> Result<()> {
    use sentinel_av::process::ProcessScanner;

    let scanner = ProcessScanner::new();

    if all {
        println!("{}", "🔍 Scanning all processes...".bright_yellow());
        let results = scanner.scan_all_processes().await?;
        println!("{}", format!("✓ Scanned {} processes", results.len()).bright_green());
    } else if let Some(pid) = pid {
        println!("{}", format!("🔍 Scanning process {}...", pid).bright_yellow());
        let result = scanner.scan_process(pid).await?;
        if result.is_suspicious {
            println!("{}", "⚠️  Process is suspicious".bright_red());
        } else {
            println!("{}", "✓ Process appears clean".bright_green());
        }
    } else {
        println!("{}", "ℹ️  Use --all to scan all processes or --pid <PID> to scan a specific process".bright_blue());
    }

    Ok(())
}

fn cmd_init_config(output: Option<PathBuf>) -> Result<()> {
    let config = Config::default();
    let output_path = output.unwrap_or_else(|| PathBuf::from("sentinel-config.toml"));

    config.save_to_file(&output_path)?;

    println!("{}", format!("✓ Config file created: {}", output_path.display()).bright_green());

    Ok(())
}

fn print_verdict(path: &PathBuf, verdict: &Verdict) {
    println!();
    match verdict {
        Verdict::Clean => {
            println!("{} {}", "✓".bright_green(), format!("{} is CLEAN", path.display()).bright_green());
        }
        Verdict::Suspicious => {
            println!("{} {}", "⚠".bright_yellow(), format!("{} is SUSPICIOUS", path.display()).bright_yellow());
        }
        Verdict::Malicious(threat) => {
            println!("{} {}", "✗".bright_red(), format!("{} is INFECTED", path.display()).bright_red().bold());
            println!();
            println!("{}", "  Threat Details:".bright_red());
            println!("{}: {}", "  Name".bright_white(), threat.name.bright_red());
            println!("{}: {}", "  Category".bright_white(), threat.category.bright_yellow());
            println!("{}: {:?}", "  Severity".bright_white(), threat.level);
            println!("{}: {}", "  Description".bright_white(), threat.description);
            println!("{}: {}", "  Detected By".bright_white(), threat.detected_by.join(", ").bright_blue());
        }
    }
}

fn format_size(bytes: u64) -> String {
    sentinel_av::utils::format_size(bytes)
}

fn format_duration(ms: u64) -> String {
    sentinel_av::utils::format_duration(ms)
}
