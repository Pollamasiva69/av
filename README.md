# 🛡️ Sentinel AV - Enterprise Antivirus for Windows

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://www.microsoft.com/windows)

**Sentinel AV** is a next-generation, enterprise-grade antivirus engine built entirely in Rust. Designed specifically for Windows environments, it provides multi-layered threat detection with real-time protection, advanced heuristics, and behavioral analysis.

## ✨ Key Features

### 🔍 Multi-Engine Detection
- **Signature-based Detection**: Hash-based identification of known threats (MD5, SHA256, BLAKE3)
- **Heuristic Analysis**: Advanced PE analysis, entropy calculation, and pattern matching
- **Behavioral Detection**: Runtime behavior monitoring and anomaly detection
- **PE File Analysis**: Deep inspection of Windows executables (headers, sections, imports, exports)

### 🚀 Real-Time Protection
- File system monitoring with instant threat response
- Automatic quarantine of detected threats
- Process and memory scanning
- Anti-ransomware protection

### 🏢 Enterprise Management
- RESTful API for centralized management
- Comprehensive logging and audit trails
- Configurable scanning policies
- Automatic definition updates
- Dashboard and statistics

### 🔐 Security Features
- Encrypted quarantine storage
- Multi-threaded parallel scanning
- Low system resource usage
- Safe file handling with sandboxing
- Packer detection (UPX, ASPack, PECompact, etc.)

## 📋 System Requirements

- **Operating System**: Windows 10/11 or Windows Server 2019+
- **Architecture**: x64 (64-bit)
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for installation + quarantine storage
- **Permissions**: Administrator privileges required for full functionality

## 🚀 Quick Start

### Installation

#### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/your-org/sentinel-av.git
cd sentinel-av

# Build in release mode
cargo build --release

# The binary will be in target/release/sentinel-av.exe
```

#### Option 2: Pre-built Binaries

Download the latest release from the [Releases](https://github.com/your-org/sentinel-av/releases) page.

### Initial Configuration

Generate a default configuration file:

```bash
sentinel-av.exe init-config --output sentinel-config.toml
```

Edit the configuration to match your environment.

## 📖 Usage

### Scan a File

```bash
# Standard scan
sentinel-av.exe scan C:\path\to\file.exe

# Deep scan (all engines)
sentinel-av.exe scan C:\path\to\file.exe --deep
```

### Scan a Directory

```bash
# Recursive directory scan
sentinel-av.exe scan C:\Users --recursive
```

### Real-Time Protection

```bash
# Start real-time protection
sentinel-av.exe protect

# Run as background service
sentinel-av.exe protect --daemon
```

### Quarantine Management

```bash
# List quarantined files
sentinel-av.exe quarantine list

# Restore a single file
sentinel-av.exe quarantine restore <FILE_ID>

# Restore ALL files from quarantine (with confirmation)
sentinel-av.exe quarantine restore-all

# Restore ALL files without confirmation prompt
sentinel-av.exe quarantine restore-all --yes

# Delete permanently
sentinel-av.exe quarantine delete <FILE_ID>
```

### Update Definitions

```bash
# Update threat definitions
sentinel-av.exe update

# Force update
sentinel-av.exe update --force
```

### Process Scanning

```bash
# Scan all running processes
sentinel-av.exe process-scan --all

# Scan specific process
sentinel-av.exe process-scan --pid 1234
```

### API Server

```bash
# Start API server (default port 8443)
sentinel-av.exe server

# Custom port
sentinel-av.exe server --port 9000
```

### Statistics

```bash
# View engine statistics
sentinel-av.exe stats
```

## 🔧 Configuration

The configuration file (`sentinel-config.toml`) allows you to customize:

- **Engine Settings**: Detector selection, file size limits, timeouts
- **Scanner Settings**: Exclusions, archive scanning, memory scanning
- **Monitor Settings**: Real-time protection paths and behavior
- **Quarantine Settings**: Storage location, retention, encryption
- **API Settings**: Network binding, authentication, TLS
- **Update Settings**: Update frequency and sources
- **Logging Settings**: Log levels, rotation, and output

Example configuration:

```toml
[engine]
enabled_detectors = ["signature", "heuristic", "behavioral"]
max_file_size_mb = 500
max_threads = 8
timeout_seconds = 300

[monitor]
enabled = true
real_time_protection = true
auto_quarantine = true
monitored_paths = ["C:\\Users", "C:\\Program Files"]

[quarantine]
path = "C:\\ProgramData\\SentinelAV\\Quarantine"
max_size_gb = 10
retention_days = 30
encrypt = true
```

## 🌐 API Reference

### Endpoints

#### Health Check
```http
GET /api/v1/health
```

#### Get Statistics
```http
GET /api/v1/stats
```

Response:
```json
{
  "total_scans": 1500,
  "total_detections": 42,
  "signature_count": 50000,
  "quarantine_count": 15
}
```

#### Scan File
```http
POST /api/v1/scan/file
Content-Type: application/json

{
  "path": "C:\\path\\to\\file.exe"
}
```

#### Scan Directory
```http
POST /api/v1/scan/directory
Content-Type: application/json

{
  "path": "C:\\Users\\Documents"
}
```

#### Update Definitions
```http
POST /api/v1/update
```

## 🏗️ Architecture

### Detection Engines

```
┌─────────────────────────────────────────┐
│         Sentinel AV Engine              │
├─────────────────────────────────────────┤
│                                         │
│  ┌───────────┐  ┌──────────┐  ┌──────┐ │
│  │ Signature │  │Heuristic │  │Behav.│ │
│  │ Detector  │  │ Detector │  │Detect│ │
│  └─────┬─────┘  └────┬─────┘  └───┬──┘ │
│        │             │             │    │
│        └─────────────┴─────────────┘    │
│                     │                   │
│              ┌──────▼──────┐            │
│              │   Verdict   │            │
│              │  Aggregator │            │
│              └──────┬──────┘            │
│                     │                   │
│         ┌───────────▼──────────┐        │
│         │   Action Handler     │        │
│         │ (Quarantine/Alert)   │        │
│         └──────────────────────┘        │
└─────────────────────────────────────────┘
```

### Component Overview

- **Core Engine**: Orchestrates all detection engines and manages scans
- **Signature Detector**: Hash-based malware identification
- **Heuristic Detector**: Static analysis of file characteristics
- **Behavioral Detector**: Runtime behavior pattern matching
- **PE Analyzer**: Windows executable structure analysis
- **File Scanner**: Multi-engine file scanning coordinator
- **Process Scanner**: Memory and process analysis
- **Quarantine Manager**: Secure file isolation with encryption
- **Database**: SQLite-based storage for signatures and logs
- **API Server**: RESTful interface for enterprise integration
- **Monitor**: Real-time file system event processing

## 🧪 Detection Capabilities

### Threat Categories

- **Viruses**: Traditional file infectors
- **Trojans**: Malicious programs disguised as legitimate software
- **Ransomware**: File encryption malware
- **Rootkits**: System-level stealth malware
- **Keyloggers**: Keystroke monitoring malware
- **Backdoors**: Remote access tools
- **Packers**: Compressed/obfuscated executables
- **PUPs**: Potentially Unwanted Programs

### Heuristic Indicators

- High entropy sections (encryption/packing)
- Suspicious PE characteristics
- Writable + executable sections
- Missing or invalid headers
- Suspicious imports/exports
- Double file extensions
- Known packer signatures
- Anomalous section names

## 🛠️ Development

### Building

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- scan test.exe
```

### Project Structure

```
sentinel-av/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── lib.rs            # Library root
│   ├── config.rs         # Configuration management
│   ├── core.rs           # Core engine
│   ├── detection/        # Detection engines
│   │   ├── mod.rs
│   │   ├── signature.rs
│   │   ├── heuristic.rs
│   │   ├── behavioral.rs
│   │   └── pe_analyzer.rs
│   ├── scanner.rs        # File scanner
│   ├── monitor.rs        # Real-time monitoring
│   ├── process.rs        # Process scanner
│   ├── quarantine.rs     # Quarantine manager
│   ├── database.rs       # Database layer
│   ├── api.rs            # REST API
│   ├── updater.rs        # Definition updater
│   └── utils.rs          # Utilities
├── Cargo.toml
└── README.md
```

### Dependencies

- **windows**: Windows API bindings
- **tokio**: Async runtime
- **axum**: Web framework for API
- **rusqlite**: SQLite database
- **goblin**: PE file parsing
- **notify**: File system monitoring
- **sha2/md5/blake3**: Cryptographic hashing
- **clap**: CLI argument parsing
- **serde**: Serialization

## 🔐 Security Considerations

### Safe Practices

- Always run scans with appropriate permissions
- Regularly update threat definitions
- Monitor quarantine storage usage
- Review detection logs periodically
- Use encrypted quarantine storage
- Implement proper access controls

### Known Limitations

- Kernel-mode rootkits require driver support (planned)
- Advanced persistent threats may evade detection
- Zero-day exploits not covered by signatures
- Performance impact on very large file scans

## 📊 Performance

### Benchmarks

- **File Scan**: ~50,000 files/minute (SSD, standard scan)
- **Memory Usage**: ~100MB base + cache
- **CPU Usage**: Scales with thread count (configurable)
- **Database**: Supports 100,000+ signatures efficiently

### Optimization Tips

- Exclude trusted directories to reduce scan time
- Adjust thread count based on CPU cores
- Use quick scan for known-safe files
- Schedule full scans during low-usage periods

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Rust community for excellent tooling
- YARA project for pattern matching inspiration
- ClamAV for open-source antivirus reference
- VirusTotal for threat intelligence

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/sentinel-av/issues)
- **Documentation**: [Wiki](https://github.com/your-org/sentinel-av/wiki)
- **Email**: security@sentinelav.example

## ⚠️ Disclaimer

This software is provided for educational and defensive security purposes. Users are responsible for compliance with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

---

**Built with ❤️ and 🦀 Rust**
