# Building Sentinel AV for Windows

This guide explains how to build Sentinel AV from source on Windows.

## Prerequisites

### 1. Install Rust

Download and install Rust from [https://rustup.rs/](https://rustup.rs/)

```powershell
# Verify installation
rustc --version
cargo --version
```

### 2. Install Visual Studio Build Tools

Rust on Windows requires the Microsoft C++ build tools. Install one of:

- **Visual Studio 2019 or later** (Community Edition is free)
- **Build Tools for Visual Studio 2019 or later**

Download from: [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)

Make sure to install:
- "Desktop development with C++" workload
- Windows 10 or 11 SDK
- MSVC v142 or later build tools

### 3. Install Required Tools (Optional but Recommended)

```powershell
# Git for version control
winget install Git.Git

# PowerShell 7+ for better scripting
winget install Microsoft.PowerShell
```

## Building

### Quick Build

Use the provided build script:

```batch
build.bat
```

This will:
1. Check for Rust installation
2. Set up the Windows target
3. Build in release mode
4. Copy outputs to `dist/` folder

### Manual Build

#### Debug Build

```powershell
cargo build
```

Output: `target/debug/sentinel-av.exe`

#### Release Build (Optimized)

```powershell
cargo build --release
```

Output: `target/release/sentinel-av.exe`

#### Specify Target Explicitly

```powershell
# For 64-bit Windows (recommended)
cargo build --release --target x86_64-pc-windows-msvc

# For 32-bit Windows
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

## Testing

### Run All Tests

```powershell
cargo test
```

### Run Specific Test

```powershell
cargo test test_name
```

### Run with Output

```powershell
cargo test -- --nocapture
```

## Running Development Build

```powershell
# Run directly with cargo
cargo run -- scan C:\path\to\file.exe

# Run compiled binary
.\target\release\sentinel-av.exe --help
```

## Build Profiles

### Debug Profile
- Fast compilation
- Includes debug symbols
- No optimizations
- Larger binary size

```powershell
cargo build
```

### Release Profile
- Slower compilation
- Maximum optimizations
- Stripped symbols
- Smaller binary size
- Production-ready

```powershell
cargo build --release
```

### Custom Profile

Edit `Cargo.toml` to create custom profiles:

```toml
[profile.custom]
inherits = "release"
opt-level = 3
lto = "fat"
codegen-units = 1
```

Build with:

```powershell
cargo build --profile custom
```

## Troubleshooting

### "link.exe not found"

**Solution**: Install Visual Studio Build Tools with C++ development tools.

### "cannot find -lwindows"

**Solution**: Update dependencies:

```powershell
cargo update
cargo clean
cargo build
```

### "failed to run custom build command"

**Solution**: Make sure you have the latest Rust toolchain:

```powershell
rustup update
```

### Compilation is Slow

**Solutions**:
1. Use debug build for development
2. Enable incremental compilation (already default)
3. Reduce dependency count
4. Use `cargo check` instead of `cargo build` for quick validation

```powershell
cargo check  # Fast syntax/type checking
```

### Out of Memory During Compilation

**Solution**: Reduce parallel jobs:

```powershell
cargo build -j 2  # Use only 2 parallel jobs
```

## Cross-Compilation

### From Linux to Windows

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install MinGW
sudo apt install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

### From macOS to Windows

```bash
# Install target
rustup target add x86_64-pc-windows-gnu

# Install MinGW via Homebrew
brew install mingw-w64

# Build
cargo build --release --target x86_64-pc-windows-gnu
```

## Optimizing Binary Size

### Strip Symbols

Already configured in `Cargo.toml`:

```toml
[profile.release]
strip = true
```

### Use UPX Compression (Optional)

```powershell
# Download UPX from https://upx.github.io/
upx --best --lzma target\release\sentinel-av.exe
```

**Warning**: Some antivirus software may flag UPX-compressed executables.

## Creating a Release

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md**
3. **Build release**:
   ```powershell
   cargo build --release
   ```
4. **Run tests**:
   ```powershell
   cargo test --release
   ```
5. **Create distribution**:
   ```powershell
   build.bat
   ```
6. **Package**:
   ```powershell
   Compress-Archive -Path dist\* -DestinationPath sentinel-av-v1.0.0-windows-x64.zip
   ```

## Development Tips

### Fast Iteration

```powershell
# Check only (no binary generation, faster)
cargo check

# Watch for changes and auto-rebuild
cargo install cargo-watch
cargo watch -x check
```

### Linting

```powershell
# Run clippy for lint warnings
cargo clippy

# Apply automatic fixes
cargo clippy --fix
```

### Formatting

```powershell
# Check formatting
cargo fmt --check

# Auto-format all code
cargo fmt
```

### Documentation

```powershell
# Generate and open documentation
cargo doc --open
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build
        run: cargo build --release
      - name: Test
        run: cargo test
```

## Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)
- [Windows Rust Guide](https://rust-lang.github.io/rustup/installation/windows.html)
- [Rust Windows API](https://microsoft.github.io/windows-docs-rs/)

## Support

For build issues, please open an issue on GitHub with:
- Your Rust version (`rustc --version`)
- Your cargo version (`cargo --version`)
- Your Windows version
- Full error output
