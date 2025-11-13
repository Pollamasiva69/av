#!/bin/bash
# Build script for Windows from Linux

echo "================================================"
echo "   Sentinel AV - Windows Build (Cross-compile)"
echo "================================================"
echo ""

echo "[1/4] Checking Rust toolchain..."
rustc --version
cargo --version
echo ""

echo "[2/4] Adding Windows target..."
rustup target add x86_64-pc-windows-gnu
echo ""

echo "[3/4] Building for Windows (release mode)..."
cargo build --release --target x86_64-pc-windows-gnu
if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    exit 1
fi
echo ""

echo "[4/4] Creating distribution..."
mkdir -p dist
cp target/x86_64-pc-windows-gnu/release/sentinel-av.exe dist/ 2>/dev/null || \
    echo "Note: .exe extension will be added when running on Windows"
cp example-config.toml dist/
cp README.md dist/
cp BUILD.md dist/
echo ""

echo "================================================"
echo "   Build completed successfully!"
echo "   Output: dist/sentinel-av.exe"
echo "================================================"
echo ""
