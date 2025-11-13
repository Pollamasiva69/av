@echo off
REM Sentinel AV Build Script for Windows
REM Requires Rust toolchain to be installed

echo ===============================================
echo    Sentinel AV - Windows Build Script
echo ===============================================
echo.

REM Check if Rust is installed
where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Cargo not found. Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)

echo [1/4] Checking Rust toolchain...
rustc --version
cargo --version
echo.

echo [2/4] Setting up Windows target...
rustup target add x86_64-pc-windows-msvc
echo.

echo [3/4] Building in release mode...
cargo build --release --target x86_64-pc-windows-msvc
if %errorlevel% neq 0 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)
echo.

echo [4/4] Creating distribution...
if not exist "dist" mkdir dist
copy "target\x86_64-pc-windows-msvc\release\sentinel-av.exe" "dist\"
copy "example-config.toml" "dist\"
copy "README.md" "dist\"
echo.

echo ===============================================
echo    Build completed successfully!
echo    Output: dist\sentinel-av.exe
echo ===============================================
echo.

pause
