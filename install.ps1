# Sentinel AV Installation Script for Windows
# Requires Administrator privileges

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "   Sentinel AV - Installation Script" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Installation paths
$InstallPath = "C:\Program Files\SentinelAV"
$DataPath = "C:\ProgramData\SentinelAV"
$QuarantinePath = "$DataPath\Quarantine"
$LogPath = "$DataPath\Logs"

# Check if already installed
if (Test-Path $InstallPath) {
    Write-Host "WARNING: Sentinel AV appears to be already installed." -ForegroundColor Yellow
    $response = Read-Host "Do you want to continue and overwrite? (y/n)"
    if ($response -ne 'y') {
        Write-Host "Installation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "[1/5] Creating installation directories..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
New-Item -ItemType Directory -Force -Path $QuarantinePath | Out-Null
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
Write-Host "    Created: $InstallPath" -ForegroundColor Gray
Write-Host "    Created: $DataPath" -ForegroundColor Gray

Write-Host "[2/5] Copying application files..." -ForegroundColor Green
if (Test-Path ".\dist\sentinel-av.exe") {
    Copy-Item ".\dist\sentinel-av.exe" -Destination "$InstallPath\" -Force
    Write-Host "    Copied: sentinel-av.exe" -ForegroundColor Gray
} else {
    Write-Host "ERROR: sentinel-av.exe not found in .\dist\" -ForegroundColor Red
    Write-Host "Please run build.bat first to compile the application." -ForegroundColor Red
    exit 1
}

Write-Host "[3/5] Creating default configuration..." -ForegroundColor Green
if (Test-Path ".\example-config.toml") {
    Copy-Item ".\example-config.toml" -Destination "$DataPath\sentinel-config.toml" -Force
    Write-Host "    Created: sentinel-config.toml" -ForegroundColor Gray
}

Write-Host "[4/5] Adding to system PATH..." -ForegroundColor Green
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallPath*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$currentPath;$InstallPath",
        "Machine"
    )
    Write-Host "    Added to PATH: $InstallPath" -ForegroundColor Gray
} else {
    Write-Host "    Already in PATH" -ForegroundColor Gray
}

Write-Host "[5/5] Setting permissions..." -ForegroundColor Green
$acl = Get-Acl $DataPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.SetAccessRule($accessRule)
Set-Acl $DataPath $acl
Write-Host "    Permissions configured" -ForegroundColor Gray

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "   Installation completed successfully!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Details:" -ForegroundColor White
Write-Host "  Program: $InstallPath" -ForegroundColor Gray
Write-Host "  Data:    $DataPath" -ForegroundColor Gray
Write-Host "  Config:  $DataPath\sentinel-config.toml" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor White
Write-Host "  1. Review and customize the configuration file" -ForegroundColor Gray
Write-Host "  2. Run 'sentinel-av update' to download threat definitions" -ForegroundColor Gray
Write-Host "  3. Run 'sentinel-av scan C:\' to perform a system scan" -ForegroundColor Gray
Write-Host "  4. Run 'sentinel-av protect' to start real-time protection" -ForegroundColor Gray
Write-Host ""
Write-Host "For help, run: sentinel-av --help" -ForegroundColor Cyan
Write-Host ""

# Ask to run update
$response = Read-Host "Would you like to update threat definitions now? (y/n)"
if ($response -eq 'y') {
    Write-Host ""
    Write-Host "Updating threat definitions..." -ForegroundColor Green
    & "$InstallPath\sentinel-av.exe" update
}

Write-Host ""
Write-Host "Installation complete. Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
