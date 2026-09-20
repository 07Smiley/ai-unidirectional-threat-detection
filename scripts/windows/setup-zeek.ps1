# Windows Zeek setup helper
# Run PowerShell as Administrator:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\scripts\windows\setup-zeek.ps1
#
# Zeek documents native Windows support as experimental. Live capture requires
# an Npcap-linked build, and the official build instructions require a Windows
# development environment plus the Npcap SDK.

$ErrorActionPreference = "Stop"

Write-Host "=== AI Unidirectional Threat Detection - Windows Zeek Setup ==="
Write-Host ""

if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey is not installed."
    Write-Host "Install Chocolatey from https://chocolatey.org/install, then rerun this script."
    exit 1
}

$tools = @(
    "git",
    "cmake",
    "ninja",
    "python"
)

foreach ($tool in $tools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "Installing $tool..."
        choco install $tool -y --no-progress
    }
}

$npcap = "C:\Windows\System32\Npcap\wpcap.dll"
if (-not (Test-Path $npcap)) {
    Write-Host ""
    Write-Host "Npcap is required for live packet capture."
    Write-Host "Opening the official Npcap download page:"
    Start-Process "https://npcap.com/#download"
    Write-Host "Install Npcap, then rerun this script."
    exit 1
}

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$thirdParty = Join-Path $root ".third_party"
$source = Join-Path $thirdParty "zeek"
$build = Join-Path $source "build"

New-Item -ItemType Directory -Force -Path $thirdParty | Out-Null

if (-not (Test-Path (Join-Path $source ".git"))) {
    Write-Host "Cloning Zeek source..."
    git clone --recursive https://github.com/zeek/zeek.git $source
} else {
    Write-Host "Zeek source already exists."
}

Write-Host ""
Write-Host "Zeek source is ready."
Write-Host "The remaining build step requires the Npcap SDK and a supported MSVC"
Write-Host "environment, as documented by Zeek. This script intentionally does not"
Write-Host "download or redistribute the Npcap SDK or an unofficial Zeek binary."
Write-Host ""
Write-Host "Source: $source"
Write-Host "Build : $build"
Write-Host ""
Write-Host "After installing the Npcap SDK and Visual Studio Build Tools, configure:"
Write-Host 'cmake.exe .. -DCMAKE_BUILD_TYPE=release -DENABLE_ZEEK_UNIT_TESTS=yes -DENABLE_CLUSTER_BACKEND_ZEROMQ=no -DVCPKG_TARGET_TRIPLET="x64-windows-static" -G Ninja -DPCAP_ROOT_DIR="<Npcap SDK path>"'
Write-Host "Then:"
Write-Host "cmake.exe --build ."
