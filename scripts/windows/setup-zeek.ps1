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
Write-Host ""
$npcapSdkCandidates = @(
    "C:\NpcapSDK",
    "C:\Program Files\NpcapSDK",
    "C:\Program Files\Npcap\SDK",
    (Join-Path $root ".third_party\npcap-sdk")
)
$npcapSdk = $null
foreach ($candidate in $npcapSdkCandidates) {
    if ((Test-Path (Join-Path $candidate "Include")) -and (Test-Path (Join-Path $candidate "Lib"))) {
        $npcapSdk = $candidate
        break
    }
}

if (-not $npcapSdk) {
    Write-Host "Npcap runtime is installed, but the Npcap SDK was not found."
    Write-Host "Zeek documents that Windows live capture requires building against the Npcap SDK."
    Write-Host "Download the SDK from the official Npcap site, extract it, and rerun this script."
    Start-Process "https://npcap.com/#download"
    exit 1
}

if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    Write-Host "MSVC cl.exe is not available in this PowerShell session."
    Write-Host "Open a Visual Studio Developer PowerShell/Command Prompt and rerun this script."
    exit 1
}

New-Item -ItemType Directory -Force -Path $build | Out-Null
Push-Location $build
try {
    $configure = @(
        "cmake.exe",
        "..",
        "-DCMAKE_BUILD_TYPE=release",
        "-DENABLE_ZEEK_UNIT_TESTS=yes",
        "-DENABLE_CLUSTER_BACKEND_ZEROMQ=no",
        '-DVCPKG_TARGET_TRIPLET=x64-windows-static',
        "-G",
        "Ninja",
        "-DPCAP_ROOT_DIR=$npcapSdk"
    )
    Write-Host "Configuring Zeek with Npcap SDK: $npcapSdk"
    & $configure[0] $configure[1..($configure.Count - 1)]
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }

    Write-Host "Building Zeek..."
    & cmake.exe --build .
    if ($LASTEXITCODE -ne 0) { throw "Zeek build failed." }
}
finally {
    Pop-Location
}

$binary = Join-Path $build "src\zeek.exe"
if (-not (Test-Path $binary)) {
    throw "Build completed without producing $binary"
}

Write-Host ""
Write-Host "Zeek Windows build completed:"
Write-Host "  $binary"
Write-Host ""
Write-Host "The application will detect this project-local binary automatically."
