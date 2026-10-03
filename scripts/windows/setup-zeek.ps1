# Windows Zeek bootstrap for AI Unidirectional Threat Detection
# Safe to rerun: installs only missing prerequisites.
# Location: <project>/scripts/windows/setup-zeek.ps1
#
# Zeek Windows support is experimental. Live capture needs Npcap (installed
# in "WinPcap API-compatible mode") and the Npcap SDK.
#
# Usage (normally launched by app.py):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\setup-zeek.ps1
#   ... -ZeekRef v7.0.0     # pin a specific Zeek tag/branch
#   ... -SkipElevation      # when already running as Administrator

[CmdletBinding()]
param(
    [switch]$SkipElevation,
    [string]$ZeekRef = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# scripts\windows -> scripts -> project root (two levels up)
$root       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$thirdParty = Join-Path $root ".third_party"
$source     = Join-Path $thirdParty "zeek"
$build      = Join-Path $source "build"
$sdkRoot    = Join-Path $thirdParty "npcap-sdk"
$logFile    = Join-Path $root "windows-bootstrap.log"

# ---------------------------------------------------------------- helpers

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
    if ($SkipElevation -or (Test-Administrator)) { return }

    Write-Host "[windows-bootstrap] Requesting Administrator privileges..."
    $refArg = ""
    if ($ZeekRef) { $refArg = " -ZeekRef '$ZeekRef'" }

    # The elevated window logs everything and stays open on failure so the
    # error can actually be read.
    $inner = "Start-Transcript -Path '$logFile' -Force | Out-Null; " +
             "try { & '$PSCommandPath' -SkipElevation$refArg; `$code = `$LASTEXITCODE; if (`$null -eq `$code) { `$code = 0 } } " +
             "catch { Write-Host `$_ -ForegroundColor Red; `$code = 1; Read-Host 'Setup failed. Press Enter to close' } " +
             "finally { Stop-Transcript | Out-Null }; exit `$code"

    $psArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $inner)
    $child = Start-Process -FilePath "powershell.exe" -Verb RunAs `
        -ArgumentList $psArgs -WorkingDirectory $root -Wait -PassThru
    if ($child.ExitCode -ne 0) {
        throw "Elevated Windows setup failed (exit code $($child.ExitCode)). See $logFile"
    }
    exit 0
}

function Find-CommandPath([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user    = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (($machine, $user) -join ";")
}

function Invoke-WingetInstall([string]$Id, [string]$Override = "") {
    if (-not (Find-CommandPath "winget")) {
        throw "WinGet is required to bootstrap Windows dependencies. Install/update 'App Installer' from the Microsoft Store, then rerun."
    }

    Write-Host "[windows-bootstrap] Installing $Id..."
    $arguments = @(
        "install", "--id", $Id, "--exact",
        "--source", "winget",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    if ($Override) { $arguments += @("--override", $Override) }

    & winget.exe @arguments
    # 3010 = success, reboot required. -1978335189 = already installed / no upgrade.
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010 -and $LASTEXITCODE -ne -1978335189) {
        throw "WinGet failed to install $Id (exit code $LASTEXITCODE)."
    }
}

function Ensure-Tool([string]$Command, [string]$WingetId) {
    if (-not (Find-CommandPath $Command)) {
        Invoke-WingetInstall $WingetId
        Refresh-Path
    }
}

# ---------------------------------------------------------------- Npcap

function Test-Npcap {
    return (
        (Test-Path "C:\Windows\System32\Npcap\wpcap.dll") -or
        (Test-Path "C:\Windows\System32\Npcap\Packet.dll") -or
        (Test-Path "C:\Windows\System32\wpcap.dll")
    )
}

function Ensure-Npcap {
    if (Test-Npcap) {
        Write-Host "[windows-bootstrap] Npcap already installed."
        return
    }

    # The free Npcap edition only installs interactively (silent mode is OEM-only).
    $downloadDir = Join-Path $thirdParty "downloads"
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    $installer = Join-Path $downloadDir "npcap-1.89.exe"
    $url = "https://npcap.com/dist/npcap-1.89.exe"

    Write-Host "[windows-bootstrap] Downloading official Npcap installer..."
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing

    Write-Host "[windows-bootstrap] Launching Npcap installer."
    Write-Host "[windows-bootstrap] IMPORTANT: tick 'Install Npcap in WinPcap API-compatible Mode'."
    $process = Start-Process -FilePath $installer -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Npcap installer exited with code $($process.ExitCode)."
    }
    if (-not (Test-Npcap)) {
        throw "Npcap installation was not detected after the installer finished."
    }
}

function Find-NpcapSdk {
    $candidates = @(
        "C:\NpcapSDK",
        "C:\Program Files\NpcapSDK",
        "C:\Program Files\Npcap\SDK",
        $sdkRoot
    )
    foreach ($candidate in $candidates) {
        if (
            (Test-Path (Join-Path $candidate "Include")) -and
            (
                (Test-Path (Join-Path $candidate "Lib\x64")) -or
                (Test-Path (Join-Path $candidate "Lib\wpcap.lib"))
            )
        ) {
            return $candidate
        }
    }
    return $null
}

function Ensure-NpcapSdk {
    $existing = Find-NpcapSdk
    if ($existing) {
        Write-Host "[windows-bootstrap] Npcap SDK found at $existing"
        return $existing
    }

    $downloadDir = Join-Path $thirdParty "downloads"
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    $zip = Join-Path $downloadDir "npcap-sdk-1.16.zip"
    $url = "https://npcap.com/dist/npcap-sdk-1.16.zip"

    Write-Host "[windows-bootstrap] Downloading official Npcap SDK..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    if (Test-Path $sdkRoot) { Remove-Item -Recurse -Force $sdkRoot }
    New-Item -ItemType Directory -Force -Path $sdkRoot | Out-Null
    Expand-Archive -Path $zip -DestinationPath $sdkRoot -Force

    $result = Find-NpcapSdk
    if ($result) { return $result }

    $nested = Get-ChildItem -Path $sdkRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path (Join-Path $_.FullName "Include")) -and (Test-Path (Join-Path $_.FullName "Lib")) } |
        Select-Object -First 1
    if ($nested) { return $nested.FullName }

    throw "Npcap SDK download/extraction completed, but no usable SDK directory was found."
}

# ---------------------------------------------------------------- toolchain

function Ensure-DeveloperMode {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "[windows-bootstrap] Windows Developer Mode is enabled for Zeek source symlinks."
}

function Find-VcVars {
    $vswhereCandidates = @(
        "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
        "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    foreach ($vswhere in $vswhereCandidates) {
        if (Test-Path $vswhere) {
            $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($LASTEXITCODE -eq 0 -and $installPath) {
                $vcvars = Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat"
                if (Test-Path $vcvars) { return $vcvars }
            }
        }
    }

    foreach ($rootPath in @("C:\Program Files\Microsoft Visual Studio", "C:\Program Files (x86)\Microsoft Visual Studio")) {
        if (-not (Test-Path $rootPath)) { continue }
        $vcvars = Get-ChildItem -Path $rootPath -Filter "vcvars64.bat" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($vcvars) { return $vcvars.FullName }
    }
    return $null
}

# Directory holding Git for Windows' bundled Unix tools (sed, etc.).
function Find-GitUsrBin {
    $git = Find-CommandPath "git"
    if ($git) {
        # ...\Git\cmd\git.exe -> ...\Git\usr\bin
        $gitRoot = Split-Path -Parent (Split-Path -Parent $git)
        $candidate = Join-Path $gitRoot "usr\bin"
        if (Test-Path (Join-Path $candidate "sed.exe")) { return $candidate }
    }
    foreach ($candidate in @("C:\Program Files\Git\usr\bin", "C:\Program Files (x86)\Git\usr\bin")) {
        if (Test-Path (Join-Path $candidate "sed.exe")) { return $candidate }
    }
    return $null
}

# Folder containing win_flex.exe, win_bison.exe and FlexLexer.h (WinFlexBison).
function Find-FlexBisonDir {
    $searchRoots = @(
        (Join-Path $thirdParty "winflexbison"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
        (Join-Path $env:ProgramFiles "WinGet\Packages"),
        "C:\ProgramData\chocolatey\lib"
    )
    foreach ($r in $searchRoots) {
        if (-not (Test-Path $r)) { continue }
        $hit = Get-ChildItem -Path $r -Filter "FlexLexer.h" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.DirectoryName "win_flex.exe") } |
            Select-Object -First 1
        if ($hit) { return $hit.DirectoryName }
    }
    return $null
}

function Ensure-FlexBison {
    $dir = Find-FlexBisonDir
    if ($dir) {
        Write-Host "[windows-bootstrap] WinFlexBison found at $dir"
        return $dir
    }

    $downloadDir = Join-Path $thirdParty "downloads"
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    $zip = Join-Path $downloadDir "win_flex_bison-2.5.25.zip"
    $url = "https://github.com/lexxmark/winflexbison/releases/download/v2.5.25/win_flex_bison-2.5.25.zip"
    $dest = Join-Path $thirdParty "winflexbison"

    Write-Host "[windows-bootstrap] Downloading WinFlexBison..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force

    $dir = Find-FlexBisonDir
    if (-not $dir) {
        throw "WinFlexBison was installed but FlexLexer.h / win_flex.exe were not found."
    }
    return $dir
}

function Ensure-WindowsTools {
    Ensure-Tool "git"   "Git.Git"
    Ensure-Tool "cmake" "Kitware.CMake"
    Ensure-Tool "ninja" "Ninja-build.Ninja"

    # Zeek's CMake requires sed; Git for Windows ships it.
    if (-not (Find-GitUsrBin)) {
        throw "sed.exe not found. Reinstall Git for Windows (it ships sed in usr\bin), then rerun."
    }

    # Zeek (and Spicy) need bison + flex, including FlexLexer.h.
    Ensure-FlexBison | Out-Null

    if (-not (Find-VcVars)) {
        Write-Host "[windows-bootstrap] MSVC C++ Build Tools not detected."
        Invoke-WingetInstall "Microsoft.VisualStudio.BuildTools" '--wait --passive --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
        Refresh-Path
    }
}

# ---------------------------------------------------------------- Zeek source / build

function Resolve-ZeekRef {
    if ($ZeekRef) { return $ZeekRef }

    # Latest stable release tag (vX.Y.Z, no -rc/-dev), so we don't build a broken master.
    Write-Host "[windows-bootstrap] Looking up latest Zeek release tag..."
    $lines = & git.exe ls-remote --tags --refs https://github.com/zeek/zeek.git "refs/tags/v*"
    if ($LASTEXITCODE -ne 0 -or -not $lines) {
        Write-Warning "Could not list Zeek tags; falling back to master."
        return "master"
    }

    $best = $lines |
        ForEach-Object { if ($_ -match 'refs/tags/(v(\d+\.\d+\.\d+))$') { [pscustomobject]@{ Tag = $Matches[1]; Ver = [version]$Matches[2] } } } |
        Sort-Object Ver -Descending |
        Select-Object -First 1

    if ($best) { return $best.Tag }
    Write-Warning "No release tags matched; falling back to master."
    return "master"
}

function Ensure-ZeekSource {
    New-Item -ItemType Directory -Force -Path $thirdParty | Out-Null
    $ref = Resolve-ZeekRef
    Write-Host "[windows-bootstrap] Zeek ref: $ref"

    if (-not (Test-Path (Join-Path $source ".git"))) {
        Write-Host "[windows-bootstrap] Cloning official Zeek source..."
        & git.exe -c core.symlinks=true clone --recursive --branch $ref https://github.com/zeek/zeek.git $source
        if ($LASTEXITCODE -ne 0) { throw "Zeek source clone failed." }
        return
    }

    Push-Location $source
    try {
        Write-Host "[windows-bootstrap] Updating existing Zeek checkout..."
        & git.exe fetch --tags origin
        if ($LASTEXITCODE -ne 0) { throw "git fetch failed." }
        & git.exe -c core.symlinks=true checkout $ref
        if ($LASTEXITCODE -ne 0) { throw "git checkout $ref failed." }
        & git.exe submodule update --init --recursive
        if ($LASTEXITCODE -ne 0) { throw "Zeek submodule update failed." }
    } finally {
        Pop-Location
    }
}

function Build-Zeek([string]$NpcapSdk, [string]$VcVars) {
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    # A previously failed configure leaves a stale CMakeCache (e.g. "sed not found").
    if ((Test-Path (Join-Path $build "CMakeCache.txt")) -and -not (Test-Path (Join-Path $build "build.ninja"))) {
        Write-Host "[windows-bootstrap] Clearing stale failed CMake configure..."
        Remove-Item -Recurse -Force $build
        New-Item -ItemType Directory -Force -Path $build | Out-Null
    }

    # Git's Unix tools go at the END of PATH so they don't shadow find.exe/sort.exe.
    $gitUsrBin = Find-GitUsrBin
    if (-not $gitUsrBin) { throw "sed.exe not found. Install Git for Windows." }
    $env:Path = "$env:Path;$gitUsrBin"

    # flex/bison + FlexLexer.h (Spicy needs the header location explicitly).
    $flexDir = Ensure-FlexBison
    $env:Path = "$env:Path;$flexDir"

    # Batch file avoids PowerShell/cmd quoting problems.
    $cmdFile = Join-Path $build "build-zeek.cmd"
    $batch = @"
@echo off
call "$VcVars" x64 || exit /b 1
cmake.exe .. -G Ninja -DCMAKE_BUILD_TYPE=release -DENABLE_CLUSTER_BACKEND_ZEROMQ=no -DVCPKG_TARGET_TRIPLET=x64-windows-static -DPCAP_ROOT_DIR="$NpcapSdk" -DFLEX_INCLUDE_DIR="$flexDir" -DFLEX_INCLUDE_DIRS="$flexDir" || exit /b 1
cmake.exe --build . || exit /b 1
"@
    Set-Content -Path $cmdFile -Value $batch -Encoding ASCII

    Push-Location $build
    try {
        Write-Host "[windows-bootstrap] Configuring and building Zeek (this takes a long time)..."
        & cmd.exe /d /c $cmdFile
        if ($LASTEXITCODE -ne 0) {
            throw "Zeek native build failed (exit code $LASTEXITCODE)."
        }
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------- main

Ensure-Elevated

Write-Host "=== AI Unidirectional Threat Detection - Windows Zeek Bootstrap ==="
Write-Host "[windows-bootstrap] Project root: $root"
Write-Host ""

Ensure-DeveloperMode
Ensure-WindowsTools
Ensure-Npcap
$sdk = Ensure-NpcapSdk
Ensure-ZeekSource

$vcvars = Find-VcVars
if (-not $vcvars) {
    throw "MSVC vcvars64.bat was not found. Restart Windows if the installer requested it, then rerun."
}

Build-Zeek $sdk $vcvars

$binary = Join-Path $build "src\zeek.exe"
if (-not (Test-Path $binary)) {
    throw "Zeek build completed without producing $binary"
}

Write-Host ""
Write-Host "[windows-bootstrap] SUCCESS"
Write-Host "[windows-bootstrap] Zeek binary: $binary"
Write-Host "[windows-bootstrap] You can now run: python app.py"