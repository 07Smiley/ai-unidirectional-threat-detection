# Windows Zeek bootstrap for AI Unidirectional Threat Detection
# This script is safe to rerun. It installs only missing prerequisites.
# Run normally from app.py; the script requests UAC elevation when required.
#
# Zeek Windows support is experimental. Live capture requires Npcap and the
# Npcap SDK. The free Npcap installer is interactive; it cannot be silently
# redistributed by this project.

[CmdletBinding()]
param(
    [switch]$SkipElevation
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$thirdParty = Join-Path $root ".third_party"
$source = Join-Path $thirdParty "zeek"
$build = Join-Path $source "build"
$sdkRoot = Join-Path $thirdParty "npcap-sdk"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
    if ($SkipElevation -or (Test-Administrator)) {
        return
    }

    Write-Host "[windows-bootstrap] Requesting Administrator privileges..."
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-SkipElevation"
    )
    $child = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args -WorkingDirectory $root -Wait -PassThru
    if ($child.ExitCode -ne 0) {
        throw "Elevated Windows setup failed with exit code $($child.ExitCode)."
    }
    exit 0
}

function Find-CommandPath([string]$Name) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

function Invoke-WingetInstall([string]$Id, [string]$Override = "") {
    if (-not (Find-CommandPath "winget")) {
        throw "WinGet is required to bootstrap Windows dependencies. Install/update App Installer, then rerun app.py."
    }

    Write-Host "[windows-bootstrap] Installing $Id..."
    $arguments = @(
        "install", "--id", $Id, "--exact",
        "--source", "winget",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    if ($Override) {
        $arguments += @("--override", $Override)
    }

    & winget.exe @arguments
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
        throw "WinGet failed to install $Id (exit code $LASTEXITCODE)."
    }
}

function Ensure-Tool([string]$Command, [string]$WingetId) {
    if (-not (Find-CommandPath $Command)) {
        Invoke-WingetInstall $WingetId
    }
}

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

    # The free Npcap edition must be installed by its signed installer. Its
    # documentation states that silent installation is an OEM-only feature.
    $downloadDir = Join-Path $thirdParty "downloads"
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    $installer = Join-Path $downloadDir "npcap-1.89.exe"
    $url = "https://npcap.com/dist/npcap-1.89.exe"

    Write-Host "[windows-bootstrap] Downloading official Npcap installer..."
    Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing

    Write-Host "[windows-bootstrap] Launching Npcap installer. Complete its prompts, then setup will continue."
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

    if (Test-Path $sdkRoot) {
        Remove-Item -Recurse -Force $sdkRoot
    }
    New-Item -ItemType Directory -Force -Path $sdkRoot | Out-Null
    Expand-Archive -Path $zip -DestinationPath $sdkRoot -Force

    $nested = Get-ChildItem -Path $sdkRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path (Join-Path $_.FullName "Include")) -and (Test-Path (Join-Path $_.FullName "Lib")) } |
        Select-Object -First 1
    if ($nested) {
        return $nested.FullName
    }

    $result = Find-NpcapSdk
    if (-not $result) {
        throw "Npcap SDK download/extraction completed, but no usable SDK directory was found."
    }
    return $result
}

function Ensure-DeveloperMode {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "[windows-bootstrap] Windows Developer Mode is enabled for Zeek source symlinks."
}

function Ensure-WindowsTools {
    Ensure-Tool "git" "Git.Git"
    Ensure-Tool "cmake" "Kitware.CMake"
    Ensure-Tool "ninja" "Ninja-build.Ninja"

    if (-not (Find-CommandPath "cl")) {
        Write-Host "[windows-bootstrap] MSVC C++ Build Tools not detected."
        Invoke-WingetInstall "Microsoft.VisualStudio.BuildTools" '--wait --passive --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
    }
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
                if (Test-Path $vcvars) {
                    return $vcvars
                }
            }
        }
    }

    $roots = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )
    foreach ($rootPath in $roots) {
        if (-not (Test-Path $rootPath)) { continue }
        $vcvars = Get-ChildItem -Path $rootPath -Filter "vcvars64.bat" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($vcvars) {
            return $vcvars.FullName
        }
    }

    return $null
}

function Ensure-ZeekSource {
    New-Item -ItemType Directory -Force -Path $thirdParty | Out-Null
    if (-not (Test-Path (Join-Path $source ".git"))) {
        Write-Host "[windows-bootstrap] Cloning official Zeek source..."
        & git.exe -c core.symlinks=true clone --recursive https://github.com/zeek/zeek.git $source
        if ($LASTEXITCODE -ne 0) {
            throw "Zeek source clone failed."
        }
    } else {
        Write-Host "[windows-bootstrap] Updating Zeek submodules..."
        Push-Location $source
        try {
            & git.exe submodule update --init --recursive
            if ($LASTEXITCODE -ne 0) {
                throw "Zeek submodule update failed."
            }
        } finally {
            Pop-Location
        }
    }
}

function Build-Zeek([string]$NpcapSdk, [string]$VcVars) {
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    $cmakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=release",
        "-DENABLE_ZEEK_UNIT_TESTS=yes",
        "-DENABLE_CLUSTER_BACKEND_ZEROMQ=no",
        "-DVCPKG_TARGET_TRIPLET=x64-windows-static",
        "-DPCAP_ROOT_DIR=$NpcapSdk",
        "-G", "Ninja"
    )

    $quoted = $cmakeArgs | ForEach-Object {
        '"' + ($_ -replace '"', '""') + '"'
    }
    $argumentLine = $quoted -join " "

    Push-Location $build
    try {
        Write-Host "[windows-bootstrap] Configuring Zeek..."
        $cmd = '"' + $VcVars + '" x64 && cmake.exe ' + $argumentLine + ' && cmake.exe --build .'
        & cmd.exe /d /s /c $cmd
        if ($LASTEXITCODE -ne 0) {
            throw "Zeek native build failed (exit code $LASTEXITCODE)."
        }
    } finally {
        Pop-Location
    }
}

Ensure-Elevated

Write-Host "=== AI Unidirectional Threat Detection - Windows Zeek Bootstrap ==="
Write-Host ""

Ensure-DeveloperMode
Ensure-WindowsTools
Ensure-Npcap
$sdk = Ensure-NpcapSdk
Ensure-ZeekSource

$vcvars = Find-VcVars
if (-not $vcvars) {
    throw "MSVC vcvars64.bat was not found after Visual Studio Build Tools setup. Restart Windows if the installer requested it, then rerun app.py."
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
