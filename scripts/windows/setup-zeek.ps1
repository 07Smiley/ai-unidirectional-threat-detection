# Windows Zeek bootstrap for AI Unidirectional Threat Detection
# Safe to rerun: installs only missing prerequisites, skips the build if the
# checked-out Zeek commit was already built.
# Location: <project>/scripts/windows/setup-zeek.ps1
#
# Zeek Windows support is experimental. Live capture needs Npcap (installed
# in "WinPcap API-compatible mode") and the Npcap SDK.
#
# Usage (normally launched by app.py):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\setup-zeek.ps1
#   ... -ZeekRef v7.0.0     # pin a specific Zeek tag/branch
#   ... -SkipElevation      # when already running as Administrator
#   ... -Rebuild            # force a rebuild even if this commit was built
#   ... -Clean              # delete the old Zeek checkout + build and start fresh
#                           # (cached downloads, Npcap SDK, WinFlexBison are kept)

[CmdletBinding()]
param(
    [switch]$SkipElevation,
    [switch]$Rebuild,
    [switch]$Clean,
    [string]$ZeekRef = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Pinned download versions (bump here when they go stale).
$NpcapVersion    = "1.89"
$NpcapSdkVersion = "1.16"
$WinFlexBisonVer = "2.5.25"

# scripts\windows -> scripts -> project root (two levels up)
$root       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$thirdParty = Join-Path $root ".third_party"
$source     = Join-Path $thirdParty "zeek"
$build      = Join-Path $source "build"
$sdkRoot    = Join-Path $thirdParty "npcap-sdk"
$logFile    = Join-Path $root "windows-bootstrap.log"
$stampFile  = Join-Path $build ".built-commit"

# ---------------------------------------------------------------- helpers

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
    if ($SkipElevation -or (Test-Administrator)) { return }

    Write-Host "[windows-bootstrap] Requesting Administrator privileges..."
    $extra = ""
    if ($ZeekRef) { $extra += " -ZeekRef '$ZeekRef'" }
    if ($Rebuild) { $extra += " -Rebuild" }
    if ($Clean)   { $extra += " -Clean" }

    # The elevated window logs everything and stays open on failure so the
    # error can actually be read.
    $inner = "Start-Transcript -Path '$logFile' -Force | Out-Null; " +
             "try { & '$PSCommandPath' -SkipElevation$extra; `$code = `$LASTEXITCODE; if (`$null -eq `$code) { `$code = 0 } } " +
             "catch { Write-Host `$_ -ForegroundColor Red; `$code = 1; Read-Host 'Setup failed. Press Enter to close' } " +
             "finally { Stop-Transcript | Out-Null }; exit `$code"

    # EncodedCommand sidesteps all Start-Process argument quoting problems
    # (paths with spaces, embedded quotes).
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    $psArgs  = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded)

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
    $code = $LASTEXITCODE

    # 0 = ok, 3010 = ok/reboot required,
    # -1978335189 = no applicable upgrade, -1978335135 = already installed.
    $ok = @(0, 3010, -1978335189, -1978335135)
    # Reset so a tolerated non-zero code never leaks out as the script's exit code.
    $global:LASTEXITCODE = 0
    if ($ok -notcontains $code) {
        throw "WinGet failed to install $Id (exit code $code)."
    }
}

function Ensure-Tool([string]$Command, [string]$WingetId) {
    if (-not (Find-CommandPath $Command)) {
        Invoke-WingetInstall $WingetId
        Refresh-Path
    }
}

function Download-File([string]$Url, [string]$OutFile) {
    # Reuse a previously downloaded file instead of downloading again.
    if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) {
        Write-Host "[windows-bootstrap] Using cached download: $OutFile"
        return
    }
    $dir = Split-Path -Parent $OutFile
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # TLS 1.2 explicitly: Windows PowerShell 5.1 may default to older protocols.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    } catch {
        # Never leave a partial file behind to be mistaken for a cache hit.
        if (Test-Path $OutFile) { Remove-Item -Force $OutFile -ErrorAction SilentlyContinue }
        throw
    }
}

# Reliable recursive delete (handles read-only .git files and very long paths).
function Remove-Tree([string]$Path) {
    if (-not (Test-Path $Path)) { return }
    & cmd.exe /d /c "rmdir /s /q `"$Path`"" | Out-Null
    $global:LASTEXITCODE = 0
    if (Test-Path $Path) {
        Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue
    }
    if (Test-Path $Path) { throw "Could not delete $Path. Close anything using it and rerun." }
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
    $installer = Join-Path $thirdParty "downloads\npcap-$NpcapVersion.exe"

    Write-Host "[windows-bootstrap] Downloading official Npcap installer..."
    Download-File "https://npcap.com/dist/npcap-$NpcapVersion.exe" $installer

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

    $zip = Join-Path $thirdParty "downloads\npcap-sdk-$NpcapSdkVersion.zip"

    Write-Host "[windows-bootstrap] Downloading official Npcap SDK..."
    Download-File "https://npcap.com/dist/npcap-sdk-$NpcapSdkVersion.zip" $zip

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

function Ensure-SystemSettings {
    # Developer Mode: lets git create symlinks for the Zeek source tree.
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "[windows-bootstrap] Windows Developer Mode is enabled for Zeek source symlinks."

    # Long paths: Zeek's submodules and build tree can exceed MAX_PATH (260).
    $fs = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    New-ItemProperty -Path $fs -Name "LongPathsEnabled" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "[windows-bootstrap] Windows long path support is enabled."
}

function Find-VcVars {
    $vswhereCandidates = @(
        "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
        "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    foreach ($vswhere in $vswhereCandidates) {
        if (Test-Path $vswhere) {
            $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            $code = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            if ($code -eq 0 -and $installPath) {
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
            Where-Object {
                (Test-Path (Join-Path $_.DirectoryName "win_flex.exe")) -and
                (Test-Path (Join-Path $_.DirectoryName "win_bison.exe")) -and
                (Test-Path (Join-Path $_.DirectoryName "data\m4sugar\m4sugar.m4"))
            } |
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

    $zip  = Join-Path $thirdParty "downloads\win_flex_bison-$WinFlexBisonVer.zip"
    $url  = "https://github.com/lexxmark/winflexbison/releases/download/v$WinFlexBisonVer/win_flex_bison-$WinFlexBisonVer.zip"
    $dest = Join-Path $thirdParty "winflexbison"

    Write-Host "[windows-bootstrap] Downloading WinFlexBison..."
    Download-File $url $zip
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force

    $dir = Find-FlexBisonDir
    if (-not $dir) {
        throw "WinFlexBison was downloaded but FlexLexer.h / win_flex.exe were not found."
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
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($code -ne 0 -or -not $lines) {
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

    if ($Clean -and (Test-Path $source)) {
        Write-Host "[windows-bootstrap] -Clean: deleting previous Zeek checkout and build..."
        Remove-Tree $source
    }

    $ref = Resolve-ZeekRef
    Write-Host "[windows-bootstrap] Zeek ref: $ref"

    if (-not (Test-Path (Join-Path $source ".git"))) {
        Write-Host "[windows-bootstrap] Cloning official Zeek source..."
        & git.exe -c core.symlinks=true -c core.longpaths=true clone --recursive --branch $ref https://github.com/zeek/zeek.git $source
        if ($LASTEXITCODE -ne 0) {
            # Remove the partial clone so the next run starts clean instead of
            # taking the "existing checkout" path on a half-cloned tree.
            if (Test-Path $source) { Remove-Item -Recurse -Force $source -ErrorAction SilentlyContinue }
            throw "Zeek source clone failed."
        }
        return
    }

    Push-Location $source
    try {
        Write-Host "[windows-bootstrap] Updating existing Zeek checkout..."
        & git.exe config core.longpaths true
        & git.exe fetch --tags origin
        if ($LASTEXITCODE -ne 0) { throw "git fetch failed." }
        & git.exe -c core.symlinks=true checkout $ref
        if ($LASTEXITCODE -ne 0) { throw "git checkout $ref failed." }
        # A branch ref (e.g. master) should follow its remote.
        & git.exe show-ref --verify --quiet "refs/remotes/origin/$ref"
        $isBranch = ($LASTEXITCODE -eq 0)
        $global:LASTEXITCODE = 0
        if ($isBranch) {
            & git.exe merge --ff-only "origin/$ref"
            if ($LASTEXITCODE -ne 0) { throw "git fast-forward to origin/$ref failed." }
        }
        & git.exe submodule update --init --recursive
        if ($LASTEXITCODE -ne 0) { throw "Zeek submodule update failed." }
    } finally {
        Pop-Location
    }
}

function Get-ZeekCommit {
    Push-Location $source
    try {
        $sha = (& git.exe rev-parse HEAD).Trim()
        $global:LASTEXITCODE = 0
        return $sha
    } finally {
        Pop-Location
    }
}

function Build-Zeek([string]$NpcapSdk, [string]$VcVars) {
    # If a previous attempt never completed (no stamp), or -Rebuild was given,
    # its CMake cache / half-built objects may be stale. Wipe only the build
    # directory and reconfigure; the cloned source and downloads are kept.
    if ((Test-Path $build) -and ($Rebuild -or -not (Test-Path $stampFile))) {
        Write-Host "[windows-bootstrap] Clearing previous incomplete build directory..."
        Remove-Tree $build
    }
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    # Git's Unix tools go at the END of PATH so they don't shadow find.exe/sort.exe.
    $gitUsrBin = Find-GitUsrBin
    if (-not $gitUsrBin) { throw "sed.exe not found. Install Git for Windows." }
    $env:Path = "$env:Path;$gitUsrBin"

    # flex/bison + FlexLexer.h (Spicy needs the header location explicitly).
    # It must come FIRST on PATH: the WinGet "Links" shim of win_bison.exe
    # cannot find its data\m4sugar folder and breaks Spicy's parser generation.
    $flexDir = Ensure-FlexBison
    $env:Path = "$flexDir;$env:Path"
    $env:BISON_PKGDATADIR = Join-Path $flexDir "data"
    $bisonExe = Join-Path $flexDir "win_bison.exe"
    $flexExe  = Join-Path $flexDir "win_flex.exe"

    # Batch file avoids PowerShell/cmd quoting problems.
    $cmdFile = Join-Path $build "build-zeek.cmd"
    $batch = @"
@echo off
call "$VcVars" x64 || exit /b 1
cmake.exe .. -G Ninja -DCMAKE_BUILD_TYPE=release -DENABLE_CLUSTER_BACKEND_ZEROMQ=no -DVCPKG_TARGET_TRIPLET=x64-windows-static -DPCAP_ROOT_DIR="$NpcapSdk" -DFLEX_INCLUDE_DIR="$flexDir" -DFLEX_INCLUDE_DIRS="$flexDir" -DBISON_EXECUTABLE="$bisonExe" -DFLEX_EXECUTABLE="$flexExe" || exit /b 1
cmake.exe --build . || exit /b 1
"@
    Set-Content -Path $cmdFile -Value $batch -Encoding ASCII

    Push-Location $build
    try {
        Write-Host "[windows-bootstrap] Configuring and building Zeek (this takes a long time)..."
        $buildLog = Join-Path $build "build-zeek.log"
        # Continue (not Stop) so native stderr piped through 2>&1 isn't turned
        # into a terminating error on Windows PowerShell 5.1.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & cmd.exe /d /c $cmdFile 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $buildLog
            $buildCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($buildCode -ne 0) {
            Write-Host ""
            Write-Host "[windows-bootstrap] ---- Build failed. Key lines from the log ----" -ForegroundColor Red
            Select-String -Path $buildLog -Pattern "CMake Error|FAILED:|error C\d+|error:|fatal error|Could NOT find|not found|No such file" |
                Select-Object -Last 25 | ForEach-Object { Write-Host $_.Line }
            Write-Host "[windows-bootstrap] Full log: $buildLog" -ForegroundColor Red
            throw "Zeek native build failed (exit code $buildCode). See $buildLog"
        }
        $global:LASTEXITCODE = 0
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------- main

Ensure-Elevated

Write-Host "=== AI Unidirectional Threat Detection - Windows Zeek Bootstrap ==="
Write-Host "[windows-bootstrap] Project root: $root"
Write-Host ""

Ensure-SystemSettings
Ensure-WindowsTools
Ensure-Npcap
$sdk = Ensure-NpcapSdk
Ensure-ZeekSource

$vcvars = Find-VcVars
if (-not $vcvars) {
    throw "MSVC vcvars64.bat was not found. Restart Windows if the installer requested it, then rerun."
}

$binary = Join-Path $build "src\zeek.exe"
$commit = Get-ZeekCommit
$built  = $null
if (Test-Path $stampFile) { $built = (Get-Content $stampFile -ErrorAction SilentlyContinue | Select-Object -First 1) }

if ((-not $Rebuild) -and (Test-Path $binary) -and ($built -eq $commit)) {
    Write-Host "[windows-bootstrap] Zeek $commit already built; skipping build (use -Rebuild to force)."
} else {
    Build-Zeek $sdk $vcvars
    if (-not (Test-Path $binary)) {
        throw "Zeek build completed without producing $binary"
    }
    Set-Content -Path $stampFile -Value $commit -Encoding ASCII
}

Write-Host ""
Write-Host "[windows-bootstrap] SUCCESS"
Write-Host "[windows-bootstrap] Zeek binary: $binary"
Write-Host "[windows-bootstrap] You can now run: python app.py"

# Explicit success code: never inherit a stale $LASTEXITCODE from a native tool.
exit 0