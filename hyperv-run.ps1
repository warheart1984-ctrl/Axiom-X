<#
.SYNOPSIS
    Boot Axiom-X in a Hyper-V Generation 1 VM and capture its serial console.

.DESCRIPTION
    Needs an elevated PowerShell (Run as administrator), or membership in
    "Hyper-V Administrators". What it does, in order:

      1. Checks elevation and its inputs:
           evidence\axiom-x-dbg.iso            (built by qemu-boot.sh; carries the
                                                kernel, user programs, ledger key;
                                                copied into evidence\hyperv\ per run)
           evidence\hyperv\ledger-hyperv.vhd   (fixed VHD copy of evidence\ledger.img;
                                                your real ledger.img is never touched)
         and makes sure both are plain files: Hyper-V refuses compressed,
         encrypted or sparse disks. It turns NTFS compression off for
         evidence\hyperv\ only (the project tree is compressed).
      2. Creates VM "Axiom-X" (Generation 1 = BIOS + IDE + legacy COM ports):
           1 vCPU (the kernel is single-CPU), 256 MB static RAM, no network,
           checkpoints off, DVD = the ISO (IDE 1:0), disk = the VHD on IDE 0:0
           (primary master: where the kernel's ATA driver looks), boot order
           CD first, COM1 -> named pipe \\.\pipe\axiomx-com1.
      3. Starts it, connects to the pipe, and copies the serial output to the
           console and to evidence\hyperv-serial-<date>.log for -Seconds seconds.
      4. Turns the VM off. With -Cleanup it also deletes the VM definition
           (the VHD and the log are kept either way, for verification).

    It changes nothing else: no virtual switch, no network, no host settings.
    Afterwards, verify the ledger off-machine (no admin needed):
      target\release\ledger-tool.exe verify evidence\hyperv\ledger-hyperv.vhd <public-key>

.PARAMETER Seconds
    How long to capture the serial console before turning the VM off (default 90).

.PARAMETER Cleanup
    Remove the VM definition afterwards (Remove-VM). Files are kept.

.PARAMETER Recreate
    If a VM named Axiom-X already exists, turn it off and remove it first.

.EXAMPLE
    # From an elevated PowerShell in the axiom-x folder:
    powershell -ExecutionPolicy Bypass -File .\hyperv-run.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    [int]$Seconds = 90,
    [switch]$Cleanup,
    [switch]$Recreate
)

$ErrorActionPreference = 'Stop'
$VmName   = 'Axiom-X'
$PipeName = 'axiomx-com1'
$Root     = $PSScriptRoot
$BuiltIso = Join-Path $Root 'evidence\axiom-x-dbg.iso'
$HvDir    = Join-Path $Root 'evidence\hyperv'
$Iso      = Join-Path $HvDir 'axiom-x-dbg.iso'
$Vhd      = Join-Path $HvDir 'ledger-hyperv.vhd'
$VmDir    = Join-Path $HvDir 'vm'
$Log      = Join-Path $Root ("evidence\hyperv-serial-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))

# --- 1. Preconditions --------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Hyper-V Administrators by its well-known SID (names are localized).
$isHvAdmin = $principal.IsInRole((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-578')))
if (-not ($isAdmin -or $isHvAdmin)) {
    throw "Run this from an elevated PowerShell (Run as administrator), or as a member of 'Hyper-V Administrators'."
}
foreach ($f in @($BuiltIso, $Vhd)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing input: $f" }
}
if ((Get-Service vmms).Status -ne 'Running') { throw "The Hyper-V service (vmms) is not running." }

# Hyper-V refuses compressed, encrypted or sparse disk files, and the
# project tree may be NTFS-compressed: keep this script's own folder
# uncompressed (only it, nothing else) and stage a fresh ISO copy there.
compact /u /s:"$HvDir" /i /q | Out-Null
compact /u "$HvDir" | Out-Null
Copy-Item -LiteralPath $BuiltIso -Destination $Iso -Force
foreach ($f in @($Iso, $Vhd)) {
    $attr = (Get-Item -LiteralPath $f).Attributes
    $bad = @('Compressed', 'Encrypted', 'SparseFile') | Where-Object { $attr -band [IO.FileAttributes]::$_ }
    if ($bad) { throw "Hyper-V cannot use $f (it is $($bad -join ', ')). Make it a plain file first." }
}

$existing = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Recreate) { throw "A VM named '$VmName' already exists. Re-run with -Recreate to replace it." }
    Write-Host "Removing existing VM '$VmName'..."
    if ($existing.State -ne 'Off') { Stop-VM -Name $VmName -TurnOff -Force }
    Remove-VM -Name $VmName -Force
}

# --- 2. Create the VM ----------------------------------------------------------
Write-Host "Creating Generation 1 VM '$VmName'..."
New-Item -ItemType Directory -Force -Path $VmDir | Out-Null
New-VM -Name $VmName -Generation 1 -MemoryStartupBytes 256MB -NoVHD -Path $VmDir | Out-Null
Set-VM -Name $VmName -StaticMemory -CheckpointType Disabled -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
Set-VMProcessor -VMName $VmName -Count 1
Get-VMNetworkAdapter -VMName $VmName | Remove-VMNetworkAdapter          # no network at all
Add-VMHardDiskDrive -VMName $VmName -ControllerType IDE -ControllerNumber 0 -ControllerLocation 0 -Path $Vhd
if (Get-VMDvdDrive -VMName $VmName) {
    Set-VMDvdDrive -VMName $VmName -ControllerNumber 1 -ControllerLocation 0 -Path $Iso
} else {
    Add-VMDvdDrive -VMName $VmName -ControllerNumber 1 -ControllerLocation 0 -Path $Iso
}
Set-VMBios -VMName $VmName -StartupOrder @('CD', 'IDE', 'LegacyNetworkAdapter', 'Floppy')
Set-VMComPort -VMName $VmName -Number 1 -Path "\\.\pipe\$PipeName"

Get-VMHardDiskDrive -VMName $VmName | Format-Table ControllerType, ControllerNumber, ControllerLocation, Path -AutoSize
Get-VMDvdDrive -VMName $VmName | Format-Table ControllerNumber, ControllerLocation, Path -AutoSize
Get-VMComPort -VMName $VmName | Format-Table Name, Path -AutoSize

# --- 3. Run and capture COM1 -----------------------------------------------
$pipe = $null
$out = $null
try {
    Write-Host "Starting VM; capturing COM1 for $Seconds s -> $Log"
    Start-VM -Name $VmName
    # Hyper-V creates the pipe server when the VM starts; connect at once so
    # little or nothing of the boot output is missed.
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::In)
    $pipe.Connect(15000)
    $out = [System.IO.File]::Open($Log, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $buf = New-Object byte[] 4096
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $pending = $null
    while ($clock.Elapsed.TotalSeconds -lt $Seconds) {
        if ($null -eq $pending) { $pending = $pipe.ReadAsync($buf, 0, $buf.Length) }
        if ($pending.Wait(250)) {
            $n = $pending.Result
            $pending = $null
            if ($n -le 0) { Write-Host "[pipe closed]"; break }
            $out.Write($buf, 0, $n)
            $out.Flush()
            Write-Host -NoNewline ([System.Text.Encoding]::ASCII.GetString($buf, 0, $n))
        }
    }
    Write-Host ""
    Write-Host "Capture finished after $([int]$clock.Elapsed.TotalSeconds) s."
}
finally {
    if ($out) { $out.Dispose() }
    if ($pipe) { $pipe.Dispose() }
    # --- 4. Stop (and optionally remove) -------------------------------------
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if ($vm -and $vm.State -ne 'Off') {
        Write-Host "Turning the VM off..."
        Stop-VM -Name $VmName -TurnOff -Force
    }
    if ($Cleanup -and $vm) {
        Write-Host "Removing the VM definition (VHD and log are kept)..."
        Remove-VM -Name $VmName -Force
        Remove-Item -Recurse -Force $VmDir -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Serial log : $Log"
Write-Host "Ledger VHD : $Vhd"
Write-Host "Verify with: target\release\ledger-tool.exe verify `"$Vhd`" <public-key>"
