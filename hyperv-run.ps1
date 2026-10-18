<#
.SYNOPSIS
    Boot Axiom-X in a Hyper-V Generation 1 VM and capture its serial console.

.DESCRIPTION
    Needs an elevated PowerShell (Run as administrator), or membership in
    "Hyper-V Administrators". What it does, in order:

      1. Checks elevation and its inputs:
           evidence\axiom-x-hyperv.iso         (preferred: built for Hyper-V with a
                                                fixed kernel command line, see below)
           or evidence\axiom-x-dbg.iso         (qemu-boot.sh's last ISO: carries the
                                                command line of the last QEMU run)
                                                Either carries the kernel, user programs
                                                and ledger key; copied into evidence\hyperv\
           evidence\hyperv\ledger-hyperv.vhd   (fixed VHD copy of evidence\ledger.img;
                                                your real ledger.img is never touched)
           evidence\hyperv\fs-hyperv.vhd       (file-system disk; created blank, 16 MiB,
                                                if missing; the kernel formats it)
         and makes sure all are plain files: Hyper-V refuses compressed,
         encrypted or sparse disks. It turns NTFS compression off for
         evidence\hyperv\ only (the project tree is compressed).
      2. Creates VM "Axiom-X" (Generation 1 = BIOS + IDE + legacy COM ports):
           1 vCPU (the kernel is single-CPU), 256 MB static RAM, no network,
           checkpoints off, DVD = the ISO (IDE 1:0), ledger disk = the VHD on
           IDE 0:0 (primary master), file-system disk on IDE 0:1 (primary
           slave): where the kernel's ATA driver looks for each. Boot order
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

.PARAMETER Interactive
    Open the VM's console window (vmconnect) so you can use the shell with
    the keyboard, and keep capturing COM1 until you turn the VM off (in the
    console window: Action > Turn Off, or close it and use Hyper-V Manager).
    -Seconds is ignored.

.PARAMETER UseLedger
    Continue the canonical ledger instead of a separate copy: build the VHD
    from evidence\ledger.img before the run (raw disk + the existing VHD's
    512-byte footer), and copy the result back to evidence\ledger.img
    afterwards (the previous ledger.img is kept as ledger.img.before-hyperv).
    Likewise the file system: evidence\fs.img (the FS image paired with that
    ledger; blank if missing) goes into fs-hyperv.vhd and comes back after,
    keeping fs.img.before-hyperv.
.NOTES
    Build the Hyper-V ISO (in WSL), e.g. with the boot self-tests on:
      ISO_ONLY=1 ISO_OUT=evidence/axiom-x-hyperv.iso KERNEL_CMDLINE= sh ./qemu-boot.sh
    or straight to the shell: KERNEL_CMDLINE=axiom.selftest=off

.EXAMPLE
    # From an elevated PowerShell in the axiom-x folder:
    powershell -ExecutionPolicy Bypass -File .\hyperv-run.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    [int]$Seconds = 90,
    [switch]$Cleanup,
    [switch]$Recreate,
    [switch]$Interactive,
    [switch]$UseLedger
)

$ErrorActionPreference = 'Stop'
$VmName   = 'Axiom-X'
$PipeName = 'axiomx-com1'
$Root     = $PSScriptRoot
$HvIso    = Join-Path $Root 'evidence\axiom-x-hyperv.iso'
$DbgIso   = Join-Path $Root 'evidence\axiom-x-dbg.iso'
$BuiltIso = if (Test-Path -LiteralPath $HvIso) { $HvIso } else { $DbgIso }
$HvDir    = Join-Path $Root 'evidence\hyperv'
$Iso      = Join-Path $HvDir 'axiom-x-dbg.iso'
$Vhd      = Join-Path $HvDir 'ledger-hyperv.vhd'
$FsVhd    = Join-Path $HvDir 'fs-hyperv.vhd'
$FsImg    = Join-Path $Root 'evidence\fs.img'
$FsSize   = 16MB
$VmDir    = Join-Path $HvDir 'vm'
$Ledger   = Join-Path $Root 'evidence\ledger.img'
$Log      = Join-Path $Root ("evidence\hyperv-serial-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd-HHmm'))

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
if ($BuiltIso -eq $DbgIso) {
    Write-Warning "Using ${DbgIso}: its kernel command line is whatever the last qemu-boot.sh run used. Build evidence\axiom-x-hyperv.iso to pin it (see .NOTES)."
}
Write-Host "ISO: $BuiltIso"

# A fixed VHD is the raw disk followed by a 512-byte footer that describes
# it (size, geometry); reuse the existing VHD's footer for the same size.
function Get-VhdFooter([string]$path, [long]$rawSize) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $footer = New-Object byte[] 512
    [Array]::Copy($bytes, $bytes.Length - 512, $footer, 0, 512)
    if ([System.Text.Encoding]::ASCII.GetString($footer, 0, 8) -ne 'conectix') { throw "$path has no VHD footer." }
    $size = [long]0
    for ($i = 48; $i -lt 56; $i++) { $size = ($size -shl 8) -bor $footer[$i] }  # current size, big-endian
    if ($size -ne $rawSize) { throw "VHD footer describes $size bytes, the ledger has $rawSize." }
    , $footer
}
if ($UseLedger) {
    if (-not (Test-Path -LiteralPath $Ledger)) { throw "Missing input: $Ledger" }
    $raw = [System.IO.File]::ReadAllBytes($Ledger)
    $footer = Get-VhdFooter $Vhd $raw.Length
    $image = New-Object byte[] ($raw.Length + 512)
    [Array]::Copy($raw, 0, $image, 0, $raw.Length)
    [Array]::Copy($footer, 0, $image, $raw.Length, 512)
    [System.IO.File]::WriteAllBytes($Vhd, $image)
    Write-Host "VHD rebuilt from $Ledger ($($raw.Length) bytes + footer)."
}

# File-system disk (primary slave). With -UseLedger it carries evidence\fs.img,
# the FS paired with the canonical ledger (its root hash is anchored there).
if ($UseLedger -and (Test-Path -LiteralPath $FsImg)) { $FsSize = (Get-Item -LiteralPath $FsImg).Length }
if ((Test-Path -LiteralPath $FsVhd) -and ((Get-Item -LiteralPath $FsVhd).Length -ne $FsSize + 512)) {
    Remove-Item -LiteralPath $FsVhd -Force
}
if (-not (Test-Path -LiteralPath $FsVhd)) {
    New-VHD -Path $FsVhd -SizeBytes $FsSize -Fixed | Out-Null
    Write-Host "Created blank file-system disk $FsVhd ($FsSize bytes)."
}
if ($UseLedger) {
    $fsRaw = if (Test-Path -LiteralPath $FsImg) { [System.IO.File]::ReadAllBytes($FsImg) } else { New-Object byte[] $FsSize }
    $fsFooter = Get-VhdFooter $FsVhd $fsRaw.Length
    $fsImage = New-Object byte[] ($fsRaw.Length + 512)
    [Array]::Copy($fsRaw, 0, $fsImage, 0, $fsRaw.Length)
    [Array]::Copy($fsFooter, 0, $fsImage, $fsRaw.Length, 512)
    [System.IO.File]::WriteAllBytes($FsVhd, $fsImage)
    Write-Host "FS VHD rebuilt from $(if (Test-Path -LiteralPath $FsImg) { $FsImg } else { 'a blank image' }) ($($fsRaw.Length) bytes + footer)."
}
foreach ($f in @($Iso, $Vhd, $FsVhd)) {
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
Add-VMHardDiskDrive -VMName $VmName -ControllerType IDE -ControllerNumber 0 -ControllerLocation 1 -Path $FsVhd
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
    if ($Interactive) {
        Write-Host "Starting VM; capturing COM1 until the VM is turned off -> $Log"
    } else {
        Write-Host "Starting VM; capturing COM1 for $Seconds s -> $Log"
    }
    Start-VM -Name $VmName
    # Hyper-V creates the pipe server when the VM starts; connect at once so
    # little or nothing of the boot output is missed.
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::In)
    $pipe.Connect(15000)
    $out = [System.IO.File]::Open($Log, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $buf = New-Object byte[] 4096
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $pending = $null
    if ($Interactive) {
        # The console window shows the VGA screen and sends keystrokes to
        # the emulated PS/2 keyboard.
        Start-Process vmconnect.exe -ArgumentList 'localhost', $VmName
    }
    $nextCheck = 0
    while ($Interactive -or $clock.Elapsed.TotalSeconds -lt $Seconds) {
        if ($Interactive -and $clock.Elapsed.TotalSeconds -ge $nextCheck) {
            $nextCheck = $clock.Elapsed.TotalSeconds + 1
            if ((Get-VM -Name $VmName).State -ne 'Running') { Write-Host "[VM turned off]"; break }
        }
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
    if ($UseLedger -and (Test-Path -LiteralPath $Vhd)) {
        # Carry the chain this boot extended back into the canonical ledger.
        $vhdBytes = [System.IO.File]::ReadAllBytes($Vhd)
        $rawBytes = New-Object byte[] ($vhdBytes.Length - 512)
        [Array]::Copy($vhdBytes, 0, $rawBytes, 0, $rawBytes.Length)
        Copy-Item -LiteralPath $Ledger -Destination "$Ledger.before-hyperv" -Force
        [System.IO.File]::WriteAllBytes($Ledger, $rawBytes)
        Write-Host "Ledger copied back to $Ledger (previous copy: ledger.img.before-hyperv)."
    }
    if ($UseLedger -and (Test-Path -LiteralPath $FsVhd)) {
        $fsBytes = [System.IO.File]::ReadAllBytes($FsVhd)
        $fsBack = New-Object byte[] ($fsBytes.Length - 512)
        [Array]::Copy($fsBytes, 0, $fsBack, 0, $fsBack.Length)
        if (Test-Path -LiteralPath $FsImg) { Copy-Item -LiteralPath $FsImg -Destination "$FsImg.before-hyperv" -Force }
        [System.IO.File]::WriteAllBytes($FsImg, $fsBack)
        Write-Host "File system copied back to $FsImg."
    }
}

Write-Host ""
Write-Host "Serial log : $Log"
Write-Host "Ledger VHD : $Vhd"
Write-Host "FS VHD     : $FsVhd"
Write-Host "Verify with: target\release\ledger-tool.exe verify `"$Vhd`" <public-key>"
if ($UseLedger) {
    Write-Host "        and: target\release\ledger-tool.exe fs-verify evidence\fs.img evidence\ledger.img <public-key>"
}
