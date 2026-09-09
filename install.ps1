<#
proxy-router installer for Windows (PowerShell 5.1+, no extra modules).

Installs router.py, the bundled sing-box.exe, the config example, docs and a
copy of this script into $env:LOCALAPPDATA\proxy-router. Idempotent: rerunning
never clobbers an existing router.json.

Pass -SetPath to append "$Dest\bin" to the user PATH (takes effect in new
shells only); by default the script only prints the hint and never touches
PATH silently.
#>
param(
  [switch]$SetPath
)

$ErrorActionPreference = 'Stop'

$Dest = Join-Path $env:LOCALAPPDATA 'proxy-router'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Dest 'bin'

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'providers') | Out-Null
foreach ($Name in @('examples', 'guides', 'rulesets')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $Dest $Name) | Out-Null
}

foreach ($Name in @('router.py', 'setup_tui.py', 'monitor.py', 'route_watcher.py', 'proxy_tray.py')) {
  Copy-Item (Join-Path $ScriptDir $Name) -Destination $Dest -Force
}
Copy-Item (Join-Path $ScriptDir 'router.example.json') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'README.md') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'LICENSE') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'install.ps1') -Destination $Dest -Force

# Examples and bundled data are defaults. Preserve any user-customized file
# already present in the destination on an installer rerun.
foreach ($Directory in @('examples', 'guides', 'presets', 'rulesets')) {
  $SourceDirectory = Join-Path $ScriptDir $Directory
  $DestinationDirectory = Join-Path $Dest $Directory
  if (Test-Path -LiteralPath $SourceDirectory -PathType Container) {
    Get-ChildItem -LiteralPath $SourceDirectory -Force | ForEach-Object {
      $Target = Join-Path $DestinationDirectory $_.Name
      if (-not (Test-Path -LiteralPath $Target)) {
        Copy-Item $_.FullName -Destination $Target -Recurse
      }
    }
  }
  else {
    Write-Verbose "Optional resource directory is not present in this bundle: $Directory"
  }
}

# Install a native Windows command entry point instead of adding only the
# engine directory to PATH.  The launcher resolves router.py relative to the
# installed prefix, so it remains valid after the source archive is removed.
$LauncherCmd = Join-Path $Bin 'proxy-router.cmd'
@'
@echo off
set "PROXY_ROUTER_ROOT=%~dp0.."
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%PROXY_ROUTER_ROOT%\router.py" %*
  exit /b %ERRORLEVEL%
)
python "%PROXY_ROUTER_ROOT%\router.py" %*
exit /b %ERRORLEVEL%
'@ | Set-Content -LiteralPath $LauncherCmd -Encoding ASCII

$LauncherPs1 = Join-Path $Bin 'proxy-router.ps1'
@'
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$env:PROXY_ROUTER_ROOT = Split-Path -Parent $PSScriptRoot
$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
  & $py.Source -3 (Join-Path $env:PROXY_ROUTER_ROOT 'router.py') @Arguments
} else {
  & python (Join-Path $env:PROXY_ROUTER_ROOT 'router.py') @Arguments
}
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $LauncherPs1 -Encoding UTF8

# Stock Windows has no launchd/systemd equivalent.  Ship a PowerShell
# supervisor that Task Scheduler can invoke without requiring Bash.
$KeepalivePs1 = Join-Path $Bin 'proxy-router-keepalive.ps1'
@'
[CmdletBinding()]
param([ValidateRange(1, 86400)][int]$Interval = 15)
$launcher = Join-Path $PSScriptRoot 'proxy-router.ps1'
while ($true) {
  & $launcher ensure
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "proxy-router ensure failed with exit code $LASTEXITCODE"
  }
  Start-Sleep -Seconds $Interval
}
'@ | Set-Content -LiteralPath $KeepalivePs1 -Encoding UTF8

$SingBox = Join-Path $ScriptDir 'bin\sing-box.exe'
if (Test-Path $SingBox) {
  Copy-Item $SingBox -Destination $Bin -Force
}
else {
  Write-Host "Warning: no bundled sing-box.exe at $SingBox; rely on SING_BOX/PATH at runtime."
}

$Config = Join-Path $Dest 'router.json'
if (-not (Test-Path $Config)) {
  Copy-Item (Join-Path $ScriptDir 'router.example.json') -Destination $Config
  Write-Host "Created $Config from the example template."
}
else {
  Write-Host 'router.json already exists; leaving it untouched.'
}

if ($SetPath) {
  $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $UserPath -or $UserPath -notlike "*$Bin*") {
    $NewPath = if ($UserPath) { "$Bin;$UserPath" } else { $Bin }
    [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    Write-Host "Added $Bin to your user PATH (takes effect in new shells)."
  }
  else {
    Write-Host "$Bin is already on your user PATH."
  }
}
else {
  Write-Host "PATH hint: add `"$Bin`" to your PATH, or re-run with -SetPath."
}

function Set-PrivateAcl {
  param([Parameter(Mandatory = $true)][string]$Path, [switch]$Directory)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = if ($Directory) {
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else { [System.Security.AccessControl.InheritanceFlags]::None }
  $propagate = if ($Directory) {
    [System.Security.AccessControl.PropagationFlags]::None
  } else { [System.Security.AccessControl.PropagationFlags]::None }
  $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $full = [System.Security.AccessControl.FileSystemRights]::FullControl
  $read = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
  foreach ($entry in @(@($current, $full), @($system, $full), @($admins, $read))) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
      $entry[0], $entry[1], $inherit, $propagate,
      [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.SetAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}

# Keep mutable state and WireGuard material readable only by the installing
# user, SYSTEM, and administrators.  The explicit ACL also removes inherited
# broad grants that are common on user profile directories.
Set-PrivateAcl -Path $Dest -Directory
Set-PrivateAcl -Path (Join-Path $Dest 'providers') -Directory
Set-PrivateAcl -Path $Config
foreach ($Name in @('sing-box.json.last-good', 'sing-box.pid')) {
  Set-PrivateAcl -Path (Join-Path $Dest $Name)
}

$Wintun = Join-Path $Bin 'wintun.dll'
if (-not (Test-Path -LiteralPath $Wintun)) {
  Write-Warning "wintun.dll is not bundled. Proxy mode works, but Windows TUN mode requires wintun.dll beside sing-box.exe."
}

Write-Host ''
Write-Host "proxy-router installed to $Dest"
Write-Host 'Usage (requires Python 3.10+):'
Write-Host "  & `"$Dest\router.py`" setup --check   # validate router.json (already created by this installer)"
Write-Host "  & `"$Dest\router.py`" ensure          # start the engine if the listener is down"
Write-Host "  & `"$Dest\router.py`" status"
Write-Host "  & `"$Dest\router.py`" routes"
Write-Host "  & `"$Bin\proxy-router.cmd`" status      # callable from a fresh shell when -SetPath is used"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$Bin\proxy-router-keepalive.ps1`""
Write-Host "Add providers: drop WireGuard configs into $Dest\providers\<provider>\<profile>.conf"
Write-Host "Or import one:  & `"$Dest\router.py`" setup --import-proton <profile.conf>"
Write-Host 'Python 3.10+ is required (python.org); sing-box is bundled as sing-box.exe.'
