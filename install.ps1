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
foreach ($Name in @('examples', 'guides', 'presets', 'rulesets')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $Dest $Name) | Out-Null
}

foreach ($Name in @('router.py', 'setup_tui.py', 'monitor.py', 'route_watcher.py', 'proxy_tray.py')) {
  Copy-Item (Join-Path $ScriptDir $Name) -Destination $Dest -Force
}
Copy-Item (Join-Path $ScriptDir 'keepalive.sh') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'router.example.json') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'README.md') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'LICENSE') -Destination $Dest -Force
Copy-Item (Join-Path $ScriptDir 'install.ps1') -Destination $Dest -Force

# Examples and bundled data are defaults. Preserve any user-customized file
# already present in the destination on an installer rerun.
foreach ($Directory in @('examples', 'guides', 'presets', 'rulesets')) {
  $SourceDirectory = Join-Path $ScriptDir $Directory
  $DestinationDirectory = Join-Path $Dest $Directory
  Get-ChildItem -LiteralPath $SourceDirectory -Force | ForEach-Object {
    $Target = Join-Path $DestinationDirectory $_.Name
    if (-not (Test-Path -LiteralPath $Target)) {
      Copy-Item $_.FullName -Destination $Target -Recurse
    }
  }
}

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

Write-Host ''
Write-Host "proxy-router installed to $Dest"
Write-Host 'Usage (requires Python 3.10+):'
Write-Host "  & `"$Dest\router.py`" init"
Write-Host "  & `"$Dest\router.py`" ensure"
Write-Host "  & `"$Dest\router.py`" status"
Write-Host "  & `"$Dest\router.py`" routes"
Write-Host "Add providers: drop WireGuard configs into $Dest\providers\<provider>\<profile>.conf"
Write-Host 'Python 3.10+ is required (python.org); sing-box is bundled as sing-box.exe.'