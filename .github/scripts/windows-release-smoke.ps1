<#
.SYNOPSIS
Clean-install smoke test for the extracted Windows release bundle (issue #67).

.DESCRIPTION
Expands the published zip into a throwaway prefix, installs it with the
bundle's own install.ps1 (with LOCALAPPDATA redirected so the developer
profile and user PATH are untouched), then exercises the installed launchers
from a fresh cmd.exe shell:

  * proxy-router.cmd --help
  * proxy-router.ps1 --help
  * proxy-router.cmd status --json, parsed as JSON

The extracted bundle is deleted before the launcher runs, so the launcher must
resolve router.py from the installed prefix. The engine is never started: this
script runs no start/ensure/vpn/system-proxy command and only reads status.

It also verifies the installer's private DACL on router.json, the install root
and the providers directory, plus inheritance for files the engine generates
later (sing-box.json and provider profiles), because those are created after
install.ps1 has run.

.PARAMETER Archive
Path to the published proxy-router-<version>-windows-<arch>.zip.

.PARAMETER WorkRoot
Optional scratch directory. Defaults to a unique directory under RUNNER_TEMP.

.PARAMETER KeepWorkRoot
Keep the scratch directory (install log, parsed launcher output) for debugging.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Archive,
  [string]$WorkRoot,
  [switch]$KeepWorkRoot
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# SYSTEM and Administrators: the only non-owner principals the installer grants.
$AllowedPrivateSids = @('S-1-5-18', 'S-1-5-32-544')

function Write-Step {
  param([string]$Message)
  Write-Host "==> $Message"
}

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Assert-OutputContains {
  param([string]$Text, [string]$Needle, [string]$Label)
  if (-not $Text.ToLowerInvariant().Contains($Needle.ToLowerInvariant())) {
    throw "${Label}: expected output to contain '$Needle'; got:`n$Text"
  }
}

function Get-PrincipalSid {
  param([System.Security.Principal.IdentityReference]$Identity)
  return $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Assert-PrivateAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label,
    [switch]$ExpectInherited
  )
  Assert-True (Test-Path -LiteralPath $Path) "$Label does not exist: $Path"
  $acl = Get-Acl -LiteralPath $Path
  if ($ExpectInherited) {
    # Files the engine generates later (sing-box.json, provider profiles) are
    # created inside the protected install root, so their own DACL stays
    # UNPROTECTED and every ACE is copied down from the parent. Requiring
    # protection here would fail every clean install.
    Assert-True (-not $acl.AreAccessRulesProtected) `
      "$Label must keep inheriting its parent DACL: $Path"
  }
  else {
    # The install root, providers directory and router.json are locked down
    # explicitly by install.ps1: the DACL must be protected, and it must have
    # discarded the broad inherited grants instead of keeping them.
    Assert-True $acl.AreAccessRulesProtected "$Label still inherits its parent DACL: $Path"
  }

  $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowed = @($current) + $AllowedPrivateSids
  $seen = New-Object System.Collections.Generic.List[string]
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = Get-PrincipalSid -Identity $rule.IdentityReference
    $seen.Add($sid) | Out-Null
    Assert-True ($allowed -contains $sid) "$Label grants access to unexpected SID $sid ($($rule.IdentityReference))"
    if ($ExpectInherited) {
      Assert-True $rule.IsInherited "$Label has an explicit ACE for $sid; generated private files must inherit the installer DACL"
    }
    else {
      Assert-True (-not $rule.IsInherited) "$Label still carries an inherited ACE for $sid; explicit entries must be protected"
    }
  }
  foreach ($required in @($current, 'S-1-5-18')) {
    Assert-True ($seen -contains $required) "$Label is missing its $required allow ACE"
  }
  Write-Host "    ACL ok: $Label"
}

function Invoke-FreshShell {
  <#
    Run a command from a new child shell with PROXY_ROUTER_ROOT removed, so the
    launcher must resolve its own root instead of leaking the caller's value.
  #>
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory
  )
  $savedRoot = $env:PROXY_ROUTER_ROOT
  Remove-Item Env:PROXY_ROUTER_ROOT -ErrorAction SilentlyContinue
  try {
    Push-Location -LiteralPath $WorkingDirectory
    try {
      $output = & $FilePath @Arguments | Out-String
      $exitCode = $LASTEXITCODE
    }
    finally {
      Pop-Location
    }
  }
  finally {
    if ($null -ne $savedRoot) { $env:PROXY_ROUTER_ROOT = $savedRoot }
  }
  if ($null -eq $output) { $output = '' }
  return [pscustomobject]@{ ExitCode = $exitCode; Output = $output.TrimEnd() }
}

Assert-True (Test-Path -LiteralPath $Archive -PathType Leaf) "release archive not found: $Archive"
$archivePath = (Resolve-Path -LiteralPath $Archive).Path

$runnerTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
if (-not $WorkRoot) {
  $WorkRoot = Join-Path $runnerTemp ('proxy-router-win-smoke-' + [guid]::NewGuid().ToString('N'))
}
$work = [System.IO.Path]::GetFullPath($WorkRoot)
New-Item -ItemType Directory -Force -Path $work | Out-Null

$savedLocalAppData = $env:LOCALAPPDATA
try {
  $extract = Join-Path $work 'extract'
  $shellDir = Join-Path $work 'shell'
  $localAppData = Join-Path $work 'localappdata'
  $dest = Join-Path $localAppData 'proxy-router'
  New-Item -ItemType Directory -Force -Path $extract, $shellDir, $localAppData | Out-Null

  Write-Step "Extracting $archivePath"
  Expand-Archive -LiteralPath $archivePath -DestinationPath $extract -Force
  $bundle = Join-Path $extract 'proxy-router'
  Assert-True (Test-Path -LiteralPath (Join-Path $bundle 'install.ps1') -PathType Leaf) `
    'archive did not contain proxy-router/install.ps1'

  Write-Step "Installing with install.ps1 into $dest"
  # A fresh LOCALAPPDATA is the installer's only root knob; the PATH opt-in
  # switch is deliberately omitted so the smoke run never edits user PATH.
  $env:LOCALAPPDATA = $localAppData
  Remove-Item Env:PROXY_ROUTER_ROOT -ErrorAction SilentlyContinue
  $installLog = Join-Path $work 'install.log'
  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File (Join-Path $bundle 'install.ps1') *> $installLog
  $installCode = $LASTEXITCODE
  Get-Content -LiteralPath $installLog | ForEach-Object { Write-Host "    $_" }
  Assert-True ($installCode -eq 0) "install.ps1 exited $installCode"

  Write-Step 'Checking the installed layout'
  foreach ($relative in @(
      'router.py',
      'router.json',
      'README.md',
      'providers',
      'examples\proxy-manager.sh',
      'bin\proxy-router.cmd',
      'bin\proxy-router.ps1',
      'bin\proxy-router-keepalive.ps1',
      'bin\sing-box.exe'
    )) {
    Assert-True (Test-Path -LiteralPath (Join-Path $dest $relative)) "installer did not create $relative"
  }
  $config = Get-Content -LiteralPath (Join-Path $dest 'router.json') -Raw | ConvertFrom-Json
  Assert-True ($config.port -ge 1 -and $config.port -le 65535) "installed router.json has invalid port $($config.port)"
  $vpnProperty = $config.PSObject.Properties['vpn']
  $expectedMode = 'proxy'
  if ($null -ne $vpnProperty -and $null -ne $vpnProperty.Value -and
    $null -ne $vpnProperty.Value.PSObject.Properties['default_mode']) {
    $expectedMode = $vpnProperty.Value.default_mode
  }
  $routingProperty = $config.PSObject.Properties['routing']
  $expectedRouting = 'default'
  if ($null -ne $routingProperty -and $null -ne $routingProperty.Value -and
    $null -ne $routingProperty.Value.PSObject.Properties['mode']) {
    $expectedRouting = $routingProperty.Value.mode
  }

  Write-Step 'Verifying installer DACLs and generated-file inheritance'
  Assert-PrivateAcl -Path $dest -Label 'install root'
  Assert-PrivateAcl -Path (Join-Path $dest 'providers') -Label 'providers directory'
  Assert-PrivateAcl -Path (Join-Path $dest 'router.json') -Label 'router.json'

  # The engine config holds every WireGuard private key, and provider profiles
  # are copied in after install. Recreate those paths now and require the
  # installer's inherited DACL, not a broad profile-directory default.
  $generatedConfig = Join-Path $dest 'sing-box.json'
  Set-Content -LiteralPath $generatedConfig -Value '{}' -Encoding ASCII
  $profileDir = Join-Path $dest 'providers\smoke'
  New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
  $profileFile = Join-Path $profileDir 'profile.conf'
  Set-Content -LiteralPath $profileFile -Value '[Interface]' -Encoding ASCII
  Assert-PrivateAcl -Path $generatedConfig -Label 'generated sing-box.json' -ExpectInherited
  Assert-PrivateAcl -Path $profileFile -Label 'generated provider profile' -ExpectInherited
  Remove-Item -LiteralPath $generatedConfig -Force
  Remove-Item -LiteralPath $profileDir -Recurse -Force

  Write-Step 'Deleting the extracted bundle (launcher must be self-contained)'
  Remove-Item -LiteralPath $extract -Recurse -Force

  $cmdLauncher = Join-Path $dest 'bin\proxy-router.cmd'
  $psLauncher = Join-Path $dest 'bin\proxy-router.ps1'
  $wrapper = Join-Path $shellDir 'fresh-cmd.cmd'
  # Bare `exit /b` preserves the current ERRORLEVEL; `%ERRORLEVEL%` would be
  # expanded when cmd parses a line, which is a foot-gun next to `call`.
  @"
@echo off
set "PROXY_ROUTER_ROOT="
call "$cmdLauncher" %*
exit /b
"@ | Set-Content -LiteralPath $wrapper -Encoding ASCII

  Write-Step 'Running installed proxy-router.cmd --help from a fresh shell'
  $help = Invoke-FreshShell -FilePath $wrapper -Arguments @('--help') -WorkingDirectory $shellDir
  Assert-True ($help.ExitCode -eq 0) "proxy-router.cmd --help exited $($help.ExitCode)`n$($help.Output)"
  Assert-OutputContains $help.Output 'usage:' 'proxy-router.cmd --help'
  Assert-OutputContains $help.Output 'selective WireGuard proxy router' 'proxy-router.cmd --help'

  Write-Step 'Running installed proxy-router.ps1 --help from a fresh shell'
  $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
  $psHelp = Invoke-FreshShell -FilePath $powershell -WorkingDirectory $shellDir `
    -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $psLauncher, '--help')
  Assert-True ($psHelp.ExitCode -eq 0) "proxy-router.ps1 --help exited $($psHelp.ExitCode)`n$($psHelp.Output)"
  Assert-OutputContains $psHelp.Output 'usage:' 'proxy-router.ps1 --help'

  Write-Step 'Running installed proxy-router.cmd status --json (engine not started)'
  $statusResult = Invoke-FreshShell -FilePath $wrapper -Arguments @('status', '--json') -WorkingDirectory $shellDir
  # A clean install has no running engine, so a healthy read-only status exits 1
  # with the full JSON document; 0 means an engine is already up on this host.
  Assert-True ($statusResult.ExitCode -eq 0 -or $statusResult.ExitCode -eq 1) `
    "status --json exited $($statusResult.ExitCode); expected 0 (up) or 1 (down)`n$($statusResult.Output)"
  $status = $null
  try {
    $status = $statusResult.Output | ConvertFrom-Json
  }
  catch {
    throw "status --json did not emit parseable JSON: $($_.Exception.Message)`n$($statusResult.Output)"
  }
  foreach ($name in 'up', 'state', 'mode', 'port', 'providers', 'routes', 'routing', 'schema_version', 'system_proxy') {
    Assert-True ($null -ne $status.PSObject.Properties[$name]) "status --json is missing '$name'"
  }
  Assert-True ($status.port -eq $config.port) "status --json reported port $($status.port); installed router.json says $($config.port)"
  Assert-True ($status.mode -eq $expectedMode) "status --json reported mode '$($status.mode)'; expected '$expectedMode'"
  Assert-True (-not $status.up) "a clean install must not report a running engine: $($status.state)"
  Assert-True ($status.routing.mode -eq $expectedRouting) `
    "status --json reported routing.mode '$($status.routing.mode)'; installed router.json says '$expectedRouting'"
  Assert-True ([int]$status.schema_version -ge 1) 'status --json reported an invalid schema_version'
  Assert-True ($status.system_proxy.status -eq 'skipped') `
    "status --json touched system proxy state on Windows: '$($status.system_proxy.status)'"
  Assert-True (-not (Test-Path -LiteralPath (Join-Path $dest 'sing-box.pid'))) `
    'status --json started the engine (sing-box.pid exists)'
  Assert-True (-not (Test-Path -LiteralPath (Join-Path $dest 'sing-box.json'))) `
    'status --json generated sing-box.json; a status read must stay read-only'

  # Exit-code propagation through cmd.exe. argparse rejects unknown flags with
  # exit 2; a launcher that swallows it (e.g. `%ERRORLEVEL%` expanded when cmd
  # parses a parenthesised block, usually to 0) turns every failure green.
  Write-Step 'Running installed proxy-router.cmd --no-such-flag (exit propagation)'
  $bad = Invoke-FreshShell -FilePath $wrapper -Arguments @('--no-such-flag') -WorkingDirectory $shellDir
  Assert-True ($bad.ExitCode -eq 2) `
    "proxy-router.cmd --no-such-flag must exit 2 through the launcher; got $($bad.ExitCode)`n$($bad.Output)"

  # Force BOTH launcher branches. cmd resolves `py` through PATHEXT, and a
  # wscript-hosted stub returns to the caller (unlike a .cmd stub, which would
  # chain and never return), so each wrapper deterministically drives one
  # branch of the generated launcher and must still hand back exit code 2.
  $wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
  if (Test-Path -LiteralPath $wscript) {
    Write-Step 'Running both .cmd launcher branches (py branch and python fallback)'
    $pyOk = Join-Path $work 'py-stub-probe-ok'
    $pyFail = Join-Path $work 'py-stub-probe-fail'
    New-Item -ItemType Directory -Force -Path $pyOk, $pyFail | Out-Null
    # `py -3 <args...>` stub: drop -3, run python with the rest, keep its code.
    # The marker file proves to the launcher's caller that `where py` really
    # resolved this stub, i.e. that the intended branch was the one exercised.
    $stubSource = @'
Option Explicit
Dim fso, here, ts, i, rest, shell, rc
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
Set ts = fso.CreateTextFile(here & "\invoked.marker", True)
ts.Close
If WScript.Arguments.Count = 0 Then WScript.Quit 96
If WScript.Arguments(0) <> "-3" Then WScript.Quit 96
rest = ""
For i = 1 To WScript.Arguments.Count - 1
  rest = rest & " """ & WScript.Arguments(i) & """"
Next
Set shell = CreateObject("WScript.Shell")
rc = shell.Run("python" & rest, 0, True)
WScript.Quit rc
'@
    Set-Content -LiteralPath (Join-Path $pyOk 'py.vbs') -Value $stubSource -Encoding ASCII
    # A probe that fails forces the launcher past the parenthesised block.
    $failSource = @'
Option Explicit
Dim fso, ts
Set fso = CreateObject("Scripting.FileSystemObject")
Set ts = fso.CreateTextFile(fso.GetParentFolderName(WScript.ScriptFullName) & "\invoked.marker", True)
ts.Close
WScript.Quit 1
'@
    Set-Content -LiteralPath (Join-Path $pyFail 'py.vbs') -Value $failSource -Encoding ASCII

    foreach ($branch in @(
        @{ Name = 'py-branch'; Stub = $pyOk; Why = 'probe passed: the parenthesised py branch must return the child exit code' },
        @{ Name = 'python-fallback'; Stub = $pyFail; Why = 'probe failed: the fallback branch must return the child exit code' }
      )) {
      $branchWrapper = Join-Path $shellDir ("fresh-cmd-" + $branch.Name + ".cmd")
      @"
@echo off
set "PROXY_ROUTER_ROOT="
set "PATH=$($branch.Stub);%PATH%"
call "$cmdLauncher" %*
exit /b
"@ | Set-Content -LiteralPath $branchWrapper -Encoding ASCII
      $branchResult = Invoke-FreshShell -FilePath $branchWrapper -Arguments @('--no-such-flag') -WorkingDirectory $shellDir
      $marker = Join-Path $branch.Stub 'invoked.marker'
      Assert-True (Test-Path -LiteralPath $marker) `
        "proxy-router.cmd ($($branch.Name)): the stub was never invoked -- cmd did not resolve py through PATHEXT, so this branch was not exercised"
      Assert-True ($branchResult.ExitCode -eq 2) `
        "proxy-router.cmd ($($branch.Name)): expected exit 2 propagated; got $($branchResult.ExitCode) -- $($branch.Why)`n$($branchResult.Output)"
      Write-Host "    exit propagation ok: $($branch.Name)"
    }
  }
  else {
    Write-Warning 'wscript.exe not found; skipping forced-branch exit propagation checks'
  }

  Write-Host ''
  Write-Host "windows clean-install CLI smoke passed: $dest"
}
finally {
  if ($null -ne $savedLocalAppData) { $env:LOCALAPPDATA = $savedLocalAppData }
  if ($KeepWorkRoot) {
    Write-Host "kept smoke work root: $work"
  }
  else {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}
