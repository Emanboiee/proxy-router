# AST contract for the Windows installer and release smoke scripts.
#
# Run by tests/test_windows_install.py under any real pwsh (CI images ship
# one; locally: pwsh -File tests/windows_ast_contract.ps1 <repo-root>).
# This parses both scripts with the PowerShell parser and inspects the AST,
# so the cmd-launcher exit contract and the DACL assertion contract are
# checked on the actual string constants -- not on comments or prose.
param(
  [Parameter(Mandatory = $true)][string]$Root
)

$ErrorActionPreference = 'Stop'

function Get-ParsedAst {
  param([Parameter(Mandatory = $true)][string]$Path)
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
  if ($errors -and $errors.Count -gt 0) {
    $messages = ($errors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
    throw "parse errors in ${Path}: $messages"
  }
  return $ast
}

function Get-StringAsts {
  param($Ast, [Parameter(Mandatory = $true)][string]$Needle)
  return @($Ast.FindAll({
      param($node)
      (($node -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or
        ($node -is [System.Management.Automation.Language.ExpandableStringExpressionAst])) -and
      $node.Value.Contains($Needle)
    }, $true))
}

function Assert-Match {
  param([string]$Text, [string]$Pattern, [string]$Message)
  if ($Text -notmatch $Pattern) { throw $Message }
}

function Assert-NotMatch {
  param([string]$Text, [string]$Pattern, [string]$Message)
  if ($Text -match $Pattern) { throw $Message }
}

$installPath = Join-Path $Root 'install.ps1'
$smokePath = Join-Path $Root '.github/scripts/windows-release-smoke.ps1'
$installAst = Get-ParsedAst $installPath
$smokeAst = Get-ParsedAst $smokePath

# ---------------------------------------------------------------------------
# install.ps1: generated .cmd launcher must propagate the runtime exit code.
# `%ERRORLEVEL%` inside a parenthesised ( ... ) block is expanded when cmd
# parses the block -- usually to 0 -- so a failing router.py looked healthy.
# ---------------------------------------------------------------------------
$launcherNodes = Get-StringAsts $installAst '@echo off'
if ($launcherNodes.Count -ne 1) {
  throw "install.ps1: expected exactly one embedded .cmd launcher, found $($launcherNodes.Count)"
}
$launcher = $launcherNodes[0].Value
Assert-NotMatch $launcher '(?m)^\s*if .*\(\s*$' `
  'the .cmd launcher must not expand exit codes inside grouped branches'
Assert-Match $launcher '(?m)^:python_fallback\s*$' 'missing Python fallback label'
$exits = [regex]::Matches($launcher, '(?m)^exit /b %ERRORLEVEL%\s*$')
if ($exits.Count -ne 2) {
  throw 'both launcher branches must explicitly propagate the child exit code'
}

# ---------------------------------------------------------------------------
# windows-release-smoke.ps1: DACL assertion contract.
#   explicit entries (install root, providers, router.json): protected DACL,
#     no inherited ACEs left;
#   generated children (sing-box.json, provider profiles): UNPROTECTED and
#     fully inherited -- requiring protection there failed every clean install.
# ---------------------------------------------------------------------------
$fnNodes = $smokeAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-PrivateAcl'
  }, $true)
if ($fnNodes.Count -ne 1) {
  throw "smoke script: expected exactly one Assert-PrivateAcl function, found $($fnNodes.Count)"
}
$fn = $fnNodes[0].Extent.Text
Assert-Match $fn 'if \(\$ExpectInherited\)' 'Assert-PrivateAcl must branch on -ExpectInherited'
Assert-Match $fn '-not \$acl\.AreAccessRulesProtected' `
  'generated (inherited) entries must be asserted UNPROTECTED'
Assert-Match $fn 'Assert-True \$acl\.AreAccessRulesProtected' `
  'explicit entries must be asserted protected'
Assert-Match $fn 'Assert-True \$rule\.IsInherited' `
  'inherited entries must require inherited ACEs'
Assert-Match $fn 'Assert-True \(-not \$rule\.IsInherited\)' `
  'explicit entries must reject leftover inherited ACEs'

# ---------------------------------------------------------------------------
# windows-release-smoke.ps1: fresh-shell wrappers + forced-branch stubs.
# Every cmd wrapper explicitly propagates the child exit code, and the nonzero
# probe (argparse exit 2 through both launcher branches) is present.
# ---------------------------------------------------------------------------
$wrapperNodes = Get-StringAsts $smokeAst '@echo off'
if ($wrapperNodes.Count -lt 1) {
  throw 'smoke script: expected at least one embedded cmd wrapper'
}
foreach ($node in $wrapperNodes) {
  Assert-Match $node.Value '(?m)^exit /b %ERRORLEVEL%\s*$' `
    'smoke cmd wrapper must propagate the child exit code on its own line'
}
$smokeText = $smokeAst.Extent.Text
foreach ($needle in @("'--no-such-flag'", 'wscript.exe', 'py.vbs', 'invoked.marker', 'exit propagation')) {
  if (-not $smokeText.Contains($needle)) {
    throw "smoke script is missing the exit-propagation probe: $needle"
  }
}

Write-Host 'AST contract ok: install.ps1 launcher + smoke DACL/propagation assertions'
