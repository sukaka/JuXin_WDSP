#Requires -Version 5.1
<#
.SYNOPSIS
  九章 WDSP 分布式流量采集 Agent Windows 卸载脚本。
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\JiuZhang\WDSPAgent",
    [string]$ConfigPath = "",
    [string]$StateDir = "",
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以管理员身份运行 PowerShell 执行卸载。"
}

$agentExe = Join-Path $InstallDir "wdsp-agent.exe"
if (Test-Path -LiteralPath $agentExe) {
    $argsList = @("uninstall")
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $argsList += @("--config", $ConfigPath) }
    if (-not [string]::IsNullOrWhiteSpace($StateDir)) { $argsList += @("--state-dir", $StateDir) }
    if ($Purge) { $argsList += "--purge" }
    & $agentExe @argsList
    if ($LASTEXITCODE -ne 0) {
        throw "wdsp-agent.exe uninstall 失败: exit=$LASTEXITCODE"
    }
} else {
    $svc = Get-Service -Name "WDSPAgent" -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        Stop-Service -Name "WDSPAgent" -Force -ErrorAction SilentlyContinue
        sc.exe delete WDSPAgent | Out-Null
    }
}

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "[wdsp-agent-uninstall] Windows Agent 卸载完成。"
