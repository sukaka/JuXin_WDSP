#Requires -Version 5.1
<#
.SYNOPSIS
  九章 WDSP 分布式流量采集 Agent Windows 安装脚本（PowerShell 5.1+）。

.DESCRIPTION
  支持从 WDSP 管理面通过一次性 Enrollment Token（Header 鉴权，不放 URL 参数）下载并校验
  SHA-256 后安装，或使用 -LocalPackage 纯离线安装；随后调用 wdsp-agent.exe install 完成
  机器证书注册、NTFS DACL 权限隔离与原生 Windows Service（WDSPAgent）启动。
#>
[CmdletBinding()]
param(
    [string]$Server = "",
    [string]$TokenFile = "",
    [string]$LocalPackage = "",
    [string]$ExpectedSha256 = "",
    [string]$InstallDir = "$env:ProgramFiles\JiuZhang\WDSPAgent",
    [string]$ConfigPath = "",
    [string]$StateDir = "",
    [ValidateSet("", "auto", "npcap", "rawsocket")]
    [string]$Backend = "",
    [ValidateSet("", "amd64", "arm64")]
    [string]$Arch = "",
    [switch]$InsecureSkipVerify,
    [switch]$ForceReenroll,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$Msg) { Write-Host "[wdsp-agent-install] $Msg" }
function Write-Warn([string]$Msg) { Write-Warning "[wdsp-agent-install] $Msg" }

# 1. 强制检查管理员权限
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以“以管理员身份运行”打开 PowerShell 后执行本安装脚本。"
}

# PowerShell 5.1 默认可能未启 TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($InsecureSkipVerify) {
    Write-Warn "已启用 -InsecureSkipVerify（仅限自签证书实验环境，生产环境禁止跳过 TLS 校验）"
    if (-not ("WdspTrustAllCerts" -as [type])) {
        Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class WdspTrustAllCerts {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback = delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) { return true; };
    }
}
"@
    }
    [WdspTrustAllCerts]::Enable()
}

# 2. 检测架构
if ([string]::IsNullOrWhiteSpace($Arch)) {
    $procArch = ($env:PROCESSOR_ARCHITECTURE + "").ToUpperInvariant()
    switch ($procArch) {
        "AMD64" { $Arch = "amd64" }
        "ARM64" { $Arch = "arm64" }
        default { throw "不支持的 Windows CPU 架构: $procArch" }
    }
}

# 3. 解析一次性注册令牌（-TokenFile 优先于 WDSP_ENROLL_TOKEN 环境变量）
$enrollToken = ""
if (-not [string]::IsNullOrWhiteSpace($TokenFile)) {
    if (-not (Test-Path -LiteralPath $TokenFile)) {
        throw "无法读取 -TokenFile: $TokenFile"
    }
    $enrollToken = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:WDSP_ENROLL_TOKEN)) {
    $enrollToken = $env:WDSP_ENROLL_TOKEN.Trim()
}

if (-not [string]::IsNullOrWhiteSpace($Server)) {
    $Server = $Server.Trim().TrimEnd("/")
    if ($Server -notmatch '^(?i)https?://') {
        $Server = "https://$Server"
    }
}

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wdsp-agent-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    $zipFile = ""
    if (-not [string]::IsNullOrWhiteSpace($LocalPackage)) {
        if (-not (Test-Path -LiteralPath $LocalPackage)) {
            throw "离线安装包不存在: $LocalPackage"
        }
        $zipFile = (Resolve-Path -LiteralPath $LocalPackage).Path
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
            $actual = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $ExpectedSha256.Trim().ToLowerInvariant()) {
                throw "离线包 SHA-256 校验失败: actual=$actual expected=$ExpectedSha256"
            }
            Write-Info "离线包 SHA-256 校验通过: $actual"
        }
    } else {
        if ([string]::IsNullOrWhiteSpace($Server)) {
            throw "在线安装必须指定 -Server https://<WDSP管理面地址>"
        }
        if ([string]::IsNullOrWhiteSpace($enrollToken)) {
            throw "在线安装必须通过环境变量 WDSP_ENROLL_TOKEN 或 -TokenFile 提供一次性注册令牌"
        }
        $baseUrl = $Server.TrimEnd("/")
        $pkgUrl = "$baseUrl/api/v1/agents/bootstrap/packages/windows/$Arch/zip"
        $zipFile = Join-Path $workDir "wdsp-agent-windows-$Arch.zip"

        Write-Info "正在从 $baseUrl 拉取 windows/$Arch/zip 安装包..."
        $req = [System.Net.HttpWebRequest]::Create($pkgUrl)
        $req.Method = "GET"
        $req.Timeout = 300000
        $req.Headers.Add("Authorization", "Bearer $enrollToken")
        $resp = $req.GetResponse()
        try {
            $srvSha = ($resp.Headers["X-WDSP-SHA256"] + "").Trim().ToLowerInvariant()
            if ($srvSha.Length -ne 64) {
                throw "服务端响应缺少合法 X-WDSP-SHA256 校验头，已中止安装"
            }
            $stream = $resp.GetResponseStream()
            $fs = [System.IO.File]::Create($zipFile)
            try { $stream.CopyTo($fs) } finally { $fs.Dispose(); $stream.Dispose() }
        } finally {
            $resp.Dispose()
        }

        $actualSha = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSha -ne $srvSha) {
            throw "安装包 SHA-256 校验不匹配: actual=$actualSha expected=$srvSha"
        }
        Write-Info "下载并校验通过 (windows/$Arch/zip): sha256=$actualSha"
    }

    # 4. 如果已有服务在运行，先停止以释放 wdsp-agent.exe 文件锁
    $existingSvc = Get-Service -Name "WDSPAgent" -ErrorAction SilentlyContinue
    if ($null -ne $existingSvc -and $existingSvc.Status -ne "Stopped") {
        Write-Info "检测到已有运行中的 WDSPAgent 服务，正在停止以便更新二进制..."
        Stop-Service -Name "WDSPAgent" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # 5. 解压并部署到目标安装目录
    $extractDir = Join-Path $workDir "extract"
    Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force
    $exeSrc = Get-ChildItem -Path $extractDir -Filter "wdsp-agent.exe" -Recurse | Select-Object -First 1
    if ($null -eq $exeSrc) {
        throw "压缩包中未找到 wdsp-agent.exe"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $agentExe = Join-Path $InstallDir "wdsp-agent.exe"
    Copy-Item -LiteralPath $exeSrc.FullName -Destination $agentExe -Force
    foreach ($helper in @("install-agent.ps1", "uninstall-agent.ps1", "README.txt")) {
        $found = Get-ChildItem -Path $extractDir -Filter $helper -Recurse | Select-Object -First 1
        if ($null -ne $found) {
            Copy-Item -LiteralPath $found.FullName -Destination (Join-Path $InstallDir $helper) -Force
        }
    }

    $verOut = & $agentExe version
    Write-Info "已部署二进制: $agentExe ($verOut)"

    # 6. 检测宿主机 Npcap 状态（合规边界：不随包分发 Npcap 驱动）
    $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { "C:\Windows" }
    $npcapDll = Join-Path $sysRoot "System32\Npcap\wpcap.dll"
    if (Test-Path -LiteralPath $npcapDll) {
        Write-Info "检测到宿主已安装 Npcap ($npcapDll)，将优先使用 Npcap 旁路只读抓包后端。"
    } else {
        Write-Warn "未检测到宿主 Npcap ($npcapDll)。Agent 将自动尝试回退至 Windows 原生 IPv4 Raw Socket（仅 IPv4、受本机防火墙策略影响）。生产环境建议自行安装 Npcap 驱动。"
    }

    # 7. 执行注册并安装/启动原生 Windows Service
    $argsList = @("install")
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $argsList += @("--server", $Server.TrimEnd("/")) }
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $argsList += @("--config", $ConfigPath) }
    if (-not [string]::IsNullOrWhiteSpace($StateDir)) { $argsList += @("--state-dir", $StateDir) }
    if (-not [string]::IsNullOrWhiteSpace($Backend)) { $argsList += @("--backend", $Backend) }
    if ($InsecureSkipVerify) { $argsList += "--insecure-skip-verify" }
    if ($ForceReenroll) { $argsList += "--force-reenroll" }
    if ($NoStart) { $argsList += "--no-start" }

    if (-not [string]::IsNullOrWhiteSpace($TokenFile)) {
        $argsList += @("--token-file", $TokenFile)
    } elseif (-not [string]::IsNullOrWhiteSpace($enrollToken)) {
        $tmpTok = Join-Path $workDir "enroll.token"
        [System.IO.File]::WriteAllText($tmpTok, $enrollToken, [System.Text.Encoding]::ASCII)
        $argsList += @("--token-file", $tmpTok)
    }

    Write-Info "正在执行 Agent 注册与 Windows 服务安装..."
    & $agentExe @argsList
    if ($LASTEXITCODE -ne 0) {
        throw "wdsp-agent.exe install 退出码异常: $LASTEXITCODE"
    }

    Write-Info "安装完成。可执行 `"$agentExe`" status 查看详细状态。"
} finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
