<#
.SYNOPSIS
  Builds the WordEye agent (linux/amd64, static) and the controller (host OS).

.DESCRIPTION
  The agent is built with CGO_ENABLED=0 so it is a genuinely static binary with
  no libc dependency — one scp onto any glibc or musl host and it runs, with no
  package installs and nothing left behind.

  -trimpath and -ldflags "-s -w" keep the binary small and free of local build
  paths, which matters because this binary gets copied onto client machines.

.EXAMPLE
  ./build.ps1
  ./build.ps1 -Version 1.2.0
#>
param(
    [string]$Version = "",
    [switch]$SkipController
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not $Version) {
    $stamp = Get-Date -Format "yyyyMMdd.HHmmss"
    $Version = "0.1.0+$stamp"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$ldflags = "-s -w -X main.version=$Version"

Write-Host "building wordeye-agent $Version (linux/amd64, static)..." -ForegroundColor Cyan
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags $ldflags -o (Join-Path $dist "wordeye-agent-linux-amd64") ./cmd/wordeye-agent
if ($LASTEXITCODE -ne 0) { throw "agent build failed" }

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

if (-not $SkipController) {
    Write-Host "building wordeye controller ($([System.Runtime.InteropServices.RuntimeInformation]::OSDescription))..." -ForegroundColor Cyan
    $ctlName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "wordeye.exe" } else { "wordeye" }
    go build -trimpath -ldflags $ldflags -o (Join-Path $dist $ctlName) ./cmd/wordeye
    if ($LASTEXITCODE -ne 0) { throw "controller build failed" }
}

Write-Host ""
Get-ChildItem $dist | ForEach-Object {
    $sha = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "{0,-34} {1,8:N0} KB  {2}" -f $_.Name, ($_.Length / 1KB), $sha.Substring(0, 16)
}

Write-Host ""
Write-Host "deploy a single host:" -ForegroundColor Green
Write-Host "  scp dist/wordeye-agent-linux-amd64 user@host:~/wordeye-agent"
Write-Host "  ssh user@host './wordeye-agent --pretty'"
Write-Host ""
Write-Host "or drive the estate:" -ForegroundColor Green
Write-Host "  ./dist/wordeye --inventory estate.yaml --pack internal/rules/packs/incident.yaml --out ./reports"
