#!/usr/bin/env pwsh
<#
.SYNOPSIS
    One-command deploy: creates the defender-xdr-kql GitHub repo and pushes all files.

.DESCRIPTION
    Requires GitHub CLI (gh) to be installed and authenticated.
    Install: winget install --id GitHub.cli
    Auth:    gh auth login

.PARAMETER RepoName
    GitHub repo name. Default: defender-xdr-kql

.PARAMETER RepoDescription
    Repo description shown on GitHub.

.PARAMETER Private
    Make the repo private. Default: public.

.PARAMETER SkipPages
    Skip enabling GitHub Pages (only works on public repos or GitHub Pro+).

.EXAMPLE
    .\Deploy-DefenderKQL.ps1
    .\Deploy-DefenderKQL.ps1 -Private
    .\Deploy-DefenderKQL.ps1 -RepoName "my-kql-library"
#>

param(
    [string]$RepoName        = "defender-xdr-kql",
    [string]$RepoDescription = "Microsoft Defender XDR Advanced Hunting KQL library — MDO, MDE, MDI, MDCA, cross-pillar XDR kill chains.",
    [switch]$Private,
    [switch]$SkipPages
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Preflight ────────────────────────────────────────────────────────────────
Write-Host "`n🔍 Checking prerequisites..." -ForegroundColor Cyan

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "GitHub CLI (gh) not found. Install with: winget install --id GitHub.cli"
}
$ghStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not authenticated. Run: gh auth login"
}

$GH_USER = (gh api user --jq '.login' 2>&1).Trim()
Write-Host "✅ Authenticated as: $GH_USER" -ForegroundColor Green

# ── Create repo ──────────────────────────────────────────────────────────────
Write-Host "`n📦 Creating GitHub repo: $GH_USER/$RepoName" -ForegroundColor Cyan

$existingRepo = gh repo view "$GH_USER/$RepoName" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "⚠️  Repo already exists — pushing updates to existing repo." -ForegroundColor Yellow
} else {
    $visibilityFlag = if ($Private) { "--private" } else { "--public" }
    gh repo create $RepoName $visibilityFlag --description $RepoDescription --confirm 2>&1 | Out-Null
    Write-Host "✅ Repo created." -ForegroundColor Green
}

# ── Git init and push ────────────────────────────────────────────────────────
Write-Host "`n🚀 Pushing files to GitHub..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

git init -q
git add .
git commit -m "chore: v3.0 full library refresh — 60 queries across MDO/MDE/MDI/MDCA/XDR" -q

$remoteUrl = "https://github.com/$GH_USER/$RepoName.git"
$existingRemote = git remote get-url origin 2>&1
if ($LASTEXITCODE -eq 0) {
    git remote set-url origin $remoteUrl
} else {
    git remote add origin $remoteUrl
}

git branch -M main
git push -u origin main --force -q

Write-Host "✅ Pushed to $remoteUrl" -ForegroundColor Green

# ── Topics ───────────────────────────────────────────────────────────────────
Write-Host "`n🏷️  Adding topics..." -ForegroundColor Cyan
$topics = "defender-xdr,kql,threat-hunting,microsoft-sentinel,advanced-hunting,mde,mdo,mdi,mdca,security"
gh repo edit "$GH_USER/$RepoName" --add-topic $topics 2>&1 | Out-Null
Write-Host "✅ Topics added." -ForegroundColor Green

# ── GitHub Pages (optional) ──────────────────────────────────────────────────
if (-not $SkipPages -and -not $Private) {
    Write-Host "`n🌐 Enabling GitHub Pages (main branch / root)..." -ForegroundColor Cyan
    gh api "repos/$GH_USER/$RepoName/pages" `
        --method POST `
        --field source[branch]=main `
        --field source[path]="/" 2>&1 | Out-Null
    Write-Host "✅ Pages enabled." -ForegroundColor Green
}

Pop-Location

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host "`n✅ All done!" -ForegroundColor Green
Write-Host "   Repo: https://github.com/$GH_USER/$RepoName" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Gray
Write-Host "  1. Set query variables (your domain, IOC values) before running" -ForegroundColor Gray
Write-Host "  2. Add environment-specific queries to queries/<pillar>/" -ForegroundColor Gray
Write-Host "  3. Update README query index when adding new files" -ForegroundColor Gray
Write-Host ""

$openRepo = Read-Host "Open repo in browser now? (y/n)"
if ($openRepo -match "^[Yy]") { gh repo view "$GH_USER/$RepoName" --web }
