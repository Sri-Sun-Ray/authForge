<#
One-time setup: enable the APIs AuthForge needs and store its secrets in Secret Manager.

Prompts for each connection string so nothing sensitive ends up in your shell history
or in git. See DEPLOY.md.

    ./scripts/setup-secrets.ps1 -ProjectId my-project
#>
param(
    [Parameter(Mandatory = $true)][string]$ProjectId
)

# Native commands write progress to stderr, which "Stop" would treat as fatal in
# Windows PowerShell; exit codes are checked explicitly instead.
$ErrorActionPreference = "Continue"

function Get-GcloudPath {
    $found = Get-Command gcloud -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    # Freshly installed and not yet on PATH
    $fallback = "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
    if (Test-Path $fallback) { return $fallback }
    throw "gcloud not found. Install it, or open a new terminal so PATH refreshes."
}
$gcloud = Get-GcloudPath

function Invoke-Gcloud {
    param([string[]]$Arguments, [string]$What)

    $output = & $gcloud @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
    return $output
}

Write-Host "Enabling the required Google Cloud APIs..." -ForegroundColor Cyan
Invoke-Gcloud -What "Enabling APIs" -Arguments @(
    "services", "enable", "run.googleapis.com", "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com", "artifactregistry.googleapis.com", "--project", $ProjectId
) | Out-Null

function Set-Secret {
    param([string]$Name, [string]$Value)

    # Listing never fails when nothing matches, unlike `secrets describe`
    $existing = Invoke-Gcloud -What "Listing secrets" -Arguments @(
        "secrets", "list", "--project", $ProjectId, "--format", "value(name)"
    )
    if ($existing -notcontains $Name) {
        Invoke-Gcloud -What "Creating secret $Name" -Arguments @(
            "secrets", "create", $Name, "--replication-policy", "automatic", "--project", $ProjectId
        ) | Out-Null
    }

    # Written to a temp file rather than piped: the value never becomes a command-line
    # argument, and WriteAllText adds no trailing newline. A stray "\n" inside a
    # connection string breaks it in ways that are miserable to debug (asyncpg reads
    # "require\n" as an invalid SSL mode).
    $temp = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($temp, $Value, (New-Object Text.UTF8Encoding $false))
        & $gcloud secrets versions add $Name --data-file=$temp --project $ProjectId | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Storing $Name failed (exit $LASTEXITCODE)" }
    }
    finally { Remove-Item $temp -Force -ErrorAction SilentlyContinue }
    Write-Host "  stored $Name" -ForegroundColor Green
}

# --- Connection strings -----------------------------------------------------
Write-Host "`nNeon gives one connection string. Paste it as-is; this script rewrites it." -ForegroundColor Cyan
$neon = (Read-Host "Neon connection string (postgresql://...)").Trim()

# asyncpg does not understand libpq's sslmode parameter; it wants ssl=require
$neon = $neon -replace "^postgres(ql)?://", "postgresql+asyncpg://"
$neon = $neon -replace "[?&]sslmode=[^&]*", ""
$neon = $neon -replace "[?&]channel_binding=[^&]*", ""
# Neon's pooled endpoint runs PgBouncer in transaction mode, which breaks asyncpg's
# prepared statements; the direct endpoint is the same database without the pooler
$neon = $neon -replace "-pooler\.", "."
$adminUrl = "$neon`?ssl=require"

# The app connects as the restricted role that migrations create
$appPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$appUrl = $adminUrl -replace "://[^:]+:[^@]+@", "://authforge_app:$appPassword@"

$redis = (Read-Host "Upstash Redis URL (rediss://...)").Trim()

Set-Secret -Name "authforge-database-url" -Value $appUrl
Set-Secret -Name "authforge-database-admin-url" -Value $adminUrl
Set-Secret -Name "authforge-app-db-password" -Value $appPassword
Set-Secret -Name "authforge-redis-url" -Value $redis

# --- JWT signing keys -------------------------------------------------------
if (-not (Test-Path "keys/private.pem")) {
    Write-Host "`nNo keys found; generating a pair..." -ForegroundColor Cyan
    python scripts/generate_keys.py
}
Set-Secret -Name "authforge-jwt-private-key" -Value (Get-Content keys/private.pem -Raw)
Set-Secret -Name "authforge-jwt-public-key" -Value (Get-Content keys/public.pem -Raw)

# --- Let Cloud Run read them ------------------------------------------------
$projectNumber = Invoke-Gcloud -What "Reading project number" -Arguments @(
    "projects", "describe", $ProjectId, "--format", "value(projectNumber)"
)
$runtime = "$projectNumber-compute@developer.gserviceaccount.com"
foreach ($name in @("authforge-database-url", "authforge-database-admin-url",
        "authforge-app-db-password", "authforge-redis-url",
        "authforge-jwt-private-key", "authforge-jwt-public-key")) {
    Invoke-Gcloud -What "Granting access to $name" -Arguments @(
        "secrets", "add-iam-policy-binding", $name,
        "--member", "serviceAccount:$runtime",
        "--role", "roles/secretmanager.secretAccessor",
        "--project", $ProjectId
    ) | Out-Null
}

Write-Host "`nSecrets ready. Next: ./scripts/deploy.ps1 -ProjectId $ProjectId" -ForegroundColor Green
