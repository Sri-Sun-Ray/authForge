<#
One-time setup: enable the APIs AuthForge needs and store its secrets in Secret Manager.

Prompts for each connection string so nothing sensitive ends up in your shell history
or in git. See DEPLOY.md.

    ./scripts/setup-secrets.ps1 -ProjectId my-project
#>
param(
    [Parameter(Mandatory = $true)][string]$ProjectId
)

$ErrorActionPreference = "Stop"

Write-Host "Enabling the required Google Cloud APIs..." -ForegroundColor Cyan
gcloud services enable run.googleapis.com cloudbuild.googleapis.com `
    secretmanager.googleapis.com artifactregistry.googleapis.com --project $ProjectId

function Set-Secret {
    param([string]$Name, [string]$Value)

    $exists = gcloud secrets describe $Name --project $ProjectId 2>$null
    if (-not $exists) {
        gcloud secrets create $Name --replication-policy automatic --project $ProjectId | Out-Null
    }
    # Piped in, so the value never appears as a command-line argument
    $Value | gcloud secrets versions add $Name --data-file=- --project $ProjectId | Out-Null
    Write-Host "  stored $Name" -ForegroundColor Green
}

# --- Connection strings -----------------------------------------------------
Write-Host "`nNeon gives one connection string. Paste it as-is; this script rewrites it." -ForegroundColor Cyan
$neon = Read-Host "Neon connection string (postgresql://...)"

# asyncpg does not understand libpq's sslmode parameter; it wants ssl=require
$neon = $neon -replace "^postgres(ql)?://", "postgresql+asyncpg://"
$neon = $neon -replace "[?&]sslmode=require", ""
$neon = $neon -replace "[?&]channel_binding=[^&]*", ""
$adminUrl = "$neon`?ssl=require"

# The app connects as the restricted role that migrations create
$appPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$appUrl = $adminUrl -replace "://[^:]+:[^@]+@", "://authforge_app:$appPassword@"

$redis = Read-Host "Upstash Redis URL (rediss://...)"

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
$projectNumber = gcloud projects describe $ProjectId --format "value(projectNumber)"
$runtime = "$projectNumber-compute@developer.gserviceaccount.com"
foreach ($name in @("authforge-database-url", "authforge-database-admin-url",
        "authforge-app-db-password", "authforge-redis-url",
        "authforge-jwt-private-key", "authforge-jwt-public-key")) {
    gcloud secrets add-iam-policy-binding $name `
        --member "serviceAccount:$runtime" `
        --role roles/secretmanager.secretAccessor `
        --project $ProjectId | Out-Null
}

Write-Host "`nSecrets ready. Next: ./scripts/deploy.ps1 -ProjectId $ProjectId" -ForegroundColor Green
