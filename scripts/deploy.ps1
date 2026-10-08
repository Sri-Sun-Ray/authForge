<#
Deploy AuthForge to Google Cloud Run.

Run scripts/setup-secrets.ps1 once first. See DEPLOY.md for the full walkthrough.

    ./scripts/deploy.ps1 -ProjectId my-project
#>
param(
    [Parameter(Mandatory = $true)][string]$ProjectId,
    [string]$Region = "asia-south1",       # Mumbai; closest to Andhra Pradesh
    [string]$Service = "authforge"
)

# gcloud reports build progress on stderr, which "Stop" would treat as a failure in
# Windows PowerShell; the exit code is checked explicitly below instead.
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

Write-Host "Deploying $Service to $ProjectId ($Region)..." -ForegroundColor Cyan

# Secrets live in Secret Manager; only their names appear here, never their values
$secrets = @(
    "DATABASE_URL=authforge-database-url:latest",
    "DATABASE_ADMIN_URL=authforge-database-admin-url:latest",
    "REDIS_URL=authforge-redis-url:latest",
    "APP_DB_PASSWORD=authforge-app-db-password:latest",
    "JWT_PRIVATE_KEY_PEM=authforge-jwt-private-key:latest",
    "JWT_PUBLIC_KEY_PEM=authforge-jwt-public-key:latest"
) -join ","

# APP_BASE_URL is set afterwards: Cloud Run's hostname contains a generated hash,
# so the real URL is only known once the service exists.
$env_vars = @("ENVIRONMENT=production", "DEBUG=false") -join ","

& $gcloud run deploy $Service `
    --source . `
    --project $ProjectId `
    --region $Region `
    --platform managed `
    --allow-unauthenticated `
    --set-env-vars $env_vars `
    --set-secrets $secrets `
    --cpu 1 `
    --memory 512Mi `
    --min-instances 0 `
    --max-instances 3 `
    --timeout 60

if ($LASTEXITCODE -ne 0) { throw "Deploy failed" }

$url = & $gcloud run services describe $Service --project $ProjectId --region $Region --format "value(status.url)"

# Links in verification and password-reset emails need the real hostname
& $gcloud run services update $Service --project $ProjectId --region $Region `
    --update-env-vars "APP_BASE_URL=$url" --quiet | Out-Null

Write-Host "`nDeployed: $url" -ForegroundColor Green
Write-Host "API docs: $url/docs"
Write-Host "Health:   $url/health/ready"
