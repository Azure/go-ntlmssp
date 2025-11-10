# Cleanup script for local E2E NTLM testing
# Run this as Administrator

param(
    [string]$SiteName = "ntlmtest",
    [string]$TestUser = "ntlmtestuser"
)

Write-Host "Cleaning up local NTLM E2E test environment..." -ForegroundColor Green

try {
    # Check if running as Administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator!"
        exit 1
    }

    # Import WebAdministration module
    Import-Module WebAdministration -Force -ErrorAction SilentlyContinue

    # Stop and remove website
    try {
        if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
            Stop-Website -Name $SiteName -ErrorAction SilentlyContinue
            Remove-Website -Name $SiteName
            Write-Host "Removed IIS site: $SiteName" -ForegroundColor Green
        } else {
            Write-Host "Site $SiteName not found (already cleaned up?)" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "Failed to remove website: $($_.Exception.Message)"
    }

    # Remove website directory
    try {
        $webRoot = "C:\inetpub\$SiteName"
        if (Test-Path $webRoot) {
            Remove-Item -Path $webRoot -Recurse -Force
            Write-Host "Removed directory: $webRoot" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to remove directory: $($_.Exception.Message)"
    }

    # Remove test user
    try {
        if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $TestUser
            Write-Host "Removed test user: $TestUser" -ForegroundColor Green
        } else {
            Write-Host "User $TestUser not found (already cleaned up?)" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "Failed to remove user: $($_.Exception.Message)"
    }

    # Remove environment variables
    [Environment]::SetEnvironmentVariable("NTLM_TEST_URL", $null, "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_USER", $null, "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_PASSWORD", $null, "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_DOMAIN", $null, "User")
    
    Write-Host "Removed environment variables" -ForegroundColor Green
    Write-Host "Cleanup completed successfully!" -ForegroundColor Green

} catch {
    Write-Error "Cleanup failed: $($_.Exception.Message)"
    exit 1
}