# Setup script for local E2E NTLM testing
# Run this as Administrator

param(
    [string]$SiteName = "ntlmtest",
    [int]$Port = 8080,
    [string]$TestUser = "ntlmtestuser",
    [string]$TestPassword = ""
)

# Generate a random password if none provided
if ([string]::IsNullOrEmpty($TestPassword)) {
    $TestPassword = -join ((65..90) + (97..122) + (48..57) + @(33,35,36,37,38,42,43,45,61,63,64) | Get-Random -Count 16 | % {[char]$_})
    Write-Host "Generated random test password for security" -ForegroundColor Cyan
}

Write-Host "Setting up local NTLM E2E test environment..." -ForegroundColor Green

try {
    # Check if running as Administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator!"
        exit 1
    }

    # Enable IIS features
    Write-Host "Enabling IIS features..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools -All -NoRestart

    # Import WebAdministration module
    Import-Module WebAdministration -Force

    # Create test user
    Write-Host "Creating test user: $TestUser" -ForegroundColor Yellow
    try {
        Get-LocalUser -Name $TestUser -ErrorAction Stop
        Write-Host "User $TestUser already exists" -ForegroundColor Cyan
    } catch {
        $securePassword = ConvertTo-SecureString $TestPassword -AsPlainText -Force
        New-LocalUser -Name $TestUser -Password $securePassword -PasswordNeverExpires -UserMayNotChangePassword
        Add-LocalGroupMember -Group "IIS_IUSRS" -Member $TestUser -ErrorAction SilentlyContinue
        Write-Host "Created user: $TestUser" -ForegroundColor Green
    }

    # Create website directory
    $webRoot = "C:\inetpub\$SiteName"
    New-Item -Path $webRoot -ItemType Directory -Force
    Write-Host "Created directory: $webRoot" -ForegroundColor Green

    # Create test HTML file
    @"
<!DOCTYPE html>
<html>
<head>
    <title>NTLM Test Page</title>
</head>
<body>
    <h1>NTLM Authentication Successful!</h1>
    <p><strong>Congratulations!</strong> Your NTLM authentication is working.</p>
    <p>This page is served by IIS with Windows Authentication enabled.</p>
    <hr>
    <p><em>Timestamp: $(Get-Date)</em></p>
</body>
</html>
"@ | Out-File -FilePath "$webRoot\index.html" -Encoding UTF8

    # Create minimal web.config (without authentication settings that might be locked)
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation targetFramework="4.8" />
    </system.web>
    <system.webServer>
        <defaultDocument>
            <files>
                <clear />
                <add value="index.html" />
            </files>
        </defaultDocument>
    </system.webServer>
</configuration>
"@ | Out-File -FilePath "$webRoot\web.config" -Encoding UTF8

    # Remove existing site if it exists
    if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
        Remove-Website -Name $SiteName
        Write-Host "Removed existing site: $SiteName" -ForegroundColor Cyan
    }

    # Create new website
    New-Website -Name $SiteName -Port $Port -PhysicalPath $webRoot -Force
    Start-Website -Name $SiteName

    # Configure authentication (with error handling for locked configurations)
    Write-Host "Configuring authentication settings..." -ForegroundColor Yellow
    
    try {
        # Try to configure at site level first
        Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value false -PSPath "IIS:\Sites\$SiteName" -ErrorAction Stop
        Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value true -PSPath "IIS:\Sites\$SiteName" -ErrorAction Stop
        Write-Host "Authentication configured at site level" -ForegroundColor Green
    } catch {
        Write-Host "Site-level configuration failed (common on servers), trying application level..." -ForegroundColor Yellow
        
        try {
            # Try application level
            Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value false -Location "$SiteName/" -ErrorAction Stop
            Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value true -Location "$SiteName/" -ErrorAction Stop
            Write-Host "Authentication configured at application level" -ForegroundColor Green
        } catch {
            Write-Warning "Could not configure authentication via PowerShell cmdlets. This might be due to server-level restrictions."
            Write-Host "Attempting to unlock authentication sections..." -ForegroundColor Yellow
            
            try {
                # Try to unlock the authentication sections
                & $env:windir\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/windowsAuthentication
                & $env:windir\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/anonymousAuthentication
                
                # Try again after unlocking
                Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value false -PSPath "IIS:\Sites\$SiteName"
                Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value true -PSPath "IIS:\Sites\$SiteName"
                Write-Host "Authentication configured after unlocking sections" -ForegroundColor Green
            } catch {
                Write-Warning "Authentication configuration failed. Manual configuration may be required."
                Write-Host "You can manually enable Windows Authentication and disable Anonymous Authentication for site '$SiteName'" -ForegroundColor Cyan
            }
        }
    }

    Write-Host "Website created successfully!" -ForegroundColor Green
    Write-Host "Site Name: $SiteName" -ForegroundColor Cyan
    Write-Host "Port: $Port" -ForegroundColor Cyan
    Write-Host "URL: http://localhost:$Port/" -ForegroundColor Cyan

    # Set environment variables for testing
    [Environment]::SetEnvironmentVariable("NTLM_TEST_URL", "http://localhost:$Port/", "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_USER", $TestUser, "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_PASSWORD", $TestPassword, "User")
    [Environment]::SetEnvironmentVariable("NTLM_TEST_DOMAIN", $env:COMPUTERNAME, "User")

    # Verify authentication configuration
    Write-Host "`nVerifying authentication configuration..." -ForegroundColor Yellow
    try {
        $anonAuth = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name enabled -PSPath "IIS:\Sites\$SiteName"
        $winAuth = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name enabled -PSPath "IIS:\Sites\$SiteName"
        
        Write-Host "Anonymous Authentication: $($anonAuth.Value)" -ForegroundColor $(if ($anonAuth.Value) { "Red" } else { "Green" })
        Write-Host "Windows Authentication: $($winAuth.Value)" -ForegroundColor $(if ($winAuth.Value) { "Green" } else { "Red" })
        
        if (-not $anonAuth.Value -and $winAuth.Value) {
            Write-Host "✓ Authentication is configured correctly!" -ForegroundColor Green
        } else {
            Write-Warning "Authentication may not be configured optimally. Tests might fail."
        }
    } catch {
        Write-Warning "Could not verify authentication configuration: $($_.Exception.Message)"
    }

    Write-Host "`nEnvironment variables set:" -ForegroundColor Green
    Write-Host "NTLM_TEST_URL=http://localhost:$Port/" -ForegroundColor Cyan
    Write-Host "NTLM_TEST_USER=$TestUser" -ForegroundColor Cyan
    Write-Host "NTLM_TEST_PASSWORD=$TestPassword" -ForegroundColor Cyan
    Write-Host "NTLM_TEST_DOMAIN=$env:COMPUTERNAME" -ForegroundColor Cyan

    Write-Host "`nTo run E2E tests:" -ForegroundColor Green
    Write-Host "go test -v -tags=e2e ./e2e -run TestNTLM_E2E" -ForegroundColor Yellow

    Write-Host "`nTo cleanup:" -ForegroundColor Green
    Write-Host ".\cleanup-e2e.ps1" -ForegroundColor Yellow

} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    exit 1
}