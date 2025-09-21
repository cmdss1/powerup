# Install Required Modules Script
# This script installs all required Microsoft Graph PowerShell modules

Write-Host "Installing required Microsoft Graph PowerShell modules..." -ForegroundColor Green

$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns", 
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Reports",
    "Microsoft.Graph.Security",
    "ImportExcel"
)

foreach ($module in $modules) {
    try {
        Write-Host "Installing $module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
        Write-Host "$module installed successfully!" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install $module : $($_.Exception.Message)"
    }
}

Write-Host "All modules installation completed!" -ForegroundColor Green
Write-Host "You can now run the MicrosoftTenantDataFetcher.ps1 script." -ForegroundColor Cyan
