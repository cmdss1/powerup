# Microsoft Tenant Data Fetcher
# PowerShell tool to fetch UAL logs, sign-in logs, and audit activity using app registration

param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\output",
    
    [Parameter(Mandatory=$false)]
    [string]$UPN = "",
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 0,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoPrompt
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
    Import-Module ImportExcel -ErrorAction Stop
} catch {
    Write-Error "Required modules not found. Please install them using:"
    Write-Error "Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Reports, ImportExcel"
    exit 1
}

# Global variables
$script:Config = $null
$script:AccessToken = $null
$script:TenantId = $null

# Function to prompt user for input
function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$DefaultValue = "",
        [string]$ValidationPattern = "",
        [string]$ErrorMessage = "Invalid input. Please try again."
    )
    
    do {
        if ($DefaultValue) {
            $userInput = Read-Host "$Prompt (default: $DefaultValue)"
            if ([string]::IsNullOrEmpty($userInput)) {
                $userInput = $DefaultValue
            }
        } else {
            $userInput = Read-Host $Prompt
        }
        
        if ($ValidationPattern) {
            if ($userInput -match $ValidationPattern) {
                return $userInput
            } else {
                Write-Host $ErrorMessage -ForegroundColor Red
            }
        } else {
            return $userInput
        }
    } while ($true)
}

# Function to load configuration
function Get-Configuration {
    param([string]$ConfigPath)
    
    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Configuration file not found: $ConfigPath"
        Write-Host "Please create a config.json file with your app registration details."
        exit 1
    }
    
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        return $config
    } catch {
        Write-Error "Failed to parse configuration file: $($_.Exception.Message)"
        exit 1
    }
}

# Function to authenticate using app registration
function Connect-MicrosoftGraphApp {
    param($Config)
    
    try {
        Write-Host "Authenticating with Microsoft Graph using app registration..." -ForegroundColor Green
        
        # Create secure string for client secret
        $SecureSecret = ConvertTo-SecureString $Config.ClientSecret -AsPlainText -Force
        
        # Create credential object
        $Credential = New-Object System.Management.Automation.PSCredential($Config.ClientId, $SecureSecret)
        
        # Connect to Microsoft Graph using app registration
        Connect-MgGraph -TenantId $Config.TenantId -ClientSecretCredential $Credential
        
        # Get access token for direct API calls
        $script:AccessToken = (Get-MgContext).AccessToken
        $script:TenantId = $Config.TenantId
        
        Write-Host "Successfully authenticated!" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to make authenticated API calls
function Invoke-GraphAPI {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [object]$Body = $null
    )
    
    $defaultHeaders = @{
        "Authorization" = "Bearer $script:AccessToken"
        "Content-Type" = "application/json"
    }
    
    $allHeaders = $defaultHeaders + $Headers
    
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $allHeaders
        }
        
        if ($Body) {
            $params.Body = $Body | ConvertTo-Json -Depth 10
        }
        
        $response = Invoke-RestMethod @params
        return $response
    } catch {
        Write-Error "API call failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            Write-Error "Response: $responseBody"
        }
        throw
    }
}

# Function to fetch Unified Audit Logs (UAL)
function Get-UnifiedAuditLogs {
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UPN = "",
        [int]$Top = 1000
    )
    
    Write-Host "Fetching Unified Audit Logs..." -ForegroundColor Yellow
    
    $baseUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    $filters = @()
    
    # Add date filter
    $filters += "activityDateTime ge $StartDate and activityDateTime le $EndDate"
    
    # Add UPN filter if specified
    if ($UPN) {
        $filters += "initiatedBy/user/userPrincipalName eq '$UPN'"
    }
    
    $filterString = $filters -join " and "
    $uri = "$baseUri`?`$filter=$filterString&`$top=$Top"
    
    try {
        $logs = @()
        $nextLink = $uri
        
        while ($nextLink) {
            Write-Host "Fetching batch of audit logs..." -ForegroundColor Cyan
            $response = Invoke-GraphAPI -Uri $nextLink
            
            if ($response.value) {
                $logs += $response.value
                Write-Host "Retrieved $($response.value.Count) audit log entries" -ForegroundColor Green
            }
            
            $nextLink = $response.'@odata.nextLink'
        }
        
        Write-Host "Total Unified Audit Logs retrieved: $($logs.Count)" -ForegroundColor Green
        return $logs
    } catch {
        Write-Error "Failed to fetch Unified Audit Logs: $($_.Exception.Message)"
        return @()
    }
}

# Function to fetch Sign-in Logs
function Get-SignInLogs {
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UPN = "",
        [int]$Top = 1000
    )
    
    Write-Host "Fetching Sign-in Logs..." -ForegroundColor Yellow
    
    $baseUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    $filters = @()
    
    # Add date filter
    $filters += "createdDateTime ge $StartDate and createdDateTime le $EndDate"
    
    # Add UPN filter if specified
    if ($UPN) {
        $filters += "userPrincipalName eq '$UPN'"
    }
    
    $filterString = $filters -join " and "
    $uri = "$baseUri`?`$filter=$filterString&`$top=$Top"
    
    try {
        $logs = @()
        $nextLink = $uri
        
        while ($nextLink) {
            Write-Host "Fetching batch of sign-in logs..." -ForegroundColor Cyan
            $response = Invoke-GraphAPI -Uri $nextLink
            
            if ($response.value) {
                $logs += $response.value
                Write-Host "Retrieved $($response.value.Count) sign-in log entries" -ForegroundColor Green
            }
            
            $nextLink = $response.'@odata.nextLink'
        }
        
        Write-Host "Total Sign-in Logs retrieved: $($logs.Count)" -ForegroundColor Green
        return $logs
    } catch {
        Write-Error "Failed to fetch Sign-in Logs: $($_.Exception.Message)"
        return @()
    }
}


# Function to export data to Excel files
function Export-DataToExcel {
    param(
        [object]$Data,
        [string]$FileName,
        [string]$OutputPath,
        [string]$SheetName = "Data"
    )
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $excelFilePath = Join-Path $OutputPath "$FileName`_$timestamp.xlsx"
    $jsonFilePath = Join-Path $OutputPath "$FileName`_$timestamp.json"
    
    try {
        # Export to Excel
        if ($Data -and $Data.Count -gt 0) {
            $Data | Export-Excel -Path $excelFilePath -WorksheetName $SheetName -AutoSize -TableStyle Medium2 -BoldTopRow
            Write-Host "Excel file exported to: $excelFilePath" -ForegroundColor Green
        } else {
            Write-Host "No data to export for $FileName" -ForegroundColor Yellow
        }
        
        # Also export to JSON for backup
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8
        Write-Host "JSON backup exported to: $jsonFilePath" -ForegroundColor Green
        
        return $excelFilePath
    } catch {
        Write-Error "Failed to export data: $($_.Exception.Message)"
        return $null
    }
}

# Function to export data to files (legacy JSON export)
function Export-DataToFiles {
    param(
        [object]$Data,
        [string]$FileName,
        [string]$OutputPath
    )
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filePath = Join-Path $OutputPath "$FileName`_$timestamp.json"
    
    try {
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        Write-Host "Data exported to: $filePath" -ForegroundColor Green
        return $filePath
    } catch {
        Write-Error "Failed to export data: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
function Main {
    try {
        Write-Host "Microsoft Tenant Data Fetcher" -ForegroundColor Cyan
        Write-Host "=============================" -ForegroundColor Cyan
        Write-Host ""
        
        # Interactive prompts if not using NoPrompt switch
        if (-not $NoPrompt) {
            # Prompt for days back if not provided
            if ($DaysBack -eq 0) {
                $DaysBack = Get-UserInput -Prompt "How many days back to fetch logs" -DefaultValue "30" -ValidationPattern "^\d+$" -ErrorMessage "Please enter a valid number of days"
                $DaysBack = [int]$DaysBack
            }
            
            # Prompt for UPN if not provided
            if ([string]::IsNullOrEmpty($UPN)) {
                $UPN = Get-UserInput -Prompt "Enter UPN to filter audit activity (leave empty for all users)" -DefaultValue ""
            }
            
            # Prompt for output path if not provided
            if ($OutputPath -eq ".\output") {
                $OutputPath = Get-UserInput -Prompt "Enter output directory path" -DefaultValue ".\output"
            }
        } else {
            # Use default values if NoPrompt is specified
            if ($DaysBack -eq 0) {
                $DaysBack = 30
            }
        }
        
        # Load configuration
        $script:Config = Get-Configuration -ConfigPath $ConfigFile
        
        # Authenticate
        if (-not (Connect-MicrosoftGraphApp -Config $script:Config)) {
            exit 1
        }
        
        # Calculate date range
        $endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        Write-Host ""
        Write-Host "Fetching data from $startDate to $endDate" -ForegroundColor Cyan
        Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
        if ($UPN) {
            Write-Host "Filtering for UPN: $UPN" -ForegroundColor Cyan
        }
        Write-Host ""
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Fetch data based on parameters
        if ($UPN) {
            # Fetch audit activity for specific UPN - create separate files for each type
            Write-Host "Fetching audit activity for UPN: $UPN" -ForegroundColor Yellow
            
            # Get directory audit logs for the user
            Write-Host "Fetching Unified Audit Logs for $UPN..." -ForegroundColor Yellow
            $ualLogs = Get-UnifiedAuditLogs -StartDate $startDate -EndDate $endDate -UPN $UPN
            Export-DataToExcel -Data $ualLogs -FileName "UnifiedAuditLogs_$($UPN.Replace('@', '_').Replace('.', '_'))" -OutputPath $OutputPath -SheetName "Unified Audit Logs"
            
            # Get sign-in logs for the user
            Write-Host "Fetching Sign-in Logs for $UPN..." -ForegroundColor Yellow
            $signInLogs = Get-SignInLogs -StartDate $startDate -EndDate $endDate -UPN $UPN
            Export-DataToExcel -Data $signInLogs -FileName "SignInLogs_$($UPN.Replace('@', '_').Replace('.', '_'))" -OutputPath $OutputPath -SheetName "Sign-in Logs"
        } else {
            # Fetch all UAL logs
            Write-Host "Fetching Unified Audit Logs..." -ForegroundColor Yellow
            $ualLogs = Get-UnifiedAuditLogs -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $ualLogs -FileName "UnifiedAuditLogs" -OutputPath $OutputPath -SheetName "Unified Audit Logs"
            
            # Fetch all sign-in logs
            Write-Host "Fetching Sign-in Logs..." -ForegroundColor Yellow
            $signInLogs = Get-SignInLogs -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $signInLogs -FileName "SignInLogs" -OutputPath $OutputPath -SheetName "Sign-in Logs"
        }
        
        Write-Host ""
        Write-Host "Data fetching completed successfully!" -ForegroundColor Green
        Write-Host "Check the output directory for Excel files: $OutputPath" -ForegroundColor Green
        
    } catch {
        Write-Error "Script execution failed: $($_.Exception.Message)"
        exit 1
    } finally {
        # Disconnect from Microsoft Graph
        if (Get-MgContext) {
            Disconnect-MgGraph | Out-Null
        }
    }
}

# Run main function
Main
