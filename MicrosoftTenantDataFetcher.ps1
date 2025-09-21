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
    Import-Module Microsoft.Graph.Security -ErrorAction Stop
    Import-Module ImportExcel -ErrorAction Stop
} catch {
    Write-Error "Required modules not found. Please install them using:"
    Write-Error "Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Reports, Microsoft.Graph.Security, ImportExcel"
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
        
        # Validate required configuration fields
        if (-not $config.TenantId -or $config.TenantId -eq "your-tenant-id-here") {
            Write-Error "TenantId is missing or not configured in config.json"
            exit 1
        }
        
        if (-not $config.ClientId -or $config.ClientId -eq "your-app-registration-client-id-here") {
            Write-Error "ClientId is missing or not configured in config.json"
            exit 1
        }
        
        if (-not $config.ClientSecret -or $config.ClientSecret -eq "your-app-registration-client-secret-here") {
            Write-Error "ClientSecret is missing or not configured in config.json"
            exit 1
        }
        
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

# Function to make authenticated API calls using Microsoft Graph cmdlets
function Get-GraphAuditLogs {
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UPN = "",
        [string]$LogType = "DirectoryAudit"
    )
    
    try {
        $filters = @()
        
        if ($LogType -eq "DirectoryAudit") {
            $filters += "activityDateTime ge $StartDate and activityDateTime le $EndDate"
            if ($UPN) {
                $filters += "initiatedBy/user/userPrincipalName eq '$UPN'"
            }
            $filterString = $filters -join " and "
            $logs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All
        } else {
            $filters += "createdDateTime ge $StartDate and createdDateTime le $EndDate"
            if ($UPN) {
                $filters += "userPrincipalName eq '$UPN'"
            }
            $filterString = $filters -join " and "
            $logs = Get-MgAuditLogSignIn -Filter $filterString -All
        }
        
        return $logs
    } catch {
        Write-Error "Failed to fetch $LogType logs: $($_.Exception.Message)"
        return @()
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
    
    try {
        $logs = Get-GraphAuditLogs -StartDate $StartDate -EndDate $EndDate -UPN $UPN -LogType "DirectoryAudit"
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
    
    try {
        $logs = Get-GraphAuditLogs -StartDate $StartDate -EndDate $EndDate -UPN $UPN -LogType "SignIn"
        Write-Host "Total Sign-in Logs retrieved: $($logs.Count)" -ForegroundColor Green
        return $logs
    } catch {
        Write-Error "Failed to fetch Sign-in Logs: $($_.Exception.Message)"
        return @()
    }
}

# Function to check email forwarding rules for a specific user
function Get-EmailForwardingRules {
    param(
        [string]$UPN,
        [string]$StartDate,
        [string]$EndDate
    )
    
    Write-Host "Checking email forwarding rules for $UPN..." -ForegroundColor Yellow
    
    $allForwardingData = @()
    
    try {
        # Method 1: Get forwarding rules from audit logs
        Write-Host "  Checking audit logs for forwarding activities..." -ForegroundColor Cyan
        $filters = @()
        $filters += "activityDateTime ge $StartDate and activityDateTime le $EndDate"
        
        if ($UPN) {
            $filters += "initiatedBy/user/userPrincipalName eq '$UPN'"
        }
        
        $filterString = $filters -join " and "
        
        # Get audit logs related to forwarding rules
        $forwardingLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Forward|Rule|Mailbox|Inbox|Exchange" -or
            $_.operationType -match "Forward|Rule|Mail|Exchange" -or
            $_.category -match "Exchange" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { $_.key -match "Forward|Rule|Mail|Exchange" }))
        }
        
        # Also check for any rules that might forward TO this user
        if ($UPN) {
            $filtersTo = @()
            $filtersTo += "activityDateTime ge $StartDate and activityDateTime le $EndDate"
            $filterStringTo = $filtersTo -join " and "
            
            $forwardingToLogs = Get-MgAuditLogDirectoryAudit -Filter $filterStringTo -All | Where-Object {
                ($_.targetResources -and ($_.targetResources | Where-Object { $_.displayName -eq $UPN })) -and
                ($_.activityDisplayName -match "Forward|Rule|Mailbox|Exchange" -or $_.operationType -match "Forward|Rule|Mail|Exchange")
            }
            
            $forwardingLogs = $forwardingLogs + $forwardingToLogs
        }
        
        Write-Host "  Found $($forwardingLogs.Count) forwarding-related audit activities" -ForegroundColor Green
        $allForwardingData += $forwardingLogs
        
        # Method 2: Check current mailbox forwarding configuration via Graph API
        if ($UPN) {
            Write-Host "  Checking current mailbox forwarding configuration..." -ForegroundColor Cyan
            try {
                # Get user's mailbox settings
                $user = Get-MgUser -UserId $UPN -Property "mail,mailNickname,userPrincipalName"
                
                # Try to get mailbox forwarding rules via Graph API
                $mailboxSettings = @()
                
                # Check for forwarding rules in additional details of recent audit logs
                $recentLogs = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $StartDate" -All | Where-Object {
                    $_.targetResources -and ($_.targetResources | Where-Object { $_.displayName -eq $UPN -or $_.displayName -eq $user.mail })
                }
                
                foreach ($log in $recentLogs) {
                    if ($log.additionalDetails) {
                        $forwardingDetails = $log.additionalDetails | Where-Object { 
                            $_.key -match "Forward|Rule|Mail|Exchange|Smtp|Recipient" 
                        }
                        
                        if ($forwardingDetails) {
                            $mailboxSettings += [PSCustomObject]@{
                                activityDateTime = $log.activityDateTime
                                activityDisplayName = "Current Mailbox Forwarding Configuration"
                                initiatedBy = $log.initiatedBy
                                targetResources = $log.targetResources
                                result = "success"
                                category = "Exchange"
                                operationType = "MailboxForwarding"
                                additionalDetails = $log.additionalDetails
                            }
                        }
                    }
                }
                
                Write-Host "  Found $($mailboxSettings.Count) current mailbox forwarding configurations" -ForegroundColor Green
                $allForwardingData += $mailboxSettings
                
            } catch {
                Write-Warning "  Could not check current mailbox configuration: $($_.Exception.Message)"
            }
        }
        
        # Method 2.5: Check for Exchange Online PowerShell activities specifically
        Write-Host "  Checking Exchange Online PowerShell activities..." -ForegroundColor Cyan
        $exchangePowerShellLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Exchange Online|ExchangeOnline|EXO" -or
            $_.operationType -match "ExchangeOnline|EXO" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.value -match "Exchange Online|ExchangeOnline|EXO|Set-Mailbox|New-InboxRule|Set-InboxRule|Remove-InboxRule|Set-MailboxForwarding|Get-Mailbox|Get-InboxRule"
            }))
        }
        
        Write-Host "  Found $($exchangePowerShellLogs.Count) Exchange Online PowerShell activities" -ForegroundColor Green
        $allForwardingData += $exchangePowerShellLogs
        
        # Method 3: Check for Exchange Online activities
        Write-Host "  Checking Exchange Online activities..." -ForegroundColor Cyan
        $exchangeLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.category -eq "Exchange" -or
            $_.activityDisplayName -match "Exchange|Mailbox|Inbox|Outbox" -or
            $_.operationType -match "Exchange|Mailbox"
        }
        
        Write-Host "  Found $($exchangeLogs.Count) Exchange Online activities" -ForegroundColor Green
        $allForwardingData += $exchangeLogs
        
        # Method 4: Check for PowerShell/Admin activities that might include forwarding
        Write-Host "  Checking PowerShell and admin activities..." -ForegroundColor Cyan
        $powerShellLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "PowerShell|Admin|Set-|New-|Remove-|Update-" -or
            $_.operationType -match "PowerShell|Admin|Set|New|Remove|Update" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Command|Cmdlet|PowerShell" -or
                $_.value -match "Set-Mailbox|New-InboxRule|Set-InboxRule|Remove-InboxRule|Set-MailboxForwarding"
            }))
        }
        
        Write-Host "  Found $($powerShellLogs.Count) PowerShell/admin activities" -ForegroundColor Green
        $allForwardingData += $powerShellLogs
        
        # Method 5: Check for any activities with "Forward" in additional details
        Write-Host "  Checking for forwarding references in all activities..." -ForegroundColor Cyan
        $allRecentLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All
        $forwardingReferences = $allRecentLogs | Where-Object {
            $_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.value -match "Forward|forward|FORWARD" -or
                $_.key -match "Forward|forward|FORWARD"
            })
        }
        
        Write-Host "  Found $($forwardingReferences.Count) activities with forwarding references" -ForegroundColor Green
        $allForwardingData += $forwardingReferences
        
        # Method 6: Check for any activities that might be related to mailbox configuration
        Write-Host "  Checking for mailbox configuration activities..." -ForegroundColor Cyan
        $mailboxConfigLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Mailbox|Inbox|Outbox|Sent|Draft|Junk|Spam" -or
            $_.operationType -match "Mailbox|Inbox|Outbox|Sent|Draft|Junk|Spam" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Mailbox|Inbox|Outbox|Sent|Draft|Junk|Spam" -or
                $_.value -match "Mailbox|Inbox|Outbox|Sent|Draft|Junk|Spam"
            }))
        }
        
        Write-Host "  Found $($mailboxConfigLogs.Count) mailbox configuration activities" -ForegroundColor Green
        $allForwardingData += $mailboxConfigLogs
        
        # Method 7: Check for any activities with "Rule" in the name or details
        Write-Host "  Checking for rule-related activities..." -ForegroundColor Cyan
        $ruleLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Rule|rule|RULE" -or
            $_.operationType -match "Rule|rule|RULE" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Rule|rule|RULE" -or
                $_.value -match "Rule|rule|RULE"
            }))
        }
        
        Write-Host "  Found $($ruleLogs.Count) rule-related activities" -ForegroundColor Green
        $allForwardingData += $ruleLogs
        
        # Method 8: Check for any activities that might be related to email configuration
        Write-Host "  Checking for email configuration activities..." -ForegroundColor Cyan
        $emailConfigLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Email|email|EMAIL|Smtp|SMTP|smtp" -or
            $_.operationType -match "Email|email|EMAIL|Smtp|SMTP|smtp" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Email|email|EMAIL|Smtp|SMTP|smtp" -or
                $_.value -match "Email|email|EMAIL|Smtp|SMTP|smtp"
            }))
        }
        
        Write-Host "  Found $($emailConfigLogs.Count) email configuration activities" -ForegroundColor Green
        $allForwardingData += $emailConfigLogs
        
        # Method 9: Check for any activities that might be related to Exchange Online
        Write-Host "  Checking for Exchange Online activities..." -ForegroundColor Cyan
        $exchangeOnlineLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Exchange Online|ExchangeOnline|EXO|Exchange" -or
            $_.operationType -match "Exchange Online|ExchangeOnline|EXO|Exchange" -or
            $_.category -match "Exchange" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Exchange Online|ExchangeOnline|EXO|Exchange" -or
                $_.value -match "Exchange Online|ExchangeOnline|EXO|Exchange"
            }))
        }
        
        Write-Host "  Found $($exchangeOnlineLogs.Count) Exchange Online activities" -ForegroundColor Green
        $allForwardingData += $exchangeOnlineLogs
        
        # Method 10: Check for any activities that might be related to mailbox forwarding
        Write-Host "  Checking for mailbox forwarding activities..." -ForegroundColor Cyan
        $mailboxForwardingLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Mailbox Forwarding|MailboxForwarding|Forwarding" -or
            $_.operationType -match "Mailbox Forwarding|MailboxForwarding|Forwarding" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Mailbox Forwarding|MailboxForwarding|Forwarding" -or
                $_.value -match "Mailbox Forwarding|MailboxForwarding|Forwarding"
            }))
        }
        
        Write-Host "  Found $($mailboxForwardingLogs.Count) mailbox forwarding activities" -ForegroundColor Green
        $allForwardingData += $mailboxForwardingLogs
        
        # Method 11: Check for any activities that might be related to inbox rules
        Write-Host "  Checking for inbox rule activities..." -ForegroundColor Cyan
        $inboxRuleLogs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            $_.activityDisplayName -match "Inbox Rule|InboxRule|Inbox" -or
            $_.operationType -match "Inbox Rule|InboxRule|Inbox" -or
            ($_.additionalDetails -and ($_.additionalDetails | Where-Object { 
                $_.key -match "Inbox Rule|InboxRule|Inbox" -or
                $_.value -match "Inbox Rule|InboxRule|Inbox"
            }))
        }
        
        Write-Host "  Found $($inboxRuleLogs.Count) inbox rule activities" -ForegroundColor Green
        $allForwardingData += $inboxRuleLogs
        
        # Remove duplicates based on activityDateTime and activityDisplayName
        $uniqueForwardingData = $allForwardingData | Sort-Object activityDateTime -Descending | Get-Unique -AsString
        
        Write-Host "Total unique forwarding-related data found: $($uniqueForwardingData.Count)" -ForegroundColor Green
        return $uniqueForwardingData
        
    } catch {
        Write-Error "Failed to check forwarding rules: $($_.Exception.Message)"
        return @()
    }
}

# Function to optimize forwarding rules data for SOC analysis
function Convert-ForwardingRulesForSOC {
    param([object]$ForwardingLogs)
    
    if (-not $ForwardingLogs) {
        return @()
    }
    
    $enhancedLogs = $ForwardingLogs | ForEach-Object {
        $log = $_
        
        # Extract forwarding details
        $forwardingDetails = if ($log.additionalDetails) {
            $forwardDetail = $log.additionalDetails | Where-Object { $_.key -match "Forward|Rule|Mail" }
            if ($forwardDetail) { $forwardDetail.value } else { "Unknown" }
        } else { "Unknown" }
        
        # Extract target information
        $targetInfo = if ($log.targetResources) {
            ($log.targetResources | ForEach-Object { $_.displayName }) -join ", "
        } else { "Unknown" }
        
        # Determine rule type
        $ruleType = switch -Wildcard ($log.activityDisplayName) {
            "*Forward*" { "Email Forwarding" }
            "*Rule*" { "Mailbox Rule" }
            "*Inbox*" { "Inbox Rule" }
            "*Mailbox*" { "Mailbox Configuration" }
            default { "Email Rule" }
        }
        
        # Create optimized object for SOC analysis
        [PSCustomObject]@{
            # Essential Information
            Timestamp = (Get-Date $log.activityDateTime).ToString("yyyy-MM-dd HH:mm:ss")
            User = $log.initiatedBy.user.userPrincipalName
            Activity = $log.activityDisplayName
            RuleType = $ruleType
            Result = $log.result
            
            # Forwarding Information
            TargetUser = $targetInfo
            ForwardingDetails = $forwardingDetails
            IPAddress = if ($log.additionalDetails) {
                $ipDetail = $log.additionalDetails | Where-Object { $_.key -eq "IpAddress" }
                if ($ipDetail) { $ipDetail.value } else { "Unknown" }
            } else { "Unknown" }
            
            # Security Context
            Category = $log.category
            OperationType = $log.operationType
            IsSuccess = $log.result -eq "success"
            
            # Additional Details
            Details = if ($log.additionalDetails) { 
                ($log.additionalDetails | ForEach-Object { "$($_.key): $($_.value)" }) -join "; " 
            } else { "None" }
            
            # Time Analysis
            Hour = (Get-Date $log.activityDateTime).Hour
            Day = (Get-Date $log.activityDateTime).DayOfWeek
        }
    }
    
    return $enhancedLogs
}

# Function to fetch Purview audit logs
function Get-PurviewAuditLogs {
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UPN = "",
        [int]$Top = 1000
    )
    
    Write-Host "Fetching Purview Audit Logs..." -ForegroundColor Yellow
    
    try {
        $filters = @()
        $filters += "activityDateTime ge $StartDate and activityDateTime le $EndDate"
        
        if ($UPN) {
            $filters += "initiatedBy/user/userPrincipalName eq '$UPN'"
        }
        
        $filterString = $filters -join " and "
        
        # Get Purview audit logs using Microsoft Graph
        $logs = Get-MgAuditLogDirectoryAudit -Filter $filterString -All | Where-Object {
            # Filter for Purview-related activities
            $_.activityDisplayName -match "File|SharePoint|OneDrive|Exchange|Mailbox|Forward|Rule|Access|Download|Upload|Delete|Modify|Create" -or
            $_.category -match "DataAccess|DataModification|DataExfiltration" -or
            $_.operationType -match "File|Mail|Access"
        }
        
        Write-Host "Total Purview Audit Logs retrieved: $($logs.Count)" -ForegroundColor Green
        return $logs
    } catch {
        Write-Error "Failed to fetch Purview Audit Logs: $($_.Exception.Message)"
        return @()
    }
}

# Function to optimize Purview data for SOC analysis
function Convert-PurviewDataForSOC {
    param([object]$PurviewLogs)
    
    if (-not $PurviewLogs) {
        return @()
    }
    
    $enhancedLogs = $PurviewLogs | ForEach-Object {
        $log = $_
        
        # Extract file information
        $fileName = if ($log.targetResources) {
            $fileResource = $log.targetResources | Where-Object { $_.displayName -like "*.*" }
            if ($fileResource) { $fileResource.displayName } else { "Unknown" }
        } else { "Unknown" }
        
        # Extract file path
        $filePath = if ($log.targetResources) {
            $fileResource = $log.targetResources | Where-Object { $_.displayName -like "*/*" -or $_.displayName -like "*\\*" }
            if ($fileResource) { $fileResource.displayName } else { "Unknown" }
        } else { "Unknown" }
        
        # Extract IP address
        $ipAddress = if ($log.additionalDetails) {
            $ipDetail = $log.additionalDetails | Where-Object { $_.key -eq "IpAddress" }
            if ($ipDetail) { $ipDetail.value } else { "Unknown" }
        } else { "Unknown" }
        
        # Extract user agent
        $userAgent = if ($log.additionalDetails) {
            $uaDetail = $log.additionalDetails | Where-Object { $_.key -eq "UserAgent" }
            if ($uaDetail) { $uaDetail.value } else { "Unknown" }
        } else { "Unknown" }
        
        # Determine activity type
        $activityType = switch -Wildcard ($log.activityDisplayName) {
            "*File*" { "File Access" }
            "*Download*" { "File Download" }
            "*Upload*" { "File Upload" }
            "*Delete*" { "File Delete" }
            "*Modify*" { "File Modify" }
            "*Create*" { "File Create" }
            "*Forward*" { "Email Forward" }
            "*Rule*" { "Rule Change" }
            "*SharePoint*" { "SharePoint Access" }
            "*OneDrive*" { "OneDrive Access" }
            "*Exchange*" { "Exchange Access" }
            "*Mailbox*" { "Mailbox Access" }
            default { "Data Access" }
        }
        
        # Create optimized object for SOC analysis
        [PSCustomObject]@{
            # Essential Information
            Timestamp = (Get-Date $log.activityDateTime).ToString("yyyy-MM-dd HH:mm:ss")
            User = $log.initiatedBy.user.userPrincipalName
            Activity = $log.activityDisplayName
            ActivityType = $activityType
            Result = $log.result
            
            # File Information
            FileName = $fileName
            FilePath = $filePath
            Resource = if ($log.targetResources) { ($log.targetResources | ForEach-Object { $_.displayName }) -join ", " } else { "Unknown" }
            
            # Network Information
            IPAddress = $ipAddress
            UserAgent = $userAgent
            
            # Security Context
            Category = $log.category
            OperationType = $log.operationType
            IsSuccess = $log.result -eq "success"
            
            # Additional Details
            Details = if ($log.additionalDetails) { 
                ($log.additionalDetails | ForEach-Object { "$($_.key): $($_.value)" }) -join "; " 
            } else { "None" }
            
            # Time Analysis
            Hour = (Get-Date $log.activityDateTime).Hour
            Day = (Get-Date $log.activityDateTime).DayOfWeek
        }
    }
    
    return $enhancedLogs
}

# Function to optimize sign-in data for fast SOC analysis
function Convert-SignInDataForSOC {
    param([object]$SignInLogs)
    
    if (-not $SignInLogs) {
        return @()
    }
    
    $enhancedLogs = $SignInLogs | ForEach-Object {
        $log = $_
        
        # Extract only essential data for speed
        $location = if ($log.location) {
            "$($log.location.city), $($log.location.state), $($log.location.countryOrRegion)"
        } else { "Unknown" }
        
        $riskLevel = if ($log.riskLevelDuringSignIn) {
            $log.riskLevelDuringSignIn
        } else { "Not Assessed" }
        
        $authMethods = if ($log.authenticationDetails) {
            ($log.authenticationDetails | ForEach-Object { $_.authenticationMethod }) -join ", "
        } else { "Unknown" }
        
        $caResult = if ($log.conditionalAccessStatus) {
            $log.conditionalAccessStatus
        } else { "Not Applied" }
        
        $clientApp = if ($log.clientAppUsed) {
            $log.clientAppUsed
        } else { "Unknown" }
        
        $os = if ($log.deviceDetail -and $log.deviceDetail.operatingSystem) {
            $log.deviceDetail.operatingSystem
        } else { "Unknown" }
        
        # Create optimized object with essential SOC fields only
        [PSCustomObject]@{
            # Essential Information
            Timestamp = (Get-Date $log.createdDateTime).ToString("yyyy-MM-dd HH:mm:ss")
            User = $log.userPrincipalName
            IP = $log.ipAddress
            Location = $location
            Success = if ($log.status) { $log.status.errorCode -eq 0 } else { $false }
            
            # Security Assessment
            RiskLevel = $riskLevel
            IsRisky = $log.isRisky
            AuthMethod = $authMethods
            MFA = if ($authMethods -like "*MFA*" -or $authMethods -like "*Multi*") { "Yes" } else { "No" }
            
            # Device & App
            Device = if ($log.deviceDetail) { $log.deviceDetail.displayName } else { "Unknown" }
            OS = $os
            App = $clientApp
            
            # Conditional Access
            CAStatus = $caResult
            CAPolicies = if ($log.appliedConditionalAccessPolicies) { 
                ($log.appliedConditionalAccessPolicies | ForEach-Object { $_.result }) -join ", " 
            } else { "None" }
            
            # Quick Analysis
            Hour = (Get-Date $log.createdDateTime).Hour
            Day = (Get-Date $log.createdDateTime).DayOfWeek
            Interactive = $log.isInteractive
        }
    }
    
    return $enhancedLogs
}

# Function to export data to Excel files
function Export-DataToExcel {
    param(
        [object]$Data,
        [string]$FileName,
        [string]$OutputPath,
        [string]$SheetName = "Data",
        [switch]$EnhanceForSOC = $false
    )
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $excelFilePath = Join-Path $OutputPath "$FileName`_$timestamp.xlsx"
    $jsonFilePath = Join-Path $OutputPath "$FileName`_$timestamp.json"
    
    try {
        # Enhance data for SOC analysis if requested
        if ($EnhanceForSOC -and $Data) {
            if ($SheetName -like "*Sign-in*") {
                $Data = Convert-SignInDataForSOC -SignInLogs $Data
            } elseif ($SheetName -like "*Purview*") {
                $Data = Convert-PurviewDataForSOC -PurviewLogs $Data
            } elseif ($SheetName -like "*Forwarding*") {
                $Data = Convert-ForwardingRulesForSOC -ForwardingLogs $Data
            }
        }
        
        # Export to Excel
        if ($Data -and $Data.Count -gt 0) {
            $Data | Export-Excel -Path $excelFilePath -WorksheetName $SheetName -AutoSize -TableStyle Medium2 -BoldTopRow
            Write-Host "Excel file exported to: $excelFilePath" -ForegroundColor Green
        } else {
            Write-Host "No data to export for $FileName" -ForegroundColor Yellow
            # Create empty Excel file with headers
            [PSCustomObject]@{Message = "No data found for the specified criteria"} | Export-Excel -Path $excelFilePath -WorksheetName $SheetName -AutoSize -TableStyle Medium2 -BoldTopRow
        }
        
        # Also export to JSON for backup
        if ($Data) {
            $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFilePath -Encoding UTF8
        } else {
            '{"message": "No data found for the specified criteria"}' | Out-File -FilePath $jsonFilePath -Encoding UTF8
        }
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
        
        # Enable verbose output if requested
        if ($VerboseOutput) {
            $VerbosePreference = "Continue"
        }
        
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
            $safeUPN = $UPN -replace '[^\w\-\.]', '_'
            Export-DataToExcel -Data $ualLogs -FileName "UnifiedAuditLogs_$safeUPN" -OutputPath $OutputPath -SheetName "Unified Audit Logs"
            
            # Get sign-in logs for the user
            Write-Host "Fetching Sign-in Logs for $UPN..." -ForegroundColor Yellow
            $signInLogs = Get-SignInLogs -StartDate $startDate -EndDate $endDate -UPN $UPN
            Export-DataToExcel -Data $signInLogs -FileName "SignInLogs_$safeUPN" -OutputPath $OutputPath -SheetName "Sign-in Logs" -EnhanceForSOC
            
            # Get Purview audit logs for the user
            Write-Host "Fetching Purview Audit Logs for $UPN..." -ForegroundColor Yellow
            $purviewLogs = Get-PurviewAuditLogs -StartDate $startDate -EndDate $endDate -UPN $UPN
            Export-DataToExcel -Data $purviewLogs -FileName "PurviewLogs_$safeUPN" -OutputPath $OutputPath -SheetName "Purview Logs" -EnhanceForSOC
            
            # Get email forwarding rules for the user
            Write-Host "Checking Email Forwarding Rules for $UPN..." -ForegroundColor Yellow
            $forwardingRules = Get-EmailForwardingRules -UPN $UPN -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $forwardingRules -FileName "ForwardingRules_$safeUPN" -OutputPath $OutputPath -SheetName "Forwarding Rules" -EnhanceForSOC
        } else {
            # Fetch all UAL logs
            Write-Host "Fetching Unified Audit Logs..." -ForegroundColor Yellow
            $ualLogs = Get-UnifiedAuditLogs -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $ualLogs -FileName "UnifiedAuditLogs" -OutputPath $OutputPath -SheetName "Unified Audit Logs"
            
            # Fetch all sign-in logs
            Write-Host "Fetching Sign-in Logs..." -ForegroundColor Yellow
            $signInLogs = Get-SignInLogs -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $signInLogs -FileName "SignInLogs" -OutputPath $OutputPath -SheetName "Sign-in Logs" -EnhanceForSOC
            
            # Fetch all Purview audit logs
            Write-Host "Fetching Purview Audit Logs..." -ForegroundColor Yellow
            $purviewLogs = Get-PurviewAuditLogs -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $purviewLogs -FileName "PurviewLogs" -OutputPath $OutputPath -SheetName "Purview Logs" -EnhanceForSOC
            
            # Fetch all email forwarding rules
            Write-Host "Checking Email Forwarding Rules..." -ForegroundColor Yellow
            $forwardingRules = Get-EmailForwardingRules -UPN "" -StartDate $startDate -EndDate $endDate
            Export-DataToExcel -Data $forwardingRules -FileName "ForwardingRules" -OutputPath $OutputPath -SheetName "Forwarding Rules" -EnhanceForSOC
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
