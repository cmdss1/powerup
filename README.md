# Microsoft Tenant Data Fetcher

A PowerShell tool to fetch Microsoft tenant data including Unified Audit Logs (UAL), sign-in logs, and audit activity for specific accounts using app registration authentication.

## Features

- **Unified Audit Logs (UAL)**: Fetch directory audit logs with filtering capabilities
- **Sign-in Logs**: Retrieve user sign-in activities and authentication details
- **UPN-specific Audit Activity**: Get comprehensive audit trail for specific user accounts
- **App Registration Authentication**: Secure authentication using registered Azure AD application
- **Interactive Prompts**: User-friendly prompts for configuration options
- **Flexible Date Range**: Configurable time period for data retrieval
- **Excel Export**: Export all data in formatted Excel files with multiple worksheets
- **JSON Backup**: Automatic JSON backup files for data integrity

## Prerequisites

1. **PowerShell 5.1 or later**
2. **Microsoft Graph PowerShell modules**:
   ```powershell
   Install-Module Microsoft.Graph.Authentication
   Install-Module Microsoft.Graph.Identity.SignIns
   Install-Module Microsoft.Graph.Identity.DirectoryManagement
   Install-Module Microsoft.Graph.Reports
   Install-Module ImportExcel
   ```
   
   Or run the provided installation script:
   ```powershell
   .\Install-RequiredModules.ps1
   ```

3. **Azure AD App Registration** with the following permissions:
   - `AuditLog.Read.All` (Application permission)
   - `Directory.Read.All` (Application permission)
   - `User.Read.All` (Application permission)

## Setup Instructions

### 1. Create Azure AD App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Enter a name for your application (e.g., "Tenant Data Fetcher")
5. Select **Accounts in this organizational directory only**
6. Click **Register**

### 2. Configure App Permissions

1. In your app registration, go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Application permissions**
5. Add the following permissions:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `User.Read.All`
6. Click **Grant admin consent** (requires admin privileges)

### 3. Create Client Secret

1. In your app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Enter a description and select expiration period
4. Click **Add**
5. **Copy the secret value immediately** (it won't be shown again)

### 4. Configure the Tool

1. Copy `config.json` and update it with your app registration details:
   ```json
   {
       "TenantId": "your-tenant-id-here",
       "ClientId": "your-app-registration-client-id-here",
       "ClientSecret": "your-app-registration-client-secret-here"
   }
   ```

2. Find your Tenant ID in Azure Portal under **Azure Active Directory** > **Overview**

## Usage

### Basic Usage

```powershell
# Interactive mode - script will prompt for all options
.\MicrosoftTenantDataFetcher.ps1

# Fetch all UAL and sign-in logs for the last 30 days (non-interactive)
.\MicrosoftTenantDataFetcher.ps1 -NoPrompt

# Fetch audit activity for a specific user
.\MicrosoftTenantDataFetcher.ps1 -UPN "user@domain.com"

# Fetch data for the last 7 days
.\MicrosoftTenantDataFetcher.ps1 -DaysBack 7

# Specify custom output directory
.\MicrosoftTenantDataFetcher.ps1 -OutputPath "C:\MyData\AuditLogs"
```

### Parameters

- `-ConfigFile`: Path to configuration file (default: "config.json")
- `-OutputPath`: Directory to save exported data (default: ".\output")
- `-UPN`: User Principal Name to filter audit activity (optional)
- `-DaysBack`: Number of days to look back (default: 30, or prompted if 0)
- `-Verbose`: Enable verbose output
- `-NoPrompt`: Skip interactive prompts and use default values

### Examples

```powershell
# Get audit activity for specific user for last 14 days
.\MicrosoftTenantDataFetcher.ps1 -UPN "john.doe@company.com" -DaysBack 14

# Export all logs to custom location
.\MicrosoftTenantDataFetcher.ps1 -OutputPath "D:\AuditData" -DaysBack 7

# Use custom config file
.\MicrosoftTenantDataFetcher.ps1 -ConfigFile "production-config.json"
```

## Output

The tool creates timestamped Excel and JSON files in the output directory:

### Excel Files (Primary Output)

**When UPN is specified:**
- `UnifiedAuditLogs_UPN_YYYYMMDD_HHMMSS.xlsx`: Directory audit logs for specific user
- `SignInLogs_UPN_YYYYMMDD_HHMMSS.xlsx`: Sign-in activities for specific user

**When UPN is not specified (all tenant data):**
- `UnifiedAuditLogs_YYYYMMDD_HHMMSS.xlsx`: All directory audit logs
- `SignInLogs_YYYYMMDD_HHMMSS.xlsx`: All sign-in activities

### JSON Files (Backup)
- `UnifiedAuditLogs_YYYYMMDD_HHMMSS.json`: Directory audit logs in JSON format
- `SignInLogs_YYYYMMDD_HHMMSS.json`: User sign-in activities in JSON format

### Excel Features
- **Formatted Tables**: Data is exported as formatted Excel tables with headers
- **Auto-sizing**: Columns automatically adjust to content width
- **Professional Styling**: Medium2 table style with bold headers
- **Separate Files**: Each log type gets its own Excel file for better organization

## Data Structure

### Unified Audit Logs
- Activity type and display name
- Timestamp and user information
- Result status and additional details
- IP addresses and location data

### Sign-in Logs
- Authentication details and status
- Device and location information
- Risk assessment data
- Conditional access results

### UPN-specific Data
- **Unified Audit Logs**: Directory audit activities for the specified user
- **Sign-in Logs**: Authentication activities for the specified user
- **Separate Files**: Each log type is exported to its own Excel file

## Security Considerations

1. **Store credentials securely**: Never commit the `config.json` file with real credentials to version control
2. **Use least privilege**: Only grant necessary permissions to the app registration
3. **Rotate secrets**: Regularly update client secrets
4. **Monitor usage**: Review app registration usage in Azure AD

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify Tenant ID, Client ID, and Client Secret
   - Ensure app registration has proper permissions
   - Check if admin consent has been granted

2. **Permission Denied**
   - Verify API permissions are correctly assigned
   - Ensure admin consent has been granted for all permissions

3. **No Data Returned**
   - Check date range (data might not be available for very recent dates)
   - Verify UPN format is correct
   - Check if audit logging is enabled in your tenant

4. **Module Import Errors**
   - Install required Microsoft Graph modules
   - Update PowerShell to latest version
   - Run PowerShell as Administrator if needed

### Logs and Debugging

Enable verbose output for detailed logging:
```powershell
.\MicrosoftTenantDataFetcher.ps1 -Verbose
```

## License

This tool is provided as-is for educational and administrative purposes. Please ensure compliance with your organization's policies and Microsoft's terms of service.
