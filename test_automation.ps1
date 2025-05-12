# PowerShell script for Firefox Browser Automation Tool with popup and alert handling
param(
    [string]$Url,
    [string]$Selector = "input[type='text']",
    [string]$Payload = "' OR '1'='1",
    [ValidateSet('form_input', 'url_parameter', 'cookie')]
    [string]$EntryType = "form_input",
    [switch]$Visible,
    [float]$Delay = 0,
    [switch]$Help
)

# Display banner
Write-Host "============================================="
Write-Host "Firefox Browser Automation Tool Test Script"
Write-Host "============================================="
Write-Host ""

# Check if Python is available
try {
    python --version | Out-Null
} catch {
    Write-Host "Error: Python is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Function to display help
function Show-Help {
    Write-Host "Usage: .\test_automation.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Url URL          Target URL to test (required)"
    Write-Host "  -Selector SEL     CSS selector for target element (default: input[type='text'])"
    Write-Host "  -Payload PAYLOAD  SQL injection payload (default: ' OR '1'='1)"
    Write-Host "  -EntryType TYPE   Entry point type: form_input, url_parameter, cookie (default: form_input)"
    Write-Host "  -Visible          Run Firefox in visible mode to see the injection in real-time"
    Write-Host "  -Delay SECONDS    Add delay between actions in seconds (default: 0)"
    Write-Host "  -Help             Show this help message"
    Write-Host ""
    Write-Host "Example:"
    Write-Host "  .\test_automation.ps1 -Url https://example.com/login -Selector 'input[name=`"username`"]' -Visible"
    Write-Host ""
}

# Show help if requested
if ($Help) {
    Show-Help
    exit 0
}

# Check if URL is provided
if ([string]::IsNullOrEmpty($Url)) {
    Write-Host "Error: Target URL is required" -ForegroundColor Red
    Show-Help
    exit 1
}

# Ensure screenshots directory exists
if (-not (Test-Path "screenshots")) {
    New-Item -ItemType Directory -Path "screenshots" | Out-Null
}

# Run the test script
Write-Host "Running Firefox Browser Automation Tool test with:"
Write-Host "  URL: $Url"
Write-Host "  Selector: $Selector"
Write-Host "  Entry Type: $EntryType"
Write-Host "  Payload: $Payload"
Write-Host "  Visible Mode: $(if ($Visible) { 'Yes' } else { 'No' })"
Write-Host "  Delay: $Delay seconds"
Write-Host ""

# Build the command
$Command = "python test_firefox_tool.py --url `"$Url`" --selector `"$Selector`" --payload `"$Payload`" --entry-type `"$EntryType`""

if ($Visible) {
    $Command += " --visible"
}

if ($Delay -gt 0) {
    $Command += " --delay $Delay"
}

Write-Host "Executing: $Command" -ForegroundColor Cyan

# Run the Python test script
try {
    Invoke-Expression $Command
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Test failed with an error." -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
    Write-Host "Test completed. Check the output above for results." -ForegroundColor Green
    Write-Host "Screenshots (if captured) are saved in the 'screenshots' directory."
} catch {
    Write-Host "An error occurred while running the test script: $_" -ForegroundColor Red
    exit 1
} 