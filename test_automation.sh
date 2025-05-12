#!/bin/bash
# Test script for Firefox Browser Automation Tool with popup and alert handling

# Ensure we're in the correct directory
cd "$(dirname "$0")"

# Display banner
echo "============================================="
echo "Firefox Browser Automation Tool Test Script"
echo "============================================="
echo ""

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "Error: Python is not installed or not in PATH"
    exit 1
fi

# Function to display help
function show_help {
    echo "Usage: ./test_automation.sh [options]"
    echo ""
    echo "Options:"
    echo "  --url URL          Target URL to test (required)"
    echo "  --selector SEL     CSS selector for target element (default: input[type=\"text\"])"
    echo "  --payload PAYLOAD  SQL injection payload (default: ' OR '1'='1)"
    echo "  --entry-type TYPE  Entry point type: form_input, url_parameter, cookie (default: form_input)"
    echo "  --visible          Run Firefox in visible mode to see the injection in real-time"
    echo "  --delay SECONDS    Add delay between actions in seconds (default: 0)"
    echo "  --help             Show this help message"
    echo ""
    echo "Example:"
    echo "  ./test_automation.sh --url https://example.com/login --selector input[name=\"username\"] --visible"
    echo ""
}

# Parse command line arguments
URL=""
SELECTOR="input[type=\"text\"]"
PAYLOAD="' OR '1'='1"
ENTRY_TYPE="form_input"
VISIBLE=""
DELAY="0"

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            URL="$2"
            shift 2
            ;;
        --selector)
            SELECTOR="$2"
            shift 2
            ;;
        --payload)
            PAYLOAD="$2"
            shift 2
            ;;
        --entry-type)
            ENTRY_TYPE="$2"
            shift 2
            ;;
        --visible)
            VISIBLE="--visible"
            shift
            ;;
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if URL is provided
if [ -z "$URL" ]; then
    echo "Error: Target URL is required"
    show_help
    exit 1
fi

# Ensure screenshots directory exists
mkdir -p screenshots

# Run the test script
echo "Running Firefox Browser Automation Tool test with:"
echo "  URL: $URL"
echo "  Selector: $SELECTOR"
echo "  Entry Type: $ENTRY_TYPE"
echo "  Payload: $PAYLOAD"
echo "  Visible Mode: ${VISIBLE:+Yes}"
echo "  Delay: $DELAY seconds"
echo ""

# Run the Python test script
COMMAND="python test_firefox_tool.py --url \"$URL\" --selector \"$SELECTOR\" --payload \"$PAYLOAD\" --entry-type \"$ENTRY_TYPE\""

if [ -n "$VISIBLE" ]; then
    COMMAND="$COMMAND --visible"
fi

if [ "$DELAY" != "0" ]; then
    COMMAND="$COMMAND --delay $DELAY"
fi

echo "Executing: $COMMAND"
eval $COMMAND

# Check exit status
if [ $? -ne 0 ]; then
    echo "Test failed with an error."
    exit 1
fi

echo ""
echo "Test completed. Check the output above for results."
echo "Screenshots (if captured) are saved in the 'screenshots' directory." 