#!/usr/bin/env python
import time
import argparse
import os
import yaml
from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool

def setup_test_payload(payload="' OR '1'='1"):
    """
    Set up a test custom payload in custom_payloads.yaml
    
    Args:
        payload: The single payload to use for testing
    """
    print(f"Setting up test custom payload: {payload}")
    
    # Create or overwrite the custom_payloads.yaml file
    with open("custom_payloads.yaml", 'w') as file:
        yaml_content = {
            "payloads": [payload]
        }
        yaml.dump(yaml_content, file)
    
    print("Custom payload file created successfully")

def test_custom_payloads(url, payload, visible=False):
    """
    Test that a custom payload is used exactly as provided
    
    Args:
        url: Target URL to test
        payload: SQL injection payload to test
        visible: Whether to run Firefox in visible mode
    """
    print(f"Testing custom payload on {url}")
    print(f"Payload: {payload}")
    print(f"Visible mode: {'Yes' if visible else 'No'}")
    
    # Set up the test payload
    setup_test_payload(payload)
    
    # Create an entry point with auto-detection
    entry_point = {
        'type': 'form_input'
    }
    
    # Initialize the tool
    tool = FirefoxBrowserAutomationTool()
    
    # Measure execution time
    start_time = time.time()
    
    # Run the tool with our test payload
    result = tool._run(
        target_url=url,
        payload="This should be ignored in favor of custom payload",  # This should be ignored
        entry_point=entry_point,
        capture_screenshot=True,
        max_retries=1,
        popup_timeout=1,
        visible_mode=visible
    )
    
    # Calculate execution time
    execution_time = time.time() - start_time
    
    print(f"\nExecution completed in {execution_time:.2f} seconds")
    print("\nResult summary:")
    print("-" * 50)
    
    # Print the full result
    print(result)
    
    # Clean up after test
    if os.path.exists("custom_payloads.yaml"):
        os.remove("custom_payloads.yaml")
        print("Custom payload file cleaned up")
    
    return result

def main():
    parser = argparse.ArgumentParser(description='Test Custom Payloads')
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--payload', '-p', default="' OR '1'='1", help='SQL injection payload to test')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode')
    
    args = parser.parse_args()
    test_custom_payloads(args.url, args.payload, args.visible)

if __name__ == "__main__":
    main() 