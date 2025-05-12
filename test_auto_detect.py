#!/usr/bin/env python
import time
import argparse
from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool

def test_auto_detect(url, visible=False):
    """
    Test the auto-detection and multiple payload features.
    
    Args:
        url: Target URL to test
        visible: Whether to run Firefox in visible mode
    """
    print(f"Testing auto-detection and multiple payloads on {url}")
    print(f"Visible mode: {'Yes' if visible else 'No'}")
    
    # Create an entry point with no selector or form_fields
    # The auto-detection should find the form fields
    entry_point = {
        'type': 'form_input',
        # No selector or form_fields provided
    }
    
    # Initial payload (which may not work)
    payload = "' OR 1=1 --"
    
    # Initialize the tool
    tool = FirefoxBrowserAutomationTool()
    
    # Measure execution time
    start_time = time.time()
    
    # Run the tool with our improved features
    result = tool._run(
        target_url=url,
        payload=payload,
        entry_point=entry_point,
        capture_screenshot=True,
        max_retries=2,
        popup_timeout=2,
        visible_mode=visible
    )
    
    # Calculate execution time
    execution_time = time.time() - start_time
    
    print(f"\nExecution completed in {execution_time:.2f} seconds")
    print("\nResult summary:")
    print("-" * 50)
    
    # Print the full result as it includes information about all payloads tried
    print(result)
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Auto-detection and Multiple Payloads')
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode')
    
    args = parser.parse_args()
    test_auto_detect(args.url, args.visible) 