#!/usr/bin/env python
import time
import argparse
from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool

def test_performance(url, visible=False):
    """
    Test the performance of the Firefox browser automation tool.
    
    Args:
        url: Target URL to test
        visible: Whether to run Firefox in visible mode
    """
    print(f"Testing Firefox browser performance on {url}")
    print(f"Visible mode: {'Yes' if visible else 'No'}")
    
    # Create a simple form field test
    entry_point = {
        'type': 'form_input',
        'form_fields': {
            'email': 'email',
            'password': 'password'
        }
    }
    
    # Use a simple SQL injection payload
    payload = "' OR '1'='1"
    
    # Initialize the tool
    tool = FirefoxBrowserAutomationTool()
    
    # Measure execution time
    start_time = time.time()
    
    # Run the tool
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
    
    print(f"Execution completed in {execution_time:.2f} seconds")
    print("\nResult summary:")
    print("-" * 50)
    
    # Print a summary of the result (first few lines)
    result_lines = result.split('\n')
    for line in result_lines[:10]:
        print(line)
    print("...")
    
    return execution_time

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Firefox Browser Automation Tool Performance')
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode')
    
    args = parser.parse_args()
    test_performance(args.url, args.visible) 