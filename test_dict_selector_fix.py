#!/usr/bin/env python
import time
import argparse
from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool

def test_dict_selector_fix(url, visible=False):
    """
    Test the fix for the "invalid type: map, expected a string" error with dictionary selectors.
    
    Args:
        url: Target URL to test
        visible: Whether to run Firefox in visible mode
    """
    print(f"Testing dictionary selector fix on {url}")
    print(f"Visible mode: {'Yes' if visible else 'No'}")
    
    # Create an entry point with a dictionary as selector - this would cause the error before our fix
    entry_point = {
        'type': 'form_input',
        'selector': {'username': 'value'},  # This was causing "invalid type: map, expected a string"
    }
    
    # Initialize the tool
    tool = FirefoxBrowserAutomationTool()
    
    # Measure execution time
    start_time = time.time()
    
    # Run the tool - should now switch to auto-detection and work
    result = tool._run(
        target_url=url,
        payload="' OR '1'='1",
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
    
    # Print the full result
    print(result)
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test dictionary selector fix')
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode')
    
    args = parser.parse_args()
    test_dict_selector_fix(args.url, args.visible) 