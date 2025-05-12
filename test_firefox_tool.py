#!/usr/bin/env python
"""
Test script for the enhanced Firefox Browser Automation Tool.
This demonstrates proper usage with popup and alert handling.
"""
import argparse
import logging
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Test the enhanced Firefox Browser Automation Tool')
    parser.add_argument('--url', required=True, help='Target URL to test')
    parser.add_argument('--selector', default='input[type="text"]', help='CSS selector for the target element')
    parser.add_argument('--payload', default="' OR '1'='1", help='SQL injection payload to use')
    parser.add_argument('--entry-type', default='form_input', choices=['form_input', 'url_parameter', 'cookie'], 
                        help='Type of entry point for the injection')
    parser.add_argument('--selector-type', default='css', choices=['css', 'xpath'], 
                        help='Type of selector (css or xpath)')
    parser.add_argument('--visible', action='store_true', 
                        help='Run Firefox in visible mode to see the injection in real-time')
    parser.add_argument('--delay', type=float, default=0, 
                        help='Add a delay (in seconds) between actions to better observe the process')
    
    args = parser.parse_args()
    
    # Ensure screenshots directory exists
    os.makedirs('screenshots', exist_ok=True)
    
    # Import the tool (import here to avoid issues if the package is not installed)
    try:
        from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool
        logger.info("Successfully imported FirefoxBrowserAutomationTool")
    except ImportError as e:
        logger.error(f"Failed to import FirefoxBrowserAutomationTool: {str(e)}")
        logger.error("Make sure the cursor_sqli package is installed or in your PYTHONPATH")
        return
    
    # Create the tool instance
    tool = FirefoxBrowserAutomationTool()
    logger.info("Created FirefoxBrowserAutomationTool instance")
    
    # Create a properly formatted entry_point dictionary
    entry_point = {
        'type': args.entry_type,
        'selector': args.selector,
        'selector_type': args.selector_type
    }
    
    logger.info(f"Using entry point: {entry_point}")
    logger.info(f"Using payload: {args.payload}")
    
    if args.visible:
        logger.info("Running in visible mode - you will see the Firefox browser window")
    else:
        logger.info("Running in headless mode - browser will not be visible")
        
    if args.delay > 0:
        logger.info(f"Using additional delay of {args.delay} seconds between actions")
        # Monkey patch the time.sleep function to add our delay
        import time
        original_sleep = time.sleep
        
        def delayed_sleep(seconds):
            original_sleep(seconds + args.delay)
            
        time.sleep = delayed_sleep
        logger.info("Applied delay to all browser actions")
    
    # Execute the tool with proper error handling
    try:
        logger.info(f"Running Firefox Browser Automation Tool on {args.url}")
        result = tool._run(
            target_url=args.url,
            payload=args.payload,
            entry_point=entry_point,  # Correctly formatted as a dictionary
            capture_screenshot=True,
            max_retries=3,            # Retry up to 3 times on failure
            popup_timeout=5,          # Wait up to 5 seconds for popups
            visible_mode=args.visible  # Use visible mode if specified
        )
        
        # Print the result
        print("\n" + "="*80)
        print("FIREFOX BROWSER AUTOMATION RESULT")
        print("="*80 + "\n")
        print(result)
        print("\n" + "="*80)
        
    except Exception as e:
        logger.error(f"Error executing Firefox Browser Automation Tool: {str(e)}")
        print(f"ERROR: {str(e)}")
        
    # Restore original sleep function if modified
    if args.delay > 0:
        time.sleep = original_sleep

if __name__ == "__main__":
    print("Firefox Browser Automation Tool Test")
    print("=" * 40)
    main() 