from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import requests
from bs4 import BeautifulSoup
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
import time
import logging
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException, ElementNotInteractableException, UnexpectedAlertPresentException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.alert import Alert

class ScrapeWebsiteToolInput(BaseModel):
    """Input schema for ScrapeWebsiteTool."""
    url: str = Field(..., description="URL of the website to scrape.")

class ScrapeWebsiteTool(BaseTool):
    name: str = "Website Scraper"
    description: str = (
        "Scrapes a website to collect information about its structure, forms, and potential SQL injection points."
    )
    args_schema: Type[BaseModel] = ScrapeWebsiteToolInput

    def _run(self, url: str) -> str:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Get server information
            server_info = response.headers.get('Server', 'Unknown')
            
            # Find forms
            forms = soup.find_all('form')
            forms_data = []
            for i, form in enumerate(forms):
                form_data = {
                    'id': form.get('id', f'form_{i}'),
                    'method': form.get('method', 'Unknown'),
                    'action': form.get('action', 'Unknown'),
                    'inputs': []
                }
                
                # Find all inputs in the form
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    input_data = {
                        'name': input_field.get('name', 'Unknown'),
                        'type': input_field.get('type', 'text'),
                        'id': input_field.get('id', 'Unknown')
                    }
                    form_data['inputs'].append(input_data)
                
                forms_data.append(form_data)
            
            # Find URL parameters in links
            links = soup.find_all('a', href=True)
            url_params = set()
            for link in links:
                href = link['href']
                if '?' in href:
                    params = href.split('?')[1].split('&')
                    for param in params:
                        if '=' in param:
                            param_name = param.split('=')[0]
                            url_params.add(param_name)
            
            # Check for common WAF signatures
            waf_signatures = [
                'cloudflare', 'akamai', 'imperva', 'f5', 'fortinet',
                'sucuri', 'wordfence', 'mod_security', 'aws waf', 'barracuda'
            ]
            detected_wafs = []
            for waf in waf_signatures:
                if waf.lower() in response.text.lower() or waf.lower() in str(response.headers).lower():
                    detected_wafs.append(waf)
            
            # Detect technologies
            tech_patterns = {
                'PHP': ['php', 'PHP'],
                'ASP.NET': ['asp', '.aspx', '.net'],
                'Django': ['django', 'csrftoken'],
                'Laravel': ['laravel'],
                'jQuery': ['jquery'],
                'React': ['react', 'reactjs'],
                'Angular': ['angular', 'ng-'],
                'Bootstrap': ['bootstrap'],
                'WordPress': ['wp-', 'wordpress'],
                'Joomla': ['joomla'],
                'Drupal': ['drupal']
            }
            
            detected_tech = []
            page_content = response.text.lower()
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in page_content:
                        detected_tech.append(tech)
                        break
            
            # Format results
            result = {
                'url': url,
                'server': server_info,
                'forms': forms_data,
                'url_parameters': list(url_params),
                'detected_wafs': detected_wafs,
                'technologies': detected_tech
            }
            
            # Return a formatted string representation
            result_str = f"Website Reconnaissance Report for {url}\n\n"
            result_str += f"Server: {server_info}\n\n"
            
            result_str += "Forms Found:\n"
            if forms_data:
                for form in forms_data:
                    result_str += f"  - ID: {form['id']}\n"
                    result_str += f"    Method: {form['method']}\n"
                    result_str += f"    Action: {form['action']}\n"
                    result_str += "    Inputs:\n"
                    for input_field in form['inputs']:
                        result_str += f"      - Name: {input_field['name']}, Type: {input_field['type']}\n"
            else:
                result_str += "  No forms found\n"
            
            result_str += "\nURL Parameters Found:\n"
            if url_params:
                for param in url_params:
                    result_str += f"  - {param}\n"
            else:
                result_str += "  No URL parameters found\n"
            
            result_str += "\nDetected WAFs:\n"
            if detected_wafs:
                for waf in detected_wafs:
                    result_str += f"  - {waf}\n"
            else:
                result_str += "  No WAFs detected\n"
            
            result_str += "\nDetected Technologies:\n"
            if detected_tech:
                for tech in detected_tech:
                    result_str += f"  - {tech}\n"
            else:
                result_str += "  No specific technologies detected\n"
            
            return result_str
            
        except Exception as e:
            return f"Error scraping the website: {str(e)}"


class SeleniumScrapingToolInput(BaseModel):
    """Input schema for SeleniumScrapingTool."""
    url: str = Field(..., description="URL of the website to scrape using Selenium.")

class SeleniumScrapingTool(BaseTool):
    name: str = "Selenium Website Scraper"
    description: str = (
        "Uses Selenium browser automation to scrape JavaScript-heavy websites and interact with dynamic elements."
    )
    args_schema: Type[BaseModel] = SeleniumScrapingToolInput

    def _run(self, url: str) -> str:
        try:
            # Set up Chrome options
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            
            # Set up the WebDriver
            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Navigate to the URL
            driver.get(url)
            
            # Wait for the page to load
            time.sleep(5)
            
            # Get page source after JavaScript execution
            page_source = driver.page_source
            
            # Create a BeautifulSoup object
            soup = BeautifulSoup(page_source, 'html.parser')
            
            # Find forms (both visible and hidden)
            forms = soup.find_all('form')
            forms_data = []
            for i, form in enumerate(forms):
                form_data = {
                    'id': form.get('id', f'dynamic_form_{i}'),
                    'method': form.get('method', 'Unknown'),
                    'action': form.get('action', 'Unknown'),
                    'inputs': []
                }
                
                # Find all inputs in the form
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    input_data = {
                        'name': input_field.get('name', 'Unknown'),
                        'type': input_field.get('type', 'text'),
                        'id': input_field.get('id', 'Unknown')
                    }
                    form_data['inputs'].append(input_data)
                
                forms_data.append(form_data)
            
            # Get AJAX requests
            ajax_scripts = []
            scripts = soup.find_all('script')
            for script in scripts:
                script_text = script.string
                if script_text:
                    # Look for AJAX or fetch calls
                    if 'ajax' in script_text.lower() or 'fetch(' in script_text.lower() or 'xhr.' in script_text.lower():
                        ajax_scripts.append(script_text)
            
            # Look for API endpoints
            api_endpoints = set()
            if len(ajax_scripts) > 0:
                api_pattern = r'(\/api\/[a-zA-Z0-9\/\-_]+)|(\/v[0-9]+\/[a-zA-Z0-9\/\-_]+)'
                for script in ajax_scripts:
                    matches = re.findall(api_pattern, script)
                    for match in matches:
                        if match[0]:
                            api_endpoints.add(match[0])
                        if match[1]:
                            api_endpoints.add(match[1])
            
            # Get cookies
            cookies = driver.get_cookies()
            
            # Format results
            result_str = f"Selenium Dynamic Website Reconnaissance for {url}\n\n"
            
            result_str += "Dynamic Forms Found:\n"
            if forms_data:
                for form in forms_data:
                    result_str += f"  - ID: {form['id']}\n"
                    result_str += f"    Method: {form['method']}\n"
                    result_str += f"    Action: {form['action']}\n"
                    result_str += "    Inputs:\n"
                    for input_field in form['inputs']:
                        result_str += f"      - Name: {input_field['name']}, Type: {input_field['type']}\n"
            else:
                result_str += "  No dynamic forms found\n"
            
            result_str += "\nPotential API Endpoints Found:\n"
            if api_endpoints:
                for endpoint in api_endpoints:
                    result_str += f"  - {endpoint}\n"
            else:
                result_str += "  No API endpoints detected\n"
            
            result_str += "\nCookies:\n"
            if cookies:
                for cookie in cookies:
                    result_str += f"  - Name: {cookie['name']}, Value: {cookie['value']}, Domain: {cookie['domain']}\n"
            else:
                result_str += "  No cookies found\n"
            
            # Clean up
            driver.quit()
            
            return result_str
            
        except Exception as e:
            return f"Error during Selenium scraping: {str(e)}"

class FirefoxSeleniumScrapingToolInput(BaseModel):
    """Input schema for FirefoxSeleniumScrapingTool."""
    url: str = Field(..., description="URL of the website to scrape using Firefox Selenium.")
    popup_timeout: int = Field(default=5, description="Timeout in seconds for popup detection.")

class FirefoxSeleniumScrapingTool(BaseTool):
    name: str = "Firefox Selenium Website Scraper"
    description: str = (
        "Uses Firefox browser automation to scrape JavaScript-heavy websites and interact with dynamic elements."
    )
    args_schema: Type[BaseModel] = FirefoxSeleniumScrapingToolInput

    def _run(self, url: str, popup_timeout: int = 5) -> str:
        driver = None
        try:
            # Set up Firefox options
            firefox_options = FirefoxOptions()
            firefox_options.add_argument("--headless")
            
            # Add user agent to appear more like a regular browser
            firefox_options.set_preference("general.useragent.override", 
                               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0")
            
            # Disable unwanted features
            firefox_options.set_preference("browser.tabs.remote.autostart", False)
            firefox_options.set_preference("browser.tabs.remote.autostart.2", False)
            
            # Disable notifications prompts
            firefox_options.set_preference("permissions.default.desktop-notification", 2)
            firefox_options.set_preference("dom.webnotifications.enabled", False)
            firefox_options.set_preference("dom.push.enabled", False)
            
            # Handle certificate errors
            firefox_options.accept_insecure_certs = True
            firefox_options.set_preference("security.insecure_connection_text.enabled", False)
            
            # Set up the WebDriver
            service = FirefoxService(GeckoDriverManager().install())
            driver = webdriver.Firefox(service=service, options=firefox_options)
            
            # Navigate to the URL
            driver.get(url)
            
            # Handle any initial popups or alerts
            self._handle_alerts_and_popups(driver, popup_timeout)
            
            # Wait for the page to load
            time.sleep(3)
            
            # Handle any popups that appeared after page load
            self._handle_alerts_and_popups(driver, popup_timeout)
            
            # Get page source after JavaScript execution
            page_source = driver.page_source
            
            # Create a BeautifulSoup object
            soup = BeautifulSoup(page_source, 'html.parser')
            
            # Find forms (both visible and hidden)
            forms = soup.find_all('form')
            forms_data = []
            for i, form in enumerate(forms):
                form_data = {
                    'id': form.get('id', f'dynamic_form_{i}'),
                    'method': form.get('method', 'Unknown'),
                    'action': form.get('action', 'Unknown'),
                    'inputs': []
                }
                
                # Find all inputs in the form
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    input_data = {
                        'name': input_field.get('name', 'Unknown'),
                        'type': input_field.get('type', 'text'),
                        'id': input_field.get('id', 'Unknown'),
                        'xpath': self._get_xpath(input_field)  # Include XPath for better selection in Firefox
                    }
                    form_data['inputs'].append(input_data)
                
                forms_data.append(form_data)
            
            # Get AJAX requests
            ajax_scripts = []
            scripts = soup.find_all('script')
            for script in scripts:
                script_text = script.string
                if script_text:
                    # Look for AJAX or fetch calls
                    if 'ajax' in script_text.lower() or 'fetch(' in script_text.lower() or 'xhr.' in script_text.lower():
                        ajax_scripts.append(script_text)
            
            # Look for API endpoints
            api_endpoints = set()
            if len(ajax_scripts) > 0:
                api_pattern = r'(\/api\/[a-zA-Z0-9\/\-_]+)|(\/v[0-9]+\/[a-zA-Z0-9\/\-_]+)'
                for script in ajax_scripts:
                    matches = re.findall(api_pattern, script)
                    for match in matches:
                        if match[0]:
                            api_endpoints.add(match[0])
                        if match[1]:
                            api_endpoints.add(match[1])
            
            # Get cookies
            cookies = driver.get_cookies()
            
            # Check for input validation mechanisms
            input_validation = self._check_input_validation(driver, forms_data)
            
            # Format results
            result_str = f"Firefox Selenium Website Reconnaissance for {url}\n\n"
            
            result_str += "Dynamic Forms Found:\n"
            if forms_data:
                for form in forms_data:
                    result_str += f"  - ID: {form['id']}\n"
                    result_str += f"    Method: {form['method']}\n"
                    result_str += f"    Action: {form['action']}\n"
                    result_str += "    Inputs:\n"
                    for input_field in form['inputs']:
                        result_str += f"      - Name: {input_field['name']}, Type: {input_field['type']}\n"
                        if 'xpath' in input_field:
                            result_str += f"        XPath: {input_field['xpath']}\n"
            else:
                result_str += "  No dynamic forms found\n"
            
            result_str += "\nPotential API Endpoints Found:\n"
            if api_endpoints:
                for endpoint in api_endpoints:
                    result_str += f"  - {endpoint}\n"
            else:
                result_str += "  No API endpoints detected\n"
            
            result_str += "\nCookies:\n"
            if cookies:
                for cookie in cookies:
                    result_str += f"  - Name: {cookie['name']}, Value: {cookie['value']}, Domain: {cookie['domain']}\n"
            else:
                result_str += "  No cookies found\n"
            
            result_str += "\nInput Validation Mechanisms:\n"
            if input_validation:
                for validation in input_validation:
                    result_str += f"  - {validation}\n"
            else:
                result_str += "  No input validation mechanisms detected\n"
            
            # Clean up
            driver.quit()
            
            return result_str
            
        except Exception as e:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return f"Error during Firefox Selenium scraping: {str(e)}"
    
    def _handle_alerts_and_popups(self, driver, timeout=5):
        """
        Handle any alerts, confirmation dialogs, or modal popups on the page.
        
        Args:
            driver: The Selenium WebDriver instance
            timeout: Maximum time to wait for alerts/popups
        """
        # First, check for JavaScript alerts
        try:
            WebDriverWait(driver, timeout).until(EC.alert_is_present())
            alert = Alert(driver)
            alert_text = alert.text
            print(f"Alert detected during reconnaissance: {alert_text}")
            alert.accept()
            print("Alert accepted")
            time.sleep(1)  # Brief pause after handling alert
        except TimeoutException:
            pass  # No alerts detected
        
        # Common popup selectors
        popup_selectors = [
            ".modal", "#modal", ".popup", "#popup", 
            "[class*='modal']", "[class*='popup']", "[class*='dialog']",
            ".cookie-banner", "#cookie-consent", "[class*='cookie']",
            ".notification", "#notification", "[class*='notification']",
            ".overlay", "#overlay", "[class*='overlay']"
        ]
        
        # Check for modal popups
        for selector in popup_selectors:
            try:
                popup = WebDriverWait(driver, timeout/2).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
                
                # Check if popup is visible
                if popup.is_displayed():
                    print(f"Popup detected with selector: {selector}")
                    
                    # Try to find close buttons with various common patterns
                    close_selectors = [
                        f"{selector} .close", f"{selector} .btn-close", f"{selector} .dismiss",
                        f"{selector} button[class*='close']", f"{selector} [aria-label='Close']",
                        f"{selector} button", f"{selector} .btn", f"{selector} a.close",
                        f"{selector} [class*='close']", f"{selector} [title*='Close']",
                        f"{selector} .x", f"{selector} .cancel"
                    ]
                    
                    popup_closed = False
                    for close_selector in close_selectors:
                        try:
                            close_btn = WebDriverWait(driver, timeout/2).until(
                                EC.element_to_be_clickable((By.CSS_SELECTOR, close_selector))
                            )
                            print(f"Found popup close button: {close_selector}")
                            close_btn.click()
                            popup_closed = True
                            print("Popup closed successfully")
                            time.sleep(1)  # Brief pause after closing popup
                            break
                        except (TimeoutException, NoSuchElementException, ElementNotInteractableException):
                            continue
                    
                    # If we couldn't find a close button, try pressing Escape key
                    if not popup_closed:
                        print("No close button found, trying Escape key")
                        webdriver.ActionChains(driver).send_keys(Keys.ESCAPE).perform()
                        time.sleep(1)
            except (TimeoutException, NoSuchElementException):
                continue
        
        # Check for iframes that might contain popups
        try:
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            for i, iframe in enumerate(iframes):
                try:
                    driver.switch_to.frame(iframe)
                    self._handle_alerts_and_popups(driver, timeout/2)  # Reduced timeout for nested handling
                    driver.switch_to.default_content()
                except Exception as e:
                    driver.switch_to.default_content()
        except Exception as e:
            # Ensure we're back to the main document
            driver.switch_to.default_content()
    
    def _get_xpath(self, element):
        """
        Generate an XPath for an element.
        This helps with better selection in Firefox.
        """
        try:
            components = []
            child = element if element.name else element.parent
            for parent in child.parents:
                siblings = parent.find_all(child.name, recursive=False)
                if len(siblings) > 1:
                    index = 0
                    for i, sibling in enumerate(siblings):
                        if sibling == child:
                            index = i + 1
                            break
                    components.insert(0, f"{child.name}[{index}]")
                else:
                    components.insert(0, child.name)
                child = parent
            
            xpath = '//' + '/'.join(components)
            return xpath
        except:
            return "unknown"
    
    def _check_input_validation(self, driver, forms_data):
        """
        Check for client-side input validation mechanisms.
        This is helpful to understand potential bypass methods.
        """
        validations = []
        try:
            for form in forms_data:
                for input_data in form['inputs']:
                    if input_data['type'] in ['text', 'password', 'email', 'number']:
                        input_id = input_data.get('id')
                        input_name = input_data.get('name')
                        
                        if input_id != 'Unknown':
                            # Check for HTML5 validation attributes
                            script = f"""
                                var element = document.getElementById('{input_id}');
                                if (element) {{
                                    return {{
                                        'required': element.hasAttribute('required'),
                                        'pattern': element.getAttribute('pattern'),
                                        'min': element.getAttribute('min'),
                                        'max': element.getAttribute('max'),
                                        'minlength': element.getAttribute('minlength'),
                                        'maxlength': element.getAttribute('maxlength')
                                    }};
                                }}
                                return null;
                            """
                            validation_attrs = driver.execute_script(script)
                            
                            if validation_attrs:
                                for attr, value in validation_attrs.items():
                                    if value:
                                        validations.append(f"Input '{input_id}' has {attr}={value}")
                            
                            # Check for JavaScript event handlers
                            events = ['onchange', 'oninput', 'onblur', 'onfocus']
                            for event in events:
                                has_event = driver.execute_script(f"return document.getElementById('{input_id}').hasAttribute('{event}')")
                                if has_event:
                                    validations.append(f"Input '{input_id}' has {event} event handler")
        except Exception as e:
            validations.append(f"Error checking validations: {str(e)}")
        
        return validations 