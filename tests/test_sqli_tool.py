import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import pytest

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from cursor_sqli.tools.reconnaissance_tools import ScrapeWebsiteTool, SeleniumScrapingTool
from cursor_sqli.tools.scanner_tools import SQLInjectionScannerTool, DatabaseIdentifierTool
from cursor_sqli.tools.payload_tools import PayloadGeneratorTool, WAFEvasionTool
from cursor_sqli.tools.executor_tools import BrowserAutomationTool, ResponseAnalyzerTool

class TestReconnaissanceTools(unittest.TestCase):
    """Test cases for the reconnaissance tools."""
    
    @patch('cursor_sqli.tools.reconnaissance_tools.requests.get')
    def test_scrape_website_tool(self, mock_get):
        """Test the ScrapeWebsiteTool functionality."""
        # Mock response
        mock_response = MagicMock()
        mock_response.text = """
        <html>
            <body>
                <form id="login_form" method="post" action="/login">
                    <input type="text" name="username" id="username">
                    <input type="password" name="password" id="password">
                    <input type="submit" value="Login">
                </form>
                <a href="?id=1">Link with parameter</a>
            </body>
        </html>
        """
        mock_response.headers = {'Server': 'Apache/2.4.41'}
        mock_get.return_value = mock_response
        
        # Test the tool
        tool = ScrapeWebsiteTool()
        result = tool._run(url="http://example.com")
        
        # Assertions
        self.assertIn("Website Reconnaissance Report", result)
        self.assertIn("Server: Apache/2.4.41", result)
        self.assertIn("Forms Found:", result)
        self.assertIn("login_form", result)
        self.assertIn("URL Parameters Found:", result)
        self.assertIn("id", result)
    
    @patch('cursor_sqli.tools.reconnaissance_tools.webdriver.Chrome')
    def test_selenium_scraping_tool(self, mock_chrome):
        """Test the SeleniumScrapingTool functionality."""
        # Mock Chrome driver
        mock_driver = MagicMock()
        mock_driver.page_source = """
        <html>
            <body>
                <form id="dynamic_form" method="post" action="/api/login">
                    <input type="text" name="username" id="username">
                    <input type="password" name="password" id="password">
                    <button type="submit">Login</button>
                </form>
                <script>
                    fetch('/api/users').then(response => response.json());
                </script>
            </body>
        </html>
        """
        mock_driver.get_cookies.return_value = [{'name': 'session', 'domain': 'example.com'}]
        mock_chrome.return_value = mock_driver
        
        # Test the tool
        tool = SeleniumScrapingTool()
        result = tool._run(url="http://example.com")
        
        # Assertions
        self.assertIn("Selenium Dynamic Website Reconnaissance", result)
        self.assertIn("Dynamic Forms Found:", result)
        self.assertIn("dynamic_form", result)
        self.assertIn("Potential API Endpoints Found:", result)
        self.assertIn("/api/users", result)
        self.assertIn("Cookies:", result)
        self.assertIn("session", result)


class TestScannerTools(unittest.TestCase):
    """Test cases for the scanner tools."""
    
    @patch('cursor_sqli.tools.scanner_tools.SQLInjectionScannerTool._send_payload')
    def test_sql_injection_scanner_tool(self, mock_send_payload):
        """Test the SQLInjectionScannerTool functionality."""
        # Mock response for vulnerable entry point
        mock_send_payload.return_value = {
            'is_vulnerable': True,
            'error_message': 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
            'response_time': 0.5,
            'db_indicator': True,
            'db_type': 'MySQL'
        }
        
        # Test data
        entry_points = [
            {
                'type': 'form',
                'location': 'http://example.com/login',
                'parameter': 'username'
            }
        ]
        
        # Test the tool
        tool = SQLInjectionScannerTool()
        result = tool._run(target_url="http://example.com", entry_points=entry_points)
        
        # Assertions
        self.assertIn("SQL Injection Vulnerability Scan Results", result)
        self.assertIn("Found 1 vulnerable entry points", result)
        self.assertIn("MySQL", result)
        self.assertIn("Recommendations:", result)
    
    @patch('cursor_sqli.tools.scanner_tools.DatabaseIdentifierTool._send_identification_payload')
    def test_database_identifier_tool(self, mock_send_identification):
        """Test the DatabaseIdentifierTool functionality."""
        # Mock responses
        mock_send_identification.return_value = {
            'success': True,
            'version_info': '5.7.33',
            'schema_info': 'users'
        }
        
        # Test data
        vulnerable_points = [
            {
                'entry_type': 'form',
                'location': 'http://example.com/login',
                'parameter': 'username'
            }
        ]
        
        # Test the tool
        tool = DatabaseIdentifierTool()
        result = tool._run(target_url="http://example.com", vulnerable_points=vulnerable_points)
        
        # Assertions
        self.assertIn("Database Identification Results", result)
        self.assertIn("Most likely database type:", result)
        self.assertIn("Version information:", result)
        self.assertIn("Schema information:", result)
        self.assertIn("Database Security Assessment:", result)


class TestPayloadTools(unittest.TestCase):
    """Test cases for the payload generator tools."""
    
    def test_payload_generator_tool(self):
        """Test the PayloadGeneratorTool functionality."""
        # Test data
        context = {
            'table': 'users',
            'columns': 'username, password',
            'condition': 'id=1'
        }
        
        # Test the tool
        tool = PayloadGeneratorTool()
        mysql_result = tool._run(db_type="MySQL", attack_type="data_extraction", context=context)
        
        # Assertions for MySQL
        self.assertIn("SQL Injection Payloads for MYSQL", mysql_result)
        self.assertIn("data_extraction", mysql_result)
        self.assertIn("UNION SELECT", mysql_result)
        self.assertIn("Usage Instructions:", mysql_result)
        
        # Test other database types
        postgres_result = tool._run(db_type="PostgreSQL", attack_type="auth_bypass", context={})
        self.assertIn("SQL Injection Payloads for POSTGRESQL", postgres_result)
        self.assertIn("auth_bypass", postgres_result)
        self.assertIn("OR 1=1", postgres_result)
    
    def test_waf_evasion_tool(self):
        """Test the WAFEvasionTool functionality."""
        # Test data
        payload = "' UNION SELECT username, password FROM users -- "
        
        # Test the tool with different WAF types
        tool = WAFEvasionTool()
        generic_result = tool._run(payload=payload)
        cloudflare_result = tool._run(payload=payload, waf_type="cloudflare")
        modsecurity_result = tool._run(payload=payload, waf_type="modsecurity")
        
        # Assertions
        self.assertIn("WAF Evasion Encodings", generic_result)
        self.assertIn("Original Payload:", generic_result)
        self.assertIn("URL Encoding", generic_result)
        self.assertIn("Evasion Techniques Overview:", generic_result)
        
        self.assertIn("Cloudflare WAF", cloudflare_result)
        self.assertIn("Unicode/Hex Hybrid", cloudflare_result)
        
        self.assertIn("ModSecurity", modsecurity_result)
        self.assertIn("Nullbyte Injection", modsecurity_result)


class TestExecutorTools(unittest.TestCase):
    """Test cases for the executor tools."""
    
    @patch('cursor_sqli.tools.executor_tools.webdriver.Chrome')
    def test_browser_automation_tool(self, mock_chrome):
        """Test the BrowserAutomationTool functionality."""
        # Mock Chrome driver
        mock_driver = MagicMock()
        mock_driver.page_source = """
        <html>
            <body>
                <div>Login successful! Welcome admin</div>
                <table>
                    <tr><td>1</td><td>admin</td><td>password123</td></tr>
                    <tr><td>2</td><td>user</td><td>pass456</td></tr>
                </table>
            </body>
        </html>
        """
        # Mock find_element to return element that can be interacted with
        mock_element = MagicMock()
        mock_form = MagicMock()
        mock_submit = MagicMock()
        mock_element.find_element.return_value = mock_form
        mock_form.find_element.return_value = mock_submit
        mock_driver.find_element.return_value = mock_element
        mock_chrome.return_value = mock_driver
        
        # Test data
        entry_point = {
            'type': 'form_input',
            'selector': '#username',
            'selector_type': 'css'
        }
        
        # Patch os.makedirs to avoid directory creation
        with patch('os.makedirs'):
            # Patch open to avoid file operations
            with patch('builtins.open', unittest.mock.mock_open()):
                # Test the tool
                tool = BrowserAutomationTool()
                result = tool._run(
                    target_url="http://example.com", 
                    payload="' OR '1'='1' -- ", 
                    entry_point=entry_point
                )
        
        # Assertions
        self.assertIn("SQL Injection Execution Result", result)
        self.assertIn("Execution Status: Success", result)
        self.assertIn("Response Analysis:", result)
        self.assertIn("Authentication Bypass Detected", result)
    
    def test_response_analyzer_tool(self):
        """Test the ResponseAnalyzerTool functionality."""
        # Test data for error-based injection
        error_html = """
        <html>
            <body>
                <div class="error">
                    You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near
                </div>
            </body>
        </html>
        """
        
        # Test data for authentication bypass
        auth_html = """
        <html>
            <body>
                <div class="welcome">Welcome admin! You have successfully logged in.</div>
                <a href="logout.php">Logout</a>
            </body>
        </html>
        """
        
        # Test data for data leakage
        data_html = """
        <html>
            <body>
                <table>
                    <tr><td>1</td><td>admin@example.com</td><td>admin123</td></tr>
                    <tr><td>2</td><td>user@example.com</td><td>pass456</td></tr>
                </table>
            </body>
        </html>
        """
        
        # Test the tool with different responses
        tool = ResponseAnalyzerTool()
        error_result = tool._run(
            response_html=error_html,
            payload="' OR '1'='1' -- ",
            db_type="MySQL"
        )
        
        auth_result = tool._run(
            response_html=auth_html,
            payload="' OR '1'='1' -- ",
            db_type="unknown"
        )
        
        data_result = tool._run(
            response_html=data_html,
            payload="' UNION SELECT username, email, password FROM users -- ",
            db_type="unknown"
        )
        
        # Assertions for error-based injection
        self.assertIn("SQL Injection Response Analysis", error_result)
        self.assertIn("Error-Based Injection:", error_result)
        self.assertIn("Success: Yes", error_result)
        
        # Assertions for authentication bypass
        self.assertIn("Authentication Bypass:", auth_result)
        self.assertIn("Success: Yes", auth_result)
        self.assertIn("Welcome admin", auth_result)
        
        # Assertions for data leakage
        self.assertIn("Data Leakage:", data_result)
        self.assertIn("Success: Yes", data_result)
        self.assertIn("Email:", data_result)


if __name__ == '__main__':
    unittest.main() 