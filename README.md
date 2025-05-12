# SQL Injection Tool using CrewAI

A powerful SQL injection testing tool built using the CrewAI framework. This tool consists of a crew of specialized agents working together to identify and exploit SQL injection vulnerabilities in web applications.

## Agents

The tool employs four specialized agents:

1. **Reconnaissance Agent**: Gathers information about the target website's structure, technologies, and potential vulnerabilities.
2. **Scanner Agent**: Analyzes identified entry points to confirm if they are vulnerable to SQL injection.
3. **Payload Generator Agent**: Creates optimized SQL injection payloads based on the identified vulnerabilities and database type.
4. **Executor Agent**: Executes the generated payloads against the vulnerable target using both Chrome and Firefox browsers and documents the results.

## Features

- Comprehensive website reconnaissance to identify potential injection points
- Analysis of vulnerable entry points with automated testing
- Database type detection and version fingerprinting
- Specialized payload generation for different database types
- WAF evasion techniques to bypass security controls
- Automated browser interaction with both Chrome and Firefox to execute payloads
- Robust popup and alert handling for more reliable injections
- Multiple form submission strategies (Enter key, submit button, JavaScript)
- Intelligent retry mechanisms for failed operations
- Cross-platform compatibility (Windows, macOS, and Linux)
- Detailed reporting of findings and vulnerabilities

## Setup and Installation

### Requirements

- Python 3.8+
- Chrome or Chromium browser installed (for Selenium Chrome automation)
- Firefox browser installed (for Selenium Firefox automation)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd cursor_sqli
```

2. Create a virtual environment and activate it:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
```

3. Install the dependencies:
```bash
pip install -r requirements.txt
```

4. Install the browser automation dependencies:
```bash
pip install selenium webdriver-manager
```

### Browser Setup

#### Firefox Setup
1. Install Firefox browser from the [official website](https://www.mozilla.org/firefox/new/).
2. The tool uses webdriver-manager to automatically download and manage the geckodriver (Firefox WebDriver).

#### Chrome Setup
1. Install Chrome browser from the [official website](https://www.google.com/chrome/).
2. The tool uses webdriver-manager to automatically download and manage the chromedriver.

## Usage

### Running the Tool

To run the SQL injection tool against a target website:

```bash
run_crew --target https://example.com
```

This will execute the full workflow:
1. The Reconnaissance Agent will gather information about the target
2. The Scanner Agent will identify vulnerable entry points
3. The Payload Generator will create optimized payloads
4. The Executor Agent will test the payloads against the target using both Chrome and Firefox browsers

### Command Line Arguments

- `--target`, `-t`: Specify the target URL (required)
- `--visible`: Run browser in visible mode to see the injection in real-time
- `--delay`: Add delay between browser actions in seconds (default: 0)
- `--test-browser`: Test browser automation only, options: chrome, firefox

### Real-time Browser Visibility

You can watch the SQL injection process happen in real-time by using the `--visible` flag:

```bash
run_crew --target https://example.com --visible
```

This feature is useful for:
- Educational purposes
- Debugging injection issues
- Understanding how the target website responds
- Seeing popup and alert handling in action

You can also add a delay to slow down the process and make it easier to observe:

```bash
run_crew --target https://example.com --visible --delay 1.5
```

See the [visible mode documentation](docs/visible_mode.md) for more details.

## Testing

The tool includes a comprehensive test suite to verify the functionality of all components. To run the tests:

```bash
pytest
```

## Architecture

### CrewAI Framework

This tool uses the CrewAI framework to manage the workflow and communication between agents. The process is sequential:

1. Reconnaissance → Scanner → Payload Generator → Executor

### Tools

Each agent has specialized tools:

- **Reconnaissance Agent**:
  - `ScrapeWebsiteTool`: Extracts information about website structure and forms
  - `SeleniumScrapingTool`: Scrapes JavaScript-heavy websites using browser automation

- **Scanner Agent**:
  - `SQLInjectionScannerTool`: Tests entry points for SQL injection vulnerabilities
  - `DatabaseIdentifierTool`: Identifies the database type and version

- **Payload Generator Agent**:
  - `PayloadGeneratorTool`: Creates SQL injection payloads based on the database type
  - `WAFEvasionTool`: Encodes payloads to bypass WAF protection

- **Executor Agent**:
  - `BrowserAutomationTool`: Executes payloads using Chrome browser automation
  - `FirefoxBrowserAutomationTool`: Executes payloads using Firefox browser automation
  - `ResponseAnalyzerTool`: Analyzes responses for signs of successful exploitation

## Error Handling

The tool implements comprehensive error handling to deal with common issues:
- Browser not available or failing to launch
- HTML elements not found on the page
- Form submission failures
- Network connectivity issues
- Popups and alerts that may interfere with injections
- Iframes and complex DOM structures
- Stale element references
- Element visibility issues

## Enhanced Browser Automation

The Firefox Browser Automation Tool has been enhanced with several features to improve reliability:

### Popup and Alert Handling
- Automated detection and dismissal of common web popups including:
  - JavaScript alerts, confirms, and prompts
  - Modal dialogs and cookie banners
  - Notification requests
  - Overlay popups
  - Popups in iframes
  
### Multi-strategy Form Submission
The tool attempts form submission using multiple strategies in sequence:
1. Direct Enter key on input fields
2. Finding and clicking submit buttons (using various selection strategies)
3. JavaScript form submission

### Retry Mechanism
All operations are wrapped in a retry mechanism that:
- Attempts failed operations multiple times
- Implements progressive delays between attempts
- Captures detailed error information for troubleshooting

### Visual Evidence
- Automated screenshots capture the page state at key moments
- Error state screenshots help with debugging

## Documentation

The project includes comprehensive documentation:

- `docs/firefox_automation.md`: Detailed guide on using the enhanced Firefox automation features
- Test scripts in the project root to demonstrate correct usage

## Security Considerations

This tool is intended for ethical security testing and penetration testing purposes only. Always ensure you have proper authorization before testing any website for vulnerabilities.

## Cross-Platform Compatibility

The tool is designed to work across multiple platforms:
- Windows
- macOS
- Linux

## License

[Specify the license here]

## Performance Optimizations

The SQL injection testing tool has been optimized for faster execution while maintaining functionality. Key improvements include:

- Reduced wait times and timeouts
- Optimized element detection strategies
- More efficient popup handling
- Faster form field input

### Quick Performance Testing

To verify the tool's performance, run:

```bash
python test_performance.py --url [TARGET_URL]
```

Add the `--visible` flag to see the browser in action:

```bash
python test_performance.py --url [TARGET_URL] --visible
```

### Performance Configuration

When using the tool in your own code, you can adjust these parameters for optimal performance:

```python
from cursor_sqli.tools.executor_tools import FirefoxBrowserAutomationTool

tool = FirefoxBrowserAutomationTool()
result = tool._run(
    target_url="http://example.com/login",
    payload="' OR '1'='1",
    entry_point={
        'type': 'form_input',
        'form_fields': {
            'username': 'username',
            'password': 'password'
        }
    },
    max_retries=2,          # Default: 2 (previously 3)
    popup_timeout=2,        # Default: 2 (previously 5)
    visible_mode=True       # Default: False
)
```

## Fix for "invalid type: map, expected a string" Error

When using the CrewAI SQL Injection tool, users may encounter an error message: `invalid type: map, expected a string at line 1 column 35`. This occurs when the agent tries to pass a dictionary as a CSS selector where a string is expected.

### The Issue

This error typically happens when:
1. The SQL Injection Execution Expert agent provides a dictionary format for the `selector` parameter 
2. The executor_tools.py tries to use this dictionary directly as a CSS selector string

### The Fix

We've implemented a robust solution that:

1. Detects when a dictionary is passed as a selector
2. Automatically switches to auto-detection mode for form fields
3. Uses a fallback mechanism if auto-detection fails
4. Provides clearer guidance to the agent on proper parameter formats

### Usage Recommendations

When using the tool, always use one of these formats for entry_point:

```python
# Auto-detection (preferred method)
entry_point = {
    'type': 'form_input'
}

# Form fields with string selectors
entry_point = {
    'type': 'form_input',
    'form_fields': {
        'email': 'input[type="email"]',  
        'password': 'input[type="password"]'
    }
}

# Single selector (use only if needed)
entry_point = {
    'type': 'form_input',
    'selector': 'input#username',  # Must be a string
    'selector_type': 'css'
}
```

### Testing the Fix

You can verify that the fix works by running:

```bash
python test_dict_selector_fix.py --url [TARGET_URL] --visible
```

This test intentionally passes a dictionary as a selector, which would have caused the error before the fix, but now successfully runs using auto-detection.

## Custom Payloads Cheatsheet

You can override the SQL Payload Engineer's suggestions with your own custom payloads using the `custom_payloads.yaml` file.

### Usage

1. Edit the `custom_payloads.yaml` file in the project root directory to include your desired SQL injection payloads
2. The SQL Injection Execution Expert will use your custom payloads instead of the Payload Engineer's suggestions
3. Leave the file empty or clear it to use the Payload Engineer's suggestions again

### Important Features

- **Exact payload usage**: Payloads are used exactly as written with no modifications
- **No "123" appended**: Password fields receive the exact payload specified (no additional characters added)
- **Form field auto-detection**: Works with the automatic form field detection system
- **Multiple payload testing**: Will try each payload in sequence until one succeeds

### Example custom_payloads.yaml

```yaml
# Custom SQL Injection Payloads
payloads:
  # Authentication bypass payloads
  - "' OR '1'='1"
  - "admin' --"
  
  # Data extraction payloads
  - "' UNION SELECT username, password FROM users --"
  
  # Database manipulation
  - "'; UPDATE users SET password='hacked' WHERE username='admin'; --"
```

### Managing Custom Payloads

Use the `load_custom_payloads.py` script to manage your custom payloads:

```bash
# View currently loaded custom payloads
python load_custom_payloads.py

# Clear custom payloads (to use Payload Engineer's suggestions)
python load_custom_payloads.py --clear

# Use a different payloads file
python load_custom_payloads.py --file my_payloads.yaml
```

### Payload Templates

Ready-to-use templates are available in the `custom_payloads_templates` directory:

```bash
# Copy a template to use it
cp custom_payloads_templates/auth_bypass.yaml custom_payloads.yaml
```

Available templates:
- `auth_bypass.yaml`: Authentication bypass payloads
- `data_extraction.yaml`: Data extraction payloads 
- `blind_injection.yaml`: Blind SQL injection techniques
- `dangerous_actions.yaml`: Database manipulation payloads (use with caution)

### Benefits

- Test specific payloads against a target
- Focus on certain attack types (authentication bypass, data extraction, etc.)
- Override the AI's choices with your expert knowledge
- Quickly iterate through known working payloads
- Ensure payloads are used exactly as written with no modifications
