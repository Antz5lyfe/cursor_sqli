#!/usr/bin/env python
import os
import yaml
import argparse

def load_custom_payloads(filepath="custom_payloads.yaml"):
    """
    Load and display custom SQL injection payloads from YAML file.
    
    Args:
        filepath: Path to the custom payloads YAML file
        
    Returns:
        List of payloads or None if file doesn't exist or is empty
    """
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"❌ Custom payloads file not found: {filepath}")
        return None
    
    try:
        # Load YAML file
        with open(filepath, 'r') as file:
            yaml_content = yaml.safe_load(file)
            
        # Check if file has payloads section and is not empty
        if not yaml_content or 'payloads' not in yaml_content or not yaml_content['payloads']:
            print(f"⚠️ No payloads found in {filepath} or file is empty")
            print("The SQL Payload Engineer's suggestions will be used instead.")
            return None
            
        # Get the payloads
        payloads = yaml_content['payloads']
        
        # Check for database-specific payloads
        db_specific = {}
        if 'db_specific' in yaml_content and yaml_content['db_specific']:
            db_specific = yaml_content['db_specific']
        
        return payloads, db_specific
    
    except Exception as e:
        print(f"❌ Error loading custom payloads: {str(e)}")
        return None

def display_payloads(payloads, db_specific=None):
    """Display the loaded payloads in a formatted way"""
    if not payloads:
        return
    
    print("\n📋 Custom SQL Injection Payloads Loaded:")
    print("=" * 60)
    
    for i, payload in enumerate(payloads, 1):
        print(f"{i:2d}. {payload}")
    
    if db_specific:
        print("\n🗄️ Database-Specific Payloads:")
        print("=" * 60)
        for db_type, db_payloads in db_specific.items():
            print(f"\n{db_type.upper()}:")
            for i, payload in enumerate(db_payloads, 1):
                print(f"{i:2d}. {payload}")

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Custom Payloads Manager')
    parser.add_argument('--file', '-f', 
                       default="custom_payloads.yaml", 
                       help='Path to custom payloads YAML file')
    parser.add_argument('--clear', '-c', action='store_true',
                       help='Clear the custom payloads file (to use Payload Engineer suggestions)')
    
    args = parser.parse_args()
    
    if args.clear:
        try:
            # Create empty file with just comments
            with open(args.file, 'w') as file:
                file.write("# Custom SQL Injection Payloads\n")
                file.write("# -----------------------\n")
                file.write("# This file is intentionally empty to use the Payload Engineer's suggestions\n")
                file.write("# Add payloads under the 'payloads:' section to override\n\n")
                file.write("payloads: []\n")
            print(f"✅ Cleared custom payloads file: {args.file}")
            print("The SQL Payload Engineer's suggestions will be used.")
            return
        except Exception as e:
            print(f"❌ Error clearing payloads file: {str(e)}")
            return
    
    # Load and display the payloads
    result = load_custom_payloads(args.file)
    if result:
        payloads, db_specific = result
        display_payloads(payloads, db_specific)
        print(f"\n✅ Total custom payloads loaded: {len(payloads)}")
        print("The SQL Injection Execution Expert will use these payloads.")
    
if __name__ == "__main__":
    main() 