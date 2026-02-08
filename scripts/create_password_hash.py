#!/usr/bin/env python3
"""
Utility script to generate password hashes for UI user management.
Users are managed via SQL inserts, not through the UI.

Usage:
    python create_password_hash.py

The script will interactively prompt for a password and output:
1. The password hash (for INSERT/UPDATE statements)
2. A sample SQL INSERT statement

Example INSERT:
    INSERT INTO users (username, full_name, password_hash, is_active)
    VALUES ('admin', 'Administrator', 'pbkdf2:sha256:600000:...:...', TRUE);
"""

import sys
import getpass

# Add parent directory to path for imports
sys.path.insert(0, 'services/backend')

from app.auth import hash_password


def main():
    print("=" * 60)
    print("Analytical-Intelligence - Password Hash Generator")
    print("=" * 60)
    print()
    
    # Get username
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty")
        sys.exit(1)
    
    # Get full name (optional)
    full_name = input("Enter full name (optional, press Enter to skip): ").strip()
    full_name_sql = f"'{full_name}'" if full_name else "NULL"
    
    # Get password
    print()
    password = getpass.getpass("Enter password: ")
    if not password:
        print("Error: Password cannot be empty")
        sys.exit(1)
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Error: Passwords do not match")
        sys.exit(1)
    
    # Validate password strength
    if len(password) < 8:
        print("Warning: Password is less than 8 characters (not recommended)")
    
    # Generate hash
    password_hash = hash_password(password)
    
    print()
    print("=" * 60)
    print("Password Hash Generated Successfully!")
    print("=" * 60)
    print()
    print("Password Hash:")
    print(password_hash)
    print()
    print("-" * 60)
    print("SQL INSERT Statement:")
    print("-" * 60)
    print(f"""
INSERT INTO users (username, full_name, password_hash, is_active)
VALUES ('{username}', {full_name_sql}, '{password_hash}', TRUE);
""")
    print("-" * 60)
    print("SQL UPDATE Statement (to change password):")
    print("-" * 60)
    print(f"""
UPDATE users SET password_hash = '{password_hash}' WHERE username = '{username}';
""")
    print("-" * 60)
    print()
    print("SECURITY REMINDER: Store passwords securely and never share them!")
    print()


if __name__ == "__main__":
    main()
