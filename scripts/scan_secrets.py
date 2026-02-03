#!/usr/bin/env python3
"""
Ship Safe - Secret Scanner
==========================

A simple script to scan your codebase for accidentally committed secrets.

HOW IT WORKS:
This script searches for common patterns that indicate secrets:
- API key prefixes (sk-, pk_, api_key, etc.)
- Password assignments
- Private keys
- Connection strings

WHY THIS MATTERS:
Leaked secrets are the #1 cause of security breaches in indie projects.
Once a secret is in git history, it's compromised forever (even if you delete it).
Run this BEFORE every commit, or add it to your CI pipeline.

USAGE:
    python scan_secrets.py                    # Scan current directory
    python scan_secrets.py /path/to/project   # Scan specific directory
    python scan_secrets.py --help             # Show help

LIMITATIONS:
- This is a simple pattern matcher, not a comprehensive secret scanner
- For production use, consider tools like: gitleaks, trufflehog, or detect-secrets
- False positives are possible (and better than false negatives!)
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Tuple

# =============================================================================
# CONFIGURATION
# =============================================================================

# Patterns that likely indicate secrets
# Format: (pattern_name, regex_pattern, description)
SECRET_PATTERNS = [
    # OpenAI / Anthropic API Keys
    (
        "OpenAI API Key",
        r'sk-[a-zA-Z0-9]{20,}',
        "OpenAI keys start with 'sk-'. If exposed, attackers can make API calls on your account."
    ),

    # Generic API Key patterns
    (
        "API Key Assignment",
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
        "Hardcoded API keys should be moved to environment variables."
    ),

    # AWS Keys
    (
        "AWS Access Key",
        r'AKIA[0-9A-Z]{16}',
        "AWS Access Key IDs start with 'AKIA'. Leaked AWS keys can drain your account."
    ),
    (
        "AWS Secret Key",
        r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']',
        "AWS Secret Keys should NEVER be in code."
    ),

    # Database URLs (often contain passwords)
    (
        "Database URL",
        r'(mysql|postgres|postgresql|mongodb|redis):\/\/[^\s"\']+:[^\s"\']+@',
        "Database connection strings with embedded passwords are high-risk."
    ),

    # Password assignments
    (
        "Password Assignment",
        r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
        "Hardcoded passwords are a critical security issue."
    ),

    # Private keys
    (
        "Private Key",
        r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "Private keys should NEVER be committed to git."
    ),

    # JWT Secrets
    (
        "JWT Secret",
        r'["\']?jwt[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
        "JWT secrets allow forging authentication tokens if exposed."
    ),

    # Stripe Keys
    (
        "Stripe Secret Key",
        r'sk_live_[a-zA-Z0-9]{24,}',
        "Stripe live keys can process real payments. Test keys (sk_test_) are less critical."
    ),

    # GitHub Tokens
    (
        "GitHub Token",
        r'ghp_[a-zA-Z0-9]{36}',
        "GitHub Personal Access Tokens can access your repos and organizations."
    ),
    (
        "GitHub OAuth",
        r'gho_[a-zA-Z0-9]{36}',
        "GitHub OAuth tokens should not be in source code."
    ),

    # Generic Secret patterns
    (
        "Secret Assignment",
        r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
        "Generic 'secret' assignments should be moved to environment variables."
    ),

    # Bearer tokens in code
    (
        "Bearer Token",
        r'["\']Bearer\s+[a-zA-Z0-9_\-\.]{20,}["\']',
        "Hardcoded bearer tokens are authentication credentials."
    ),

    # Supabase
    (
        "Supabase Service Key",
        r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        "Supabase service role keys bypass RLS. Only use them server-side."
    ),
]

# Files/directories to skip (these are unlikely to contain your secrets)
SKIP_DIRS = {
    'node_modules',
    '.git',
    'venv',
    'env',
    '.venv',
    '__pycache__',
    '.next',
    'dist',
    'build',
    '.nuxt',
    'vendor',
    '.bundle',
    'coverage',
}

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot',
    '.mp3', '.mp4', '.wav', '.avi',
    '.zip', '.tar', '.gz', '.rar',
    '.pdf', '.doc', '.docx',
    '.lock',  # package-lock.json, yarn.lock, etc.
    '.min.js', '.min.css',  # Minified files
}

# Maximum file size to scan (skip large files)
MAX_FILE_SIZE = 1_000_000  # 1MB


# =============================================================================
# SCANNER LOGIC
# =============================================================================

def should_skip_file(file_path: Path) -> bool:
    """Check if we should skip scanning this file."""

    # Skip by extension
    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        return True

    # Skip binary files (basic check)
    if file_path.suffix.lower() in {'.exe', '.dll', '.so', '.dylib', '.bin'}:
        return True

    # Skip if file is too large
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return True
    except OSError:
        return True

    return False


def scan_file(file_path: Path) -> List[Tuple[str, int, str, str]]:
    """
    Scan a single file for secrets.

    Returns a list of tuples: (pattern_name, line_number, matched_text, description)
    """
    findings = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

            for line_num, line in enumerate(lines, start=1):
                for pattern_name, pattern, description in SECRET_PATTERNS:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Mask the middle of the secret for safe display
                        matched_text = match.group()
                        if len(matched_text) > 10:
                            masked = matched_text[:6] + '***' + matched_text[-4:]
                        else:
                            masked = matched_text[:3] + '***'

                        findings.append((pattern_name, line_num, masked, description))

    except Exception as e:
        # Skip files we can't read
        pass

    return findings


def scan_directory(root_path: Path) -> dict:
    """
    Recursively scan a directory for secrets.

    Returns a dict mapping file paths to their findings.
    """
    results = {}

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Skip excluded directories (modify dirnames in-place to prevent descent)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename

            if should_skip_file(file_path):
                continue

            findings = scan_file(file_path)
            if findings:
                results[file_path] = findings

    return results


def print_results(results: dict, root_path: Path):
    """Print scan results in a readable format."""

    if not results:
        print("\n" + "=" * 60)
        print("  No secrets detected!")
        print("=" * 60)
        print("\nNote: This scanner uses pattern matching and may miss some secrets.")
        print("Consider also using: gitleaks, trufflehog, or detect-secrets")
        return

    total_findings = sum(len(findings) for findings in results.values())

    print("\n" + "=" * 60)
    print(f"  POTENTIAL SECRETS FOUND: {total_findings}")
    print("=" * 60)

    for file_path, findings in sorted(results.items()):
        # Show relative path for cleaner output
        try:
            rel_path = file_path.relative_to(root_path)
        except ValueError:
            rel_path = file_path

        print(f"\n{rel_path}")
        print("-" * len(str(rel_path)))

        for pattern_name, line_num, matched_text, description in findings:
            print(f"  Line {line_num}: [{pattern_name}]")
            print(f"    Found: {matched_text}")
            print(f"    Why it matters: {description}")
            print()

    print("=" * 60)
    print("  RECOMMENDED ACTIONS:")
    print("=" * 60)
    print("""
1. Move secrets to environment variables (.env file)
2. Add .env to your .gitignore
3. If secrets were already committed:
   - Rotate the compromised credentials immediately
   - Consider using 'git filter-branch' or 'BFG Repo-Cleaner'
   - Remember: pushing a delete doesn't remove git history!

4. Set up pre-commit hooks to catch this automatically:
   pip install pre-commit
   # Add gitleaks or detect-secrets to your .pre-commit-config.yaml
""")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Scan your codebase for accidentally committed secrets.",
        epilog="Example: python scan_secrets.py /path/to/your/project"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show which files are being scanned"
    )

    args = parser.parse_args()

    root_path = Path(args.path).resolve()

    if not root_path.exists():
        print(f"Error: Path does not exist: {root_path}")
        sys.exit(1)

    if not root_path.is_dir():
        print(f"Error: Path is not a directory: {root_path}")
        sys.exit(1)

    print(f"\nScanning: {root_path}")
    print("This may take a moment for large projects...")

    results = scan_directory(root_path)
    print_results(results, root_path)

    # Exit with error code if secrets found (useful for CI)
    if results:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
