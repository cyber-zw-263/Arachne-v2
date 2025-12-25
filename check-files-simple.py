#!/usr/bin/env python3
"""
SIMPLE ARACHNE AUDITOR
Quick check for missing files.
"""

import os
from pathlib import Path

# Expected files structure
EXPECTED_FILES = [
    "arachne_core.py",
    "requirements.txt",
    "README.md",
    "setup.py",
    ".gitignore",
    ".env.example",
    "config/targets.json",
    "config/notification_webhooks.json",
    "config/modules.json",
    "config/wordlists/api_params_custom.txt",
    "config/wordlists/directories_context.txt",
    "config/wordlists/mutations_base.txt",
    "modules/__init__.py",
    "modules/silken_sentry.py",
    "modules/venom_fang.py",
    "modules/widows_bite.py",
    "modules/myrmidon.py",
    "modules/tapestry.py",
    "modules/correlation_engine.py",
    "modules/orb_weaver.py",
    "modules/signal_system.py",
    "utils/__init__.py",
    "utils/crypto_vault.py",
    "utils/async_http_client.py",
    "utils/payload_genius.py",
    "utils/waf_buster.py",
    "integrations/__init__.py",
    "integrations/shodan_censys_client.py",
    "reports/generator.py",
    "reports/template.md",
    "tests/__init__.py",
    "tests/test_integration.py",
]

def check_project(root_path="."):
    """Check which files are missing."""
    root = Path(root_path)
    missing = []
    empty = []
    exists = []
    
    print(f"🔍 Checking project at: {root.absolute()}")
    print("-" * 50)
    
    for filepath in EXPECTED_FILES:
        full_path = root / filepath
        
        if full_path.exists():
            size = full_path.stat().st_size
            if size > 100:  # More than 100 bytes
                exists.append((filepath, size))
            else:
                empty.append((filepath, size))
        else:
            missing.append(filepath)
    
    # Print results
    if exists:
        print(f"\n✅ EXISTING ({len(exists)}):")
        for filepath, size in sorted(exists)[:10]:  # Show first 10
            print(f"  {filepath} ({size} bytes)")
        if len(exists) > 10:
            print(f"  ... and {len(exists) - 10} more")
    
    if empty:
        print(f"\n⚠️  EMPTY/SMALL ({len(empty)}):")
        for filepath, size in empty:
            print(f"  {filepath} ({size} bytes)")
    
    if missing:
        print(f"\n❌ MISSING ({len(missing)}):")
        for filepath in missing:
            print(f"  {filepath}")
    
    # Summary
    print("\n" + "=" * 50)
    total = len(EXPECTED_FILES)
    complete = len(exists)
    percentage = (complete / total) * 100
    
    print(f"📊 SUMMARY: {complete}/{total} files ({percentage:.1f}%)")
    
    if percentage < 50:
        print("🚨 Project is less than 50% complete!")
    elif percentage < 80:
        print("⚠️  Project needs more work")
    else:
        print("✅ Project is well structured!")
    
    return missing, empty, exists

def generate_fix_commands(missing_files):
    """Generate bash commands to create missing structure."""
    if not missing_files:
        return
    
    print("\n💡 Quick fix commands:")
    print("# Create directories:")
    
    dirs_to_create = set()
    for filepath in missing_files:
        dir_path = os.path.dirname(filepath)
        if dir_path:
            dirs_to_create.add(dir_path)
    
    for directory in sorted(dirs_to_create):
        print(f"mkdir -p {directory}")
    
    print("\n# Create empty files:")
    for filepath in missing_files:
        print(f"touch {filepath}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        root_path = sys.argv[1]
    else:
        root_path = "."
    
    missing, empty, exists = check_project(root_path)
    
    if missing:
        response = input("\nGenerate fix commands? (y/n): ")
        if response.lower() in ['y', 'yes']:
            generate_fix_commands(missing)