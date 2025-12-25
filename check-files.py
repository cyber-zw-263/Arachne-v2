#!/usr/bin/env python3
"""
ARACHNE PROJECT AUDITOR
Checks your local project against the expected structure and reports missing files.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
import json

console = Console()

class ArachneAuditor:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.expected_structure = self._get_expected_structure()
        
    def _get_expected_structure(self) -> Dict:
        """Define the expected Arachne v2.0 file structure."""
        return {
            "files": {
                "arachne_core.py": {"min_size": 1000, "description": "Main orchestrator"},
                "requirements.txt": {"min_size": 100, "description": "Python dependencies"},
                "README.md": {"min_size": 50, "description": "Project documentation"},
                "setup.py": {"min_size": 500, "description": "Setup wizard"},
                ".gitignore": {"min_size": 10, "description": "Git ignore file"},
                ".env.example": {"min_size": 100, "description": "Environment template"},
            },
            "directories": {
                "config": {
                    "files": {
                        "targets.json": {"min_size": 50, "description": "Target configuration"},
                        "notification_webhooks.json": {"min_size": 50, "description": "Notification config"},
                        "modules.json": {"min_size": 50, "description": "Module configuration"},
                    },
                    "subdirs": {
                        "wordlists": {
                            "files": {
                                "api_params_custom.txt": {"min_size": 10, "description": "API parameters"},
                                "directories_context.txt": {"min_size": 10, "description": "Directory names"},
                                "mutations_base.txt": {"min_size": 10, "description": "Payload mutations"},
                            }
                        }
                    }
                },
                "modules": {
                    "files": {
                        "__init__.py": {"min_size": 10, "description": "Package init"},
                        "silken_sentry.py": {"min_size": 500, "description": "Subdomain hunter"},
                        "venom_fang.py": {"min_size": 500, "description": "API fuzzer"},
                        "widows_bite.py": {"min_size": 500, "description": "Injection suite"},
                        "myrmidon.py": {"min_size": 300, "description": "Auth testing"},
                        "tapestry.py": {"min_size": 300, "description": "Report generator"},
                        "correlation_engine.py": {"min_size": 500, "description": "Knowledge graph"},
                        "orb_weaver.py": {"min_size": 300, "description": "Dashboard"},
                        "signal_system.py": {"min_size": 300, "description": "Notifications"},
                        "neural_mimic.py": {"min_size": 300, "description": "AI bypass"},
                        "graphql_ast_hacker.py": {"min_size": 300, "description": "GraphQL attacks"},
                        "websocket_protocol_phreak.py": {"min_size": 300, "description": "WebSocket attacks"},
                        "synthetic_relationship_engine.py": {"min_size": 300, "description": "Synthetic personas"},
                    }
                },
                "utils": {
                    "files": {
                        "__init__.py": {"min_size": 10, "description": "Package init"},
                        "crypto_vault.py": {"min_size": 200, "description": "Encryption"},
                        "async_http_client.py": {"min_size": 200, "description": "HTTP client"},
                        "payload_genius.py": {"min_size": 300, "description": "Payload generator"},
                        "waf_buster.py": {"min_size": 200, "description": "WAF bypass"},
                        "semantic_analyzer.py": {"min_size": 200, "description": "Code analysis"},
                        "polyglot_gen.py": {"min_size": 200, "description": "Polyglot payloads"},
                        "temporal_analyzer.py": {"min_size": 200, "description": "Time attacks"},
                    }
                },
                "integrations": {
                    "files": {
                        "__init__.py": {"min_size": 10, "description": "Package init"},
                        "burp_parser.py": {"min_size": 100, "description": "Burp parser"},
                        "nuclei_runner.py": {"min_size": 100, "description": "Nuclei runner"},
                        "ffuf_wrapper.py": {"min_size": 100, "description": "FFUF wrapper"},
                        "shodan_censys_client.py": {"min_size": 200, "description": "Intel clients"},
                    }
                },
                "reports": {
                    "files": {
                        "generator.py": {"min_size": 200, "description": "Report generator"},
                        "template.md": {"min_size": 100, "description": "Report template"},
                    },
                    "subdirs": {
                        "templates": {
                            "files": {
                                "target_report.md": {"min_size": 100, "description": "Target report template"},
                            }
                        },
                        "archive": {}
                    }
                },
                "data": {
                    "subdirs": {
                        "screenshots": {},
                        "harvested_js": {},
                        "loot": {},
                    }
                },
                "tests": {
                    "files": {
                        "__init__.py": {"min_size": 10, "description": "Package init"},
                        "test_integration.py": {"min_size": 100, "description": "Integration tests"},
                        "test_venom_fang.py": {"min_size": 100, "description": "Venom fang tests"},
                    }
                }
            }
        }
    
    def audit(self) -> Dict:
        """Run the full audit and return results."""
        console.print(Panel.fit(
            "[bold cyan]ARACHNE PROJECT AUDITOR[/bold cyan]\n"
            f"Checking: {self.project_root}",
            border_style="cyan"
        ))
        
        results = {
            "missing_files": [],
            "empty_files": [],
            "missing_dirs": [],
            "existing_files": [],
            "stats": {
                "total_expected": 0,
                "total_found": 0,
                "complete_percentage": 0
            }
        }
        
        # Check root files
        console.print("\n[bold]Checking root files...[/bold]")
        for filename, file_info in self.expected_structure["files"].items():
            results["stats"]["total_expected"] += 1
            file_path = self.project_root / filename
            
            if file_path.exists():
                size = file_path.stat().st_size
                if size >= file_info["min_size"]:
                    results["existing_files"].append((str(file_path), size, file_info["description"]))
                    results["stats"]["total_found"] += 1
                else:
                    results["empty_files"].append((str(file_path), size, file_info["min_size"], file_info["description"]))
            else:
                results["missing_files"].append((str(file_path), file_info["description"]))
        
        # Check directories recursively
        self._check_directory(self.expected_structure["directories"], self.project_root, results)
        
        # Calculate completion percentage
        if results["stats"]["total_expected"] > 0:
            results["stats"]["complete_percentage"] = (
                results["stats"]["total_found"] / results["stats"]["total_expected"]
            ) * 100
        
        return results
    
    def _check_directory(self, structure: Dict, base_path: Path, results: Dict):
        """Recursively check directory structure."""
        for dir_name, dir_contents in structure.items():
            dir_path = base_path / dir_name
            
            # Check if directory exists
            if not dir_path.exists():
                results["missing_dirs"].append(str(dir_path))
                # Don't check files in missing directories
                continue
            
            # Check files in this directory
            if "files" in dir_contents:
                for filename, file_info in dir_contents["files"].items():
                    results["stats"]["total_expected"] += 1
                    file_path = dir_path / filename
                    
                    if file_path.exists():
                        size = file_path.stat().st_size
                        if size >= file_info["min_size"]:
                            results["existing_files"].append((str(file_path), size, file_info["description"]))
                            results["stats"]["total_found"] += 1
                        else:
                            results["empty_files"].append((str(file_path), size, file_info["min_size"], file_info["description"]))
                    else:
                        results["missing_files"].append((str(file_path), file_info["description"]))
            
            # Recursively check subdirectories
            if "subdirs" in dir_contents:
                self._check_directory(dir_contents["subdirs"], dir_path, results)
    
    def display_results(self, results: Dict):
        """Display audit results in a beautiful format."""
        # Summary panel
        summary = Panel(
            f"[bold]Project Status:[/bold] {results['stats']['complete_percentage']:.1f}% complete\n"
            f"[green]✓ Found:[/green] {results['stats']['total_found']} files\n"
            f"[yellow]⚠ Missing:[/yellow] {len(results['missing_files'])} files\n"
            f"[red]✗ Empty:[/red] {len(results['empty_files'])} files\n"
            f"[blue]📁 Missing dirs:[/blue] {len(results['missing_dirs'])}",
            title="Audit Summary",
            border_style="green" if results['stats']['complete_percentage'] > 70 else "yellow",
            box=box.ROUNDED
        )
        console.print(summary)
        
        # Missing files table
        if results['missing_files']:
            console.print("\n[bold red]MISSING FILES[/bold red]")
            table = Table(show_header=True, box=box.SIMPLE)
            table.add_column("File", style="red")
            table.add_column("Description")
            
            for file_path, description in sorted(results['missing_files']):
                relative_path = Path(file_path).relative_to(self.project_root)
                table.add_row(str(relative_path), description)
            
            console.print(table)
        
        # Empty files table (files that exist but are too small)
        if results['empty_files']:
            console.print("\n[bold yellow]EMPTY OR INCOMPLETE FILES[/bold yellow]")
            table = Table(show_header=True, box=box.SIMPLE)
            table.add_column("File", style="yellow")
            table.add_column("Current Size", justify="right")
            table.add_column("Expected Min", justify="right")
            table.add_column("Description")
            
            for file_path, size, min_size, description in sorted(results['empty_files']):
                relative_path = Path(file_path).relative_to(self.project_root)
                table.add_row(
                    str(relative_path),
                    f"{size} bytes",
                    f"{min_size}+ bytes",
                    description
                )
            
            console.print(table)
        
        # Missing directories
        if results['missing_dirs']:
            console.print("\n[bold blue]MISSING DIRECTORIES[/bold blue]")
            for dir_path in sorted(results['missing_dirs']):
                relative_path = Path(dir_path).relative_to(self.project_root)
                console.print(f"  📁 {relative_path}")
        
        # Show existing files if requested
        if Confirm.ask("\n[dim]Show existing complete files?[/dim]", default=False):
            console.print("\n[bold green]EXISTING COMPLETE FILES[/bold green]")
            table = Table(show_header=True, box=box.SIMPLE)
            table.add_column("File", style="green")
            table.add_column("Size", justify="right")
            table.add_column("Description")
            
            for file_path, size, description in sorted(results['existing_files'])[:20]:  # Show first 20
                relative_path = Path(file_path).relative_to(self.project_root)
                table.add_row(str(relative_path), f"{size} bytes", description)
            
            console.print(table)
            
            if len(results['existing_files']) > 20:
                console.print(f"[dim]... and {len(results['existing_files']) - 20} more files[/dim]")
        
        # Recommendations
        if results['missing_files'] or results['empty_files']:
            console.print("\n[bold cyan]RECOMMENDATIONS[/bold cyan]")
            
            if results['missing_files']:
                console.print("1. Create missing files using:")
                console.print("   [cyan]python build_arachne.py[/cyan]")
            
            if results['empty_files']:
                console.print("2. Fill empty files with:")
                console.print("   [cyan]python fill_missing_code.py[/cyan]")
            
            if results['missing_dirs']:
                console.print("3. Create missing directories:")
                console.print("   [cyan]mkdir -p[/cyan] [missing_dirs]")
    
    def generate_fix_script(self, results: Dict, output_file: str = "fill_missing_code.py"):
        """Generate a script to fix missing files."""
        script_content = '''#!/usr/bin/env python3
"""
ARACHNE MISSING CODE FIXER
Generated by the Arachne Project Auditor
Fills missing or empty files with template code.
"""

import os
from pathlib import Path

def create_file(filepath: str, content: str):
    """Create a file with given content."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✓ Created: {filepath} ({len(content)} bytes)")

# Missing files to create
missing_files = {
'''

        # Add template code for each missing file
        templates = self._get_file_templates()
        
        for file_path, description in results['missing_files']:
            relative_path = Path(file_path).relative_to(self.project_root)
            filename = relative_path.name
            
            if filename in templates:
                # Escape quotes in the content
                content = templates[filename].replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                script_content += f'    "{file_path}": """{content}""",\n'
            else:
                # Generic template for unknown files
                generic_content = f'''# {filename}
# {description}
# TODO: Implement this module

def main():
    """Main function."""
    print("{filename} - Placeholder implementation")

if __name__ == "__main__":
    main()'''
                content = generic_content.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                script_content += f'    "{file_path}": """{content}""",\n'
        
        script_content += '''}

# Empty files to fill (if they exist but are too small)
empty_files = {
'''
        
        for file_path, size, min_size, description in results['empty_files']:
            filename = Path(file_path).name
            
            if filename in templates:
                content = templates[filename].replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                script_content += f'    "{file_path}": """{content}""",\n'
        
        script_content += '''}

def main():
    """Create all missing files."""
    print("Arachne Missing Code Fixer")
    print("=" * 50)
    
    # Create missing files
    if missing_files:
        print("\\nCreating missing files...")
        for filepath, content in missing_files.items():
            create_file(filepath, content)
    
    # Fill empty files
    if empty_files:
        print("\\nFilling empty files...")
        for filepath, content in empty_files.items():
            if os.path.exists(filepath):
                # Backup original
                backup = filepath + ".backup"
                if os.path.exists(filepath):
                    os.rename(filepath, backup)
                    print(f"  Backed up: {backup}")
                
            create_file(filepath, content)
    
    print("\\n✓ Done! Run the auditor again to check progress.")

if __name__ == "__main__":
    main()
'''
        
        # Save the fix script
        fix_script_path = self.project_root / output_file
        with open(fix_script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        fix_script_path.chmod(0o755)  # Make it executable
        console.print(f"\n[green]✓ Fix script generated: {output_file}[/green]")
        console.print(f"[dim]Run: python {output_file}[/dim]")
    
    def _get_file_templates(self) -> Dict[str, str]:
        """Return template code for common Arachne files."""
        return {
            "__init__.py": '''"""
Arachne Module Package
"""
__version__ = "2.0.0"
__author__ = "Hxcker-263"
''',
            "requirements.txt": '''# Arachne v2.0 Requirements
aiohttp>=3.10.0
rich>=13.5.0
playwright>=1.45.0
cryptography>=43.0.0
networkx>=3.2
''',
            "README.md": '''# Arachne v2.0
Post-AI Vulnerability Framework

## Quick Start
1. Run setup: `python setup.py`
2. Install dependencies: `pip install -r requirements.txt`
3. Start scanning: `python arachne_core.py`
''',
            ".gitignore": '''# Python
__pycache__/
*.py[cod]
*$py.class

# Arachne
data/
reports/
.env
.arachne_keys
.arachne_key

# OS
.DS_Store
Thumbs.db
''',
            "targets.json": '''{
  "targets": [],
  "global_settings": {
    "rate_limit": 10,
    "max_concurrent": 5,
    "auto_report": true
  }
}
''',
            "api_params_custom.txt": '''id
user
search
query
filter
api
token
key
secret
auth
session
''',
            "directories_context.txt": '''admin
api
dev
internal
private
secure
test
staging
prod
backup
''',
            "mutations_base.txt": '''' OR '1'='1
' OR '1'='1'--
' UNION SELECT
<script>alert(1)</script>
${7*7}
{{7*7}}
''',
        }
    
    def show_project_tree(self):
        """Display the current project tree."""
        console.print("\n[bold cyan]CURRENT PROJECT TREE[/bold cyan]")
        
        def build_tree(path: Path, tree: Tree, ignore_dirs: set = None):
            if ignore_dirs is None:
                ignore_dirs = {'.git', '__pycache__', '.pytest_cache', '.idea', '.vscode'}
            
            items = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
            
            for item in items:
                if item.name.startswith('.') and item.name not in ['.env', '.gitignore']:
                    continue
                if item.name in ignore_dirs:
                    continue
                
                if item.is_file():
                    size = item.stat().st_size
                    size_str = f" ({size} bytes)" if size > 0 else " (empty)"
                    
                    if size == 0:
                        tree.add(f"[yellow]📄 {item.name}[/yellow][dim]{size_str}[/dim]")
                    elif size < 100:
                        tree.add(f"[yellow]📄 {item.name}[/yellow][dim]{size_str}[/dim]")
                    else:
                        tree.add(f"[green]📄 {item.name}[/green][dim]{size_str}[/dim]")
                else:
                    subtree = tree.add(f"[blue]📁 {item.name}/[/blue]")
                    build_tree(item, subtree, ignore_dirs)
        
        tree = Tree(f"[bold]{self.project_root.name}/[/bold]")
        build_tree(self.project_root, tree)
        console.print(tree)

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Arachne Project Auditor")
    parser.add_argument("path", nargs="?", default=".", help="Project path to audit")
    parser.add_argument("--tree", action="store_true", help="Show project tree")
    parser.add_argument("--fix", action="store_true", help="Generate fix script")
    parser.add_argument("--strict", action="store_true", help="Strict mode (smaller min sizes)")
    
    args = parser.parse_args()
    
    auditor = ArachneAuditor(args.path)
    
    if args.tree:
        auditor.show_project_tree()
        return
    
    # Run audit
    results = auditor.audit()
    
    # Display results
    auditor.display_results(results)
    
    # Generate fix script if requested
    if args.fix and (results['missing_files'] or results['empty_files']):
        auditor.generate_fix_script(results)
    
    # Exit code based on completeness
    if results['stats']['complete_percentage'] < 50:
        console.print("\n[bold red]⚠ Project is less than 50% complete![/bold red]")
        sys.exit(1)
    elif results['stats']['complete_percentage'] < 80:
        console.print("\n[bold yellow]⚠ Project needs more work[/bold yellow]")
        sys.exit(2)

if __name__ == "__main__":
    main()