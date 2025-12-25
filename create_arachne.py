#!/usr/bin/env python3
"""
ARACHNE PROJECT BUILDER
A stylish, interactive file tree generator with ASCII art and progress visualization.
Run this to create the complete Arachne v2.0 project structure.
"""

import os
import sys
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.syntax import Syntax
from rich.columns import Columns
from rich import box
import json

console = Console()

class ArachneBuilder:
    def __init__(self):
        self.project_root = Path.cwd()
        self.files_created = 0
        self.dirs_created = 0
        self.tree = Tree("📁 [bold cyan]arachne/[/bold cyan]")
        
    def show_banner(self):
        """Display beautiful ASCII art banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    █████╗ ██████╗  █████╗  ██████╗██╗  ██╗███╗   ██╗███████╗║
║   ██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║████╗  ██║██╔════╝║
║   ███████║██████╔╝███████║██║     ███████║██╔██╗ ██║█████╗  ║
║   ██╔══██║██╔══██╗██╔══██║██║     ██╔══██║██║╚██╗██║██╔══╝  ║
║   ██║  ██║██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║███████╗║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝║
║                                                              ║
║                    [bold cyan]v2.0 Project Builder[/bold cyan]                    ║
╚══════════════════════════════════════════════════════════════╝
"""
        console.print(banner, style="cyan")
        
    def confirm_creation(self):
        """Get user confirmation before creating files."""
        console.print("\n[bold]This will create the complete Arachne project structure.[/bold]")
        console.print("[yellow]Current directory:[/yellow]", str(self.project_root))
        
        response = console.input("\n[bold green]Proceed? (y/N): [/bold green]").strip().lower()
        if response not in ['y', 'yes']:
            console.print("[yellow]Creation cancelled.[/yellow]")
            sys.exit(0)
            
    def create_structure(self):
        """Create the entire project file tree."""
        structure = {
            "files": {
                "arachne_core.py": self._get_core_content(),
                "requirements.txt": self._get_requirements(),
                "setup.py": self._get_setup_content(),
                "run_arachne.sh": self._get_run_script(),
                "Dockerfile": self._get_dockerfile(),
                "docker-compose.yml": self._get_docker_compose(),
                "README.md": self._get_readme(),
                ".env.example": self._get_env_example(),
                ".gitignore": self._get_gitignore(),
            },
            "directories": {
                "config": {
                    "files": {
                        "targets.json": self._get_targets_config(),
                        "notification_webhooks.json": self._get_notifications_config(),
                        "wordlists/": {
                            "api_params_custom.txt": "# Custom API parameters\nid\nuser\nsearch\nquery\nfilter\n",
                            "directories_context.txt": "# Context-aware directories\nadmin\napi\ndev\ninternal\n",
                            "mutations_base.txt": "# Payload mutations\n' OR '1'='1\n' OR '1'='1'--\n' UNION SELECT\n",
                        }
                    }
                },
                "modules": {
                    "files": {
                        "__init__.py": '"""\nArachne Modules Package\n"""\n\n__all__ = [\n    \'orb_weaver\',\n    \'silken_sentry\', \n    \'venom_fang\',\n    \'widows_bite\',\n    \'myrmidon\',\n    \'neural_mimic\',\n    \'graphql_ast_hacker\',\n    \'websocket_protocol_phreak\',\n    \'synthetic_relationship_engine\',\n    \'tapestry\',\n    \'correlation_engine\',\n    \'signal_system\'\n]\n',
                        "orb_weaver.py": self._get_module_stub("Dashboard"),
                        "silken_sentry.py": self._get_module_stub("SubdomainHunter"),
                        "venom_fang.py": self._get_module_stub("APIFuzzer"),
                        "widows_bite.py": self._get_module_stub("InjectionSuite"),
                        "neural_mimic.py": self._get_module_stub("NeuralMimic"),
                        "correlation_engine.py": self._get_module_stub("KnowledgeGraph"),
                        "signal_system.py": self._get_module_stub("SignalSystem"),
                    }
                },
                "utils": {
                    "files": {
                        "__init__.py": '"""\nArachne Utilities\n"""\n',
                        "crypto_vault.py": self._get_crypto_vault(),
                        "async_http_client.py": self._get_async_client(),
                        "payload_genius.py": self._get_payload_genius(),
                        "waf_buster.py": self._get_waf_buster(),
                    }
                },
                "integrations": {
                    "files": {
                        "__init__.py": '"""\nThird-party Integrations\n"""\n',
                        "shodan_censys_client.py": self._get_shodan_client(),
                        "nuclei_runner.py": self._get_nuclei_runner(),
                        "burp_parser.py": "# Burp Suite state file parser\n",
                    }
                },
                "reports": {
                    "files": {
                        "generator.py": self._get_report_generator(),
                        "templates/": {
                            "target_report.md": self._get_report_template(),
                        },
                        "archive/": {}
                    }
                },
                "data": {
                    "subdirs": ["screenshots", "harvested_js", "loot"]
                },
                "tests": {
                    "files": {
                        "__init__.py": '"""\nArachne Tests\n"""\n',
                        "test_integration.py": self._get_test_file(),
                    }
                },
                "scripts": {
                    "files": {
                        "deploy_cloud.sh": self._get_deploy_script(),
                        "cloud_init.sh": "#!/bin/bash\n# Cloud initialization script for Arachne\n",
                    }
                },
            }
        }
        
        # Show creation progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Building Arachne structure...", total=100)
            
            # Create directories first
            self._create_dirs(structure["directories"], progress, task, 40)
            
            # Create files
            self._create_files(structure["files"], self.project_root, progress, task, 60)
            
            # Update completion
            progress.update(task, completed=100)
        
    def _create_dirs(self, structure, progress, task, weight):
        """Recursively create directories."""
        for dir_name, contents in structure.items():
            dir_path = self.project_root / dir_name
            dir_path.mkdir(exist_ok=True)
            self.dirs_created += 1
            
            # Add to visual tree
            dir_node = self.tree.add(f"📁 [blue]{dir_name}/[/blue]")
            
            if "files" in contents:
                for file_name, file_content in contents["files"].items():
                    if file_name.endswith('/'):
                        # It's a subdirectory with files
                        subdir_path = dir_path / file_name[:-1]
                        subdir_path.mkdir(exist_ok=True)
                        subdir_node = dir_node.add(f"📁 [cyan]{file_name}[/cyan]")
                        
                        for subfile, subcontent in file_content.items():
                            file_path = subdir_path / subfile
                            self._write_file(file_path, subcontent)
                            subdir_node.add(f"📄 [green]{subfile}[/green]")
                            self.files_created += 1
                            progress.update(task, advance=weight/50)
                    else:
                        # It's a file
                        file_path = dir_path / file_name
                        self._write_file(file_path, file_content)
                        dir_node.add(f"📄 [green]{file_name}[/green]")
                        self.files_created += 1
                        progress.update(task, advance=weight/50)
            
            if "subdirs" in contents:
                for subdir in contents["subdirs"]:
                    subdir_path = dir_path / subdir
                    subdir_path.mkdir(exist_ok=True)
                    dir_node.add(f"📁 [dim]{subdir}/[/dim]")
                    self.dirs_created += 1
                    progress.update(task, advance=weight/100)
    
    def _create_files(self, files, base_path, progress, task, weight):
        """Create root-level files."""
        for file_name, content in files.items():
            file_path = base_path / file_name
            self._write_file(file_path, content)
            self.tree.add(f"📄 [bold green]{file_name}[/bold green]")
            self.files_created += 1
            progress.update(task, advance=weight/len(files))
    
    def _write_file(self, path, content):
        """Write content to file with proper encoding."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def show_summary(self):
        """Display creation summary with visual tree."""
        console.print("\n" + "═" * 60)
        console.print("[bold green]✅ ARACHNE PROJECT CREATED SUCCESSFULLY![/bold green]")
        console.print("═" * 60)
        
        # Show stats
        stats_panel = Panel(
            f"[bold]📊 Creation Statistics:[/bold]\n"
            f"• 📁 Directories: [cyan]{self.dirs_created}[/cyan]\n"
            f"• 📄 Files: [green]{self.files_created}[/green]\n"
            f"• 💾 Total size: [yellow]{self._get_total_size()} KB[/yellow]",
            title="Summary",
            border_style="green",
            box=box.ROUNDED
        )
        
        console.print(stats_panel)
        
        # Show project tree
        console.print("\n[bold]🌳 Project Structure:[/bold]")
        console.print(self.tree)
        
        # Show next steps
        steps = Columns([
            Panel(
                "[bold]1. Installation[/bold]\n"
                "[cyan]pip install -r requirements.txt[/cyan]\n"
                "[dim]Install all dependencies[/dim]",
                border_style="blue"
            ),
            Panel(
                "[bold]2. Configuration[/bold]\n"
                "[cyan]python setup.py[/cyan]\n"
                "[dim]Interactive setup wizard[/dim]",
                border_style="cyan"
            ),
            Panel(
                "[bold]3. Execution[/bold]\n"
                "[cyan]python arachne_core.py[/cyan]\n"
                "[dim]Launch the framework[/dim]",
                border_style="green"
            ),
        ])
        
        console.print("\n[bold]🚀 Next Steps:[/bold]")
        console.print(steps)
        
        # Show a sample of the main file
        console.print("\n[bold]📝 Main File Preview:[/bold]")
        core_preview = self._get_core_content()[:500] + "\n..."
        console.print(Syntax(core_preview, "python", theme="monokai", line_numbers=True))
    
    def _get_total_size(self):
        """Calculate total size of created files."""
        total = 0
        for path in self.project_root.rglob('*'):
            if path.is_file():
                total += path.stat().st_size
        return total // 1024
    
    # Content generators (abbreviated for space)
    def _get_core_content(self):
        return '''#!/usr/bin/env python3
"""
ARACHNE CORE v2.0 - The Complete Orchestrator
"""
import asyncio
import signal
import sys
from rich.console import Console
console = Console()

class ArachneCore:
    def __init__(self):
        self.running = True
        
    async def run(self):
        console.print("[bold cyan]🕸️ Arachne v2.0 Initializing...[/bold cyan]")
        # Core implementation here
        console.print("[green]✅ Arachne is ready![/green]")

def main():
    core = ArachneCore()
    asyncio.run(core.run())

if __name__ == "__main__":
    main()'''
    
    def _get_requirements(self):
        return '''# ARACHNE v2.0 - Post-AI Vulnerability Framework
aiohttp>=3.10.0
rich>=13.5.0
playwright>=1.45.0
torch>=2.3.0
transformers>=4.40.0
networkx>=3.2
cryptography>=43.0.0'''
    
    def _get_setup_content(self):
        return '''#!/usr/bin/env python3
"""
Arachne Setup Script
"""
from rich.console import Console
console = Console()

def main():
    console.print("[bold cyan]Arachne v2.0 Setup[/bold cyan]")
    console.print("[green]✅ Setup complete![/green]")

if __name__ == "__main__":
    main()'''
    
    def _get_run_script(self):
        return '''#!/bin/bash
# Arachne v2.0 Runner
echo "Starting Arachne v2.0..."
python3 arachne_core.py "$@"'''
    
    def _get_dockerfile(self):
        return '''FROM python:3.11-slim
WORKDIR /arachne
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "arachne_core.py"]'''
    
    def _get_docker_compose(self):
        return '''version: '3.8'
services:
  arachne:
    build: .
    volumes:
      - ./data:/arachne/data
      - ./reports:/arachne/reports'''
    
    def _get_readme(self):
        return '''# Arachne v2.0
**Post-AI Vulnerability Framework**
The most advanced bug bounty automation system for 2025/2026.'''
    
    def _get_env_example(self):
        return '''# Arachne Environment Configuration
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
ARACHNE_LOG_LEVEL=INFO'''
    
    def _get_gitignore(self):
        return '''# Arachne Git Ignore
.env
*.pyc
__pycache__/
data/
reports/
*.key
.vscode/
.DS_Store'''
    
    def _get_targets_config(self):
        return json.dumps({
            "targets": [{
                "domain": "example.com",
                "scope": ["*.example.com"],
                "priority": "medium"
            }],
            "global_settings": {
                "rate_limit": 10,
                "max_concurrent": 5,
                "auto_report": True
            }
        }, indent=2)
    
    def _get_notifications_config(self):
        return json.dumps({
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "chat_id": ""
            }
        }, indent=2)
    
    def _get_module_stub(self, module_name):
        return f'''#!/usr/bin/env python3
"""
{module_name} Module
Arachne v2.0 - Post-AI Vulnerability Framework
"""
class {module_name}:
    def __init__(self):
        print(f"{module_name} initialized")
    
    async def run(self):
        print(f"{module_name} running...")

if __name__ == "__main__":
    import asyncio
    module = {module_name}()
    asyncio.run(module.run())'''
    
    def _get_crypto_vault(self):
        return '''"""
Secure API key management
"""
from cryptography.fernet import Fernet
import json

class Vault:
    def __init__(self):
        self.cipher = Fernet.generate_key()
    
    def save_keys(self, keys):
        """Encrypt and save API keys"""
        pass'''
    
    def _get_async_client(self):
        return '''"""
Stealthy HTTP client with rotation
"""
import aiohttp

class StealthClient:
    def __init__(self):
        self.session = None'''
    
    def _get_payload_genius(self):
        return '''"""
AI-powered payload generation
"""
class PayloadGenius:
    def __init__(self):
        self.polyglots = []
    
    def generate(self):
        """Generate creative payloads"""
        pass'''
    
    def _get_waf_buster(self):
        return '''"""
WAF detection and bypass
"""
class WAFBuster:
    def __init__(self):
        self.fingerprints = {}
    
    def detect(self, headers):
        """Detect WAF from headers"""
        pass'''
    
    def _get_shodan_client(self):
        return '''"""
Shodan and Censys integration
"""
import aiohttp

class IntelHarvester:
    def __init__(self, api_keys):
        self.api_keys = api_keys'''
    
    def _get_nuclei_runner(self):
        return '''"""
Nuclei template runner
"""
import subprocess

class NucleiRunner:
    def __init__(self):
        pass'''
    
    def _get_report_generator(self):
        return '''"""
Auto-report generation
"""
class ReportWeaver:
    def __init__(self):
        pass
    
    def generate(self):
        """Generate reports"""
        pass'''
    
    def _get_report_template(self):
        return '''# Arachne v2.0 Report
## Target: {{ target }}
## Findings:
{% for finding in findings %}
### {{ finding.type }}
- Severity: {{ finding.severity }}
{% endfor %}'''
    
    def _get_test_file(self):
        return '''"""
Arachne Integration Tests
"""
import pytest

def test_basic():
    """Basic test"""
    assert 1 + 1 == 2'''
    
    def _get_deploy_script(self):
        return '''#!/bin/bash
# Arachne Cloud Deployment
echo "Deploying Arachne v2.0..."
# Deployment logic here'''

def main():
    """Main entry point."""
    builder = ArachneBuilder()
    
    try:
        builder.show_banner()
        builder.confirm_creation()
        builder.create_structure()
        builder.show_summary()
        
        # Final celebration
        console.print("\n" + "🎉" * 30)
        console.print("[bold magenta]✨ Arachne v2.0 is ready to hunt! ✨[/bold magenta]")
        console.print("[dim]Your digital predator awaits commands...[/dim]")
        console.print("🎉" * 30)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Creation interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()