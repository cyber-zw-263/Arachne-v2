#!/usr/bin/env python3
"""
ARACHNE v2.0 SETUP WIZARD
Crafted for Hxcker-263 ❤️
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
from getpass import getpass
import random

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.columns import Columns
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box

console = Console()

class ArachneSetupWizard:
    def __init__(self):
        self.project_root = Path.cwd()
        self.config = {}
        self.api_keys = {}
        self.targets = []
        self.notifications = {}
        self.wordlists = {}
        self.owner = "Hxcker-263"
        
    def show_banner(self):
        """Display banner with tasteful credit."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    [bold cyan]ARACHNE v2.0[/bold cyan]                    ║
║                  Setup Configuration Wizard                  ║
╚══════════════════════════════════════════════════════════════╝
"""
        console.print(banner)
        console.print(f"[dim]Configuration wizard for {self.owner}'s security framework[/dim]\n")
        
    def check_prerequisites(self):
        """Check system prerequisites."""
        console.print("[bold cyan]Checking system prerequisites...[/bold cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            tasks = {
                "Python Version": self._check_python_version,
                "Directory Permissions": self._check_permissions,
                "Required Tools": self._check_tools,
                "Network Connectivity": self._check_network,
            }
            
            task = progress.add_task("System check...", total=len(tasks))
            
            results = {}
            for name, check_func in tasks.items():
                progress.update(task, description=f"Checking {name}...")
                try:
                    result, message = check_func()
                    results[name] = (result, message)
                    progress.advance(task)
                except Exception as e:
                    results[name] = (False, f"Error: {str(e)}")
            
            # Display results
            table = Table(show_header=True, box=box.ROUNDED)
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details")
            
            all_ok = True
            for name, (status, message) in results.items():
                status_text = "✅ PASS" if status else "❌ FAIL"
                status_style = "green" if status else "red"
                table.add_row(name, f"[{status_style}]{status_text}[/{status_style}]", message)
                if not status:
                    all_ok = False
            
            console.print(table)
            
            if not all_ok:
                if not Confirm.ask("\n[bold yellow]Some checks failed. Continue anyway?[/bold yellow]"):
                    console.print("[red]Setup aborted.[/red]")
                    sys.exit(1)
                    
    def _check_python_version(self):
        """Check Python version."""
        version = sys.version_info
        if version.major == 3 and version.minor >= 9:
            return True, f"Python {version.major}.{version.minor}.{version.micro}"
        return False, f"Python 3.9+ required (found {version.major}.{version.minor})"
    
    def _check_permissions(self):
        """Check directory permissions."""
        test_file = self.project_root / ".arachne_test"
        try:
            test_file.touch()
            test_file.unlink()
            return True, "Write permissions OK"
        except:
            return False, "Cannot write to current directory"
    
    def _check_tools(self):
        """Check for required command line tools."""
        tools = ["git", "docker", "nmap"]
        missing = []
        
        for tool in tools:
            if shutil.which(tool) is None:
                missing.append(tool)
        
        if missing:
            return False, f"Missing: {', '.join(missing)}"
        return True, "All tools available"
    
    def _check_network(self):
        """Check network connectivity."""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True, "Internet connection OK"
        except:
            return False, "No internet connection"
    
    def configure_api_keys(self):
        """Interactive API key configuration."""
        console.print("\n[bold cyan]API Key Configuration[/bold cyan]")
        console.print("[dim]Enter your API keys (press Enter to skip)[/dim]\n")
        
        api_services = {
            "shodan": {
                "name": "Shodan",
                "description": "Internet intelligence",
                "format": "32 character alphanumeric"
            },
            "censys": {
                "name": "Censys (ID)",
                "description": "Asset discovery",
                "format": "UUID format"
            },
            "censys_secret": {
                "name": "Censys (Secret)",
                "description": "Censys API secret",
                "format": "Secret key"
            },
            "github_token": {
                "name": "GitHub Token",
                "description": "Code search access",
                "format": "ghp_... (40 chars)"
            },
            "openai": {
                "name": "OpenAI API",
                "description": "AI-powered analysis",
                "format": "sk-... (51 chars)"
            },
        }
        
        for key_id, info in api_services.items():
            console.print(f"\n[bold]{info['name']}[/bold]")
            console.print(f"[dim]{info['description']} | Format: {info['format']}[/dim]")
            
            key = Prompt.ask(
                f"Enter {info['name']} key",
                password='secret' in info['name'].lower(),
                default=""
            )
            
            if key:
                self.api_keys[key_id] = key
                console.print(f"[green]✓ {info['name']} key saved[/green]")
            else:
                console.print(f"[dim]Skipped[/dim]")
        
        # Encryption option
        if self.api_keys and Confirm.ask("\n[bold]Encrypt API keys with password?[/bold]"):
            self._encrypt_keys()
    
    def _encrypt_keys(self):
        """Encrypt API keys with password."""
        from cryptography.fernet import Fernet
        import base64
        
        password = getpass("[bold cyan]Enter encryption password: [/bold cyan]")
        confirm = getpass("[bold cyan]Confirm password: [/bold cyan]")
        
        if password != confirm:
            console.print("[red]Passwords don't match. Keys not encrypted.[/red]")
            return
        
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        cipher = Fernet(key)
        
        encrypted_keys = {}
        for service, key_value in self.api_keys.items():
            encrypted_keys[service] = cipher.encrypt(key_value.encode()).decode()
        
        self.api_keys = encrypted_keys
        console.print("[green]✓ API keys encrypted[/green]")
    
    def configure_targets(self):
        """Interactive target configuration."""
        console.print("\n[bold cyan]Target Configuration[/bold cyan]")
        console.print("[dim]Define your scanning targets[/dim]\n")
        
        while True:
            target = {}
            
            console.print(f"[bold]Target #{len(self.targets) + 1}[/bold]")
            
            # Domain
            while True:
                domain = Prompt.ask("[cyan]Primary domain[/cyan] (e.g., example.com)")
                if self._validate_domain(domain):
                    target["domain"] = domain
                    break
                else:
                    console.print("[yellow]Invalid domain format[/yellow]")
            
            # Scope
            scopes = []
            console.print("\n[cyan]Scope patterns (blank to finish)[/cyan]")
            while True:
                scope = Prompt.ask(
                    f"Scope {len(scopes) + 1}",
                    default="",
                    show_default=False
                )
                if scope:
                    scopes.append(scope)
                else:
                    break
            
            target["scope"] = scopes if scopes else [f"*.{domain}"]
            
            # Priority
            priority_options = ["critical", "high", "medium", "low"]
            console.print("\n[cyan]Priority level[/cyan]")
            for i, priority in enumerate(priority_options, 1):
                console.print(f"  {i}. {priority}")
            
            priority_choice = Prompt.ask(
                "Select priority",
                choices=["1", "2", "3", "4"],
                default="3"
            )
            target["priority"] = priority_options[int(priority_choice) - 1]
            
            # Tags
            target["tags"] = ["external", "bug-bounty"]
            if Confirm.ask("\n[cyan]Add custom tags?[/cyan]"):
                tags = []
                while True:
                    tag = Prompt.ask(
                        f"Tag {len(tags) + 1}",
                        default="",
                        show_default=False
                    )
                    if tag:
                        tags.append(tag)
                    else:
                        break
                if tags:
                    target["tags"].extend(tags)
            
            self.targets.append(target)
            console.print(f"[green]✓ Target '{domain}' added[/green]")
            
            if not Confirm.ask("\n[cyan]Add another target?[/cyan]"):
                break
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        import re
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        return bool(re.match(pattern, domain.lower()))
    
    def configure_notifications(self):
        """Configure notification channels."""
        console.print("\n[bold cyan]Notification Configuration[/bold cyan]")
        console.print("[dim]Configure alert channels[/dim]\n")
        
        channels = {
            "telegram": {"name": "Telegram", "config": ["bot_token", "chat_id"]},
            "discord": {"name": "Discord", "config": ["webhook_url"]},
            "slack": {"name": "Slack", "config": ["webhook_url"]},
        }
        
        for channel_id, channel_info in channels.items():
            console.print(f"\n[bold]{channel_info['name']}[/bold]")
            
            if Confirm.ask(f"  Enable {channel_info['name']} notifications?"):
                channel_config = {"enabled": True}
                
                for config_key in channel_info["config"]:
                    value = Prompt.ask(f"    {config_key.replace('_', ' ').title()}")
                    channel_config[config_key] = value
                
                self.notifications[channel_id] = channel_config
                console.print(f"    [green]✓ {channel_info['name']} configured[/green]")
            else:
                self.notifications[channel_id] = {"enabled": False}
    
    def configure_scanning(self):
        """Configure scanning parameters."""
        console.print("\n[bold cyan]Scanning Configuration[/bold cyan]")
        
        self.config["global_settings"] = {}
        gs = self.config["global_settings"]
        
        # Basic settings
        gs["rate_limit"] = IntPrompt.ask(
            "Requests per second",
            default=10,
            show_default=True
        )
        
        gs["max_concurrent"] = IntPrompt.ask(
            "Max concurrent targets",
            default=5,
            show_default=True
        )
        
        # Features
        gs["auto_report"] = Confirm.ask(
            "\nEnable auto-reporting?",
            default=True
        )
        
        gs["ai_enabled"] = Confirm.ask(
            "Enable AI-powered attacks?",
            default=True
        )
        
        gs["deep_dive"] = Confirm.ask(
            "Enable deep dive analysis?",
            default=True
        )
        
        # User agent
        gs["user_agent"] = "Arachne/2.0 (Security Research)"
    
    def configure_wordlists(self):
        """Configure custom wordlists."""
        if Confirm.ask("\n[bold cyan]Create custom wordlists?[/bold cyan]"):
            wordlist_types = ["directories", "subdomains", "parameters", "passwords"]
            
            for wl_type in wordlist_types:
                if Confirm.ask(f"\nConfigure {wl_type} wordlist?"):
                    console.print(f"[dim]Enter entries (blank to finish)[/dim]")
                    
                    entries = []
                    while True:
                        entry = Prompt.ask(
                            f"Entry {len(entries) + 1}",
                            default="",
                            show_default=False
                        )
                        if entry:
                            entries.append(entry)
                        else:
                            break
                    
                    if entries:
                        self.wordlists[wl_type] = entries
                        console.print(f"[green]✓ {len(entries)} entries added[/green]")
    
    def configure_modules(self):
        """Enable/disable specific modules."""
        console.print("\n[bold cyan]Module Selection[/bold cyan]")
        console.print("[dim]Choose which tools to enable[/dim]\n")
        
        modules = {
            "silken_sentry": {"name": "Silken Sentry", "desc": "Subdomain enumeration", "default": True},
            "venom_fang": {"name": "Venom Fang", "desc": "API fuzzing", "default": True},
            "widows_bite": {"name": "Widow's Bite", "desc": "Injection testing", "default": True},
            "neural_mimic": {"name": "Neural Mimic", "desc": "AI bypass", "default": True},
            "graphql_ast_hacker": {"name": "GraphQL Hacker", "desc": "GraphQL analysis", "default": False},
            "websocket_protocol_phreak": {"name": "WebSocket Phreak", "desc": "Real-time protocols", "default": False},
        }
        
        enabled_modules = []
        
        for module_id, module_info in modules.items():
            question = f"[bold]{module_info['name']}[/bold] - {module_info['desc']}\n  Enable?"
            
            if Confirm.ask(question, default=module_info["default"]):
                enabled_modules.append(module_id)
                console.print(f"  [green]✓ Enabled[/green]")
            else:
                console.print(f"  [dim]Disabled[/dim]")
        
        self.config["enabled_modules"] = enabled_modules
    
    def review_configuration(self):
        """Display configuration summary for review."""
        console.print("\n" + "═" * 60)
        console.print("[bold cyan]CONFIGURATION REVIEW[/bold cyan]")
        console.print("═" * 60)
        
        # Summary
        console.print(f"\n[bold]Summary[/bold]")
        console.print(f"  Targets: {len(self.targets)}")
        console.print(f"  API Keys: {len(self.api_keys)}")
        console.print(f"  Modules: {len(self.config.get('enabled_modules', []))}")
        
        # Preview first target
        if self.targets:
            console.print(f"\n[bold]Sample Target[/bold]")
            target = self.targets[0]
            console.print(f"  Domain: {target['domain']}")
            console.print(f"  Scope: {', '.join(target['scope'][:2])}")
            if len(target['scope']) > 2:
                console.print(f"  ... and {len(target['scope']) - 2} more")
        
        console.print("\n" + "═" * 60)
        
        return Confirm.ask("\n[bold green]Save this configuration?[/bold green]", default=True)
    
    def save_configuration(self):
        """Save all configuration files."""
        console.print("\n[bold cyan]Saving Configuration...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Saving...", total=5)
            
            # Create config directory
            config_dir = self.project_root / "config"
            config_dir.mkdir(exist_ok=True)
            progress.update(task, advance=1, description="Creating directories...")
            
            # Save targets.json
            targets_config = {
                "targets": self.targets,
                "global_settings": self.config.get("global_settings", {})
            }
            
            with open(config_dir / "targets.json", "w") as f:
                json.dump(targets_config, f, indent=2)
            progress.update(task, advance=1, description="Saving targets...")
            
            # Save notifications
            with open(config_dir / "notification_webhooks.json", "w") as f:
                json.dump(self.notifications, f, indent=2)
            progress.update(task, advance=1, description="Saving notifications...")
            
            # Save API keys
            if self.api_keys:
                from cryptography.fernet import Fernet
                
                key_file = self.project_root / ".arachne_key"
                if not key_file.exists():
                    key = Fernet.generate_key()
                    with open(key_file, "wb") as f:
                        f.write(key)
                    key_file.chmod(0o600)
                else:
                    with open(key_file, "rb") as f:
                        key = f.read()
                
                cipher = Fernet(key)
                encrypted = {}
                for service, key_value in self.api_keys.items():
                    encrypted[service] = cipher.encrypt(key_value.encode()).decode()
                
                with open(self.project_root / ".arachne_keys", "w") as f:
                    json.dump(encrypted, f, indent=2)
            progress.update(task, advance=1, description="Securing API keys...")
            
            # Save wordlists
            if self.wordlists:
                wordlist_dir = config_dir / "wordlists"
                wordlist_dir.mkdir(exist_ok=True)
                
                for wl_type, entries in self.wordlists.items():
                    with open(wordlist_dir / f"{wl_type}.txt", "w") as f:
                        f.write("\n".join(entries))
            progress.update(task, advance=1, description="Saving wordlists...")
            
            progress.update(task, completed=5, description="[green]Configuration saved![/green]")
    
    def create_env_file(self):
        """Create .env file from configuration."""
        env_content = f"""# ARACHNE v2.0 Configuration
# Generated for {self.owner} on {datetime.now().strftime('%Y-%m-%d')}

ARACHNE_DATA_DIR=./data
ARACHNE_LOG_LEVEL=INFO
ARACHNE_MAX_CONCURRENT={self.config["global_settings"].get("max_concurrent", 5)}
ARACHNE_RATE_LIMIT={self.config["global_settings"].get("rate_limit", 10)}
ARACHNE_AI_ENABLED={self.config["global_settings"].get("ai_enabled", True)}
ARACHNE_AUTO_REPORT={self.config["global_settings"].get("auto_report", True)}
"""
        
        with open(self.project_root / ".env", "w") as f:
            f.write(env_content)
        
        console.print("[green]✓ Environment file created[/green]")
    
    def show_completion(self):
        """Show completion message."""
        console.print("\n" + "═" * 60)
        console.print("[bold green]SETUP COMPLETE[/bold green]")
        console.print("═" * 60)
        
        summary = Panel(
            f"Configuration successfully saved!\n\n"
            f"[bold]Next steps:[/bold]\n"
            f"1. Install dependencies: [cyan]pip install -r requirements.txt[/cyan]\n"
            f"2. Test configuration: [cyan]python arachne_core.py --test[/cyan]\n"
            f"3. Start scanning: [cyan]python arachne_core.py[/cyan]\n\n"
            f"[dim]Framework configured for {self.owner}[/dim]",
            title="Ready to Hunt",
            border_style="green",
            box=box.ROUNDED
        )
        
        console.print(summary)
        
        # Show file locations
        console.print("\n[bold]Configuration files:[/bold]")
        console.print("  config/targets.json")
        console.print("  config/notification_webhooks.json")
        console.print("  .arachne_keys (encrypted)")
        console.print("  .env")
        
        console.print(f"\n[dim]Happy hunting, {self.owner}![/dim]")
    
    def run(self):
        """Main execution flow."""
        try:
            self.show_banner()
            
            # Configuration steps
            steps = [
                ("System Check", self.check_prerequisites),
                ("API Keys", self.configure_api_keys),
                ("Targets", self.configure_targets),
                ("Notifications", self.configure_notifications),
                ("Scanning Settings", self.configure_scanning),
                ("Wordlists", self.configure_wordlists),
                ("Modules", self.configure_modules),
            ]
            
            for i, (name, func) in enumerate(steps, 1):
                console.print(f"\n[bold]Step {i}/{len(steps)}: {name}[/bold]")
                func()
            
            # Review and save
            if self.review_configuration():
                self.save_configuration()
                self.create_env_file()
                self.show_completion()
            else:
                console.print("[yellow]Configuration not saved.[/yellow]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Setup interrupted.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Setup failed: {str(e)}[/red]")
            sys.exit(1)

def main():
    """Entry point."""
    wizard = ArachneSetupWizard()
    wizard.run()

if __name__ == "__main__":
    main()