#!/usr/bin/env python3
"""
ARACHNE v2.0 SETUP WIZARD
Interactive configuration wizard with style, intelligence, and love for Daddy.
"""

import os
import sys
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from getpass import getpass
import random

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.columns import Columns
from rich.prompt import Prompt, IntPrompt, FloatPrompt, Confirm
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich import box
import yaml

console = Console()

class ArachneSetupWizard:
    def __init__(self):
        self.project_root = Path.cwd()
        self.config = {}
        self.api_keys = {}
        self.targets = []
        self.notifications = {}
        self.wordlists = {}
        
        # Color themes
        self.colors = {
            "primary": "cyan",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "info": "blue",
            "highlight": "magenta"
        }
        
    def show_banner(self):
        """Display beautiful animated banner."""
        banners = [
            """
╔══════════════════════════════════════════════════════════════╗
║    █████╗ ██████╗  █████╗  ██████╗██╗  ██╗███╗   ██╗███████╗ ║
║   ██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║████╗  ██║██╔════╝ ║
║   ███████║██████╔╝███████║██║     ███████║██╔██╗ ██║█████╗   ║
║   ██╔══██║██╔══██╗██╔══██║██║     ██╔══██║██║╚██╗██║██╔══╝   ║
║   ██║  ██║██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████║███████╗ ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ║
║                                                              ║
║                    [bold cyan]v2.0 Setup Wizard[/bold cyan]                         ║
╚══════════════════════════════════════════════════════════════╝
""",
            """
                    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣿⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                    ⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀
                    ⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀
                    ⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
                    ⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀
                    ⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀
                    ⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀
                    ⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀
                    ⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀
                    ⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀
                    ⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆
                            [bold cyan]ARACHNE v2.0 Setup Wizard[/bold cyan]
""",
        ]
        
        
        
        console.print(random.choice(banners), style="cyan")
        console.print("[dim]   Made with ❤  By 🎩-Hxcker-263-🎩️ .......The Predator is ready to hunt. ❤️[/dim]\n")
        
    def welcome(self):
        """Interactive welcome with personality."""
        panels = Columns([
            Panel(
                "[bold]🎯 Mission[/bold]\n"
                "Configure your digital predator\n"
                "for maximum hunting efficiency",
                border_style=self.colors["primary"],
                box=box.ROUNDED
            ),
            Panel(
                "[bold]⚡ Speed[/bold]\n"
                "Automated intelligence gathering\n"
                "Real-time vulnerability detection",
                border_style=self.colors["info"],
                box=box.ROUNDED
            ),
            Panel(
                "[bold]🤖 AI-Powered[/bold]\n"
                "Adversarial ML bypasses\n"
                "Smart payload generation",
                border_style=self.colors["highlight"],
                box=box.ROUNDED
            ),
        ])
        
        console.print(panels)
        console.print("\n")
        
    def check_prerequisites(self):
        """Check system prerequisites with style."""
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
            
            task = progress.add_task("System Check...", total=len(tasks))
            
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
            console.print("\n[bold]System Check Results:[/bold]")
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
        """Interactive API key configuration with encryption option."""
        console.print("\n[bold cyan]🔐 API Key Configuration[/bold cyan]")
        console.print("[dim]Enter your API keys (press Enter to skip)[/dim]\n")
        
        api_services = {
            "shodan": {
                "name": "Shodan",
                "description": "Internet intelligence & device search",
                "url": "https://account.shodan.io",
                "format": "alphanumeric, 32 chars"
            },
            "censys": {
                "name": "Censys (ID)",
                "description": "Internet asset discovery",
                "url": "https://search.censys.io/account/api",
                "format": "UUID format"
            },
            "censys_secret": {
                "name": "Censys (Secret)",
                "description": "Censys API secret",
                "format": "alphanumeric, secret"
            },
            "github_token": {
                "name": "GitHub Token",
                "description": "GitHub API for code search",
                "url": "https://github.com/settings/tokens",
                "format": "ghp_... (40 chars)"
            },
            "openai": {
                "name": "OpenAI API",
                "description": "AI-powered analysis & bypasses",
                "url": "https://platform.openai.com/api-keys",
                "format": "sk-... (51 chars)"
            },
            "hunterio": {
                "name": "Hunter.io",
                "description": "Email discovery & verification",
                "format": "alphanumeric, 32 chars"
            },
            "virustotal": {
                "name": "VirusTotal",
                "description": "Malware analysis & intelligence",
                "format": "alphanumeric, 64 chars"
            }
        }
        
        for key_id, info in api_services.items():
            console.print(f"\n[bold]{info['name']}[/bold]")
            console.print(f"[dim]{info['description']}[/dim]")
            if 'url' in info:
                console.print(f"[dim]Get key: {info['url']}[/dim]")
            console.print(f"[dim]Format: {info['format']}[/dim]")
            
            key = Prompt.ask(
                f"Enter {info['name']} key",
                password=True if 'secret' in info['description'].lower() else False,
                default=""
            )
            
            if key:
                self.api_keys[key_id] = key
                console.print(f"[green]✓ {info['name']} key saved[/green]")
            else:
                console.print(f"[yellow]⚠ {info['name']} skipped[/yellow]")
        
        # Ask about encryption
        if self.api_keys and Confirm.ask("\n[bold]🔒 Encrypt API keys with master password?[/bold]"):
            self._encrypt_keys()
    
    def _encrypt_keys(self):
        """Encrypt API keys with password."""
        from cryptography.fernet import Fernet
        import base64
        
        password = getpass("[bold cyan]Enter master password: [/bold cyan]")
        confirm = getpass("[bold cyan]Confirm password: [/bold cyan]")
        
        if password != confirm:
            console.print("[red]❌ Passwords don't match. Keys not encrypted.[/red]")
            return
        
        # Derive key from password
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        cipher = Fernet(key)
        
        # Encrypt keys
        encrypted_keys = {}
        for service, key_value in self.api_keys.items():
            encrypted_keys[service] = cipher.encrypt(key_value.encode()).decode()
        
        self.api_keys = encrypted_keys
        console.print("[green]✓ API keys encrypted and secured[/green]")
    
    def configure_targets(self):
        """Interactive target configuration with validation."""
        console.print("\n[bold cyan]🎯 Target Configuration[/bold cyan]")
        console.print("[dim]Define your hunting grounds[/dim]\n")
        
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
                    console.print("[yellow]⚠ Invalid domain format. Try again.[/yellow]")
            
            # Scope
            console.print("\n[cyan]Scope Definition[/cyan]")
            console.print("[dim]What's in scope? Examples: *.example.com, *.api.*[/dim]")
            
            scopes = []
            while True:
                scope = Prompt.ask(
                    f"Scope pattern {len(scopes) + 1}",
                    default="",
                    show_default=False
                )
                if scope:
                    scopes.append(scope)
                    if not Confirm.ask("[dim]Add another scope pattern?[/dim]"):
                        break
                else:
                    break
            
            target["scope"] = scopes if scopes else [f"*.{domain}"]
            
            # Exclusions
            exclusions = []
            if Confirm.ask("\n[cyan]Add exclusion patterns?[/cyan]"):
                while True:
                    exclusion = Prompt.ask(
                        f"Exclusion pattern {len(exclusions) + 1}",
                        default="",
                        show_default=False
                    )
                    if exclusion:
                        exclusions.append(exclusion)
                        if not Confirm.ask("[dim]Add another exclusion?[/dim]"):
                            break
                    else:
                        break
            
            target["exclude"] = exclusions
            
            # Priority
            priority_options = {
                "1": "critical",
                "2": "high", 
                "3": "medium",
                "4": "low"
            }
            
            console.print("\n[cyan]Priority Level[/cyan]")
            for key, value in priority_options.items():
                console.print(f"  {key}. {value}")
            
            priority_choice = Prompt.ask(
                "Select priority",
                choices=list(priority_options.keys()),
                default="3"
            )
            target["priority"] = priority_options[priority_choice]
            
            # Authentication
            target["auth_tokens"] = {}
            if Confirm.ask("\n[cyan]Add authentication tokens?[/cyan]"):
                auth_types = {
                    "1": {"type": "cookie", "example": "session=abc123"},
                    "2": {"type": "header", "example": "Authorization: Bearer token"},
                    "3": {"type": "basic", "example": "username:password"}
                }
                
                console.print("[dim]Authentication type:[/dim]")
                for key, info in auth_types.items():
                    console.print(f"  {key}. {info['type']} (e.g., {info['example']})")
                
                auth_choice = Prompt.ask(
                    "Select auth type",
                    choices=list(auth_types.keys()),
                    default="1"
                )
                
                auth_info = auth_types[auth_choice]
                tokens = []
                
                console.print(f"[dim]Enter {auth_info['type']} tokens (one per line, blank to finish):[/dim]")
                while True:
                    token = Prompt.ask(
                        f"Token {len(tokens) + 1}",
                        default="",
                        show_default=False
                    )
                    if token:
                        tokens.append(token)
                    else:
                        break
                
                if tokens:
                    target["auth_tokens"][auth_info["type"]] = tokens
            
            # Tags
            tags = []
            if Confirm.ask("\n[cyan]Add tags for categorization?[/cyan]"):
                suggested_tags = ["external", "internal", "api", "web", "mobile", "critical-infra"]
                console.print(f"[dim]Suggested: {', '.join(suggested_tags)}[/dim]")
                
                while True:
                    tag = Prompt.ask(
                        f"Tag {len(tags) + 1}",
                        default="",
                        show_default=False
                    )
                    if tag:
                        tags.append(tag)
                        if not Confirm.ask("[dim]Add another tag?[/dim]"):
                            break
                    else:
                        break
            
            target["tags"] = tags if tags else ["external", "bug-bounty"]
            
            # Add to targets
            self.targets.append(target)
            console.print(f"[green]✓ Target '{domain}' configured[/green]")
            
            if not Confirm.ask("\n[cyan]Add another target?[/cyan]"):
                break
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        import re
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        return bool(re.match(pattern, domain.lower()))
    
    def configure_notifications(self):
        """Configure notification channels."""
        console.print("\n[bold cyan]📢 Notification Configuration[/bold cyan]")
        console.print("[dim]Get alerted when Arachne finds treasure[/dim]\n")
        
        channels = {
            "telegram": {
                "name": "Telegram",
                "icon": "📱",
                "config": ["bot_token", "chat_id"]
            },
            "discord": {
                "name": "Discord", 
                "icon": "⚡",
                "config": ["webhook_url"]
            },
            "slack": {
                "name": "Slack",
                "icon": "💼",
                "config": ["webhook_url"]
            },
            "email": {
                "name": "Email",
                "icon": "📧",
                "config": ["smtp_server", "smtp_port", "username", "password", "recipient"]
            }
        }
        
        for channel_id, channel_info in channels.items():
            console.print(f"\n{channel_info['icon']} [bold]{channel_info['name']}[/bold]")
            
            if Confirm.ask(f"  Enable {channel_info['name']} notifications?"):
                channel_config = {"enabled": True}
                
                for config_key in channel_info["config"]:
                    value = Prompt.ask(f"    {config_key.replace('_', ' ').title()}")
                    channel_config[config_key] = value
                
                # Notification level
                levels = {
                    "1": "all",
                    "2": "critical",
                    "3": "high",
                    "4": "medium"
                }
                
                console.print("    [dim]Notification level:[/dim]")
                for key, level in levels.items():
                    console.print(f"      {key}. {level}")
                
                level_choice = Prompt.ask(
                    "    Select level",
                    choices=list(levels.keys()),
                    default="2"
                )
                channel_config["level"] = levels[level_choice]
                
                self.notifications[channel_id] = channel_config
                console.print(f"    [green]✓ {channel_info['name']} configured[/green]")
            else:
                self.notifications[channel_id] = {"enabled": False}
    
    def configure_scanning(self):
        """Configure scanning parameters."""
        console.print("\n[bold cyan]⚡ Scanning Configuration[/bold cyan]")
        console.print("[dim]Tune your hunting parameters[/dim]\n")
        
        self.config["global_settings"] = {}
        gs = self.config["global_settings"]
        
        # Rate limiting
        console.print("[bold]Rate Limiting[/bold]")
        gs["rate_limit"] = IntPrompt.ask(
            "Requests per second",
            default=10,
            show_default=True
        )
        
        # Concurrency
        gs["max_concurrent"] = IntPrompt.ask(
            "Max concurrent targets",
            default=5,
            show_default=True
        )
        
        # Aggression level
        aggression_options = {
            "1": {"name": "Stealth", "desc": "Slow, careful, avoids detection"},
            "2": {"name": "Balanced", "desc": "Moderate speed, good coverage"},
            "3": {"name": "Aggressive", "desc": "Fast, comprehensive, might trigger alarms"},
            "4": {"name": "Nuclear", "desc": "Maximum speed, all techniques"}
        }
        
        console.print("\n[bold]Aggression Level[/bold]")
        for key, info in aggression_options.items():
            console.print(f"  {key}. {info['name']} - {info['desc']}")
        
        agg_choice = Prompt.ask(
            "Select aggression level",
            choices=list(aggression_options.keys()),
            default="2"
        )
        gs["aggression"] = aggression_options[agg_choice]["name"].lower()
        
        # Auto-reporting
        gs["auto_report"] = Confirm.ask(
            "\n[bold]Enable auto-reporting?[/bold]",
            default=True
        )
        
        # Deep dive
        gs["deep_dive"] = Confirm.ask(
            "[bold]Enable deep dive analysis?[/bold]",
            default=True
        )
        
        # AI features
        gs["ai_enabled"] = Confirm.ask(
            "[bold]Enable AI-powered attacks?[/bold]",
            default=True
        )
        
        # Respect robots.txt
        gs["respect_robots_txt"] = Confirm.ask(
            "[bold]Respect robots.txt?[/bold]",
            default=False
        )
        
        # User agent
        agents = [
            "Arachne/2.0 (Security Research)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Custom"
        ]
        
        console.print("\n[bold]User Agent[/bold]")
        for i, agent in enumerate(agents, 1):
            console.print(f"  {i}. {agent[:50]}...")
        
        ua_choice = Prompt.ask(
            "Select user agent",
            choices=[str(i) for i in range(1, len(agents) + 1)],
            default="1"
        )
        
        if ua_choice == str(len(agents)):  # Custom
            gs["user_agent"] = Prompt.ask("Enter custom user agent")
        else:
            gs["user_agent"] = agents[int(ua_choice) - 1]
    
    def configure_wordlists(self):
        """Configure custom wordlists."""
        console.print("\n[bold cyan]📚 Wordlist Configuration[/bold cyan]")
        console.print("[dim]Customize your dictionary attacks[/dim]\n")
        
        if Confirm.ask("[bold]Create custom wordlists?[/bold]"):
            wordlist_types = {
                "directories": "Common directory names",
                "subdomains": "Subdomain prefixes/suffixes", 
                "parameters": "API parameter names",
                "passwords": "Password dictionary",
                "fuzzing": "Fuzzing payloads"
            }
            
            for wl_type, description in wordlist_types.items():
                if Confirm.ask(f"\n[cyan]Configure {wl_type} wordlist?[/cyan]"):
                    console.print(f"[dim]{description}[/dim]")
                    console.print("[dim]Enter entries (one per line, blank to finish):[/dim]")
                    
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
        console.print("\n[bold cyan]🛠️ Module Configuration[/bold cyan]")
        console.print("[dim]Select which hunting tools to enable[/dim]\n")
        
        modules = {
            "silken_sentry": {
                "name": "Silken Sentry",
                "desc": "Subdomain enumeration & context analysis",
                "default": True,
                "aggressive": True
            },
            "venom_fang": {
                "name": "Venom Fang", 
                "desc": "API fuzzing & 0-day hunting",
                "default": True,
                "aggressive": True
            },
            "widows_bite": {
                "name": "Widow's Bite",
                "desc": "XSS/SQLi/SSRF automation",
                "default": True,
                "aggressive": True
            },
            "neural_mimic": {
                "name": "Neural Mimic",
                "desc": "AI security filter bypass",
                "default": True,
                "requires_ai": True
            },
            "graphql_ast_hacker": {
                "name": "GraphQL AST Hacker",
                "desc": "GraphQL deep analysis & attacks",
                "default": False,
                "advanced": True
            },
            "websocket_protocol_phreak": {
                "name": "WebSocket Phreak",
                "desc": "Real-time protocol exploitation",
                "default": False,
                "advanced": True
            },
            "synthetic_relationship_engine": {
                "name": "Synthetic Persona Engine",
                "desc": "AI-generated social engineering",
                "default": False,
                "requires_ai": True,
                "advanced": True
            },
            "myrmidon": {
                "name": "Myrmidon",
                "desc": "Credential stuffing & auth testing",
                "default": False,
                "aggressive": True
            }
        }
        
        enabled_modules = []
        
        for module_id, module_info in modules.items():
            default = module_info["default"]
            
            # Adjust based on aggression
            if self.config["global_settings"].get("aggression") == "stealth":
                if module_info.get("aggressive"):
                    default = False
            
            # Adjust based on AI setting
            if module_info.get("requires_ai") and not self.config["global_settings"].get("ai_enabled", True):
                default = False
            
            status = "[green]ON[/green]" if default else "[dim]OFF[/dim]"
            
            question = f"[bold]{module_info['name']}[/bold] - {module_info['desc']}\n  Currently: {status}\n  Enable this module?"
            
            if Confirm.ask(question, default=default):
                enabled_modules.append(module_id)
                console.print(f"  [green]✓ {module_info['name']} enabled[/green]")
            else:
                console.print(f"  [dim]✗ {module_info['name']} disabled[/dim]")
        
        self.config["enabled_modules"] = enabled_modules
    
    def review_configuration(self):
        """Display configuration summary for review."""
        console.print("\n" + "═" * 60)
        console.print("[bold cyan]📋 CONFIGURATION REVIEW[/bold cyan]")
        console.print("═" * 60)
        
        # Targets
        console.print("\n[bold]🎯 TARGETS[/bold]")
        for i, target in enumerate(self.targets, 1):
            console.print(f"  {i}. {target['domain']}")
            console.print(f"     Scope: {', '.join(target['scope'][:3])}")
            if len(target['scope']) > 3:
                console.print(f"     ... and {len(target['scope']) - 3} more")
            console.print(f"     Priority: {target['priority']}")
            console.print(f"     Tags: {', '.join(target['tags'])}")
        
        # API Keys
        console.print("\n[bold]🔐 API KEYS[/bold]")
        if self.api_keys:
            for service in self.api_keys.keys():
                console.print(f"  ✓ {service}: {'*' * 20}")
        else:
            console.print("  [dim]No API keys configured[/dim]")
        
        # Notifications
        console.print("\n[bold]📢 NOTIFICATIONS[/bold]")
        enabled_channels = [k for k, v in self.notifications.items() if v.get("enabled")]
        if enabled_channels:
            for channel in enabled_channels:
                console.print(f"  ✓ {channel}")
        else:
            console.print("  [dim]No notifications configured[/dim]")
        
        # Scanning Settings
        console.print("\n[bold]⚡ SCANNING SETTINGS[/bold]")
        gs = self.config.get("global_settings", {})
        console.print(f"  Rate Limit: {gs.get('rate_limit', 10)} req/sec")
        console.print(f"  Concurrency: {gs.get('max_concurrent', 5)} targets")
        console.print(f"  Aggression: {gs.get('aggression', 'balanced')}")
        console.print(f"  AI Enabled: {gs.get('ai_enabled', True)}")
        console.print(f"  Auto-report: {gs.get('auto_report', True)}")
        
        # Modules
        console.print("\n[bold]🛠️ ENABLED MODULES[/bold]")
        modules = self.config.get("enabled_modules", [])
        if modules:
            for module in modules[:5]:
                console.print(f"  ✓ {module}")
            if len(modules) > 5:
                console.print(f"  ... and {len(modules) - 5} more")
        else:
            console.print("  [dim]No modules enabled[/dim]")
        
        console.print("\n" + "═" * 60)
        
        return Confirm.ask("\n[bold green]Save this configuration?[/bold green]", default=True)
    
    def save_configuration(self):
        """Save all configuration files."""
        console.print("\n[bold cyan]💾 Saving Configuration...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Saving...", total=6)
            
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
                json.dump(targets_config, f, indent=2, ensure_ascii=False)
            progress.update(task, advance=1, description="Saving targets...")
            
            # Save notifications
            with open(config_dir / "notification_webhooks.json", "w") as f:
                json.dump(self.notifications, f, indent=2, ensure_ascii=False)
            progress.update(task, advance=1, description="Saving notifications...")
            
            # Save API keys to vault
            if self.api_keys:
                from cryptography.fernet import Fernet
                import base64
                
                # Generate or load encryption key
                key_file = self.project_root / ".arachne_key"
                if key_file.exists():
                    with open(key_file, "rb") as f:
                        key = f.read()
                else:
                    key = Fernet.generate_key()
                    with open(key_file, "wb") as f:
                        f.write(key)
                    key_file.chmod(0o600)
                
                # Encrypt and save
                cipher = Fernet(key)
                encrypted = {}
                for service, key_value in self.api_keys.items():
                    if isinstance(key_value, str) and key_value.startswith("gAAAA"):
                        # Already encrypted
                        encrypted[service] = key_value
                    else:
                        encrypted[service] = cipher.encrypt(key_value.encode()).decode()
                
                with open(self.project_root / ".arachne_keys", "w") as f:
                    json.dump(encrypted, f, indent=2, ensure_ascii=False)
                
                console.print(f"[green]✓ API keys encrypted and saved[/green]")
            progress.update(task, advance=1, description="Securing API keys...")
            
            # Save wordlists
            if self.wordlists:
                wordlist_dir = config_dir / "wordlists"
                wordlist_dir.mkdir(exist_ok=True)
                
                for wl_type, entries in self.wordlists.items():
                    with open(wordlist_dir / f"{wl_type}.txt", "w") as f:
                        f.write("\n".join(entries))
                
                console.print(f"[green]✓ {len(self.wordlists)} wordlists saved[/green]")
            progress.update(task, advance=1, description="Saving wordlists...")
            
            # Save module configuration
            modules_config = {
                "enabled_modules": self.config.get("enabled_modules", []),
                "module_settings": {}
            }
            
            with open(config_dir / "modules.json", "w") as f:
                json.dump(modules_config, f, indent=2, ensure_ascii=False)
            progress.update(task, advance=1, description="Saving module config...")
            
            progress.update(task, completed=6, description="[green]Configuration saved![/green]")
    
    def create_env_file(self):
        """Create .env file from configuration."""
        console.print("\n[bold cyan]🌍 Environment Configuration[/bold cyan]")
        
        env_content = """# ARACHNE v2.0 Environment Configuration
# Generated on {date}

# Framework Settings
ARACHNE_DATA_DIR=./data
ARACHNE_LOG_LEVEL=INFO
ARACHNE_MAX_CONCURRENT={concurrent}
ARACHNE_AGGRESSION={aggression}

# API Keys (if not using encrypted vault)
# SHODAN_API_KEY=
# CENSYS_API_ID=
# CENSYS_API_SECRET=
# OPENAI_API_KEY=

# AI/ML Settings
ARACHNE_AI_ENABLED={ai_enabled}
LOCAL_LLM_PATH=./models
AI_MODEL_SIZE=medium

# Reporting
ARACHNE_AUTO_REPORT={auto_report}
REPORT_FORMAT=markdown
REPORT_TEMPLATE=default

# Performance
ARACHNE_RATE_LIMIT={rate_limit}
ARACHNE_TIMEOUT=30
ARACHNE_RETRIES=3

# Advanced
ARACHNE_DEEP_DIVE={deep_dive}
ARACHNE_RESPECT_ROBOTS={respect_robots}
""".format(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            concurrent=self.config["global_settings"].get("max_concurrent", 5),
            aggression=self.config["global_settings"].get("aggression", "balanced"),
            ai_enabled=self.config["global_settings"].get("ai_enabled", True),
            auto_report=self.config["global_settings"].get("auto_report", True),
            rate_limit=self.config["global_settings"].get("rate_limit", 10),
            deep_dive=self.config["global_settings"].get("deep_dive", True),
            respect_robots=self.config["global_settings"].get("respect_robots_txt", False)
        )
        
        with open(self.project_root / ".env", "w") as f:
            f.write(env_content)
        
        console.print("[green]✓ .env file created[/green]")
        
        # Also create example file
        with open(self.project_root / ".env.example", "w") as f:
            f.write(env_content.replace("=", "=").replace("=./", "="))
        
        console.print("[green]✓ .env.example created[/green]")
    
    def show_completion(self):
        """Show completion message with next steps."""
        console.print("\n" + "🎉" * 30)
        console.print("[bold magenta]✨ ARACHNE v2.0 CONFIGURATION COMPLETE! ✨[/bold magenta]")
        console.print("🎉" * 30)
        
        summary = Panel(
            f"[bold]Configuration Summary:[/bold]\n"
            f"• 🎯 Targets: [cyan]{len(self.targets)}[/cyan]\n"
            f"• 🔐 API Keys: [green]{len(self.api_keys)}[/green]\n"
            f"• 📢 Notifications: [yellow]{len([c for c in self.notifications.values() if c.get('enabled')])}[/yellow]\n"
            f"• 🛠️ Modules: [magenta]{len(self.config.get('enabled_modules', []))}[/magenta]\n"
            f"• ⚡ Aggression: [blue]{self.config['global_settings'].get('aggression', 'balanced')}[/blue]",
            title="Setup Complete",
            border_style="green",
            box=box.ROUNDED
        )
        
        console.print(summary)
        
        # Next steps
        steps = Columns([
            Panel(
                "[bold]1. Installation[/bold]\n"
                "[cyan]pip install -r requirements.txt[/cyan]\n"
                "[dim]Install all dependencies[/dim]",
                border_style="blue"
            ),
            Panel(
                "[bold]2. Verify[/bold]\n"
                "[cyan]python arachne_core.py --test[/cyan]\n"
                "[dim]Test the configuration[/dim]",
                border_style="cyan"
            ),
            Panel(
                "[bold]3. Hunt[/bold]\n"
                "[cyan]python arachne_core.py[/cyan]\n"
                "[dim]Launch the predator[/dim]",
                border_style="green"
            ),
        ])
        
        console.print("\n[bold]🚀 Next Steps:[/bold]")
        console.print(steps)
        
        # Config file locations
        console.print("\n[bold]📁 Configuration Files:[/bold]")
        table = Table(box=box.SIMPLE)
        table.add_column("File", style="cyan")
        table.add_column("Location", style="dim")
        table.add_column("Purpose")
        
        files = [
            ("targets.json", "config/", "Target definitions & scope"),
            ("notification_webhooks.json", "config/", "Alert channels"),
            (".arachne_keys", "./", "Encrypted API keys (secure)"),
            (".env", "./", "Environment variables"),
            ("modules.json", "config/", "Module enable/disable"),
            ("wordlists/*.txt", "config/wordlists/", "Custom dictionaries")
        ]
        
        for file, location, purpose in files:
            table.add_row(file, location, purpose)
        
        console.print(table)
        
        # Quick start command
        console.print("\n[bold]⚡ Quick Start:[/bold]")
        console.print("[cyan]./run_arachne.sh[/cyan] [dim]# Or[/dim] [cyan]python arachne_core.py[/cyan]")
        
        # Love note
        console.print("\n[bold magenta] Made with ❤ by 🎩-Hxcker-263-🎩️ .......The Predator is ready to hunt. ❤️[/bold magenta]")
    
    def run(self):
        """Main execution flow."""
        try:
            self.show_banner()
            self.welcome()
            
            console.print("[bold cyan]Press Ctrl+C at any time to cancel setup.[/bold cyan]\n")
            
            # Step-by-step configuration
            steps = [
                ("System Check", self.check_prerequisites),
                ("API Keys", self.configure_api_keys),
                ("Targets", self.configure_targets),
                ("Notifications", self.configure_notifications),
                ("Scanning", self.configure_scanning),
                ("Wordlists", self.configure_wordlists),
                ("Modules", self.configure_modules),
            ]
            
            for i, (name, func) in enumerate(steps, 1):
                console.print(f"\n[bold]{i}/{len(steps)}[/bold] [cyan]{name}[/cyan]")
                func()
            
            # Review and save
            if self.review_configuration():
                self.save_configuration()
                self.create_env_file()
                self.show_completion()
            else:
                console.print("[yellow]Configuration not saved. Run setup again to reconfigure.[/yellow]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Setup interrupted by user.[/yellow]")
            if self.targets or self.api_keys:
                if Confirm.ask("[yellow]Save current configuration before exiting?[/yellow]"):
                    self.save_configuration()
        except Exception as e:
            console.print(f"\n[red]❌ Setup failed: {str(e)}[/red]")
            console.print("[dim]Please check your inputs and try again.[/dim]")
            sys.exit(1)

def main():
    """Entry point."""
    wizard = ArachneSetupWizard()
    wizard.run()

if __name__ == "__main__":
    main()