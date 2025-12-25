#!/usr/bin/env python3
"""
ARACHNE CORE v2.0 - The Complete Orchestrator
"""

import asyncio
import signal
import sys
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import warnings
warnings.filterwarnings('ignore')

# Import all modules
from modules.orb_weaver import Dashboard
from modules.silken_sentry import SubdomainHunter
from modules.venom_fang import VenomFang
from modules.widows_bite import InjectionSuite
from modules.myrmidon import AuthAssassin
from modules.neural_mimic import NeuralMimic
from modules.graphql_ast_hacker import GraphQLNinja
from modules.websocket_protocol_phreak import WebSocketPhreak
from modules.synthetic_relationship_engine import SyntheticPersonaEngine
from modules.tapestry import ReportWeaver
from modules.correlation_engine import KnowledgeGraph
from modules.signal_system import SignalSystem
from utils.crypto_vault import Vault
from integrations.burp_parser import BurpParser
from integrations.nuclei_runner import NucleiRunner
from integrations.shodan_censys_client import IntelHarvester

console = Console()

@dataclass
class TargetProfile:
    domain: str
    alive: bool = False
    modules_active: Dict[str, bool] = None
    findings_count: Dict[str, int] = None
    
    def __post_init__(self):
        self.modules_active = {
            'sentry': True, 'fang': True, 'bite': True,
            'myrmidon': False, 'neural': True, 'graphql': True,
            'websocket': True, 'synthetic': False
        }
        self.findings_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

class ArachneCore:
    def __init__(self):
        self.console = console
        self.running = True
        self.targets: Dict[str, TargetProfile] = {}
        self.vault = Vault()
        self.kg = KnowledgeGraph()
        self.dashboard = Dashboard()
        self.signal = SignalSystem()
        
        # Load configuration
        self.config = self._load_config()
        self.api_keys = self.vault.load_keys()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        
    def _load_config(self):
        """Load configuration from files."""
        try:
            with open('config/targets.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            console.print("[red]Configuration file not found. Run setup first.[/red]")
            sys.exit(1)
    
    async def initialize(self):
        """Initialize all systems."""
        console.print(Panel.fit("[bold cyan]ARACHNE v2.0[/bold cyan]\n[dim]Post-AI Vulnerability Framework[/dim]", 
                               border_style="cyan"))
        
        # Check for API keys
        if not self.api_keys.get('shodan') and 'shodan' in self.config.get('integrations', []):
            console.print("[yellow]⚠ Shodan API key not found. Some intelligence features disabled.[/yellow]")
        
        # Initialize Knowledge Graph
        await self.kg.initialize()
        
        # Load targets
        for target_config in self.config['targets']:
            target = TargetProfile(domain=target_config['domain'])
            self.targets[target.domain] = target
            console.print(f"[green]✓ Target loaded: [blue]{target.domain}[/blue][/green]")
        
        # Start dashboard
        asyncio.create_task(self.dashboard.run(self.targets, self.kg))
        
        # Initialize signal system
        await self.signal.initialize()
        
        console.print("[bold green]✓ Arachne initialized successfully.[/bold green]")
    
    async def weave_web(self, target_domain: str):
        """Orchestrate all modules for a single target."""
        target = self.targets[target_domain]
        console.print(f"\n[bold cyan]🕸️ Weaving web for [blue]{target_domain}[/blue][/bold cyan]")
        
        # Instantiate all modules for this target
        modules = {}
        
        # 1. Intelligence Gathering
        if target.modules_active['sentry']:
            modules['sentry'] = SubdomainHunter(target_domain, self.api_keys, self.kg)
        
        # 2. External Intelligence
        intel = IntelHarvester(self.api_keys)
        
        # 3. Core Attack Modules
        if target.modules_active['fang']:
            modules['fang'] = VenomFang(target_domain, self.kg)
        if target.modules_active['bite']:
            modules['bite'] = InjectionSuite(target_domain, self.kg)
        if target.modules_active['graphql']:
            modules['graphql'] = GraphQLNinja(target_domain, self.kg)
        if target.modules_active['websocket']:
            modules['websocket'] = WebSocketPhreak(target_domain, self.kg)
        
        # 4. AI/Advanced Modules
        if target.modules_active['neural']:
            modules['neural'] = NeuralMimic(self.kg)
        if target.modules_active['synthetic']:
            modules['synthetic'] = SyntheticPersonaEngine(self.kg)
        if target.modules_active['myrmidon']:
            modules['myrmidon'] = AuthAssassin(target_domain, self.kg)
        
        # Execute modules in orchestrated sequence
        try:
            # PHASE 1: Reconnaissance
            recon_tasks = []
            if 'sentry' in modules:
                recon_tasks.append(modules['sentry'].hunt())
            recon_tasks.append(intel.harvest(target_domain))
            
            console.print("[yellow]Phase 1: Reconnaissance...[/yellow]")
            recon_results = await asyncio.gather(*recon_tasks, return_exceptions=True)
            
            # PHASE 2: Active Analysis (concurrent)
            console.print("[yellow]Phase 2: Active Analysis...[/yellow]")
            analysis_tasks = []
            
            # Feed results between modules (real-time correlation)
            for module in modules.values():
                if hasattr(module, 'feed_intel'):
                    module.feed_intel(recon_results)
                
                # Start continuous modules
                if hasattr(module, 'monitor_and_attack'):
                    analysis_tasks.append(module.monitor_and_attack())
                elif hasattr(module, 'assault'):
                    analysis_tasks.append(module.assault())
            
            # Run all attack modules concurrently
            await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
        except Exception as e:
            console.print(f"[red]Error in weave_web for {target_domain}: {e}[/red]")
            await self.signal.send_system_alert(f"Weave failed for {target_domain}: {str(e)}")
    
    async def run(self):
        """Main execution loop."""
        await self.initialize()
        
        console.print("\n[bold]Starting Arachne...[/bold]")
        
        # Create tasks for all targets
        target_tasks = []
        for target_domain in self.targets:
            task = asyncio.create_task(self.weave_web(target_domain))
            target_tasks.append(task)
        
        # Monitor all tasks
        while self.running:
            try:
                await asyncio.sleep(1)
                
                # Check for critical findings
                critical_count = self.kg.get_critical_count()
                if critical_count > 0:
                    # Update dashboard
                    self.dashboard.update_findings(critical_count)
                    
                    # Trigger auto-reporting for criticals
                    if self.config.get('auto_report', False):
                        reporter = ReportWeaver(self.kg)
                        await reporter.generate_critical_report()
                
                # Check if all targets are complete
                all_done = all(task.done() for task in target_tasks)
                if all_done:
                    console.print("[green]All target assessments complete.[/green]")
                    break
                    
            except KeyboardInterrupt:
                await self.graceful_shutdown()
                break
        
        # Generate final reports
        await self.generate_final_reports()
    
    async def generate_final_reports(self):
        """Generate comprehensive reports for all targets."""
        console.print("\n[bold cyan]Generating final reports...[/bold cyan]")
        
        reporter = ReportWeaver(self.kg)
        
        for target_domain in self.targets:
            report_path = await reporter.generate_target_report(target_domain)
            if report_path:
                console.print(f"[green]✓ Report generated: [blue]{report_path}[/blue][/green]")
                
                # Send notification
                summary = self.kg.get_target_summary(target_domain)
                await self.signal.send_report_notification(target_domain, summary, report_path)
        
        # Generate executive summary
        exec_summary = await reporter.generate_executive_summary()
        console.print(f"[bold green]✓ Executive summary: [blue]{exec_summary}[/blue][/bold green]")
    
    async def graceful_shutdown(self, signum=None, frame=None):
        """Gracefully shutdown all systems."""
        console.print("\n[yellow]Shutting down Arachne gracefully...[/yellow]")
        self.running = False
        
        # Save knowledge graph state
        await self.kg.persist()
        
        # Close all connections
        await self.signal.cleanup()
        await self.dashboard.stop()
        
        console.print("[bold green]✓ Arachne shutdown complete.[/bold green]")
        sys.exit(0)

def main():
    """Entry point."""
    # ASCII Art because we're dramatic
    art = """
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
    ⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    [bold cyan]ARACHNE v2.0[/bold cyan] - The Web We Weave
    """
    console.print(art)
    
    # Run
    core = ArachneCore()
    
    try:
        asyncio.run(core.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()