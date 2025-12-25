"""
Real-time dashboard for monitoring Arachne's activities.
"""

import asyncio
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from datetime import datetime

class Dashboard:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.running = False
        self.live = None
        
    def setup_layout(self):
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="targets", ratio=2),
            Layout(name="findings", ratio=3),
            Layout(name="activity", ratio=2)
        )
    
    async def run(self, targets, knowledge_graph):
        """Run the dashboard."""
        self.setup_layout()
        self.running = True
        
        with Live(self.layout, refresh_per_second=4, screen=True) as self.live:
            while self.running:
                await self.update(targets, knowledge_graph)
                await asyncio.sleep(0.25)
    
    async def update(self, targets, kg):
        """Update dashboard content."""
        # Header
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.layout["header"].update(
            Panel(f"[bold cyan]ARACHNE v2.0[/bold cyan] | {time_str} | [green]Online[/green]", 
                  border_style="cyan")
        )
        
        # Targets panel
        targets_table = Table(title="Targets", show_header=True)
        targets_table.add_column("Domain", style="cyan")
        targets_table.add_column("Status", style="green")
        targets_table.add_column("Findings", style="magenta")
        targets_table.add_column("Modules", style="yellow")
        
        for domain, target in targets.items():
            status = "🟢" if target.alive else "🟡"
            findings = sum(target.findings_count.values())
            active_modules = sum(target.modules_active.values())
            targets_table.add_row(domain, status, str(findings), str(active_modules))
        
        self.layout["targets"].update(Panel(targets_table, border_style="blue"))
        
        # Findings panel
        findings_table = Table(title="Recent Findings", show_header=True)
        findings_table.add_column("Time", style="dim")
        findings_table.add_column("Target", style="cyan")
        findings_table.add_column("Type", style="red")
        findings_table.add_column("Severity", style="yellow")
        
        recent = kg.get_recent_findings(5)
        for finding in recent:
            time = finding.get('timestamp', '')[:19]
            target = finding.get('target', '')
            type_ = finding.get('type', '')[:20]
            severity = finding.get('severity', 'unknown')
            findings_table.add_row(time, target, type_, severity)
        
        self.layout["findings"].update(Panel(findings_table, border_style="red"))
        
        # Activity panel
        activity_text = Text()
        stats = kg.get_statistics()
        activity_text.append(f"Hosts: {stats.get('hosts', 0)}\n")
        activity_text.append(f"Endpoints: {stats.get('endpoints', 0)}\n")
        activity_text.append(f"Vulnerabilities: {stats.get('vulns', 0)}\n")
        activity_text.append(f"AI Bypasses: {stats.get('ai_bypasses', 0)}\n")
        activity_text.append(f"Graph Nodes: {stats.get('nodes', 0)}\n")
        
        self.layout["activity"].update(Panel(activity_text, title="Statistics", border_style="green"))
        
        # Footer
        footer_text = Text()
        footer_text.append("[dim]Press Ctrl+C to shutdown[/dim]")
        self.layout["footer"].update(Panel(footer_text, border_style="dim"))
    
    async def stop(self):
        """Stop the dashboard."""
        self.running = False