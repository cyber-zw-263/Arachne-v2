"""
Auto-report generation.
"""

from jinja2 import Environment, FileSystemLoader
import json
from datetime import datetime
import markdown
from typing import Dict, List

class ReportWeaver:
    def __init__(self, knowledge_graph):
        self.kg = knowledge_graph
        self.env = Environment(loader=FileSystemLoader('reports/templates'))
        
    async def generate_target_report(self, target_domain: str) -> str:
        """Generate comprehensive report for a target."""
        summary = self.kg.get_target_summary(target_domain)
        findings = self._get_findings_for_target(target_domain)
        
        template = self.env.get_template('target_report.md')
        
        report_content = template.render(
            target=target_domain,
            summary=summary,
            findings=findings,
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            version="Arachne v2.0"
        )
        
        # Save report
        filename = f"reports/{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(filename, 'w') as f:
            f.write(report_content)
        
        # Also generate HTML version
        self._generate_html(filename)
        
        return filename
    
    def _get_findings_for_target(self, target_domain: str) -> List[Dict]:
        """Get all findings for a target."""
        findings = []
        target_id = f"target:{target_domain}"
        
        if target_id not in self.kg.graph:
            return findings
        
        for node in self.kg.graph.nodes():
            data = self.kg.graph.nodes[node]
            if data.get('node_type') == 'finding':
                # Check if connected to target
                if target_id in self.kg.graph.nodes():
                    if nx.has_path(self.kg.graph, node, target_id):
                        findings.append(data)
        
        return findings
    
    def _generate_html(self, markdown_file: str):
        """Generate HTML from markdown report."""
        with open(markdown_file, 'r') as f:
            md_content = f.read()
        
        html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
        
        # Add basic styling
        styled_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Arachne Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .critical {{ color: #dc3545; font-weight: bold; }}
                .high {{ color: #fd7e14; }}
                .medium {{ color: #ffc107; }}
                .low {{ color: #28a745; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                code {{ background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
                pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """
        
        html_file = markdown_file.replace('.md', '.html')
        with open(html_file, 'w') as f:
            f.write(styled_html)