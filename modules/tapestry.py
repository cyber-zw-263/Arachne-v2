#!/usr/bin/env python3
"""
TAPESTRY - Auto-reporting & AI Vulnerability Prediction
Generates professional reports and predicts vulnerabilities using AI.
"""

import json
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import hashlib

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

@dataclass
class Vulnerability:
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    proof_of_concept: str = ""
    references: List[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    target: str = ""
    location: str = ""
    module: str = ""

@dataclass
class TargetSummary:
    domain: str
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    last_scan: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

class Tapestry:
    def __init__(self, knowledge_graph=None):
        self.kg = knowledge_graph
        self.vulnerabilities: List[Vulnerability] = []
        self.target_summaries: Dict[str, TargetSummary] = {}
        
        if JINJA2_AVAILABLE:
            # Setup Jinja2 environment
            template_dir = Path("reports/templates")
            template_dir.mkdir(parents=True, exist_ok=True)
            
            self.env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(['html', 'xml', 'md']),
                trim_blocks=True,
                lstrip_blocks=True
            )
            
            # Create default template if it doesn't exist
            self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default report templates."""
        template_dir = Path("reports/templates")
        template_dir.mkdir(parents=True, exist_ok=True)
        
        # Markdown template
        md_template = """# Security Assessment Report

## Executive Summary
**Target**: {{ target }}
**Assessment Date**: {{ date }}
**Total Vulnerabilities**: {{ summary.total_vulnerabilities }}
**Critical Findings**: {{ summary.critical_count }}
**Overall Risk**: {{ overall_risk }}

## Assessment Details
- **Scan Duration**: {{ scan_duration }}
- **Methodology**: Automated security scanning with manual verification
- **Scope**: {{ scope }}

## Vulnerability Summary
| Severity | Count |
|----------|-------|
{% for severity in severities -%}
| {{ severity.name }} | {{ severity.count }} |
{% endfor %}

## Detailed Findings
{% for vuln in vulnerabilities %}
### {{ vuln.title }}
- **ID**: {{ vuln.id }}
- **Severity**: {{ vuln.severity|upper }}
{% if vuln.cvss_score -%}
- **CVSS Score**: {{ vuln.cvss_score }}
{% endif -%}
- **Location**: {{ vuln.location }}
- **Discovered**: {{ vuln.discovered_at[:10] }}

#### Description
{{ vuln.description }}

#### Impact
{{ vuln.impact }}

#### Proof of Concept
```
{{ vuln.proof_of_concept }}
```

#### Remediation
{{ vuln.remediation }}

{% if vuln.references -%}
#### References
{% for ref in vuln.references -%}
- {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
"""
        with open(template_dir / "report.md.j2", "w") as f:
            f.write(md_template)
        
        # HTML template (simplified - stored as a separate string to avoid parsing issues)
        html_template = ('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
                         '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
                         '<title>Security Assessment Report - {{ target }}</title>'
                         '<style>body { font-family: Arial, sans-serif; margin: 40px; }</style>'
                         '</head><body>'
                         '<h1>Security Assessment Report</h1>'
                         '<h2>Executive Summary</h2>'
                         '<p><strong>Target</strong>: {{ target }}</p>'
                         '<h2>Vulnerability Summary</h2>'
                         '<table><tr><th>Severity</th><th>Count</th></tr>'
                         '{% for severity in severities %}<tr><td>{{ severity.name }}</td><td>{{ severity.count }}</td></tr>{% endfor %}'
                         '</table>'
                         '<h2>Detailed Findings</h2>'
                         '{% for vuln in vulnerabilities %}<div><h3>{{ vuln.title }}</h3></div>{% endfor %}'
                         '<footer><p>Report Generated: {{ generated_at }}</p></footer>'
                         '</body></html>')
        with open(template_dir / "report.html.j2", "w") as f:
            f.write(html_template)

    def add_vulnerability(self, vulnerability: Vulnerability):
        """Add a vulnerability to the report."""
        # Generate ID if not provided
        if not vulnerability.id:
            base = f"{vulnerability.title}{vulnerability.location}{vulnerability.severity}"
            vulnerability.id = hashlib.md5(base.encode()).hexdigest()[:8]
    
        self.vulnerabilities.append(vulnerability)
    
        # Update target summary
        if vulnerability.target not in self.target_summaries:
            self.target_summaries[vulnerability.target] = TargetSummary(domain=vulnerability.target)
    
        summary = self.target_summaries[vulnerability.target]
        summary.total_vulnerabilities += 1
    
        if vulnerability.severity == 'critical':
            summary.critical_count += 1
        elif vulnerability.severity == 'high':
            summary.high_count += 1
        elif vulnerability.severity == 'medium':
            summary.medium_count += 1
        elif vulnerability.severity == 'low':
            summary.low_count += 1
        else:
            summary.info_count += 1
    
        summary.last_scan = datetime.now().isoformat()

    def generate_report(self, 
                       target: str,
                       output_format: str = "markdown",
                       output_file: Optional[str] = None) -> str:
        """Generate a comprehensive security report."""
        # Filter vulnerabilities for target
        target_vulns = [v for v in self.vulnerabilities if v.target == target]
    
        if not target_vulns:
            return f"No vulnerabilities found for target: {target}"
    
        # Get target summary
        summary = self.target_summaries.get(target, TargetSummary(domain=target))
    
        # Prepare data for template
        severities = [
            {'name': 'critical', 'count': summary.critical_count, 'class': 'critical', 'percentage': self._calculate_percentage(summary.critical_count, summary.total_vulnerabilities)},
            {'name': 'high', 'count': summary.high_count, 'class': 'high', 'percentage': self._calculate_percentage(summary.high_count, summary.total_vulnerabilities)},
            {'name': 'medium', 'count': summary.medium_count, 'class': 'medium', 'percentage': self._calculate_percentage(summary.medium_count, summary.total_vulnerabilities)},
            {'name': 'low', 'count': summary.low_count, 'class': 'low', 'percentage': self._calculate_percentage(summary.low_count, summary.total_vulnerabilities)},
            {'name': 'info', 'count': summary.info_count, 'class': 'info', 'percentage': self._calculate_percentage(summary.info_count, summary.total_vulnerabilities)},
        ]
    
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(summary)
        overall_risk_class = overall_risk.lower().replace(' ', '-')
    
        # Template data
        template_data = {
            'target': target,
            'date': datetime.now().strftime('%Y-%m-%d'),
            'summary': summary,
            'vulnerabilities': sorted(target_vulns, key=lambda x: self._severity_to_num(x.severity), reverse=True),
            'severities': severities,
            'overall_risk': overall_risk,
            'overall_risk_class': overall_risk_class,
            'scan_duration': 'Automated scan',
            'scope': f'*.{target}',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    
        # Generate report based on format
        if output_format == "markdown" and JINJA2_AVAILABLE:
            template = self.env.get_template("report.md.j2")
            report_content = template.render(**template_data)
        elif output_format == "html" and JINJA2_AVAILABLE:
            template = self.env.get_template("report.html.j2")
            report_content = template.render(**template_data)
        else:
            # Fallback to simple text
            report_content = self._generate_simple_report(target, target_vulns, summary)
    
        # Save to file if requested
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
        
            print(f"Report saved to: {output_path}")
    
        return report_content

    def _calculate_percentage(self, count: int, total: int) -> float:
        """Calculate percentage."""
        if total == 0:
            return 0.0
        return round((count / total) * 100, 1)

    def _severity_to_num(self, severity: str) -> int:
        """Convert severity to numeric value for sorting."""
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_map.get(severity.lower(), 0)

    def _calculate_overall_risk(self, summary: TargetSummary) -> str:
        """Calculate overall risk level."""
        if summary.critical_count > 0:
            return "Critical"
        elif summary.high_count > 2:
            return "High"
        elif summary.high_count > 0 or summary.medium_count > 3:
            return "Medium"
        elif summary.medium_count > 0 or summary.low_count > 5:
            return "Low"
        else:
            return "Informational"

    def _generate_simple_report(self, target: str, vulnerabilities: List[Vulnerability], summary: TargetSummary) -> str:
        """Generate a simple text report."""
        lines = [
            f"SECURITY ASSESSMENT REPORT",
            f"Target: {target}",
            f"Date: {datetime.now().strftime('%Y-%m-%d')}",
            "=" * 50,
            "",
            f"SUMMARY:",
            f"  Total vulnerabilities: {summary.total_vulnerabilities}",
            f"  Critical: {summary.critical_count}",
            f"  High: {summary.high_count}",
            f"  Medium: {summary.medium_count}",
            f"  Low: {summary.low_count}",
            f"  Info: {summary.info_count}",
            "",
            "VULNERABILITIES:",
            "",
        ]
    
        for vuln in sorted(vulnerabilities, key=lambda x: self._severity_to_num(x.severity), reverse=True):
            lines.append(f"[{vuln.severity.upper()}] {vuln.title}")
            lines.append(f"  ID: {vuln.id}")
            lines.append(f"  Location: {vuln.location}")
            lines.append(f"  Description: {vuln.description[:100]}...")
            lines.append("")
    
        lines.append("RECOMMENDATIONS:")
        lines.append("1. Address critical and high severity findings immediately")
        lines.append("2. Implement regular security scanning")
        lines.append("3. Review and update security policies")
        lines.append("")
        lines.append(f"Report generated by Arachne v2.0 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
        return "\n".join(lines)

    def predict_vulnerabilities(self, target: str, technologies: List[str]) -> List[Dict]:
        """Predict potential vulnerabilities based on technologies."""
        predictions = []
    
        # Common vulnerabilities by technology
        tech_vulnerabilities = {
            'wordpress': [
                {'type': 'XSS', 'severity': 'medium', 'confidence': 0.7},
                {'type': 'SQLi', 'severity': 'high', 'confidence': 0.6},
                {'type': 'File Upload', 'severity': 'high', 'confidence': 0.8},
            ],
            'apache': [
                {'type': 'Directory Traversal', 'severity': 'medium', 'confidence': 0.5},
                {'type': 'HTTP Method Tampering', 'severity': 'low', 'confidence': 0.4},
            ],
            'nginx': [
                {'type': 'Path Traversal', 'severity': 'medium', 'confidence': 0.5},
                {'type': 'Header Injection', 'severity': 'low', 'confidence': 0.3},
            ],
            'nodejs': [
                {'type': 'Prototype Pollution', 'severity': 'high', 'confidence': 0.6},
                {'type': 'RCE', 'severity': 'critical', 'confidence': 0.4},
            ],
            'react': [
                {'type': 'XSS', 'severity': 'medium', 'confidence': 0.7},
                {'type': 'CSRF', 'severity': 'low', 'confidence': 0.5},
            ],
            'mongodb': [
                {'type': 'NoSQL Injection', 'severity': 'high', 'confidence': 0.8},
                {'type': 'Unauthorized Access', 'severity': 'critical', 'confidence': 0.6},
            ],
            'docker': [
                {'type': 'Container Escape', 'severity': 'critical', 'confidence': 0.3},
                {'type': 'Privilege Escalation', 'severity': 'high', 'confidence': 0.5},
            ],
            'kubernetes': [
                {'type': 'RBAC Misconfiguration', 'severity': 'high', 'confidence': 0.7},
                {'type': 'Secrets Exposure', 'severity': 'critical', 'confidence': 0.6},
            ],
        }
    
        # Check each technology
        for tech in technologies:
            tech_lower = tech.lower()
        
            for known_tech, vulns in tech_vulnerabilities.items():
                if known_tech in tech_lower:
                    predictions.extend(vulns)
    
        # Deduplicate and sort by severity
        unique_predictions = []
        seen = set()
    
        for pred in predictions:
            key = f"{pred['type']}-{pred['severity']}"
            if key not in seen:
                seen.add(key)
                unique_predictions.append(pred)
    
        # Sort by severity (critical -> high -> medium -> low)
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        unique_predictions.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
    
        return unique_predictions

    def export_vulnerabilities(self, format: str = "json") -> str:
        """Export all vulnerabilities in specified format."""
        if format == "json":
            data = {
                'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
                'summary': {k: self._summary_to_dict(v) for k, v in self.target_summaries.items()},
                'exported_at': datetime.now().isoformat()
            }
            return json.dumps(data, indent=2, default=str)
    
        elif format == "yaml":
            data = {
                'vulnerabilities': [self._vuln_to_dict(v) for v in self.vulnerabilities],
                'summary': {k: self._summary_to_dict(v) for k, v in self.target_summaries.items()},
                'exported_at': datetime.now().isoformat()
            }
            return yaml.dump(data, default_flow_style=False)
    
        elif format == "csv":
            lines = ["id,title,severity,cvss_score,target,location,module,discovered_at"]
            for vuln in self.vulnerabilities:
                lines.append(f"{vuln.id},{vuln.title},{vuln.severity},{vuln.cvss_score or ''},"
                           f"{vuln.target},{vuln.location},{vuln.module},{vuln.discovered_at}")
            return "\n".join(lines)
    
        return ""

    def _vuln_to_dict(self, vulnerability: Vulnerability) -> Dict:
        """Convert vulnerability to dictionary."""
        return {
            'id': vulnerability.id,
            'title': vulnerability.title,
            'severity': vulnerability.severity,
            'cvss_score': vulnerability.cvss_score,
            'description': vulnerability.description,
            'impact': vulnerability.impact,
            'remediation': vulnerability.remediation,
            'proof_of_concept': vulnerability.proof_of_concept,
            'references': vulnerability.references,
            'discovered_at': vulnerability.discovered_at,
            'target': vulnerability.target,
            'location': vulnerability.location,
            'module': vulnerability.module
        }

    def _summary_to_dict(self, summary: TargetSummary) -> Dict:
        """Convert target summary to dictionary."""
        return {
            'domain': summary.domain,
            'total_vulnerabilities': summary.total_vulnerabilities,
            'critical_count': summary.critical_count,
            'high_count': summary.high_count,
            'medium_count': summary.medium_count,
            'low_count': summary.low_count,
            'info_count': summary.info_count,
            'last_scan': summary.last_scan,
            'technologies': summary.technologies
        }
    
        async def generate_target_report(self, target_domain: str) -> str:
            """Generate a simple report for a target."""
            target_vulns = [v for v in self.vulnerabilities if v.target == target_domain]
            return f"Security Assessment Report for {target_domain}\nVulnerabilities found: {len(target_vulns)}"
ReportWeaver = Tapestry