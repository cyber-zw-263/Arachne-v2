# Security Assessment Report

## Executive Summary
**Client**: {{ client_name }}  
**Target**: {{ target }}  
**Assessment Date**: {{ assessment_date }}  
**Report ID**: {{ report_id }}  
**Overall Risk**: {{ overall_risk }}

### Key Findings
- **Total Vulnerabilities**: {{ total_vulnerabilities }}
- **Critical**: {{ critical_count }}
- **High**: {{ high_count }}
- **Medium**: {{ medium_count }}
- **Low**: {{ low_count }}
- **Informational**: {{ info_count }}

## Scope
**In-Scope**:
{{ scope_in }}

**Out-of-Scope**:
{{ scope_out }}

**Testing Methodology**:
- Automated vulnerability scanning
- Manual verification of findings
- Exploitation proof-of-concept testing
- Impact analysis

## Vulnerability Summary
| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {{ critical_count }} | {{ critical_percentage }}% |
| High     | {{ high_count }} | {{ high_percentage }}% |
| Medium   | {{ medium_count }} | {{ medium_percentage }}% |
| Low      | {{ low_count }} | {{ low_percentage }}% |
| Info     | {{ info_count }} | {{ info_percentage }}% |

## Detailed Findings

{% for vulnerability in vulnerabilities %}
### {{ vulnerability.id }}: {{ vulnerability.title }}
**Severity**: {{ vulnerability.severity|upper }}  
**CVSS Score**: {{ vulnerability.cvss_score }}  
**Location**: `{{ vulnerability.location }}`  
**Discovered**: {{ vulnerability.discovered_at[:10] }}  
**Module**: {{ vulnerability.module }}

#### Description
{{ vulnerability.description }}

#### Impact
{{ vulnerability.impact }}

#### Proof of Concept
{{ vulnerability.language }}
{{ vulnerability.proof_of_concept }}

#### Remediation
{{ vulnerability.remediation }}

{% if vulnerability.references %}

#### References
{% for reference in vulnerability.references %}
{{ loop.index }}. {{ reference }}
{% endfor %}
{% endif %}

#### Risk Assessment
Likelihood: {{ vulnerability.likelihood }}

Impact: {{ vulnerability.impact_level }}

Exploitation Complexity: {{ vulnerability.exploitation_complexity }}

{% endfor %}

#### Risk Matrix
text
Impact →
Likelihood ↓  | Critical | High     | Medium   | Low      |
-------------|----------|----------|----------|----------|
 Very High   |{% for cell in risk_matrix[0] %} {{ cell }} {% endfor %}|
 High        |{% for cell in risk_matrix[1] %} {{ cell }} {% endfor %}|
 Medium      |{% for cell in risk_matrix[2] %} {{ cell }} {% endfor %}|
 Low         |{% for cell in risk_matrix[3] %} {{ cell }} {% endfor %}|

#### Recommendations
Immediate Actions (1-7 days)
{% for action in immediate_actions %}
{{ loop.index }}. {{ action }}
{% endfor %}

#### Short-term Actions (8-30 days)
{% for action in short_term_actions %}
{{ loop.index }}. {{ action }}
{% endfor %}

#### Long-term Actions (31-90 days)
{% for action in long_term_actions %}
{{ loop.index }}. {{ action }}
{% endfor %}

#### Strategic Recommendations
{% for recommendation in strategic_recommendations %}
{{ loop.index }}. {{ recommendation }}
{% endfor %}

#### Technical Details
Testing Environment
Tool: Arachne v2.0

Scan Duration: {{ scan_duration }}

Requests Made: {{ total_requests }}

Coverage: {{ coverage_percentage }}%

#### Target Technologies Identified
{% for technology in technologies %}

{{ technology }}
{% endfor %}

#### Testing Limitations
{% for limitation in limitations %}
{{ loop.index }}. {{ limitation }}
{% endfor %}

#### Appendix
Vulnerability Classification
Critical: Could lead to complete system compromise

High: Significant impact, requires immediate attention

Medium: Moderate impact, should be addressed promptly

Low: Minor impact, address as resources allow

Informational: No direct security impact, but useful information

CVSS Scoring
All CVSS scores follow the CVSS v3.1 specification. Scores range from 0.0 (no risk) to 10.0 (critical).

#### Remediation Timeline
gantt
    title Vulnerability Remediation Timeline
    dateFormat  YYYY-MM-DD
    section Critical
    {{ critical_timeline }}
    section High
    {{ high_timeline }}
    section Medium
    {{ medium_timeline }}
    section Low
    {{ low_timeline }}

#### Glossary
CVE: Common Vulnerabilities and Exposures

CVSS: Common Vulnerability Scoring System

IDOR: Insecure Direct Object Reference

RCE: Remote Code Execution

SQLi: SQL Injection

XSS: Cross-Site Scripting

SSRF: Server-Side Request Forgery

#### Contact Information
For questions about this report or assistance with remediation:

Security Team: security@arachne-framework.com

Documentation: https://docs.arachne-framework.com

#### Emergency: +1-555-ARACHNE

#### Legal Notice
This report contains confidential information about the security posture of {{ client_name }}. Distribution is restricted to authorized personnel only. Unauthorized distribution may result in legal action.

Report Generated: {{ generated_at }}
Report Version: {{ report_version }}
Confidentiality Level: RESTRICTED
Arachne Framework v2.0 - Post-AI Vulnerability Assessment
```