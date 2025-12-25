#!/usr/bin/env python3
"""
SILKEN-SENTRY
Not just a subdomain enumerator. A live-context hunter.
It discovers, then immediately immerses itself in the found host,
extracting JavaScript, endpoints, comments, and framework fingerprints
to feed the rest of Arachne in real-time.
"""

import asyncio
import aiohttp
import dns.asyncresolver
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from urllib.parse import urljoin, urlparse
import re
import json
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.async_http_client import StealthClient  # Our custom stealth client
from utils.semantic_analyzer import extract_technologies, find_secrets_in_text
from integrations.shodan_censys_client import query_shodan_host

console = Console()

@dataclass
class HostContext:
    """The living dossier of a discovered host."""
    url: str
    ip: str = ""
    status_code: int = 0
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)  # {action, method, inputs}
    comments: List[str] = field(default_factory=list)  # HTML/JS comments
    secrets: List[str] = field(default_factory=list)  # API keys, tokens
    screenshot_path: str = ""
    waf_detected: Optional[str] = None

class SubdomainHunter:
    def __init__(self, root_domain: str, api_keys: dict, knowledge_graph):
        self.root_domain = root_domain
        self.api_keys = api_keys
        self.kg = knowledge_graph
        self.discovered_subdomains: Set[str] = set()
        self.live_hosts: Dict[str, HostContext] = {}  # url -> HostContext
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.session = None

        # Creative Source: Our enumeration uses not just wordlists, but
        # predictive permutation based on common patterns and target history.
        self.base_wordlist = self._generate_dynamic_wordlist()

    def _generate_dynamic_wordlist(self) -> List[str]:
        """Generates a creative, adaptive wordlist for this specific target."""
        common = {'api', 'dev', 'staging', 'test', 'admin', 'portal', 'internal',
                  'secure', 'vpn', 'mail', 'webmail', 'blog', 'shop', 'cdn',
                  'beta', 'alpha', 'prod', 'production', 'demo', 'backup'}
        # Extract company name from root domain (e.g., 'google' from 'google.com')
        company_name = self.root_domain.split('.')[0]
        # Add permutations based on company name
        name_variants = {company_name, f"{company_name}-prod", f"{company_name}prod",
                         f"{company_name}-dev", f"dev-{company_name}", company_name.upper()}
        # Add common prefixes/suffixes
        prefixes = ['', 'admin-', 'dev-', 'stg-', 'uat-', 'prod-', 'internal-']
        suffixes = ['', '-admin', '-dev', '-staging', '-prod', '-internal']
        
        wordlist = set()
        for prefix in prefixes:
            for suffix in suffixes:
                for word in common.union(name_variants):
                    candidate = f"{prefix}{word}{suffix}"
                    wordlist.add(candidate)
        return list(wordlist)

    async def _check_dns(self, subdomain: str) -> Optional[List[str]]:
        """Async DNS resolution with creative NS fallback."""
        fqdn = f"{subdomain}.{self.root_domain}"
        try:
            answers = await self.resolver.resolve(fqdn, 'A')
            return [str(r) for r in answers]
        except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer,
                dns.asyncresolver.Timeout):
            # Try CNAME as well
            try:
                answers = await self.resolver.resolve(fqdn, 'CNAME')
                cnames = [str(r.target).rstrip('.') for r in answers]
                # Try to resolve the CNAME to an IP
                ip_results = []
                for cname in cnames:
                    try:
                        a_answers = await self.resolver.resolve(cname, 'A')
                        ip_results.extend([str(r) for r in a_answers])
                    except:
                        pass
                return ip_results if ip_results else None
            except:
                return None

    async def _enumerate_via_creative_sources(self) -> Set[str]:
        """Query certificate transparency, archives, and external APIs creatively."""
        console.print(f"[yellow]••• Querying creative sources for [cyan]{self.root_domain}[/cyan]...[/yellow]")
        found = set()

        # 1. Certificate Transparency (crt.sh) - but with a twist: look for wildcards
        crt_sh_url = f"https://crt.sh/?q=%25.{self.root_domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(crt_sh_url, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            # Extract ALL names, including wildcards
                            names = name.split('\n') if '\n' in name else [name]
                            for n in names:
                                n = n.strip().lower()
                                if n.startswith('*.'):
                                    # We found a wildcard! This is gold.
                                    base = n[2:]
                                    if base.endswith(self.root_domain):
                                        # Generate creative subdomains for this wildcard scope
                                        for word in ['admin', 'dev', 'staging', 'api', 'internal']:
                                            found.add(f"{word}.{base}")
                                elif n.endswith(self.root_domain):
                                    found.add(n)
        except Exception as e:
            console.print(f"[red]crt.sh query failed: {e}[/red]")

        # 2. Wayback Machine CDX API - but look for *paths* that might hint at subdomains
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.root_domain}/*&output=json&fl=original&collapse=urlkey"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(wayback_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for url_list in data[1:]:  # Skip header
                            url = url_list[0]
                            parsed = urlparse(url)
                            if parsed.hostname:
                                found.add(parsed.hostname)
        except:
            pass

        # 3. Shodan/ Censys if API key provided
        if self.api_keys.get('shodan'):
            shodan_hosts = await query_shodan_host(self.root_domain, self.api_keys['shodan'])
            found.update(shodan_hosts)

        console.print(f"[green]••• Creative sources found [magenta]{len(found)}[/magenta] unique hosts.[/green]")
        return found

    async def _deep_dive_host(self, url: str, ip: str):
        """The MAGIC. When we find a live host, we IMMEDIATELY dive in with a headless browser
        to extract live JavaScript, endpoints, and context."""
        if not url.startswith('http'):
            url = f"http://{url}"
        
        context = HostContext(url=url, ip=ip)
        console.print(f"[dim]  Diving into [blue]{url}[/blue]...[/dim]")

        # Use Playwright for robust headless browsing
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Listen for all network requests (to capture API calls, JS files)
                api_endpoints = set()
                js_files = set()
                
                def on_request(request):
                    req_url = request.url
                    if req_url.endswith('.js'):
                        js_files.add(req_url)
                    # Heuristic for API endpoints
                    elif any(api_indicator in req_url for api_indicator in 
                            ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', 'json', 'ajax']):
                        api_endpoints.add(req_url)
                
                page.on("request", on_request)
                
                # Navigate and wait a bit for JS to load
                response = await page.goto(url, wait_until='networkidle', timeout=10000)
                if response:
                    context.status_code = response.status
                
                # Get page title
                context.title = await page.title()
                
                # Extract ALL HTML comments
                html = await page.content()
                comment_pattern = r'<!--(.*?)-->'
                context.comments = re.findall(comment_pattern, html, re.DOTALL)
                
                # Extract forms
                forms = await page.query_selector_all('form')
                for form in forms:
                    action = await form.get_attribute('action') or ''
                    method = await form.get_attribute('method') or 'get'
                    # Make action absolute
                    action = urljoin(url, action)
                    inputs = []
                    for inp in await form.query_selector_all('input, textarea, select'):
                        inp_name = await inp.get_attribute('name')
                        if inp_name:
                            inputs.append(inp_name)
                    context.forms.append({
                        'action': action,
                        'method': method.upper(),
                        'inputs': inputs
                    })
                
                # Take a screenshot for the loot
                sanitized_hostname = urlparse(url).hostname.replace('.', '_')
                screenshot_dir = "data/screenshots"
                os.makedirs(screenshot_dir, exist_ok=True)
                screenshot_path = f"{screenshot_dir}/{sanitized_hostname}.png"
                await page.screenshot(path=screenshot_path)
                context.screenshot_path = screenshot_path
                
                await browser.close()
                
                # Process captured data
                context.js_files = list(js_files)
                context.api_endpoints = list(api_endpoints)
                
                # Analyze technologies from comments, JS, headers
                all_text = html + ' '.join(context.comments)
                context.technologies = extract_technologies(all_text)
                
                # Hunt for secrets in JS files and comments
                secret_candidates = []
                for js_url in js_files:
                    # Fetch JS content
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(js_url, timeout=5) as resp:
                                if resp.status == 200:
                                    js_content = await resp.text()
                                    secret_candidates.extend(find_secrets_in_text(js_content))
                    except:
                        pass
                context.secrets = secret_candidates
                
                # Check for WAF
                from utils.waf_buster import detect_waf
                context.waf_detected = detect_waf(url)
                
        except Exception as e:
            console.print(f"[red]  Deep dive failed for {url}: {e}[/red]")
            # Fallback to simple HTTP request
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as resp:
                        context.status_code = resp.status
                        html = await resp.text()
                        # Simple tech detection from headers
                        server_header = resp.headers.get('Server', '')
                        if server_header:
                            context.technologies.append(server_header)
            except:
                pass
        
        # Add this rich context to our knowledge graph
        await self.kg.add_host_context(context)
        self.live_hosts[url] = context
        
        # FEED OTHER MODULES IN REAL-TIME
        # This is the key innovation - immediate propagation
        if context.api_endpoints:
            console.print(f"[dim]    → Feeding [magenta]{len(context.api_endpoints)}[/magenta] API endpoints to Venom-Fang[/dim]")
            # In the full system, this would be a message bus or direct method call
            # For now, we'll write to a shared queue file
            with open("data/api_endpoints_queue.txt", "a") as f:
                for endpoint in context.api_endpoints:
                    f.write(f"{endpoint}\n")
        
        if context.forms:
            console.print(f"[dim]    → Feeding [magenta]{len(context.forms)}[/magenta] forms to Widow's-Bite[/dim]")

    async def hunt(self):
        """Main hunting method - orchestrates creative enumeration and deep dives."""
        console.print(f"[bold cyan]\n🕸️ SILKEN-SENTRY weaving for [blue]{self.root_domain}[/blue][/bold cyan]")
        
        # Phase 1: Creative Enumeration
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task1 = progress.add_task("[yellow]DNS Bruteforce...", total=len(self.base_wordlist))
            
            # Concurrent DNS resolution
            semaphore = asyncio.Semaphore(100)  # Limit concurrency
            
            async def check_one(subdomain):
                ips = await self._check_dns(subdomain)
                if ips:
                    self.discovered_subdomains.add(f"{subdomain}.{self.root_domain}")
                async with semaphore:
                    progress.update(task1, advance=1)
                return ips
            
            dns_tasks = [check_one(word) for word in self.base_wordlist]
            dns_results = await asyncio.gather(*dns_tasks)
        
        # Phase 2: External creative sources
        external_hosts = await self._enumerate_via_creative_sources()
        self.discovered_subdomains.update(external_hosts)
        
        console.print(f"[green]✓ Total discovered: [magenta]{len(self.discovered_subdomains)}[/magenta] hosts[/green]")
        
        # Phase 3: HTTP probing & deep dive CONCURRENTLY
        alive_hosts = []
        console.print("[yellow]••• Probing alive hosts and performing deep dive...[/yellow]")
        
        async def probe_and_dive(hostname):
            # Try both HTTP and HTTPS
            protocols = ['http://', 'https://']
            for proto in protocols:
                url = f"{proto}{hostname}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=10, allow_redirects=True) as resp:
                            if resp.status < 500:  # Consider 4xx as "alive" (host responds)
                                # Get IP if we don't have it
                                ip = resp.remote_address[0] if hasattr(resp.remote_address, '__iter__') else str(resp.remote_address)
                                await self._deep_dive_host(url, ip)
                                alive_hosts.append(url)
                                break
                except:
                    continue
        
        # Concurrent deep dives (limit to 5 at a time for resource management)
        semaphore = asyncio.Semaphore(5)
        async def limited_dive(host):
            async with semaphore:
                await probe_and_dive(host)
        
        dive_tasks = [limited_dive(host) for host in self.discovered_subdomains]
        await asyncio.gather(*dive_tasks)
        
        console.print(f"[bold green]✓ Deep dive complete. [magenta]{len(alive_hosts)}[/magenta] alive hosts with full context harvested.[/bold green]")
        
        # Summary
        total_secrets = sum(len(ctx.secrets) for ctx in self.live_hosts.values())
        total_endpoints = sum(len(ctx.api_endpoints) for ctx in self.live_hosts.values())
        console.print(f"[dim]  Harvested: [blue]{total_endpoints}[/blue] API endpoints, [blue]{total_secrets}[/blue] potential secrets, [blue]{len(self.live_hosts)}[/blue] host dossiers.[/dim]")
        
        return list(self.discovered_subdomains), alive_hosts

# For testing
async def main():
    hunter = SubdomainHunter("example.com", {}, None)
    await hunter.hunt()

if __name__ == "__main__":
    asyncio.run(main())