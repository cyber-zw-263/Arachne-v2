#!/usr/bin/env python3
"""
FFUF WRAPPER INTEGRATION
Orchestrates ffuf with Arachne's dynamic wordlists and intelligence.
"""

import asyncio
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
import tempfile

@dataclass
class FFUFResult:
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str
    redirect_location: Optional[str] = None

class FFUFWrapper:
    def __init__(self, ffuf_path: str = "ffuf", wordlist_dir: Path = None):
        self.ffuf_path = ffuf_path
        self.wordlist_dir = wordlist_dir or Path("config/wordlists")
        self.results: List[FFUFResult] = []
        
    async def fuzz_directory(self, 
                            base_url: str,
                            wordlist: str = "directories_context.txt",
                            extensions: List[str] = None) -> List[FFUFResult]:
        """
        Fuzz directories on a target.
        
        Args:
            base_url: Base URL to fuzz (e.g., https://example.com)
            wordlist: Wordlist filename to use
            extensions: File extensions to try (e.g., ['.php', '.html', '.txt'])
        """
        if extensions is None:
            extensions = ['', '.php', '.html', '.txt', '.json', '.xml']
        
        # Prepare wordlist path
        wordlist_path = self.wordlist_dir / wordlist
        if not wordlist_path.exists():
            print(f"Wordlist not found: {wordlist_path}")
            return []
        
        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_file:
            output_file = tmp_file.name
        
        try:
            # Build ffuf command
            cmd = [
                self.ffuf_path,
                "-u", f"{base_url}/FUZZ",
                "-w", str(wordlist_path),
                "-of", "json",
                "-o", output_file,
                "-ac",  # Auto-calibration
                "-c",   # Color output
                "-t", "50",  # Threads
                "-p", "0.1",  # Delay between requests
                "-H", "User-Agent: Arachne/2.0 (Security Research)",
                "-H", "X-Forwarded-For: 127.0.0.1",
                "-mc", "200,204,301,302,307,401,403,500",  # Match these status codes
                "-timeout", "10",
            ]
            
            # Add extensions if specified
            if extensions:
                for ext in extensions:
                    cmd.extend(["-e", ext])
            
            print(f"Running ffuf: {' '.join(cmd[:10])}...")
            
            # Run ffuf
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                print(f"FFUF error: {stderr.decode()}")
                return []
            
            # Parse results
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            self.results = self._parse_results(data)
            return self.results
            
        finally:
            # Clean up temp file
            Path(output_file).unlink(missing_ok=True)
    
    async def fuzz_parameters(self,
                             url: str,
                             params_wordlist: str = "api_params_custom.txt",
                             values_wordlist: str = "mutations_base.txt") -> List[Dict]:
        """
        Fuzz GET/POST parameters.
        
        Args:
            url: URL with parameter placeholder (e.g., https://example.com/search?q=FUZZ)
            params_wordlist: Wordlist for parameter names
            values_wordlist: Wordlist for parameter values
        """
        # Prepare wordlists
        params_path = self.wordlist_dir / params_wordlist
        values_path = self.wordlist_dir / values_wordlist
        
        if not params_path.exists() or not values_path.exists():
            print("Wordlists not found")
            return []
        
        results = []
        
        # Read parameter names
        with open(params_path, 'r') as f:
            parameters = [line.strip() for line in f if line.strip()]
        
        # Read payload values
        with open(values_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        
        # Test each parameter with each payload
        for param in parameters[:20]:  # Limit for demo
            for payload in payloads[:10]:
                # Replace FUZZ placeholder
                test_url = url.replace("FUZZ", f"{param}={payload}")
                
                # You would make HTTP request here
                # For now, just store the test case
                results.append({
                    'url': test_url,
                    'parameter': param,
                    'payload': payload,
                    'method': 'GET'
                })
        
        return results
    
    def _parse_results(self, data: Dict) -> List[FFUFResult]:
        """Parse ffuf JSON output."""
        results = []
        
        if 'results' not in data:
            return results
        
        for item in data['results']:
            result = FFUFResult(
                url=item.get('url', ''),
                status=item.get('status', 0),
                length=item.get('length', 0),
                words=item.get('words', 0),
                lines=item.get('lines', 0),
                content_type=item.get('content-type', ''),
                redirect_location=item.get('redirectlocation')
            )
            results.append(result)
        
        return results
    
    def generate_report(self) -> str:
        """Generate a report from ffuf results."""
        if not self.results:
            return "No results"
        
        report_lines = [
            "# FFUF Scan Report",
            f"Total findings: {len(self.results)}",
            "\n## Findings:"
        ]
        
        for result in self.results:
            report_lines.append(f"- {result.url}")
            report_lines.append(f"  Status: {result.status}, Length: {result.length}")
            if result.redirect_location:
                report_lines.append(f"  Redirect: {result.redirect_location}")
        
        return "\n".join(report_lines)

# Example usage
async def main():
    wrapper = FFUFWrapper()
    
    # Directory fuzzing example
    results = await wrapper.fuzz_directory(
        base_url="https://example.com",
        wordlist="directories_context.txt",
        extensions=['.php', '.html']
    )
    
    print(f"Found {len(results)} directories")
    
    # Parameter fuzzing example
    param_results = await wrapper.fuzz_parameters(
        url="https://example.com/search?q=FUZZ"
    )
    
    print(f"Generated {len(param_results)} parameter tests")

if __name__ == "__main__":
    asyncio.run(main())