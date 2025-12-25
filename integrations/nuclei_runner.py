#!/usr/bin/env python3
"""
ARACHNE - Nuclei Integration
Orchestrates Nuclei scanning, parses JSON output, and feeds results into the ARACHNE knowledge graph.
"""
import asyncio
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, AsyncGenerator
import aiofiles
from datetime import datetime

class NucleiRunner:
    """
    Wraps the Nuclei CLI, providing async orchestration and result integration.
    """

    def __init__(self, nuclei_path: str = "nuclei", template_dir: Optional[str] = None):
        """
        Args:
            nuclei_path: Path to Nuclei binary or 'nuclei' if in PATH.
            template_dir: Custom template directory (optional).
        """
        self.nuclei_path = nuclei_path
        self.template_dir = template_dir
        self.results: List[Dict[str, Any]] = []

    async def check_installed(self) -> bool:
        """Verify Nuclei is installed and accessible."""
        try:
            proc = await asyncio.create_subprocess_shell(
                f"{self.nuclei_path} -version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                print(f"[+] Nuclei found: {stdout.decode().splitlines()[0]}")
                return True
            else:
                print(f"[-] Nuclei check failed: {stderr.decode()}")
                return False
        except FileNotFoundError:
            print(f"[-] Nuclei binary not found at '{self.nuclei_path}'. Install from https://github.com/projectdiscovery/nuclei")
            return False

    async def run_scan(self,
                       target: str,
                       templates: Optional[List[str]] = None,
                       severity: Optional[List[str]] = None,
                       rate_limit: int = 150,
                       timeout: int = 10,
                       output_file: Optional[Path] = None) -> bool:
        """
        Run a Nuclei scan against a target.

        Args:
            target: URL, host, or file with targets.
            templates: Specific template(s) to run (e.g., ['cves', 'misconfigurations']).
            severity: Filter by severity (e.g., ['critical', 'high']).
            rate_limit: Requests per second limit.
            timeout: Timeout per request in seconds.
            output_file: File to write JSON output to.
        """
        if not await self.check_installed():
            return False

        cmd = [self.nuclei_path, "-json", "-silent", "-stats", "-si", "5"]

        # Target
        if Path(target).exists():
            cmd.extend(["-l", target])
        else:
            cmd.extend(["-u", target])

        # Templates
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        else:
            cmd.append("-nt")  # All templates except helpers

        # Severity filter
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # Rate limiting and timeout
        cmd.extend(["-rl", str(rate_limit), "-timeout", str(timeout)])

        # Custom template directory
        if self.template_dir:
            cmd.extend(["-templates", self.template_dir])

        # Output file (for persistence)
        if output_file:
            cmd.extend(["-o", str(output_file)])

        print(f"[*] Running Nuclei: {' '.join(cmd)}")

        # Run asynchronously, streaming output
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Process stdout line by line (JSONL format)
        async for line in self._read_stream(proc.stdout):
            if line:
                try:
                    result = json.loads(line)
                    self.results.append(result)
                    # Print a brief summary for immediate feedback
                    template = result.get('template', 'unknown')
                    host = result.get('host', 'unknown')
                    print(f"[Nuclei] {template} -> {host}")
                except json.JSONDecodeError:
                    # Might be a stats line or other output
                    if 'requests' in line.lower():
                        print(f"[Nuclei Stats] {line.strip()}")

        # Capture any errors
        stderr = await proc.stderr.read()
        if stderr:
            print(f"[-] Nuclei stderr: {stderr.decode()}")

        await proc.wait()
        print(f"[+] Nuclei scan finished. Found {len(self.results)} results.")
        return True

    async def _read_stream(self, stream: asyncio.StreamReader) -> AsyncGenerator[str, None]:
        """Async generator to read lines from a stream."""
        while True:
            line = await stream.readline()
            if not line:
                break
            yield line.decode('utf-8', errors='ignore').strip()

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all collected results."""
        return self.results

    def convert_to_graph_nodes(self) -> List[Dict[str, Any]]:
        """
        Convert Nuclei results into nodes for the ARACHNE knowledge graph.
        Each node represents a finding with relationships to the target.
        """
        nodes = []
        for result in self.results:
            node_id = f"nuclei_{result.get('template-id', 'unknown')}_{hash(json.dumps(result, sort_keys=True))}"

            # Extract key information
            info = result.get('info', {})
            severity = info.get('severity', 'unknown').upper()
            name = info.get('name', 'Unnamed Finding')
            description = info.get('description', '')
            reference = info.get('reference', [])
            if isinstance(reference, str):
                reference = [reference]

            # Build node
            node = {
                'id': node_id,
                'type': 'vulnerability',
                'source': 'nuclei',
                'severity': severity,
                'data': {
                    'name': name,
                    'description': description[:500],  # Truncate long descriptions
                    'template_id': result.get('template-id'),
                    'template_url': info.get('template-url', ''),
                    'references': reference,
                    'host': result.get('host'),
                    'matched_at': result.get('matched-at'),
                    'timestamp': result.get('timestamp', datetime.utcnow().isoformat()),
                    'raw': result  # Keep the full result for reference
                },
                'relationships': [
                    {
                        'type': 'AFFECTS',
                        'target': result.get('host'),
                        'target_type': 'domain'
                    }
                ]
            }
            nodes.append(node)
        return nodes

    async def run_from_arachne_targets(self, targets_file: Path, output_dir: Path):
        """
        Integrated method to be called from ARACHNE core.
        Scans targets from the ARACHNE target list, saves results, returns graph nodes.
        """
        if not targets_file.exists():
            print(f"[-] Targets file not found: {targets_file}")
            return []

        # Create a unique output file for this run
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"nuclei_scan_{timestamp}.jsonl"

        # Run with a broad template set, focusing on critical/high
        await self.run_scan(
            target=str(targets_file),
            severity=['critical', 'high', 'medium'],
            output_file=output_file
        )

        # Convert to graph nodes
        nodes = self.convert_to_graph_nodes()
        print(f"[+] Generated {len(nodes)} graph nodes from Nuclei results.")
        return nodes


if __name__ == "__main__":
    # Quick test
    async def test():
        runner = NucleiRunner()
        # Test against a safe, non-prod target
        await runner.run_scan("http://scanme.nmap.org", templates=["technologies"], severity=["low"])
        print(f"Got {len(runner.get_results())} results.")
        nodes = runner.convert_to_graph_nodes()
        if nodes:
            print(f"Sample node: {json.dumps(nodes[0], indent=2)}")

    asyncio.run(test())