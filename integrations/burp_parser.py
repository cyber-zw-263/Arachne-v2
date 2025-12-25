#!/usr/bin/env python3
"""
ARACHNE - Burp Suite State Parser
Ingests Burp Suite's saved state (.burp files) or Proxy history/SAVE files.
Extracts requests, responses, parameters, and endpoints for seeding the ARACHNE graph.
"""
import json
import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

class BurpParser:
    """
    Parses various Burp Suite export formats into a uniform structure for ARACHNE.
    """

    def __init__(self):
        self.requests = []  # List of dicts with 'url', 'method', 'headers', 'body', 'response'

    def parse_burp_state(self, state_file: Path) -> bool:
        """
        Parse a Burp Suite saved state file (.burp).
        This is a ZIP file containing multiple XML files.
        """
        import zipfile
        if not zipfile.is_zipfile(state_file):
            print(f"[-] {state_file} is not a valid ZIP/Burp state file.")
            return False

        try:
            with zipfile.ZipFile(state_file, 'r') as zf:
                # Look for the main request/response XML file
                xml_files = [f for f in zf.namelist() if f.endswith('.xml') and 'request' in f.lower()]
                if not xml_files:
                    print(f"[-] No request/response XML found in {state_file}")
                    return False

                main_xml = xml_files[0]
                with zf.open(main_xml) as f:
                    content = f.read()
                    return self._parse_burp_xml(content)
        except Exception as e:
            print(f"[-] Failed to parse Burp state: {e}")
            return False

    def _parse_burp_xml(self, xml_content: bytes) -> bool:
        """Parse the Burp XML format (from state or export)."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            print("[-] Could not parse XML content.")
            return False

        # Namespace handling (Burp XML often has namespaces)
        ns = {'burp': 'http://portswigger.net/burp/project'}  # Common namespace
        # Try without namespace first
        items = root.findall('.//item') or root.findall('.//burp:item', ns)

        for item in items:
            try:
                # Extract fields, with and without namespace
                time = (item.find('time') or item.find('burp:time', ns)).text
                url = (item.find('url') or item.find('burp:url', ns)).text
                method = (item.find('method') or item.find('burp:method', ns)).text
                status_code_elem = item.find('status') or item.find('burp:status', ns)
                status_code = int(status_code_elem.text) if status_code_elem is not None else 0

                # Request and response are often base64 encoded
                req_b64 = (item.find('request') or item.find('burp:request', ns)).text
                res_b64 = (item.find('response') or item.find('burp:response', ns)).text

                if not all([req_b64, url, method]):
                    continue

                # Decode base64
                try:
                    request_raw = base64.b64decode(req_b64.encode('ascii'))
                    response_raw = base64.b64decode(res_b64.encode('ascii')) if res_b64 else b''
                except:
                    # Might already be plaintext in some exports
                    request_raw = req_b64.encode('utf-8')
                    response_raw = res_b64.encode('utf-8') if res_b64 else b''

                # Parse request into headers and body
                req_str = request_raw.decode('utf-8', errors='ignore')
                headers_raw, _, body_raw = req_str.partition('\r\n\r\n')
                headers_list = headers_raw.split('\r\n')
                method_path = headers_list[0] if headers_list else ''
                headers = {}
                for h in headers_list[1:]:
                    if ': ' in h:
                        k, v = h.split(': ', 1)
                        headers[k] = v

                self.requests.append({
                    'timestamp': time,
                    'url': url,
                    'method': method,
                    'status_code': status_code,
                    'headers': headers,
                    'body': body_raw,
                    'response_raw': response_raw,
                    'source': 'burp_state'
                })

            except Exception as e:
                print(f"[-] Error parsing item: {e}")
                continue

        print(f"[+] Parsed {len(self.requests)} requests from Burp state.")
        return True

    def parse_burp_proxy_history(self, history_file: Path) -> bool:
        """
        Parse a Burp Proxy history export (SAVE file in XML or JSON).
        """
        content = history_file.read_text(encoding='utf-8', errors='ignore')

        # Try JSON first (Burp's newer JSON export)
        if content.strip().startswith('{'):
            return self._parse_burp_json(json.loads(content))
        else:
            # Assume XML
            return self._parse_burp_xml(content.encode('utf-8'))

    def _parse_burp_json(self, data: Dict[str, Any]) -> bool:
        """Parse Burp's JSON export format."""
        try:
            # Structure can vary; try common patterns
            if 'log' in data and 'entries' in data['log']:
                entries = data['log']['entries']
            elif isinstance(data, list):
                entries = data
            else:
                print("[-] Unrecognized JSON structure.")
                return False

            for entry in entries:
                req = entry.get('request', {})
                res = entry.get('response', {})
                url = req.get('url', '')
                method = req.get('method', 'GET')
                headers_list = req.get('headers', [])
                headers = {h['name']: h['value'] for h in headers_list}
                body = req.get('postData', {}).get('text', '')

                response_status = res.get('status', 0)
                response_content = res.get('content', {}).get('text', '')

                self.requests.append({
                    'timestamp': entry.get('startedDateTime', ''),
                    'url': url,
                    'method': method,
                    'status_code': response_status,
                    'headers': headers,
                    'body': body,
                    'response_raw': response_content.encode('utf-8') if isinstance(response_content, str) else b'',
                    'source': 'burp_json'
                })

            print(f"[+] Parsed {len(self.requests)} requests from Burp JSON.")
            return True

        except Exception as e:
            print(f"[-] Failed to parse Burp JSON: {e}")
            return False

    def extract_parameters(self) -> Dict[str, List[Any]]:
        """Extract all unique parameters from parsed requests."""
        params = {
            'query_params': set(),
            'body_params': set(),
            'headers_custom': set(),
            'endpoints': set()
        }

        for req in self.requests:
            # Parse URL for query parameters
            parsed = urlparse(req['url'])
            params['endpoints'].add(parsed.path)
            query = parse_qs(parsed.query)
            params['query_params'].update(query.keys())

            # Parse POST body (assuming application/x-www-form-urlencoded for simplicity)
            if req['method'] in ['POST', 'PUT', 'PATCH'] and req['body']:
                # Try URL-encoded first
                body_qs = parse_qs(req['body'])
                params['body_params'].update(body_qs.keys())
                # TODO: Add JSON body parsing

            # Custom headers (non-standard)
            standard_headers = {'host', 'user-agent', 'accept', 'content-type', 'cookie', 'connection'}
            for h in req['headers']:
                if h.lower() not in standard_headers:
                    params['headers_custom'].add(h)

        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in params.items()}

    def to_arachne_seed(self) -> Dict[str, Any]:
        """
        Convert parsed Burp data into a seed format for ARACHNE modules.
        """
        seed = {
            'requests': self.requests[:1000],  # Limit to first 1000 to avoid huge memory
            'parameters': self.extract_parameters(),
            'unique_domains': set(),
            'unique_paths': set()
        }

        for req in self.requests[:1000]:
            parsed = urlparse(req['url'])
            seed['unique_domains'].add(parsed.netloc)
            seed['unique_paths'].add(parsed.path)

        seed['unique_domains'] = list(seed['unique_domains'])
        seed['unique_paths'] = list(seed['unique_paths'])
        return seed


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python burp_parser.py <path_to_burp_file>")
        sys.exit(1)

    parser = BurpParser()
    file_path = Path(sys.argv[1])

    if file_path.suffix == '.burp':
        success = parser.parse_burp_state(file_path)
    else:
        success = parser.parse_burp_proxy_history(file_path)

    if success:
        seed = parser.to_arachne_seed()
        print(f"[+] Extracted {len(seed['requests'])} requests.")
        print(f"[+] Unique domains: {len(seed['unique_domains'])}")
        print(f"[+] Unique paths: {len(seed['unique_paths'])}")
        print(f"[+] Query parameters: {len(seed['parameters']['query_params'])}")
        print(f"[+] Body parameters: {len(seed['parameters']['body_params'])}")
        # Save a sample seed
        with open('burp_seed_sample.json', 'w') as f:
            json.dump(seed, f, indent=2, default=str)
        print("[+] Sample seed saved to burp_seed_sample.json")