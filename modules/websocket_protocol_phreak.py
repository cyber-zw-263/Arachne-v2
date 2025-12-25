#!/usr/bin/env python3
"""
WEBSOCKET PROTOCOL PHREAK
Advanced WebSocket/SSE protocol testing and exploitation.
Finds vulnerabilities in real-time communication protocols.
"""

import asyncio
import json
import websockets
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import random
import hashlib

@dataclass
class WebSocketMessage:
    timestamp: str
    direction: str  # 'incoming' or 'outgoing'
    message_type: str  # 'text', 'binary', 'ping', 'pong', 'close'
    content: Any
    size: int

@dataclass
class WebSocketVulnerability:
    type: str
    severity: str
    description: str
    proof_of_concept: str
    impact: str = ""
    location: str = ""

@dataclass
class WebSocketEndpoint:
    url: str
    protocols: List[str] = field(default_factory=list)
    origin: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False
    auth_token: Optional[str] = None

class WebSocketProtocolPhreak:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.endpoints: List[WebSocketEndpoint] = []
        self.messages: List[WebSocketMessage] = []
        self.vulnerabilities: List[WebSocketVulnerability] = []
        self.connection = None
        self.session_id = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]
        
    async def discover_websocket_endpoints(self) -> List[WebSocketEndpoint]:
        """Discover WebSocket endpoints on the target."""
        endpoints = []
        
        # Common WebSocket paths
        common_paths = [
            '/ws', '/websocket', '/socket', '/wss',
            '/api/ws', '/api/socket', '/live', '/realtime',
            '/chat', '/notifications', '/updates',
            '/socket.io', '/wsocket', '/wsp'
        ]
        
        # Try to upgrade HTTP connections to WebSocket
        for path in common_paths:
            ws_url = self.target_url.replace('http', 'ws') + path
            wss_url = self.target_url.replace('http', 'wss') + path
            
            for url in [ws_url, wss_url]:
                endpoint = WebSocketEndpoint(url=url)
                
                # Try to connect
                if await self.test_connection(endpoint):
                    endpoints.append(endpoint)
        
        self.endpoints = endpoints
        return endpoints
    
    async def test_connection(self, endpoint: WebSocketEndpoint) -> bool:
        """Test if WebSocket endpoint is accessible."""
        try:
            async with websockets.connect(
                endpoint.url,
                timeout=10,
                extra_headers={
                    'User-Agent': 'Arachne-WebSocket-Tester/2.0',
                    'Origin': self.target_url
                }
            ) as websocket:
                # Send ping to test responsiveness
                await websocket.ping()
                
                # Try to receive a message (with timeout)
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=2)
                    self._record_message(message, 'incoming', 'text')
                except asyncio.TimeoutError:
                    pass  # No message received, that's okay
                
                return True
                
        except Exception as e:
            print(f"Connection failed for {endpoint.url}: {e}")
            return False
    
    async def fingerprint_protocol(self, endpoint: WebSocketEndpoint) -> Dict:
        """Fingerprint WebSocket protocol and implementation."""
        fingerprint = {
            'url': endpoint.url,
            'supports_ping_pong': False,
            'supports_fragmentation': False,
            'message_types_supported': [],
            'max_message_size': None,
            'compression_enabled': False,
            'protocols_offered': []
        }
        
        try:
            async with websockets.connect(
                endpoint.url,
                timeout=15,
                extra_headers={
                    'User-Agent': 'Arachne-WebSocket-Fingerprinter/2.0',
                    'Origin': self.target_url,
                    'Sec-WebSocket-Extensions': 'permessage-deflate'
                }
            ) as websocket:
                
                # Test ping/pong
                try:
                    await websocket.ping()
                    pong = await asyncio.wait_for(websocket.recv(), timeout=3)
                    if isinstance(pong, bytes) and len(pong) == 0:  # Pong frame
                        fingerprint['supports_ping_pong'] = True
                except:
                    pass
                
                # Test different message types
                test_messages = [
                    ('text', 'Hello WebSocket'),
                    ('text', 'A' * 1000),  # Medium size
                    ('text', 'B' * 10000),  # Large size
                    ('binary', b'\x00\x01\x02\x03\x04'),
                ]
                
                for msg_type, content in test_messages:
                    try:
                        if msg_type == 'text':
                            await websocket.send(content)
                        else:
                            await websocket.send(content)
                        
                        # Try to receive response
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=2)
                            fingerprint['message_types_supported'].append(msg_type)
                        except asyncio.TimeoutError:
                            pass
                            
                    except websockets.exceptions.PayloadTooBig:
                        if fingerprint['max_message_size'] is None:
                            fingerprint['max_message_size'] = len(content)
                    except:
                        pass
                
                # Check for compression
                if 'permessage-deflate' in str(websocket.response.headers.get('Sec-WebSocket-Extensions', '')):
                    fingerprint['compression_enabled'] = True
                
                # Get offered protocols
                protocols = websocket.response.headers.get('Sec-WebSocket-Protocol', '')
                if protocols:
                    fingerprint['protocols_offered'] = [p.strip() for p in protocols.split(',')]
        
        except Exception as e:
            print(f"Fingerprinting failed: {e}")
        
        return fingerprint
    
    async def fuzz_messages(self, endpoint: WebSocketEndpoint, num_messages: int = 50):
        """Fuzz WebSocket with malformed and malicious messages."""
        fuzz_payloads = [
            # Overly large messages
            ('size', 'A' * 100000),
            ('size', 'B' * 1000000),
            
            # Malformed JSON
            ('json', '{invalid json'),
            ('json', '{"test": NaN}'),
            ('json', '{"test": Infinity}'),
            ('json', '{"test": -Infinity}'),
            ('json', '{"test": undefined}'),
            
            # Deeply nested structures
            ('nested', json.dumps({'a': {'b': {'c': {'d': {'e': 'deep'}}}} * 10)),
            
            # Special characters and injections
            ('injection', '{"cmd": "echo \'test\'"}'),
            ('injection', '</script><script>alert(1)</script>'),
            ('injection', '${7*7}'),
            ('injection', '{{7*7}}'),
            
            # Binary fuzzing
            ('binary', b'\x00' * 1000),
            ('binary', b'\xff' * 1000),
            ('binary', b'\x00\xff' * 500),
            
            # Control characters
            ('control', '\x00\x01\x02\x03\x04\x05\x06\x07'),
            ('control', '\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'),
            
            # Unicode attacks
            ('unicode', '𒀀' * 100),  # Cuneiform character
            ('unicode', '\u202e' + 'evil' + '\u202c'),  # Right-to-left override
            ('unicode', '\u0000' + 'injected'),
            
            # Regex bombs
            ('regex', 'a' * 10000 + '!'),
            ('regex', '(a+)+' + 'a' * 50 + '!'),
        ]
        
        results = []
        
        try:
            async with websockets.connect(
                endpoint.url,
                timeout=30,
                extra_headers={
                    'User-Agent': 'Arachne-WebSocket-Fuzzer/2.0',
                    'Origin': self.target_url
                }
            ) as websocket:
                
                for i, (category, payload) in enumerate(fuzz_payloads[:num_messages]):
                    try:
                        start_time = datetime.now()
                        
                        if isinstance(payload, str):
                            await websocket.send(payload)
                        else:
                            await websocket.send(payload)
                        
                        # Wait for response
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=5)
                            response_time = (datetime.now() - start_time).total_seconds()
                            
                            result = {
                                'payload_num': i + 1,
                                'category': category,
                                'payload_size': len(payload) if isinstance(payload, (str, bytes)) else 0,
                                'status': 'responded',
                                'response_time': response_time,
                                'response_size': len(response) if hasattr(response, '__len__') else 0
                            }
                            
                            # Check for error indicators in response
                            if any(indicator in str(response).lower() 
                                   for indicator in ['error', 'exception', 'invalid', 'malformed']):
                                result['error_indicator'] = True
                            
                        except asyncio.TimeoutError:
                            result = {
                                'payload_num': i + 1,
                                'category': category,
                                'payload_size': len(payload) if isinstance(payload, (str, bytes)) else 0,
                                'status': 'timeout',
                                'response_time': None
                            }
                        
                        except websockets.exceptions.ConnectionClosed:
                            result = {
                                'payload_num': i + 1,
                                'category': category,
                                'payload_size': len(payload) if isinstance(payload, (str, bytes)) else 0,
                                'status': 'connection_closed',
                                'response_time': None
                            }
                            # Reconnect for next test
                            break
                        
                        results.append(result)
                        
                        # Small delay between messages
                        await asyncio.sleep(0.1)
                    
                    except Exception as e:
                        results.append({
                            'payload_num': i + 1,
                            'category': category,
                            'status': 'error',
                            'error': str(e)
                        })
        
        except Exception as e:
            print(f"Fuzzing failed: {e}")
        
        return results
    
    async def test_state_confusion(self, endpoint: WebSocketEndpoint):
        """Test for state confusion and race conditions."""
        vulnerabilities = []
        
        # Test parallel connections with same session
        try:
            # Create multiple connections "simultaneously"
            connections = []
            for i in range(5):
                try:
                    ws = await websockets.connect(
                        endpoint.url,
                        timeout=10,
                        extra_headers={
                            'User-Agent': f'Arachne-Parallel-{i}/2.0',
                            'Origin': self.target_url,
                            'X-Session-ID': self.session_id
                        }
                    )
                    connections.append(ws)
                except:
                    pass
            
            # Send messages from all connections
            messages_sent = 0
            for i, ws in enumerate(connections):
                try:
                    await ws.send(json.dumps({
                        'type': 'join',
                        'room': 'test_room',
                        'user_id': f'test_user_{i}',
                        'session': self.session_id
                    }))
                    messages_sent += 1
                except:
                    pass
            
            if messages_sent > 1:
                # Check for duplicate sessions or state issues
                vulnerabilities.append(
                    WebSocketVulnerability(
                        type="Parallel Session Handling",
                        severity="MEDIUM",
                        description=f"Multiple parallel connections accepted with same session ID",
                        proof_of_concept=f"Created {messages_sent} parallel connections with session: {self.session_id}",
                        impact="Potential for race conditions or session confusion"
                    )
                )
            
            # Clean up
            for ws in connections:
                try:
                    await ws.close()
                except:
                    pass
        
        except Exception as e:
            print(f"State confusion test failed: {e}")
        
        # Test message ordering
        try:
            async with websockets.connect(
                endpoint.url,
                timeout=15,
                extra_headers={
                    'User-Agent': 'Arachne-Order-Tester/2.0',
                    'Origin': self.target_url
                }
            ) as websocket:
                
                # Send rapid sequence of messages
                messages = [
                    '{"seq": 1, "action": "start"}',
                    '{"seq": 2, "action": "middle"}',
                    '{"seq": 3, "action": "end"}',
                    '{"seq": 4, "action": "cancel"}',  # This should cancel previous
                ]
                
                for msg in messages:
                    await websocket.send(msg)
                    await asyncio.sleep(0.01)  # Very small delay
                
                # Collect responses
                responses = []
                for _ in range(len(messages)):
                    try:
                        resp = await asyncio.wait_for(websocket.recv(), timeout=2)
                        responses.append(resp)
                    except asyncio.TimeoutError:
                        break
                
                # Check if responses are in order
                if len(responses) > 1:
                    # Parse sequence numbers from responses
                    seq_numbers = []
                    for resp in responses:
                        try:
                            data = json.loads(resp)
                            if 'seq' in data:
                                seq_numbers.append(data['seq'])
                        except:
                            pass
                    
                    # Check if sequence is maintained
                    if seq_numbers != sorted(seq_numbers):
                        vulnerabilities.append(
                            WebSocketVulnerability(
                                type="Message Ordering Issue",
                                severity="LOW",
                                description="WebSocket messages processed out of order",
                                proof_of_concept=f"Sent messages in order: 1,2,3,4 but received: {seq_numbers}",
                                impact="Potential race conditions in stateful operations"
                            )
                        )
        
        except Exception as e:
            print(f"Message ordering test failed: {e}")
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    async def test_authentication_bypass(self, endpoint: WebSocketEndpoint):
        """Test for WebSocket authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        # Test 1: Connect without required headers
        try:
            async with websockets.connect(
                endpoint.url,
                timeout=10,
                extra_headers={
                    'User-Agent': 'Arachne-Unauth-Tester/2.0'
                    # No Origin, no Auth headers
                }
            ) as websocket:
                
                # Try to send a privileged command
                await websocket.send('{"action": "get_users"}')
                
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3)
                    
                    # Check if we got data we shouldn't have access to
                    if any(indicator in response.lower() 
                           for indicator in ['user', 'admin', 'password', 'email', 'list']):
                        vulnerabilities.append(
                            WebSocketVulnerability(
                                type="Authentication Bypass",
                                severity="CRITICAL",
                                description="WebSocket endpoint accessible without authentication",
                                proof_of_concept="Connected without auth headers and retrieved: " + response[:100],
                                impact="Unauthorized access to sensitive data/functionality"
                            )
                        )
                
                except asyncio.TimeoutError:
                    pass  # No response is okay
        
        except Exception as e:
            print(f"Unauthenticated test failed: {e}")
        
        # Test 2: Try common auth bypass techniques
        bypass_attempts = [
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'Bearer '},
            {'X-API-Key': 'test'},
            {'X-Auth-Token': 'guest'},
            {'Cookie': 'session=test'},
        ]
        
        for bypass in bypass_attempts:
            try:
                headers = {'User-Agent': 'Arachne-Bypass-Tester/2.0'}
                headers.update(bypass)
                
                async with websockets.connect(
                    endpoint.url,
                    timeout=10,
                    extra_headers=headers
                ) as websocket:
                    
                    await websocket.send('{"action": "ping"}')
                    
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=2)
                        if 'pong' in response.lower() or 'success' in response.lower():
                            vulnerabilities.append(
                                WebSocketVulnerability(
                                    type="Weak Authentication",
                                    severity="MEDIUM",
                                    description=f"WebSocket accepts weak auth: {list(bypass.keys())[0]}",
                                    proof_of_concept=f"Used header: {bypass}",
                                    impact="Potential for authentication bypass"
                                )
                            )
                    except asyncio.TimeoutError:
                        pass
            
            except Exception as e:
                pass  # Expected to fail for most attempts
        
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    
    def _record_message(self, content: Any, direction: str, message_type: str):
        """Record a WebSocket message."""
        message = WebSocketMessage(
            timestamp=datetime.now().isoformat(),
            direction=direction,
            message_type=message_type,
            content=content,
            size=len(content) if hasattr(content, '__len__') else 0
        )
        self.messages.append(message)
    
    def analyze_results(self) -> Dict:
        """Analyze test results and generate report."""
        analysis = {
            'endpoints_tested': len(self.endpoints),
            'messages_captured': len(self.messages),
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerability_types': {},
            'recommendations': []
        }
        
        # Count vulnerability types
        for vuln in self.vulnerabilities:
            analysis['vulnerability_types'][vuln.type] = analysis['vulnerability_types'].get(vuln.type, 0) + 1
        
        # Generate recommendations
        if any(v.severity == 'CRITICAL' for v in self.vulnerabilities):
            analysis['recommendations'].append("🔴 **IMMEDIATE ACTION**: Address critical authentication bypass vulnerabilities")
        
        if 'Parallel Session Handling' in analysis['vulnerability_types']:
            analysis['recommendations'].append("🟡 Implement proper session handling for parallel connections")
        
        if 'Message Ordering Issue' in analysis['vulnerability_types']:
            analysis['recommendations'].append("🟡 Ensure message processing maintains correct order")
        
        if not self.vulnerabilities:
            analysis['recommendations'].append("🟢 No critical vulnerabilities found. Consider implementing rate limiting.")
        
        return analysis
    
    def generate_report(self) -> str:
        """Generate WebSocket security assessment report."""
        analysis = self.analyze_results()
        
        report_lines = [
            "# WebSocket Security Assessment",
            f"Target: {self.target_url}",
            f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Session ID: {self.session_id}",
            "",
            "## Executive Summary",
            f"Endpoints tested: {analysis['endpoints_tested']}",
            f"Vulnerabilities found: {analysis['vulnerabilities_found']}",
            f"Messages analyzed: {analysis['messages_captured']}",
        ]
        
        if analysis['vulnerability_types']:
            report_lines.append("\n## Vulnerability Breakdown")
            for vuln_type, count in analysis['vulnerability_types'].items():
                report_lines.append(f"- {vuln_type}: {count}")
        
        if self.vulnerabilities:
            report_lines.append("\n## Detailed Findings")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report_lines.append(f"\n{i}. **{vuln.type}** ({vuln.severity})")
                report_lines.append(f"   Description: {vuln.description}")
                report_lines.append(f"   Proof of Concept: {vuln.proof_of_concept[:100]}...")
                if vuln.impact:
                    report_lines.append(f"   Impact: {vuln.impact}")
        
        if analysis['recommendations']:
            report_lines.append("\n## Recommendations")
            for rec in analysis['recommendations']:
                report_lines.append(f"- {rec}")
        
        # General recommendations
        report_lines.append("\n## General WebSocket Security Best Practices")
        report_lines.append("1. **Authentication**: Implement proper authentication before upgrade")
        report_lines.append("2. **Authorization**: Validate permissions for each message/action")
        report_lines.append("3. **Input Validation**: Sanitize all incoming WebSocket messages")
        report_lines.append("4. **Rate Limiting**: Implement per-connection rate limits")
        report_lines.append("5. **Message Size Limits**: Enforce maximum message sizes")
        report_lines.append("6. **Session Management**: Properly handle parallel connections")
        report_lines.append("7. **Logging**: Log all WebSocket connections and critical actions")
        
        report_lines.append(f"\n---\n*Report generated by Arachne WebSocket Protocol Phreak v2.0*")
        
        return "\n".join(report_lines)

# Example usage
async def main():
    phreak = WebSocketProtocolPhreak("https://example.com")
    
    print("Discovering WebSocket endpoints...")
    endpoints = await phreak.discover_websocket_endpoints()
    
    if not endpoints:
        print("No WebSocket endpoints found")
        return
    
    print(f"Found {len(endpoints)} WebSocket endpoints")
    
    for endpoint in endpoints:
        print(f"\nTesting endpoint: {endpoint.url}")
        
        # Fingerprint
        fingerprint = await phreak.fingerprint_protocol(endpoint)
        print(f"  Protocol: {fingerprint.get('protocols_offered', ['unknown'])[0]}")
        print(f"  Compression: {fingerprint.get('compression_enabled', False)}")
        print(f"  Ping/Pong: {fingerprint.get('supports_ping_pong', False)}")
        
        # Test for vulnerabilities
        print("  Testing for authentication bypass...")
        await phreak.test_authentication_bypass(endpoint)
        
        print("  Testing for state confusion...")
        await phreak.test_state_confusion(endpoint)
        
        print("  Fuzzing messages...")
        fuzz_results = await phreak.fuzz_messages(endpoint, num_messages=20)
        print(f"    Fuzzed {len(fuzz_results)} messages")
    
    # Generate report
    report = phreak.generate_report()
    print("\n" + "=" * 60)
    print(report)
    
    # Save report
    with open("websocket_assessment.md", "w") as f:
        f.write(report)
    print("\nReport saved to websocket_assessment.md")

if __name__ == "__main__":
    asyncio.run(main())