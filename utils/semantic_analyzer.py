#!/usr/bin/env python3
"""
ARACHNE - Semantic Analyzer
Extracts meaning, secrets, and architectural hints from source code and comments.
Uses heuristics and pattern matching to think like a developer who made a mistake.
"""
import re
import ast
import tokenize
from io import StringIO
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional
import json

class CodeSemantics:
    """Holds the extracted semantic meaning from a piece of code."""

    def __init__(self):
        self.secrets: List[Dict[str, str]] = []  # {'type': 'aws_key', 'value': '...', 'context': 'line 42'}
        self.endpoints: List[Dict[str, str]] = []  # {'method': 'GET', 'path': '/api/user', 'params': ['id']}
        self.imports: Set[str] = set()  # Libraries and modules used
        self.comments: List[Dict[str, str]] = []  # {'text': 'TODO: fix auth', 'line': 12}
        self.config_patterns: Dict[str, List[str]] = {}  # 'database_url': ['postgres://...']
        self.vulnerability_hints: List[str] = []  # 'hardcoded_password', 'eval_used'

class SemanticAnalyzer:
    """
    Reads code not for syntax, but for secrets, structure, and developer intent.
    """

    # Regex patterns for secrets (high recall, will have false positives)
    SECRET_PATTERNS = {
        'aws_access_key': re.compile(r'(AKIA|ASIA)[A-Z0-9]{16}'),
        'aws_secret_key': re.compile(r'(?i)aws[_-]?secret[_-]?(access[_-]?)?key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+]{40}'),
        'generic_api_key': re.compile(r'(?i)(api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\'][A-Za-z0-9._\-+/=]{10,120}["\']'),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'),
        'private_key': re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
        'connection_string': re.compile(r'(postgres|mysql|mongodb)://[A-Za-z0-9_\-\.]+:[^@\s]+@[A-Za-z0-9_\-\.]+/[A-Za-z0-9_\-\.]+'),
    }

    # Patterns for API endpoints in code
    ENDPOINT_PATTERNS = {
        'flask': re.compile(r'@app\.route\(["\']([^"\']+)["\']'),
        'django': re.compile(r'path\(["\']([^"\']+)["\']'),
        'express': re.compile(r'\.(get|post|put|delete)\(["\']([^"\']+)["\']'),
        'generic_url': re.compile(r'["\'`](/api/[A-Za-z0-9_\-\./]+)["\'`]'),
    }

    # Dangerous function calls
    DANGEROUS_CALLS = {
        'eval': re.compile(r'eval\('),
        'exec': re.compile(r'exec\('),
        'os_system': re.compile(r'os\.system\('),
        'subprocess': re.compile(r'subprocess\.call|Popen'),
        'deserialize': re.compile(r'pickle\.loads|yaml\.load|marshal\.loads'),
        'sql_concat': re.compile(r'(\"|\')\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(\"|\')'),
    }

    def analyze_file(self, file_path: Path) -> CodeSemantics:
        """Perform semantic analysis on a single file."""
        semantics = CodeSemantics()
        if not file_path.exists():
            return semantics

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return semantics

        # Extract by language
        if file_path.suffix in ['.py', '.pyc']:
            self._analyze_python(content, semantics, str(file_path))
        elif file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
            self._analyze_javascript(content, semantics, str(file_path))
        elif file_path.suffix in ['.java', '.cpp', '.c', '.cs']:
            self._analyze_generic(content, semantics, str(file_path))
        else:
            self._analyze_generic(content, semantics, str(file_path))

        # Run universal pattern matchers
        self._find_secrets(content, semantics, str(file_path))
        self._find_endpoints(content, semantics)
        self._find_dangerous_calls(content, semantics)
        self._extract_comments(content, semantics)

        return semantics

    def _analyze_python(self, content: str, semantics: CodeSemantics, file_path: str):
        """Python-specific semantic extraction using ast."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Imports
                if isinstance(node, ast.Import):
                    for n in node.names:
                        semantics.imports.add(n.name)
                elif isinstance(node, ast.ImportFrom):
                    semantics.imports.add(node.module or "")

                # Function definitions might hint at endpoints (Flask/Django views)
                if isinstance(node, ast.FunctionDef):
                    # Look for decorators
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                            if decorator.func.attr == 'route':
                                # Flask style @app.route('/path')
                                for arg in decorator.args:
                                    if isinstance(arg, ast.Constant):
                                        semantics.endpoints.append({'method': 'ANY', 'path': arg.s, 'source': file_path})

                # Assignments that look like configuration
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                            key = target.id.lower()
                            value = node.value.s if isinstance(node.value.s, str) else str(node.value.s)
                            if any(conf in key for conf in ['url', 'host', 'pass', 'secret', 'key']):
                                semantics.config_patterns.setdefault(key, []).append(value)
        except SyntaxError:
            pass

    def _analyze_javascript(self, content: str, semantics: CodeSemantics, file_path: str):
        """JavaScript/Node.js specific extraction (heuristic)."""
        # Find require/import statements
        import_re = re.compile(r'(?:require\(["\']|from ["\']|import ["\'])([^"\']+)["\']')
        for match in import_re.findall(content):
            semantics.imports.add(match)

        # Look for Express.js app.METHOD patterns
        for method in ['get', 'post', 'put', 'delete', 'patch']:
            pattern = re.compile(r'\.' + method + r'\(["\']([^"\']+)["\']')
            for match in pattern.findall(content):
                semantics.endpoints.append({'method': method.upper(), 'path': match, 'source': file_path})

    def _analyze_generic(self, content: str, semantics: CodeSemantics, file_path: str):
        """Fallback analysis for any text-based file."""
        # Look for import/include statements
        import_re = re.compile(r'(?:#include|import|using)\s+[<"]([^>"]+)[>"]')
        for match in import_re.findall(content):
            semantics.imports.add(match)

    def _find_secrets(self, content: str, semantics: CodeSemantics, file_path: str):
        """Run secret patterns over the content."""
        for line_num, line in enumerate(content.splitlines(), 1):
            for secret_type, pattern in self.SECRET_PATTERNS.items():
                for match in pattern.findall(line):
                    semantics.secrets.append({
                        'type': secret_type,
                        'value': match if isinstance(match, str) else match[0],
                        'line': line_num,
                        'context': line.strip()[:100],
                        'file': file_path
                    })

    def _find_endpoints(self, content: str, semantics: CodeSemantics):
        """Find API endpoint patterns."""
        for endpoint_type, pattern in self.ENDPOINT_PATTERNS.items():
            for match in pattern.findall(content):
                if isinstance(match, tuple):
                    path = match[1] if len(match) > 1 else match[0]
                else:
                    path = match
                semantics.endpoints.append({
                    'method': 'GET' if 'get' in endpoint_type else 'ANY',
                    'path': path,
                    'pattern_type': endpoint_type
                })

    def _find_dangerous_calls(self, content: str, semantics: CodeSemantics):
        """Flag potentially dangerous code patterns."""
        for danger_type, pattern in self.DANGEROUS_CALLS.items():
            if pattern.search(content):
                semantics.vulnerability_hints.append(danger_type)

    def _extract_comments(self, content: str, semantics: CodeSemantics):
        """Extract comments for hidden context (TODO, FIXME, secrets in comments)."""
        comment_patterns = [
            r'//\s*(.*)',  # Single-line
            r'#\s*(.*)',   # Python/bash
            r'/\*\*(.*?)\*/',  # Multi-line JS/Java (simplified)
            r'<!--(.*?)-->',   # HTML
        ]
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern in comment_patterns:
                match = re.search(pattern, line)
                if match:
                    comment_text = match.group(1).strip()
                    if comment_text and len(comment_text) > 2:
                        # Check for interesting keywords
                        interesting = any(word in comment_text.lower() for word in ['todo', 'fixme', 'hack', 'temp', 'password', 'key', 'secret', 'bug', 'vulnerability'])
                        if interesting:
                            semantics.comments.append({
                                'text': comment_text[:200],
                                'line': line_num,
                                'interesting': interesting
                            })

    def analyze_directory(self, directory: Path) -> Dict[str, CodeSemantics]:
        """Recursively analyze all files in a directory."""
        results = {}
        for file_path in directory.rglob('*'):
            if file_path.is_file() and not any(part.startswith('.') for part in file_path.parts):
                # Skip binary files heuristically
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(1024)
                        # Very basic binary detection
                        if b'\x00' in chunk:
                            continue
                except:
                    continue

                semantics = self.analyze_file(file_path)
                if (semantics.secrets or semantics.endpoints or semantics.vulnerability_hints):
                    results[str(file_path)] = semantics
        return results


if __name__ == "__main__":
    print("[*] Testing Semantic Analyzer on self...")
    analyzer = SemanticAnalyzer()
    results = analyzer.analyze_file(Path(__file__))
    print(f"[+] Found {len(results.secrets)} potential secrets (false positives likely).")
    print(f"[+] Found {len(results.endpoints)} endpoint patterns.")
    print(f"[+] Found {len(results.imports)} unique imports: {list(results.imports)[:5]}...")
    if results.vulnerability_hints:
        print(f"[!] Danger hints: {results.vulnerability_hints}")