import aiohttp
import asyncio
import random
from typing import Optional, Dict, Any

class StealthClient:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Arachne/2.0 (Security Research)'
        ]
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': random.choice(self.user_agents)}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make a request with random delays and fingerprint rotation."""
        # Random delay between requests (0.1-2 seconds)
        await asyncio.sleep(random.uniform(0.1, 2))
        
        # Rotate User-Agent
        if self.session:
            self.session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
        # Add random headers to blend in
        extra_headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': str(random.randint(0, 1)),
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
        
        if 'headers' in kwargs:
            kwargs['headers'].update(extra_headers)
        else:
            kwargs['headers'] = extra_headers
        
        # Make the request
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        return await self.session.request(method, url, **kwargs)


# Backwards compatibility: some modules expect `AsyncHTTPClient`
AsyncHTTPClient = StealthClient