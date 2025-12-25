"""
External intelligence integration.
"""

import aiohttp
import json
from typing import List, Dict, Optional

class IntelHarvester:
    def __init__(self, api_keys: dict):
        self.api_keys = api_keys
        
    async def harvest(self, domain: str) -> Dict[str, List]:
        """Harvest intelligence from external sources."""
        results = {
            'shodan': [],
            'censys': [],
            'github': [],
            'wayback': []
        }
        
        # Shodan
        if self.api_keys.get('shodan'):
            results['shodan'] = await self._query_shodan(domain)
        
        # Censys
        if self.api_keys.get('censys_id') and self.api_keys.get('censys_secret'):
            results['censys'] = await self._query_censys(domain)
        
        # GitHub (for exposed secrets)
        if self.api_keys.get('github_token'):
            results['github'] = await self._query_github(domain)
        
        # Wayback Machine
        results['wayback'] = await self._query_wayback(domain)
        
        return results
    
    async def _query_shodan(self, domain: str) -> List[Dict]:
        """Query Shodan for host information."""
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_keys['shodan']}&query=hostname:{domain}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('matches', [])
        except:
            pass
        return []
    
    async def _query_wayback(self, domain: str) -> List[str]:
        """Query Wayback Machine for historical URLs."""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # First row is headers
                        return [row[0] for row in data[1:]] if len(data) > 1 else []
        except:
            pass
        return []