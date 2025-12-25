"""
Notification system for critical findings.
"""

import aiohttp
import json
from typing import Dict, Any
from datetime import datetime

class SignalSystem:
    def __init__(self):
        self.config = {}
        self.session = None
        
    async def initialize(self):
        """Initialize notification system."""
        try:
            with open('config/notification_webhooks.json', 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {}
        
        self.session = aiohttp.ClientSession()
        
    async def send_critical(self, finding: dict):
        """Send notification for critical finding."""
        message = self._format_message(finding)
        
        # Send to all enabled channels
        if self.config.get('telegram', {}).get('enabled'):
            await self._send_telegram(message)
        
        if self.config.get('discord', {}).get('enabled'):
            await self._send_discord(message)
        
        if self.config.get('slack', {}).get('enabled'):
            await self._send_slack(message)
    
    async def _send_telegram(self, message: str):
        """Send to Telegram."""
        config = self.config.get('telegram', {})
        bot_token = config.get('bot_token')
        chat_id = config.get('chat_id')
        
        if not bot_token or not chat_id:
            return
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        
        try:
            async with self.session.post(url, json=data) as resp:
                if resp.status != 200:
                    print(f"Telegram send failed: {await resp.text()}")
        except Exception as e:
            print(f"Telegram error: {e}")
    
    async def _send_discord(self, message: str):
        """Send to Discord."""
        config = self.config.get('discord', {})
        webhook = config.get('webhook_url')
        
        if not webhook:
            return
        
        embed = {
            "title": "🚨 Critical Finding",
            "description": message,
            "color": 0xff0000,
            "timestamp": datetime.now().isoformat()
        }
        
        data = {"embeds": [embed]}
        
        try:
            async with self.session.post(webhook, json=data) as resp:
                if resp.status not in [200, 204]:
                    print(f"Discord send failed: {await resp.text()}")
        except Exception as e:
            print(f"Discord error: {e}")
    
    def _format_message(self, finding: dict) -> str:
        """Format finding into notification message."""
        target = finding.get('target', 'Unknown')
        vuln_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        vector = finding.get('vector', '')
        
        message = f"""
<b>🚨 ARACHNE CRITICAL FINDING</b>

<b>Target:</b> {target}
<b>Type:</b> {vuln_type}
<b>Severity:</b> {severity}
<b>Vector:</b> {vector[:100]}...

<b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return message
    
    async def cleanup(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()