"""
Knowledge graph for correlating findings and intelligence.
"""

import networkx as nx
from datetime import datetime
import json
from typing import Dict, List, Any, Optional
import hashlib

class KnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_counters = {}
        
    async def initialize(self):
        """Initialize the graph with base schema."""
        # Add node types
        node_types = ['target', 'subdomain', 'ip', 'port', 'service', 
                     'endpoint', 'parameter', 'vulnerability', 'credential',
                     'technology', 'employee', 'finding', 'ai_model']
        
        for nt in node_types:
            self.graph.add_node(f"type:{nt}", node_type="type")
        
        print("Knowledge Graph initialized")
    
    async def add_host_context(self, host_data: dict):
        """Add a host and its context to the graph."""
        host_id = f"host:{host_data['url']}"
        
        # Add host node
        self.graph.add_node(host_id, 
                           node_type="host",
                           **host_data)
        
        # Add technologies as nodes and connect
        for tech in host_data.get('technologies', []):
            tech_id = f"tech:{tech}"
            self.graph.add_node(tech_id, node_type="technology", name=tech)
            self.graph.add_edge(host_id, tech_id, relationship="uses")
        
        # Add secrets
        for secret in host_data.get('secrets', []):
            secret_id = f"secret:{hashlib.md5(secret.encode()).hexdigest()[:8]}"
            self.graph.add_node(secret_id, node_type="secret", value=secret)
            self.graph.add_edge(host_id, secret_id, relationship="exposed")
        
        # Connect to target domain
        target_domain = host_data['url'].split('//')[1].split('/')[0]
        base_domain = '.'.join(target_domain.split('.')[-2:])
        target_id = f"target:{base_domain}"
        self.graph.add_edge(host_id, target_id, relationship="belongs_to")
    
    async def add_finding(self, finding: dict):
        """Add a vulnerability finding to the graph."""
        finding_id = f"finding:{hashlib.md5(json.dumps(finding).encode()).hexdigest()[:12]}"
        
        self.graph.add_node(finding_id,
                           node_type="finding",
                           timestamp=datetime.now().isoformat(),
                           **finding)
        
        # Connect to affected host/endpoint
        if 'target' in finding:
            target_id = f"target:{finding['target']}"
            if target_id in self.graph:
                self.graph.add_edge(finding_id, target_id, relationship="affects")
        
        # Connect to vulnerability type
        if 'type' in finding:
            vuln_type = finding['type'].replace(' ', '_').lower()
            vuln_id = f"vulntype:{vuln_type}"
            self.graph.add_node(vuln_id, node_type="vulnerability_type", name=finding['type'])
            self.graph.add_edge(finding_id, vuln_id, relationship="is_type")
        
        return finding_id
    
    def get_critical_count(self) -> int:
        """Count critical findings."""
        count = 0
        for node, data in self.graph.nodes(data=True):
            if data.get('node_type') == 'finding':
                if data.get('severity', '').lower() == 'critical':
                    count += 1
        return count
    
    def get_recent_findings(self, limit: int = 10) -> List[dict]:
        """Get most recent findings."""
        findings = []
        for node, data in self.graph.nodes(data=True):
            if data.get('node_type') == 'finding':
                findings.append(data)
        
        # Sort by timestamp
        findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return findings[:limit]
    
    def get_target_summary(self, target_domain: str) -> dict:
        """Get summary for a target."""
        summary = {
            'domain': target_domain,
            'hosts': 0,
            'vulnerabilities': 0,
            'critical': 0,
            'technologies': set(),
            'last_scan': None
        }
        
        target_id = f"target:{target_domain}"
        if target_id not in self.graph:
            return summary
        
        # Find connected nodes
        for node in nx.descendants(self.graph, target_id):
            data = self.graph.nodes[node]
            if data.get('node_type') == 'host':
                summary['hosts'] += 1
            elif data.get('node_type') == 'finding':
                summary['vulnerabilities'] += 1
                if data.get('severity') == 'critical':
                    summary['critical'] += 1
                # Update last scan time
                timestamp = data.get('timestamp')
                if timestamp and (not summary['last_scan'] or timestamp > summary['last_scan']):
                    summary['last_scan'] = timestamp
            elif data.get('node_type') == 'technology':
                summary['technologies'].add(data.get('name', ''))
        
        summary['technologies'] = list(summary['technologies'])
        return summary
    
    def get_statistics(self) -> dict:
        """Get overall statistics."""
        stats = {
            'nodes': self.graph.number_of_nodes(),
            'edges': self.graph.number_of_edges(),
            'hosts': 0,
            'endpoints': 0,
            'vulns': 0,
            'ai_bypasses': 0
        }
        
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('node_type', '')
            if node_type == 'host':
                stats['hosts'] += 1
            elif node_type == 'endpoint':
                stats['endpoints'] += 1
            elif node_type == 'finding':
                stats['vulns'] += 1
                if data.get('ai_bypass', False):
                    stats['ai_bypasses'] += 1
        
        return stats
    
    async def persist(self):
        """Persist graph to disk."""
        # Convert to dict for serialization
        data = nx.node_link_data(self.graph)
        with open('data/knowledge_graph.json', 'w') as f:
            json.dump(data, f, indent=2)
    
    async def load(self):
        """Load graph from disk."""
        try:
            with open('data/knowledge_graph.json', 'r') as f:
                data = json.load(f)
            self.graph = nx.node_link_graph(data)
        except FileNotFoundError:
            pass