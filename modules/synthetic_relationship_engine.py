#!/usr/bin/env python3
"""
SYNTHETIC RELATIONSHIP ENGINE
Creates AI-generated personas and social networks for advanced social engineering attacks.
"""

import random
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from pathlib import Path

try:
    from faker import Faker
    FAKER_AVAILABLE = True
except ImportError:
    FAKER_AVAILABLE = False

@dataclass
class SyntheticPersona:
    id: str
    first_name: str
    last_name: str
    email: str
    username: str
    password: str
    birth_date: str
    location: str
    job_title: str
    company: str
    interests: List[str]
    social_connections: List[str] = field(default_factory=list)
    activity_history: List[Dict] = field(default_factory=list)
    profile_picture_hash: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class SocialConnection:
    persona_a: str
    persona_b: str
    connection_type: str  # 'friend', 'colleague', 'family', 'acquaintance'
    strength: float  # 0.0 to 1.0
    established_date: str

class SyntheticRelationshipEngine:
    def __init__(self, knowledge_graph=None):
        self.kg = knowledge_graph
        self.personas: Dict[str, SyntheticPersona] = {}
        self.connections: List[SocialConnection] = []
        self.faker = Faker() if FAKER_AVAILABLE else None
        
        # Predefined interests and job titles
        self.interests_pool = [
            'technology', 'cybersecurity', 'programming', 'AI/ML',
            'gaming', 'music', 'photography', 'travel', 'cooking',
            'fitness', 'reading', 'movies', 'hiking', 'coding',
            'data science', 'blockchain', 'devops', 'cloud computing'
        ]
        
        self.job_titles = [
            'Security Engineer', 'DevOps Specialist', 'Software Developer',
            'Data Scientist', 'Cloud Architect', 'Network Administrator',
            'Penetration Tester', 'Security Analyst', 'IT Manager',
            'System Administrator', 'Database Administrator', 'Web Developer',
            'Machine Learning Engineer', 'Blockchain Developer', 'CTO',
            'Security Consultant', 'Incident Responder', 'Threat Hunter'
        ]
        
        self.companies = [
            'TechCorp', 'SecureSystems', 'DataFlow', 'CloudNine',
            'CyberShield', 'InnovateTech', 'FutureSystems', 'DigitalFortress',
            'QuantumSecurity', 'NexusTech', 'AlphaSolutions', 'BetaSystems'
        ]
    
    def generate_persona(self, seed: Optional[str] = None) -> SyntheticPersona:
        """Generate a synthetic persona with consistent attributes."""
        if seed:
            random.seed(seed)
        
        if self.faker:
            first_name = self.faker.first_name()
            last_name = self.faker.last_name()
            location = self.faker.city()
        else:
            # Fallback if Faker is not available
            first_names = ['Alex', 'Jordan', 'Taylor', 'Casey', 'Riley', 'Morgan', 'Cameron', 'Drew']
            last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis']
            locations = ['New York', 'San Francisco', 'London', 'Berlin', 'Tokyo', 'Singapore', 'Sydney']
            
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            location = random.choice(locations)
        
        # Generate consistent ID
        base_string = f"{first_name}{last_name}{location}{datetime.now().timestamp()}"
        persona_id = hashlib.md5(base_string.encode()).hexdigest()[:12]
        
        # Generate email
        email_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com']
        email = f"{first_name.lower()}.{last_name.lower()}{random.randint(10, 99)}@{random.choice(email_domains)}"
        
        # Generate username
        username = f"{first_name[0].lower()}{last_name.lower()}{random.randint(100, 999)}"
        
        # Generate password (simulated - in real use, these would be more sophisticated)
        password = self._generate_realistic_password()
        
        # Generate birth date (age 25-45)
        birth_year = random.randint(1978, 1998)
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)
        birth_date = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"
        
        # Select job and company
        job_title = random.choice(self.job_titles)
        company = random.choice(self.companies)
        
        # Select interests (3-5 random interests)
        num_interests = random.randint(3, 5)
        interests = random.sample(self.interests_pool, num_interests)
        
        # Create persona
        persona = SyntheticPersona(
            id=persona_id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
            password=password,
            birth_date=birth_date,
            location=location,
            job_title=job_title,
            company=company,
            interests=interests
        )
        
        # Generate profile picture hash (simulated)
        persona.profile_picture_hash = hashlib.md5(persona.email.encode()).hexdigest()[:16]
        
        # Generate initial activity
        self._generate_initial_activity(persona)
        
        self.personas[persona_id] = persona
        return persona
    
    def _generate_realistic_password(self) -> str:
        """Generate a realistic-looking password."""
        patterns = [
            # Common patterns
            lambda: f"{random.choice(['P@ssw0rd', 'Welcome', 'Summer'])}{random.randint(10, 99)}!",
            lambda: f"{random.choice(['Secure', 'My', 'New'])}{random.choice(['Pass', 'Key', 'Lock'])}{random.randint(100, 999)}",
            lambda: f"{random.choice(['ilove', 'ilike', 'ihate'])}{random.choice(['coding', 'tech', 'security'])}{random.randint(1, 9)}",
            lambda: f"{random.choice(['@', '#', '$'])}{random.choice(['admin', 'root', 'user'])}{random.randint(2020, 2025)}",
            # More secure looking
            lambda: ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=2)) +
                   ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=4)) +
                   ''.join(random.choices('0123456789', k=2)) +
                   random.choice(['!', '@', '#', '$']),
        ]
        
        return random.choice(patterns)()
    
    def _generate_initial_activity(self, persona: SyntheticPersona):
        """Generate initial activity history for a persona."""
        activity_types = [
            'account_created',
            'profile_updated',
            'post_created',
            'connection_made',
            'liked_post',
            'commented',
            'shared_link'
        ]
        
        # Generate 5-10 initial activities
        num_activities = random.randint(5, 10)
        
        for i in range(num_activities):
            days_ago = random.randint(0, 30)
            activity_date = (datetime.now() - timedelta(days=days_ago)).isoformat()
            
            activity_type = random.choice(activity_types)
            
            if activity_type == 'post_created':
                content = random.choice([
                    f"Working on some exciting {random.choice(persona.interests)} projects at {persona.company}!",
                    f"Just finished reading a great book about {random.choice(['security', 'AI', 'cloud computing'])}",
                    f"Attended an amazing conference on {random.choice(persona.interests)}",
                    f"Learning {random.choice(['Python', 'Go', 'Rust'])} for {random.choice(['security', 'automation', 'data analysis'])}"
                ])
            elif activity_type == 'commented':
                content = "Great post! Thanks for sharing."
            else:
                content = ""
            
            activity = {
                'type': activity_type,
                'timestamp': activity_date,
                'content': content,
                'visibility': random.choice(['public', 'friends', 'connections'])
            }
            
            persona.activity_history.append(activity)
    
    def create_social_network(self, num_personas: int = 10) -> List[SyntheticPersona]:
        """Create a network of synthetic personas with connections."""
        personas = []
        
        # Generate personas
        for i in range(num_personas):
            seed = f"persona_{i}_{datetime.now().timestamp()}"
            persona = self.generate_persona(seed)
            personas.append(persona)
        
        # Create connections between personas
        for i, persona_a in enumerate(personas):
            # Each persona connects to 3-7 other personas
            num_connections = random.randint(3, min(7, num_personas - 1))
            
            # Select random other personas to connect to
            possible_connections = [p for p in personas if p.id != persona_a.id]
            connections = random.sample(possible_connections, min(num_connections, len(possible_connections)))
            
            for persona_b in connections:
                # Determine connection type based on similarity
                similarity = self._calculate_persona_similarity(persona_a, persona_b)
                
                if similarity > 0.7:
                    connection_type = random.choice(['friend', 'colleague'])
                elif similarity > 0.4:
                    connection_type = 'colleague'
                else:
                    connection_type = 'acquaintance'
                
                # Create connection
                connection = SocialConnection(
                    persona_a=persona_a.id,
                    persona_b=persona_b.id,
                    connection_type=connection_type,
                    strength=similarity,
                    established_date=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat()
                )
                
                self.connections.append(connection)
                
                # Add to persona's connections
                persona_a.social_connections.append(persona_b.id)
                persona_b.social_connections.append(persona_a.id)
        
        return personas
    
    def _calculate_persona_similarity(self, persona_a: SyntheticPersona, persona_b: SyntheticPersona) -> float:
        """Calculate similarity between two personas (0.0 to 1.0)."""
        similarity_score = 0.0
        
        # Same location
        if persona_a.location == persona_b.location:
            similarity_score += 0.2
        
        # Same company
        if persona_a.company == persona_b.company:
            similarity_score += 0.3
        
        # Common interests
        common_interests = set(persona_a.interests) & set(persona_b.interests)
        if common_interests:
            similarity_score += len(common_interests) * 0.1
        
        # Similar job titles
        if any(word in persona_a.job_title.lower() and word in persona_b.job_title.lower() 
               for word in ['security', 'engineer', 'developer', 'admin', 'analyst']):
            similarity_score += 0.2
        
        return min(similarity_score, 1.0)
    
    def generate_targeted_persona(self, target_domain: str, role: str = "employee") -> SyntheticPersona:
        """Generate a persona targeted for a specific domain/company."""
        # Extract company name from domain
        company_name = target_domain.split('.')[0].title()
        
        # Generate base persona
        persona = self.generate_persona(f"target_{target_domain}")
        
        # Customize for target
        persona.company = company_name
        persona.email = f"{persona.first_name.lower()}.{persona.last_name.lower()}@{target_domain}"
        
        if role == "employee":
            persona.job_title = random.choice([
                f"Security Engineer at {company_name}",
                f"DevOps Specialist at {company_name}",
                f"System Administrator at {company_name}",
                f"IT Manager at {company_name}"
            ])
            persona.interests.extend(['corporate security', 'enterprise IT', 'business technology'])
        
        elif role == "executive":
            persona.job_title = random.choice([
                f"CTO at {company_name}",
                f"Security Director at {company_name}",
                f"Head of IT at {company_name}"
            ])
            persona.interests.extend(['leadership', 'management', 'business strategy'])
        
        # Add domain-specific interests
        if 'tech' in target_domain or 'software' in target_domain:
            persona.interests.extend(['software development', 'agile', 'devops'])
        
        if 'bank' in target_domain or 'finance' in target_domain:
            persona.interests.extend(['fintech', 'banking security', 'financial technology'])
        
        return persona
    
    def simulate_social_interaction(self, 
                                   persona_id: str, 
                                   target_persona_id: str,
                                   interaction_type: str = "connection_request") -> Dict:
        """Simulate a social interaction between personas."""
        if persona_id not in self.personas or target_persona_id not in self.personas:
            return {"error": "Persona not found"}
        
        persona = self.personas[persona_id]
        target = self.personas[target_persona_id]
        
        interaction = {
            'from': persona_id,
            'to': target_persona_id,
            'type': interaction_type,
            'timestamp': datetime.now().isoformat(),
            'success_probability': 0.0,
            'message': ''
        }
        
        # Calculate success probability
        similarity = self._calculate_persona_similarity(persona, target)
        
        if interaction_type == "connection_request":
            # Check if already connected
            if target_persona_id in persona.social_connections:
                interaction['success_probability'] = 1.0  # Already connected
                interaction['message'] = "Already connected"
            else:
                # Higher similarity = higher chance of acceptance
                base_chance = 0.3
                similarity_bonus = similarity * 0.4
                common_connections = len(set(persona.social_connections) & set(target.social_connections))
                connection_bonus = common_connections * 0.1
                
                interaction['success_probability'] = min(base_chance + similarity_bonus + connection_bonus, 0.9)
                interaction['message'] = f"Hi {target.first_name}, we have {common_connections} mutual connections. Would you like to connect?"
        
        elif interaction_type == "message":
            if target_persona_id in persona.social_connections:
                # Already connected, higher chance of response
                interaction['success_probability'] = 0.8
                interaction['message'] = f"Hey {target.first_name}, saw your post about {random.choice(target.interests)}. What are your thoughts on the latest developments?"
            else:
                # Not connected, lower chance
                interaction['success_probability'] = 0.2
                interaction['message'] = f"Hi {target.first_name}, I noticed we both work in {random.choice(target.interests)}. Would love to connect!"
        
        # Simulate the interaction outcome
        interaction['success'] = random.random() < interaction['success_probability']
        
        if interaction['success'] and interaction_type == "connection_request":
            # Add connection
            persona.social_connections.append(target_persona_id)
            target.social_connections.append(persona_id)
            
            # Create connection record
            connection = SocialConnection(
                persona_a=persona_id,
                persona_b=target_persona_id,
                connection_type='acquaintance',
                strength=similarity,
                established_date=datetime.now().isoformat()
            )
            self.connections.append(connection)
        
        return interaction
    
    def export_personas(self, format: str = "json") -> str:
        """Export personas to specified format."""
        if format == "json":
            data = {
                'personas': {pid: self._persona_to_dict(p) for pid, p in self.personas.items()},
                'connections': [self._connection_to_dict(c) for c in self.connections],
                'generated_at': datetime.now().isoformat(),
                'total_personas': len(self.personas),
                'total_connections': len(self.connections)
            }
            return json.dumps(data, indent=2)
        
        elif format == "csv":
            # Simple CSV export
            lines = ["id,first_name,last_name,email,username,company,job_title,location,interests,connections"]
            for persona in self.personas.values():
                interests_str = ';'.join(persona.interests)
                connections_str = ';'.join(persona.social_connections)
                lines.append(f"{persona.id},{persona.first_name},{persona.last_name},{persona.email},"
                           f"{persona.username},{persona.company},{persona.job_title},"
                           f"{persona.location},{interests_str},{connections_str}")
            return "\n".join(lines)
        
        return ""
    
    def _persona_to_dict(self, persona: SyntheticPersona) -> Dict:
        """Convert persona to dictionary."""
        return {
            'id': persona.id,
            'first_name': persona.first_name,
            'last_name': persona.last_name,
            'email': persona.email,
            'username': persona.username,
            'job_title': persona.job_title,
            'company': persona.company,
            'location': persona.location,
            'interests': persona.interests,
            'social_connections': persona.social_connections,
            'profile_picture_hash': persona.profile_picture_hash,
            'created_at': persona.created_at
        }
    
    def _connection_to_dict(self, connection: SocialConnection) -> Dict:
        """Convert connection to dictionary."""
        return {
            'persona_a': connection.persona_a,
            'persona_b': connection.persona_b,
            'type': connection.connection_type,
            'strength': connection.strength,
            'established_date': connection.established_date
        }
    
    def generate_report(self) -> str:
        """Generate a report on the synthetic network."""
        report_lines = [
            "# Synthetic Relationship Network Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\n## Network Statistics",
            f"Total personas: {len(self.personas)}",
            f"Total connections: {len(self.connections)}",
            f"Average connections per persona: {len(self.connections) * 2 / len(self.personas) if self.personas else 0:.1f}",
        ]
        
        if self.personas:
            # Connection type distribution
            connection_types = {}
            for conn in self.connections:
                connection_types[conn.connection_type] = connection_types.get(conn.connection_type, 0) + 1
            
            report_lines.append("\n## Connection Types")
            for conn_type, count in connection_types.items():
                percentage = count / len(self.connections) * 100
                report_lines.append(f"- {conn_type}: {count} ({percentage:.1f}%)")
            
            # Top personas by connections
            report_lines.append("\n## Most Connected Personas")
            sorted_personas = sorted(self.personas.values(), 
                                   key=lambda p: len(p.social_connections), 
                                   reverse=True)[:5]
            
            for i, persona in enumerate(sorted_personas, 1):
                report_lines.append(f"{i}. {persona.first_name} {persona.last_name}")
                report_lines.append(f"   Connections: {len(persona.social_connections)}")
                report_lines.append(f"   Company: {persona.company}")
                report_lines.append(f"   Job: {persona.job_title}")
        
        return "\n".join(report_lines)

# Example usage
def main():
    engine = SyntheticRelationshipEngine()
    
    # Create a small network
    print("Generating synthetic network...")
    personas = engine.create_social_network(num_personas=8)
    
    print(f"Created {len(personas)} personas")
    print(f"Created {len(engine.connections)} connections")
    
    # Generate a targeted persona
    target_persona = engine.generate_targeted_persona("acmecorp.com", role="employee")
    print(f"\nTargeted persona for acmecorp.com:")
    print(f"  Name: {target_persona.first_name} {target_persona.last_name}")
    print(f"  Email: {target_persona.email}")
    print(f"  Job: {target_persona.job_title}")
    print(f"  Interests: {', '.join(target_persona.interests[:3])}...")
    
    # Simulate an interaction
    if len(personas) >= 2:
        interaction = engine.simulate_social_interaction(
            persona_id=target_persona.id,
            target_persona_id=personas[0].id,
            interaction_type="connection_request"
        )
        
        print(f"\nSimulated interaction:")
        print(f"  Type: {interaction['type']}")
        print(f"  Message: {interaction['message']}")
        print(f"  Success probability: {interaction['success_probability']:.1%}")
        print(f"  Actual success: {interaction['success']}")
    
    # Generate report
    report = engine.generate_report()
    print(f"\n{report}")
    
    # Export data
    json_data = engine.export_personas("json")
    print(f"\nExported {len(json_data)} bytes of JSON data")

if __name__ == "__main__":
    main()


# Backwards compatibility: core imports `SyntheticPersonaEngine`
SyntheticPersonaEngine = SyntheticRelationshipEngine