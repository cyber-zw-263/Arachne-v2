"""
Quantum-inspired optimization for vulnerability discovery.
Uses simulated annealing and quantum algorithms to optimize attack paths.
"""

import numpy as np
import random
from typing import List, Dict, Tuple
import networkx as nx

class QuantumAnnealer:
    def __init__(self, knowledge_graph):
        self.kg = knowledge_graph
        self.temperature = 1.0
        self.cooling_rate = 0.995
        
    def find_optimal_attack_path(self, target_node: str) -> List[str]:
        """
        Find the optimal attack path using quantum-inspired simulated annealing.
        Considers: exploit difficulty, detection risk, access gained.
        """
        # Convert knowledge graph to problem space
        graph = self.kg.graph
        
        # Initialize random path
        current_path = self._random_path_to_target(target_node)
        current_energy = self._calculate_path_energy(current_path)
        
        best_path = current_path[:]
        best_energy = current_energy
        
        # Annealing process
        while self.temperature > 0.01:
            # Generate neighbor (quantum tunnel possibility)
            if random.random() < 0.1:  # Quantum tunneling probability
                neighbor_path = self._quantum_tunnel(current_path, target_node)
            else:
                neighbor_path = self._mutate_path(current_path)
            
            neighbor_energy = self._calculate_path_energy(neighbor_path)
            
            # Acceptance probability (Metropolis criterion with quantum adjustment)
            delta_energy = neighbor_energy - current_energy
            acceptance_prob = np.exp(-delta_energy / self.temperature)
            
            # Quantum fluctuation: sometimes accept worse solutions
            if random.random() < acceptance_prob or random.random() < 0.05:
                current_path = neighbor_path
                current_energy = neighbor_energy
                
                if current_energy < best_energy:
                    best_path = current_path[:]
                    best_energy = current_energy
            
            # Cool down
            self.temperature *= self.cooling_rate
        
        return best_path
    
    def _calculate_path_energy(self, path: List[str]) -> float:
        """Calculate 'energy' (cost) of an attack path. Lower is better."""
        energy = 0.0
        
        for i in range(len(path) - 1):
            node_a = path[i]
            node_b = path[i + 1]
            
            # Get edge data
            edge_data = self.kg.graph.get_edge_data(node_a, node_b, {})
            
            # Factors:
            # 1. Exploit difficulty (from knowledge graph)
            difficulty = edge_data.get('difficulty', 0.5)
            
            # 2. Detection risk
            risk = edge_data.get('detection_risk', 0.3)
            
            # 3. Access gained (inverse)
            access_gained = edge_data.get('access_gained', 0.1)
            
            # Quantum-inspired weighting
            energy += (difficulty * 0.6 + risk * 0.3 - access_gained * 0.1)
        
        return energy
    
    def _quantum_tunnel(self, path: List[str], target: str) -> List[str]:
        """Quantum tunneling: jump to a seemingly disconnected but potentially better state."""
        # Find all nodes in graph
        all_nodes = list(self.kg.graph.nodes())
        
        # Randomly insert a node that might connect indirectly
        if len(path) > 2:
            insert_pos = random.randint(1, len(path) - 2)
            
            # Find a node that connects to both neighbors (directly or through 2 hops)
            candidates = []
            for node in all_nodes:
                if (nx.has_path(self.kg.graph, path[insert_pos - 1], node) and
                    nx.has_path(self.kg.graph, node, path[insert_pos + 1])):
                    candidates.append(node)
            
            if candidates:
                new_node = random.choice(candidates)
                # Find shortest path through new node
                try:
                    path1 = nx.shortest_path(self.kg.graph, path[insert_pos - 1], new_node)
                    path2 = nx.shortest_path(self.kg.graph, new_node, path[insert_pos + 1])
                    new_segment = path1[:-1] + path2  # Avoid duplicate node
                    return path[:insert_pos - 1] + new_segment + path[insert_pos + 2:]
                except:
                    pass
        
        return path
    
    def suggest_next_target(self) -> Dict:
        """
        Use quantum annealing to suggest the next most promising target
        based on current knowledge graph state.
        """
        # Find all unfinished targets
        targets = []
        for node, data in self.kg.graph.nodes(data=True):
            if data.get('node_type') == 'target':
                # Calculate target attractiveness
                attractiveness = self._calculate_target_attractiveness(node)
                targets.append((node, attractiveness))
        
        # Sort by attractiveness (quantum-weighted)
        targets.sort(key=lambda x: x[1], reverse=True)
        
        if targets:
            target_id = targets[0][0]
            target_name = target_id.replace('target:', '')
            
            # Find optimal attack path
            attack_path = self.find_optimal_attack_path(target_id)
            
            return {
                'target': target_name,
                'confidence': targets[0][1],
                'recommended_path': attack_path,
                'estimated_time': len(attack_path) * 15,  # minutes
                'potential_impact': self._estimate_impact(target_id)
            }
        
        return {}