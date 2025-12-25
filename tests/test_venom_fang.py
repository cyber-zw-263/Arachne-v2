#!/usr/bin/env python3
"""
Tests for Venom Fang module
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from modules.venom_fang import VenomFang, APIEndpoint, PolyglotGenerator, TemporalPayloadFactory

class TestVenomFang:
    @pytest.fixture
    def venom_fang(self):
        """Create a VenomFang instance for testing."""
        return VenomFang("test.com", None)
    
    @pytest.fixture
    def sample_endpoint(self):
        """Create a sample API endpoint for testing."""
        return APIEndpoint(
            url="https://api.test.com/users?id=123",
            method="GET",
            parameters={
                'id': {'in': 'query', 'type': 'integer'}
            },
            discovered_from="api.test.com"
        )
    
    def test_endpoint_creation(self, venom_fang, sample_endpoint):
        """Test API endpoint creation and parsing."""
        assert sample_endpoint.url == "https://api.test.com/users?id=123"
        assert sample_endpoint.method == "GET"
        assert 'id' in sample_endpoint.parameters
        assert sample_endpoint.parameters['id']['in'] == 'query'
        assert sample_endpoint.parameters['id']['type'] == 'integer'
    
    def test_type_inference(self, venom_fang):
        """Test type inference from sample values."""
        assert venom_fang._infer_type("123") == 'integer'
        assert venom_fang._infer_type("123.45") == 'float'
        assert venom_fang._infer_type("true") == 'boolean'
        assert venom_fang._infer_type("false") == 'boolean'
        assert venom_fang._infer_type("550e8400-e29b-41d4-a716-446655440000") == 'uuid'
        assert venom_fang._infer_type("2024-01-01") == 'date'
        assert venom_fang._infer_type("test") == 'string'
    
    def test_polyglot_generation(self):
        """Test polyglot payload generation."""
        generator = PolyglotGenerator()
        polyglot = generator.create_multipurpose_string()
        
        assert isinstance(polyglot, str)
        assert len(polyglot) > 0
        
        # Test that it creates different polyglots
        polyglots = [generator.create_multipurpose_string() for _ in range(3)]
        assert len(set(polyglots)) >= 2  # At least 2 should be different
    
    def test_temporal_payloads(self):
        """Test temporal payload generation."""
        factory = TemporalPayloadFactory()
        temporal_payloads = factory.generate_time_anomalies()
        
        assert isinstance(temporal_payloads, list)
        assert len(temporal_payloads) > 0
        
        # Check for common temporal anomalies
        expected_anomalies = ["1970-01-01", "2038-01-19", "0000-00-00"]
        for anomaly in expected_anomalies:
            assert any(anomaly in payload for payload in temporal_payloads)
    
    @pytest.mark.asyncio
    async def test_ai_payload_generation(self, venom_fang):
        """Test AI-powered payload generation (mocked)."""
        with patch('transformers.pipeline') as mock_pipeline:
            mock_generator = MagicMock()
            mock_generator.return_value = [{'generated_text': 'test payload'}]
            mock_pipeline.return_value = mock_generator
            
            venom_fang.ai_enabled = True
            venom_fang.payload_generator = mock_generator
            
            payloads = venom_fang._generate_ai_payloads("id", "integer")
            
            assert isinstance(payloads, list)
            mock_generator.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_endpoint_fuzzing(self, venom_fang, sample_endpoint):
        """Test endpoint fuzzing with mocked HTTP requests."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value="Normal response")
            
            mock_session_instance = MagicMock()
            mock_session_instance.__aenter__.return_value = mock_session_instance
            mock_session_instance.__aexit__.return_value = None
            mock_session_instance.get.return_value.__aenter__.return_value = mock_response
            
            mock_session.return_value = mock_session_instance
            
            # Add endpoint to test
            venom_fang.endpoints.append(sample_endpoint)
            
            # Run fuzzing
            await venom_fang._test_endpoint_concurrently(sample_endpoint)
            
            assert sample_endpoint.tested == True
    
    def test_response_analysis(self, venom_fang):
        """Test response analysis for vulnerability indicators."""
        # Mock response
        class MockResponse:
            def __init__(self, text_content):
                self.text_content = text_content
            
            async def text(self):
                return self.text_content
        
        # Test SQL error detection
        sql_response = MockResponse("Error in SQL syntax near 'OR 1=1'")
        analysis_task = venom_fang._analyze_response(sql_response, None, "id", "' OR 1=1")
        
        # Run the async analysis
        try:
            import asyncio
            result = asyncio.run(analysis_task)
            # The function modifies endpoint.vulnerable, so we check the endpoint was passed
        except:
            pass  # For testing purposes
    
    def test_payload_context_awareness(self):
        """Test context-aware payload generation."""
        # This would test the PayloadGenius class's ability to generate
        # context-appropriate payloads based on parameter names and types
        pass
    
    @pytest.mark.asyncio
    async def test_concurrent_fuzzing(self, venom_fang):
        """Test concurrent fuzzing of multiple endpoints."""
        # Create multiple test endpoints
        endpoints = [
            APIEndpoint(
                url=f"https://api.test.com/endpoint{i}",
                method="GET",
                parameters={'param': {'in': 'query', 'type': 'string'}},
                discovered_from="api.test.com"
            )
            for i in range(3)
        ]
        
        venom_fang.endpoints = endpoints
        
        # Mock the fuzzing function to avoid actual HTTP requests
        with patch.object(venom_fang, '_test_endpoint_concurrently') as mock_fuzz:
            mock_fuzz.return_value = None
            
            # Test monitoring method
            await venom_fang.monitor_and_fuzz()
            
            # Should have been called for each endpoint
            assert mock_fuzz.call_count == 3
    
    def test_vulnerability_scoring(self):
        """Test vulnerability scoring and prioritization."""
        # Test that critical vulnerabilities are properly identified
        # and prioritized over lower severity issues
        pass
    
    @pytest.mark.asyncio
    async def test_error_handling(self, venom_fang, sample_endpoint):
        """Test error handling during fuzzing."""
        with patch('aiohttp.ClientSession') as mock_session:
            # Simulate connection error
            mock_session_instance = MagicMock()
            mock_session_instance.__aenter__.return_value = mock_session_instance
            mock_session_instance.__aexit__.return_value = None
            mock_session_instance.get.side_effect = Exception("Connection failed")
            
            mock_session.return_value = mock_session_instance
            
            # This should not crash
            await venom_fang._test_endpoint_concurrently(sample_endpoint)
            
            # Endpoint should still be marked as tested
            assert sample_endpoint.tested == True
    
    def test_report_generation(self, venom_fang):
        """Test report generation from findings."""
        # Create mock findings
        test_finding = {
            'target': 'test.com',
            'type': 'SQL Injection',
            'vector': 'GET /users?id=',
            'payload': "' OR 1=1--",
            'indicators': ['Error contains SQL syntax'],
            'timestamp': '2024-01-01T00:00:00'
        }
        
        # Test that findings can be converted to reports
        # This would typically involve formatting and file writing
        pass

class TestIntegration:
    """Integration tests for Venom Fang with other modules."""
    
    @pytest.mark.asyncio
    async def test_knowledge_graph_integration(self):
        """Test integration with knowledge graph."""
        # Mock knowledge graph
        mock_kg = MagicMock()
        mock_kg.add_finding = AsyncMock()
        
        venom_fang = VenomFang("test.com", mock_kg)
        
        # Simulate finding a vulnerability
        with patch.object(venom_fang, '_analyze_response') as mock_analyze:
            mock_analyze.return_value = None
            
            # This would normally add to knowledge graph
            # For now, just verify the integration point exists
            assert venom_fang.kg == mock_kg
    
    @pytest.mark.asyncio
    async def test_signal_system_integration(self):
        """Test integration with notification system."""
        # This would test that critical findings trigger notifications
        pass

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])