"""
Test Suite for Post-Quantum Crypto Policy Engine - QuantumCrypt-AI
June 2026 Production Release
Comprehensive tests for policy enforcement, compliance validation, and algorithm registry.
"""
import pytest
import json
import os
import tempfile
from pathlib import Path

from quantum_crypt.post_quantum_crypto_policy_engine_2026_june import (
    AlgorithmSecurityLevel,
    AlgorithmStatus,
    PolicySeverity,
    ComplianceStandard,
    AlgorithmRegistry,
    CryptoPolicy,
    PolicyEnforcer,
    CryptoPolicyEngine,
    create_standard_policy,
    create_high_security_policy,
    create_crypto_policy_engine,
)


class TestAlgorithmRegistry:
    """Tests for AlgorithmRegistry class"""
    
    def test_registry_initialization(self):
        """Test registry initializes with algorithms"""
        registry = AlgorithmRegistry()
        assert len(registry.algorithms) > 0
    
    def test_get_algorithm_info(self):
        """Test getting algorithm information"""
        registry = AlgorithmRegistry()
        info = registry.get_algorithm_info("CRYSTALS-Kyber")
        assert info is not None
        assert info.quantum_resistant is True
    
    def test_get_recommended_algorithms(self):
        """Test getting recommended algorithms"""
        registry = AlgorithmRegistry()
        recommended = registry.get_recommended_algorithms()
        assert len(recommended) > 0


class TestCryptoPolicy:
    """Tests for CryptoPolicy class"""
    
    def test_standard_policy(self):
        """Test standard production policy"""
        policy = create_standard_policy()
        assert policy.minimum_security_level == AlgorithmSecurityLevel.LEVEL_3
        assert policy.require_quantum_resistant is True
    
    def test_high_security_policy(self):
        """Test high security policy"""
        policy = create_high_security_policy()
        assert policy.minimum_security_level == AlgorithmSecurityLevel.LEVEL_5


class TestPolicyEnforcer:
    """Tests for PolicyEnforcer class"""
    
    def test_validate_recommended_algorithm(self):
        """Test validating a recommended algorithm"""
        enforcer = PolicyEnforcer()
        violations = enforcer.validate_algorithm("ML-KEM-768")
        assert len(violations) == 0  # No violations for recommended algorithm
    
    def test_validate_deprecated_algorithm(self):
        """Test validating a deprecated algorithm"""
        enforcer = PolicyEnforcer()
        violations = enforcer.validate_algorithm("RSA-2048")
        assert len(violations) > 0


class TestCryptoPolicyEngine:
    """Tests for main CryptoPolicyEngine class"""
    
    def test_engine_creation(self):
        """Test engine creation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CryptoPolicyEngine(reports_directory=tmpdir)
            assert engine.enforcer is not None
    
    def test_factory_function(self):
        """Test factory function"""
        engine = create_crypto_policy_engine("standard")
        assert isinstance(engine, CryptoPolicyEngine)
    
    def test_validate_usage(self):
        """Test usage validation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CryptoPolicyEngine(reports_directory=tmpdir)
            result = engine.validate_usage("ML-KEM-768")
            assert "compliant" in result
    
    def test_get_migration_guide(self):
        """Test getting migration guide"""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CryptoPolicyEngine(reports_directory=tmpdir)
            guide = engine.get_migration_guide()
            assert "recommendations" in guide
    
    def test_full_assessment(self):
        """Test running full policy assessment"""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CryptoPolicyEngine(reports_directory=tmpdir)
            assessment = engine.run_full_assessment()
            assert 0 <= assessment.overall_score <= 100


class TestIntegration:
    """Integration tests for complete policy engine workflow"""
    
    def test_complete_policy_workflow(self):
        """Test complete policy engine workflow"""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = CryptoPolicyEngine(reports_directory=tmpdir)
            
            # Validate several algorithms
            algorithms_to_check = [
                ("ML-KEM-768", 768, "key_exchange"),
                ("ML-DSA-65", 195, "signing"),
                ("RSA-2048", 2048, "legacy"),
            ]
            
            for algo, key_size, context in algorithms_to_check:
                result = engine.validate_usage(algo, key_size, context)
            
            # Run full assessment
            assessment = engine.run_full_assessment()
            assert assessment.overall_score > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
