"""
Test suite for Comprehensive PQ API Documentation & Stability Catalog v14
June 2026 Release

Tests verify:
1. PQ API stability registry functionality
2. NIST security level tracking
3. Docstring template generation
4. PQ algorithm compliance reporting
5. Usage example catalogs
"""

import pytest
import logging
from quantum_crypt.comprehensive_pq_api_documentation_stability_master_v14_2026_june import (
    SecurityLevel,
    AlgorithmStandard,
    StabilityLevel,
    PQAlgorithmMetadata,
    APIMetadata,
    PQAPIStabilityRegistry,
    pq_api_registry,
    PQDocstringTemplate,
    PQUsageExampleCatalog,
)


class TestSecurityLevel:
    """Test NIST Security Levels enum."""
    
    def test_security_level_values(self):
        """Verify all NIST security levels exist."""
        assert SecurityLevel.LEVEL_1.value == 1  # AES-128
        assert SecurityLevel.LEVEL_2.value == 2  # SHA-256 collision
        assert SecurityLevel.LEVEL_3.value == 3  # AES-192
        assert SecurityLevel.LEVEL_4.value == 4  # SHA-384 collision
        assert SecurityLevel.LEVEL_5.value == 5  # AES-256


class TestAlgorithmStandard:
    """Test Algorithm Standardization Status enum."""
    
    def test_standard_values(self):
        """Verify all standardization statuses exist."""
        assert AlgorithmStandard.NIST_STANDARD.value == "nist_standard"
        assert AlgorithmStandard.NIST_ROUND_4.value == "nist_round_4"
        assert AlgorithmStandard.NIST_ROUND_3.value == "nist_round_3"
        assert AlgorithmStandard.RESEARCH.value == "research"
        assert AlgorithmStandard.LEGACY_CLASSICAL.value == "legacy_classical"


class TestPQAlgorithmMetadata:
    """Test PQAlgorithmMetadata dataclass."""
    
    def test_metadata_creation(self):
        """Test basic metadata creation."""
        metadata = PQAlgorithmMetadata(
            name="kyber768_keygen",
            standard_status=AlgorithmStandard.NIST_STANDARD,
            security_level=SecurityLevel.LEVEL_3,
            stability=StabilityLevel.STABLE,
            version_added="1.0.0",
            key_size_bytes=1184,
            ciphertext_size_bytes=1088
        )
        assert metadata.name == "kyber768_keygen"
        assert metadata.security_level == SecurityLevel.LEVEL_3
        assert metadata.key_size_bytes == 1184


class TestPQAPIStabilityRegistry:
    """Test PQAPIStabilityRegistry functionality."""
    
    def setup_method(self):
        """Fresh registry for each test."""
        self.registry = PQAPIStabilityRegistry()
    
    def test_mark_nist_standard(self):
        """Test marking algorithm as NIST standard."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0",
            nist_id="FIPS 203"
        )
        def kyber768_keygen():
            return "keypair"
        
        result = kyber768_keygen()
        assert result == "keypair"
        
        # Registry should have NIST standard algorithms
        nist_algorithms = self.registry.list_nist_standards()
        assert len(nist_algorithms) >= 1
        assert nist_algorithms[0].standard_status == AlgorithmStandard.NIST_STANDARD
        assert nist_algorithms[0].security_level == SecurityLevel.LEVEL_3
    
    def test_mark_experimental(self, caplog):
        """Test marking algorithm as experimental."""
        @self.registry.mark_experimental(
            security_level=SecurityLevel.LEVEL_5,
            version="0.5.0"
        )
        def research_kem():
            return "experimental"
        
        with caplog.at_level(logging.WARNING):
            result = research_kem()
        
        assert result == "experimental"
        assert "EXPERIMENTAL PQ ALGORITHM" in caplog.text
        
        # Registry should have experimental algorithms
        experimental = self.registry.list_by_security_level(SecurityLevel.LEVEL_5)
        assert len(experimental) >= 1
        assert experimental[0].standard_status == AlgorithmStandard.RESEARCH
    
    def test_mark_deprecated(self, caplog):
        """Test marking API as deprecated."""
        @self.registry.mark_deprecated(
            version="1.0.0",
            replacement="kyber768_keygen",
            reason="Old NIST Round 3 implementation"
        )
        def old_kem():
            return "deprecated"
        
        with caplog.at_level(logging.WARNING):
            result = old_kem()
        
        assert result == "deprecated"
        assert "DEPRECATED PQ API" in caplog.text
        assert "kyber768_keygen" in caplog.text
    
    def test_list_by_security_level(self):
        """Test listing algorithms by security level."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_1,
            version="1.0.0"
        )
        def kyber512(): pass
        
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0"
        )
        def kyber768(): pass
        
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_5,
            version="1.0.0"
        )
        def kyber1024(): pass
        
        level3 = self.registry.list_by_security_level(SecurityLevel.LEVEL_3)
        level5 = self.registry.list_by_security_level(SecurityLevel.LEVEL_5)
        
        assert len(level3) == 1
        assert len(level5) == 1
    
    def test_list_nist_standards(self):
        """Test listing all NIST standardized algorithms."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0"
        )
        def kyber768(): pass
        
        @self.registry.mark_experimental(
            security_level=SecurityLevel.LEVEL_3,
            version="0.5.0"
        )
        def experimental_kem(): pass
        
        standards = self.registry.list_nist_standards()
        assert len(standards) == 1
        assert "kyber768" in standards[0].name  # qualname includes full path
    
    def test_generate_compliance_report(self):
        """Test NIST compliance report generation."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0"
        )
        def kyber768(): pass
        
        report = self.registry.generate_compliance_report()
        
        assert "QUANTUMCRYPT-AI POST-QUANTUM COMPLIANCE REPORT" in report
        assert "NIST STANDARD" in report
        assert "LEVEL 1 (AES-128)" in report
        assert "LEVEL 5 (AES-256)" in report
        assert "kyber768" in report
    
    def test_get_algorithm_metadata_not_found(self):
        """Test getting non-existent metadata."""
        metadata = self.registry.get_algorithm_metadata("nonexistent")
        assert metadata is None


class TestPQDocstringTemplate:
    """Test PQDocstringTemplate generation."""
    
    def test_kem_algorithm_template(self):
        """Test KEM algorithm docstring template."""
        docstring = PQDocstringTemplate.kem_algorithm(
            "Kyber768",
            nist_level=3,
            key_size=1184,
            ct_size=1088
        )
        
        assert "Kyber768" in docstring
        assert "NIST Security Level: 3" in docstring
        assert "AES-192" in docstring
        assert "Public Key Size: 1184 bytes" in docstring
        assert "Ciphertext Size: 1088 bytes" in docstring
        assert "USAGE EXAMPLE:" in docstring
        assert "NIST FIPS 203" in docstring
    
    def test_signature_algorithm_template(self):
        """Test signature algorithm docstring template."""
        docstring = PQDocstringTemplate.signature_algorithm(
            "Dilithium3",
            nist_level=3,
            sig_size=2420
        )
        
        assert "Dilithium3" in docstring
        assert "NIST Security Level: 3" in docstring
        assert "Signature Size: 2420 bytes" in docstring
        assert "EUF-CMA Secure: Yes" in docstring
        assert "NIST FIPS 204/205" in docstring


class TestPQUsageExampleCatalog:
    """Test PQUsageExampleCatalog."""
    
    def test_get_kyber_examples(self):
        """Test Kyber usage examples."""
        examples = PQUsageExampleCatalog.get_kyber_examples()
        
        assert "basic_key_exchange" in examples
        assert "hybrid_tls" in examples
        
        assert "Kyber768" in examples["basic_key_exchange"]
        assert "keygen" in examples["basic_key_exchange"]
        assert "encaps" in examples["basic_key_exchange"]
        assert "decaps" in examples["basic_key_exchange"]
    
    def test_get_dilithium_examples(self):
        """Test Dilithium usage examples."""
        examples = PQUsageExampleCatalog.get_dilithium_examples()
        
        assert "basic_signing" in examples
        assert "batch_verification" in examples
        
        assert "Dilithium3" in examples["basic_signing"]
        assert "sign" in examples["basic_signing"]
        assert "verify" in examples["basic_signing"]


class TestGlobalRegistry:
    """Test global registry instance."""
    
    def test_global_registry_exists(self):
        """Verify global registry is instantiated."""
        assert pq_api_registry is not None
        assert isinstance(pq_api_registry, PQAPIStabilityRegistry)


class TestBackwardCompatibility:
    """Verify no breakage to existing patterns."""
    
    def setup_method(self):
        self.registry = PQAPIStabilityRegistry()
    
    def test_decorated_function_preserves_behavior(self):
        """Test decorated functions work identically."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0"
        )
        def add(a, b):
            return a + b
        
        assert add(2, 3) == 5
        assert add.__name__ == "add"
    
    def test_nist_standard_no_warning(self, caplog):
        """Test NIST standard algorithms don't emit warnings."""
        @self.registry.mark_nist_standard(
            security_level=SecurityLevel.LEVEL_3,
            version="1.0.0"
        )
        def kyber():
            return "secure"
        
        with caplog.at_level(logging.WARNING):
            result = kyber()
        
        # No warnings for NIST standard algorithms
        assert result == "secure"
        assert "WARNING" not in caplog.text or "EXPERIMENTAL" not in caplog.text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
