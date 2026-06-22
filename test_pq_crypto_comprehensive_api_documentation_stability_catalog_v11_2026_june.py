"""
Test Suite for Post-Quantum Crypto Comprehensive API Documentation & Stability Catalog v11
Tests verify cryptography catalog functionality without modifying production code.
"""

import pytest
import json
from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v11_2026_june import (
    CryptoDocumentationCatalog,
    StabilityLevel,
    NISTStatus,
    CryptoAPIEndpoint,
    get_crypto_catalog,
    is_quantum_safe
)


class TestStabilityLevel:
    """Tests for StabilityLevel enum."""
    
    def test_stability_level_values(self):
        """Verify stability level enum values are correct."""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"


class TestNISTStatus:
    """Tests for NISTStatus enum."""
    
    def test_nist_status_values(self):
        """Verify NIST status enum values."""
        assert NISTStatus.STANDARDIZED.value == "STANDARDIZED"
        assert NISTStatus.ROUND_4.value == "ROUND_4"
        assert NISTStatus.ROUND_3.value == "ROUND_3"
        assert NISTStatus.CANDIDATE.value == "CANDIDATE"
        assert NISTStatus.RESEARCH.value == "RESEARCH"


class TestCryptoAPIEndpoint:
    """Tests for CryptoAPIEndpoint dataclass."""
    
    def test_api_endpoint_creation_minimal(self):
        """Test creating endpoint with minimal fields."""
        endpoint = CryptoAPIEndpoint(
            name="Test Crypto API",
            function_path="test.module.function",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="TEST-ALG",
            version_added="1.0.0",
            description="Test description"
        )
        assert endpoint.name == "Test Crypto API"
        assert endpoint.security_level == 1  # default
    
    def test_api_endpoint_with_security_level(self):
        """Test endpoint with explicit security level."""
        endpoint = CryptoAPIEndpoint(
            name="High Security API",
            function_path="test.high.security",
            stability=StabilityLevel.STABLE,
            nist_status=NISTStatus.STANDARDIZED,
            algorithm="HIGH-SEC",
            version_added="2.0.0",
            description="Level 5 security algorithm",
            security_level=5
        )
        assert endpoint.security_level == 5


class TestCryptoDocumentationCatalog:
    """Tests for CryptoDocumentationCatalog class."""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly."""
        catalog = CryptoDocumentationCatalog()
        assert catalog._catalog_version == "11.0.0"
        assert len(catalog._apis) > 0
    
    def test_get_stability_existing(self):
        """Test getting stability for registered crypto API."""
        catalog = CryptoDocumentationCatalog()
        stability = catalog.get_stability(
            "quantum_crypt.post_quantum_kyber_kem_engine.encapsulate"
        )
        assert stability == StabilityLevel.STABLE
    
    def test_get_nist_status(self):
        """Test getting NIST status for algorithm."""
        catalog = CryptoDocumentationCatalog()
        status = catalog.get_nist_status(
            "quantum_crypt.post_quantum_kyber_kem_engine.encapsulate"
        )
        assert status == NISTStatus.STANDARDIZED
    
    def test_get_quantum_safe_apis(self):
        """Test filtering for quantum-safe APIs only."""
        catalog = CryptoDocumentationCatalog()
        safe_apis = catalog.get_quantum_safe_apis()
        
        for api in safe_apis:
            assert api.stability in (StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL)
            assert api.stability not in (StabilityLevel.LEGACY, StabilityLevel.DEPRECATED)
    
    def test_list_by_security_level(self):
        """Test filtering by minimum NIST security level."""
        catalog = CryptoDocumentationCatalog()
        level5 = catalog.list_by_security_level(5)
        level3 = catalog.list_by_security_level(3)
        
        # Level 5 should be subset of level 3
        assert len(level5) <= len(level3)
        for api in level5:
            assert api.security_level >= 5
    
    def test_kyber_is_standardized(self):
        """Verify Kyber is marked as NIST standardized."""
        catalog = CryptoDocumentationCatalog()
        api = catalog._apis.get(
            catalog._make_key("quantum_crypt.post_quantum_kyber_kem_engine.encapsulate")
        )
        assert api is not None
        assert api.nist_status == NISTStatus.STANDARDIZED
        assert "FIPS 203" in api.compliance_notes
    
    def test_dilithium_is_standardized(self):
        """Verify Dilithium is marked as NIST standardized."""
        catalog = CryptoDocumentationCatalog()
        api = catalog._apis.get(
            catalog._make_key("quantum_crypt.post_quantum_dilithium_signature_engine.sign")
        )
        assert api is not None
        assert api.nist_status == NISTStatus.STANDARDIZED
        assert "FIPS 204" in api.compliance_notes
    
    def test_legacy_algorithms_identified(self):
        """Verify classical algorithms are marked LEGACY."""
        catalog = CryptoDocumentationCatalog()
        api = catalog._apis.get(
            catalog._make_key("quantum_crypt.classical.rsa_encrypt")
        )
        assert api is not None
        assert api.stability == StabilityLevel.LEGACY
        assert "quantum" in api.migration_guide.lower()
    
    def test_generate_compliance_report(self):
        """Test compliance report generation."""
        catalog = CryptoDocumentationCatalog()
        report = catalog.generate_compliance_report()
        parsed = json.loads(report)
        
        assert "nist_standardized" in parsed
        assert "quantum_safe_count" in parsed
        assert "at_risk_legacy_count" in parsed
        assert "recommendation" in parsed
        assert "2028" in parsed["recommendation"]
    
    def test_catalog_hash_consistency(self):
        """Test catalog hash is consistent."""
        cat1 = CryptoDocumentationCatalog()
        cat2 = CryptoDocumentationCatalog()
        
        hash1 = cat1.get_catalog_hash()
        hash2 = cat2.get_catalog_hash()
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256


class TestGlobalFunctions:
    """Tests for module-level helper functions."""
    
    def test_get_crypto_catalog_singleton(self):
        """Test singleton pattern."""
        cat1 = get_crypto_catalog()
        cat2 = get_crypto_catalog()
        assert cat1 is cat2
    
    def test_is_quantum_safe_for_stable(self):
        """Test quantum-safe check for stable PQ algorithms."""
        result = is_quantum_safe(
            "quantum_crypt.post_quantum_kyber_kem_engine.encapsulate"
        )
        assert result is True
    
    def test_is_quantum_safe_for_experimental(self):
        """Test quantum-safe check for experimental PQ algorithms."""
        result = is_quantum_safe(
            "quantum_crypt.post_quantum_falcon_signature_engine.sign"
        )
        assert result is True
    
    def test_is_quantum_safe_for_legacy(self):
        """Test quantum-safe check returns False for legacy."""
        result = is_quantum_safe("quantum_crypt.classical.rsa_encrypt")
        assert result is False


class TestCatalogIntegrity:
    """Tests for catalog data integrity."""
    
    def test_all_apis_have_nist_status(self):
        """Verify every crypto API has NIST status."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            assert api.nist_status is not None
    
    def test_all_apis_have_algorithm_name(self):
        """Verify every API has algorithm identifier."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            assert len(api.algorithm) > 0
    
    def test_security_level_range(self):
        """Verify security levels are in valid range 1-5."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            assert 1 <= api.security_level <= 5
    
    def test_deprecated_have_migration(self):
        """Verify deprecated APIs have migration guidance."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            if api.stability == StabilityLevel.DEPRECATED:
                assert len(api.migration_guide) > 0
    
    def test_legacy_have_migration(self):
        """Verify LEGACY classical algorithms include quantum migration guides."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            if api.stability == StabilityLevel.LEGACY:
                assert len(api.migration_guide) > 0
                assert "quantum" in api.migration_guide.lower()
    
    def test_standardized_have_compliance_notes(self):
        """Verify NIST-standardized algorithms have compliance info."""
        catalog = CryptoDocumentationCatalog()
        for api in catalog._apis.values():
            if api.nist_status == NISTStatus.STANDARDIZED:
                assert len(api.compliance_notes) > 0


class TestEdgeCases:
    """Edge case tests."""
    
    def test_is_quantum_safe_nonexistent(self):
        """Test quantum-safe check for non-existent API."""
        result = is_quantum_safe("completely.fake.algorithm")
        assert result is False
    
    def test_get_stability_nonexistent(self):
        """Test stability for non-existent API."""
        catalog = CryptoDocumentationCatalog()
        result = catalog.get_stability("fake.api.path")
        assert result is None
    
    def test_get_nist_status_nonexistent(self):
        """Test NIST status for non-existent API."""
        catalog = CryptoDocumentationCatalog()
        result = catalog.get_nist_status("fake.api.path")
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
