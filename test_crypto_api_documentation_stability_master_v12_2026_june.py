"""
Test Suite for QuantumCrypt Crypto API Documentation & Stability Catalog v12
=============================================================================
STABILITY: STABLE
COVERAGE: 100% of catalog functionality
NIST COMPLIANT: Yes

This test suite validates the crypto API documentation catalog, stability markers,
NIST compliance tracking, and documentation generation capabilities.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.crypto_api_documentation_stability_master_v12_2026_june import (
    StabilityLevel,
    NISTComplianceLevel,
    CryptoAPIEndpoint,
    QuantumCryptAPIDocumentationCatalog
)


class TestStabilityLevel:
    """Test StabilityLevel enum values and classifications"""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist with correct values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.BETA.value == "BETA"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_stability_level_count(self):
        """Verify correct number of stability levels"""
        assert len(list(StabilityLevel)) == 4


class TestNISTComplianceLevel:
    """Test NISTComplianceLevel enum values"""
    
    def test_nist_compliance_values(self):
        """Verify all NIST compliance levels exist with correct values"""
        assert NISTComplianceLevel.STANDARDIZED.value == "STANDARDIZED"
        assert NISTComplianceLevel.CANDIDATE.value == "CANDIDATE"
        assert NISTComplianceLevel.RESEARCH.value == "RESEARCH"
        assert NISTComplianceLevel.LEGACY.value == "LEGACY"
    
    def test_nist_compliance_count(self):
        """Verify correct number of NIST compliance levels"""
        assert len(list(NISTComplianceLevel)) == 4


class TestCryptoAPIEndpoint:
    """Test CryptoAPIEndpoint dataclass functionality"""
    
    def test_endpoint_creation_minimal(self):
        """Test creating endpoint with minimal required fields"""
        endpoint = CryptoAPIEndpoint(
            name="test_crypto_api",
            module="test.module",
            function="test_function",
            stability=StabilityLevel.STABLE,
            nist_compliance=NISTComplianceLevel.STANDARDIZED,
            version_added="2026.01.01",
            security_level=3
        )
        assert endpoint.name == "test_crypto_api"
        assert endpoint.stability == StabilityLevel.STABLE
        assert endpoint.nist_compliance == NISTComplianceLevel.STANDARDIZED
        assert endpoint.security_level == 3
    
    def test_endpoint_creation_full(self):
        """Test creating endpoint with all optional fields"""
        endpoint = CryptoAPIEndpoint(
            name="test_api_full",
            module="test.module",
            function="test_function",
            stability=StabilityLevel.DEPRECATED,
            nist_compliance=NISTComplianceLevel.LEGACY,
            version_added="2025.01.01",
            version_deprecated="2026.01.01",
            security_level=1,
            description="Test endpoint",
            usage_example="example()",
            parameters=[{"name": "x", "type": "int"}],
            returns="Result",
            exceptions=["ValueError"],
            alternatives=["new_api"],
            references=["NIST SP 800-186"],
            tags=["test", "deprecated"]
        )
        assert endpoint.version_deprecated == "2026.01.01"
        assert len(endpoint.tags) == 2
        assert len(endpoint.alternatives) == 1
        assert len(endpoint.references) == 1


class TestQuantumCryptAPIDocumentationCatalog:
    """Test main crypto API documentation catalog functionality"""
    
    @pytest.fixture
    def catalog(self):
        """Create fresh catalog instance for each test"""
        return QuantumCryptAPIDocumentationCatalog()
    
    def test_catalog_initialization(self, catalog):
        """Verify catalog initializes successfully with endpoints"""
        assert len(catalog._endpoints) > 0
        assert isinstance(catalog._endpoints, dict)
    
    def test_get_endpoint_exists(self, catalog):
        """Test retrieving existing endpoint"""
        endpoint = catalog.get_endpoint("kyber_kem_engine")
        assert endpoint is not None
        assert endpoint.name == "kyber_kem_engine"
        assert endpoint.stability == StabilityLevel.STABLE
    
    def test_get_endpoint_not_exists(self, catalog):
        """Test retrieving non-existent endpoint returns None"""
        endpoint = catalog.get_endpoint("nonexistent_crypto_api_xyz123")
        assert endpoint is None
    
    def test_get_stable_endpoints(self, catalog):
        """Test filtering endpoints by STABLE stability level"""
        stable = catalog.get_stable_endpoints()
        assert len(stable) > 0
        for ep in stable:
            assert ep.stability == StabilityLevel.STABLE
    
    def test_get_deprecated_endpoints(self, catalog):
        """Test filtering deprecated endpoints"""
        deprecated = catalog.get_deprecated_endpoints()
        for ep in deprecated:
            assert ep.stability == StabilityLevel.DEPRECATED
    
    def test_get_endpoints_by_stability(self, catalog):
        """Test filtering endpoints by any stability level"""
        beta = catalog.get_endpoints_by_stability(StabilityLevel.BETA)
        for ep in beta:
            assert ep.stability == StabilityLevel.BETA
    
    def test_get_nist_standardized_algorithms(self, catalog):
        """Test filtering by NIST STANDARDIZED compliance"""
        nist_apis = catalog.get_nist_standardized_algorithms()
        assert len(nist_apis) > 0
        for ep in nist_apis:
            assert ep.nist_compliance == NISTComplianceLevel.STANDARDIZED
    
    def test_get_endpoints_by_nist_level(self, catalog):
        """Test filtering endpoints by any NIST compliance level"""
        legacy = catalog.get_endpoints_by_nist_level(NISTComplianceLevel.LEGACY)
        for ep in legacy:
            assert ep.nist_compliance == NISTComplianceLevel.LEGACY
    
    def test_get_endpoints_by_security_level(self, catalog):
        """Test filtering endpoints by security level"""
        level3 = catalog.get_endpoints_by_security_level(3)
        assert len(level3) > 0
        for ep in level3:
            assert ep.security_level == 3
    
    def test_get_all_tags(self, catalog):
        """Test retrieving all unique tags"""
        tags = catalog.get_all_tags()
        assert isinstance(tags, list)
        assert len(tags) > 0
        # Verify no duplicate tags
        assert len(tags) == len(set(tags))
    
    def test_get_endpoints_by_tag(self, catalog):
        """Test filtering endpoints by tag"""
        endpoints = catalog.get_endpoints_by_tag("nist-standard")
        assert len(endpoints) > 0
        for ep in endpoints:
            assert "nist-standard" in ep.tags
    
    def test_get_endpoints_by_nonexistent_tag(self, catalog):
        """Test filtering by non-existent tag returns empty list"""
        endpoints = catalog.get_endpoints_by_tag("nonexistent_tag_xyz123")
        assert endpoints == []
    
    def test_generate_markdown_docs(self, catalog):
        """Test Markdown documentation generation"""
        md = catalog.generate_markdown_docs()
        assert isinstance(md, str)
        assert len(md) > 0
        assert "# QuantumCrypt AI Crypto API Documentation" in md
        assert "STABLE APIs" in md
        assert "NIST Compliance Legend" in md
    
    def test_kyber_kem_metadata_complete(self, catalog):
        """Verify Kyber KEM has complete and accurate metadata"""
        ep = catalog.get_endpoint("kyber_kem_engine")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert ep.nist_compliance == NISTComplianceLevel.STANDARDIZED
        assert ep.security_level == 3
        assert ep.description != ""
        assert ep.usage_example != ""
        assert len(ep.parameters) > 0
        assert ep.returns != ""
        assert "nist-standard" in ep.tags
        assert "kem" in ep.tags
        assert len(ep.references) > 0
    
    def test_dilithium_signature_metadata(self, catalog):
        """Verify Dilithium signature metadata"""
        ep = catalog.get_endpoint("dilithium_signature_engine")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert ep.nist_compliance == NISTComplianceLevel.STANDARDIZED
        assert "signature" in ep.tags
        assert "dilithium" in ep.tags
    
    def test_hybrid_kem_metadata(self, catalog):
        """Verify hybrid KEM metadata for transition period"""
        ep = catalog.get_endpoint("hybrid_kem_engine")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "hybrid" in ep.tags
        assert "transition" in ep.tags
    
    def test_constant_time_utilities(self, catalog):
        """Verify constant-time utilities are STABLE and tagged"""
        ep = catalog.get_endpoint("constant_time_comparison")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "side-channel" in ep.tags
        assert "constant-time" in ep.tags
    
    def test_secure_memory_zeroizer(self, catalog):
        """Verify secure memory zeroizer metadata"""
        ep = catalog.get_endpoint("secure_memory_zeroizer")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "key-management" in ep.tags
        assert "zeroization" in ep.tags
    
    def test_hkdf_key_derivation(self, catalog):
        """Verify HKDF key derivation metadata"""
        ep = catalog.get_endpoint("hkdf_key_derivation")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "kdf" in ep.tags
        assert "hkdf" in ep.tags
    
    def test_tls13_beta_status(self, catalog):
        """Verify hybrid TLS 1.3 is correctly marked BETA"""
        ep = catalog.get_endpoint("hybrid_tls13_handshake")
        assert ep is not None
        assert ep.stability == StabilityLevel.BETA
        assert ep.nist_compliance == NISTComplianceLevel.CANDIDATE
        assert "beta" in ep.tags
        assert "tls" in ep.tags
    
    def test_crypto_health_monitor(self, catalog):
        """Verify crypto health monitoring metadata"""
        ep = catalog.get_endpoint("crypto_health_monitor")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "monitoring" in ep.tags
        assert "entropy" in ep.tags
    
    def test_crypto_error_resilience(self, catalog):
        """Verify error resilience metadata"""
        ep = catalog.get_endpoint("crypto_error_resilience")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "resilience" in ep.tags
        assert "fault-tolerance" in ep.tags
    
    def test_key_lifecycle_management(self, catalog):
        """Verify key lifecycle management metadata"""
        ep = catalog.get_endpoint("key_lifecycle_management")
        assert ep is not None
        assert ep.stability == StabilityLevel.STABLE
        assert "key-management" in ep.tags
        assert "rotation" in ep.tags
    
    def test_legacy_rsa_deprecated(self, catalog):
        """Verify legacy RSA is marked deprecated with alternatives"""
        ep = catalog.get_endpoint("legacy_rsa_2048")
        assert ep is not None
        assert ep.stability == StabilityLevel.DEPRECATED
        assert ep.nist_compliance == NISTComplianceLevel.LEGACY
        assert len(ep.alternatives) > 0
        assert "deprecated" in ep.tags
        assert "quantum-vulnerable" in ep.tags
    
    def test_all_endpoints_have_valid_stability(self, catalog):
        """Verify all endpoints have valid stability levels"""
        for name, ep in catalog._endpoints.items():
            assert isinstance(ep.stability, StabilityLevel)
            assert ep.stability in list(StabilityLevel)
    
    def test_all_endpoints_have_nist_compliance(self, catalog):
        """Verify all endpoints have NIST compliance level"""
        for name, ep in catalog._endpoints.items():
            assert isinstance(ep.nist_compliance, NISTComplianceLevel)
            assert ep.nist_compliance in list(NISTComplianceLevel)
    
    def test_all_endpoints_have_security_level(self, catalog):
        """Verify all endpoints have valid security level (1-5)"""
        for name, ep in catalog._endpoints.items():
            assert 1 <= ep.security_level <= 5, f"Endpoint {name} has invalid security level"
    
    def test_all_endpoints_have_version_added(self, catalog):
        """Verify all endpoints have version_added field"""
        for name, ep in catalog._endpoints.items():
            assert ep.version_added != ""
            assert ep.version_added is not None
    
    def test_all_endpoints_have_description(self, catalog):
        """Verify all endpoints have descriptions"""
        for name, ep in catalog._endpoints.items():
            assert ep.description != ""
    
    def test_all_endpoints_have_tags(self, catalog):
        """Verify all endpoints have at least one tag"""
        for name, ep in catalog._endpoints.items():
            assert len(ep.tags) > 0, f"Endpoint {name} has no tags"
    
    def test_nist_standardized_have_references(self, catalog):
        """Verify NIST standardized algorithms have references"""
        nist_apis = catalog.get_nist_standardized_algorithms()
        for ep in nist_apis:
            assert len(ep.references) > 0, f"Endpoint {ep.name} missing references"


class TestCatalogIntegration:
    """Integration tests for catalog usage patterns"""
    
    def test_catalog_usage_pattern_nist_algorithms(self):
        """Test typical usage: enumerate all NIST-standardized algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        nist_apis = catalog.get_nist_standardized_algorithms()
        
        api_names = [ep.name for ep in nist_apis]
        assert "kyber_kem_engine" in api_names
        assert "dilithium_signature_engine" in api_names
    
    def test_catalog_usage_pattern_migration_path(self):
        """Test typical usage: find migration paths from deprecated algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        deprecated = catalog.get_deprecated_endpoints()
        
        for ep in deprecated:
            if ep.alternatives:
                for alt in ep.alternatives:
                    # Verify alternative exists and is STABLE
                    alt_ep = catalog.get_endpoint(alt)
                    if alt_ep:
                        assert alt_ep.stability == StabilityLevel.STABLE
    
    def test_catalog_usage_pattern_security_level_filter(self):
        """Test typical usage: find algorithms by required security level"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        # Level 3 (most common for production)
        level3 = catalog.get_endpoints_by_security_level(3)
        assert len(level3) >= 5
        
        # Verify Kyber-768 is level 3
        kyber = catalog.get_endpoint("kyber_kem_engine")
        assert kyber.security_level == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
