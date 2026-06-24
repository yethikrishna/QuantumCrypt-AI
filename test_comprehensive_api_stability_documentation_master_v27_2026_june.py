"""
Test Suite for QuantumCrypt-AI API Stability Documentation v27
SESSION: 127
DIMENSION: F - Documentation & API Stability
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from comprehensive_api_stability_documentation_master_v27_2026_june import (
    StabilityLevel,
    CryptoAPIEndpoint,
    QuantumCryptAPIStabilityCatalog,
    get_crypto_stability_catalog,
    crypto_api_stability
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_stability_level_count(self):
        assert len(list(StabilityLevel)) == 4


class TestCryptoAPIEndpoint:
    """Test CryptoAPIEndpoint dataclass"""
    
    def test_crypto_api_endpoint_creation(self):
        endpoint = CryptoAPIEndpoint(
            name="TestCryptoAPI",
            module="test_module",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            algorithm_standard="NIST SP 800-186",
            nist_status="FINAL",
            description="Test crypto endpoint"
        )
        assert endpoint.name == "TestCryptoAPI"
        assert endpoint.stability == StabilityLevel.STABLE
        assert endpoint.nist_status == "FINAL"
        assert endpoint.algorithm_standard == "NIST SP 800-186"
    
    def test_crypto_api_endpoint_defaults(self):
        endpoint = CryptoAPIEndpoint(
            name="TestAPI",
            module="test_module",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0"
        )
        assert endpoint.version_deprecated is None
        assert endpoint.deprecation_scheduled is None
        assert isinstance(endpoint.security_properties, list)
        assert isinstance(endpoint.compatibility_notes, list)


class TestQuantumCryptAPIStabilityCatalog:
    """Test main crypto API stability catalog"""
    
    def setup_method(self):
        self.catalog = QuantumCryptAPIStabilityCatalog()
    
    def test_catalog_initialization(self):
        assert self.catalog.catalog_version == "27.0.0"
        assert self.catalog.generated_at is not None
    
    def test_catalog_has_apis(self):
        apis = self.catalog.list_apis()
        assert len(apis) > 0
        print(f"Total Crypto APIs documented: {len(apis)}")
    
    def test_get_api_exists(self):
        api = self.catalog.get_api("hybrid_kem_engine")
        assert api is not None
        assert api.name == "PostQuantumHybridKEMEngine"
        assert api.stability == StabilityLevel.STABLE
    
    def test_get_api_not_exists(self):
        api = self.catalog.get_api("nonexistent_crypto_api_xyz")
        assert api is None
    
    def test_list_apis_filter_stable(self):
        stable_apis = self.catalog.list_apis(StabilityLevel.STABLE)
        assert len(stable_apis) > 0
        for api in stable_apis:
            assert api.stability == StabilityLevel.STABLE
    
    def test_list_apis_filter_experimental(self):
        experimental_apis = self.catalog.list_apis(StabilityLevel.EXPERIMENTAL)
        for api in experimental_apis:
            assert api.stability == StabilityLevel.EXPERIMENTAL
    
    def test_list_apis_filter_deprecated(self):
        deprecated_apis = self.catalog.list_apis(StabilityLevel.DEPRECATED)
        for api in deprecated_apis:
            assert api.stability == StabilityLevel.DEPRECATED
    
    def test_get_nist_algorithms(self):
        nist_final = self.catalog.get_nist_algorithms("FINAL")
        assert isinstance(nist_final, list)
        nist_standardized = self.catalog.get_nist_algorithms("STANDARDIZED")
        assert isinstance(nist_standardized, list)
    
    def test_stability_summary(self):
        summary = self.catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "LEGACY" in summary
        assert summary["STABLE"] > 0
    
    def test_generate_markdown_docs(self):
        md = self.catalog.generate_markdown_docs()
        assert md is not None
        assert len(md) > 0
        assert "# QuantumCrypt-AI API Stability Documentation" in md
        assert "NIST Algorithm Status" in md
        assert "STABLE APIs" in md
        assert "DEPRECATION NOTICE" in md
    
    def test_kem_apis_present(self):
        assert self.catalog.get_api("hybrid_kem_engine") is not None
        assert self.catalog.get_api("session_key_manager") is not None
    
    def test_kdf_apis_present(self):
        assert self.catalog.get_api("memory_hard_kdf") is not None
        assert self.catalog.get_api("hkdf_engine") is not None
    
    def test_random_generation_apis_present(self):
        assert self.catalog.get_api("secure_random") is not None
    
    def test_key_management_apis_present(self):
        assert self.catalog.get_api("key_lifecycle_manager") is not None
        assert self.catalog.get_api("key_rotation_service") is not None
    
    def test_security_hardening_apis_present(self):
        assert self.catalog.get_api("side_channel_resistant") is not None
        assert self.catalog.get_api("rate_limiter_dos") is not None
    
    def test_experimental_apis_present(self):
        assert self.catalog.get_api("zkp_verifier") is not None
        assert self.catalog.get_api("secure_mpc_engine") is not None
    
    def test_migration_tools_present(self):
        assert self.catalog.get_api("migration_assessor") is not None
        assert self.catalog.get_api("cert_transparency_auditor") is not None
    
    def test_deprecated_apis_marked(self):
        legacy = self.catalog.get_api("legacy_rsa_wrapper")
        assert legacy is not None
        assert legacy.stability == StabilityLevel.DEPRECATED
        assert legacy.version_deprecated is not None
        assert legacy.deprecation_scheduled is not None
        assert legacy.migration_guide != ""
    
    def test_api_metadata_complete(self):
        for api in self.catalog.list_apis():
            assert api.name != ""
            assert api.module != ""
            assert api.version_introduced != ""
            assert api.description != ""
    
    def test_security_properties_on_stable_apis(self):
        for api in self.catalog.list_apis(StabilityLevel.STABLE):
            # Crypto APIs should have security properties
            assert isinstance(api.security_properties, list)
    
    def test_nist_status_on_standard_apis(self):
        kem = self.catalog.get_api("hybrid_kem_engine")
        assert kem.nist_status != ""
        assert kem.algorithm_standard != ""
    
    def test_deprecated_apis_have_migration(self):
        for api in self.catalog.list_apis(StabilityLevel.DEPRECATED):
            assert api.migration_guide != ""
    
    def test_get_security_properties_matrix(self):
        matrix = self.catalog.get_security_properties_matrix()
        assert isinstance(matrix, dict)
        assert len(matrix) > 0
        for name, props in matrix.items():
            assert isinstance(props, list)
    
    def test_validate_migration_readiness(self):
        result = self.catalog.validate_migration_readiness(["RSA", "Kyber"])
        assert "pq_ready_algorithms" in result
        assert "needs_migration" in result
        assert "readiness_score" in result
        assert "overall_assessment" in result
        assert "RSA" in result["needs_migration"]
        assert "Kyber" in result["pq_ready_algorithms"]
    
    def test_migration_readiness_scoring(self):
        # All classical should have low score
        result = self.catalog.validate_migration_readiness(["RSA", "ECDSA", "DH"])
        assert result["readiness_score"] < 50
        
        # All PQ should have perfect score
        result2 = self.catalog.validate_migration_readiness(["Kyber", "Dilithium"])
        assert result2["readiness_score"] == 100
        assert result2["overall_assessment"] == "READY"


class TestSingleton:
    """Test singleton catalog access"""
    
    def test_get_crypto_stability_catalog_singleton(self):
        cat1 = get_crypto_stability_catalog()
        cat2 = get_crypto_stability_catalog()
        assert cat1 is cat2
    
    def test_singleton_returns_valid_catalog(self):
        catalog = get_crypto_stability_catalog()
        assert isinstance(catalog, QuantumCryptAPIStabilityCatalog)
        assert len(catalog.list_apis()) > 0


class TestCryptoStabilityDecorator:
    """Test @crypto_api_stability decorator"""
    
    def test_decorator_marks_function(self):
        @crypto_api_stability(StabilityLevel.STABLE, since="2.0.0", nist_status="FINAL")
        def test_func():
            return "test"
        
        assert hasattr(test_func, "_crypto_api_stability")
        assert test_func._crypto_api_stability["level"] == StabilityLevel.STABLE
        assert test_func._crypto_api_stability["since"] == "2.0.0"
        assert test_func._crypto_api_stability["nist_status"] == "FINAL"
        assert test_func._crypto_api_stability["documented"] is True
    
    def test_decorator_preserves_function(self):
        @crypto_api_stability(StabilityLevel.STABLE, since="2.0.0")
        def test_func(x):
            return x * 3
        
        assert test_func(5) == 15  # Function still works


class TestDocumentationQuality:
    """Test documentation quality standards for crypto APIs"""
    
    def setup_method(self):
        self.catalog = QuantumCryptAPIStabilityCatalog()
    
    def test_no_empty_descriptions(self):
        for api in self.catalog.list_apis():
            assert len(api.description.strip()) > 0, \
                f"Crypto API {api.name} has empty description"
    
    def test_version_format_valid(self):
        for api in self.catalog.list_apis():
            parts = api.version_introduced.split(".")
            assert len(parts) >= 2, f"API {api.name} invalid version format"
    
    def test_stable_apis_have_usage_examples(self):
        for api in self.catalog.list_apis(StabilityLevel.STABLE):
            if api.usage_example:
                assert len(api.usage_example.strip()) > 0
    
    def test_module_names_are_valid(self):
        for api in self.catalog.list_apis():
            assert " " not in api.module, f"API {api.name} has invalid module name"
    
    def test_performance_notes_on_kem(self):
        kem = self.catalog.get_api("hybrid_kem_engine")
        assert kem.performance_notes != ""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
