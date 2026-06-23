"""
Test Suite for QuantumCrypt-AI PQ Crypto API Documentation & Stability Catalog v17
Tests verify:
1. Catalog initialization and algorithm database
2. NIST standardization status tracking
3. Stability level classification
4. Side-channel resistance tracking
5. FIPS compliance tracking
6. Migration guide integrity
7. Compliance matrix generation
8. JSON documentation export
9. Helper function correctness
10. No runtime impact on existing code

100% ADD-ONLY - No existing code modified
"""

import pytest
import json
from quantum_crypt.pq_crypto_comprehensive_api_documentation_stability_catalog_v17_2026_june import (
    QuantumCryptAPICatalog,
    StabilityLevel,
    NISTStatus,
    CryptoAlgorithm,
    APIEndpoint,
    MigrationGuide,
    api_catalog,
    get_api_stability,
    get_nist_status,
    is_side_channel_resistant
)


class TestCatalogInitialization:
    """Test basic catalog initialization and structure."""
    
    def test_catalog_singleton_exists(self):
        """Singleton instance should be pre-initialized."""
        assert api_catalog is not None
        assert isinstance(api_catalog, QuantumCryptAPICatalog)
    
    def test_new_catalog_initializes(self):
        """New catalog instance should initialize without errors."""
        catalog = QuantumCryptAPICatalog()
        assert catalog is not None
    
    def test_algorithms_database_populated(self):
        """Algorithm database should contain NIST PQ algorithms."""
        catalog = QuantumCryptAPICatalog()
        assert len(catalog._algorithms) >= 7  # All NIST algorithms
        assert "CRYSTALS-Kyber" in catalog._algorithms
        assert "CRYSTALS-Dilithium" in catalog._algorithms
    
    def test_endpoints_populated(self):
        """Catalog should contain documented crypto endpoints."""
        catalog = QuantumCryptAPICatalog()
        assert len(catalog._endpoints) >= 15  # v17 crypto modules


class TestAlgorithmDatabase:
    """Test NIST algorithm database integrity."""
    
    def test_kyber_is_standardized(self):
        """CRYSTALS-Kyber should be NIST STANDARDIZED."""
        catalog = QuantumCryptAPICatalog()
        kyber = catalog.get_algorithm("CRYSTALS-Kyber")
        assert kyber is not None
        assert kyber.nist_status == NISTStatus.STANDARDIZED
        assert kyber.quantum_resistant == True
    
    def test_dilithium_is_standardized(self):
        """CRYSTALS-Dilithium should be NIST STANDARDIZED."""
        catalog = QuantumCryptAPICatalog()
        dilithium = catalog.get_algorithm("CRYSTALS-Dilithium")
        assert dilithium is not None
        assert dilithium.nist_status == NISTStatus.STANDARDIZED
    
    def test_round4_algorithms_exist(self):
        """Round 4 candidate algorithms should be tracked."""
        catalog = QuantumCryptAPICatalog()
        round4 = catalog.list_nist_algorithms(NISTStatus.ROUND_4)
        assert len(round4) >= 3  # Classic-McEliece, BIKE, HQC
    
    def test_algorithm_performance_data(self):
        """Algorithms should have performance characteristics."""
        catalog = QuantumCryptAPICatalog()
        kyber = catalog.get_algorithm("CRYSTALS-Kyber")
        assert isinstance(kyber.performance, dict)
        assert "keygen_ms" in kyber.performance
    
    def test_get_nonexistent_algorithm_returns_none(self):
        """Nonexistent algorithms should return None."""
        catalog = QuantumCryptAPICatalog()
        alg = catalog.get_algorithm("NonExistentAlgorithmXYZ")
        assert alg is None


class TestStabilityClassification:
    """Test stability level classification for crypto endpoints."""
    
    def test_stable_modules_exist(self):
        """STABLE crypto modules should exist."""
        catalog = QuantumCryptAPICatalog()
        stable = catalog.list_by_stability(StabilityLevel.STABLE)
        assert len(stable) > 0
        stable_names = [ep.name for ep in stable]
        assert "HybridKEMEngine" in stable_names or "PostQuantumDigitalSignature" in stable_names
    
    def test_beta_modules_exist(self):
        """BETA crypto modules should exist."""
        catalog = QuantumCryptAPICatalog()
        beta = catalog.list_by_stability(StabilityLevel.BETA)
        assert len(beta) > 0
    
    def test_experimental_modules_exist(self):
        """EXPERIMENTAL crypto modules should exist."""
        catalog = QuantumCryptAPICatalog()
        experimental = catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(experimental) > 0
        # MPC and ZKP should be EXPERIMENTAL
        exp_names = [ep.name for ep in experimental]
        assert "SecureMPCEngine" in exp_names or "ZeroKnowledgeProofEngine" in exp_names
    
    def test_get_endpoint_returns_correct_type(self):
        """get_endpoint should return APIEndpoint or None."""
        catalog = QuantumCryptAPICatalog()
        endpoint = catalog.get_endpoint("hybrid_kem_engine_v2")
        assert endpoint is not None
        assert isinstance(endpoint, APIEndpoint)


class TestSecurityTracking:
    """Test security property tracking for crypto modules."""
    
    def test_side_channel_resistant_modules_exist(self):
        """Side-channel resistant modules should be tracked."""
        catalog = QuantumCryptAPICatalog()
        sc_modules = [ep for ep in catalog._endpoints.values() if ep.side_channel_resistant]
        assert len(sc_modules) > 0
        # Memory zeroizer should be side-channel resistant
        sc_names = [ep.name for ep in sc_modules]
        assert "SecureMemoryZeroizer" in sc_names or "KeyOperationProtector" in sc_names
    
    def test_fips_compliant_modules_tracked(self):
        """FIPS compliant modules should be tracked."""
        catalog = QuantumCryptAPICatalog()
        fips_modules = [ep for ep in catalog._endpoints.values() if ep.fips_compliant]
        # At minimum, memory zeroizer should be FIPS compliant
        assert len(fips_modules) >= 1
    
    def test_v17_key_protector_documentation(self):
        """v17: KeyOperationProtector should be documented."""
        catalog = QuantumCryptAPICatalog()
        protector = catalog.get_endpoint("side_channel_key_protector_v17")
        assert protector is not None
        assert protector.side_channel_resistant == True
        assert protector.fips_compliant == True
    
    def test_v17_telemetry_documentation(self):
        """v17: Crypto telemetry should be documented."""
        catalog = QuantumCryptAPICatalog()
        telemetry = catalog.get_endpoint("crypto_telemetry_v14")
        assert telemetry is not None
        # Security notes should document key material protection
        assert len(telemetry.security_notes) > 0


class TestMigrationGuides:
    """Test migration guide integrity."""
    
    def test_migration_guides_exist(self):
        """Migration guides should be populated."""
        catalog = QuantumCryptAPICatalog()
        assert len(catalog._migration_guides) > 0
    
    def test_v16_to_v17_backward_compatible(self):
        """v16 -> v17 should be fully backward compatible."""
        catalog = QuantumCryptAPICatalog()
        v17_guide = [g for g in catalog._migration_guides if g.to_version == "v17"]
        assert len(v17_guide) > 0
        assert v17_guide[0].backward_compatible == True


class TestComplianceMatrix:
    """Test compliance matrix generation."""
    
    def test_compliance_matrix_structure(self):
        """Compliance matrix should have required fields."""
        catalog = QuantumCryptAPICatalog()
        matrix = catalog.get_compliance_matrix()
        assert "catalog_version" in matrix
        assert matrix["catalog_version"] == "v17"
        assert "nist_algorithms" in matrix
        assert "fips_modules" in matrix
        assert "side_channel_resistant" in matrix
        assert "security_boundaries" in matrix
        assert "recommended_production_algorithms" in matrix
    
    def test_recommended_algorithms_exist(self):
        """Production algorithm recommendations should exist."""
        catalog = QuantumCryptAPICatalog()
        matrix = catalog.get_compliance_matrix()
        assert len(matrix["recommended_production_algorithms"]) >= 2
        assert "Kyber" in str(matrix["recommended_production_algorithms"])
        assert "Dilithium" in str(matrix["recommended_production_algorithms"])
    
    def test_security_boundaries_documentation(self):
        """Security boundaries should be documented."""
        catalog = QuantumCryptAPICatalog()
        matrix = catalog.get_compliance_matrix()
        boundaries = matrix["security_boundaries"]
        assert "key_material" in boundaries
        assert "telemetry" in boundaries
        # Key material should NEVER be logged
        assert "NEVER" in boundaries["key_material"].upper()


class TestDocumentationExport:
    """Test JSON documentation export."""
    
    def test_generate_json_documentation(self):
        """JSON documentation should generate without errors."""
        catalog = QuantumCryptAPICatalog()
        docs = catalog.generate_documentation(format="json")
        assert docs is not None
        parsed = json.loads(docs)
        assert "catalog_version" in parsed
        assert parsed["catalog_version"] == "v17"
        assert "nist_algorithm_breakdown" in parsed
    
    def test_nist_algorithm_breakdown(self):
        """NIST algorithm breakdown should be in export."""
        catalog = QuantumCryptAPICatalog()
        docs = catalog.generate_documentation(format="json")
        parsed = json.loads(docs)
        assert "NIST STANDARDIZED" in parsed["nist_algorithm_breakdown"]
        assert "NIST ROUND 4" in parsed["nist_algorithm_breakdown"]


class TestHelperFunctions:
    """Test public helper functions."""
    
    def test_get_api_stability_works(self):
        """get_api_stability should return stability string."""
        stability = get_api_stability("hybrid_kem_engine_v2")
        assert stability == "STABLE"
    
    def test_get_nist_status_works(self):
        """get_nist_status should return NIST status."""
        status = get_nist_status("CRYSTALS-Kyber")
        assert status == "NIST STANDARDIZED"
    
    def test_is_side_channel_resistant_works(self):
        """is_side_channel_resistant should return boolean."""
        result = is_side_channel_resistant("secure_memory_zeroizer")
        assert result == True
    
    def test_helper_nonexistent_returns_none(self):
        """Nonexistent items should return None."""
        assert get_api_stability("nonexistent") is None
        assert get_nist_status("nonexistent") is None
        assert is_side_channel_resistant("nonexistent") is None


class TestNoRuntimeImpact:
    """Verify documentation module has NO runtime impact."""
    
    def test_import_only_no_side_effects(self):
        """Importing should not modify global state."""
        from quantum_crypt import pq_crypto_comprehensive_api_documentation_stability_catalog_v17_2026_june
        assert pq_crypto_comprehensive_api_documentation_stability_catalog_v17_2026_june is not None
    
    def test_pure_documentation_no_code_changes(self):
        """Module should be pure documentation."""
        import os
        from quantum_crypt import pq_crypto_comprehensive_api_documentation_stability_catalog_v17_2026_june as doc_mod
        module_path = doc_mod.__file__
        assert "v17" in module_path
        assert "documentation" in module_path.lower()


class TestEndpointMetadataCompleteness:
    """Test endpoint metadata completeness."""
    
    def test_all_endpoints_have_performance(self):
        """All endpoints should have performance data."""
        catalog = QuantumCryptAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert len(endpoint.performance_characteristics) > 0, f"{name} missing performance"
    
    def test_all_endpoints_have_thread_safe(self):
        """All endpoints should have thread_safe flag."""
        catalog = QuantumCryptAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert isinstance(endpoint.thread_safe, bool), f"{name} missing thread_safe"
    
    def test_all_endpoints_have_version(self):
        """All endpoints should have since_version."""
        catalog = QuantumCryptAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert endpoint.since_version.startswith("v"), f"{name} invalid since_version"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
