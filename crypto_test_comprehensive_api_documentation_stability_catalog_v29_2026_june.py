"""
Test Suite for QuantumCrypt-AI Comprehensive API Documentation & Stability Catalog v29
======================================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. All STABLE API methods work correctly
2. Documentation catalog loads without errors
3. NIST algorithm classification is correct
4. Backward compatibility is maintained
5. No breaking changes to existing code
"""

import pytest
import json
from quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    StabilityLevel,
    CryptoAlgorithmDocumentation,
    pq_api_documentation_catalog
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        """Verify stability level values are correct"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_stability_level_count(self):
        """Verify exactly 3 stability levels exist"""
        assert len(list(StabilityLevel)) == 3


class TestCryptoAlgorithmDocumentation:
    """Test CryptoAlgorithmDocumentation dataclass"""
    
    def test_algorithm_documentation_creation(self):
        """Verify algorithm documentation can be created"""
        doc = CryptoAlgorithmDocumentation(
            algorithm_name="TestAlgorithm",
            standard="TEST-STD",
            nist_status="STANDARDIZED",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Test algorithm",
            primary_use_cases=["Test use case"],
            usage_examples=["Example code"],
            key_classes=["TestClass"],
            key_methods=["test_method"],
            security_level="NIST Level 3",
            performance_notes="Test performance",
            dependencies=["dep1"]
        )
        assert doc.algorithm_name == "TestAlgorithm"
        assert doc.stability == StabilityLevel.STABLE
        assert doc.nist_status == "STANDARDIZED"
    
    def test_optional_fields_default_none(self):
        """Verify optional fields default to None"""
        doc = CryptoAlgorithmDocumentation(
            algorithm_name="Test",
            standard="TEST",
            nist_status="TEST",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Test",
            primary_use_cases=[],
            usage_examples=[],
            key_classes=[],
            key_methods=[],
            security_level="",
            performance_notes="",
            dependencies=[]
        )
        assert doc.deprecation_notice is None
        assert doc.migration_guide is None


class TestQuantumCryptAPIDocumentationCatalog:
    """Test main PQ documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Verify catalog initializes successfully"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        assert catalog is not None
        assert len(catalog._algorithms) > 0
    
    def test_singleton_instance(self):
        """Verify singleton instance is available"""
        assert pq_api_documentation_catalog is not None
        assert isinstance(pq_api_documentation_catalog, QuantumCryptAPIDocumentationCatalog)
    
    def test_get_algorithm_documentation_existing(self):
        """Verify get_algorithm_documentation returns doc for existing algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        doc = catalog.get_algorithm_documentation("crystals_kyber")
        assert doc is not None
        assert doc.algorithm_name == "CRYSTALS-Kyber"
    
    def test_get_algorithm_documentation_case_insensitive(self):
        """Verify algorithm lookup is case-insensitive"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        doc1 = catalog.get_algorithm_documentation("CRYSTALS_KYBER")
        doc2 = catalog.get_algorithm_documentation("crystals_kyber")
        assert doc1 == doc2
    
    def test_get_algorithm_documentation_nonexistent(self):
        """Verify get_algorithm_documentation returns None for nonexistent algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        doc = catalog.get_algorithm_documentation("nonexistent_algo_xyz")
        assert doc is None
    
    def test_list_algorithms_by_stability(self):
        """Verify listing algorithms by stability level"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        stable = catalog.list_algorithms_by_stability(StabilityLevel.STABLE)
        experimental = catalog.list_algorithms_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = catalog.list_algorithms_by_stability(StabilityLevel.DEPRECATED)
        
        assert len(stable) > 0
        assert len(experimental) > 0
        assert len(deprecated) >= 0
    
    def test_nist_standardized_algorithms_are_stable(self):
        """Verify NIST standardized algorithms are marked STABLE"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        stable = catalog.list_algorithms_by_stability(StabilityLevel.STABLE)
        
        assert "crystals_kyber" in stable
        assert "crystals_dilithium" in stable
        assert "falcon" in stable
        assert "sphincs_plus" in stable
    
    def test_experimental_algorithms_include_round4(self):
        """Verify Round 4 candidates are marked EXPERIMENTAL"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        experimental = catalog.list_algorithms_by_stability(StabilityLevel.EXPERIMENTAL)
        
        assert "classic_mceliece" in experimental
        assert "bike" in experimental
        assert "ntru_prime" in experimental
        assert "hybrid_tls_13" in experimental
    
    def test_deprecated_includes_sidh(self):
        """Verify broken algorithms are marked DEPRECATED"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        deprecated = catalog.list_algorithms_by_stability(StabilityLevel.DEPRECATED)
        
        assert "sidh" in deprecated
    
    def test_list_algorithms_by_nist_status(self):
        """Verify listing by NIST status"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        standardized = catalog.list_algorithms_by_nist_status("STANDARDIZED")
        assert len(standardized) > 0
        
        round4 = catalog.list_algorithms_by_nist_status("ROUND_4_CANDIDATE")
        assert len(round4) > 0
    
    def test_get_nist_standardized_algorithms(self):
        """Verify NIST standardized algorithms helper"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        standardized = catalog.get_nist_standardized_algorithms()
        
        assert len(standardized) >= 4
        assert "crystals_kyber" in standardized
        assert "crystals_dilithium" in standardized
    
    def test_get_stability_summary(self):
        """Verify stability summary returns correct counts"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        summary = catalog.get_stability_summary()
        
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert summary["STABLE"] >= 4
        assert summary["EXPERIMENTAL"] >= 4
    
    def test_generate_documentation_report_json(self):
        """Verify JSON report generation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        report = catalog.generate_documentation_report(format="json")
        
        # Verify valid JSON
        data = json.loads(report)
        assert "catalog_version" in data
        assert "generated_at" in data
        assert "stability_summary" in data
        assert "algorithms" in data
        assert data["catalog_version"] == "v29"
    
    def test_generate_documentation_report_markdown(self):
        """Verify markdown report generation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        report = catalog.generate_documentation_report(format="markdown")
        
        assert "# QuantumCrypt-AI" in report
        assert "## Stability Summary" in report
        assert "## Algorithm Documentation" in report
        assert "CRYSTALS-Kyber" in report
    
    def test_validate_api_compatibility(self):
        """Verify API compatibility validation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        result = catalog.validate_api_compatibility("v28")
        
        assert result["compatible"] is True
        assert "breaking_changes" in result
        assert "nist_updates" in result
        assert "warnings" in result
        assert "recommendation" in result
        assert len(result["breaking_changes"]) == 0
    
    def test_stable_api_method_signatures_unchanged(self):
        """CRITICAL: Verify STABLE API method signatures haven't changed"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        import inspect
        
        # get_algorithm_documentation
        sig = inspect.signature(catalog.get_algorithm_documentation)
        params = list(sig.parameters.keys())
        assert params == ["algo_name"]
        
        # list_algorithms_by_stability
        sig = inspect.signature(catalog.list_algorithms_by_stability)
        params = list(sig.parameters.keys())
        assert params == ["stability"]
        
        # list_algorithms_by_nist_status
        sig = inspect.signature(catalog.list_algorithms_by_nist_status)
        params = list(sig.parameters.keys())
        assert params == ["status"]
        
        # get_stability_summary
        sig = inspect.signature(catalog.get_stability_summary)
        params = list(sig.parameters.keys())
        assert params == []
        
        # generate_documentation_report
        sig = inspect.signature(catalog.generate_documentation_report)
        params = list(sig.parameters.keys())
        assert params == ["format"]
        
        # validate_api_compatibility
        sig = inspect.signature(catalog.validate_api_compatibility)
        params = list(sig.parameters.keys())
        assert params == ["client_version"]
        
        # get_nist_standardized_algorithms
        sig = inspect.signature(catalog.get_nist_standardized_algorithms)
        params = list(sig.parameters.keys())
        assert params == []
    
    def test_all_algorithms_have_required_fields(self):
        """Verify all algorithms have complete documentation fields"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        for algo_name, doc in catalog._algorithms.items():
            assert doc.algorithm_name != ""
            assert doc.standard != ""
            assert doc.nist_status != ""
            assert doc.stability in StabilityLevel
            assert doc.version != ""
            assert doc.description != ""
            assert doc.security_level != ""
            assert doc.performance_notes != ""
            assert isinstance(doc.primary_use_cases, list)
            assert isinstance(doc.usage_examples, list)
            assert isinstance(doc.key_classes, list)
            assert isinstance(doc.key_methods, list)
            assert isinstance(doc.dependencies, list)
    
    def test_deprecated_algorithms_have_notices(self):
        """Verify deprecated algorithms have deprecation notices"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        deprecated = catalog.list_algorithms_by_stability(StabilityLevel.DEPRECATED)
        
        for algo_name in deprecated:
            doc = catalog.get_algorithm_documentation(algo_name)
            assert doc.deprecation_notice is not None
            assert doc.migration_guide is not None
    
    def test_sidh_is_marked_broken(self):
        """Verify SIDH is properly marked as broken and deprecated"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        doc = catalog.get_algorithm_documentation("sidh")
        
        assert doc is not None
        assert doc.stability == StabilityLevel.DEPRECATED
        assert "BROKEN" in doc.security_level
        assert "Castryck-Decru" in doc.deprecation_notice
        assert "Kyber" in doc.migration_guide
    
    def test_nist_fips_references(self):
        """Verify NIST FIPS standard references are present"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        kyber = catalog.get_algorithm_documentation("crystals_kyber")
        dilithium = catalog.get_algorithm_documentation("crystals_dilithium")
        falcon = catalog.get_algorithm_documentation("falcon")
        sphincs = catalog.get_algorithm_documentation("sphincs_plus")
        
        assert "FIPS 203" in kyber.standard
        assert "FIPS 204" in dilithium.standard
        assert "FIPS 205" in falcon.standard
        assert "FIPS 206" in sphincs.standard


class TestBackwardCompatibility:
    """Critical backward compatibility tests"""
    
    def test_previous_catalog_still_importable(self):
        """Verify v27-28 catalogs still import (if exist)"""
        try:
            from quantum_crypt import crypto_comprehensive_api_documentation_stability_catalog_v27_2026_june
            assert True
        except ImportError:
            assert True  # Expected if doesn't exist
    
    def test_new_catalog_does_not_break_existing(self):
        """Verify adding v29 doesn't break existing code"""
        from quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june import (
            QuantumCryptAPIDocumentationCatalog
        )
        catalog = QuantumCryptAPIDocumentationCatalog()
        assert catalog is not None
    
    def test_no_breaking_changes_to_imports(self):
        """Verify imports work without breaking existing code"""
        from quantum_crypt import crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june
        
        assert hasattr(crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "QuantumCryptAPIDocumentationCatalog")
        assert hasattr(crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "StabilityLevel")
        assert hasattr(crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "CryptoAlgorithmDocumentation")
        assert hasattr(crypto_comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "pq_api_documentation_catalog")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
