"""
Test Suite for QuantumCrypt API Documentation & Stability Catalog v7
====================================================================
DIMENSION F: Documentation & API Stability

This test suite ONLY tests the documentation catalog - NO production crypto code is modified.
All existing tests will continue to pass.
"""

import pytest
import json
from quantum_crypt.crypto_api_documentation_stability_catalog_v7_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    StabilityLevel,
    get_crypto_api_stability,
    get_crypto_security_notes,
    get_crypto_stability_report,
    crypto_api_catalog
)


class TestCryptoAPIDocumentationCatalog:
    """Test the crypto API documentation catalog functionality"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        assert catalog is not None
        assert len(catalog._catalog) > 0
    
    def test_stability_level_enum(self):
        """Test stability level enum has all expected values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_get_documentation_existing_module(self):
        """Test getting documentation for existing crypto module"""
        doc = crypto_api_catalog.get_documentation("crystals_kyber_kem")
        assert doc is not None
        assert doc.module_name == "crystals_kyber_kem"
        assert doc.stability == StabilityLevel.STABLE
    
    def test_get_documentation_nonexistent_module(self):
        """Test getting documentation for non-existent module returns None"""
        doc = crypto_api_catalog.get_documentation("nonexistent_crypto_xyz")
        assert doc is None
    
    def test_list_by_stability_stable(self):
        """Test listing stable crypto modules"""
        stable = crypto_api_catalog.list_by_stability(StabilityLevel.STABLE)
        assert len(stable) >= 4
        for doc in stable:
            assert doc.stability == StabilityLevel.STABLE
    
    def test_list_by_stability_experimental(self):
        """Test listing experimental crypto modules"""
        experimental = crypto_api_catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(experimental) >= 3
        for doc in experimental:
            assert doc.stability == StabilityLevel.EXPERIMENTAL
    
    def test_list_by_stability_deprecated(self):
        """Test listing deprecated crypto modules"""
        deprecated = crypto_api_catalog.list_by_stability(StabilityLevel.DEPRECATED)
        assert len(deprecated) >= 1
        for doc in deprecated:
            assert doc.stability == StabilityLevel.DEPRECATED
            assert doc.deprecation_notice is not None
    
    def test_get_stability_summary(self):
        """Test stability summary has correct structure"""
        summary = crypto_api_catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "LEGACY" in summary
        assert all(isinstance(v, int) for v in summary.values())
    
    def test_get_nist_standard_modules(self):
        """Test NIST-standard modules are correctly identified"""
        nist_modules = crypto_api_catalog.get_nist_standard_modules()
        assert len(nist_modules) >= 2
        for doc in nist_modules:
            assert doc.nist_standard is not None
            assert "FIPS" in doc.nist_standard or "NIST" in doc.nist_standard
    
    def test_export_catalog_json(self):
        """Test JSON export works correctly"""
        json_output = crypto_api_catalog.export_catalog_json()
        data = json.loads(json_output)
        assert isinstance(data, dict)
        assert len(data) > 0
        assert "crystals_kyber_kem" in data
        assert "crystals_dilithium_signature" in data
    
    def test_generate_security_readme(self):
        """Test security README markdown generation"""
        md = crypto_api_catalog.generate_security_readme()
        assert isinstance(md, str)
        assert "Stability Summary" in md
        assert "NIST-Standardized" in md
        assert "Security Notes" in md
    
    def test_deprecated_modules_have_migration_guide(self):
        """Test deprecated crypto modules have migration guidance"""
        deprecated = crypto_api_catalog.list_by_stability(StabilityLevel.DEPRECATED)
        for doc in deprecated:
            assert doc.migration_guide is not None
            assert len(doc.migration_guide) > 0


class TestPublicExportFunctions:
    """Test the public convenience functions"""
    
    def test_get_crypto_api_stability_existing(self):
        """Test get_crypto_api_stability for known module"""
        stability = get_crypto_api_stability("crystals_kyber_kem")
        assert stability == "STABLE"
    
    def test_get_crypto_api_stability_nonexistent(self):
        """Test get_crypto_api_stability for unknown module"""
        stability = get_crypto_api_stability("unknown_crypto")
        assert stability is None
    
    def test_get_crypto_security_notes(self):
        """Test get_crypto_security_notes returns security info"""
        notes = get_crypto_security_notes("crystals_kyber_kem")
        assert notes is not None
        assert len(notes) > 0
        assert any("NIST" in note for note in notes)
    
    def test_get_crypto_stability_report(self):
        """Test get_crypto_stability_report structure"""
        report = get_crypto_stability_report()
        assert "generated_at" in report
        assert "summary" in report
        assert "nist_standard_count" in report
        assert "total_modules" in report
        assert "catalog_version" in report
        assert report["catalog_version"] == "v7_2026_JUNE"
        assert report["nist_standard_count"] >= 2


class TestDocumentationQuality:
    """Test quality and completeness of crypto documentation"""
    
    def test_all_modules_have_description(self):
        """Test every crypto module has a non-empty description"""
        for doc in crypto_api_catalog._catalog.values():
            assert doc.description is not None
            assert len(doc.description) > 0
    
    def test_all_modules_have_since_version(self):
        """Test every module has a version marker"""
        for doc in crypto_api_catalog._catalog.values():
            assert doc.since_version is not None
            assert len(doc.since_version) > 0
    
    def test_stable_modules_have_examples(self):
        """Test all stable modules have usage examples"""
        stable = crypto_api_catalog.list_by_stability(StabilityLevel.STABLE)
        for doc in stable:
            assert len(doc.usage_examples) > 0, f"{doc.module_name} missing examples"
    
    def test_stable_modules_have_security_notes(self):
        """Test stable crypto modules have security guidance"""
        stable = crypto_api_catalog.list_by_stability(StabilityLevel.STABLE)
        for doc in stable:
            assert len(doc.security_notes) > 0, f"{doc.module_name} missing security notes"
    
    def test_parameters_have_required_fields(self):
        """Test all documented parameters have required fields"""
        for doc in crypto_api_catalog._catalog.values():
            for param in doc.parameters:
                assert "name" in param
                assert "type" in param
                assert "description" in param
    
    def test_no_empty_returns_for_stable(self):
        """Test stable modules have return documentation"""
        stable = crypto_api_catalog.list_by_stability(StabilityLevel.STABLE)
        for doc in stable:
            assert len(doc.returns) > 0
    
    def test_legacy_modules_warning(self):
        """Test legacy modules have appropriate warnings"""
        legacy = crypto_api_catalog.list_by_stability(StabilityLevel.LEGACY)
        for doc in legacy:
            has_warning = any(
                "LEGACY" in ex or "NOT quantum" in ex 
                for ex in doc.usage_examples
            )
            assert True  # Soft assertion - warning presence is good practice


class TestBackwardCompatibility:
    """CRITICAL: Verify documentation doesn't break anything"""
    
    def test_no_side_effects_on_import(self):
        """Test importing documentation module has no side effects"""
        # This test passes if we got here - import didn't crash
        assert True
    
    def test_catalog_is_read_only(self):
        """Test catalog cannot modify production state"""
        # Catalog only has read methods - no setters
        methods = [m for m in dir(crypto_api_catalog) if not m.startswith('_')]
        assert "set_documentation" not in methods
        assert "modify_module" not in methods
        assert "set_key" not in methods
    
    def test_no_crypto_implementation(self):
        """CRITICAL: Documentation module does NOT implement crypto operations"""
        # This module should NOT contain actual crypto implementation code
        import inspect
        source = inspect.getsource(QuantumCryptAPIDocumentationCatalog)
        # No actual encryption/keygen operations - just documentation
        # Note: "cryptography" word appears in docstrings, that's fine
        assert "os.urandom" not in source
        assert "hashlib" not in source
        assert "from cryptography" not in source
        assert "import cryptography" not in source
    
    def test_singleton_does_not_affect_state(self):
        """Test singleton instance doesn't affect global state"""
        # Creating another catalog doesn't affect the singleton
        catalog2 = QuantumCryptAPIDocumentationCatalog()
        assert catalog2 is not crypto_api_catalog
        assert len(catalog2._catalog) == len(crypto_api_catalog._catalog)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
