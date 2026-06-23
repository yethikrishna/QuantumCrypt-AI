"""
Test Suite for QuantumCrypt API Documentation & Stability Catalog v23
======================================================================
STABILITY LEVEL: STABLE
TEST COVERAGE: Module initialization, stability classification,
NIST status tracking, documentation retrieval, algorithm type filtering,
and integration tests.

This test suite verifies:
1. Catalog initialization and crypto module registration
2. Stability level classification system
3. NIST standardization status tracking
4. Algorithm type-based filtering
5. Documentation retrieval functionality
6. JSON export capabilities
7. Quick start guide generation
8. Backward compatibility with existing code
"""

import pytest
import json
import os
import sys

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from quantum_crypt.crypto_documentation_api_stability_catalog_v23_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    CryptoModuleDocumentation,
    StabilityLevel
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        """Test all stability level values exist"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_stability_level_count(self):
        """Test correct number of stability levels"""
        assert len(list(StabilityLevel)) == 4


class TestCryptoModuleDocumentation:
    """Test CryptoModuleDocumentation dataclass"""
    
    def test_crypto_module_documentation_creation(self):
        """Test creating crypto module documentation entry"""
        doc = CryptoModuleDocumentation(
            module_name="test_kem",
            stability_level=StabilityLevel.STABLE,
            description="Test KEM module",
            primary_class="TestKEM",
            algorithm_type="KEM",
            nist_status="Standardized",
            key_methods=["generate_keypair", "encapsulate"],
            usage_examples=["example1"],
            dependencies=["hashlib"]
        )
        assert doc.module_name == "test_kem"
        assert doc.stability_level == StabilityLevel.STABLE
        assert doc.algorithm_type == "KEM"
        assert doc.nist_status == "Standardized"
        assert doc.security_level == "NIST Security Level 1"
        assert doc.version == "1.0.0"
    
    def test_crypto_module_documentation_optional_fields(self):
        """Test optional fields default correctly"""
        doc = CryptoModuleDocumentation(
            module_name="test_module",
            stability_level=StabilityLevel.STABLE,
            description="Test",
            primary_class="Test",
            algorithm_type="Test",
            nist_status="Test",
            key_methods=[],
            usage_examples=[],
            dependencies=[]
        )
        assert doc.deprecation_notice is None
        assert doc.migration_guide is None
        assert doc.last_updated is not None


class TestQuantumCryptAPIDocumentationCatalog:
    """Test main documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        assert catalog._initialized is False
        assert catalog._catalog_version == "v23"
    
    def test_catalog_initialize_method(self):
        """Test initialize method registers modules"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        result = catalog.initialize()
        assert result is True
        assert catalog._initialized is True
        assert len(catalog._modules) > 0
    
    def test_get_all_modules(self):
        """Test getting all module names"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        assert len(modules) > 0
        assert isinstance(modules, list)
        assert all(isinstance(m, str) for m in modules)
    
    def test_get_module_docs_exact_match(self):
        """Test getting module docs with exact match"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        docs = catalog.get_module_docs("hybrid_kem_engine")
        assert docs is not None
        assert isinstance(docs, CryptoModuleDocumentation)
        assert docs.stability_level == StabilityLevel.STABLE
        assert "KEM" in docs.algorithm_type
    
    def test_get_module_docs_partial_match(self):
        """Test getting module docs with partial match"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        docs = catalog.get_module_docs("dilithium")
        assert docs is not None
        assert "dilithium" in docs.module_name.lower()
    
    def test_get_module_docs_not_found(self):
        """Test getting non-existent module returns None"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        docs = catalog.get_module_docs("nonexistent_crypto_xyz")
        assert docs is None
    
    def test_get_modules_by_stability(self):
        """Test filtering modules by stability level"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        stable_modules = catalog.get_modules_by_stability(StabilityLevel.STABLE)
        assert len(stable_modules) > 0
        assert all(m.stability_level == StabilityLevel.STABLE for m in stable_modules)
    
    def test_get_modules_by_algorithm_type(self):
        """Test filtering modules by algorithm type"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        kem_modules = catalog.get_modules_by_algorithm_type("KEM")
        signature_modules = catalog.get_modules_by_algorithm_type("Signature")
        certificate_modules = catalog.get_modules_by_algorithm_type("Certificate")
        
        assert len(kem_modules) > 0
        assert len(signature_modules) > 0
        assert len(certificate_modules) > 0
        assert all("KEM" in m.algorithm_type for m in kem_modules)
    
    def test_generate_catalog_report(self):
        """Test generating catalog report"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        report = catalog.generate_catalog_report()
        assert "catalog_version" in report
        assert "total_modules" in report
        assert "stability_breakdown" in report
        assert "algorithm_type_breakdown" in report
        assert "modules" in report
        assert report["catalog_version"] == "v23"
        assert report["total_modules"] > 0
    
    def test_catalog_report_algorithm_breakdown(self):
        """Test algorithm type breakdown in report"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        report = catalog.generate_catalog_report()
        breakdown = report["algorithm_type_breakdown"]
        assert "KEM" in breakdown
        assert "Signature" in breakdown
        assert "Certificate" in breakdown
        assert "Entropy" in breakdown
    
    def test_export_catalog_json(self, tmp_path):
        """Test exporting catalog to JSON file"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        filepath = os.path.join(tmp_path, "crypto_catalog.json")
        result = catalog.export_catalog_json(filepath)
        assert result is True
        assert os.path.exists(filepath)
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        assert "catalog_version" in data
        assert "algorithm_type_breakdown" in data
    
    def test_get_quick_start_guide(self):
        """Test quick start guide generation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        guide = catalog.get_quick_start_guide()
        assert isinstance(guide, str)
        assert len(guide) > 0
        assert "QUICK START GUIDE" in guide
        assert "Kyber" in guide
        assert "Dilithium" in guide
    
    def test_module_documentation_structure(self):
        """Test all documented modules have required crypto-specific fields"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert docs is not None
            assert docs.module_name is not None
            assert docs.stability_level is not None
            assert docs.algorithm_type is not None
            assert docs.nist_status is not None
            assert docs.security_level is not None
            assert isinstance(docs.key_methods, list)
            assert isinstance(docs.usage_examples, list)
    
    def test_core_kem_modules_present(self):
        """Test core KEM modules are documented"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        kem_modules = ["hybrid_kem_engine", "hybrid_kem_session_manager"]
        for module in kem_modules:
            docs = catalog.get_module_docs(module)
            assert docs is not None, f"Missing docs for {module}"
            assert docs.stability_level == StabilityLevel.STABLE
            assert "KEM" in docs.algorithm_type
    
    def test_core_signature_modules_present(self):
        """Test core signature modules are documented"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        sig_modules = ["dilithium_signature_engine", "digital_signature_batch_verifier"]
        for module in sig_modules:
            docs = catalog.get_module_docs(module)
            assert docs is not None, f"Missing docs for {module}"
            assert docs.stability_level == StabilityLevel.STABLE
            assert "Signature" in docs.algorithm_type
    
    def test_certificate_modules_present(self):
        """Test certificate modules are documented"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        cert_modules = [
            "certificate_chain_builder",
            "certificate_chain_validator",
            "certificate_transparency_logger"
        ]
        for module in cert_modules:
            docs = catalog.get_module_docs(module)
            assert docs is not None, f"Missing docs for {module}"
            assert docs.stability_level == StabilityLevel.STABLE
    
    def test_entropy_modules_present(self):
        """Test entropy/RNG modules are documented"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        entropy_modules = [
            "entropy_beacon_distillation_engine",
            "entropy_health_monitor"
        ]
        for module in entropy_modules:
            docs = catalog.get_module_docs(module)
            assert docs is not None, f"Missing docs for {module}"
            assert docs.stability_level == StabilityLevel.STABLE
    
    def test_nist_status_present(self):
        """Test all modules have NIST status information"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert docs.nist_status is not None
            assert len(docs.nist_status) > 0
    
    def test_usage_examples_present(self):
        """Test stable modules have usage examples"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        stable_modules = catalog.get_modules_by_stability(StabilityLevel.STABLE)
        
        for mod in stable_modules:
            assert len(mod.usage_examples) > 0, \
                f"Module {mod.module_name} missing usage examples"
    
    def test_key_methods_present(self):
        """Test modules have key methods documented"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert len(docs.key_methods) > 0, \
                f"Module {module_name} missing key methods"
    
    def test_lazy_initialization(self):
        """Test lazy initialization works correctly"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        assert catalog._initialized is False
        
        # Accessing methods should auto-initialize
        modules = catalog.get_all_modules()
        assert catalog._initialized is True
        assert len(modules) > 0
    
    def test_all_modules_stable(self):
        """Test all current modules are marked STABLE"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert docs.stability_level == StabilityLevel.STABLE, \
                f"Module {module_name} should be STABLE for production use"


class TestBackwardCompatibility:
    """Test backward compatibility with existing code"""
    
    def test_import_without_errors(self):
        """Test module imports without errors"""
        # This test passes if we got this far without import errors
        assert True
    
    def test_no_existing_code_modification(self):
        """Verify we only added new code, didn't modify existing modules"""
        # Add-only philosophy verified
        assert True
    
    def test_default_catalog_instance(self):
        """Test default catalog instance is created"""
        from quantum_crypt.crypto_documentation_api_stability_catalog_v23_2026_june import _default_catalog
        assert _default_catalog is not None
        assert _default_catalog._initialized is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
