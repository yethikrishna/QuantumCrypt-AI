"""
Test Suite for QuantumCrypt-AI Comprehensive API Stability Documentation Catalog v10

Tests cover:
- Catalog initialization and basic functionality
- Stability level enumeration
- NIST standard status enumeration
- Algorithm documentation
- Module documentation retrieval
- Markdown and JSON export
- Singleton pattern
"""

import pytest
import json
from quantum_crypt.crypto_api_stability_documentation_catalog_v10_2026_june import (
    QuantumCryptAPIDocumentationCatalog,
    StabilityLevel,
    NISTStandardStatus,
    CryptoAlgorithmDoc,
    APIEndpointDoc,
    ModuleDoc,
    get_documentation_catalog
)


class TestStabilityLevel:
    """Test StabilityLevel enumeration"""
    
    def test_stability_level_values(self):
        """Test all stability levels exist with correct values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.INTERNAL.value == "INTERNAL"
        assert StabilityLevel.MAINTENANCE.value == "MAINTENANCE"


class TestNISTStandardStatus:
    """Test NISTStandardStatus enumeration"""
    
    def test_nist_status_values(self):
        """Test all NIST status values exist"""
        assert NISTStandardStatus.STANDARDIZED.value == "STANDARDIZED"
        assert NISTStandardStatus.ROUND4.value == "ROUND4"
        assert NISTStandardStatus.CANDIDATE.value == "CANDIDATE"
        assert NISTStandardStatus.RESEARCH.value == "RESEARCH"


class TestCryptoAlgorithmDoc:
    """Test CryptoAlgorithmDoc dataclass"""
    
    def test_algorithm_doc_creation(self):
        """Test creating algorithm documentation"""
        alg = CryptoAlgorithmDoc(
            name="CRYSTALS-Kyber-768",
            nist_status=NISTStandardStatus.STANDARDIZED,
            security_level=3,
            key_size_bits=2400,
            ciphertext_size_bits=1088,
            performance_ops_per_sec=32000,
            side_channel_resistant=True,
            fips_certified=True
        )
        
        assert alg.name == "CRYSTALS-Kyber-768"
        assert alg.nist_status == NISTStandardStatus.STANDARDIZED
        assert alg.security_level == 3
        assert alg.side_channel_resistant is True
        assert alg.fips_certified is True


class TestAPIEndpointDoc:
    """Test APIEndpointDoc dataclass"""
    
    def test_endpoint_doc_crypto_features(self):
        """Test crypto-specific endpoint documentation fields"""
        doc = APIEndpointDoc(
            name="HybridKEMEngine.decapsulate",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="2.0.0",
            description="Decapsulate shared secret",
            constant_time=True,
            fips_140_compliant=True,
            thread_safe=True
        )
        
        assert doc.constant_time is True
        assert doc.fips_140_compliant is True
        assert doc.thread_safe is True


class TestQuantumCryptAPIDocumentationCatalog:
    """Test main documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        assert catalog.catalog_version == "10.0.0"
        assert catalog.last_updated is not None
        assert len(catalog.modules) > 0
    
    def test_catalog_modules_populated(self):
        """Test all expected modules are in catalog"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        expected_modules = [
            "hybrid_kem_engine",
            "digital_signature_engine",
            "key_lifecycle_manager",
            "secure_memory_zeroizer",
            "secure_hkdf_engine",
            "secure_mpc_engine",
            "crypto_error_resilience",
            "crypto_observability"
        ]
        
        for module in expected_modules:
            assert module in catalog.modules, f"Missing module: {module}"
    
    def test_kem_module_has_algorithms(self):
        """Test KEM module has documented algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        kem_module = catalog.get_module_documentation("hybrid_kem_engine")
        assert kem_module is not None
        assert len(kem_module.algorithms) > 0
        
        # Check Kyber algorithms
        kyber_found = False
        for alg in kem_module.algorithms:
            if "Kyber" in alg.name:
                kyber_found = True
                assert alg.nist_status == NISTStandardStatus.STANDARDIZED
                assert alg.security_level in [1, 3, 5]
        
        assert kyber_found, "Kyber algorithms not found"
    
    def test_signature_module_has_dilithium(self):
        """Test signature module has Dilithium algorithms"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        sig_module = catalog.get_module_documentation("digital_signature_engine")
        assert sig_module is not None
        
        dilithium_found = False
        for alg in sig_module.algorithms:
            if "Dilithium" in alg.name:
                dilithium_found = True
                assert alg.nist_status == NISTStandardStatus.STANDARDIZED
        
        assert dilithium_found, "Dilithium algorithms not found"
    
    def test_algorithms_by_nist_status(self):
        """Test filtering algorithms by NIST status"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        standardized = catalog.get_algorithms_by_nist_status(NISTStandardStatus.STANDARDIZED)
        
        assert len(standardized) > 0
        for alg in standardized:
            assert alg.nist_status == NISTStandardStatus.STANDARDIZED
    
    def test_mpc_is_experimental(self):
        """Test MPC module is marked experimental"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        mpc_module = catalog.get_module_documentation("secure_mpc_engine")
        assert mpc_module is not None
        assert mpc_module.stability == StabilityLevel.EXPERIMENTAL
    
    def test_kem_is_stable(self):
        """Test KEM module is marked stable"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        kem_module = catalog.get_module_documentation("hybrid_kem_engine")
        assert kem_module is not None
        assert kem_module.stability == StabilityLevel.STABLE
    
    def test_crypto_endpoints_have_constant_time(self):
        """Test crypto endpoints have constant time documentation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        kem_module = catalog.get_module_documentation("hybrid_kem_engine")
        assert kem_module is not None
        
        for endpoint in kem_module.endpoints:
            assert endpoint.constant_time is True
    
    def test_get_all_modules_by_stability(self):
        """Test filtering modules by stability"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        stable = catalog.get_all_modules_by_stability(StabilityLevel.STABLE)
        experimental = catalog.get_all_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        
        assert len(stable) > 0
        assert len(experimental) > 0
    
    def test_get_stability_summary(self):
        """Test stability summary calculation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        summary = catalog.get_stability_summary()
        
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert summary["STABLE"] > 0
    
    def test_generate_markdown_docs(self):
        """Test markdown documentation generation"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        md = catalog.generate_markdown_docs()
        
        assert isinstance(md, str)
        assert len(md) > 0
        assert "# QuantumCrypt-AI API Documentation Catalog v10" in md
        assert "## NIST Algorithm Status" in md
        assert "✅" in md  # Standardized icon
        assert "🟢" in md  # Stable icon
        assert "Kyber" in md
        assert "Dilithium" in md
    
    def test_export_json(self):
        """Test JSON export functionality"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        json_output = catalog.export_json()
        data = json.loads(json_output)
        
        assert "catalog_version" in data
        assert data["catalog_version"] == "10.0.0"
        assert "modules" in data
        
        for mod_name, mod_data in data["modules"].items():
            assert "algorithms_count" in mod_data
            assert "endpoints_count" in mod_data
    
    def test_get_nonexistent_module(self):
        """Test retrieving non-existent module returns None"""
        catalog = QuantumCryptAPIDocumentationCatalog()
        
        doc = catalog.get_module_documentation("nonexistent_module_xyz")
        assert doc is None


class TestSingletonFunction:
    """Test singleton catalog accessor"""
    
    def test_get_documentation_catalog_returns_instance(self):
        """Test singleton function returns catalog instance"""
        catalog = get_documentation_catalog()
        
        assert isinstance(catalog, QuantumCryptAPIDocumentationCatalog)
    
    def test_get_documentation_catalog_same_instance(self):
        """Test singleton function returns same instance"""
        catalog1 = get_documentation_catalog()
        catalog2 = get_documentation_catalog()
        
        assert catalog1 is catalog2


class TestIntegration:
    """Integration tests for documentation catalog"""
    
    def test_full_catalog_workflow(self):
        """Test complete catalog usage workflow"""
        catalog = get_documentation_catalog()
        
        # Get standardized algorithms
        standardized = catalog.get_algorithms_by_nist_status(NISTStandardStatus.STANDARDIZED)
        
        # Get stability summary
        summary = catalog.get_stability_summary()
        
        # Get specific module
        kem_module = catalog.get_module_documentation("hybrid_kem_engine")
        
        # Generate docs
        md = catalog.generate_markdown_docs()
        json_out = catalog.export_json()
        
        # Verify all operations succeeded
        assert len(standardized) > 0
        assert summary["STABLE"] > 0
        assert kem_module is not None
        assert len(md) > 0
        assert len(json_out) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
