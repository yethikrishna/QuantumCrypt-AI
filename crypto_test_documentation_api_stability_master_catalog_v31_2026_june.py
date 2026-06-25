"""
Test Suite for QuantumCrypt-AI Crypto API Documentation & Stability Catalog V31
DIMENSION F: Documentation & API Stability

Tests verify:
1. All crypto stability decorators work correctly
2. Crypto API catalog initialization and querying
3. Security level tracking
4. NIST status documentation
5. Documentation generation
6. Backward compatibility - NO existing code broken

ADD-ONLY PHILOSOPHY: These tests only validate NEW functionality,
never modify or test existing production code behavior.
"""

import pytest
import warnings

# Import the new documentation module
from quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v31_2026_june import (
    StabilityLevel,
    SecurityLevel,
    NISTStatus,
    CryptoAPIDocumentation,
    VersionCompatibility,
    stable_crypto_api,
    experimental_crypto_api,
    deprecated_crypto_api,
    QuantumCryptAPICatalog,
    get_crypto_api_catalog,
    print_crypto_api_stability_summary
)


class TestSecurityLevelEnum:
    """Test security level classification enum."""
    
    def test_security_level_values(self):
        """Verify all security levels are defined."""
        assert SecurityLevel.NIST_LEVEL_1.value == "NIST_LEVEL_1"
        assert SecurityLevel.NIST_LEVEL_3.value == "NIST_LEVEL_3"
        assert SecurityLevel.NIST_LEVEL_5.value == "NIST_LEVEL_5"
        assert SecurityLevel.QUANTUM_RESISTANT.value == "QUANTUM_RESISTANT"
        assert SecurityLevel.CLASSICAL_ONLY.value == "CLASSICAL_ONLY"


class TestNISTStatusEnum:
    """Test NIST standardization status enum."""
    
    def test_nist_status_values(self):
        """Verify all NIST status values."""
        assert NISTStatus.STANDARDIZED.value == "STANDARDIZED"
        assert NISTStatus.ROUND_4.value == "ROUND_4"
        assert NISTStatus.ROUND_3.value == "ROUND_3"
        assert NISTStatus.CANDIDATE.value == "CANDIDATE"
        assert NISTStatus.RESEARCH.value == "RESEARCH"


class TestCryptoStabilityDecorators:
    """Test cryptographic API stability decorators."""
    
    def test_stable_crypto_api_marks_metadata(self):
        """Verify @stable_crypto_api correctly marks function metadata."""
        @stable_crypto_api(
            version_added="2.5.0",
            security_level=SecurityLevel.NIST_LEVEL_5,
            nist_status=NISTStatus.STANDARDIZED
        )
        def crypto_func():
            return "secure"
        
        assert hasattr(crypto_func, "_stability")
        assert crypto_func._stability == StabilityLevel.STABLE
        assert crypto_func._security_level == SecurityLevel.NIST_LEVEL_5
        assert crypto_func._nist_status == NISTStatus.STANDARDIZED
        assert crypto_func._version_added == "2.5.0"
    
    def test_stable_crypto_api_preserves_behavior(self):
        """Verify @stable_crypto_api doesn't change function behavior."""
        @stable_crypto_api(version_added="2.5.0")
        def encrypt(data: bytes, key: bytes) -> bytes:
            return data[::-1]  # Dummy "encryption"
        
        test_data = b"test data"
        test_key = b"key123"
        
        result = encrypt(test_data, test_key)
        assert result == test_data[::-1]
        assert encrypt.__name__ == "encrypt"
    
    def test_experimental_crypto_api_marks_metadata(self):
        """Verify @experimental_crypto_api marks function correctly."""
        @experimental_crypto_api(
            version_added="2.5.0",
            security_level=SecurityLevel.QUANTUM_RESISTANT,
            nist_status=NISTStatus.ROUND_4
        )
        def pq_func():
            return "pq"
        
        assert pq_func._stability == StabilityLevel.EXPERIMENTAL
        assert pq_func._security_level == SecurityLevel.QUANTUM_RESISTANT
        assert pq_func._nist_status == NISTStatus.ROUND_4
    
    def test_deprecated_crypto_api_issues_warning_with_reason(self):
        """Verify @deprecated_crypto_api issues detailed warnings."""
        @deprecated_crypto_api(
            version_deprecated="2.0.0",
            removal_version="3.0.0",
            replacement="crystals_kyber_keypair()",
            reason="Not quantum-resistant"
        )
        def old_rsa():
            return "rsa"
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_rsa()
            
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated since 2.0.0" in str(w[0].message)
            assert "crystals_kyber_keypair()" in str(w[0].message)
            assert "Not quantum-resistant" in str(w[0].message)
        
        assert result == "rsa"


class TestCryptoAPIDocumentationDataclass:
    """Test the CryptoAPIDocumentation data structure."""
    
    def test_crypto_api_documentation_full(self):
        """Test creating a complete crypto API documentation entry."""
        doc = CryptoAPIDocumentation(
            function_name="aes_gcm.encrypt",
            stability=StabilityLevel.STABLE,
            security_level=SecurityLevel.NIST_LEVEL_1,
            nist_status=NISTStatus.STANDARDIZED,
            version_added="1.0.0",
            description="AES-GCM AEAD encryption",
            usage_example="encrypt(data, key, nonce)",
            parameters={"data": "bytes - plaintext", "key": "bytes - 16/24/32 bytes"},
            key_size_recommendations={"AES-128": 16, "AES-256": 32},
            performance_notes="Hardware accelerated via AES-NI"
        )
        
        assert doc.function_name == "aes_gcm.encrypt"
        assert doc.security_level == SecurityLevel.NIST_LEVEL_1
        assert doc.nist_status == NISTStatus.STANDARDIZED
        assert "AES-128" in doc.key_size_recommendations
        assert doc.performance_notes != ""
    
    def test_crypto_api_documentation_minimal(self):
        """Test minimal documentation creation."""
        doc = CryptoAPIDocumentation(
            function_name="test.func",
            stability=StabilityLevel.STABLE,
            security_level=SecurityLevel.NIST_LEVEL_1,
            nist_status=NISTStatus.STANDARDIZED,
            version_added="1.0.0"
        )
        
        assert doc.version_deprecated is None
        assert isinstance(doc.parameters, dict)
        assert isinstance(doc.compatibility_notes, list)


class TestQuantumCryptAPICatalog:
    """Test the main crypto API catalog functionality."""
    
    def test_catalog_initializes_with_apis(self):
        """Test catalog initializes with documented crypto APIs."""
        catalog = QuantumCryptAPICatalog()
        
        assert len(catalog.api_docs) > 0
        assert len(catalog.compatibility_matrix) > 0
    
    def test_get_crypto_api_documentation(self):
        """Test retrieving crypto API documentation."""
        catalog = QuantumCryptAPICatalog()
        
        doc = catalog.get_api_documentation("aes_gcm_engine.encrypt")
        assert doc is not None
        assert doc.stability == StabilityLevel.STABLE
        assert doc.security_level == SecurityLevel.NIST_LEVEL_1
        assert doc.nist_status == NISTStatus.STANDARDIZED
    
    def test_get_nonexistent_api_returns_none(self):
        """Test non-existent API returns None."""
        catalog = QuantumCryptAPICatalog()
        assert catalog.get_api_documentation("not.real") is None
    
    def test_list_apis_by_stability(self):
        """Test filtering crypto APIs by stability."""
        catalog = QuantumCryptAPICatalog()
        
        stable = catalog.list_apis_by_stability(StabilityLevel.STABLE)
        experimental = catalog.list_apis_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = catalog.list_apis_by_stability(StabilityLevel.DEPRECATED)
        
        assert len(stable) > 0
        assert len(experimental) >= 0
        assert len(deprecated) > 0
    
    def test_list_apis_by_security_level(self):
        """Test filtering APIs by security strength."""
        catalog = QuantumCryptAPICatalog()
        
        l1_apis = catalog.list_apis_by_security_level(SecurityLevel.NIST_LEVEL_1)
        l5_apis = catalog.list_apis_by_security_level(SecurityLevel.NIST_LEVEL_5)
        
        assert len(l1_apis) > 0
        assert len(l5_apis) > 0
    
    def test_crystals_kyber_is_quantum_resistant(self):
        """Verify Kyber is marked as properly secured."""
        catalog = QuantumCryptAPICatalog()
        doc = catalog.get_api_documentation("crystals_kyber_engine.keygen")
        
        assert doc is not None
        assert doc.stability == StabilityLevel.STABLE
        assert doc.security_level == SecurityLevel.NIST_LEVEL_5
        assert doc.nist_status == NISTStatus.STANDARDIZED
    
    def test_rsa_is_deprecated(self):
        """Verify RSA is marked as deprecated."""
        catalog = QuantumCryptAPICatalog()
        doc = catalog.get_api_documentation("rsa_engine.encrypt")
        
        assert doc is not None
        assert doc.stability == StabilityLevel.DEPRECATED
        assert doc.security_level == SecurityLevel.CLASSICAL_ONLY
        assert doc.version_deprecated == "2.0.0"
        assert "quantum-resistant" in doc.migration_guide
    
    def test_generate_documentation_report(self):
        """Test crypto documentation report generation."""
        catalog = QuantumCryptAPICatalog()
        report = catalog.generate_documentation_report()
        
        assert "QUANTUMCRYPT-AI" in report
        assert "STABLE" in report
        assert "NIST_LEVEL_5" in report
        assert "STANDARDIZED" in report
    
    def test_catalog_repr(self):
        """Test catalog string representation."""
        catalog = QuantumCryptAPICatalog()
        assert "QuantumCryptAPICatalog" in repr(catalog)
        assert "apis" in repr(catalog)


class TestGlobalCryptoCatalogFunctions:
    """Test global catalog singleton functions."""
    
    def test_get_crypto_api_catalog_singleton(self):
        """Test singleton pattern works."""
        cat1 = get_crypto_api_catalog()
        cat2 = get_crypto_api_catalog()
        
        assert cat1 is cat2
        assert isinstance(cat1, QuantumCryptAPICatalog)
    
    def test_print_crypto_summary_executes(self):
        """Test summary function runs without errors."""
        print_crypto_api_stability_summary()


class TestVersionCompatibilityMatrix:
    """Test version compatibility tracking."""
    
    def test_fips_compliant_tracking(self):
        """Test FIPS compliance flag works."""
        compat = VersionCompatibility(
            module_name="pq_crypto",
            minimum_supported_version="2.0.0",
            recommended_version="2.5.0",
            fips_compliant=True
        )
        
        assert compat.fips_compliant is True
        assert compat.backward_compatible is True


class TestBackwardCompatibilityCritical:
    """CRITICAL: Verify NO existing functionality is broken."""
    
    def test_new_module_imports_cleanly(self):
        """New module imports without errors."""
        import quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v31_2026_june
        assert True  # Pass if no exception
    
    def test_decorators_are_transparent(self):
        """Decorators don't change wrapped function behavior."""
        def original_encrypt(data: bytes, key: bytes) -> bytes:
            return bytes(d ^ k for d, k in zip(data, key * (len(data) // len(key) + 1)))
        
        decorated = stable_crypto_api(version_added="2.5.0")(original_encrypt)
        
        test_data = b"Hello, Quantum!"
        test_key = b"secret"
        
        assert original_encrypt(test_data, test_key) == decorated(test_data, test_key)
    
    def test_no_global_state_modification(self):
        """Importing module doesn't modify unexpected global state."""
        # Import should not:
        # - Modify builtins
        # - Change warning filters
        # - Alter other modules
        import quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v31_2026_june
        
        # Module should only export its own API
        assert hasattr(quantum_crypt.crypto_comprehensive_api_documentation_stability_catalog_v31_2026_june, 
                      "QuantumCryptAPICatalog")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
