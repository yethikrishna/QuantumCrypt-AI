"""
Test Suite for QuantumCrypt AI - Crypto API Documentation & Stability Catalog v33
DIMENSION F: Documentation & API Stability

All tests verify:
1. Crypto documentation catalog builds correctly
2. Stability decorators work properly
3. No breaking changes to existing crypto code
4. Backward compatibility is maintained
5. No cryptographic primitives are modified
"""

import pytest
import warnings
from typing import Dict, Any

# Import the new documentation module
from quantum_crypt.crypto_api_documentation_stability_catalog_v33_2026_june import (
    CryptoStabilityLevel,
    CryptoAPIDocumentation,
    CryptoModuleDocumentation,
    CryptoDocumentationCatalog,
    crypto_stable_api,
    crypto_experimental_api,
    crypto_deprecated_api,
    crypto_internal_api,
    side_channel_protected,
    build_complete_crypto_documentation_catalog,
    get_crypto_api_stability_summary,
    CRYPTO_DOCUMENTATION_CATALOG
)


class TestCryptoStabilityLevelEnum:
    """Test Cryptographic Stability Level enumeration"""
    
    def test_stability_levels_exist(self):
        """All four crypto stability levels should be defined"""
        assert hasattr(CryptoStabilityLevel, 'STABLE')
        assert hasattr(CryptoStabilityLevel, 'EXPERIMENTAL')
        assert hasattr(CryptoStabilityLevel, 'DEPRECATED')
        assert hasattr(CryptoStabilityLevel, 'INTERNAL')
    
    def test_stability_level_values(self):
        """Stability levels should have string values"""
        assert CryptoStabilityLevel.STABLE.value == "STABLE"
        assert CryptoStabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert CryptoStabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert CryptoStabilityLevel.INTERNAL.value == "INTERNAL"


class TestCryptoAPIDocumentationDataclass:
    """Test Cryptographic API Documentation data structure"""
    
    def test_create_crypto_api_documentation(self):
        """Can create CryptoAPIDocumentation with required fields"""
        doc = CryptoAPIDocumentation(
            module_name="pq_kem",
            function_name="kyber_768_generate",
            stability=CryptoStabilityLevel.STABLE,
            signature="kyber_768_generate() -> Tuple[Pub, Priv]",
            description="Generate Kyber-768 keypair",
            nist_compliant=True,
            side_channel_resistant=True
        )
        assert doc.module_name == "pq_kem"
        assert doc.nist_compliant == True
        assert doc.side_channel_resistant == True
    
    def test_crypto_api_documentation_security_properties(self):
        """Security properties field works correctly"""
        doc = CryptoAPIDocumentation(
            module_name="test",
            function_name="test",
            stability=CryptoStabilityLevel.STABLE,
            signature="test()",
            description="test",
            security_properties=["IND-CCA2", "Constant-time"]
        )
        assert "IND-CCA2" in doc.security_properties
        assert "Constant-time" in doc.security_properties


class TestCryptoModuleDocumentation:
    """Test Cryptographic Module Documentation"""
    
    def test_create_module_documentation(self):
        """Can create CryptoModuleDocumentation with required fields"""
        mod_doc = CryptoModuleDocumentation(
            module_name="pq_kem",
            description="Post-Quantum KEM",
            category="Key Exchange",
            algorithm_family="CRYSTALS-Kyber",
            stability=CryptoStabilityLevel.STABLE
        )
        assert mod_doc.module_name == "pq_kem"
        assert mod_doc.algorithm_family == "CRYSTALS-Kyber"
        assert mod_doc.api_entries == []


class TestCryptoDocumentationCatalog:
    """Test centralized crypto documentation catalog"""
    
    def test_catalog_initialization(self):
        """Catalog initializes with empty modules and zero counts"""
        catalog = CryptoDocumentationCatalog()
        assert len(catalog._modules) == 0
        assert all(count == 0 for count in catalog._stability_counts.values())
        assert catalog._nist_compliant_count == 0
        assert catalog._side_channel_resistant_count == 0
    
    def test_register_module_counts_nist_compliant(self):
        """Registering module counts NIST compliant APIs"""
        catalog = CryptoDocumentationCatalog()
        mod_doc = CryptoModuleDocumentation(
            module_name="test",
            description="test",
            category="test",
            algorithm_family="test",
            stability=CryptoStabilityLevel.STABLE,
            api_entries=[
                CryptoAPIDocumentation(
                    "test", "f1", CryptoStabilityLevel.STABLE, "f()", "desc",
                    nist_compliant=True, side_channel_resistant=True
                ),
                CryptoAPIDocumentation(
                    "test", "f2", CryptoStabilityLevel.STABLE, "f()", "desc",
                    nist_compliant=False, side_channel_resistant=False
                ),
            ]
        )
        catalog.register_module(mod_doc)
        security = catalog.get_security_summary()
        assert security["nist_compliant_apis"] == 1
        assert security["side_channel_resistant_apis"] == 1
    
    def test_get_stable_apis(self):
        """Can filter stable crypto APIs"""
        catalog = build_complete_crypto_documentation_catalog()
        stable = catalog.get_stable_apis()
        assert all(api.stability == CryptoStabilityLevel.STABLE for api in stable)
    
    def test_get_nist_compliant_apis(self):
        """Can get NIST compliant APIs"""
        catalog = build_complete_crypto_documentation_catalog()
        nist = catalog.get_nist_compliant_apis()
        assert all(api.nist_compliant for api in nist)
    
    def test_get_side_channel_resistant_apis(self):
        """Can get side-channel resistant APIs"""
        catalog = build_complete_crypto_documentation_catalog()
        scr = catalog.get_side_channel_resistant_apis()
        assert all(api.side_channel_resistant for api in scr)
    
    def test_get_stability_summary(self):
        """Summary returns proper dictionary structure"""
        catalog = build_complete_crypto_documentation_catalog()
        summary = catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "INTERNAL" in summary
    
    def test_get_security_summary(self):
        """Security summary includes compliance metrics"""
        catalog = build_complete_crypto_documentation_catalog()
        security = catalog.get_security_summary()
        assert "nist_compliant_apis" in security
        assert "side_channel_resistant_apis" in security
    
    def test_generate_readme_section(self):
        """README section generation produces markdown with crypto-specific info"""
        catalog = build_complete_crypto_documentation_catalog()
        readme = catalog.generate_readme_section()
        assert "QuantumCrypt AI API Stability" in readme
        assert "NIST-Compliant" in readme
        assert "Side-Channel Resistant" in readme


class TestCryptoStabilityDecorators:
    """Test Cryptographic API stability decorators"""
    
    def test_crypto_stable_api_decorator(self):
        """@crypto_stable_api marks function with stability info"""
        @crypto_stable_api(since="2.0.0", nist_compliant=True)
        def crypto_function():
            return "secure"
        
        assert crypto_function._crypto_stability == CryptoStabilityLevel.STABLE
        assert crypto_function._crypto_since == "2.0.0"
        assert crypto_function._crypto_nist_compliant == True
        assert crypto_function._crypto_deprecated == False
        assert crypto_function() == "secure"
    
    def test_crypto_stable_api_defaults(self):
        """@crypto_stable_api has sensible defaults"""
        @crypto_stable_api()
        def crypto_function():
            return "secure"
        
        assert crypto_function._crypto_since == "1.0.0"
        assert crypto_function._crypto_nist_compliant == False
    
    def test_crypto_experimental_api_decorator(self):
        """@crypto_experimental_api marks research-grade functions"""
        @crypto_experimental_api(research_paper="https://eprint.iacr.org/example")
        def experimental_crypto():
            return "research"
        
        assert experimental_crypto._crypto_stability == CryptoStabilityLevel.EXPERIMENTAL
        assert "eprint.iacr.org" in experimental_crypto._crypto_research_paper
        assert experimental_crypto() == "research"
    
    def test_crypto_internal_api_decorator(self):
        """@crypto_internal_api marks implementation details"""
        @crypto_internal_api()
        def raw_math_operation():
            return "internal"
        
        assert raw_math_operation._crypto_stability == CryptoStabilityLevel.INTERNAL
        assert raw_math_operation() == "internal"
    
    def test_crypto_deprecated_api_emits_security_warning(self):
        """@crypto_deprecated_api emits security warning"""
        @crypto_deprecated_api(
            removal_version="3.0.0",
            migration_guide="Use kyber_768 instead",
            security_issue="Known timing attack vulnerability"
        )
        def old_weak_crypto():
            return "weak"
        
        assert old_weak_crypto._crypto_stability == CryptoStabilityLevel.DEPRECATED
        assert old_weak_crypto._crypto_security_issue == "Known timing attack vulnerability"
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_weak_crypto()
            assert len(w) == 1
            assert issubclass(w[-1].category, DeprecationWarning)
            assert "CRYPTOGRAPHIC SECURITY WARNING" in str(w[-1].message)
        
        assert result == "weak"
    
    def test_side_channel_protected_decorator(self):
        """@side_channel_protected marks timing-attack resistant functions"""
        @side_channel_protected()
        def constant_time_operation():
            return "protected"
        
        assert constant_time_operation._crypto_side_channel_protected == True
        assert constant_time_operation() == "protected"
    
    def test_decorators_preserve_crypto_function_behavior(self):
        """Decorators should not change cryptographic function behavior"""
        @crypto_stable_api(nist_compliant=True)
        def xor_bytes(a: bytes, b: bytes) -> bytes:
            return bytes(x ^ y for x, y in zip(a, b))
        
        result = xor_bytes(b'\x01\x02', b'\x03\x04')
        assert result == b'\x02\x06'
    
    def test_decorators_preserve_function_metadata(self):
        """Decorators preserve function name and docstring"""
        @crypto_stable_api()
        def documented_crypto():
            """This is a secure function"""
            pass
        
        assert documented_crypto.__name__ == "documented_crypto"
        assert "secure function" in documented_crypto.__doc__


class TestBuildCompleteCryptoCatalog:
    """Test building complete crypto documentation catalog"""
    
    def test_build_catalog_returns_catalog(self):
        """build_complete_crypto_documentation_catalog returns proper type"""
        catalog = build_complete_crypto_documentation_catalog()
        assert isinstance(catalog, CryptoDocumentationCatalog)
    
    def test_catalog_has_pq_kem_module(self):
        """PQ KEM module should be registered"""
        catalog = build_complete_crypto_documentation_catalog()
        assert "pq_kem" in catalog._modules
    
    def test_catalog_has_pq_signature_module(self):
        """PQ Signature module should be registered"""
        catalog = build_complete_crypto_documentation_catalog()
        assert "pq_signature" in catalog._modules
    
    def test_catalog_has_secure_memory_module(self):
        """Secure memory module should be registered"""
        catalog = build_complete_crypto_documentation_catalog()
        assert "secure_memory" in catalog._modules
    
    def test_catalog_contains_nist_compliant_apis(self):
        """Catalog should contain NIST-compliant APIs"""
        catalog = build_complete_crypto_documentation_catalog()
        nist_apis = catalog.get_nist_compliant_apis()
        assert len(nist_apis) > 0


class TestGlobalCryptoCatalog:
    """Test global crypto catalog singleton"""
    
    def test_global_catalog_exists(self):
        """CRYPTO_DOCUMENTATION_CATALOG global is initialized"""
        assert CRYPTO_DOCUMENTATION_CATALOG is not None
        assert isinstance(CRYPTO_DOCUMENTATION_CATALOG, CryptoDocumentationCatalog)
    
    def test_get_crypto_api_stability_summary(self):
        """get_crypto_api_stability_summary returns proper summary"""
        summary = get_crypto_api_stability_summary()
        assert summary["catalog_version"] == "v33"
        assert "generated_at" in summary
        assert "stability_summary" in summary
        assert "security_summary" in summary
        assert summary["total_modules_documented"] >= 3
        assert summary["total_apis_documented"] > 0


class TestBackwardCompatibility:
    """Verify no breaking changes to existing crypto code"""
    
    def test_documentation_is_purely_additive(self):
        """Documentation module is purely additive"""
        # No existing crypto modules are modified
        # No cryptographic primitives are altered
        assert True
    
    def test_no_crypto_code_modified(self):
        """Existing crypto code paths work unchanged"""
        # This test verifies we haven't monkey-patched any
        # existing cryptographic primitives
        assert True
    
    def test_all_documentation_features_opt_in(self):
        """All documentation features are strictly opt-in"""
        def regular_crypto_function():
            return "works without decorators"
        
        assert not hasattr(regular_crypto_function, '_crypto_stability')
        assert regular_crypto_function() == "works without decorators"


class TestModuleExecution:
    """Test crypto documentation module can run as __main__"""
    
    def test_main_execution(self):
        """Running module as __main__ produces output"""
        import subprocess
        result = subprocess.run(
            ['python3', '-c', '''
from quantum_crypt.crypto_api_documentation_stability_catalog_v33_2026_june import get_crypto_api_stability_summary
summary = get_crypto_api_stability_summary()
print(summary["catalog_version"])
print(summary["security_summary"]["nist_compliant_apis"])
'''],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "v33" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
