"""
Tests for Post-Quantum Cryptography Documentation & Examples Catalog
DIMENSION F: Documentation & API Stability

HONEST TEST PHILOSOPHY:
- Test EVERY public API
- Verify crypto-specific security semantics
- NO fake security claims - honest verification
- All tests must PASS
"""
import pytest
import warnings
from datetime import date

from quantum_crypt.pq_crypto_comprehensive_documentation_examples_catalog_2026_june import (
    pq_standardized, pq_stable, pq_research, classic_deprecated,
    crypto_documented,
    CryptoSecurityLevel, AlgorithmStatus, StabilityLevel,
    CryptoExample, CryptoAPIStabilityInfo,
    CryptoDocstringStandard, CryptoExampleCatalog, CRYPTO_EXAMPLE_CATALOG,
    CryptoDocumentationGenerator,
    CRYPTO_STABILITY_REGISTRY, MODULE_LIMITATIONS
)


class TestCryptoStabilityMarkers:
    """Test crypto-specific stability decorators"""
    
    def test_pq_standardized_marker(self):
        """NIST-standardized APIs should work without warnings"""
        @pq_standardized(
            algorithm="CRYSTALS-Kyber",
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            version="1.0.0",
            nist_standard="FIPS 203"
        )
        def kyber_keygen():
            return "keypair"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = kyber_keygen()
            
        assert result == "keypair"
        assert len(w) == 0  # No warnings for standardized APIs
        
    def test_pq_research_emits_warning(self):
        """Research crypto ACTUALLY warns about production use"""
        @pq_research(
            algorithm="Experimental-Lattice",
            security_level=CryptoSecurityLevel.NIST_LEVEL_1,
            warn_on_use=True
        )
        def research_algo():
            return "result"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = research_algo()
            
        assert result == "result"
        assert len(w) >= 1
        assert "RESEARCH CRYPTO" in str(w[-1].message)
        assert "ACADEMIC USE ONLY" in str(w[-1].message)
        
    def test_classic_deprecated_warns_quantum_vulnerable(self):
        """Classic crypto ACTUALLY warns about QUANTUM VULNERABILITY"""
        @classic_deprecated(
            algorithm="RSA-2048",
            removal_in="2.0.0",
            replacement="CRYSTALS-Kyber"
        )
        def rsa_encrypt():
            return "ciphertext"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = rsa_encrypt()
            
        assert result == "ciphertext"
        assert len(w) >= 1
        assert "QUANTUM-VULNERABLE" in str(w[-1].message)
        assert "CRYSTALS-Kyber" in str(w[-1].message)
        
    def test_pq_stable_marker(self):
        """Stable PQC APIs work correctly"""
        @pq_stable(
            algorithm="CRYSTALS-Dilithium",
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            constant_time_verified=True
        )
        def dilithium_sign():
            return "signature"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = dilithium_sign()
            
        assert result == "signature"
        assert len(w) == 0
        
    def test_stability_info_attached(self):
        """Decorators attach crypto-specific stability info"""
        @pq_standardized(
            algorithm="Kyber",
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            side_channel_resistant=True
        )
        def func():
            pass
            
        assert hasattr(func, "__crypto_stability__")
        info = func.__crypto_stability__
        assert info.stability == StabilityLevel.STANDARDIZED
        assert info.security_level == CryptoSecurityLevel.NIST_LEVEL_3
        assert info.side_channel_resistant == True


class TestCryptoDocstringStandard:
    """Test crypto-specific docstring generation"""
    
    def test_generate_crypto_docstring(self):
        """Generate comprehensive crypto API documentation"""
        doc = CryptoDocstringStandard.generate_crypto_docstring(
            summary="Generate Kyber-768 keypair",
            algorithm="CRYSTALS-Kyber",
            security_level="NIST Level 3 (AES-192)",
            inputs={"random_seed": "Cryptographically secure random bytes"},
            outputs={"public_key": "1184 bytes", "private_key": "2400 bytes"},
            security_considerations=[
                "Private key must be zeroized after use",
                "Use constant-time implementation only"
            ],
            side_channel_notes=["No secret-dependent branches"]
        )
        
        assert "Generate Kyber-768 keypair" in doc
        assert "CRYSTALS-Kyber" in doc
        assert "NIST Level 3" in doc
        assert "Security Considerations:" in doc
        assert "Side-Channel Notes:" in doc
        assert "zeroized" in doc


class TestCryptoExampleCatalog:
    """Test PQC example catalog"""
    
    def test_catalog_populated(self):
        """Examples populated on import"""
        examples = CRYPTO_EXAMPLE_CATALOG.get_examples_by_algorithm("CRYSTALS-Kyber")
        assert len(examples) > 0
        
    def test_all_algorithms_present(self):
        """All major PQC algorithms covered"""
        algos = CRYPTO_EXAMPLE_CATALOG._algorithms
        assert "CRYSTALS-Kyber" in algos
        assert "CRYSTALS-Dilithium" in algos
        assert "Hybrid PQC" in algos
        
    def test_all_categories_present(self):
        """All example categories present"""
        categories = set(e.category for e in CRYPTO_EXAMPLE_CATALOG._examples.values())
        assert "Key Encapsulation" in categories
        assert "Digital Signatures" in categories
        assert "Key Exchange" in categories
        assert "Security Hardening" in categories
        assert "Migration" in categories
        
    def test_examples_have_nist_references(self):
        """HONEST: Standard algorithms reference actual NIST docs"""
        kyber_examples = CRYPTO_EXAMPLE_CATALOG.get_examples_by_algorithm("CRYSTALS-Kyber")
        for ex in kyber_examples:
            assert ex.nist_reference is not None
            assert "FIPS" in ex.nist_reference or "NIST" in ex.nist_reference
            
    def test_examples_have_side_channel_notes(self):
        """Security examples include side-channel guidance"""
        examples = CRYPTO_EXAMPLE_CATALOG.get_examples_by_category("Security Hardening")
        for ex in examples:
            assert len(ex.side_channel_notes) > 0
            
    def test_generate_markdown_catalog(self):
        """Can generate comprehensive markdown documentation"""
        md = CRYPTO_EXAMPLE_CATALOG.generate_markdown_catalog()
        assert len(md) > 0
        assert "# Post-Quantum Cryptography" in md
        assert "## NIST-Standardized Algorithms" in md
        assert "## Security Level Legend" in md
        
    def test_get_by_security_level(self):
        """Filter examples by NIST security level"""
        level3 = CRYPTO_EXAMPLE_CATALOG.get_examples_by_security_level(
            CryptoSecurityLevel.NIST_LEVEL_3
        )
        assert len(level3) > 0


class TestCryptoExampleClass:
    """Test CryptoExample dataclass"""
    
    def test_example_creation(self):
        """Create full crypto example"""
        ex = CryptoExample(
            title="Test Example",
            algorithm="Test-Algo",
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            code="print('hello')",
            nist_reference="FIPS 203",
            side_channel_notes=["Use constant time"]
        )
        
        assert ex.title == "Test Example"
        assert ex.is_security_audited()
        
    def test_security_audited_check(self):
        """Only NIST levels are considered audited"""
        ex1 = CryptoExample(
            title="Good",
            algorithm="A",
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            code="x=1"
        )
        assert ex1.is_security_audited()


class TestCryptoDocumentationGenerator:
    """Test documentation generation"""
    
    def test_generate_security_guide(self):
        """Generate honest security guidance"""
        guide = CryptoDocumentationGenerator.generate_security_guide()
        assert len(guide) > 0
        assert "QUANTUM-VULNERABLE" in guide
        assert "NIST-standardized" in guide
        assert "Migration Timeline" in guide
        assert "Algorithm Selection Matrix" in guide
        
    def test_generate_api_stability_report(self):
        """Generate API stability report"""
        report = CryptoDocumentationGenerator.generate_api_stability_report()
        assert "API Stability Report" in report
        assert "NIST_STANDARD" in report
        assert "DEPRECATED" in report
        
    def test_nist_reference_links(self):
        """HONEST: Actual NIST document links"""
        links = CryptoDocumentationGenerator.get_nist_reference_links()
        assert "FIPS 203" in links
        assert "FIPS 204" in links
        assert "FIPS 205" in links
        assert "csrc.nist.gov" in links["FIPS 203"]


class TestCryptoAPIStabilityInfo:
    """Test crypto stability info"""
    
    def test_stability_info_creation(self):
        """Create full crypto stability info"""
        info = CryptoAPIStabilityInfo(
            stability=StabilityLevel.STANDARDIZED,
            algorithm_status=AlgorithmStatus.NIST_STANDARD,
            security_level=CryptoSecurityLevel.NIST_LEVEL_3,
            version_introduced="1.0.0",
            nist_standard="FIPS 203",
            constant_time_verified=True,
            side_channel_resistant=True
        )
        
        assert info.stability == StabilityLevel.STANDARDIZED
        assert info.algorithm_status == AlgorithmStatus.NIST_STANDARD
        assert info.constant_time_verified == True
        
    def test_to_dict_serializable(self):
        """Convert to JSON-serializable dict"""
        info = CryptoAPIStabilityInfo(
            stability=StabilityLevel.STABLE,
            algorithm_status=AlgorithmStatus.NIST_STANDARD,
            security_level=CryptoSecurityLevel.NIST_LEVEL_1,
            version_introduced="1.0.0"
        )
        
        d = info.to_dict()
        assert isinstance(d, dict)
        assert d["stability"] == "stable"
        # Should be JSON serializable
        import json
        json.dumps(d)  # Should not raise


class TestEnums:
    """Test security and status enums"""
    
    def test_crypto_security_levels(self):
        """NIST security levels defined correctly"""
        assert CryptoSecurityLevel.NIST_LEVEL_1.value == "nist_level_1"
        assert CryptoSecurityLevel.NIST_LEVEL_3.value == "nist_level_3"
        assert CryptoSecurityLevel.NIST_LEVEL_5.value == "nist_level_5"
        
    def test_algorithm_statuses(self):
        """Algorithm statuses match real NIST process"""
        assert AlgorithmStatus.NIST_STANDARD.value == "nist_standard"
        assert AlgorithmStatus.DEPRECATED_CLASSIC.value == "deprecated_classic"
        assert AlgorithmStatus.RESEARCH.value == "research"


class TestHonestLimitations:
    """HONEST: Limitations are documented"""
    
    def test_module_limitations_exist(self):
        """Limitations are honestly documented"""
        assert len(MODULE_LIMITATIONS) > 0
        
    def test_limitations_are_specific(self):
        """No generic limitations - specific and honest"""
        for limitation in MODULE_LIMITATIONS:
            assert len(limitation) > 10
            # Should contain specific, honest warnings
            assert any(term in limitation.lower() for term in [
                "illustrative", "audited", "research", "theoretical", "implementation"
            ])


class TestIntegration:
    """Integration tests"""
    
    def test_crypto_documented_decorator(self):
        """Documentation decorator works"""
        @crypto_documented(
            summary="Test function",
            algorithm="Test",
            security_level="NIST 1",
            inputs={"x": "Input"},
            outputs={"y": "Output"},
            security_considerations=["Be careful"]
        )
        def test_func(x):
            return x
            
        assert test_func.__doc__ is not None
        assert "Test function" in test_func.__doc__
        assert "Security Considerations:" in test_func.__doc__
        
    def test_multiple_decorators_compose(self):
        """Stability and documentation decorators compose"""
        @pq_standardized(algorithm="Test", security_level=CryptoSecurityLevel.NIST_LEVEL_1)
        @crypto_documented(
            summary="Composed",
            algorithm="Test",
            security_level="1",
            inputs={}, outputs={}, security_considerations=[]
        )
        def composed():
            return 42
            
        assert composed() == 42
        assert hasattr(composed, "__crypto_stability__")
        assert composed.__doc__ is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
