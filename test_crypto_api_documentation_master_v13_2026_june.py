"""
Test Suite for QuantumCrypt-AI Documentation & Stability Catalog v13
======================================================================
Comprehensive tests covering all functionality in the v13 documentation system.
All tests are ADD-ONLY - no existing tests modified.
"""

import unittest
import warnings
import json

# Import the new module
from quantum_crypt.crypto_api_documentation_master_v13_2026_june import (
    StabilityLevel,
    APIExample,
    APIStabilityInfo,
    stable,
    experimental,
    deprecated,
    CryptoDocumentationCatalogV13,
    get_crypto_documentation_catalog,
)


class TestCryptoStabilityLevelEnum(unittest.TestCase):
    """Test StabilityLevel enumeration for crypto module."""
    
    def test_stability_level_values(self):
        """Test all stability levels have correct string values."""
        self.assertEqual(str(StabilityLevel.STABLE), "stable")
        self.assertEqual(str(StabilityLevel.EXPERIMENTAL), "experimental")
        self.assertEqual(str(StabilityLevel.DEPRECATED), "deprecated")
        self.assertEqual(str(StabilityLevel.INTERNAL), "internal")


class TestCryptoAPIExample(unittest.TestCase):
    """Test APIExample dataclass."""
    
    def test_example_creation(self):
        """Test APIExample creation."""
        example = APIExample(
            title="Encryption Example",
            code="encrypt(b'data', key)",
            description="Encrypt sensitive data"
        )
        self.assertEqual(example.title, "Encryption Example")
        self.assertIn("encrypt", example.code)


class TestCryptoAPIStabilityInfo(unittest.TestCase):
    """Test APIStabilityInfo dataclass."""
    
    def test_api_info_creation(self):
        """Test creating APIStabilityInfo for crypto API."""
        info = APIStabilityInfo(
            module_name="post_quantum_encryption",
            method_name="encrypt",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Post-quantum encryption using Kyber",
            categories=["encryption", "post-quantum"]
        )
        self.assertEqual(info.stability, StabilityLevel.STABLE)
        self.assertIn("post-quantum", info.categories)
    
    def test_to_dict_serialization(self):
        """Test dictionary serialization."""
        info = APIStabilityInfo(
            module_name="crypto",
            method_name="sign",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Digital signature"
        )
        d = info.to_dict()
        self.assertEqual(d["stability"], "stable")
        self.assertEqual(d["method"], "sign")


class TestCryptoStabilityDecorators(unittest.TestCase):
    """Test stability decorators for crypto functions."""
    
    def test_stable_decorator(self):
        """Test @stable decorator on crypto function."""
        @stable(version="13.0.0", description="Quantum-safe encryption")
        def encrypt(data: bytes, key: bytes) -> bytes:
            return data  # Simplified
        
        self.assertEqual(encrypt.__api_stability__, StabilityLevel.STABLE)
        self.assertEqual(encrypt(b"test", b"key"), b"test")
    
    def test_experimental_decorator(self):
        """Test @experimental decorator on bleeding-edge crypto."""
        @experimental(version="13.0.0", description="FHE - experimental")
        def he_encrypt(data: int) -> object:
            return {"ciphertext": data}
        
        self.assertEqual(he_encrypt.__api_stability__, StabilityLevel.EXPERIMENTAL)
        result = he_encrypt(42)
        self.assertEqual(result["ciphertext"], 42)
    
    def test_deprecated_decorator(self):
        """Test @deprecated decorator emits warning."""
        @deprecated(
            version="12.0.0",
            removal_version="15.0.0",
            alternative="kyber_encrypt"
        )
        def old_rsa_encrypt(data: bytes) -> bytes:
            return data
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_rsa_encrypt(b"test")
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
        
        self.assertEqual(result, b"test")


class TestCryptoDocumentationCatalogV13(unittest.TestCase):
    """Test CryptoDocumentationCatalogV13 functionality."""
    
    def setUp(self):
        """Create fresh catalog."""
        self.catalog = CryptoDocumentationCatalogV13()
    
    def test_empty_catalog(self):
        """Test empty catalog."""
        self.assertEqual(len(self.catalog._apis), 0)
    
    def test_register_crypto_api(self):
        """Test registering a crypto API."""
        info = APIStabilityInfo(
            module_name="post_quantum_encryption_engine",
            method_name="encrypt",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="NIST-standard PQC encryption",
            categories=["core", "encryption", "nist"]
        )
        self.catalog.register(info)
        self.assertEqual(len(self.catalog._apis), 1)
    
    def test_filter_by_crypto_category(self):
        """Test filtering by crypto categories."""
        categories = ["encryption", "signatures", "key-management", "random"]
        for i, cat in enumerate(categories):
            self.catalog.register(APIStabilityInfo(
                module_name=f"mod{i}",
                method_name=f"api{i}",
                stability=StabilityLevel.STABLE,
                version_introduced="1.0.0",
                description=f"Crypto API {i}",
                categories=[cat]
            ))
        
        encryption_apis = self.catalog.get_by_category("encryption")
        self.assertEqual(len(encryption_apis), 1)
    
    def test_generate_markdown(self):
        """Test Markdown API reference generation."""
        self.catalog.register(APIStabilityInfo(
            module_name="kyber_encryption",
            method_name="kem_encrypt",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Kyber key encapsulation mechanism",
            categories=["nist", "kem", "pqc"],
            parameters={"public_key": "Recipient Kyber public key"},
            return_value="(ciphertext, shared_secret)"
        ))
        
        md = self.catalog.generate_markdown_reference()
        self.assertIn("# QuantumCrypt-AI API Reference", md)
        self.assertIn("Kyber", md)
        self.assertIn("kem_encrypt", md)
    
    def test_export_json(self):
        """Test JSON catalog export."""
        self.catalog.register(APIStabilityInfo(
            module_name="dilithium",
            method_name="sign",
            stability=StabilityLevel.STABLE,
            version_introduced="3.0.0",
            description="Dilattice signatures"
        ))
        json_str = self.catalog.export_json()
        data = json.loads(json_str)
        self.assertEqual(data["catalog_version"], "13.0.0")
        self.assertEqual(data["total_apis"], 1)
    
    def test_stability_report(self):
        """Test stability coverage report."""
        for _ in range(8):
            self.catalog.register(APIStabilityInfo(
                module_name="mod",
                method_name="api",
                stability=StabilityLevel.STABLE,
                version_introduced="1.0.0",
                description="Test",
                categories=["crypto"]
            ))
        for _ in range(3):
            self.catalog.register(APIStabilityInfo(
                module_name="mod_exp",
                method_name="api_exp",
                stability=StabilityLevel.EXPERIMENTAL,
                version_introduced="10.0.0",
                description="Experimental",
                categories=["experimental"]
            ))
        
        report = self.catalog.get_stability_report()
        self.assertEqual(report["total_apis"], 11)
        self.assertEqual(report["stable"], 8)
        self.assertEqual(report["experimental"], 3)


class TestCryptoSingletonCatalog(unittest.TestCase):
    """Test singleton catalog instance."""
    
    def test_singleton_pattern(self):
        """Test same instance returned."""
        cat1 = get_crypto_documentation_catalog()
        cat2 = get_crypto_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_preloaded_crypto_apis(self):
        """Test catalog comes with crypto APIs preloaded."""
        catalog = get_crypto_documentation_catalog()
        
        # Should have multiple crypto APIs
        self.assertGreater(len(catalog._apis), 5)
        
        # Should have crypto-specific categories
        cats = catalog.get_all_categories()
        self.assertTrue(any("quantum" in c or "crypto" in c or "encryption" in c for c in cats))


class TestCryptoBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility."""
    
    def test_import_without_conflicts(self):
        """Test module imports cleanly."""
        from quantum_crypt.crypto_api_documentation_master_v13_2026_june import (
            CryptoDocumentationCatalogV13, stable
        )
        self.assertIsNotNone(CryptoDocumentationCatalogV13)
        self.assertIsNotNone(stable)
    
    def test_decorated_function_identity(self):
        """Test decorated functions preserve identity."""
        @stable(version="13.0.0")
        def secure_hash(data: bytes) -> bytes:
            return hashlib.sha256(data).digest()
        
        import hashlib
        test_hash = secure_hash(b"test")
        self.assertEqual(len(test_hash), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
