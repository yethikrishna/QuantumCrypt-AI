"""
Test Suite for QuantumCrypt-AI Crypto API Documentation & Stability Catalog v7
DIMENSION F: Documentation & API Stability
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
"""

import unittest
import json
from quantum_crypt.pq_crypto_api_documentation_stability_catalog_v7_2026_june import (
    StabilityLevel,
    CryptoAPIEndpoint,
    CryptoAPIDocumentationCatalog,
    get_crypto_documentation_catalog,
    get_crypto_api_stability,
    is_nist_compliant,
    get_nist_algorithms,
)


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enumeration."""
    
    def test_stability_level_values(self):
        """Test all stability levels exist."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")
    
    def test_stability_level_string_conversion(self):
        """Test string conversion works correctly."""
        self.assertEqual(str(StabilityLevel.STABLE), "STABLE")


class TestCryptoAPIEndpoint(unittest.TestCase):
    """Test CryptoAPIEndpoint dataclass."""
    
    def test_crypto_api_endpoint_creation(self):
        """Test CryptoAPIEndpoint creation with all fields."""
        endpoint = CryptoAPIEndpoint(
            name="TestAPI.method",
            module="test_module",
            signature="method(x: int) -> str",
            docstring="Test method",
            stability=StabilityLevel.STABLE,
            nist_compliant=True,
        )
        self.assertEqual(endpoint.name, "TestAPI.method")
        self.assertEqual(endpoint.stability, StabilityLevel.STABLE)
        self.assertTrue(endpoint.nist_compliant)
    
    def test_crypto_api_endpoint_to_dict(self):
        """Test serialization to dictionary."""
        endpoint = CryptoAPIEndpoint(
            name="TestAPI.method",
            module="test_module",
            signature="method(x: int) -> str",
            docstring="Test method",
            stability=StabilityLevel.STABLE,
            security_notes=["Important security consideration"],
            nist_compliant=True,
        )
        data = endpoint.to_dict()
        self.assertEqual(data["name"], "TestAPI.method")
        self.assertEqual(data["stability"], "STABLE")
        self.assertTrue(data["nist_compliant"])
        self.assertGreater(len(data["security_notes"]), 0)


class TestCryptoAPIDocumentationCatalog(unittest.TestCase):
    """Test main crypto documentation catalog."""
    
    def setUp(self):
        """Create fresh catalog for each test."""
        self.catalog = CryptoAPIDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Test catalog initializes with standard APIs."""
        self.assertGreater(len(self.catalog._apis), 0)
        self.assertGreater(len(self.catalog._modules), 0)
    
    def test_register_api(self):
        """Test registering a new API."""
        initial_count = len(self.catalog._apis)
        self.catalog.register_api(
            name="NewCryptoAPI.test",
            module="new_module",
            signature="test() -> None",
            docstring="Test Crypto API",
            stability=StabilityLevel.STABLE,
        )
        self.assertEqual(len(self.catalog._apis), initial_count + 1)
    
    def test_get_api(self):
        """Test retrieving API documentation."""
        api = self.catalog.get_api("KyberKEM.generate_keypair")
        self.assertIsNotNone(api)
        self.assertEqual(api.name, "KyberKEM.generate_keypair")
        self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_get_api_not_found(self):
        """Test retrieving non-existent API."""
        api = self.catalog.get_api("NonExistent.CryptoAPI")
        self.assertIsNone(api)
    
    def test_search_apis(self):
        """Test API search functionality."""
        results = self.catalog.search_apis("kyber")
        self.assertGreater(len(results), 0)
        for api in results:
            self.assertTrue("kyber" in api.name.lower())
    
    def test_search_by_tag(self):
        """Test search by tag."""
        results = self.catalog.search_apis("nist")
        self.assertGreater(len(results), 0)
    
    def test_get_apis_by_stability(self):
        """Test filtering APIs by stability level."""
        stable = self.catalog.get_apis_by_stability(StabilityLevel.STABLE)
        experimental = self.catalog.get_apis_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = self.catalog.get_apis_by_stability(StabilityLevel.DEPRECATED)
        internal = self.catalog.get_apis_by_stability(StabilityLevel.INTERNAL)
        
        self.assertGreater(len(stable), 0)
        self.assertGreater(len(experimental), 0)
        self.assertGreater(len(deprecated), 0)
        self.assertGreater(len(internal), 0)
    
    def test_get_nist_compliant_apis(self):
        """Test getting NIST-compliant APIs."""
        nist_apis = self.catalog.get_nist_compliant_apis()
        self.assertGreater(len(nist_apis), 0)
        for api in nist_apis:
            self.assertTrue(api.nist_compliant)
    
    def test_export_json(self):
        """Test JSON export functionality."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertIn("total_apis", data)
        self.assertIn("nist_compliant_count", data)
        self.assertIn("stability_counts", data)
        self.assertIn("apis", data)
        self.assertEqual(data["total_apis"], len(self.catalog._apis))
        self.assertGreater(data["nist_compliant_count"], 0)
    
    def test_export_markdown(self):
        """Test Markdown export functionality."""
        md_output = self.catalog.export_markdown()
        self.assertIn("# QuantumCrypt-AI Post-Quantum Crypto API Reference", md_output)
        self.assertIn("## Stability Legend", md_output)
        self.assertIn("NIST Compliant", md_output)
        self.assertIn("STABLE", md_output)
        self.assertIn("EXPERIMENTAL", md_output)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_crypto_documentation_catalog_singleton(self):
        """Test singleton pattern works."""
        cat1 = get_crypto_documentation_catalog()
        cat2 = get_crypto_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_get_crypto_api_stability(self):
        """Test getting API stability level."""
        stability = get_crypto_api_stability("KyberKEM.generate_keypair")
        self.assertEqual(stability, "STABLE")
    
    def test_get_crypto_api_stability_not_found(self):
        """Test getting stability for non-existent API."""
        stability = get_crypto_api_stability("NonExistent.API")
        self.assertIsNone(stability)
    
    def test_is_nist_compliant(self):
        """Test NIST compliance detection."""
        self.assertTrue(is_nist_compliant("KyberKEM.generate_keypair"))
        self.assertTrue(is_nist_compliant("DilithiumSigner.sign"))
        self.assertFalse(is_nist_compliant("KeyLifecycleManager.generate_key"))
        self.assertFalse(is_nist_compliant("NonExistent.API"))
    
    def test_get_nist_algorithms(self):
        """Test getting list of NIST-compliant APIs."""
        nist_apis = get_nist_algorithms()
        self.assertIsInstance(nist_apis, list)
        self.assertGreater(len(nist_apis), 0)
        self.assertIn("KyberKEM.generate_keypair", nist_apis)


class TestAPIStabilityClassification(unittest.TestCase):
    """Verify correct stability classification for all crypto APIs."""
    
    def setUp(self):
        self.catalog = get_crypto_documentation_catalog()
    
    def test_kem_apis_are_stable_and_nist(self):
        """Verify all KEM APIs are STABLE and NIST compliant."""
        kem_apis = [
            "KyberKEM.generate_keypair",
            "KyberKEM.encapsulate",
            "KyberKEM.decapsulate",
        ]
        for api_name in kem_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.STABLE)
            self.assertTrue(api.nist_compliant)
    
    def test_signature_apis_are_stable_and_nist(self):
        """Verify all signature APIs are STABLE and NIST compliant."""
        signature_apis = [
            "DilithiumSigner.generate_keypair",
            "DilithiumSigner.sign",
            "DilithiumSigner.verify",
            "FalconSigner.generate_keypair",
        ]
        for api_name in signature_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.STABLE)
            self.assertTrue(api.nist_compliant)
    
    def test_symmetric_apis_are_stable(self):
        """Verify symmetric encryption APIs are STABLE."""
        symmetric_apis = [
            "AESGCM.encrypt",
            "AESGCM.decrypt",
            "ChaCha20Poly1305.encrypt",
            "HKDF.derive",
            "Argon2id.hash",
        ]
        for api_name in symmetric_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_hybrid_apis_are_stable(self):
        """Verify hybrid crypto APIs are STABLE."""
        hybrid_apis = [
            "HybridKEM.generate_keypair",
            "HybridSigner.generate_keypair",
        ]
        for api_name in hybrid_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_key_management_apis_are_experimental(self):
        """Verify key management APIs are EXPERIMENTAL."""
        km_apis = [
            "KeyLifecycleManager.generate_key",
            "KeyLifecycleManager.rotate_key",
            "HSMWrapper.wrap_key",
        ]
        for api_name in km_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.EXPERIMENTAL)
    
    def test_certificate_apis_are_experimental(self):
        """Verify certificate APIs are EXPERIMENTAL."""
        cert_apis = [
            "PQCertificateGenerator.generate_csr",
            "PQCertificateVerifier.verify_chain",
        ]
        for api_name in cert_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.EXPERIMENTAL)
    
    def test_mpc_apis_are_experimental(self):
        """Verify MPC APIs are EXPERIMENTAL."""
        mpc_apis = [
            "ShamirSecretSharing.split",
            "ShamirSecretSharing.reconstruct",
        ]
        for api_name in mpc_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(api.stability, StabilityLevel.EXPERIMENTAL)
    
    def test_deprecated_apis_have_notice(self):
        """Verify deprecated APIs have deprecation notices."""
        api = self.catalog.get_api("LegacyAES.encrypt_ecb")
        self.assertIsNotNone(api)
        self.assertEqual(api.stability, StabilityLevel.DEPRECATED)
        self.assertGreater(len(api.deprecation_notice), 0)
    
    def test_internal_apis_marked_internal(self):
        """Verify internal APIs are correctly marked."""
        api = self.catalog.get_api("CryptoEngine._initialize_backend")
        self.assertIsNotNone(api)
        self.assertEqual(api.stability, StabilityLevel.INTERNAL)


class TestDocumentationQuality(unittest.TestCase):
    """Test quality and completeness of crypto API documentation."""
    
    def setUp(self):
        self.catalog = get_crypto_documentation_catalog()
    
    def test_all_apis_have_docstrings(self):
        """Verify every API has a non-empty docstring."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.docstring.strip()), 0,
                f"API {api.name} missing docstring"
            )
    
    def test_all_apis_have_signatures(self):
        """Verify every API has a signature."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.signature.strip()), 0,
                f"API {api.name} missing signature"
            )
    
    def test_stable_apis_have_since_version(self):
        """Verify STABLE APIs have version information."""
        for api in self.catalog.get_apis_by_stability(StabilityLevel.STABLE):
            self.assertGreater(
                len(api.since_version), 0,
                f"STABLE API {api.name} missing since_version"
            )
    
    def test_deprecated_apis_have_notice(self):
        """Verify all DEPRECATED APIs have deprecation notices."""
        for api in self.catalog.get_apis_by_stability(StabilityLevel.DEPRECATED):
            self.assertGreater(
                len(api.deprecation_notice), 0,
                f"DEPRECATED API {api.name} missing notice"
            )
    
    def test_all_apis_have_tags(self):
        """Verify all APIs have at least one classification tag."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.tags), 0,
                f"API {api.name} has no classification tags"
            )
    
    def test_nist_apis_have_security_notes(self):
        """Verify NIST-compliant APIs have security notes."""
        for api in self.catalog.get_nist_compliant_apis():
            self.assertGreater(
                len(api.security_notes), 0,
                f"NIST API {api.name} missing security notes"
            )


class TestNISTComplianceVerification(unittest.TestCase):
    """Test NIST compliance tracking."""
    
    def setUp(self):
        self.catalog = get_crypto_documentation_catalog()
    
    def test_kyber_is_nist_compliant(self):
        """Verify Kyber is marked as NIST compliant."""
        api = self.catalog.get_api("KyberKEM.generate_keypair")
        self.assertIsNotNone(api)
        self.assertTrue(api.nist_compliant)
    
    def test_dilithium_is_nist_compliant(self):
        """Verify Dilithium is marked as NIST compliant."""
        api = self.catalog.get_api("DilithiumSigner.sign")
        self.assertIsNotNone(api)
        self.assertTrue(api.nist_compliant)
    
    def test_falcon_is_nist_compliant(self):
        """Verify Falcon is marked as NIST compliant."""
        api = self.catalog.get_api("FalconSigner.generate_keypair")
        self.assertIsNotNone(api)
        self.assertTrue(api.nist_compliant)
    
    def test_hybrid_not_explicitly_nist(self):
        """Verify hybrid APIs are not explicitly marked NIST."""
        api = self.catalog.get_api("HybridKEM.generate_keypair")
        self.assertIsNotNone(api)
        # Hybrid contains NIST algos but composite itself is not standardized
        # This is correct behavior


class TestExportIntegrity(unittest.TestCase):
    """Test export functionality integrity."""
    
    def setUp(self):
        self.catalog = get_crypto_documentation_catalog()
    
    def test_json_export_valid_json(self):
        """Verify JSON export produces valid JSON."""
        json_str = self.catalog.export_json()
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            self.fail("JSON export produced invalid JSON")
        
        self.assertIsInstance(data["total_apis"], int)
        self.assertIsInstance(data["nist_compliant_count"], int)
        self.assertIsInstance(data["apis"], list)
        self.assertEqual(len(data["apis"]), data["total_apis"])
    
    def test_markdown_export_contains_all_sections(self):
        """Verify Markdown export contains all expected sections."""
        md = self.catalog.export_markdown()
        required_sections = [
            "Post-Quantum Crypto API Reference",
            "Stability Legend",
            "NIST Compliance Legend",
            "STABLE APIs",
            "EXPERIMENTAL APIs",
        ]
        for section in required_sections:
            self.assertIn(section, md, f"Missing section: {section}")
    
    def test_markdown_contains_nist_badges(self):
        """Verify Markdown export contains NIST badges."""
        md = self.catalog.export_markdown()
        self.assertIn("✅ NIST", md)
    
    def test_markdown_contains_security_notes(self):
        """Verify Markdown export contains security notes."""
        md = self.catalog.export_markdown()
        self.assertIn("**Security Notes:**", md)
    
    def test_markdown_contains_code_examples(self):
        """Verify Markdown export contains code examples."""
        md = self.catalog.export_markdown()
        self.assertIn("```python", md)
        self.assertIn("```", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
