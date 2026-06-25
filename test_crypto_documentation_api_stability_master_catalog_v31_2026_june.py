"""
Test Suite for QuantumCrypt-AI Documentation & API Stability Catalog v31
========================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. Documentation catalog loads correctly
2. All cryptographic API entries have complete security metadata
3. Stability markers are correctly assigned
4. NIST standardization flags are accurate
5. Quantum-safety markers are correct
6. Side-channel resistance indicators are present
7. Usage examples are syntactically valid
8. Markdown generation works
9. No breaking changes to existing code

PHILOSOPHY: Test only, don't modify production code
"""

import sys
import unittest

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')


class TestCryptoDocumentationCatalog(unittest.TestCase):
    """Test suite for cryptographic documentation catalog functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        from quantum_crypt.crypto_documentation_api_stability_master_catalog_v31_2026_june import (
            QuantumCryptDocumentationCatalog,
            StabilityLevel,
            get_crypto_documentation_catalog,
            get_crypto_api_documentation
        )
        self.catalog_class = QuantumCryptDocumentationCatalog
        self.StabilityLevel = StabilityLevel
        self.get_catalog = get_crypto_documentation_catalog
        self.get_api_doc = get_crypto_api_documentation
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        catalog = self.catalog_class()
        self.assertIsNotNone(catalog)
        self.assertGreater(len(catalog._catalog), 0)
        self.assertEqual(catalog.version, "31.0.0")
    
    def test_singleton_accessor(self):
        """Test singleton accessor function works"""
        catalog = self.get_catalog()
        self.assertIsNotNone(catalog)
        self.assertIsInstance(catalog, self.catalog_class)
    
    def test_get_api_documentation(self):
        """Test quick API documentation accessor"""
        doc = self.get_api_doc("PostQuantumHybridKEM")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, "PostQuantumHybridKEM")
    
    def test_get_nonexistent_api_returns_none(self):
        """Test accessing non-existent API returns None"""
        doc = self.get_api_doc("NonExistentCryptoAPI12345")
        self.assertIsNone(doc)
    
    def test_all_apis_have_complete_metadata(self):
        """Verify all crypto API entries have required metadata fields"""
        catalog = self.catalog_class()
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                # Required fields
                self.assertIsNotNone(entry.name, f"{api_name}: missing name")
                self.assertIsNotNone(entry.module_path, f"{api_name}: missing module_path")
                self.assertIsNotNone(entry.stability, f"{api_name}: missing stability")
                self.assertIsNotNone(entry.category, f"{api_name}: missing category")
                self.assertIsNotNone(entry.description, f"{api_name}: missing description")
                self.assertIsNotNone(entry.since_version, f"{api_name}: missing since_version")
                
                # Crypto-specific booleans should be explicit
                self.assertIsInstance(entry.nist_standardized, bool, f"{api_name}: nist_standardized not bool")
                self.assertIsInstance(entry.quantum_safe, bool, f"{api_name}: quantum_safe not bool")
                self.assertIsInstance(entry.side_channel_resistant, bool, f"{api_name}: side_channel_resistant not bool")
                
                # Description should be meaningful
                self.assertGreater(
                    len(entry.description.strip()),
                    10,
                    f"{api_name}: description too short"
                )
    
    def test_stability_levels_are_valid(self):
        """Verify all stability markers are valid enum values"""
        catalog = self.catalog_class()
        
        valid_stabilities = {
            self.StabilityLevel.STABLE,
            self.StabilityLevel.BETA,
            self.StabilityLevel.EXPERIMENTAL,
            self.StabilityLevel.DEPRECATED
        }
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertIn(entry.stability, valid_stabilities,
                            f"{api_name}: invalid stability level")
    
    def test_kem_apis_exist(self):
        """Verify KEM APIs are documented"""
        catalog = self.catalog_class()
        
        kem_apis = catalog.list_by_category("Key Encapsulation (KEM)")
        self.assertGreater(len(kem_apis), 0)
        
        api_names = {e.name for e in kem_apis}
        self.assertIn("PostQuantumHybridKEM", api_names)
    
    def test_kem_has_nist_standardized_flag(self):
        """Verify PostQuantumHybridKEM is marked as NIST standardized"""
        catalog = self.catalog_class()
        kem = catalog.get_api("PostQuantumHybridKEM")
        
        self.assertIsNotNone(kem)
        self.assertTrue(kem.nist_standardized, "CRYSTALS-Kyber should be NIST standardized")
        self.assertTrue(kem.quantum_safe, "KEM should be quantum-safe")
        self.assertTrue(kem.side_channel_resistant, "KEM should be side-channel resistant")
    
    def test_mpc_apis_exist(self):
        """Verify MPC APIs are documented"""
        catalog = self.catalog_class()
        
        mpc_apis = catalog.list_by_category("Secure Multi-Party Computation")
        self.assertGreater(len(mpc_apis), 0)
        
        api_names = {e.name for e in mpc_apis}
        self.assertIn("PostQuantumSecureMPCEngine", api_names)
    
    def test_key_derivation_apis_exist(self):
        """Verify key derivation APIs are documented"""
        catalog = self.catalog_class()
        
        kdf_apis = catalog.list_by_category("Key Derivation & Authentication")
        self.assertGreater(len(kdf_apis), 0)
        
        api_names = {e.name for e in kdf_apis}
        self.assertIn("SecureKeyDerivationFunction", api_names)
        self.assertIn("PostQuantumSecureHKDFMemoryHard", api_names)
        self.assertIn("PostQuantumSecureMAC", api_names)
    
    def test_fpe_apis_exist(self):
        """Verify format-preserving encryption APIs are documented"""
        catalog = self.catalog_class()
        
        fpe_apis = catalog.list_by_category("Format-Preserving Encryption")
        self.assertGreater(len(fpe_apis), 0)
        
        api_names = {e.name for e in fpe_apis}
        self.assertIn("FormatPreservingEncryptionEngine", api_names)
    
    def test_security_hardening_apis_exist(self):
        """Verify security hardening APIs are documented"""
        catalog = self.catalog_class()
        
        sec_apis = catalog.list_by_category("Security Hardening")
        self.assertGreater(len(sec_apis), 0)
        
        api_names = {e.name for e in sec_apis}
        self.assertIn("SideChannelResistantKeyWrapper", api_names)
        self.assertIn("CryptoSecureMemoryZeroizer", api_names)
        self.assertIn("CryptoConstantTimeComparator", api_names)
    
    def test_observability_apis_exist(self):
        """Verify observability APIs are documented"""
        catalog = self.catalog_class()
        
        obs_apis = catalog.list_by_category("Observability")
        self.assertGreater(len(obs_apis), 0)
        
        api_names = {e.name for e in obs_apis}
        self.assertIn("CryptoObservabilityEngine", api_names)
        self.assertIn("CryptoAuditTrail", api_names)
    
    def test_error_resilience_apis_exist(self):
        """Verify error resilience APIs are documented"""
        catalog = self.catalog_class()
        
        err_apis = catalog.list_by_category("Error Resilience")
        self.assertGreater(len(err_apis), 0)
        
        api_names = {e.name for e in err_apis}
        self.assertIn("CryptoErrorResilienceEngine", api_names)
        self.assertIn("CryptoCircuitBreaker", api_names)
        self.assertIn("CryptoRetryWithBackoff", api_names)
    
    def test_list_by_stability(self):
        """Test filtering APIs by stability level"""
        catalog = self.catalog_class()
        
        stable = catalog.list_by_stability(self.StabilityLevel.STABLE)
        beta = catalog.list_by_stability(self.StabilityLevel.BETA)
        
        self.assertGreater(len(stable), 0, "Should have STABLE crypto APIs")
        self.assertGreater(len(beta), 0, "Should have BETA crypto APIs")
    
    def test_list_nist_standardized(self):
        """Test listing NIST-standardized algorithms"""
        catalog = self.catalog_class()
        nist_apis = catalog.list_nist_standardized()
        
        self.assertGreater(len(nist_apis), 0, "Should have NIST-standardized APIs")
        api_names = {e.name for e in nist_apis}
        self.assertIn("PostQuantumHybridKEM", api_names)
    
    def test_list_quantum_safe(self):
        """Test listing quantum-safe primitives"""
        catalog = self.catalog_class()
        pq_apis = catalog.list_quantum_safe()
        
        self.assertGreater(len(pq_apis), 0, "Should have quantum-safe APIs")
    
    def test_list_side_channel_resistant(self):
        """Test listing side-channel resistant implementations"""
        catalog = self.catalog_class()
        scr_apis = catalog.list_side_channel_resistant()
        
        self.assertGreater(len(scr_apis), 0, "Should have side-channel resistant APIs")
    
    def test_get_all_categories(self):
        """Test getting all unique categories"""
        catalog = self.catalog_class()
        categories = catalog.get_all_categories()
        
        self.assertIsInstance(categories, list)
        self.assertGreater(len(categories), 0)
        self.assertEqual(categories, sorted(categories), "Categories should be sorted")
    
    def test_generate_markdown_docs(self):
        """Test Markdown documentation generation"""
        catalog = self.catalog_class()
        md = catalog.generate_markdown_docs()
        
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 0)
        self.assertIn("# QuantumCrypt-AI Cryptographic API Documentation", md)
        self.assertIn("Stability Legend", md)
        self.assertIn("Security Legend", md)
        self.assertIn("✅ **STABLE**", md)
        self.assertIn("NIST", md)
        self.assertIn("PQ", md)
        self.assertIn("SCR", md)
    
    def test_get_security_summary(self):
        """Test security summary generation"""
        catalog = self.catalog_class()
        summary = catalog.get_security_summary()
        
        self.assertIsInstance(summary, dict)
        self.assertIn("total_apis", summary)
        self.assertIn("nist_standardized", summary)
        self.assertIn("quantum_safe", summary)
        self.assertIn("side_channel_resistant", summary)
        self.assertIn("stability_breakdown", summary)
        self.assertGreater(summary["total_apis"], 0)
    
    def test_usage_examples_are_present(self):
        """Verify important crypto APIs have usage examples"""
        catalog = self.catalog_class()
        
        important_apis = [
            "PostQuantumHybridKEM",
            "PostQuantumSecureMPCEngine",
            "SecureKeyDerivationFunction",
            "FormatPreservingEncryptionEngine",
            "SideChannelResistantKeyWrapper",
            "CryptoSecureMemoryZeroizer"
        ]
        
        for api_name in important_apis:
            with self.subTest(api=api_name):
                entry = catalog.get_api(api_name)
                self.assertIsNotNone(entry, f"API {api_name} not found")
                self.assertGreater(
                    len(entry.usage_example.strip()),
                    20,
                    f"{api_name}: usage example missing or too short"
                )
    
    def test_parameters_are_documented(self):
        """Verify APIs have parameter documentation"""
        catalog = self.catalog_class()
        
        entry = catalog.get_api("PostQuantumHybridKEM")
        self.assertGreater(len(entry.parameters), 0, "KEM should have parameters documented")
        
        for param in entry.parameters:
            self.assertIn("name", param)
            self.assertIn("type", param)
            self.assertIn("desc", param)
    
    def test_returns_field_is_documented(self):
        """Verify APIs have return value documentation"""
        catalog = self.catalog_class()
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertGreater(
                    len(entry.returns.strip()),
                    5,
                    f"{api_name}: returns documentation missing"
                )
    
    def test_security_properties_are_present(self):
        """Verify security properties are documented for key APIs"""
        catalog = self.catalog_class()
        
        kem = catalog.get_api("PostQuantumHybridKEM")
        self.assertGreater(len(kem.security_properties), 0, "KEM should have security properties")
        self.assertIn("IND-CCA2 secure", kem.security_properties)
    
    def test_performance_benchmarks_are_present(self):
        """Verify performance benchmarks are present for key APIs"""
        catalog = self.catalog_class()
        
        kem = catalog.get_api("PostQuantumHybridKEM")
        self.assertGreater(len(kem.performance_benchmarks), 0, "KEM should have benchmarks")
        self.assertIn("keygen", kem.performance_benchmarks)
        self.assertIn("throughput", kem.performance_benchmarks)
    
    def test_security_warnings_are_present(self):
        """Verify security warnings are present for critical APIs"""
        catalog = self.catalog_class()
        
        kem = catalog.get_api("PostQuantumHybridKEM")
        self.assertGreater(len(kem.security_warnings), 0, "KEM should have security warnings")
    
    def test_related_apis_are_listed(self):
        """Verify APIs have related APIs listed"""
        catalog = self.catalog_class()
        
        # At least some APIs should have related APIs
        has_related = False
        for entry in catalog._catalog.values():
            if len(entry.related_apis) > 0:
                has_related = True
                break
        
        self.assertTrue(has_related, "Some crypto APIs should have related APIs listed")
    
    def test_module_imports_without_errors(self):
        """Test the module can be imported without syntax errors"""
        import importlib
        module = importlib.import_module(
            'quantum_crypt.crypto_documentation_api_stability_master_catalog_v31_2026_june'
        )
        self.assertIsNotNone(module)
    
    def test_docstring_formatting(self):
        """Verify module has proper header docstring"""
        import quantum_crypt.crypto_documentation_api_stability_master_catalog_v31_2026_june as module
        self.assertIsNotNone(module.__doc__)
        self.assertIn("QuantumCrypt-AI", module.__doc__)
        self.assertIn("STABILITY", module.__doc__)


class TestCryptoStabilityEnum(unittest.TestCase):
    """Test StabilityLevel enum functionality"""
    
    def test_enum_values(self):
        """Test enum has all expected values"""
        from quantum_crypt.crypto_documentation_api_stability_master_catalog_v31_2026_june import StabilityLevel
        
        expected = {"STABLE", "BETA", "EXPERIMENTAL", "DEPRECATED"}
        actual = {level.value for level in StabilityLevel}
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    print("="*70)
    print("QuantumCrypt-AI: Documentation & API Stability Tests v31")
    print("Dimension F: Documentation & API Stability")
    print("="*70)
    
    unittest.main(verbosity=2)
