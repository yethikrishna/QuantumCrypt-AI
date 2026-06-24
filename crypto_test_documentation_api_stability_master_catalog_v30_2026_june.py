"""
Test Suite for QuantumCrypt Documentation & API Stability Catalog v30
Dimension: F - Documentation & API Stability
Date: 2026-06-25

Tests verify:
1. Catalog initialization and module/algorithm registration
2. Stability level and NIST security level enumeration
3. Algorithm catalog completeness and quantum readiness
4. API endpoint documentation completeness
5. Quantum migration guidance
6. Singleton pattern correctness
7. Report generation
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from crypto_documentation_api_stability_master_catalog_v30_2026_june import (
    StabilityLevel,
    NISTSecurityLevel,
    AlgorithmInfo,
    APIEndpoint,
    ModuleDocumentation,
    DocumentationCatalog,
    get_documentation_catalog,
    print_api_stability_report,
    print_quantum_readiness_guide,
    __api_stability__,
)


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enumeration"""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")


class TestNISTSecurityLevel(unittest.TestCase):
    """Test NISTSecurityLevel enumeration"""
    
    def test_nist_level_values(self):
        """Verify all NIST security levels exist"""
        self.assertEqual(NISTSecurityLevel.LEVEL_1.value, 1)
        self.assertEqual(NISTSecurityLevel.LEVEL_3.value, 3)
        self.assertEqual(NISTSecurityLevel.LEVEL_5.value, 5)
    
    def test_nist_level_str(self):
        """Verify string conversion"""
        self.assertEqual(str(NISTSecurityLevel.LEVEL_1), "LEVEL_1")
        self.assertEqual(str(NISTSecurityLevel.LEVEL_5), "LEVEL_5")


class TestAlgorithmInfo(unittest.TestCase):
    """Test AlgorithmInfo dataclass"""
    
    def test_algorithm_info_creation(self):
        """Test algorithm info creation"""
        algo = AlgorithmInfo(
            name="Test-Algo",
            standard="FIPS 203",
            nist_level=NISTSecurityLevel.LEVEL_3,
            type="key-exchange",
            quantum_safe=True,
            recommended=True,
            key_sizes={"pk": 100, "sk": 200},
            performance_notes="Test notes"
        )
        self.assertEqual(algo.name, "Test-Algo")
        self.assertTrue(algo.quantum_safe)
        self.assertTrue(algo.recommended)


class TestAPIEndpoint(unittest.TestCase):
    """Test APIEndpoint dataclass"""
    
    def test_endpoint_with_quantum_readiness(self):
        """Test endpoint quantum readiness field"""
        endpoint = APIEndpoint(
            name="test.func",
            module="test",
            stability=StabilityLevel.STABLE,
            since_version="v1",
            description="Test",
            quantum_readiness="PQ_ONLY"
        )
        self.assertEqual(endpoint.quantum_readiness, "PQ_ONLY")


class TestDocumentationCatalog(unittest.TestCase):
    """Test main DocumentationCatalog class"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Verify catalog initializes with all modules"""
        modules = self.catalog.get_all_modules()
        self.assertGreater(len(modules), 0)
        self.assertIn("post_quantum", modules)
        self.assertIn("classical_crypto", modules)
        self.assertIn("hybrid_signature", modules)
        self.assertIn("key_management", modules)
        self.assertIn("security_hardening", modules)
        self.assertIn("side_channel_protection", modules)
        self.assertIn("error_resilience", modules)
        self.assertIn("observability", modules)
    
    def test_algorithm_catalog_populated(self):
        """Verify algorithm catalog is populated"""
        algorithms = self.catalog.get_all_algorithms()
        self.assertGreater(len(algorithms), 0)
    
    def test_post_quantum_algorithms_present(self):
        """Verify key PQ algorithms are documented"""
        algorithms = self.catalog.get_all_algorithms()
        self.assertTrue(any("Kyber" in a for a in algorithms))
        self.assertTrue(any("Dilithium" in a for a in algorithms))
        self.assertTrue(any("Falcon" in a for a in algorithms))
        self.assertTrue(any("SPHINCS" in a for a in algorithms))
    
    def test_classical_algorithms_present(self):
        """Verify classical algorithms are documented"""
        algorithms = self.catalog.get_all_algorithms()
        self.assertTrue(any("RSA" in a for a in algorithms))
        self.assertTrue(any("ECDSA" in a for a in algorithms))
        self.assertTrue(any("Ed25519" in a for a in algorithms))
    
    def test_recommended_algorithms_quantum_safe(self):
        """Verify recommended quantum-safe algorithms"""
        recommended = self.catalog.get_recommended_algorithms(quantum_safe_only=True)
        self.assertGreater(len(recommended), 0)
        for algo in recommended:
            self.assertTrue(algo.quantum_safe)
            self.assertTrue(algo.recommended)
    
    def test_classical_not_quantum_safe(self):
        """Verify classical algorithms marked NOT quantum-safe"""
        rsa = self.catalog.get_algorithm_info("RSA-2048")
        self.assertIsNotNone(rsa)
        self.assertFalse(rsa.quantum_safe)
        self.assertFalse(rsa.recommended)
        
        ecdsa = self.catalog.get_algorithm_info("ECDSA-P256")
        self.assertIsNotNone(ecdsa)
        self.assertFalse(ecdsa.quantum_safe)
        self.assertFalse(ecdsa.recommended)
    
    def test_kyber768_is_recommended(self):
        """Verify Kyber-768 is recommended quantum-safe"""
        kyber = self.catalog.get_algorithm_info("CRYSTALS-Kyber-768")
        self.assertIsNotNone(kyber)
        self.assertTrue(kyber.quantum_safe)
        self.assertTrue(kyber.recommended)
        self.assertEqual(kyber.nist_level, NISTSecurityLevel.LEVEL_3)
    
    def test_dilithium3_is_recommended(self):
        """Verify Dilithium-3 is recommended quantum-safe"""
        dilithium = self.catalog.get_algorithm_info("CRYSTALS-Dilithium-3")
        self.assertIsNotNone(dilithium)
        self.assertTrue(dilithium.quantum_safe)
        self.assertTrue(dilithium.recommended)
        self.assertEqual(dilithium.nist_level, NISTSecurityLevel.LEVEL_3)
    
    def test_module_docs_have_quantum_migration_notes(self):
        """Verify modules have quantum migration guidance"""
        for module_name in ["post_quantum", "classical_crypto", "hybrid_signature", "key_management"]:
            docs = self.catalog.get_module_docs(module_name)
            self.assertIsNotNone(docs)
            self.assertGreater(
                len(docs.quantum_migration_notes.strip()), 0,
                f"Module {module_name} missing quantum migration notes"
            )
    
    def test_endpoints_have_quantum_readiness(self):
        """Verify all crypto endpoints have quantum readiness marker"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                self.assertIn(
                    endpoint.quantum_readiness,
                    ["PQ_ONLY", "HYBRID", "CLASSICAL", "QUANTUM_RESISTANT", "APPLICABLE"],
                    f"Endpoint {endpoint.name} invalid quantum_readiness"
                )
    
    def test_post_quantum_endpoints_pq_only(self):
        """Verify PQ module endpoints marked PQ_ONLY"""
        docs = self.catalog.get_module_docs("post_quantum")
        for endpoint in docs.endpoints:
            self.assertEqual(
                endpoint.quantum_readiness, "PQ_ONLY",
                f"PQ endpoint {endpoint.name} should be PQ_ONLY"
            )
    
    def test_print_stability_report(self):
        """Test stability report generation"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            self.catalog.print_stability_report()
        
        output = f.getvalue()
        self.assertIn("QUANTUMCRYPT-AI API STABILITY REPORT", output)
        self.assertIn("Kyber", output)
        self.assertIn("Dilithium", output)
        self.assertIn("QUANTUM READINESS GUIDANCE", output)
    
    def test_print_quantum_readiness_guide(self):
        """Test quantum readiness guide generation"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            self.catalog.print_quantum_readiness_guide()
        
        output = f.getvalue()
        self.assertIn("POST-QUANTUM MIGRATION READINESS GUIDE", output)
        self.assertIn("PHASE 1", output)
        self.assertIn("PHASE 2", output)
        self.assertIn("PHASE 3", output)
        self.assertIn("Kyber-768", output)
        self.assertIn("Dilithium-3", output)


class TestPostQuantumDocumentation(unittest.TestCase):
    """Specific tests for post-quantum module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("post_quantum")
    
    def test_pq_endpoints_exist(self):
        """Verify PQ endpoints are documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("Kyber" in name for name in endpoint_names))
        self.assertTrue(any("Dilithium" in name for name in endpoint_names))
    
    def test_all_pq_stable(self):
        """All PQ endpoints should be STABLE"""
        for endpoint in self.docs.endpoints:
            self.assertEqual(
                endpoint.stability, StabilityLevel.STABLE,
                f"PQ endpoint {endpoint.name} should be STABLE"
            )


class TestHybridSignatureDocumentation(unittest.TestCase):
    """Specific tests for hybrid signature module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("hybrid_signature")
    
    def test_hybrid_endpoints(self):
        """Verify hybrid endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("verify" in name for name in endpoint_names))
        self.assertTrue(any("recommend" in name for name in endpoint_names))


class TestSecurityHardeningDocumentation(unittest.TestCase):
    """Specific tests for security hardening module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("security_hardening")
    
    def test_security_endpoints(self):
        """Verify security endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("constant_time_compare" in name for name in endpoint_names))
        self.assertTrue(any("secure_zeroize" in name for name in endpoint_names))


class TestDocumentationQuality(unittest.TestCase):
    """Quality tests for documentation"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
    
    def test_all_modules_have_overview(self):
        """Verify all modules have overview"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(len(docs.overview.strip()), 0)
    
    def test_all_modules_have_getting_started(self):
        """Verify all modules have getting started guide"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(len(docs.getting_started.strip()), 0)
    
    def test_all_modules_have_best_practices(self):
        """Verify all modules have best practices"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(len(docs.best_practices), 0)
    
    def test_all_modules_have_common_pitfalls(self):
        """Verify all modules have common pitfalls"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(len(docs.common_pitfalls), 0)
    
    def test_algorithms_have_key_sizes(self):
        """Verify all algorithms have key size information"""
        for algo_name in self.catalog.get_all_algorithms():
            algo = self.catalog.get_algorithm_info(algo_name)
            self.assertGreater(len(algo.key_sizes), 0)
            self.assertGreater(len(algo.performance_notes), 0)


class TestSingletonPattern(unittest.TestCase):
    """Test singleton catalog instance"""
    
    def test_singleton_returns_same_instance(self):
        """Verify singleton pattern works"""
        cat1 = get_documentation_catalog()
        cat2 = get_documentation_catalog()
        self.assertIs(cat1, cat2)


class TestPrintFunctions(unittest.TestCase):
    """Test convenience print functions"""
    
    def test_print_api_stability_report(self):
        """Test print function works"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print_api_stability_report()
        
        output = f.getvalue()
        self.assertIn("API STABILITY REPORT", output)
    
    def test_print_quantum_readiness_guide(self):
        """Test quantum readiness guide function"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print_quantum_readiness_guide()
        
        output = f.getvalue()
        self.assertIn("MIGRATION PATH", output)


class TestApiStabilityMarkers(unittest.TestCase):
    """Test module-level API stability markers"""
    
    def test_all_exports_have_stability(self):
        """Verify all exports have stability markers"""
        import crypto_documentation_api_stability_master_catalog_v30_2026_june as module
        for export in module.__all__:
            self.assertIn(
                export, __api_stability__,
                f"Export {export} missing stability marker"
            )
    
    def test_all_markers_are_stable(self):
        """Verify all markers are STABLE"""
        for name, marker in __api_stability__.items():
            self.assertEqual(
                marker, "STABLE",
                f"Export {name} should be STABLE"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
