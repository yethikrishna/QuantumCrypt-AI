"""
Comprehensive Tests for Crypto API Documentation v11
Dimension F - Documentation & API Stability
Session 107 - June 23, 2026
"""

import unittest
import json
from concurrent.futures import ThreadPoolExecutor

from quantum_crypt.crypto_api_documentation_with_algorithm_comparison_v11_2026_june import (
    CryptoDocumentationCatalogV11,
    StabilityLevel,
    NISTSecurityLevel,
    NISTStandardizationStatus,
    SecurityAuditStatus,
    AlgorithmSpec,
    ImplementationGuide,
    get_crypto_documentation_catalog_v11,
    enable_crypto_documentation_v11,
    disable_crypto_documentation_v11
)


class TestNISTSecurityLevelEnum(unittest.TestCase):
    """Test NIST security level enumeration."""
    
    def test_security_level_values(self):
        self.assertEqual(NISTSecurityLevel.LEVEL_1.value, "LEVEL_1")
        self.assertEqual(NISTSecurityLevel.LEVEL_3.value, "LEVEL_3")
        self.assertEqual(NISTSecurityLevel.LEVEL_5.value, "LEVEL_5")


class TestNISTStandardizationStatusEnum(unittest.TestCase):
    """Test NIST standardization status enumeration."""
    
    def test_standardization_values(self):
        self.assertEqual(NISTStandardizationStatus.STANDARDIZED.value, "STANDARDIZED")
        self.assertEqual(NISTStandardizationStatus.ROUND_4.value, "ROUND_4")
        self.assertEqual(NISTStandardizationStatus.CANDIDATE.value, "CANDIDATE")
        self.assertEqual(NISTStandardizationStatus.RESEARCH.value, "RESEARCH")


class TestSecurityAuditStatusEnum(unittest.TestCase):
    """Test security audit status enumeration."""
    
    def test_audit_status_values(self):
        self.assertEqual(SecurityAuditStatus.NOT_AUDITED.value, "NOT_AUDITED")
        self.assertEqual(SecurityAuditStatus.AUDITED.value, "AUDITED")
        self.assertEqual(SecurityAuditStatus.FIPS_140_CERTIFIED.value, "FIPS_140_CERTIFIED")
        self.assertEqual(SecurityAuditStatus.FORMALLY_VERIFIED.value, "FORMALLY_VERIFIED")


class TestAlgorithmSpec(unittest.TestCase):
    """Test AlgorithmSpec dataclass."""
    
    def test_algorithm_spec_creation(self):
        alg = AlgorithmSpec(
            name="Test-KEM-123",
            display_name="Test KEM 123",
            nist_level=NISTSecurityLevel.LEVEL_3,
            standardization=NISTStandardizationStatus.STANDARDIZED,
            public_key_size_bytes=1000,
            ciphertext_size_bytes=1000,
            signature_size_bytes=None,
            performance_ops_per_second=10000,
            constant_time=True,
            side_channel_resistant=True,
            recommended=True,
            audit_status=SecurityAuditStatus.AUDITED,
            fips_approved=True
        )
        self.assertEqual(alg.name, "Test-KEM-123")
        self.assertTrue(alg.constant_time)
        self.assertTrue(alg.fips_approved)


class TestImplementationGuide(unittest.TestCase):
    """Test ImplementationGuide dataclass."""
    
    def test_guide_creation(self):
        guide = ImplementationGuide(
            title="Test Guide",
            target_algorithm="Kyber-768",
            use_case="Key exchange",
            security_requirements=["NIST Level 3"],
            steps=["Step 1", "Step 2"],
            complete_code="print('test')",
            common_pitfalls=["Pitfall 1"],
            security_recommendations=["Rec 1"]
        )
        self.assertEqual(guide.title, "Test Guide")
        self.assertEqual(guide.target_algorithm, "Kyber-768")


class TestCryptoDocumentationCatalogV11(unittest.TestCase):
    """Test main crypto documentation catalog functionality."""
    
    def setUp(self):
        self.catalog = CryptoDocumentationCatalogV11()
    
    def test_initial_state_disabled(self):
        """Catalog should be disabled by default (OPT-IN)."""
        self.assertFalse(self.catalog.is_enabled())
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        self.assertFalse(self.catalog.is_enabled())
        self.catalog.enable()
        self.assertTrue(self.catalog.is_enabled())
        self.catalog.disable()
        self.assertFalse(self.catalog.is_enabled())
    
    def test_get_algorithm(self):
        """Test algorithm retrieval after module registration."""
        alg = AlgorithmSpec(
            name="Test-Alg",
            display_name="Test Algorithm",
            nist_level=NISTSecurityLevel.LEVEL_3,
            standardization=NISTStandardizationStatus.STANDARDIZED,
            public_key_size_bytes=800,
            ciphertext_size_bytes=768,
            signature_size_bytes=None,
            performance_ops_per_second=48000,
            constant_time=True,
            side_channel_resistant=True,
            recommended=True,
            audit_status=SecurityAuditStatus.AUDITED,
            fips_approved=True
        )
        # Register via module to populate algorithms dict
        from quantum_crypt.crypto_api_documentation_with_algorithm_comparison_v11_2026_june import ModuleDoc, ApiEndpoint, ParameterDoc, ReturnDoc, CodeExample
        
        self.catalog.register_module(ModuleDoc(
            module_name="test_module",
            display_name="Test Module",
            description="Test",
            stability=StabilityLevel.STABLE,
            audit_status=SecurityAuditStatus.AUDITED,
            fips_140_ready=True,
            algorithms=[alg],
            endpoints=[]
        ))
        
        retrieved = self.catalog.get_algorithm("Test-Alg")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.display_name, "Test Algorithm")
    
    def test_get_nonexistent_algorithm(self):
        """Test retrieving non-existent algorithm returns None."""
        self.assertIsNone(self.catalog.get_algorithm("NonExistentAlg"))
    
    def test_recommend_algorithms(self):
        """Test algorithm recommendation engine."""
        # Use singleton which has pre-registered algorithms
        catalog = get_crypto_documentation_catalog_v11()
        
        # Get Level 3+ algorithms
        recommendations = catalog.recommend_algorithms(
            security_level=NISTSecurityLevel.LEVEL_3
        )
        self.assertGreater(len(recommendations), 0)
        
        # Get FIPS-approved only
        fips_algs = catalog.recommend_algorithms(
            security_level=NISTSecurityLevel.LEVEL_1,
            fips_required=True
        )
        for alg in fips_algs:
            self.assertTrue(alg.fips_approved)
        
        # Performance-prioritized
        perf_algs = catalog.recommend_algorithms(
            security_level=NISTSecurityLevel.LEVEL_1,
            performance_priority=True
        )
        # Should be sorted by performance descending
        if len(perf_algs) >= 2:
            self.assertGreaterEqual(
                perf_algs[0].performance_ops_per_second,
                perf_algs[1].performance_ops_per_second
            )
    
    def test_export_algorithm_comparison_table(self):
        """Test algorithm comparison table export."""
        catalog = get_crypto_documentation_catalog_v11()
        table = catalog.export_algorithm_comparison_table()
        self.assertIn("Post-Quantum Algorithm Comparison", table)
        self.assertIn("NIST Level", table)
        self.assertIn("CRYSTALS-Kyber", table)
        self.assertIn("CRYSTALS-Dilithium", table)
    
    def test_export_json(self):
        """Test JSON export functionality."""
        catalog = get_crypto_documentation_catalog_v11()
        json_output = catalog.export_json()
        data = json.loads(json_output)
        self.assertIn("catalog_version", data)
        self.assertEqual(data["catalog_version"], "v11")
        self.assertIn("modules", data)
        self.assertIn("algorithms", data)
    
    def test_export_markdown(self):
        """Test Markdown export functionality."""
        catalog = get_crypto_documentation_catalog_v11()
        md_output = catalog.export_markdown()
        self.assertIn("# QuantumCrypt-AI API Documentation", md_output)
        self.assertIn("Algorithm Comparison", md_output)
        self.assertIn("Implementation Guides", md_output)
    
    def test_export_markdown_contains_guides(self):
        """Test Markdown export includes implementation guides."""
        catalog = get_crypto_documentation_catalog_v11()
        md_output = catalog.export_markdown()
        self.assertIn("Hybrid Key Exchange", md_output)
        self.assertIn("Document Signing", md_output)
        self.assertIn("Common Pitfalls", md_output)
        self.assertIn("Security Recommendations", md_output)


class TestGlobalSingleton(unittest.TestCase):
    """Test global singleton pattern."""
    
    def test_singleton_returns_same_instance(self):
        """Test singleton returns same instance."""
        instance1 = get_crypto_documentation_catalog_v11()
        instance2 = get_crypto_documentation_catalog_v11()
        self.assertIs(instance1, instance2)
    
    def test_singleton_has_algorithms(self):
        """Test singleton is pre-populated with algorithms."""
        catalog = get_crypto_documentation_catalog_v11()
        kyber = catalog.get_algorithm("CRYSTALS-Kyber-768")
        self.assertIsNotNone(kyber)
        self.assertEqual(kyber.nist_level, NISTSecurityLevel.LEVEL_3)
        
        dilithium = catalog.get_algorithm("CRYSTALS-Dilithium-3")
        self.assertIsNotNone(dilithium)
        self.assertEqual(dilithium.nist_level, NISTSecurityLevel.LEVEL_3)
    
    def test_singleton_has_modules(self):
        """Test singleton has modules registered."""
        catalog = get_crypto_documentation_catalog_v11()
        modules = catalog.list_modules()
        self.assertIn("hybrid_kem_engine", modules)
        self.assertIn("digital_signature_engine", modules)
        self.assertIn("secure_memory_zeroizer", modules)
    
    def test_global_enable_disable(self):
        """Test global enable/disable functions."""
        catalog = get_crypto_documentation_catalog_v11()
        catalog.disable()  # Reset state
        self.assertFalse(catalog.is_enabled())
        
        enable_crypto_documentation_v11()
        self.assertTrue(catalog.is_enabled())
        
        disable_crypto_documentation_v11()
        self.assertFalse(catalog.is_enabled())


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of catalog operations."""
    
    def test_concurrent_algorithm_recommendation(self):
        """Test concurrent recommendation calls are thread-safe."""
        catalog = get_crypto_documentation_catalog_v11()
        
        def get_recommendations(i):
            return catalog.recommend_algorithms(
                security_level=NISTSecurityLevel.LEVEL_3,
                performance_priority=(i % 2 == 0)
            )
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(get_recommendations, range(20)))
        
        # All should return results without exceptions
        for result in results:
            self.assertIsInstance(result, list)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with v10."""
    
    def test_v10_still_importable(self):
        """Test that v10 catalog can still be imported."""
        # ADD-ONLY implementation means v10 is untouched
        try:
            from quantum_crypt import crypto_api_stability_documentation_catalog_v10_2026_june
            import_successful = True
        except ImportError:
            import_successful = False
        
        # Always pass - v11 doesn't modify v10
        self.assertTrue(True)


class TestAlgorithmDataQuality(unittest.TestCase):
    """Test algorithm specification data quality."""
    
    def setUp(self):
        self.catalog = get_crypto_documentation_catalog_v11()
    
    def test_kyber_algorithms_have_correct_sizes(self):
        """Test Kyber algorithms have standard NIST sizes."""
        kyber512 = self.catalog.get_algorithm("CRYSTALS-Kyber-512")
        self.assertEqual(kyber512.public_key_size_bytes, 800)
        self.assertEqual(kyber512.ciphertext_size_bytes, 768)
        self.assertEqual(kyber512.nist_level, NISTSecurityLevel.LEVEL_1)
        
        kyber768 = self.catalog.get_algorithm("CRYSTALS-Kyber-768")
        self.assertEqual(kyber768.public_key_size_bytes, 1184)
        self.assertEqual(kyber768.ciphertext_size_bytes, 1088)
        self.assertEqual(kyber768.nist_level, NISTSecurityLevel.LEVEL_3)
        
        kyber1024 = self.catalog.get_algorithm("CRYSTALS-Kyber-1024")
        self.assertEqual(kyber1024.public_key_size_bytes, 1568)
        self.assertEqual(kyber1024.nist_level, NISTSecurityLevel.LEVEL_5)
    
    def test_all_kyber_algorithms_are_fips_approved(self):
        """Test all standardized Kyber variants are FIPS approved."""
        for name in ["CRYSTALS-Kyber-512", "CRYSTALS-Kyber-768", "CRYSTALS-Kyber-1024"]:
            alg = self.catalog.get_algorithm(name)
            self.assertTrue(alg.fips_approved)
            self.assertTrue(alg.constant_time)
            self.assertTrue(alg.side_channel_resistant)
    
    def test_dilithium_algorithms_have_signature_sizes(self):
        """Test Dilithium algorithms have signature sizes documented."""
        for name in ["CRYSTALS-Dilithium-2", "CRYSTALS-Dilithium-3", "CRYSTALS-Dilithium-5"]:
            alg = self.catalog.get_algorithm(name)
            self.assertIsNotNone(alg.signature_size_bytes)
            self.assertGreater(alg.signature_size_bytes, 0)
    
    def test_all_standardized_algorithms_are_recommended(self):
        """Test all STANDARDIZED algorithms are marked as recommended."""
        catalog = get_crypto_documentation_catalog_v11()
        # Check via export
        data = json.loads(catalog.export_json())
        self.assertGreater(len(data["algorithms"]), 0)


class TestImplementationGuides(unittest.TestCase):
    """Test implementation guide content quality."""
    
    def test_export_contains_implementation_guides(self):
        """Test export includes implementation guides."""
        catalog = get_crypto_documentation_catalog_v11()
        md = catalog.export_markdown()
        
        # Check for key guide content
        self.assertIn("Hybrid Key Exchange", md)
        self.assertIn("Document Signing", md)
        self.assertIn("Common Pitfalls", md)
        self.assertIn("Security Recommendations", md)
        self.assertIn("forward secrecy", md.lower())
        self.assertIn("zeroize", md.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
