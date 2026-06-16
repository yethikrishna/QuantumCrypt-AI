"""
Test Suite for FIPS 205 SLH-DSA - June 2026
Tests for SPHINCS+ implementation and NIST Round 3 signatures
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
import time
from quantum_crypt.fips_205_slhdsa_2026 import (
    SLHDSA, SLHDSAParameterSet, NISTRound3Signatures2026,
    get_slhdsa_compliance_report
)


class TestSLHDSA(unittest.TestCase):
    """Test cases for SLH-DSA (SPHINCS+)"""
    
    def test_keygen_128f(self):
        """Test key generation for SLH-DSA-SHA2-128f"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        
        self.assertEqual(len(keypair.public_key), 32)
        self.assertEqual(len(keypair.private_key), 64)
        self.assertEqual(keypair.parameter_set, SLHDSAParameterSet.SHA2_128F)
    
    def test_keygen_256f(self):
        """Test key generation for SLH-DSA-SHA2-256f"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_256F)
        keypair = slhdsa.keygen()
        
        self.assertEqual(len(keypair.public_key), 64)
        self.assertEqual(len(keypair.private_key), 128)
    
    def test_sign_verify_deterministic(self):
        """Test deterministic sign and verify"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        
        message = b"Test message for SLH-DSA signing June 2026"
        signature = slhdsa.sign(message, keypair.private_key, deterministic=True)
        
        # Verify signature
        is_valid = slhdsa.verify(message, signature, keypair.public_key)
        self.assertTrue(is_valid)
    
    def test_sign_verify_randomized(self):
        """Test randomized sign and verify"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        
        message = b"Randomized test message"
        signature = slhdsa.sign(message, keypair.private_key, deterministic=False)
        
        is_valid = slhdsa.verify(message, signature, keypair.public_key)
        self.assertTrue(is_valid)
    
    def test_wrong_message_fails(self):
        """Test verification fails with wrong message"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        
        message = b"Original message"
        signature = slhdsa.sign(message, keypair.private_key)
        
        wrong_message = b"Tampered message"
        is_valid = slhdsa.verify(wrong_message, signature, keypair.public_key)
        self.assertFalse(is_valid)
    
    def test_wrong_signature_size(self):
        """Test verification fails with wrong signature size"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        
        message = b"Test message"
        is_valid = slhdsa.verify(message, b"wrong size", keypair.public_key)
        self.assertFalse(is_valid)
    
    def test_parameter_sets(self):
        """Test all parameter sets work"""
        for param_set in SLHDSAParameterSet:
            slhdsa = SLHDSA(param_set)
            keypair = slhdsa.keygen()
            message = b"Test across all parameter sets"
            signature = slhdsa.sign(message, keypair.private_key)
            is_valid = slhdsa.verify(message, signature, keypair.public_key)
            self.assertTrue(is_valid, f"Failed for {param_set.value}")


class TestNISTRound3Signatures(unittest.TestCase):
    """Test cases for NIST Round 3 Additional Signatures"""
    
    def test_mayo_algorithm(self):
        """Test MAYO algorithm"""
        pqc = NISTRound3Signatures2026()
        pk, sk = pqc.generate_keypair("MAYO", security_level=1)
        
        message = b"Test MAYO signature"
        signature = pqc.sign(message, sk, "MAYO")
        is_valid = pqc.verify(message, signature, pk, "MAYO")
        
        self.assertTrue(is_valid)
    
    def test_faest_algorithm(self):
        """Test FAEST algorithm"""
        pqc = NISTRound3Signatures2026()
        pk, sk = pqc.generate_keypair("FAEST", security_level=3)
        
        message = b"Test FAEST signature June 2026"
        signature = pqc.sign(message, sk, "FAEST")
        is_valid = pqc.verify(message, signature, pk, "FAEST")
        
        self.assertTrue(is_valid)
    
    def test_sqisign_algorithm(self):
        """Test SQIsign algorithm"""
        pqc = NISTRound3Signatures2026()
        pk, sk = pqc.generate_keypair("SQIsign", security_level=5)
        
        message = b"Test SQIsign isogeny-based signature"
        signature = pqc.sign(message, sk, "SQIsign")
        is_valid = pqc.verify(message, signature, pk, "SQIsign")
        
        self.assertTrue(is_valid)
    
    def test_invalid_algorithm(self):
        """Test invalid algorithm raises error"""
        pqc = NISTRound3Signatures2026()
        with self.assertRaises(ValueError):
            pqc.generate_keypair("INVALID_ALG")


class TestPerformanceBenchmark(unittest.TestCase):
    """Performance benchmark tests"""
    
    def test_slhdsa_performance(self):
        """Benchmark SLH-DSA performance"""
        slhdsa = SLHDSA(SLHDSAParameterSet.SHA2_128F)
        keypair = slhdsa.keygen()
        message = b"Performance benchmark test message June 2026"
        
        # Keygen benchmark
        start = time.perf_counter()
        for _ in range(10):
            slhdsa.keygen()
        keygen_time = time.perf_counter() - start
        
        # Sign benchmark
        start = time.perf_counter()
        for _ in range(5):
            slhdsa.sign(message, keypair.private_key)
        sign_time = time.perf_counter() - start
        
        # Verify benchmark
        signature = slhdsa.sign(message, keypair.private_key)
        start = time.perf_counter()
        for _ in range(5):
            slhdsa.verify(message, signature, keypair.public_key)
        verify_time = time.perf_counter() - start
        
        print(f"\nSLH-DSA Performance Benchmark:")
        print(f"  Keygen (10 ops): {keygen_time*1000:.2f}ms")
        print(f"  Sign (5 ops): {sign_time*1000:.2f}ms")
        print(f"  Verify (5 ops): {verify_time*1000:.2f}ms")
        
        # All operations should complete within reasonable time
        self.assertLess(keygen_time, 5.0)
        self.assertLess(sign_time, 5.0)
        self.assertLess(verify_time, 5.0)


class TestComplianceReport(unittest.TestCase):
    """Test compliance report"""
    
    def test_compliance_report(self):
        """Test compliance report generation"""
        report = get_slhdsa_compliance_report()
        
        self.assertTrue(report['fips_205_implemented'])
        self.assertEqual(report['fips_205_name'], "SLH-DSA (SPHINCS+)")
        self.assertIn(1, report['security_levels_supported'])
        self.assertIn(3, report['security_levels_supported'])
        self.assertIn(5, report['security_levels_supported'])
        self.assertIn("MAYO", report['nist_round3_candidates'])
        self.assertIn("FAEST", report['nist_round3_candidates'])


def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("Running FIPS 205 SLH-DSA Tests - June 2026")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSLHDSA))
    suite.addTests(loader.loadTestsFromTestCase(TestNISTRound3Signatures))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceBenchmark))
    suite.addTests(loader.loadTestsFromTestCase(TestComplianceReport))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 60)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Tests Failed: {len(result.failures)}")
    print(f"Tests Errors: {len(result.errors)}")
    print("=" * 60)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
