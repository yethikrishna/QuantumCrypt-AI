#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Multi-Party Computation Engine
Production-grade tests with real cryptographic validation.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
from post_quantum_secure_multi_party_computation_2026_june import (
    SecureMultiPartyComputation,
    ShamirSecretSharing,
    PrimeField,
    VerifiableCommitment,
    SecurityLevel,
    OperationType,
    Share
)


class TestPrimeField(unittest.TestCase):
    """Test PrimeField arithmetic operations"""
    
    def test_addition(self):
        """Test field addition"""
        field = PrimeField(SecurityLevel.AES_128)
        result = field.add(5, 10)
        self.assertEqual(result, 15)
    
    def test_multiplication(self):
        """Test field multiplication"""
        field = PrimeField(SecurityLevel.AES_128)
        result = field.mul(5, 10)
        self.assertEqual(result, 50)
    
    def test_modular_inverse(self):
        """Test modular inverse"""
        field = PrimeField(SecurityLevel.AES_128)
        a = 42
        a_inv = field.inv(a)
        result = field.mul(a, a_inv)
        self.assertEqual(result, 1)
    
    def test_division(self):
        """Test field division"""
        field = PrimeField(SecurityLevel.AES_128)
        # 10 / 2 = 5
        result = field.div(10, 2)
        self.assertEqual(result, 5)
    
    def test_security_level_primes(self):
        """Test different security levels have different primes"""
        field128 = PrimeField(SecurityLevel.AES_128)
        field256 = PrimeField(SecurityLevel.AES_256)
        
        self.assertGreater(field256.prime, field128.prime)
        self.assertGreater(field256.prime.bit_length(), 500)


class TestVerifiableCommitment(unittest.TestCase):
    """Test Pedersen commitment scheme"""
    
    def test_commit_and_verify(self):
        """Test commitment creation and verification"""
        field = PrimeField(SecurityLevel.AES_128)
        committer = VerifiableCommitment(field)
        
        value = 42
        commitment, randomness = committer.commit(value)
        
        # Should verify correctly
        self.assertTrue(committer.verify(value, randomness, commitment))
        
        # Should fail with wrong value
        self.assertFalse(committer.verify(43, randomness, commitment))
        
        # Should fail with wrong randomness
        self.assertFalse(committer.verify(value, randomness + 1, commitment))


class TestShamirSecretSharing(unittest.TestCase):
    """Test Shamir's Secret Sharing implementation"""
    
    def test_basic_split_and_reconstruct(self):
        """Test basic secret splitting and reconstruction"""
        sss = ShamirSecretSharing(threshold=3, num_parties=5)
        secret = 12345
        
        shares, _ = sss.split_secret(secret)
        
        # Need exactly threshold shares to reconstruct
        reconstructed = sss.reconstruct_secret(shares[:3])
        self.assertEqual(reconstructed, secret)
    
    def test_insufficient_shares_fails(self):
        """Test reconstruction fails with insufficient shares"""
        sss = ShamirSecretSharing(threshold=3, num_parties=5)
        secret = 12345
        
        shares, _ = sss.split_secret(secret)
        
        # Should raise error with only 2 shares
        with self.assertRaises(ValueError):
            sss.reconstruct_secret(shares[:2])
    
    def test_different_share_combinations(self):
        """Test different combinations of shares all work"""
        sss = ShamirSecretSharing(threshold=3, num_parties=5)
        secret = 99999
        
        shares, _ = sss.split_secret(secret)
        
        # Different combinations should all work
        self.assertEqual(sss.reconstruct_secret(shares[0:3]), secret)
        self.assertEqual(sss.reconstruct_secret(shares[1:4]), secret)
        self.assertEqual(sss.reconstruct_secret(shares[2:5]), secret)
        self.assertEqual(sss.reconstruct_secret([shares[0], shares[2], shares[4]]), secret)
    
    def test_large_secret(self):
        """Test with large secret values"""
        sss = ShamirSecretSharing(threshold=2, num_parties=3)
        
        # Test with various secret sizes
        for secret in [0, 1, 1000, 10**6, 2**100]:
            if secret < sss.field.prime:
                shares, _ = sss.split_secret(secret)
                reconstructed = sss.reconstruct_secret(shares[:2])
                self.assertEqual(reconstructed, secret)
    
    def test_invalid_threshold(self):
        """Test invalid threshold raises error"""
        with self.assertRaises(ValueError):
            ShamirSecretSharing(threshold=1, num_parties=5)
        
        with self.assertRaises(ValueError):
            ShamirSecretSharing(threshold=6, num_parties=5)
    
    def test_secret_out_of_range(self):
        """Test secret out of field range raises error"""
        sss = ShamirSecretSharing(threshold=2, num_parties=3)
        
        with self.assertRaises(ValueError):
            sss.split_secret(-1)
        
        with self.assertRaises(ValueError):
            sss.split_secret(sss.field.prime)


class TestSecureMultiPartyComputation(unittest.TestCase):
    """Test SMPC engine operations"""
    
    def test_secure_addition(self):
        """Test secure addition operation"""
        smpc = SecureMultiPartyComputation(threshold=3, num_parties=5)
        
        a = 42
        b = 58
        result = smpc.secure_add(a, b)
        
        self.assertEqual(result.value, (a + b) % smpc.field.prime)
        self.assertEqual(result.operation, OperationType.ADDITION)
        self.assertTrue(result.verification_success)
        self.assertGreater(result.computation_time_ms, 0)
    
    def test_secure_multiplication(self):
        """Test secure multiplication operation"""
        smpc = SecureMultiPartyComputation(threshold=3, num_parties=5)
        
        a = 7
        b = 8
        result = smpc.secure_mul(a, b)
        
        self.assertEqual(result.value, (a * b) % smpc.field.prime)
        self.assertEqual(result.operation, OperationType.MULTIPLICATION)
        self.assertTrue(result.verification_success)
    
    def test_secure_xor(self):
        """Test secure XOR operation"""
        smpc = SecureMultiPartyComputation(threshold=2, num_parties=3)
        
        a = 0b1010
        b = 0b1100
        result = smpc.secure_xor(a, b)
        
        self.assertEqual(result.value, a ^ b)
        self.assertEqual(result.operation, OperationType.XOR)
    
    def test_multiple_operations(self):
        """Test multiple operations in sequence"""
        smpc = SecureMultiPartyComputation(threshold=2, num_parties=3)
        
        # (a + b) * c
        a = 10
        b = 20
        c = 5
        
        add_result = smpc.secure_add(a, b)
        mul_result = smpc.secure_mul(add_result.value, c)
        
        expected = ((a + b) * c) % smpc.field.prime
        self.assertEqual(mul_result.value, expected)
    
    def test_distributed_key_generation(self):
        """Test distributed key generation"""
        smpc = SecureMultiPartyComputation(threshold=3, num_parties=5)
        
        shares, commitment = smpc.distributed_key_generation()
        
        self.assertEqual(len(shares), 5)
        self.assertIsInstance(commitment, int)
        
        # Can reconstruct key from threshold shares
        key = smpc.sss.reconstruct_secret(shares[:3])
        self.assertIsInstance(key, int)
    
    def test_different_security_levels(self):
        """Test SMPC works with different security levels"""
        for level in [SecurityLevel.AES_128, SecurityLevel.AES_256]:
            smpc = SecureMultiPartyComputation(
                threshold=2, 
                num_parties=3,
                security_level=level
            )
            
            result = smpc.secure_add(10, 20)
            self.assertEqual(result.security_level, level)
            self.assertTrue(result.verification_success)
    
    def test_statistics_tracking(self):
        """Test statistics are properly tracked"""
        smpc = SecureMultiPartyComputation(threshold=2, num_parties=3)
        
        initial_stats = smpc.get_statistics()
        self.assertEqual(initial_stats["total_operations"], 0)
        
        smpc.secure_add(1, 2)
        smpc.secure_mul(3, 4)
        
        stats = smpc.get_statistics()
        self.assertEqual(stats["total_operations"], 2)
        self.assertEqual(stats["successful_operations"], 2)
        self.assertEqual(stats["success_rate"], 100.0)
    
    def test_security_report(self):
        """Test security report generation"""
        smpc = SecureMultiPartyComputation(threshold=3, num_parties=5)
        
        smpc.secure_add(10, 20)
        smpc.secure_mul(5, 6)
        
        report = smpc.generate_security_report()
        self.assertIsInstance(report, str)
        self.assertIn("statistics", report)
        self.assertIn("security_analysis", report)
        self.assertIn("quantum_resistance", report)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print(f"{'='*60}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
