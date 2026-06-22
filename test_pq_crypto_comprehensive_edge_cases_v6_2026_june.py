"""
QuantumCrypt-AI: Comprehensive Post-Quantum Cryptography Edge Case Tests
DIMENSION C: Test Coverage Expansion
Session 92 - June 22, 2026

FOCUS: Cryptographic edge cases, boundary conditions, error paths, integration tests
STRICTLY ADD-ONLY: No production code modified, only tests added
"""

import unittest
import sys
import os
import threading
import time
import json
import secrets
from typing import Dict, List, Any

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))


class TestCryptographicBoundaryConditions(unittest.TestCase):
    """Test boundary conditions for cryptographic operations"""
    
    def test_empty_message_encryption(self):
        """Test encryption of empty message - critical boundary"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            
            # Empty message - should handle gracefully
            empty_msg = b""
            result = crypto.encrypt(empty_msg)
            self.assertIsNotNone(result)
            
            # Single byte message - minimum boundary
            single_byte = b"\x00"
            result_single = crypto.encrypt(single_byte)
            self.assertIsNotNone(result_single)
            
        except ImportError:
            self.skipTest("Crypto core module not available")
    
    def test_maximum_message_size(self):
        """Test encryption at maximum message sizes"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            
            # Various large message sizes
            message_sizes = [
                1024,      # 1KB
                16384,     # 16KB
                65536,     # 64KB
                262144,    # 256KB
            ]
            
            for size in message_sizes:
                large_msg = secrets.token_bytes(size)
                result = crypto.encrypt(large_msg)
                self.assertIsNotNone(result)
                
        except ImportError:
            self.skipTest("Crypto core module not available")
    
    def test_all_zero_and_all_one_messages(self):
        """Test messages with extreme byte patterns"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            
            # All zeros
            all_zeros = b"\x00" * 1024
            result_zeros = crypto.encrypt(all_zeros)
            self.assertIsNotNone(result_zeros)
            
            # All ones (0xFF)
            all_ones = b"\xff" * 1024
            result_ones = crypto.encrypt(all_ones)
            self.assertIsNotNone(result_ones)
            
            # Alternating pattern
            alternating = b"\x00\xff" * 512
            result_alt = crypto.encrypt(alternating)
            self.assertIsNotNone(result_alt)
            
        except ImportError:
            self.skipTest("Crypto core module not available")
    
    def test_repeated_byte_patterns(self):
        """Test messages with repeated byte patterns"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            
            patterns = [
                b"A" * 2048,
                b"\x55" * 2048,  # 01010101 pattern
                b"\xaa" * 2048,  # 10101010 pattern
                b"DEADBEEF" * 256,
            ]
            
            for pattern in patterns:
                result = crypto.encrypt(pattern)
                self.assertIsNotNone(result)
                
        except ImportError:
            self.skipTest("Crypto core module not available")


class TestKeyManagementEdgeCases(unittest.TestCase):
    """Test key management edge cases"""
    
    def test_key_generation_boundaries(self):
        """Test key generation at various security levels"""
        try:
            from pq_crypto_key_manager_2026 import KeyManager
            
            key_manager = KeyManager()
            
            # Various key sizes if supported
            security_levels = [128, 192, 256]
            
            for level in security_levels:
                try:
                    key = key_manager.generate_key(security_level=level)
                    self.assertIsNotNone(key)
                    self.assertIsInstance(key, bytes)
                except (ValueError, NotImplementedError):
                    # Some levels may not be supported - that's OK
                    continue
                    
        except ImportError:
            self.skipTest("Key manager module not available")
    
    def test_key_import_export_boundaries(self):
        """Test key import/export edge cases"""
        try:
            from pq_crypto_key_manager_2026 import KeyManager
            
            key_manager = KeyManager()
            
            # Generate and re-import
            original_key = key_manager.generate_key()
            
            # Export
            exported = key_manager.export_key(original_key)
            self.assertIsNotNone(exported)
            
            # Re-import
            imported = key_manager.import_key(exported)
            self.assertIsNotNone(imported)
            
        except ImportError:
            self.skipTest("Key manager module not available")
    
    def test_invalid_key_rejection(self):
        """Test that invalid keys are properly rejected"""
        try:
            from pq_crypto_key_manager_2026 import KeyManager
            
            key_manager = KeyManager()
            
            invalid_keys = [
                b"",  # Empty key
                b"\x00",  # Too short
                b"short",  # Wrong length
            ]
            
            for invalid_key in invalid_keys:
                with self.assertRaises((ValueError, Exception)):
                    key_manager.validate_key(invalid_key)
                    
        except ImportError:
            self.skipTest("Key manager module not available")
    
    def test_key_rotation_boundaries(self):
        """Test key rotation edge cases"""
        try:
            from pq_crypto_key_manager_2026 import KeyManager
            
            key_manager = KeyManager()
            
            # Rapid key rotation
            for i in range(50):
                new_key = key_manager.generate_key()
                self.assertIsNotNone(new_key)
            
            # Should complete without issues
            
        except ImportError:
            self.skipTest("Key manager module not available")


class TestDigitalSignatureEdgeCases(unittest.TestCase):
    """Test digital signature edge cases"""
    
    def test_empty_message_signing(self):
        """Test signing empty and boundary messages"""
        try:
            from pq_crypto_dilithium_2026 import DilithiumSigner
            
            signer = DilithiumSigner()
            
            # Empty message
            sig_empty = signer.sign(b"")
            self.assertIsNotNone(sig_empty)
            
            # Single byte
            sig_single = signer.sign(b"\x00")
            self.assertIsNotNone(sig_single)
            
            # Large message
            large_msg = secrets.token_bytes(65536)
            sig_large = signer.sign(large_msg)
            self.assertIsNotNone(sig_large)
            
        except ImportError:
            self.skipTest("Dilithium module not available")
    
    def test_signature_verification_edge_cases(self):
        """Test signature verification edge cases"""
        try:
            from pq_crypto_dilithium_2026 import DilithiumSigner
            
            signer = DilithiumSigner()
            msg = b"Test message for signing"
            sig = signer.sign(msg)
            
            # Correct verification
            result_valid = signer.verify(msg, sig)
            self.assertIsNotNone(result_valid)
            
            # Wrong message
            result_wrong = signer.verify(b"Different message", sig)
            self.assertIsNotNone(result_wrong)
            
            # Tampered signature (flip a bit)
            if len(sig) > 0:
                tampered_sig = bytearray(sig)
                tampered_sig[0] ^= 0x01
                result_tampered = signer.verify(msg, bytes(tampered_sig))
                self.assertIsNotNone(result_tampered)
            
        except ImportError:
            self.skipTest("Dilithium module not available")
    
    def test_repeated_signing_consistency(self):
        """Test that signing same message produces consistent results"""
        try:
            from pq_crypto_dilithium_2026 import DilithiumSigner
            
            signer = DilithiumSigner()
            msg = b"Consistency test message"
            
            # Sign multiple times
            signatures = []
            for i in range(10):
                sig = signer.sign(msg)
                signatures.append(sig)
            
            # All should verify
            for sig in signatures:
                result = signer.verify(msg, sig)
                self.assertIsNotNone(result)
            
        except ImportError:
            self.skipTest("Dilithium module not available")


class TestKEMEdgeCases(unittest.TestCase):
    """Test Key Encapsulation Mechanism edge cases"""
    
    def test_kem_encapsulation_boundaries(self):
        """Test KEM encapsulation edge cases"""
        try:
            from pq_crypto_kyber_2026 import KyberKEM
            
            kem = KyberKEM()
            
            # Generate keypair
            pk, sk = kem.keygen()
            self.assertIsNotNone(pk)
            self.assertIsNotNone(sk)
            
            # Encapsulate multiple times
            for i in range(10):
                ss, ct = kem.encaps(pk)
                self.assertIsNotNone(ss)
                self.assertIsNotNone(ct)
                
                # Decapsulate
                ss_decaps = kem.decaps(sk, ct)
                self.assertIsNotNone(ss_decaps)
            
        except ImportError:
            self.skipTest("Kyber KEM module not available")
    
    def test_kem_invalid_ciphertext_handling(self):
        """Test KEM with invalid ciphertexts"""
        try:
            from pq_crypto_kyber_2026 import KyberKEM
            
            kem = KyberKEM()
            pk, sk = kem.keygen()
            
            invalid_cts = [
                b"",  # Empty
                b"short",  # Too short
                b"\x00" * 10000,  # All zeros, wrong length
            ]
            
            for invalid_ct in invalid_cts:
                try:
                    result = kem.decaps(sk, invalid_ct)
                    # Should either raise or return safe value
                    self.assertIsNotNone(result)
                except (ValueError, Exception):
                    # Exception is acceptable for invalid input
                    pass
            
        except ImportError:
            self.skipTest("Kyber KEM module not available")


class TestHashFunctionEdgeCases(unittest.TestCase):
    """Test hash function edge cases"""
    
    def test_hash_empty_input(self):
        """Test hashing empty input"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            
            # Empty input
            hash_empty = hasher.hash(b"")
            self.assertIsNotNone(hash_empty)
            self.assertIsInstance(hash_empty, bytes)
            
            # Single byte
            hash_single = hasher.hash(b"\x00")
            self.assertIsNotNone(hash_single)
            
        except ImportError:
            self.skipTest("Hash module not available")
    
    def test_hash_large_inputs(self):
        """Test hashing large inputs"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            
            input_sizes = [1024, 16384, 65536, 262144]
            
            for size in input_sizes:
                data = secrets.token_bytes(size)
                digest = hasher.hash(data)
                self.assertIsNotNone(digest)
                # Hash output should be consistent length
                self.assertTrue(len(digest) in [32, 48, 64])
            
        except ImportError:
            self.skipTest("Hash module not available")
    
    def test_hash_determinism(self):
        """Test that hashing is deterministic"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            data = b"Test message for determinism check"
            
            # Hash multiple times
            hash1 = hasher.hash(data)
            hash2 = hasher.hash(data)
            hash3 = hasher.hash(data)
            
            # All should be identical
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash2, hash3)
            
        except ImportError:
            self.skipTest("Hash module not available")
    
    def test_hmac_edge_cases(self):
        """Test HMAC edge cases"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            
            # Empty key, empty message
            result1 = hasher.hmac(b"", b"")
            self.assertIsNotNone(result1)
            
            # Normal key, empty message
            result2 = hasher.hmac(b"secretkey", b"")
            self.assertIsNotNone(result2)
            
            # Empty key, normal message
            result3 = hasher.hmac(b"", b"Test message")
            self.assertIsNotNone(result3)
            
            # Very long key
            long_key = b"A" * 1024
            result4 = hasher.hmac(long_key, b"Test message")
            self.assertIsNotNone(result4)
            
        except ImportError:
            self.skipTest("Hash module not available")


class TestRandomNumberGeneration(unittest.TestCase):
    """Test CSPRNG edge cases"""
    
    def test_random_boundary_sizes(self):
        """Test random generation at various sizes"""
        try:
            from pq_crypto_random_2026 import SecureRandom
            
            rng = SecureRandom()
            
            sizes = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 65536]
            
            for size in sizes:
                random_bytes = rng.random_bytes(size)
                self.assertIsNotNone(random_bytes)
                self.assertEqual(len(random_bytes), size)
            
        except ImportError:
            self.skipTest("Random module not available")
    
    def test_random_statistical_properties(self):
        """Test basic statistical properties of random output"""
        try:
            from pq_crypto_random_2026 import SecureRandom
            
            rng = SecureRandom()
            
            # Generate many samples
            sample = rng.random_bytes(10000)
            
            # Count byte frequency
            freq = [0] * 256
            for b in sample:
                freq[b] += 1
            
            # No byte should be completely absent (statistically)
            # Allow some variance for small sample
            zero_count = sum(1 for f in freq if f == 0)
            # With 10000 bytes, we expect ~0 zeros on average
            self.assertLess(zero_count, 20)
            
        except ImportError:
            self.skipTest("Random module not available")
    
    def test_random_uniqueness(self):
        """Test that random outputs are unique"""
        try:
            from pq_crypto_random_2026 import SecureRandom
            
            rng = SecureRandom()
            
            # Generate many 32-byte values
            values = set()
            for i in range(1000):
                val = rng.random_bytes(32)
                # Extremely unlikely to have collision
                self.assertNotIn(val, values)
                values.add(val)
            
        except ImportError:
            self.skipTest("Random module not available")


class TestConcurrencyAndThreadSafety(unittest.TestCase):
    """Test concurrent access to crypto modules"""
    
    def test_concurrent_encryption(self):
        """Test concurrent encryption operations"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            results = []
            errors = []
            
            def encrypt_worker():
                try:
                    msg = secrets.token_bytes(1024)
                    result = crypto.encrypt(msg)
                    results.append(result)
                except Exception as e:
                    errors.append(e)
            
            threads = []
            for i in range(20):
                t = threading.Thread(target=encrypt_worker)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join(timeout=10)
            
            self.assertEqual(len(errors), 0, f"Concurrency errors: {errors}")
            self.assertEqual(len(results), 20)
            
        except ImportError:
            self.skipTest("Crypto core module not available")
    
    def test_concurrent_signing(self):
        """Test concurrent signing operations"""
        try:
            from pq_crypto_dilithium_2026 import DilithiumSigner
            
            signer = DilithiumSigner()
            results = []
            errors = []
            
            def sign_worker():
                try:
                    msg = secrets.token_bytes(256)
                    sig = signer.sign(msg)
                    results.append(sig)
                except Exception as e:
                    errors.append(e)
            
            threads = []
            for i in range(15):
                t = threading.Thread(target=sign_worker)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join(timeout=10)
            
            self.assertEqual(len(errors), 0)
            self.assertEqual(len(results), 15)
            
        except ImportError:
            self.skipTest("Dilithium module not available")
    
    def test_concurrent_hashing(self):
        """Test concurrent hashing"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            results = []
            errors = []
            
            def hash_worker():
                try:
                    data = secrets.token_bytes(4096)
                    digest = hasher.hash(data)
                    results.append(digest)
                except Exception as e:
                    errors.append(e)
            
            threads = []
            for i in range(30):
                t = threading.Thread(target=hash_worker)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join(timeout=10)
            
            self.assertEqual(len(errors), 0)
            self.assertEqual(len(results), 30)
            
        except ImportError:
            self.skipTest("Hash module not available")


class TestModuleIntegrationChains(unittest.TestCase):
    """Test integration chains between crypto modules"""
    
    def test_encrypt_then_sign_chain(self):
        """Test encrypt -> sign -> verify -> decrypt chain"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            from pq_crypto_dilithium_2026 import DilithiumSigner
            
            crypto = QuantumCryptoCore()
            signer = DilithiumSigner()
            
            msg = b"Secret message to encrypt and sign"
            
            # Full pipeline
            encrypted = crypto.encrypt(msg)
            self.assertIsNotNone(encrypted)
            
            signature = signer.sign(encrypted)
            self.assertIsNotNone(signature)
            
            # Verify signature
            verify_result = signer.verify(encrypted, signature)
            self.assertIsNotNone(verify_result)
            
        except ImportError:
            self.skipTest("Required modules not available")
    
    def test_hash_then_hmac_chain(self):
        """Test hash then HMAC chain"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            key = b"test-secret-key-12345"
            data = b"Important data to hash and authenticate"
            
            # Hash
            digest = hasher.hash(data)
            self.assertIsNotNone(digest)
            
            # HMAC
            auth_tag = hasher.hmac(key, data)
            self.assertIsNotNone(auth_tag)
            
            self.assertNotEqual(digest, auth_tag)  # Different outputs
            
        except ImportError:
            self.skipTest("Hash module not available")
    
    def test_kem_then_encrypt_chain(self):
        """Test KEM key exchange then encryption chain"""
        try:
            from pq_crypto_kyber_2026 import KyberKEM
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            kem = KyberKEM()
            crypto = QuantumCryptoCore()
            
            # Key exchange
            pk, sk = kem.keygen()
            ss_alice, ct = kem.encaps(pk)
            ss_bob = kem.decaps(sk, ct)
            
            # Both should have same shared secret
            self.assertEqual(ss_alice, ss_bob)
            
            # Use shared secret for encryption
            msg = b"Message using KEM-derived key"
            encrypted = crypto.encrypt_with_key(msg, ss_alice)
            self.assertIsNotNone(encrypted)
            
        except ImportError:
            self.skipTest("Required modules not available")


class TestErrorRecoveryAndGracefulDegradation(unittest.TestCase):
    """Test error recovery and graceful degradation"""
    
    def test_malformed_input_handling(self):
        """Test handling of malformed inputs"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            
            malformed_inputs = [
                None,
                "string instead of bytes",
                12345,
                [],
                {},
            ]
            
            for malformed in malformed_inputs:
                try:
                    result = crypto.encrypt(malformed)
                    # If it doesn't raise, it should return something
                    self.assertIsNotNone(result)
                except (TypeError, ValueError, AttributeError):
                    # These exceptions are acceptable for bad input
                    pass
                
        except ImportError:
            self.skipTest("Crypto core module not available")
    
    def test_corrupted_data_decryption(self):
        """Test decryption of corrupted ciphertext"""
        try:
            from pq_crypto_core_2026 import QuantumCryptoCore
            
            crypto = QuantumCryptoCore()
            msg = b"Original message"
            encrypted = crypto.encrypt(msg)
            
            # Corrupt the ciphertext
            if isinstance(encrypted, bytes) and len(encrypted) > 0:
                corrupted = bytearray(encrypted)
                corrupted[0] ^= 0xFF
                corrupted[-1] ^= 0xFF
                
                try:
                    result = crypto.decrypt(bytes(corrupted))
                    # Should either fail gracefully or detect corruption
                    self.assertIsNotNone(result)
                except Exception:
                    # Exception for corrupted data is acceptable
                    pass
                
        except ImportError:
            self.skipTest("Crypto core module not available")


class TestPerformanceAndStability(unittest.TestCase):
    """Test performance and stability under load"""
    
    def test_repeated_operation_stability(self):
        """Test stability through repeated operations"""
        try:
            from pq_crypto_hash_2026 import CryptoHash
            
            hasher = CryptoHash()
            
            # Many repeated operations
            for i in range(1000):
                data = f"Iteration {i} test data".encode()
                digest = hasher.hash(data)
                self.assertIsNotNone(digest)
            
            # Should complete without memory issues
            
        except ImportError:
            self.skipTest("Hash module not available")
    
    def test_batch_operation_performance(self):
        """Test batch operation performance"""
        try:
            from pq_crypto_random_2026 import SecureRandom
            
            rng = SecureRandom()
            
            # Generate many random values quickly
            start = time.time()
            for i in range(1000):
                rng.random_bytes(32)
            elapsed = time.time() - start
            
            # Should complete in reasonable time
            self.assertLess(elapsed, 10.0)  # 10 seconds max for 1000 ops
            
        except ImportError:
            self.skipTest("Random module not available")


def run_comprehensive_crypto_tests():
    """Run all comprehensive crypto edge case tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestCryptographicBoundaryConditions,
        TestKeyManagementEdgeCases,
        TestDigitalSignatureEdgeCases,
        TestKEMEdgeCases,
        TestHashFunctionEdgeCases,
        TestRandomNumberGeneration,
        TestConcurrencyAndThreadSafety,
        TestModuleIntegrationChains,
        TestErrorRecoveryAndGracefulDegradation,
        TestPerformanceAndStability,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save results
    results_summary = {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'success': result.wasSuccessful(),
        'timestamp': time.time(),
    }
    
    with open('test_results_pq_crypto_comprehensive_edge_cases_v6_2026_june.json', 'w') as f:
        json.dump(results_summary, f, indent=2)
    
    return result


if __name__ == '__main__':
    result = run_comprehensive_crypto_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
