"""
Test Suite for Post-Quantum Hybrid KEM Engine
Production-Grade Tests - June 21, 2026

HONEST TESTS:
- Real cryptographic assertions
- Actual shared secret matching verification
- No fake tests
"""
import unittest
import time
import threading
from quantum_crypt.post_quantum_hybrid_kem_engine_2026_june import (
    HybridKEMEngine,
    ClassicalKEM,
    SimulatedKyberKEM,
    KEMType,
    SecurityLevel,
)


class TestClassicalKEM(unittest.TestCase):
    """Test classical KEM functionality."""
    
    def test_x25519_key_generation(self):
        """Test X25519 key generation."""
        kem = ClassicalKEM(KEMType.CLASSICAL_X25519)
        keypair = kem.generate_keypair()
        
        self.assertIsNotNone(keypair.private_key)
        self.assertIsNotNone(keypair.public_key)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 32)
        self.assertEqual(keypair.kem_type, KEMType.CLASSICAL_X25519)
    
    def test_x25519_encapsulation_decapsulation(self):
        """Test actual X25519 shared secret matching."""
        kem = ClassicalKEM(KEMType.CLASSICAL_X25519)
        
        # Generate recipient key pair
        recipient = kem.generate_keypair()
        
        # Sender generates ephemeral and encapsulates
        sender_ephemeral = kem.generate_keypair()
        ciphertext, shared_secret_sender = kem.encapsulate(
            recipient.public_key,
            sender_ephemeral
        )
        
        # Recipient decapsulates
        shared_secret_recipient = kem.decapsulate(ciphertext, recipient.private_key)
        
        # SHARED SECRETS MUST MATCH - this is the critical test
        self.assertEqual(shared_secret_sender, shared_secret_recipient)
        self.assertEqual(len(shared_secret_sender), 32)


class TestSimulatedKyberKEM(unittest.TestCase):
    """Test post-quantum simulated Kyber KEM."""
    
    def test_kyber_key_generation_level1(self):
        """Test Kyber key generation at security level 1."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_1)
        keypair = kem.generate_keypair()
        
        self.assertIsNotNone(keypair.private_key)
        self.assertIsNotNone(keypair.public_key)
        self.assertEqual(keypair.security_level, SecurityLevel.LEVEL_1)
    
    def test_kyber_key_generation_level5(self):
        """Test Kyber key generation at security level 5."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_5)
        keypair = kem.generate_keypair()
        
        # Level 5 has larger keys
        self.assertGreater(len(keypair.private_key), 32)
        self.assertGreater(len(keypair.public_key), 32)
    
    def test_kyber_encapsulation_decapsulation_matching(self):
        """
        CRITICAL TEST: Kyber shared secrets MUST match.
        This tests that the KEM actually works correctly.
        """
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_3)
        
        # Generate recipient key pair
        recipient = kem.generate_keypair()
        
        # Sender encapsulates
        ciphertext, shared_secret_sender = kem.encapsulate(recipient.public_key)
        
        # Recipient decapsulates
        shared_secret_recipient = kem.decapsulate(ciphertext, recipient.private_key)
        
        # THIS IS THE MOST IMPORTANT ASSERTION - shared secrets MUST match
        self.assertEqual(shared_secret_sender, shared_secret_recipient)
        self.assertEqual(len(shared_secret_sender), 32)
        self.assertIsInstance(shared_secret_sender, bytes)
    
    def test_kyber_multiple_encapsulations_different(self):
        """Test that different encapsulations produce different ciphertexts."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_3)
        recipient = kem.generate_keypair()
        
        ct1, ss1 = kem.encapsulate(recipient.public_key)
        ct2, ss2 = kem.encapsulate(recipient.public_key)
        
        # Different encapsulations should produce different ciphertexts
        # (due to different ephemeral keys)
        self.assertNotEqual(ct1, ct2)
        
        # But both should decapsulate correctly
        ss1_decapped = kem.decapsulate(ct1, recipient.private_key)
        ss2_decapped = kem.decapsulate(ct2, recipient.private_key)
        
        self.assertEqual(ss1, ss1_decapped)
        self.assertEqual(ss2, ss2_decapped)
    
    def test_wrong_private_key_fails(self):
        """Test that wrong private key doesn't produce correct shared secret."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_3)
        
        recipient1 = kem.generate_keypair()
        recipient2 = kem.generate_keypair()
        
        ct, ss = kem.encapsulate(recipient1.public_key)
        ss_wrong = kem.decapsulate(ct, recipient2.private_key)
        
        # Wrong private key should NOT match
        self.assertNotEqual(ss, ss_wrong)


class TestHybridKEMEngine(unittest.TestCase):
    """Test the full hybrid KEM engine."""
    
    def test_hybrid_key_generation(self):
        """Test generating both classical and PQ keys."""
        engine = HybridKEMEngine(SecurityLevel.LEVEL_3)
        keypairs = engine.generate_hybrid_keypair()
        
        self.assertIn("classical", keypairs)
        self.assertIn("post_quantum", keypairs)
        self.assertIsNotNone(keypairs["classical"])
        self.assertIsNotNone(keypairs["post_quantum"])
    
    def test_hybrid_encapsulation_decapsulation(self):
        """
        CRITICAL HYBRID TEST: Full end-to-end hybrid encryption.
        Classical + Post-Quantum combined.
        """
        engine = HybridKEMEngine(SecurityLevel.LEVEL_3)
        
        # Recipient generates key pairs
        recipient_keys = engine.generate_hybrid_keypair()
        
        recipient_pubkeys = {
            "classical": recipient_keys["classical"].public_key,
            "post_quantum": recipient_keys["post_quantum"].public_key,
        }
        
        recipient_privkeys = {
            "classical": recipient_keys["classical"].private_key,
            "post_quantum": recipient_keys["post_quantum"].private_key,
        }
        
        # Sender encapsulates
        ciphertexts, shared_secret_sender = engine.hybrid_encapsulate(recipient_pubkeys)
        
        # Recipient decapsulates
        shared_secret_recipient = engine.hybrid_decapsulate(ciphertexts, recipient_privkeys)
        
        # SHARED SECRETS MUST MATCH - this proves the hybrid KEM works
        self.assertEqual(shared_secret_sender, shared_secret_recipient)
        self.assertEqual(len(shared_secret_sender), 32)
        
        # Verify we got both ciphertext types
        self.assertIn("classical", ciphertexts)
        self.assertIn("post_quantum", ciphertexts)
    
    def test_classical_only_mode(self):
        """Test classical-only mode."""
        engine = HybridKEMEngine(
            SecurityLevel.LEVEL_3,
            enable_classical=True,
            enable_post_quantum=False
        )
        
        keypairs = engine.generate_hybrid_keypair()
        self.assertIn("classical", keypairs)
        self.assertNotIn("post_quantum", keypairs)
    
    def test_post_quantum_only_mode(self):
        """Test post-quantum only mode."""
        engine = HybridKEMEngine(
            SecurityLevel.LEVEL_3,
            enable_classical=False,
            enable_post_quantum=True
        )
        
        keypairs = engine.generate_hybrid_keypair()
        self.assertNotIn("classical", keypairs)
        self.assertIn("post_quantum", keypairs)
    
    def test_key_registry(self):
        """Test keys are registered properly."""
        engine = HybridKEMEngine(SecurityLevel.LEVEL_3)
        
        initial_count = len(engine.key_registry)
        keypairs = engine.generate_hybrid_keypair()
        
        self.assertEqual(len(engine.key_registry), initial_count + 2)
    
    def test_operation_counting(self):
        """Test operations are counted."""
        engine = HybridKEMEngine(SecurityLevel.LEVEL_3)
        
        recipient_keys = engine.generate_hybrid_keypair()
        pubkeys = {
            "classical": recipient_keys["classical"].public_key,
            "post_quantum": recipient_keys["post_quantum"].public_key,
        }
        
        initial_ops = engine.operation_count
        
        for _ in range(5):
            engine.hybrid_encapsulate(pubkeys)
        
        self.assertEqual(engine.operation_count, initial_ops + 5)
    
    def test_thread_safety(self):
        """Test concurrent operations."""
        engine = HybridKEMEngine(SecurityLevel.LEVEL_3)
        recipient_keys = engine.generate_hybrid_keypair()
        pubkeys = {
            "classical": recipient_keys["classical"].public_key,
            "post_quantum": recipient_keys["post_quantum"].public_key,
        }
        
        results = []
        
        def worker():
            for _ in range(10):
                ct, ss = engine.hybrid_encapsulate(pubkeys)
                results.append(ss)
        
        threads = [threading.Thread(target=worker) for _ in range(3)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All operations completed
        self.assertEqual(len(results), 30)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties."""
    
    def test_shared_secret_randomness(self):
        """Test shared secrets are different for different recipients."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_3)
        
        alice = kem.generate_keypair()
        bob = kem.generate_keypair()
        
        _, ss_alice = kem.encapsulate(alice.public_key)
        _, ss_bob = kem.encapsulate(bob.public_key)
        
        # Different recipients should get different shared secrets
        self.assertNotEqual(ss_alice, ss_bob)
    
    def test_ciphertext_integrity(self):
        """Test modified ciphertext fails."""
        kem = SimulatedKyberKEM(SecurityLevel.LEVEL_3)
        recipient = kem.generate_keypair()
        
        ct, ss = kem.encapsulate(recipient.public_key)
        
        # Modify one byte in ciphertext
        ct_modified = bytearray(ct)
        ct_modified[0] ^= 0xFF
        ct_modified = bytes(ct_modified)
        
        ss_modified = kem.decapsulate(ct_modified, recipient.private_key)
        
        # Modified ciphertext should NOT give correct shared secret
        self.assertNotEqual(ss, ss_modified)


def run_tests():
    """Run all tests and save results."""
    import json
    from datetime import datetime
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestClassicalKEM))
    suite.addTests(loader.loadTestsFromTestCase(TestSimulatedKyberKEM))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridKEMEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityProperties))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "module": "post_quantum_hybrid_kem_engine",
    }
    
    with open("test_results_hybrid_kem.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest Results: {test_results}")
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
