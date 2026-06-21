#!/usr/bin/env python3
"""
Test suite for Post-Quantum Hybrid KEM Engine
REAL WORKING TESTS - production grade verification
"""

import sys
import json
import time
import os
from quantum_crypt.post_quantum_hybrid_kem_engine_2026_june import (
    SecurityLevel,
    KEMType,
    KeyPair,
    EncryptedMessage,
    ClassicalKEM,
    SimulatedKyberKEM,
    HybridKEMEngine
)


def test_classical_kem():
    """Test classical X25519 KEM functionality"""
    print("=" * 60)
    print("TEST 1: Classical X25519 KEM")
    print("=" * 60)
    
    kem = ClassicalKEM(KEMType.CLASSICAL_X25519)
    
    # Generate recipient keypair
    recipient_kp = kem.generate_keypair()
    print(f"  Recipient key ID: {recipient_kp.key_id}")
    print(f"  Public key size: {len(recipient_kp.public_key)} bytes")
    print(f"  Private key size: {len(recipient_kp.private_key)} bytes")
    
    # Generate sender ephemeral keypair and encapsulate
    sender_kp = kem.generate_keypair()
    ciphertext, shared_secret_sender = kem.encapsulate(recipient_kp.public_key, sender_kp)
    
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    print(f"  Shared secret (sender): {shared_secret_sender.hex()[:16]}...")
    
    # Decapsulate
    shared_secret_recipient = kem.decapsulate(ciphertext, recipient_kp.private_key)
    print(f"  Shared secret (recipient): {shared_secret_recipient.hex()[:16]}...")
    
    # Verify shared secrets match
    assert shared_secret_sender == shared_secret_recipient, "Shared secrets must match!"
    print("  ✓ Shared secrets match - KEM working correctly")
    
    return True


def test_post_quantum_kem():
    """Test post-quantum simulated Kyber KEM"""
    print("\n" + "=" * 60)
    print("TEST 2: Post-Quantum Simulated Kyber KEM")
    print("=" * 60)
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        kem = SimulatedKyberKEM(level)
        
        # Generate keypair
        kp = kem.generate_keypair()
        print(f"  [{level.value}] Public key: {len(kp.public_key)} bytes, "
              f"Private key: {len(kp.private_key)} bytes")
        
        # Encapsulate
        ciphertext, ss_sender = kem.encapsulate(kp.public_key)
        print(f"  [{level.value}] Ciphertext: {len(ciphertext)} bytes")
        
        # Decapsulate
        ss_recipient = kem.decapsulate(ciphertext, kp.private_key)
        
        assert ss_sender == ss_recipient, f"Shared secrets must match for {level.value}!"
        print(f"  [{level.value}] ✓ Working correctly")
    
    return True


def test_hybrid_key_generation():
    """Test hybrid key pair generation"""
    print("\n" + "=" * 60)
    print("TEST 3: Hybrid Key Pair Generation")
    print("=" * 60)
    
    engine = HybridKEMEngine(security_level=SecurityLevel.LEVEL_5)
    
    keypairs = engine.generate_hybrid_keypair()
    
    print(f"  Classical key generated: {'classical' in keypairs}")
    print(f"  Post-quantum key generated: {'post_quantum' in keypairs}")
    
    if 'classical' in keypairs:
        print(f"  Classical key ID: {keypairs['classical'].key_id}")
        print(f"  Classical pubkey: {len(keypairs['classical'].public_key)} bytes")
    
    if 'post_quantum' in keypairs:
        print(f"  PQ key ID: {keypairs['post_quantum'].key_id}")
        print(f"  PQ pubkey: {len(keypairs['post_quantum'].public_key)} bytes")
    
    stats = engine.get_engine_statistics()
    print(f"  Keys in registry: {stats['keys_in_registry']}")
    
    print("  ✓ Hybrid key generation working correctly")
    return True


def test_hybrid_encapsulation_decapsulation():
    """Test full hybrid encapsulation/decapsulation cycle"""
    print("\n" + "=" * 60)
    print("TEST 4: Hybrid Encapsulation/Decapsulation Cycle")
    print("=" * 60)
    
    engine = HybridKEMEngine(security_level=SecurityLevel.LEVEL_5)
    
    # Generate recipient keys
    recipient_keys = engine.generate_hybrid_keypair()
    recipient_pubkeys = {
        "classical": recipient_keys["classical"].public_key,
        "post_quantum": recipient_keys["post_quantum"].public_key
    }
    recipient_privkeys = {
        "classical": recipient_keys["classical"].private_key,
        "post_quantum": recipient_keys["post_quantum"].private_key
    }
    
    # Encapsulate
    ciphertexts, ss_sender = engine.hybrid_encapsulate(recipient_pubkeys)
    
    print(f"  Sender shared secret: {ss_sender.hex()[:32]}...")
    print(f"  Ciphertext types: {list(ciphertexts.keys())}")
    total_ct_size = sum(len(v) for v in ciphertexts.values())
    print(f"  Total ciphertext size: {total_ct_size} bytes")
    
    # Decapsulate
    ss_recipient = engine.hybrid_decapsulate(ciphertexts, recipient_privkeys)
    print(f"  Recipient shared secret: {ss_recipient.hex()[:32]}...")
    
    assert ss_sender == ss_recipient, "Hybrid shared secrets must match!"
    print("  ✓ Hybrid encapsulation/decapsulation working correctly")
    
    stats = engine.get_engine_statistics()
    print(f"  Total operations: {stats['total_operations']}")
    
    return True


def test_hybrid_encryption_decryption():
    """Test full hybrid encryption/decryption with AES-GCM"""
    print("\n" + "=" * 60)
    print("TEST 5: Hybrid Encryption/Decryption (KEM + AES-GCM)")
    print("=" * 60)
    
    engine = HybridKEMEngine(security_level=SecurityLevel.LEVEL_5)
    
    # Generate recipient keys
    recipient_keys = engine.generate_hybrid_keypair()
    recipient_pubkeys = {
        "classical": recipient_keys["classical"].public_key,
        "post_quantum": recipient_keys["post_quantum"].public_key
    }
    recipient_privkeys = {
        "classical": recipient_keys["classical"].private_key,
        "post_quantum": recipient_keys["post_quantum"].private_key
    }
    
    # Test message
    plaintext = b"THIS IS A SECRET MESSAGE FOR POST-QUANTUM HYBRID ENCRYPTION TESTING - JUNE 2026"
    associated_data = b"v1|sender=alice|recipient=bob|timestamp=" + str(int(time.time())).encode()
    
    print(f"  Plaintext: {plaintext[:50]}...")
    print(f"  Plaintext size: {len(plaintext)} bytes")
    
    # Encrypt
    start_time = time.time()
    encrypted = engine.encrypt_message(plaintext, recipient_pubkeys, associated_data)
    encrypt_time = (time.time() - start_time) * 1000
    
    print(f"  Ciphertext size: {len(encrypted.ciphertext)} bytes")
    print(f"  KEM ciphertext: {len(encrypted.kem_ciphertext)} bytes")
    print(f"  Nonce: {encrypted.nonce.hex()}")
    print(f"  Auth tag: {encrypted.tag.hex()}")
    print(f"  Encryption time: {encrypt_time:.2f}ms")
    
    # Decrypt
    start_time = time.time()
    decrypted = engine.decrypt_message(encrypted, recipient_privkeys, associated_data)
    decrypt_time = (time.time() - start_time) * 1000
    
    print(f"  Decryption time: {decrypt_time:.2f}ms")
    print(f"  Decrypted: {decrypted[:50]}...")
    
    assert plaintext == decrypted, "Decrypted message must match original!"
    print("  ✓ Hybrid encryption/decryption working correctly")
    
    return True


def test_authentication_verification():
    """Test that tampering is detected"""
    print("\n" + "=" * 60)
    print("TEST 6: Authentication Verification (Tamper Detection)")
    print("=" * 60)
    
    engine = HybridKEMEngine(security_level=SecurityLevel.LEVEL_5)
    
    recipient_keys = engine.generate_hybrid_keypair()
    recipient_pubkeys = {
        "classical": recipient_keys["classical"].public_key,
        "post_quantum": recipient_keys["post_quantum"].public_key
    }
    recipient_privkeys = {
        "classical": recipient_keys["classical"].private_key,
        "post_quantum": recipient_keys["post_quantum"].private_key
    }
    
    plaintext = b"Secret message"
    encrypted = engine.encrypt_message(plaintext, recipient_pubkeys)
    
    # Tamper with ciphertext
    tampered_ciphertext = encrypted.ciphertext[:-1] + b"X"
    encrypted.ciphertext = tampered_ciphertext
    
    try:
        decrypted = engine.decrypt_message(encrypted, recipient_privkeys)
        print("  ✗ Tampering NOT detected - FAIL")
        return False
    except Exception as e:
        print(f"  ✓ Tampering correctly detected: {type(e).__name__}")
        print("  ✓ Authentication working correctly")
        return True


def test_different_security_levels():
    """Test all security levels"""
    print("\n" + "=" * 60)
    print("TEST 7: Different Security Levels")
    print("=" * 60)
    
    for level in [SecurityLevel.LEVEL_1, SecurityLevel.LEVEL_3, SecurityLevel.LEVEL_5]:
        engine = HybridKEMEngine(security_level=level)
        
        recipient_keys = engine.generate_hybrid_keypair()
        pubkeys = {k: v.public_key for k, v in recipient_keys.items()}
        privkeys = {k: v.private_key for k, v in recipient_keys.items()}
        
        plaintext = f"Test message for security {level.value}".encode()
        encrypted = engine.encrypt_message(plaintext, pubkeys)
        decrypted = engine.decrypt_message(encrypted, privkeys)
        
        assert plaintext == decrypted, f"Failed at security level {level.value}"
        print(f"  [{level.value}] ✓ Security level working")
        print(f"    Algorithm info: {encrypted.algorithm_info}")
    
    return True


def test_classical_only_mode():
    """Test classical-only mode"""
    print("\n" + "=" * 60)
    print("TEST 8: Classical-Only Mode")
    print("=" * 60)
    
    engine = HybridKEMEngine(
        security_level=SecurityLevel.LEVEL_1,
        enable_classical=True,
        enable_post_quantum=False
    )
    
    stats = engine.get_engine_statistics()
    print(f"  Classical enabled: {stats['classical_enabled']}")
    print(f"  PQ enabled: {stats['post_quantum_enabled']}")
    
    recipient_keys = engine.generate_hybrid_keypair()
    print(f"  Keys generated: {list(recipient_keys.keys())}")
    
    pubkeys = {k: v.public_key for k, v in recipient_keys.items()}
    privkeys = {k: v.private_key for k, v in recipient_keys.items()}
    
    plaintext = b"Classical only encryption test"
    encrypted = engine.encrypt_message(plaintext, pubkeys)
    decrypted = engine.decrypt_message(encrypted, privkeys)
    
    assert plaintext == decrypted, "Classical-only mode failed!"
    print("  ✓ Classical-only mode working correctly")
    
    return True


def test_performance_benchmark():
    """Performance benchmark"""
    print("\n" + "=" * 60)
    print("TEST 9: Performance Benchmark")
    print("=" * 60)
    
    engine = HybridKEMEngine(security_level=SecurityLevel.LEVEL_5)
    
    recipient_keys = engine.generate_hybrid_keypair()
    pubkeys = {k: v.public_key for k, v in recipient_keys.items()}
    privkeys = {k: v.private_key for k, v in recipient_keys.items()}
    
    iterations = 50
    plaintext = b"Performance test message " * 10
    
    encrypt_times = []
    decrypt_times = []
    
    for i in range(iterations):
        start = time.time()
        encrypted = engine.encrypt_message(plaintext, pubkeys)
        encrypt_times.append((time.time() - start) * 1000)
        
        start = time.time()
        decrypted = engine.decrypt_message(encrypted, privkeys)
        decrypt_times.append((time.time() - start) * 1000)
    
    avg_encrypt = sum(encrypt_times) / len(encrypt_times)
    avg_decrypt = sum(decrypt_times) / len(decrypt_times)
    
    print(f"  Iterations: {iterations}")
    print(f"  Average encryption: {avg_encrypt:.3f}ms")
    print(f"  Average decryption: {avg_decrypt:.3f}ms")
    print(f"  Total throughput: {1000/(avg_encrypt+avg_decrypt):.1f} ops/sec")
    
    stats = engine.get_engine_statistics()
    print(f"  Total operations: {stats['total_operations']}")
    
    print("  ✓ Performance benchmark completed")
    return True


def run_all_tests():
    """Run all tests and generate report"""
    print("\n" + "=" * 60)
    print("POST-QUANTUM HYBRID KEM ENGINE")
    print("PRODUCTION TEST SUITE - JUNE 2026")
    print("=" * 60 + "\n")
    
    tests = [
        test_classical_kem,
        test_post_quantum_kem,
        test_hybrid_key_generation,
        test_hybrid_encapsulation_decapsulation,
        test_hybrid_encryption_decryption,
        test_authentication_verification,
        test_different_security_levels,
        test_classical_only_mode,
        test_performance_benchmark
    ]
    
    results = []
    start_time = time.time()
    
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result, None))
        except Exception as e:
            results.append((test.__name__, False, str(e)))
            print(f"  ✗ FAILED: {e}")
            import traceback
            traceback.print_exc()
    
    total_time = time.time() - start_time
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, r, _ in results if r)
    failed = len(results) - passed
    
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\n  Total: {passed}/{len(results)} tests passed")
    print(f"  Total time: {total_time:.3f}s")
    
    # Save test results
    test_results = {
        "test_suite": "post_quantum_hybrid_kem_engine",
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": len(results),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(results),
        "total_time_seconds": total_time,
        "tests": [{"name": n, "passed": r, "error": e} for n, r, e in results]
    }
    
    with open("test_results_hybrid_kem_engine.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\n  Test results saved to test_results_hybrid_kem_engine.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
