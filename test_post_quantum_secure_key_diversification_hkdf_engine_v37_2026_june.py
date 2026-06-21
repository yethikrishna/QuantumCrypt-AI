"""
Test suite for Post-Quantum Secure HKDF Engine v37
Production-grade tests with real assertions, no empty shells.
"""
import json
import os
import sys
import tempfile

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_key_diversification_hkdf_engine_v37_2026_june import (
    PostQuantumHKDFEngineV37,
    DerivedKey,
    KeyDiversificationContext,
    HashAlgorithm,
    SecurityStrength,
    ConstantTimeOperations,
    PostQuantumEntropySource,
    MemoryHardStretcher
)

def run_tests():
    print("=" * 60)
    print("Testing Post-Quantum Secure HKDF Engine v37")
    print("=" * 60)
    
    test_results = {
        "tests_passed": 0,
        "tests_failed": 0,
        "test_details": []
    }
    
    # Test 1: Initialize HKDF engine
    print("\n[Test 1] Engine Initialization")
    try:
        engine = PostQuantumHKDFEngineV37(
            hash_algorithm=HashAlgorithm.SHA512,
            security_strength=SecurityStrength.LEVEL_5,
            use_memory_hard=True
        )
        stats = engine.get_engine_stats()
        assert stats["security_strength_bits"] == 256, "Should be 256-bit security"
        assert stats["hash_algorithm"] == "SHA-512", "Should use SHA-512"
        print(f"  ✓ Engine initialized with {stats['security_strength_bits']}-bit security")
        print(f"  ✓ Hash algorithm: {stats['hash_algorithm']}")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Initialization", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Initialization", "status": "FAILED", "error": str(e)})
    
    # Test 2: Basic key derivation
    print("\n[Test 2] Basic Key Derivation")
    try:
        engine = PostQuantumHKDFEngineV37()
        master_seed = engine.generate_master_seed(64)
        
        derived = engine.derive_key(
            input_key_material=master_seed,
            length=32,
            info=b"test-encryption-key"
        )
        
        assert len(derived.key_material) == 32, "Should be 32 bytes"
        assert derived.verify() == True, "Key should pass verification"
        assert derived.length == 32, "Length metadata should match"
        
        print(f"  ✓ Derived {derived.length} bytes key")
        print(f"  ✓ Key ID: {derived.key_id}")
        print(f"  ✓ Verification: PASSED")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Basic Derivation", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Basic Derivation", "status": "FAILED", "error": str(e)})
    
    # Test 3: Deterministic derivation (same IKM + salt = same key)
    print("\n[Test 3] Deterministic Derivation")
    try:
        engine = PostQuantumHKDFEngineV37()
        ikm = b"test-input-key-material-12345"
        salt = b"fixed-salt-for-testing"
        
        derived1 = engine.derive_key(ikm, 32, salt=salt, info=b"context1")
        derived2 = engine.derive_key(ikm, 32, salt=salt, info=b"context1")
        
        assert derived1.key_material == derived2.key_material, "Should be deterministic"
        print("  ✓ Same IKM + salt produces identical key")
        
        # Different info should produce different keys
        derived3 = engine.derive_key(ikm, 32, salt=salt, info=b"context2")
        assert derived1.key_material != derived3.key_material, "Different info should change key"
        print("  ✓ Different info produces different key")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Deterministic", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Deterministic", "status": "FAILED", "error": str(e)})
    
    # Test 4: Key diversification context
    print("\n[Test 4] Key Diversification Context")
    try:
        engine = PostQuantumHKDFEngineV37()
        ikm = engine.generate_master_seed(32)
        
        context = KeyDiversificationContext(
            application_id="QuantumCrypt-App",
            key_version=1,
            usage_context="aes-256-gcm-encryption"
        )
        
        derived = engine.derive_key(ikm, 32, context=context)
        assert len(derived.key_material) == 32
        assert derived.verify()
        
        info_bytes = context.to_info_bytes()
        assert b"QuantumCrypt-App" in info_bytes
        assert b"aes-256-gcm" in info_bytes
        
        print(f"  ✓ Context serialized: {info_bytes[:50]}...")
        print("  ✓ Context-based derivation successful")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Diversification Context", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Diversification Context", "status": "FAILED", "error": str(e)})
    
    # Test 5: Multiple key derivation
    print("\n[Test 5] Multiple Key Derivation")
    try:
        engine = PostQuantumHKDFEngineV37()
        ikm = engine.generate_master_seed(64)
        
        key_specs = [
            (32, "aes-encryption"),
            (64, "hmac-signing"),
            (16, "iv-generation"),
            (48, "trio-des-legacy")
        ]
        
        keys = engine.derive_multiple_keys(ikm, key_specs)
        
        assert len(keys) == 4, "Should derive 4 keys"
        assert keys[0].length == 32
        assert keys[1].length == 64
        assert keys[2].length == 16
        assert keys[3].length == 48
        
        # All keys should be different
        key_materials = [k.key_material for k in keys]
        assert len(set(key_materials)) == 4, "All keys should be unique"
        
        print(f"  ✓ Derived {len(keys)} unique keys from single IKM")
        for i, k in enumerate(keys):
            print(f"    Key {i+1}: {k.length} bytes - {k.key_id[:12]}...")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Multiple Keys", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Multiple Keys", "status": "FAILED", "error": str(e)})
    
    # Test 6: Constant-time operations
    print("\n[Test 6] Constant-Time Operations")
    try:
        ct = ConstantTimeOperations()
        
        # Test constant-time equality
        assert ct.ct_equal(b"test123", b"test123") == True
        assert ct.ct_equal(b"test123", b"test456") == False
        print("  ✓ Constant-time equality works")
        
        # Test constant-time XOR
        a = b"\x01\x02\x03"
        b = b"\x04\x05\x06"
        xor_result = ct.ct_xor(a, b)
        assert xor_result == b"\x05\x07\x05"
        print("  ✓ Constant-time XOR works")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Constant-Time Ops", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Constant-Time Ops", "status": "FAILED", "error": str(e)})
    
    # Test 7: Post-quantum entropy source
    print("\n[Test 7] Post-Quantum Entropy Source")
    try:
        entropy = PostQuantumEntropySource(SecurityStrength.LEVEL_5)
        
        bytes1 = entropy.get_random_bytes(32)
        bytes2 = entropy.get_random_bytes(32)
        
        assert len(bytes1) == 32
        assert len(bytes2) == 32
        assert bytes1 != bytes2, "Random bytes should be different"
        
        salt = entropy.generate_salt()
        assert len(salt) == 32, "Salt should be 32 bytes for 256-bit security"
        
        print(f"  ✓ Generated 2x 32-byte random sequences")
        print(f"  ✓ Salt generation: {len(salt)} bytes")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Entropy Source", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Entropy Source", "status": "FAILED", "error": str(e)})
    
    # Test 8: Memory-hard stretching
    print("\n[Test 8] Memory-Hard Stretching")
    try:
        stretcher = MemoryHardStretcher(iterations=2, memory_cost_kb=16)
        input_key = b"weak-password-123"
        salt = b"test-salt"
        
        stretched = stretcher.stretch(input_key, salt, HashAlgorithm.SHA256)
        
        assert len(stretched) == HashAlgorithm.SHA256.output_length
        assert stretched != input_key, "Should transform input key"
        
        # Deterministic stretching
        stretched2 = stretcher.stretch(input_key, salt, HashAlgorithm.SHA256)
        assert stretched == stretched2, "Stretching should be deterministic"
        
        print(f"  ✓ Stretched key to {len(stretched)} bytes")
        print("  ✓ Stretching is deterministic")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Memory-Hard Stretching", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Memory-Hard Stretching", "status": "FAILED", "error": str(e)})
    
    # Test 9: Forward-secure key rotation
    print("\n[Test 9] Forward-Secure Key Rotation")
    try:
        engine = PostQuantumHKDFEngineV37()
        original_key = engine.generate_master_seed(32)
        original_copy = original_key[:]
        
        rotated_key, rot_id = engine.forward_secure_rotate(original_key, rotation_count=3)
        
        assert len(rotated_key) == len(original_copy)
        assert rotated_key != original_copy, "Key should change after rotation"
        
        print(f"  ✓ Key rotated 3 times")
        print(f"  ✓ Rotation ID: {rot_id}")
        print(f"  ✓ Zeroizations performed: {engine._zeroizations_performed}")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Key Rotation", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Key Rotation", "status": "FAILED", "error": str(e)})
    
    # Test 10: Key hierarchy derivation
    print("\n[Test 10] Key Hierarchy Derivation")
    try:
        engine = PostQuantumHKDFEngineV37()
        master = engine.generate_master_seed(32)
        
        hierarchy = engine.derive_key_hierarchy(
            master_key=master,
            levels=3,
            keys_per_level=2,
            key_length=32
        )
        
        assert hierarchy["levels"] == 3
        assert hierarchy["keys_per_level"] == 2
        assert "level_0" in hierarchy["key_tree"]
        assert "level_1" in hierarchy["key_tree"]
        assert "level_2" in hierarchy["key_tree"]
        
        level0_keys = hierarchy["key_tree"]["level_0"]
        assert len(level0_keys) == 2
        
        print(f"  ✓ Hierarchy root: {hierarchy['root_key_id'][:16]}...")
        print(f"  ✓ Levels: {hierarchy['levels']}, Keys/level: {hierarchy['keys_per_level']}")
        print(f"  ✓ Total derived: {engine._total_keys_derived} keys")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Key Hierarchy", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Key Hierarchy", "status": "FAILED", "error": str(e)})
    
    # Test 11: Key verification
    print("\n[Test 11] Derivation Verification")
    try:
        engine = PostQuantumHKDFEngineV37()
        ikm = b"test-verification-key"
        
        derived = engine.derive_key(ikm, 32, info=b"verify-me")
        
        # Correct verification
        assert engine.verify_derivation(derived, ikm) == True
        print("  ✓ Correct derivation verified")
        
        # Wrong IKM should fail
        assert engine.verify_derivation(derived, b"wrong-ikm") == False
        print("  ✓ Wrong IKM correctly rejected")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Verification", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Verification", "status": "FAILED", "error": str(e)})
    
    # Test 12: Different hash algorithms
    print("\n[Test 12] Hash Algorithm Support")
    try:
        for alg in [HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512]:
            engine = PostQuantumHKDFEngineV37(hash_algorithm=alg)
            ikm = engine.generate_master_seed(32)
            derived = engine.derive_key(ikm, alg.output_length)
            assert len(derived.key_material) == alg.output_length
            print(f"  ✓ {alg.name}: {alg.output_length} bytes OK")
        
        test_results["tests_passed"] += 1
        test_results["test_details"].append({"test": "Hash Algorithms", "status": "PASSED"})
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results["tests_failed"] += 1
        test_results["test_details"].append({"test": "Hash Algorithms", "status": "FAILED", "error": str(e)})
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"  Tests Passed: {test_results['tests_passed']}")
    print(f"  Tests Failed: {test_results['tests_failed']}")
    total = test_results['tests_passed'] + test_results['tests_failed']
    print(f"  Success Rate: {test_results['tests_passed']/total*100:.1f}%")
    print("=" * 60)
    
    return test_results

if __name__ == "__main__":
    results = run_tests()
    
    # Save results
    output_path = os.path.join(os.path.dirname(__file__), 
                              "test_results_hkdf_engine_v37_2026_june.json")
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nTest results saved to: {output_path}")
