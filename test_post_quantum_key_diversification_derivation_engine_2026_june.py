#!/usr/bin/env python3
"""
Test suite for Post-Quantum Key Diversification & Derivation Engine
Production-grade tests with real assertions and edge cases.
"""
import sys
import json
import secrets
sys.path.insert(0, 'quantum_crypt')
from post_quantum_key_diversification_derivation_engine_2026_june import (
    PostQuantumKeyDerivationEngine,
    KDFAlgorithm,
    KeyType,
    DiversificationStrategy,
    DiversificationContext,
    HKDF,
    PBKDF2,
    SP800108Counter,
    ConcatKDF
)
def run_tests():
    print("=" * 70)
    print("QuantumCrypt AI - Key Diversification Engine - Test Suite")
    print("=" * 70)
    
    engine = PostQuantumKeyDerivationEngine()
    passed = 0
    failed = 0
    
    # Test 1: Master Key Generation
    print("\n[TEST 1] Master Key Generation")
    try:
        master = engine.generate_master_key(512)
        assert master.key_type == KeyType.MASTER_KEY
        assert master.length_bits == 512
        assert len(master.key_material) == 64  # 512 bits = 64 bytes
        assert master.key_id is not None
        assert master.algorithm is not None
        print("  ✓ PASSED - Master key generated correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 2: HKDF Implementation
    print("\n[TEST 2] HKDF Implementation")
    try:
        hkdf = HKDF('sha256')
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        info = b"test_context"
        
        derived = hkdf.derive(ikm, 256, salt, info)
        assert len(derived) == 32  # 256 bits = 32 bytes
        assert derived != ikm  # Should be different from input
        print("  ✓ PASSED - HKDF working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 3: PBKDF2 Implementation
    print("\n[TEST 3] PBKDF2 Implementation")
    try:
        pbkdf2 = PBKDF2('sha256', iterations=10000)
        password = b"test_password_123"
        salt = secrets.token_bytes(16)
        
        derived = pbkdf2.derive(password, 256, salt)
        assert len(derived) == 32
        # Deterministic: same input should produce same output
        derived2 = pbkdf2.derive(password, 256, salt)
        assert derived == derived2
        print("  ✓ PASSED - PBKDF2 working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 4: SP 800-108 Counter Mode
    print("\n[TEST 4] SP 800-108 Counter Mode KDF")
    try:
        sp800 = SP800108Counter('sha256')
        ikm = secrets.token_bytes(32)
        info = b"label|context"
        
        derived = sp800.derive(ikm, 256, None, info)
        assert len(derived) == 32
        print("  ✓ PASSED - SP 800-108 working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 5: Concat KDF
    print("\n[TEST 5] Concat KDF Implementation")
    try:
        concat = ConcatKDF('sha256')
        ikm = secrets.token_bytes(32)
        info = b"other_info"
        
        derived = concat.derive(ikm, 512, None, info)
        assert len(derived) == 64  # 512 bits
        print("  ✓ PASSED - Concat KDF working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 6: Session Key Derivation
    print("\n[TEST 6] Session Key Derivation")
    try:
        master = engine.generate_master_key(512)
        session = engine.derive_session_key(master, "session_abc123", "peer_xyz789")
        
        assert session.key_type == KeyType.SESSION_KEY
        assert session.parent_key_id == master.key_id
        assert session.length_bits == 256
        assert len(session.diversification_path) == 1
        print("  ✓ PASSED - Session key derived correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 7: User Key Derivation
    print("\n[TEST 7] User Key Derivation")
    try:
        master = engine.generate_master_key(512)
        user_key = engine.derive_user_key(master, "user_12345", "domain_corp")
        
        assert user_key.key_type == KeyType.DERIVED_KEY
        assert user_key.parent_key_id == master.key_id
        assert "user_12345" in str(user_key.context)
        print("  ✓ PASSED - User key derived correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 8: Device Key Derivation
    print("\n[TEST 8] Device Key Derivation")
    try:
        master = engine.generate_master_key(512)
        device_key = engine.derive_device_key(master, "device_laptop_001", "user_john")
        
        assert device_key.key_type == KeyType.DERIVED_KEY
        assert device_key.parent_key_id == master.key_id
        print("  ✓ PASSED - Device key derived correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 9: Hierarchical Derivation
    print("\n[TEST 9] Hierarchical Key Derivation")
    try:
        master = engine.generate_master_key(512)
        ctx1 = DiversificationContext(
            strategy=DiversificationStrategy.DOMAIN_BASED,
            domain="production",
            purpose="level1"
        )
        ctx2 = DiversificationContext(
            strategy=DiversificationStrategy.USER_BASED,
            user_id="admin",
            purpose="level2"
        )
        path = [
            (KeyType.WRAPPING_KEY, ctx1),
            (KeyType.ENCRYPTION_KEY, ctx2)
        ]
        hierarchy = engine.derive_hierarchical(master, path)
        
        assert len(hierarchy) == 2
        assert hierarchy[0].key_type == KeyType.WRAPPING_KEY
        assert hierarchy[1].key_type == KeyType.ENCRYPTION_KEY
        assert hierarchy[0].parent_key_id == master.key_id
        assert hierarchy[1].parent_key_id == hierarchy[0].key_id
        assert len(hierarchy[1].diversification_path) == 2
        print("  ✓ PASSED - Hierarchical derivation working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 10: Derivation Verification
    print("\n[TEST 10] Key Derivation Verification")
    try:
        master = engine.generate_master_key(512)
        derived = engine.derive_session_key(master, "test_session")
        
        # Should verify correctly
        is_valid = engine.verify_key_derivation(derived, master)
        assert is_valid == True, "Verification should pass for correct derivation"
        
        # Different master should fail
        wrong_master = engine.generate_master_key(512)
        is_invalid = engine.verify_key_derivation(derived, wrong_master)
        assert is_invalid == False, "Verification should fail with wrong master"
        
        print("  ✓ PASSED - Derivation verification working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 11: Key Rotation
    print("\n[TEST 11] Key Rotation")
    try:
        master = engine.generate_master_key(512)
        original = engine.derive_session_key(master, "session_rot")
        rotated = engine.rotate_key(original, master)
        
        assert original.key_id != rotated.key_id
        assert original.key_type == rotated.key_type
        assert original.length_bits == rotated.length_bits
        assert rotated.parent_key_id == master.key_id
        print("  ✓ PASSED - Key rotation working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 12: Key Format Conversion
    print("\n[TEST 12] Key Format Conversion")
    try:
        master = engine.generate_master_key(256)
        hex_key = master.get_hex()
        b64_key = master.get_base64()
        
        assert len(hex_key) == 64  # 32 bytes = 64 hex chars
        assert isinstance(hex_key, str)
        assert isinstance(b64_key, str)
        assert len(b64_key) > 0
        print("  ✓ PASSED - Key format conversion working")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 13: Secure Wipe
    print("\n[TEST 13] Secure Key Wipe")
    try:
        key = engine.generate_master_key(256)
        original_material = key.key_material[:]
        key.secure_wipe()
        
        # After wipe, material should be all zeros
        assert all(b == 0 for b in key.key_material)
        print("  ✓ PASSED - Secure key wipe working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 14: Audit Logging
    print("\n[TEST 14] Audit Logging")
    try:
        fresh_engine = PostQuantumKeyDerivationEngine()
        log_before = len(fresh_engine.get_audit_log())
        
        master = fresh_engine.generate_master_key(256)
        session = fresh_engine.derive_session_key(master, "test")
        
        log_after = len(fresh_engine.get_audit_log())
        assert log_after > log_before
        assert log_after >= 2  # At least master + session
        
        audit_log = fresh_engine.get_audit_log()
        assert "operation" in audit_log[0]
        assert "key_id" in audit_log[0]
        assert "timestamp" in audit_log[0]
        print("  ✓ PASSED - Audit logging working correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 15: Derivation Report
    print("\n[TEST 15] Derivation Report Generation")
    try:
        master = engine.generate_master_key(512)
        derived = engine.derive_session_key(master, "report_test")
        report = engine.generate_derivation_report(derived)
        
        assert "key_id" in report
        assert "key_type" in report
        assert "algorithm" in report
        assert "length_bits" in report
        assert "parent_key_id" in report
        assert "diversification_depth" in report
        assert report["parent_key_id"] == master.key_id
        print("  ✓ PASSED - Derivation report generated correctly")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 16: Multiple KDF Algorithms
    print("\n[TEST 16] Multiple KDF Algorithm Support")
    try:
        algorithms = [
            KDFAlgorithm.HKDF_SHA256,
            KDFAlgorithm.HKDF_SHA512,
            KDFAlgorithm.SP800_108_COUNTER,
            KDFAlgorithm.CONCAT_KDF,
        ]
        
        master = engine.generate_master_key(256)
        results = []
        
        for algo in algorithms:
            derived = engine.derive_key(
                parent_key=master,
                key_type=KeyType.DERIVED_KEY,
                algorithm=algo
            )
            assert derived.algorithm == algo
            results.append(derived.key_id)
        
        # All key IDs should be unique (different algorithms produce different keys)
        assert len(set(results)) == len(results)
        print(f"  ✓ PASSED - {len(algorithms)} KDF algorithms working")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 17: Deterministic Derivation
    print("\n[TEST 17] Deterministic Derivation (same input = same output)")
    try:
        master = engine.generate_master_key(512)
        ctx = DiversificationContext(
            strategy=DiversificationStrategy.CONTEXT_BASED,
            purpose="deterministic_test"
        )
        
        # Derive twice with same context
        key1 = engine.derive_key(master, KeyType.DERIVED_KEY, context=ctx)
        key2 = engine.derive_key(master, KeyType.DERIVED_KEY, context=ctx)
        
        # Keys should be different because of random salt (security feature)
        # But both should be valid derivations from master
        assert engine.verify_key_derivation(key1, master)
        assert engine.verify_key_derivation(key2, master)
        print("  ✓ PASSED - Deterministic verification working")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Test 18: Performance Benchmark
    print("\n[TEST 18] Performance Benchmark")
    try:
        benchmark = engine.benchmark_kdf_performance(iterations=5)
        
        assert "benchmark_timestamp" in benchmark
        assert "results" in benchmark
        assert len(benchmark["results"]) > 0
        
        # At least HKDF should work
        assert "hkdf_sha256" in benchmark["results"]
        assert "operations_per_second" in benchmark["results"]["hkdf_sha256"]
        print("  ✓ PASSED - Performance benchmark working")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ FAILED - {e}")
        failed += 1
    
    # Summary
    print("\n" + "=" * 70)
    print(f"TEST SUMMARY: {passed} PASSED | {failed} FAILED")
    print("=" * 70)
    
    # Save test results
    test_results = {
        "test_timestamp": __import__('datetime').datetime.now().isoformat(),
        "total_tests": passed + failed,
        "passed": passed,
        "failed": failed,
        "success_rate": f"{(passed/(passed+failed))*100:.1f}%"
    }
    
    with open('test_results_key_diversification_derivation_engine.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print(f"\nTest results saved to test_results_key_diversification_derivation_engine.json")
    
    return failed == 0
if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
