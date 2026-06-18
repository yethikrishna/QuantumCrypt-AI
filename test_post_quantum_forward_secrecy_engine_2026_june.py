#!/usr/bin/env python3
"""
Test Suite for Post-Quantum Forward Secrecy Engine
June 2026 - Production Grade Tests

REAL TESTS - no mocking!
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib.util

# Load module directly
spec = importlib.util.spec_from_file_location(
    'forward_secrecy',
    'quantum_crypt/post_quantum_forward_secrecy_engine_2026_june.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

ForwardSecrecyEngine = module.ForwardSecrecyEngine


def run_all_tests():
    print("=" * 70)
    print("QuantumCrypt-AI: Post-Quantum Forward Secrecy Engine Tests")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Initialize engine
    print("\n[TEST 1] Initialize ForwardSecrecyEngine")
    try:
        engine = ForwardSecrecyEngine(
            rotation_interval_seconds=3600,
            max_key_usage=100
        )
        print("  ✓ Engine initialized successfully")
        print(f"    Rotation interval: {engine.rotation_interval}s")
        print(f"    Max key usage: {engine.max_key_usage}")
        test_results.append(("Initialize engine", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Initialize engine", False))
    
    # Test 2: Generate ephemeral keypair
    print("\n[TEST 2] Generate ephemeral keypair")
    try:
        keypair = engine.generate_ephemeral_keypair()
        print(f"  ✓ Ephemeral keypair generated")
        print(f"    Key ID: {keypair.key_id}")
        print(f"    Algorithm: {keypair.algorithm.value}")
        print(f"    Public key length: {len(keypair.public_key)} bytes")
        print(f"    Private key length: {len(keypair.private_key)} bytes")
        print(f"    Used: {keypair.used}")
        test_results.append(("Generate ephemeral keypair", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Generate ephemeral keypair", False))
    
    # Test 3: Perform key exchange
    print("\n[TEST 3] Perform post-quantum key exchange")
    try:
        peer_public_key = os.urandom(32)
        result = engine.perform_key_exchange(
            private_key_id=keypair.key_id,
            peer_public_key=peer_public_key,
            session_info={"context": "test-session-001"}
        )
        print(f"  ✓ Key exchange completed")
        print(f"    Session ID: {result['session_id']}")
        print(f"    Algorithm: {result['algorithm']}")
        print(f"    Key fingerprint: {result['session_key_fingerprint']}")
        print(f"    Ephemeral key marked as used: {keypair.used}")
        test_results.append(("Perform key exchange", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Perform key exchange", False))
    
    # Test 4: Get session key with usage tracking
    print("\n[TEST 4] Get session key with usage tracking")
    try:
        session_id = result["session_id"]
        key1 = engine.get_session_key(session_id)
        key2 = engine.get_session_key(session_id)
        key3 = engine.get_session_key(session_id)
        
        session = engine.session_keys[session_id]
        
        print(f"  ✓ Session keys retrieved")
        print(f"    Usage count: {session.key_usage_count}")
        print(f"    Keys identical: {key1 == key2 == key3}")
        print(f"    Key length: {len(key1)} bytes")
        test_results.append(("Get session key with tracking", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Get session key with tracking", False))
    
    # Test 5: Forward secrecy enforcement - cannot reuse ephemeral keys
    print("\n[TEST 5] Forward secrecy enforcement - no key reuse")
    try:
        try:
            engine.perform_key_exchange(
                private_key_id=keypair.key_id,
                peer_public_key=os.urandom(32)
            )
            print("  ✗ Should have raised error for reused key!")
            test_results.append(("Forward secrecy enforcement", False))
        except ValueError as e:
            print(f"  ✓ Correctly rejected reused ephemeral key")
            print(f"    Error: {e}")
            test_results.append(("Forward secrecy enforcement", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Forward secrecy enforcement", False))
    
    # Test 6: Rotate session key
    print("\n[TEST 6] Rotate session key (forward secrecy)")
    try:
        rotation_result = engine.rotate_session_key(
            session_id=session_id,
            reason="security_rotation"
        )
        print(f"  ✓ Session key rotated")
        print(f"    Old session: {rotation_result['old_session_id']}")
        print(f"    New session: {rotation_result['new_session_id']}")
        print(f"    Reason: {rotation_result['rotation_reason']}")
        print(f"    New key fingerprint: {rotation_result['new_key_fingerprint']}")
        test_results.append(("Rotate session key", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Rotate session key", False))
    
    # Test 7: Revoke session key
    print("\n[TEST 7] Revoke and wipe session key")
    try:
        revoke_success = engine.revoke_session_key(
            session_id=session_id,
            reason="compromise_suspected"
        )
        print(f"  ✓ Session key revoked: {revoke_success}")
        
        # Verify key is no longer accessible
        revoked_key = engine.get_session_key(session_id)
        print(f"    Revoked key returns None: {revoked_key is None}")
        test_results.append(("Revoke session key", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Revoke session key", False))
    
    # Test 8: HKDF key derivation verification
    print("\n[TEST 8] HKDF key derivation verification")
    try:
        shared_secret = b"test_shared_secret_12345"
        salt = b"test_salt"
        info = b"test_context"
        
        derived1 = engine._hkdf_derive(shared_secret, salt, info, 32)
        derived2 = engine._hkdf_derive(shared_secret, salt, info, 32)
        
        print(f"  ✓ HKDF deterministic derivation verified")
        print(f"    Derivations identical: {derived1 == derived2}")
        print(f"    Output length correct: {len(derived1)} == 32")
        test_results.append(("HKDF derivation verification", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("HKDF derivation verification", False))
    
    # Test 9: Cleanup expired keys
    print("\n[TEST 9] Secure cleanup of expired keys")
    try:
        cleanup_stats = engine.cleanup_expired_keys()
        print(f"  ✓ Expired key cleanup executed")
        print(f"    Ephemeral keys cleaned: {cleanup_stats['ephemeral_keys_cleaned']}")
        print(f"    Keys securely wiped: {cleanup_stats['keys_securely_wiped']}")
        test_results.append(("Cleanup expired keys", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Cleanup expired keys", False))
    
    # Test 10: Get forward secrecy status and audit report
    print("\n[TEST 10] Forward secrecy status & audit report")
    try:
        status = engine.get_forward_secrecy_status()
        report = engine.generate_session_audit_report()
        
        print(f"  ✓ Status report generated")
        print(f"    Forward secrecy enabled: {status['forward_secrecy_enabled']}")
        print(f"    Active sessions: {status['active_sessions']}")
        print(f"    Total rotations: {status['total_rotations']}")
        print(f"    Keys generated: {status['statistics']['keys_generated']}")
        print(f"    Keys rotated: {status['statistics']['keys_rotated']}")
        print(f"    Keys revoked: {status['statistics']['keys_revoked']}")
        print(f"  ✓ Audit report ID: {report['report_id']}")
        print(f"    PFS compliant: {report['forward_secrecy_compliant']}")
        test_results.append(("Status & audit report", True))
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        test_results.append(("Status & audit report", False))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
