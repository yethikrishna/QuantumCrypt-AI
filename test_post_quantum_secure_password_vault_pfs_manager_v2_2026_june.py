"""
Test suite for Post-Quantum Secure Password Vault PFS Manager v2
Production-grade testing with real cryptographic operations.
"""
import sys
import os
import json
import time

# Add the quantum_crypt directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_password_vault_pfs_manager_v2_2026_june import (
    PostQuantumPasswordVaultPFSManagerV2,
    VaultSecurityLevel,
    SessionState,
    KeyRotationStatus,
    RotationPolicy
)


def test_vault_initialization():
    """Test basic vault initialization"""
    print("=" * 60)
    print("TEST 1: Vault Initialization")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="MySecureMasterPassword123!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT
    )
    
    health = vault.get_vault_health()
    
    print(f"\nVault Health:")
    print(f"  Security Level: {health['security_level']}")
    print(f"  Master Key Version: {health['master_key_version']}")
    print(f"  Rotation Status: {health['rotation_status']}")
    print(f"  Active Sessions: {health['active_sessions']}")
    print(f"  Audit Log Entries: {health['audit_log_entries']}")
    
    assert health['security_level'] == 'quantum_resistant'
    assert health['master_key_version'] == 1
    assert health['active_sessions'] >= 1
    assert health['rotation_status'] == 'up_to_date'
    
    print("\n✓ TEST 1 PASSED\n")
    return True


def test_add_and_retrieve_entry():
    """Test adding and retrieving password entries"""
    print("=" * 60)
    print("TEST 2: Add and Retrieve Vault Entries")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="TestMasterPassword456!",
        security_level=VaultSecurityLevel.ENHANCED
    )
    
    # Add entry
    result = vault.add_entry(
        service_name="GitHub",
        username="user@example.com",
        password="GitHubSecurePass789!",
        tags=["development", "code"]
    )
    
    print(f"\nAdd Entry Result:")
    print(f"  Success: {result.success}")
    print(f"  Entry ID: {result.entry_id}")
    print(f"  Session ID: {result.session_id}")
    print(f"  Message: {result.message}")
    
    assert result.success == True
    assert result.entry_id is not None
    entry_id = result.entry_id
    
    # Retrieve entry
    retrieved = vault.get_entry(entry_id)
    assert retrieved is not None
    
    service, username, password = retrieved
    print(f"\nRetrieved Entry:")
    print(f"  Service: {service}")
    print(f"  Username: {username}")
    print(f"  Password: {password}")
    
    assert service == "GitHub"
    assert username == "user@example.com"
    assert password == "GitHubSecurePass789!"
    
    # Check health updated
    health = vault.get_vault_health()
    assert health['total_entries'] == 1
    
    print("\n✓ TEST 2 PASSED\n")
    return True


def test_search_entries():
    """Test searching vault entries"""
    print("=" * 60)
    print("TEST 3: Search Vault Entries")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="SearchTest789!",
        security_level=VaultSecurityLevel.STANDARD
    )
    
    # Add multiple entries
    vault.add_entry("Google", "user@gmail.com", "GooglePass1", ["email", "work"])
    vault.add_entry("GitHub", "dev@github.com", "GitHubPass2", ["development", "code"])
    vault.add_entry("Amazon", "user@amazon.com", "AmazonPass3", ["shopping", "cloud"])
    
    # Search by service
    results = vault.search_entries("Google")
    print(f"\nSearch 'Google': {len(results)} results")
    assert len(results) == 1
    assert results[0]['service_name'] == "Google"
    
    # Search by tag
    results = vault.search_entries("development")
    print(f"Search 'development': {len(results)} results")
    assert len(results) == 1
    
    # Search that matches nothing
    results = vault.search_entries("Nonexistent")
    print(f"Search 'Nonexistent': {len(results)} results")
    assert len(results) == 0
    
    print("\n✓ TEST 3 PASSED\n")
    return True


def test_delete_entry():
    """Test deleting vault entries"""
    print("=" * 60)
    print("TEST 4: Delete Vault Entry")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="DeleteTest123!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT
    )
    
    # Add and delete
    result = vault.add_entry("TestService", "test@test.com", "TestPass123")
    entry_id = result.entry_id
    
    health_before = vault.get_vault_health()
    print(f"\nEntries before delete: {health_before['total_entries']}")
    
    delete_result = vault.delete_entry(entry_id)
    print(f"Delete Success: {delete_result.success}")
    
    health_after = vault.get_vault_health()
    print(f"Entries after delete: {health_after['total_entries']}")
    
    assert delete_result.success == True
    assert health_after['total_entries'] == health_before['total_entries'] - 1
    
    # Verify entry is gone
    retrieved = vault.get_entry(entry_id)
    assert retrieved is None
    
    print("\n✓ TEST 4 PASSED\n")
    return True


def test_session_management_pfs():
    """Test session management with Perfect Forward Secrecy - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 5: Session Management (PFS - NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="SessionTest456!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT
    )
    
    # Get initial session count
    health = vault.get_vault_health()
    initial_sessions = health['active_sessions']
    print(f"\nInitial active sessions: {initial_sessions}")
    
    # Perform operations to use sessions
    for i in range(5):
        vault.add_entry(f"Service{i}", f"user{i}@test.com", f"Pass{i}")
    
    health_after = vault.get_vault_health()
    print(f"Active sessions after operations: {health_after['active_sessions']}")
    print(f"Expired sessions: {health_after['expired_sessions']}")
    
    # Revoke a session
    session_ids = list(vault._session_keys.keys())
    if session_ids:
        revoke_result = vault.revoke_session(session_ids[0])
        print(f"Revoke session success: {revoke_result.success}")
        
        health_final = vault.get_vault_health()
        print(f"Expired/revoked sessions after revoke: {health_final['expired_sessions']}")
        assert health_final['expired_sessions'] > 0
    
    print("\n✓ TEST 5 PASSED\n")
    return True


def test_master_key_rotation():
    """Test master key rotation - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 6: Master Key Rotation (NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="OldPassword123!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT
    )
    
    # Add some entries
    vault.add_entry("Service1", "user1@test.com", "Password1")
    vault.add_entry("Service2", "user2@test.com", "Password2")
    
    health_before = vault.get_vault_health()
    print(f"\nBefore rotation:")
    print(f"  Key Version: {health_before['master_key_version']}")
    print(f"  Entries: {health_before['total_entries']}")
    
    # Rotate master key
    rotate_result = vault.rotate_master_key("OldPassword123!", "NewPassword456!")
    print(f"\nRotation Result:")
    print(f"  Success: {rotate_result.success}")
    print(f"  Message: {rotate_result.message}")
    
    health_after = vault.get_vault_health()
    print(f"\nAfter rotation:")
    print(f"  Key Version: {health_after['master_key_version']}")
    print(f"  Active Sessions: {health_after['active_sessions']}")
    
    assert rotate_result.success == True
    assert health_after['master_key_version'] > health_before['master_key_version']
    
    # Verify entries are still accessible
    entries = vault.search_entries("Service")
    assert len(entries) == 2
    
    print("\n✓ TEST 6 PASSED\n")
    return True


def test_emergency_rotation():
    """Test emergency key rotation for breach scenarios - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 7: Emergency Rotation (Breach Detection - NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="EmergencyTest789!",
        security_level=VaultSecurityLevel.MAXIMUM
    )
    
    vault.add_entry("CriticalService", "admin@company.com", "CriticalPass123")
    
    health_before = vault.get_vault_health()
    print(f"\nBefore emergency:")
    print(f"  Breach detected: {health_before['breach_detected']}")
    print(f"  Compromised entries: {health_before['compromised_entries']}")
    
    # Trigger emergency rotation
    emergency_result = vault.emergency_rotation("EmergencyTest789!")
    print(f"\nEmergency Rotation:")
    print(f"  Success: {emergency_result.success}")
    print(f"  Message: {emergency_result.message}")
    
    health_after = vault.get_vault_health()
    print(f"\nAfter emergency:")
    print(f"  Breach detected: {health_after['breach_detected']}")
    print(f"  Compromised entries: {health_after['compromised_entries']}")
    print(f"  Rotation status: {health_after['rotation_status']}")
    
    assert emergency_result.success == True
    assert health_after['breach_detected'] == True
    assert health_after['compromised_entries'] > 0
    
    print("\n✓ TEST 7 PASSED\n")
    return True


def test_audit_logging_integrity():
    """Test audit logging with cryptographic integrity - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 8: Audit Logging with Integrity (NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="AuditTest123!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT,
        enable_audit_logging=True
    )
    
    # Perform operations
    vault.add_entry("TestService", "user@test.com", "TestPass")
    vault.add_entry("AnotherService", "user2@test.com", "AnotherPass")
    
    audit_log = vault.get_audit_log(limit=10)
    print(f"\nAudit Log Entries: {len(audit_log)}")
    for entry in audit_log[:3]:
        print(f"  [{entry['timestamp']}] {entry['operation']}")
    
    # Verify integrity
    integrity_valid, valid_count = vault.verify_audit_log_integrity()
    print(f"\nAudit Log Integrity:")
    print(f"  Valid: {integrity_valid}")
    print(f"  Valid entries: {valid_count}/{len(audit_log)}")
    
    assert len(audit_log) > 0
    assert integrity_valid == True
    
    print("\n✓ TEST 8 PASSED\n")
    return True


def test_batch_operations():
    """Test batch operations - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 9: Batch Operations (NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="BatchTest456!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT
    )
    
    batch_entries = [
        ("Facebook", "user@facebook.com", "FBPass1", ["social"]),
        ("Twitter", "user@twitter.com", "TWPass2", ["social"]),
        ("LinkedIn", "user@linkedin.com", "LIPass3", ["professional"]),
        ("Instagram", "user@instagram.com", "IGPass4", ["social"]),
    ]
    
    results = vault.batch_add_entries(batch_entries)
    success_count = sum(1 for r in results if r.success)
    
    print(f"\nBatch Results:")
    print(f"  Total: {len(results)}")
    print(f"  Successful: {success_count}")
    
    health = vault.get_vault_health()
    print(f"  Total entries: {health['total_entries']}")
    
    assert success_count == len(batch_entries)
    assert health['total_entries'] == len(batch_entries)
    
    print("\n✓ TEST 9 PASSED\n")
    return True


def test_memory_hard_kdf():
    """Test memory-hard key derivation - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 10: Memory-Hard KDF (Quantum Resistance - NEW V2 FEATURE)")
    print("=" * 60)
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="KDFTest789!",
        security_level=VaultSecurityLevel.MAXIMUM
    )
    
    # Measure KDF performance
    start_time = time.time()
    salt = vault._generate_salt()
    derived_key = vault._memory_hard_kdf("TestPassword123!", salt, iterations=2)
    kdf_time = (time.time() - start_time) * 1000
    
    print(f"\nMemory-Hard KDF:")
    print(f"  Key length: {len(derived_key)} bytes")
    print(f"  Time: {kdf_time:.2f} ms")
    print(f"  Salt size: {len(salt)} bytes")
    
    assert len(derived_key) == vault.KEY_SIZE
    assert len(salt) == vault.SALT_SIZE
    
    # Verify determinism
    derived_key2 = vault._memory_hard_kdf("TestPassword123!", salt, iterations=2)
    assert derived_key == derived_key2, "KDF should be deterministic"
    
    # Verify different passwords produce different keys
    derived_key3 = vault._memory_hard_kdf("DifferentPassword!", salt, iterations=2)
    assert derived_key != derived_key3, "Different passwords should produce different keys"
    
    print("\n✓ TEST 10 PASSED\n")
    return True


def test_custom_rotation_policy():
    """Test custom rotation policy configuration - NEW V2 FEATURE"""
    print("=" * 60)
    print("TEST 11: Custom Rotation Policy (NEW V2 FEATURE)")
    print("=" * 60)
    
    custom_policy = RotationPolicy(
        master_key_rotation_days=30,
        session_key_rotation_hours=12,
        notify_before_days=3,
        auto_rotate=True
    )
    
    vault = PostQuantumPasswordVaultPFSManagerV2(
        master_password="PolicyTest123!",
        security_level=VaultSecurityLevel.QUANTUM_RESISTANT,
        rotation_policy=custom_policy
    )
    
    health = vault.get_vault_health()
    policy = health['rotation_policy']
    
    print(f"\nRotation Policy:")
    print(f"  Master key rotation: {policy['master_key_rotation_days']} days")
    print(f"  Session key rotation: {policy['session_key_rotation_hours']} hours")
    print(f"  Notify before: {policy['notify_before_days']} days")
    print(f"  Auto rotate: {policy['auto_rotate']}")
    
    assert policy['master_key_rotation_days'] == 30
    assert policy['session_key_rotation_hours'] == 12
    
    print("\n✓ TEST 11 PASSED\n")
    return True


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("POST-QUANTUM PASSWORD VAULT PFS MANAGER V2 - TEST SUITE")
    print("=" * 70 + "\n")
    
    tests = [
        test_vault_initialization,
        test_add_and_retrieve_entry,
        test_search_entries,
        test_delete_entry,
        test_session_management_pfs,
        test_master_key_rotation,
        test_emergency_rotation,
        test_audit_logging_integrity,
        test_batch_operations,
        test_memory_hard_kdf,
        test_custom_rotation_policy,
    ]
    
    passed = 0
    failed = 0
    test_results = {}
    
    for test in tests:
        try:
            if test():
                passed += 1
                test_results[test.__name__] = "PASSED"
            else:
                failed += 1
                test_results[test.__name__] = "FAILED"
        except Exception as e:
            failed += 1
            test_results[test.__name__] = f"ERROR: {str(e)}"
            print(f"\n✗ TEST {test.__name__} FAILED: {e}\n")
    
    print("=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    print(f"Success Rate: {passed/len(tests):.2%}")
    print("=" * 70)
    
    # Save results
    with open('test_results_password_vault_pfs_manager_v2_2026_june.json', 'w') as f:
        json.dump({
            'test_results': test_results,
            'passed': passed,
            'failed': failed,
            'total': len(tests),
            'success_rate': passed/len(tests),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }, f, indent=2)
    
    print(f"\nTest results saved to: test_results_password_vault_pfs_manager_v2_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
