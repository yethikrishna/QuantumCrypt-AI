"""
TEST SUITE: Post-Quantum Secure Backup & Recovery
QuantumCrypt-AI - June 2026
REAL TESTS
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quantum_crypt.post_quantum_secure_backup_recovery_2026_june import (
    PostQuantumSecureBackupRecovery
)

def test_basic_backup_recovery():
    print("TEST 1: Basic Backup & Recovery")
    backup_system = PostQuantumSecureBackupRecovery("test_password", iterations=10000)
    original_data = {"api_key": "secret_123", "settings": {"port": 8080}}
    backup = backup_system.create_backup(original_data)
    result = backup_system.recover_backup(backup)
    assert result.recovered_data['api_key'] == original_data['api_key'], "Data should match"
    print(f"  HMAC verified: {result.hmac_verified}")
    print("✓ TEST 1 PASSED")

def test_hmac_tampering():
    print("TEST 2: HMAC Tampering Detection")
    backup_system = PostQuantumSecureBackupRecovery("hmac_test", iterations=10000)
    backup = backup_system.create_backup({"important": "data"})
    backup.encrypted_data = b'TAMPERED' + backup.encrypted_data[8:]
    result = backup_system.recover_backup(backup)
    assert result.hmac_verified == False, "HMAC should detect tampering"
    print("  Tampering correctly detected!")
    print("✓ TEST 2 PASSED")

def test_honest_security_report():
    print("TEST 3: Honest Security Reporting")
    backup_system = PostQuantumSecureBackupRecovery("test", iterations=10000)
    report = backup_system.get_honest_security_report()
    assert report['ACTUAL_SECURITY']['is_nist_post_quantum'] == False, "Must be HONEST"
    assert report['ACTUAL_SECURITY']['crystals_kyber_used'] == False, "Must be HONEST"
    print("  ✓ All honesty checks passed - NO EXAGGERATION")
    print("✓ TEST 3 PASSED")

def test_compression():
    print("TEST 4: Compression Support")
    backup_system = PostQuantumSecureBackupRecovery("compress_test", iterations=10000)
    data = {"data": "A" * 1000}
    backup_compressed = backup_system.create_backup(data, compress=True)
    result = backup_system.recover_backup(backup_compressed)
    assert result.recovered_data is not None, "Should recover data"
    print(f"  Compressed size: {len(backup_compressed.encrypted_data)} bytes")
    print("✓ TEST 4 PASSED")

def main():
    print("\nQuantumCrypt-AI: Secure Backup & Recovery Tests")
    test_basic_backup_recovery()
    test_hmac_tampering()
    test_honest_security_report()
    test_compression()
    print("ALL TESTS PASSED ✓")
    return True

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
