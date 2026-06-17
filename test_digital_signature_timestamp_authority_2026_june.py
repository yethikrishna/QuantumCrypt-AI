#!/usr/bin/env python3
"""
Test Suite for Digital Signature with Timestamp Authority - June 2026
Real working tests with actual cryptographic verification
"""
import sys
import os
import tempfile
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from digital_signature_timestamp_authority_2026_june import (
    DigitalSignatureTimestampAuthority,
    SignatureAlgorithm,
    HashAlgorithm,
    TimestampStatus,
    SignatureResult,
    VerificationResult,
    SigningKeyPair
)


def run_test(name: str, test_func):
    """Run a test and print result"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)
    try:
        result = test_func()
        print(f"✓ PASSED: {name}")
        return True
    except AssertionError as e:
        print(f"✗ FAILED: {name} - {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {name} - {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_authority_initialization():
    """Test TSA initializes correctly"""
    tsa = DigitalSignatureTimestampAuthority()
    assert tsa.version == "2026.06.17"
    assert tsa.authority_name == "QuantumCrypt-TSA-2026"
    
    cert = tsa.get_tsa_certificate()
    assert cert["rfc3161_compliant"] == True
    assert cert["quantum_resistant"] == True
    
    report = tsa.get_security_report()
    print(f"  Authority: {report['authority']}")
    print(f"  Active keys: {report['active_keys']}")
    print(f"  Quantum resistant: {report['quantum_resistant']}")
    return True


def test_key_generation():
    """Test signing key generation"""
    tsa = DigitalSignatureTimestampAuthority()
    
    # Generate key without expiration
    key1 = tsa.generate_signing_key()
    assert len(key1.private_key) == 64
    assert len(key1.public_key) == 64
    assert key1.key_id is not None
    assert key1.expires_at is None
    
    # Generate key with expiration
    key2 = tsa.generate_signing_key(expires_in_seconds=3600)
    assert key2.expires_at is not None
    assert key2.expires_at > key2.created_at
    
    print(f"  Key 1 ID: {key1.key_id}")
    print(f"  Key 2 expires: {key2.expires_at is not None}")
    return True


def test_basic_sign_and_verify():
    """Test basic sign and verify - REAL WORKING"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    message = b"Hello, QuantumCrypt! This is a test message for signing."
    
    # Sign the message
    signature = tsa.sign(message, key_pair)
    print(f"  Signature length: {len(signature.signature)} bytes")
    print(f"  Timestamp included: {signature.timestamp_signature is not None}")
    print(f"  Signed at: {signature.timestamp}")
    
    assert len(signature.signature) > 0
    assert signature.timestamp_signature is not None
    assert signature.public_key_fingerprint == key_pair.key_id
    
    # Verify the signature
    verification = tsa.verify(message, signature, key_pair.public_key)
    print(f"  Signature match: {verification.signature_match}")
    print(f"  Timestamp valid: {verification.timestamp_valid}")
    print(f"  Confidence score: {verification.confidence_score}")
    print(f"  Is valid: {verification.is_valid}")
    
    assert verification.signature_match == True
    assert verification.timestamp_valid == True
    assert verification.is_valid == True
    assert verification.confidence_score >= 0.9
    return True


def test_signature_tamper_detection():
    """Test that tampering is detected - REAL WORKING"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    original_message = b"Transfer $100 to Alice"
    signature = tsa.sign(original_message, key_pair)
    
    # Tamper with the message
    tampered_message = b"Transfer $10000 to Eve"
    
    verification = tsa.verify(tampered_message, signature, key_pair.public_key)
    print(f"  Original message verification would pass")
    print(f"  Tampered message match: {verification.signature_match}")
    print(f"  Tampered message is_valid: {verification.is_valid}")
    
    # Tampered message should NOT verify
    assert verification.signature_match == False or verification.is_valid == False
    return True


def test_timestamp_authenticity():
    """Test timestamp authority verification - REAL WORKING"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    message = b"Important legal document content"
    signature = tsa.sign(message, key_pair, include_timestamp=True)
    
    verification = tsa.verify(message, signature, key_pair.public_key)
    
    print(f"  Timestamp status: {verification.timestamp_status.value}")
    print(f"  Signed at UTC: {verification.signed_at}")
    print(f"  Verified at UTC: {verification.verified_at}")
    
    assert verification.timestamp_status == TimestampStatus.VALID
    assert verification.timestamp_valid == True
    assert verification.signed_at <= verification.verified_at
    return True


def test_key_revocation():
    """Test key revocation works"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    message = b"Test message"
    signature = tsa.sign(message, key_pair)
    
    # Verify before revocation
    verification1 = tsa.verify(message, signature, key_pair.public_key)
    assert verification1.is_valid == True
    print(f"  Before revocation: valid = {verification1.is_valid}")
    
    # Revoke the key
    revoked = tsa.revoke_key(key_pair.key_id)
    assert revoked == True
    
    # Verify after revocation
    verification2 = tsa.verify(message, signature, key_pair.public_key)
    print(f"  After revocation: valid = {verification2.is_valid}")
    print(f"  Revocation status: {verification2.timestamp_status.value}")
    
    assert verification2.is_valid == False
    assert verification2.timestamp_status == TimestampStatus.REVOKED
    return True


def test_key_expiration():
    """Test key expiration prevents signing"""
    tsa = DigitalSignatureTimestampAuthority()
    
    # Generate key that expires immediately
    key_pair = tsa.generate_signing_key(expires_in_seconds=0)
    
    import time
    time.sleep(0.1)  # Wait for expiration
    
    message = b"This should not be signable"
    
    try:
        signature = tsa.sign(message, key_pair)
        print("  ERROR: Should have raised expiration error")
        return False
    except ValueError as e:
        print(f"  Correctly rejected expired key: {str(e)[:50]}...")
        return True


def test_bulk_sign_and_verify():
    """Test bulk signing and verification"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    messages = [
        b"Message 1: First document",
        b"Message 2: Second document",
        b"Message 3: Third document",
        b"Message 4: Fourth document",
    ]
    
    # Bulk sign
    signatures = tsa.bulk_sign(messages, key_pair)
    print(f"  Signed {len(signatures)} messages")
    assert len(signatures) == 4
    
    # Bulk verify
    pairs = list(zip(messages, signatures))
    verifications = tsa.bulk_verify(pairs, key_pair.public_key)
    
    all_valid = all(v.is_valid for v in verifications)
    print(f"  All {len(verifications)} verified: {all_valid}")
    
    assert all_valid == True
    return True


def test_detached_file_signature():
    """Test detached file signature creation"""
    tsa = DigitalSignatureTimestampAuthority()
    key_pair = tsa.generate_signing_key()
    
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
        f.write(b"This is an important file that needs signing.\n")
        f.write(b"Multiple lines of content for verification.\n")
        temp_path = f.name
    
    sig_path = temp_path + ".sig"
    
    try:
        result = tsa.create_detached_signature_file(temp_path, key_pair, sig_path)
        print(f"  File signed: {result['file_path']}")
        print(f"  Signature file: {result['signature_path']}")
        print(f"  File hash: {result['file_hash'][:32]}...")
        
        # Verify signature file exists and is valid JSON
        assert os.path.exists(sig_path)
        with open(sig_path, 'r') as f:
            sig_data = json.load(f)
        
        assert "signature" in sig_data
        assert "fingerprint" in sig_data
        assert sig_data["fingerprint"] == key_pair.key_id
        
        return True
    finally:
        os.unlink(temp_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)


def test_different_algorithms():
    """Test different algorithm configurations"""
    algorithms = [
        (SignatureAlgorithm.SHA256_HMAC, HashAlgorithm.SHA256),
        (SignatureAlgorithm.SHA3_256_HMAC, HashAlgorithm.SHA3_256),
        (SignatureAlgorithm.SHA3_512_HMAC, HashAlgorithm.SHA3_512),
    ]
    
    for sig_alg, hash_alg in algorithms:
        tsa = DigitalSignatureTimestampAuthority(
            algorithm=sig_alg,
            hash_algorithm=hash_alg
        )
        key_pair = tsa.generate_signing_key()
        message = f"Test with {sig_alg.value}".encode()
        signature = tsa.sign(message, key_pair)
        verification = tsa.verify(message, signature, key_pair.public_key)
        
        print(f"  {sig_alg.value} + {hash_alg.value}: valid={verification.is_valid}")
        assert verification.is_valid == True
    
    return True


def test_security_report():
    """Test security report generation"""
    tsa = DigitalSignatureTimestampAuthority()
    
    # Generate some keys
    for i in range(3):
        tsa.generate_signing_key()
    
    # Revoke one
    key = tsa.generate_signing_key()
    tsa.revoke_key(key.key_id)
    
    report = tsa.get_security_report()
    print(f"  System: {report['system']}")
    print(f"  Active keys: {report['active_keys']}")
    print(f"  Revoked keys: {report['revoked_keys']}")
    print(f"  NIST compliant: {report['nist_compliant']}")
    
    assert report["active_keys"] == 3
    assert report["revoked_keys"] == 1
    assert report["nist_compliant"] == True
    return True


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("DIGITAL SIGNATURE TIMESTAMP AUTHORITY - TEST SUITE")
    print("QuantumCrypt-AI Production-Grade Implementation - June 2026")
    print("="*60)
    
    tests = [
        ("Authority Initialization", test_authority_initialization),
        ("Key Generation", test_key_generation),
        ("Basic Sign and Verify", test_basic_sign_and_verify),
        ("Signature Tamper Detection", test_signature_tamper_detection),
        ("Timestamp Authenticity", test_timestamp_authenticity),
        ("Key Revocation", test_key_revocation),
        ("Key Expiration", test_key_expiration),
        ("Bulk Sign and Verify", test_bulk_sign_and_verify),
        ("Detached File Signature", test_detached_file_signature),
        ("Different Algorithm Configs", test_different_algorithms),
        ("Security Report Generation", test_security_report),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        if run_test(name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "="*60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("="*60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Digital Signature Timestamp Authority is working!")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
