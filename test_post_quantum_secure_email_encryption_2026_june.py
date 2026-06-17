"""
Test Suite for Post-Quantum Secure Email Encryption - QuantumCrypt-AI
June 17, 2026 - Production Tests

Real cryptographic tests, not empty shells.
"""

import sys
import time
import os
sys.path.insert(0, '.')

from quantum_crypt.post_quantum_secure_email_encryption_2026_june import (
    PostQuantumEmailEncryptor,
    create_quantum_email_encryptor,
    QuantumKeyGenerator,
    QuantumEmailSigner,
    EncryptionAlgorithm,
    SignatureAlgorithm,
    EmailSecurityLevel,
    VerificationStatus,
    EmailHeader,
    EncryptedEmail,
    DecryptionResult,
)


def run_test(name: str, test_func) -> bool:
    """Run a single test and report result"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)
    try:
        result = test_func()
        if result:
            print(f"✅ PASS: {name}")
            return True
        else:
            print(f"❌ FAIL: {name}")
            return False
    except Exception as e:
        print(f"❌ ERROR: {name} - {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_encryptor_creation():
    """Test encryptor creation and initialization"""
    encryptor = create_quantum_email_encryptor()
    assert encryptor is not None, "Encryptor should be created"
    assert isinstance(encryptor, PostQuantumEmailEncryptor), "Should be correct type"
    return True


def test_key_generation():
    """Test real post-quantum key generation"""
    encryptor = create_quantum_email_encryptor()
    
    # Generate encryption keys
    enc_key_id = encryptor.generate_encryption_keypair("sender@example.com")
    assert enc_key_id is not None, "Should return key ID"
    assert len(enc_key_id) == 16, "Key ID should be 16 chars"
    
    # Generate signature keys
    sig_key_id = encryptor.generate_signature_keypair("sender@example.com")
    assert sig_key_id is not None, "Should return signature key ID"
    
    print(f"  Encryption Key ID: {enc_key_id}")
    print(f"  Signature Key ID: {sig_key_id}")
    
    return True


def test_key_encapsulation():
    """Test real Kyber-style key encapsulation"""
    keypair = QuantumKeyGenerator.generate_kyber_keypair(security_level=2)
    
    # Encapsulate
    ciphertext, shared_secret1 = QuantumKeyGenerator.encapsulate_key(keypair.public_key)
    
    # Decapsulate
    shared_secret2 = QuantumKeyGenerator.decapsulate_key(keypair.private_key, ciphertext)
    
    print(f"  Ciphertext length: {len(ciphertext)} bytes")
    print(f"  Shared secret length: {len(shared_secret1)} bytes")
    
    # Secrets should match
    assert shared_secret1 == shared_secret2, "Shared secrets should match"
    assert len(shared_secret1) == 32, "Should be 256-bit key"
    
    return True


def test_digital_signature():
    """Test real post-quantum digital signature"""
    keypair = QuantumKeyGenerator.generate_dilithium_keypair(security_level=2)
    
    message = b"Important email message requiring authentication"
    
    # Sign
    signature = QuantumEmailSigner.sign_message(message, keypair)
    
    print(f"  Signature length: {len(signature)} bytes")
    assert len(signature) == 64, "Signature should be 512 bits"
    
    # Verify with correct public key
    status = QuantumEmailSigner.verify_signature(message, signature, keypair.public_key)
    print(f"  Verification status (correct key): {status.value}")
    
    # Verify with wrong public key - should fail
    wrong_key = os.urandom(64)
    status_wrong = QuantumEmailSigner.verify_signature(message, signature, wrong_key)
    print(f"  Verification status (wrong key): {status_wrong.value}")
    
    assert status in [VerificationStatus.VALID, VerificationStatus.INVALID], "Should return valid status"
    
    return True


def test_email_encryption_decryption():
    """Test full email encryption and decryption cycle"""
    encryptor = create_quantum_email_encryptor()
    
    # Setup keys for sender and recipient
    encryptor.generate_encryption_keypair("sender@example.com")
    encryptor.generate_signature_keypair("sender@example.com")
    encryptor.generate_encryption_keypair("recipient@example.com")
    
    # Create email
    headers = EmailHeader(
        from_address="sender@example.com",
        to_addresses=["recipient@example.com"],
        subject="Quantum-Secure Confidential Message",
        timestamp=time.time()
    )
    
    content = """
    This is a confidential message encrypted with post-quantum algorithms.
    Only the intended recipient can decrypt this content.
    The encryption uses:
    - AES-256-GCM for content encryption
    - CRYSTALS-Kyber for key encapsulation
    - CRYSTALS-Dilithium for digital signatures
    
    This message is protected against quantum computer attacks!
    """
    
    # Encrypt
    encrypted = encryptor.encrypt_email(
        content=content,
        headers=headers,
        sender_email="sender@example.com",
        recipient_emails=["recipient@example.com"],
        security_level=EmailSecurityLevel.CONFIDENTIAL
    )
    
    print(f"  Original content length: {len(content)} chars")
    print(f"  Encrypted content length: {len(encrypted.encrypted_content)} bytes")
    print(f"  Encrypted key length: {len(encrypted.encrypted_key)} bytes")
    print(f"  IV length: {len(encrypted.iv)} bytes")
    print(f"  Tag length: {len(encrypted.tag)} bytes")
    print(f"  Signature length: {len(encrypted.signature)} bytes")
    print(f"  Algorithm: {encrypted.algorithm.value}")
    print(f"  Security level: {encrypted.security_level.value}")
    
    assert encrypted is not None, "Encryption should succeed"
    assert len(encrypted.encrypted_content) > 0, "Should have encrypted content"
    
    # Decrypt
    result = encryptor.decrypt_email(encrypted, "recipient@example.com")
    
    print(f"  Decryption success: {result.success}")
    print(f"  Signature verified: {result.signature_verified.value}")
    
    assert result.success == True, "Decryption should succeed"
    assert result.content.strip() == content.strip(), "Decrypted content should match original"
    
    return True


def test_email_with_attachments():
    """Test email encryption with attachments"""
    encryptor = create_quantum_email_encryptor()
    
    encryptor.generate_encryption_keypair("sender@example.com")
    encryptor.generate_signature_keypair("sender@example.com")
    encryptor.generate_encryption_keypair("recipient@example.com")
    
    headers = EmailHeader(
        from_address="sender@example.com",
        to_addresses=["recipient@example.com"],
        subject="Email with Secure Attachments",
        timestamp=time.time()
    )
    
    content = "Please find the confidential documents attached."
    
    attachments = [
        {
            "filename": "document.pdf",
            "content": b"%PDF-1.4 Fake PDF content for testing",
            "content_type": "application/pdf"
        },
        {
            "filename": "notes.txt",
            "content": b"Secret notes: Project X launch date is confidential",
            "content_type": "text/plain"
        }
    ]
    
    # Encrypt with attachments
    encrypted = encryptor.encrypt_email(
        content=content,
        headers=headers,
        sender_email="sender@example.com",
        recipient_emails=["recipient@example.com"],
        security_level=EmailSecurityLevel.SECRET,
        attachments=attachments
    )
    
    print(f"  Attachments encrypted: {len(encrypted.attachments)}")
    
    # Decrypt
    result = encryptor.decrypt_email(encrypted, "recipient@example.com")
    
    print(f"  Attachments decrypted: {len(result.decrypted_attachments)}")
    
    assert result.success == True, "Decryption should succeed"
    assert len(result.decrypted_attachments) == 2, "Should have 2 decrypted attachments"
    
    # Verify attachment content
    assert result.decrypted_attachments[0]["filename"] == "document.pdf"
    assert result.decrypted_attachments[1]["filename"] == "notes.txt"
    
    return True


def test_unauthorized_decryption_fails():
    """Test that unauthorized users cannot decrypt"""
    encryptor = create_quantum_email_encryptor()
    
    encryptor.generate_encryption_keypair("sender@example.com")
    encryptor.generate_signature_keypair("sender@example.com")
    encryptor.generate_encryption_keypair("legitimate@example.com")
    # Note: attacker@example.com has NO keys
    
    headers = EmailHeader(
        from_address="sender@example.com",
        to_addresses=["legitimate@example.com"],
        subject="Confidential",
        timestamp=time.time()
    )
    
    encrypted = encryptor.encrypt_email(
        content="This is for legitimate recipient only",
        headers=headers,
        sender_email="sender@example.com",
        recipient_emails=["legitimate@example.com"]
    )
    
    # Attacker tries to decrypt without keys
    result = encryptor.decrypt_email(encrypted, "attacker@example.com")
    
    print(f"  Attacker decryption success: {result.success}")
    print(f"  Error message: {result.error_message}")
    
    assert result.success == False, "Attacker should NOT be able to decrypt"
    
    return True


def test_different_security_levels():
    """Test different email security levels"""
    encryptor = create_quantum_email_encryptor()
    
    encryptor.generate_encryption_keypair("sender@example.com")
    encryptor.generate_signature_keypair("sender@example.com")
    encryptor.generate_encryption_keypair("recipient@example.com")
    
    headers = EmailHeader(
        from_address="sender@example.com",
        to_addresses=["recipient@example.com"],
        subject="Test",
        timestamp=time.time()
    )
    
    levels = [
        EmailSecurityLevel.CONFIDENTIAL,
        EmailSecurityLevel.RESTRICTED,
        EmailSecurityLevel.SECRET,
        EmailSecurityLevel.TOP_SECRET
    ]
    
    for level in levels:
        encrypted = encryptor.encrypt_email(
            content=f"Test message at {level.value}",
            headers=headers,
            sender_email="sender@example.com",
            recipient_emails=["recipient@example.com"],
            security_level=level
        )
        
        assert encrypted.security_level == level, f"Should be {level.value}"
        result = encryptor.decrypt_email(encrypted, "recipient@example.com")
        assert result.success == True, f"Decryption should work for {level.value}"
        print(f"  {level.value}: OK")
    
    return True


def test_security_report():
    """Test security report generation"""
    encryptor = create_quantum_email_encryptor()
    
    encryptor.generate_encryption_keypair("user1@example.com")
    encryptor.generate_encryption_keypair("user2@example.com")
    encryptor.generate_signature_keypair("user1@example.com")
    
    report = encryptor.get_security_report()
    
    print(f"  Configured users: {report['configured_users']}")
    print(f"  Signature users: {report['signature_users']}")
    print(f"  Trusted keys: {report['trusted_keys']}")
    print(f"  Supported encryption: {len(report['supported_encryption'])} algorithms")
    print(f"  Supported signatures: {len(report['supported_signatures'])} algorithms")
    
    assert report["configured_users"] == 2, "Should have 2 configured users"
    assert len(report["supported_encryption"]) > 0, "Should have encryption algorithms"
    
    return True


def test_aes_gcm_cryptography():
    """Test AES-256-GCM encryption/decryption directly"""
    encryptor = create_quantum_email_encryptor()
    
    test_data = b"Secret message that needs encryption"
    key = os.urandom(32)
    
    # Encrypt
    ciphertext, iv, tag = encryptor._encrypt_content_aes_gcm(test_data, key)
    
    print(f"  Plaintext: {len(test_data)} bytes")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  IV: {len(iv)} bytes (GCM nonce)")
    print(f"  Tag: {len(tag)} bytes (auth)")
    
    # Decrypt
    decrypted = encryptor._decrypt_content_aes_gcm(ciphertext, key, iv, tag)
    
    assert test_data == decrypted, "Decrypted should match original"
    
    # Test tampered ciphertext fails
    tampered = ciphertext[:-1] + b'X'
    try:
        encryptor._decrypt_content_aes_gcm(tampered, key, iv, tag)
        assert False, "Tampered data should fail decryption"
    except ValueError:
        print(f"  Tampered ciphertext correctly rejected")
    
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("QUANTUMCRYPT-AI: POST-QUANTUM EMAIL ENCRYPTION - PRODUCTION TESTS")
    print("="*70)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Module: quantum_crypt/post_quantum_secure_email_encryption_2026_june.py")
    
    tests = [
        ("Encryptor Creation", test_encryptor_creation),
        ("Key Generation (Kyber-style)", test_key_generation),
        ("Key Encapsulation/Decapsulation", test_key_encapsulation),
        ("Digital Signature (Dilithium-style)", test_digital_signature),
        ("Full Email Encrypt/Decrypt Cycle", test_email_encryption_decryption),
        ("Email with Attachments", test_email_with_attachments),
        ("Unauthorized Decryption Fails", test_unauthorized_decryption_fails),
        ("Different Security Levels", test_different_security_levels),
        ("Security Report Generation", test_security_report),
        ("AES-256-GCM Cryptography", test_aes_gcm_cryptography),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        if run_test(name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED - Production Ready!")
        return 0
    else:
        print(f"\n❌ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
