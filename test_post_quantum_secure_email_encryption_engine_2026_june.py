"""
Test Suite for Post-Quantum Secure Email Encryption Engine
Production-grade tests with actual assertions
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

import unittest
import json
import base64
from datetime import datetime
from post_quantum_secure_email_encryption_engine_2026_june import (
    PostQuantumEmailEncryptionEngine,
    EmailAttachment,
    EncryptedEmailResult,
    DecryptedEmailResult,
    EmailHeader,
    EncryptionType,
    SignatureStatus,
    ChaCha20Engine,
    SimplePoly1305,
    HKDF
)


class TestPostQuantumEmailEncryptionEngine(unittest.TestCase):
    """Production-grade test suite for Email Encryption Engine"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test engine instance"""
        cls.engine = PostQuantumEmailEncryptionEngine()
        cls.test_key, cls.test_fingerprint = cls.engine.generate_encryption_key()
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        # Create fresh engine to avoid test ordering issues
        fresh_engine = PostQuantumEmailEncryptionEngine()
        self.assertIsNotNone(fresh_engine.hkdf)
        self.assertEqual(fresh_engine._operations_count, 0)
        self.assertIsInstance(fresh_engine._signature_keys, dict)
        self.assertEqual(fresh_engine.ALGORITHM, "CHACHA20-POLY1305")
    
    def test_generate_message_id(self):
        """Test message ID generation"""
        msg_id1 = self.engine.generate_message_id()
        msg_id2 = self.engine.generate_message_id()
        
        self.assertIsInstance(msg_id1, str)
        self.assertEqual(len(msg_id1), 32)
        self.assertNotEqual(msg_id1, msg_id2)  # IDs should be unique
    
    def test_generate_encryption_key(self):
        """Test encryption key generation"""
        key, fingerprint = self.engine.generate_encryption_key()
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # 256-bit key
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 16)
    
    def test_generate_signing_key(self):
        """Test signing key generation"""
        key, key_id = self.engine.generate_signing_key()
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key_id, str)
        self.assertEqual(len(key_id), 16)
        self.assertIn(key_id, self.engine._signature_keys)
    
    def test_generate_nonce(self):
        """Test nonce generation"""
        nonce1 = self.engine.generate_nonce()
        nonce2 = self.engine.generate_nonce()
        
        self.assertIsInstance(nonce1, bytes)
        self.assertEqual(len(nonce1), 12)
        self.assertNotEqual(nonce1, nonce2)  # Nonces should be unique
    
    def test_chacha20_encryption_decryption(self):
        """Test ChaCha20 core encryption and decryption"""
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        plaintext = b"Hello, Quantum Cryptography!"
        
        chacha = ChaCha20Engine(key)
        ciphertext = chacha.encrypt(plaintext, nonce)
        decrypted = chacha.decrypt(ciphertext, nonce)
        
        self.assertNotEqual(plaintext, ciphertext)
        self.assertEqual(plaintext, decrypted)
    
    def test_chacha20_different_keys(self):
        """Test that different keys produce different ciphertexts"""
        nonce = b'\x00' * 12
        plaintext = b"Test message"
        
        chacha1 = ChaCha20Engine(b'\x00' * 32)
        chacha2 = ChaCha20Engine(b'\x01' * 32)
        
        cipher1 = chacha1.encrypt(plaintext, nonce)
        cipher2 = chacha2.encrypt(plaintext, nonce)
        
        self.assertNotEqual(cipher1, cipher2)
    
    def test_poly1305_tag_computation(self):
        """Test Poly1305 tag computation"""
        key = b'\x00' * 32
        message = b"Test message for authentication"
        
        poly = SimplePoly1305(key)
        tag = poly.compute_tag(message)
        
        self.assertIsInstance(tag, bytes)
        self.assertEqual(len(tag), 16)
    
    def test_poly1305_tag_verification(self):
        """Test Poly1305 tag verification"""
        key = b'\x00' * 32
        message = b"Test message"
        
        poly = SimplePoly1305(key)
        tag = poly.compute_tag(message)
        
        self.assertTrue(poly.verify_tag(message, tag))
        self.assertFalse(poly.verify_tag(b"Different message", tag))
    
    def test_hkdf_derivation(self):
        """Test HKDF key derivation"""
        hkdf = HKDF()
        ikm = b"input key material"
        salt = b"salt value"
        info = b"context info"
        
        derived = hkdf.derive_key(ikm, salt, info, length=32)
        
        self.assertIsInstance(derived, bytes)
        self.assertEqual(len(derived), 32)
    
    def test_hkdf_deterministic(self):
        """Test HKDF produces same output for same inputs"""
        hkdf = HKDF()
        ikm = b"input key material"
        salt = b"salt value"
        
        derived1 = hkdf.derive_key(ikm, salt, b"test", length=32)
        derived2 = hkdf.derive_key(ikm, salt, b"test", length=32)
        
        self.assertEqual(derived1, derived2)
    
    def test_parse_email_headers(self):
        """Test email header parsing"""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 19 Jun 2026 10:00:00 UTC

This is the email body.
"""
        headers = self.engine.parse_email_headers(email_content)
        
        self.assertIsInstance(headers, dict)
        self.assertEqual(headers.get('from'), 'sender@example.com')
        self.assertEqual(headers.get('to'), 'recipient@example.com')
        self.assertEqual(headers.get('subject'), 'Test Email')
    
    def test_extract_email_body(self):
        """Test email body extraction"""
        email_content = """From: sender@example.com
To: recipient@example.com

This is the email body.
It has multiple lines.
"""
        body = self.engine.extract_email_body(email_content)
        
        self.assertIsInstance(body, str)
        self.assertIn("This is the email body", body)
        self.assertIn("multiple lines", body)
    
    def test_encrypt_email_body(self):
        """Test email body encryption"""
        body = "This is a secret email message with confidential content."
        
        ciphertext, nonce, tag = self.engine.encrypt_email_body(body, self.test_key)
        
        self.assertIsInstance(ciphertext, bytes)
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(tag, bytes)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(len(tag), 16)
        self.assertNotEqual(body.encode('utf-8'), ciphertext)
    
    def test_decrypt_email_body_success(self):
        """Test successful email body decryption"""
        original_body = "This is a secret message."
        
        ciphertext, nonce, tag = self.engine.encrypt_email_body(original_body, self.test_key)
        decrypted_body, verified = self.engine.decrypt_email_body(ciphertext, self.test_key, nonce, tag)
        
        self.assertTrue(verified)
        self.assertEqual(original_body, decrypted_body)
    
    def test_decrypt_email_body_wrong_key(self):
        """Test decryption fails with wrong key"""
        original_body = "Secret message"
        wrong_key = b'\x99' * 32
        
        ciphertext, nonce, tag = self.engine.encrypt_email_body(original_body, self.test_key)
        decrypted_body, verified = self.engine.decrypt_email_body(ciphertext, wrong_key, nonce, tag)
        
        self.assertFalse(verified)
        self.assertEqual(decrypted_body, "")
    
    def test_encrypt_attachment(self):
        """Test attachment encryption"""
        attachment = EmailAttachment(
            filename="document.pdf",
            content_type="application/pdf",
            content=b"%PDF-1.4 test content"
        )
        
        encrypted = self.engine.encrypt_attachment(attachment, self.test_key)
        
        self.assertTrue(encrypted.encrypted)
        self.assertEqual(encrypted.filename, "document.pdf.qcrypt")
        self.assertNotEqual(attachment.content, encrypted.content)
        self.assertIsInstance(encrypted.checksum, str)
        self.assertEqual(len(encrypted.checksum), 64)  # SHA256 hex
    
    def test_decrypt_attachment_success(self):
        """Test successful attachment decryption"""
        original_content = b"%PDF-1.4 test document content"
        attachment = EmailAttachment(
            filename="document.pdf",
            content_type="application/pdf",
            content=original_content
        )
        
        encrypted = self.engine.encrypt_attachment(attachment, self.test_key)
        decrypted = self.engine.decrypt_attachment(encrypted, self.test_key)
        
        self.assertIsNotNone(decrypted)
        self.assertFalse(decrypted.encrypted)
        self.assertEqual(decrypted.filename, "document.pdf")
        self.assertEqual(original_content, decrypted.content)
    
    def test_decrypt_attachment_wrong_key(self):
        """Test attachment decryption fails with wrong key"""
        wrong_key = b'\x99' * 32
        attachment = EmailAttachment(
            filename="doc.pdf",
            content_type="application/pdf",
            content=b"test"
        )
        
        encrypted = self.engine.encrypt_attachment(attachment, self.test_key)
        decrypted = self.engine.decrypt_attachment(encrypted, wrong_key)
        
        self.assertIsNone(decrypted)
    
    def test_sign_email(self):
        """Test email signing"""
        signing_key, _ = self.engine.generate_signing_key()
        content = "Email content to sign"
        
        signature = self.engine.sign_email(content, signing_key)
        
        self.assertIsInstance(signature, str)
        # Verify it's valid base64
        decoded = base64.b64decode(signature)
        self.assertEqual(len(decoded), 64)  # SHA512 output
    
    def test_verify_email_signature_valid(self):
        """Test valid signature verification"""
        signing_key, _ = self.engine.generate_signing_key()
        content = "Test email content"
        
        signature = self.engine.sign_email(content, signing_key)
        is_valid = self.engine.verify_email_signature(content, signature, signing_key)
        
        self.assertTrue(is_valid)
    
    def test_verify_email_signature_invalid(self):
        """Test invalid signature detection"""
        signing_key, _ = self.engine.generate_signing_key()
        content = "Test email content"
        
        signature = self.engine.sign_email(content, signing_key)
        is_valid = self.engine.verify_email_signature("Different content", signature, signing_key)
        
        self.assertFalse(is_valid)
    
    def test_encrypt_full_email(self):
        """Test full email encryption"""
        subject = "Confidential Report"
        sender = "alice@example.com"
        recipients = ["bob@example.com", "charlie@example.com"]
        body = "This is the confidential email body content."
        attachments = [
            EmailAttachment(
                filename="report.pdf",
                content_type="application/pdf",
                content=b"%PDF-1.4 report content"
            )
        ]
        
        result = self.engine.encrypt_full_email(
            subject, sender, recipients, body, attachments, self.test_key, sign=True
        )
        
        self.assertIsInstance(result, EncryptedEmailResult)
        self.assertTrue(result.success)
        self.assertEqual(result.subject, subject)
        self.assertEqual(result.sender, sender)
        self.assertEqual(result.recipients, recipients)
        self.assertTrue(result.body_encrypted)
        self.assertEqual(result.attachments_encrypted, 1)
        self.assertEqual(result.total_attachments, 1)
        self.assertTrue(result.signed)
        self.assertGreater(result.encryption_time_ms, 0)
        self.assertEqual(result.algorithm, self.engine.ALGORITHM)
        self.assertEqual(result.key_fingerprint, self.test_fingerprint)
    
    def test_create_mime_encrypted_email(self):
        """Test MIME formatted encrypted email creation"""
        subject = "Encrypted Email"
        sender = "sender@example.com"
        recipients = ["recipient@example.com"]
        body = "Secret message body"
        
        mime_email = self.engine.create_mime_encrypted_email(
            subject, sender, recipients, body, self.test_key
        )
        
        self.assertIsInstance(mime_email, str)
        self.assertIn("From: sender@example.com", mime_email)
        self.assertIn("To: recipient@example.com", mime_email)
        self.assertIn("Subject: Encrypted Email", mime_email)
        self.assertIn("X-QuantumCrypt-Encrypted: yes", mime_email)
        self.assertIn("BEGIN QUANTUMCRYPT ENCRYPTED MESSAGE", mime_email)
        self.assertIn("END QUANTUMCRYPT ENCRYPTED MESSAGE", mime_email)
    
    def test_is_quantumcrypt_email(self):
        """Test QuantumCrypt email detection"""
        encrypted_email = self.engine.create_mime_encrypted_email(
            "Test", "a@b.com", ["c@d.com"], "body", self.test_key
        )
        regular_email = """From: a@b.com
To: c@d.com
Subject: Regular

Body
"""
        self.assertTrue(self.engine.is_quantumcrypt_email(encrypted_email))
        self.assertFalse(self.engine.is_quantumcrypt_email(regular_email))
    
    def test_get_email_encryption_info(self):
        """Test encryption info extraction"""
        encrypted_email = self.engine.create_mime_encrypted_email(
            "Test Subject", "sender@test.com", ["recipient@test.com"], "body", self.test_key
        )
        
        info = self.engine.get_email_encryption_info(encrypted_email)
        
        self.assertIsNotNone(info)
        self.assertEqual(info["algorithm"], "CHACHA20-POLY1305")
        self.assertTrue(info["has_nonce"])
        self.assertTrue(info["has_tag"])
        self.assertEqual(info["subject"], "Test Subject")
        self.assertEqual(info["sender"], "sender@test.com")
    
    def test_email_header_serialization(self):
        """Test email header serialization"""
        nonce = b'\x00' * 12
        tag = b'\x00' * 16
        
        header = EmailHeader.create(
            algorithm="TEST-ALG",
            nonce=nonce,
            tag=tag,
            body_size=1024,
            attachment_count=2,
            signed=True
        )
        
        serialized = header.serialize()
        
        self.assertIsInstance(serialized, bytes)
        self.assertEqual(len(serialized), EmailHeader.get_header_size())
    
    def test_email_header_deserialization(self):
        """Test email header deserialization"""
        nonce = b'\x01' * 12
        tag = b'\x02' * 16
        
        original = EmailHeader.create(
            algorithm="TEST",
            nonce=nonce,
            tag=tag,
            body_size=2048,
            attachment_count=3,
            signed=False
        )
        
        serialized = original.serialize()
        deserialized = EmailHeader.deserialize(serialized)
        
        self.assertIsNotNone(deserialized)
        self.assertEqual(deserialized.algorithm, "TEST")
        self.assertEqual(deserialized.nonce, nonce)
        self.assertEqual(deserialized.tag, tag)
        self.assertEqual(deserialized.body_size, 2048)
        self.assertEqual(deserialized.attachment_count, 3)
        self.assertFalse(deserialized.signed)
    
    def test_email_header_tamper_detection(self):
        """Test header tampering detection"""
        header = EmailHeader.create(
            algorithm="TEST",
            nonce=b'\x00' * 12,
            tag=b'\x00' * 16,
            body_size=100,
            attachment_count=1,
            signed=True
        )
        
        serialized = header.serialize()
        tampered = serialized[:-1] + b'\xff'  # Tamper with checksum
        
        deserialized = EmailHeader.deserialize(tampered)
        self.assertIsNone(deserialized)
    
    def test_encryption_type_enum(self):
        """Test EncryptionType enum"""
        self.assertEqual(EncryptionType.BODY_ONLY.value, "BODY_ONLY")
        self.assertEqual(EncryptionType.ATTACHMENTS_ONLY.value, "ATTACHMENTS_ONLY")
        self.assertEqual(EncryptionType.FULL_EMAIL.value, "FULL_EMAIL")
        self.assertEqual(EncryptionType.SIGNATURE_ONLY.value, "SIGNATURE_ONLY")
    
    def test_signature_status_enum(self):
        """Test SignatureStatus enum"""
        self.assertEqual(SignatureStatus.VALID.value, "VALID")
        self.assertEqual(SignatureStatus.INVALID.value, "INVALID")
        self.assertEqual(SignatureStatus.UNVERIFIED.value, "UNVERIFIED")
        self.assertEqual(SignatureStatus.EXPIRED.value, "EXPIRED")
    
    def test_get_engine_info(self):
        """Test engine info retrieval"""
        info = self.engine.get_engine_info()
        
        self.assertIsInstance(info, dict)
        self.assertEqual(info["engine"], "PostQuantumEmailEncryptionEngine")
        self.assertEqual(info["algorithm"], "CHACHA20-POLY1305")
        self.assertEqual(info["key_size_bits"], 256)
        self.assertEqual(info["nonce_size_bytes"], 12)
        self.assertEqual(info["tag_size_bytes"], 16)
        self.assertEqual(info["kdf"], "HKDF-SHA512")
        self.assertTrue(info["mime_compatible"])
        self.assertTrue(info["supports_attachments"])
    
    def test_full_email_workflow(self):
        """Test complete email encryption workflow"""
        # Step 1: Generate keys
        key, fingerprint = self.engine.generate_encryption_key()
        
        # Step 2: Create test email content
        subject = "Q3 Financial Report - CONFIDENTIAL"
        sender = "cfo@company.com"
        recipients = ["board@company.com"]
        body = """
        Confidential Q3 Financial Report:
        - Revenue: $10.5M
        - Expenses: $7.2M
        - Net Profit: $3.3M
        """
        attachments = [
            EmailAttachment(
                filename="q3_financials.xlsx",
                content_type="application/vnd.openxmlformats",
                content=b"XLSX binary content here"
            ),
            EmailAttachment(
                filename="board_memo.pdf",
                content_type="application/pdf",
                content=b"PDF memo content here"
            )
        ]
        
        # Step 3: Encrypt
        result = self.engine.encrypt_full_email(
            subject, sender, recipients, body, attachments, key
        )
        
        # Step 4: Verify result
        self.assertTrue(result.success)
        self.assertEqual(result.attachments_encrypted, 2)
        self.assertEqual(result.total_attachments, 2)
        self.assertGreater(result.encryption_time_ms, 0)
        
        # Step 5: Create MIME email
        mime_email = self.engine.create_mime_encrypted_email(
            subject, sender, recipients, body, key
        )
        
        # Step 6: Verify detection
        self.assertTrue(self.engine.is_quantumcrypt_email(mime_email))
        
        # Step 7: Save results
        with open("test_results_email_encryption.json", "w") as f:
            json.dump({
                "success": result.success,
                "message_id": result.message_id,
                "fingerprint": fingerprint,
                "algorithm": result.algorithm,
                "attachments_encrypted": result.attachments_encrypted,
                "encryption_time_ms": result.encryption_time_ms,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        
        self.assertTrue(os.path.exists("test_results_email_encryption.json"))


if __name__ == "__main__":
    # Run tests and output results
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPostQuantumEmailEncryptionEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate summary
    summary = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "timestamp": datetime.now().isoformat()
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY:")
    print("="*60)
    for key, value in summary.items():
        print(f"{key}: {value}")
    print("="*60)
    
    with open("test_results_email_encryption.json", "w") as f:
        json.dump(summary, f, indent=2)
