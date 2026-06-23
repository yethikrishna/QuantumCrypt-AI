"""
Tests for QuantumCrypt Security Hardening v17 - Input Validation & Injection Protection
DIMENSION B: Security Hardening
All tests must pass - backward compatibility verified.
"""
import pytest
import os
import tempfile
import base64

from quantum_crypt.crypto_security_hardening_input_validation_injection_protection_v17_2026_june import (
    CryptoPathTraversalProtector,
    CryptoAlgorithmValidator,
    KeyMaterialValidator,
    CryptoInjectionProtector,
    CryptoInputValidator,
    CryptoHeaderInjectionProtector,
    is_safe_key_path,
    sanitize_key_path,
    validate_symmetric_algo,
    validate_mode,
    validate_hash_algo,
    validate_aes_key,
    validate_nonce,
    sanitize_key_input,
    generate_secure_nonce,
    generate_secure_salt,
    sanitize_openssl_arg,
    validate_hex,
    validate_base64,
    is_safe_crypto_header,
    sanitize_crypto_header,
)


class TestCryptoPathTraversalProtector:
    """Test key file path traversal protection."""
    
    def test_is_safe_key_path_normal(self):
        """Test normal safe key paths are accepted."""
        protector = CryptoPathTraversalProtector()
        assert protector.is_safe_key_path("key.pem", strict=False) is True
        assert protector.is_safe_key_path("keys/private.key", strict=False) is True
        assert protector.is_safe_key_path("cert.p12", strict=False) is True
    
    def test_is_safe_key_path_rejects_bad_extensions(self):
        """Test paths with wrong extensions are rejected."""
        protector = CryptoPathTraversalProtector()
        assert protector.is_safe_key_path("file.exe", strict=False) is False
        assert protector.is_safe_key_path("script.sh", strict=False) is False
        assert protector.is_safe_key_path("document.pdf", strict=False) is False
    
    def test_is_safe_key_path_detects_traversal(self):
        """Test path traversal attempts are detected."""
        protector = CryptoPathTraversalProtector()
        assert protector.is_safe_key_path("../etc/ssl.key", strict=False) is False
        assert protector.is_safe_key_path("..\\..\\secret.pem", strict=False) is False
    
    def test_sanitize_key_path(self):
        """Test key path sanitization."""
        protector = CryptoPathTraversalProtector()
        assert protector.sanitize_key_path("../key.pem") == ""
        assert protector.sanitize_key_path("safe_key.pem") == "safe_key.pem"
    
    def test_safe_key_path_join(self):
        """Test safe key path joining."""
        protector = CryptoPathTraversalProtector()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = protector.safe_key_path_join(tmpdir, "keys", "private.pem")
            assert result is not None
            
            # Traversal attempt should fail
            result = protector.safe_key_path_join(tmpdir, "..", "etc", "key.pem")
            assert result is None
    
    def test_convenience_functions(self):
        """Test public convenience functions."""
        assert is_safe_key_path("key.pem", strict=False) is True
        assert is_safe_key_path("../unsafe.key", strict=False) is False
        assert sanitize_key_path("key.pem") == "key.pem"


class TestCryptoAlgorithmValidator:
    """Test algorithm name validation."""
    
    def test_validate_symmetric_algorithm(self):
        """Test symmetric algorithm validation."""
        validator = CryptoAlgorithmValidator()
        
        valid, algo = validator.validate_symmetric_algorithm("AES")
        assert valid is True
        assert algo == "AES"
        
        valid, algo = validator.validate_symmetric_algorithm("AES-256")
        assert valid is True
        
        valid, algo = validator.validate_symmetric_algorithm("CHACHA20")
        assert valid is True
        
        valid, algo = validator.validate_symmetric_algorithm("INVALID")
        assert valid is False
    
    def test_validate_mode(self):
        """Test cipher mode validation."""
        validator = CryptoAlgorithmValidator()
        
        valid, mode = validator.validate_mode("GCM")
        assert valid is True
        assert mode == "GCM"
        
        valid, mode = validator.validate_mode("CBC")
        assert valid is True
        
        valid, mode = validator.validate_mode("INVALID")
        assert valid is False
    
    def test_validate_hash_algorithm(self):
        """Test hash algorithm validation."""
        validator = CryptoAlgorithmValidator()
        
        valid, algo = validator.validate_hash_algorithm("SHA256")
        assert valid is True
        
        valid, algo = validator.validate_hash_algorithm("SHA512")
        assert valid is True
    
    def test_validate_asymmetric_algorithm(self):
        """Test asymmetric algorithm validation."""
        validator = CryptoAlgorithmValidator()
        
        valid, algo = validator.validate_asymmetric_algorithm("RSA")
        assert valid is True
        
        valid, algo = validator.validate_asymmetric_algorithm("ED25519")
        assert valid is True
    
    def test_validate_padding(self):
        """Test padding validation."""
        validator = CryptoAlgorithmValidator()
        
        valid, padding = validator.validate_padding("PKCS7")
        assert valid is True
        
        valid, padding = validator.validate_padding("OAEP")
        assert valid is True
    
    def test_validate_key_size(self):
        """Test key size validation."""
        validator = CryptoAlgorithmValidator()
        
        # AES key sizes
        assert validator.validate_key_size(128, "AES") is True
        assert validator.validate_key_size(256, "AES") is True
        assert validator.validate_key_size(64, "AES") is False  # Too small
        
        # RSA minimum
        assert validator.validate_key_size(2048, "RSA") is True
        assert validator.validate_key_size(1024, "RSA") is False  # Too small


class TestKeyMaterialValidator:
    """Test cryptographic key material validation."""
    
    def test_validate_aes_key(self):
        """Test AES key validation."""
        validator = KeyMaterialValidator()
        
        # Valid AES key lengths
        assert validator.validate_aes_key(b'x' * 16) is True  # 128-bit
        assert validator.validate_aes_key(b'x' * 24) is True  # 192-bit
        assert validator.validate_aes_key(b'x' * 32) is True  # 256-bit
        
        # Invalid lengths
        assert validator.validate_aes_key(b'x' * 15) is False
        assert validator.validate_aes_key(b'x' * 33) is False
        assert validator.validate_aes_key("not bytes") is False
    
    def test_validate_nonce(self):
        """Test nonce validation."""
        validator = KeyMaterialValidator()
        
        assert validator.validate_nonce(b'x' * 12, 12) is True
        assert validator.validate_nonce(b'x' * 16, 16) is True
        assert validator.validate_nonce(b'x' * 10, 12) is False
    
    def test_validate_iv(self):
        """Test IV validation."""
        validator = KeyMaterialValidator()
        
        assert validator.validate_iv(b'x' * 16, 16) is True
        assert validator.validate_iv(b'x' * 16) is True  # Default block size
    
    def test_validate_salt(self):
        """Test salt validation."""
        validator = KeyMaterialValidator()
        
        assert validator.validate_salt(b'x' * 16) is True
        assert validator.validate_salt(b'x' * 4) is False  # Too short
    
    def test_sanitize_key_input(self):
        """Test key input sanitization from various formats."""
        validator = KeyMaterialValidator()
        
        # Raw bytes pass through
        assert validator.sanitize_key_input(b'test') == b'test'
        
        # Hex string decoded
        result = validator.sanitize_key_input("48656c6c6f")
        assert result == b'Hello'
        
        # Base64 string decoded
        result = validator.sanitize_key_input("SGVsbG8=")
        assert result == b'Hello'
    
    def test_generate_secure_nonce(self):
        """Test secure nonce generation."""
        validator = KeyMaterialValidator()
        
        nonce1 = validator.generate_secure_nonce(12)
        nonce2 = validator.generate_secure_nonce(12)
        
        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert nonce1 != nonce2  # Cryptographically random
    
    def test_generate_secure_salt(self):
        """Test secure salt generation."""
        validator = KeyMaterialValidator()
        
        salt1 = validator.generate_secure_salt(16)
        salt2 = validator.generate_secure_salt(16)
        
        assert len(salt1) == 16
        assert len(salt2) == 16
        assert salt1 != salt2
    
    def test_convenience_functions(self):
        """Test key validation convenience functions."""
        assert validate_aes_key(b'x' * 32) is True
        assert validate_nonce(b'x' * 12) is True
        assert sanitize_key_input(b'test') == b'test'
        
        nonce = generate_secure_nonce(12)
        assert len(nonce) == 12
        
        salt = generate_secure_salt(16)
        assert len(salt) == 16


class TestCryptoInjectionProtector:
    """Test crypto operation injection protection."""
    
    def test_sanitize_openssl_arg(self):
        """Test openssl argument sanitization."""
        protector = CryptoInjectionProtector()
        
        # Dangerous characters removed
        result = protector.sanitize_openssl_arg("file.pem; rm -rf /")
        assert ';' not in result
        assert ' ' not in result
        
        result = protector.sanitize_openssl_arg("key.pem | cat /etc/passwd")
        assert '|' not in result
    
    def test_detect_command_injection(self):
        """Test command injection detection."""
        protector = CryptoInjectionProtector()
        
        suspicious, score = protector.detect_command_injection("file.pem; rm -rf /")
        assert suspicious is True
        assert score > 0.3
    
    def test_convenience_function(self):
        """Test convenience function."""
        result = sanitize_openssl_arg("test; bad")
        assert ';' not in result


class TestCryptoInputValidator:
    """Test crypto input validation."""
    
    def test_validate_hex(self):
        """Test hex string validation."""
        validator = CryptoInputValidator()
        
        valid, val = validator.validate_hex("48656c6c6f")
        assert valid is True
        assert val == "48656c6c6f"
        
        valid, val = validator.validate_hex("DEADBEEF")
        assert valid is True
        assert val == "deadbeef"  # Lowercased
        
        valid, val = validator.validate_hex("not hex!")
        assert valid is False
    
    def test_validate_base64(self):
        """Test base64 string validation."""
        validator = CryptoInputValidator()
        
        valid, val = validator.validate_base64("SGVsbG8=")
        assert valid is True
        
        valid, val = validator.validate_base64("not base64!")
        assert valid is False
    
    def test_validate_iterations(self):
        """Test KDF iteration count validation."""
        validator = CryptoInputValidator()
        
        valid, val = validator.validate_iterations(100000)
        assert valid is True
        assert val == 100000
        
        valid, val = validator.validate_iterations(100)  # Too low
        assert valid is False
    
    def test_validate_plaintext_length(self):
        """Test plaintext length validation."""
        validator = CryptoInputValidator()
        
        assert validator.validate_plaintext_length(1024) is True
        assert validator.validate_plaintext_length(-1) is False
    
    def test_convenience_functions(self):
        """Test convenience functions."""
        valid, val = validate_hex("deadbeef")
        assert valid is True
        
        valid, val = validate_base64("SGVsbG8=")
        assert valid is True


class TestCryptoHeaderInjectionProtector:
    """Test crypto API header injection protection."""
    
    def test_is_safe_header_value(self):
        """Test safe header detection."""
        protector = CryptoHeaderInjectionProtector()
        
        assert protector.is_safe_header_value("application/json") is True
        assert protector.is_safe_header_value("value\r\nSet-Cookie: bad") is False
    
    def test_sanitize_header_value(self):
        """Test header sanitization."""
        protector = CryptoHeaderInjectionProtector()
        
        result = protector.sanitize_header_value("value\r\nBad: stuff")
        assert '\r' not in result
        assert '\n' not in result
    
    def test_convenience_functions(self):
        """Test convenience functions."""
        assert is_safe_crypto_header("safe") is True
        assert is_safe_crypto_header("unsafe\r\n") is False
        assert sanitize_crypto_header("test\r\n") == "test"


class TestBackwardCompatibility:
    """Verify backward compatibility - no breaking changes."""
    
    def test_all_imports_work(self):
        """All classes and functions import correctly."""
        assert CryptoPathTraversalProtector is not None
        assert CryptoAlgorithmValidator is not None
        assert KeyMaterialValidator is not None
        assert CryptoInjectionProtector is not None
        assert CryptoInputValidator is not None
        assert CryptoHeaderInjectionProtector is not None
    
    def test_no_exceptions_on_empty_input(self):
        """Empty input handling doesn't crash."""
        assert is_safe_key_path(None, strict=False) is False
        assert sanitize_key_path(None) == ''
        assert validate_symmetric_algo(None) == (False, '')
        assert validate_aes_key(None) is False
        assert sanitize_key_input(None) is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
