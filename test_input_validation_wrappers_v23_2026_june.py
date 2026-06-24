"""
Tests for Input Validation Wrappers v23 - QuantumCrypt-AI
Security Hardening - Dimension B
"""

import pytest
from quantum_crypt.input_validation_wrappers_v23_2026_june import (
    InputValidator,
    ValidatedCryptoWrapper,
    SecurityPolicy,
    ValidationError,
    InvalidInputError,
    SecurityViolationError,
    crypto_validator,
)


class TestInputValidator:
    """Tests for InputValidator class."""
    
    def test_validate_bytes_basic(self):
        """Test basic bytes validation."""
        data = b'hello world'
        result = InputValidator.validate_bytes(data)
        assert result == data
    
    def test_validate_bytes_bytearray(self):
        """Test bytearray validation."""
        data = bytearray(b'test')
        result = InputValidator.validate_bytes(data)
        assert result == b'test'
    
    def test_validate_bytes_min_length(self):
        """Test minimum length validation."""
        data = b'short'
        result = InputValidator.validate_bytes(data, min_len=3)
        assert result == data
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_bytes(data, min_len=10)
    
    def test_validate_bytes_max_length(self):
        """Test maximum length validation."""
        data = b'hello'
        result = InputValidator.validate_bytes(data, max_len=10)
        assert result == data
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_bytes(data, max_len=3)
    
    def test_validate_bytes_exact_length(self):
        """Test exact length validation."""
        data = b'exactly 16 bytes'  # 16 bytes exactly
        result = InputValidator.validate_bytes(data, exact_len=16)
        assert result == data
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_bytes(data, exact_len=32)
    
    def test_validate_bytes_wrong_type(self):
        """Test wrong type rejection."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_bytes("not bytes")
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_bytes(12345)
    
    def test_validate_key(self):
        """Test cryptographic key validation."""
        key = b'x' * 32
        result = InputValidator.validate_key(key, 32)
        assert result == key
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_key(b'short', 32)
    
    def test_validate_nonce(self):
        """Test nonce/IV validation."""
        nonce = b'n' * 12
        result = InputValidator.validate_nonce(nonce, 12)
        assert result == nonce
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_nonce(b'short', 16)
    
    def test_validate_hex_string_valid(self):
        """Test valid hex string validation."""
        hex_str = "deadBEEF1234"
        result = InputValidator.validate_hex_string(hex_str)
        assert result == hex_str
    
    def test_validate_hex_string_invalid(self):
        """Test invalid hex string rejection."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_hex_string("not hex!")
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_hex_string("g")  # g not in hex
    
    def test_validate_hex_string_length(self):
        """Test hex string length validation."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_hex_string("a", min_len=10)
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_hex_string("a" * 100, max_len=10)
    
    def test_validate_base64_string_valid(self):
        """Test valid base64 string."""
        b64 = "SGVsbG8="  # "Hello" in base64
        result = InputValidator.validate_base64_string(b64)
        assert result == b64
    
    def test_validate_base64_string_invalid(self):
        """Test invalid base64 rejection."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_base64_string("not base64!")
    
    def test_validate_integer_basic(self):
        """Test basic integer validation."""
        result = InputValidator.validate_integer(42)
        assert result == 42
    
    def test_validate_integer_bounds(self):
        """Test integer bounds validation."""
        result = InputValidator.validate_integer(50, min_val=0, max_val=100)
        assert result == 50
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_integer(-1, min_val=0)
        
        with pytest.raises(InvalidInputError):
            InputValidator.validate_integer(101, max_val=100)
    
    def test_validate_integer_wrong_type(self):
        """Test wrong type rejection for integer."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_integer("not an int")
    
    def test_validate_plaintext_bytes(self):
        """Test plaintext validation with bytes."""
        pt = b'secret message'
        result = InputValidator.validate_plaintext(pt)
        assert result == pt
    
    def test_validate_plaintext_string(self):
        """Test plaintext validation with string (auto-encoded)."""
        pt = "secret message"
        result = InputValidator.validate_plaintext(pt)
        assert result == pt.encode('utf-8')
    
    def test_validate_plaintext_empty(self):
        """Test empty plaintext rejection."""
        with pytest.raises(InvalidInputError):
            InputValidator.validate_plaintext(b'')
    
    def test_validate_ciphertext(self):
        """Test ciphertext validation."""
        ct = b'encrypted data here'
        result = InputValidator.validate_ciphertext(ct)
        assert result == ct
    
    def test_sanitize_string(self):
        """Test string sanitization."""
        dirty = "Hello\x00World\n\t"
        clean = InputValidator.sanitize_string(dirty)
        assert '\x00' not in clean
        assert 'Hello' in clean
        assert 'World' in clean
    
    def test_prevent_null_bytes_present(self):
        """Test null byte detection."""
        data = b'hello\x00world'
        with pytest.raises(SecurityViolationError):
            InputValidator.prevent_null_bytes(data)
    
    def test_prevent_null_bytes_absent(self):
        """Test no null bytes passes."""
        data = b'hello world'
        InputValidator.prevent_null_bytes(data)  # Should not raise


class TestValidatedCryptoWrapper:
    """Tests for ValidatedCryptoWrapper class."""
    
    def test_wrapper_initialization(self):
        """Test wrapper initialization."""
        wrapper = ValidatedCryptoWrapper()
        assert wrapper.validation_count == 0
        assert wrapper.rejection_count == 0
    
    def test_validate_inputs_decorator(self):
        """Test input validation decorator."""
        wrapper = ValidatedCryptoWrapper()
        
        @wrapper.validate_inputs(
            key=lambda k: InputValidator.validate_key(k, 4),
            data=lambda d: InputValidator.validate_bytes(d)
        )
        def test_func(key, data):
            return (key, data)
        
        # Valid inputs
        result = test_func(b'1234', b'test')
        assert result == (b'1234', b'test')
        assert wrapper.validation_count == 2
        assert wrapper.rejection_count == 0
        
        # Invalid inputs
        with pytest.raises(InvalidInputError):
            test_func(b'short', b'test')
        assert wrapper.rejection_count == 1
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        wrapper = ValidatedCryptoWrapper()
        stats = wrapper.get_stats()
        assert 'validations_performed' in stats
        assert 'rejections' in stats
        assert stats['validations_performed'] == 0


class TestSecurityPolicy:
    """Tests for SecurityPolicy class."""
    
    def test_enforce_min_key_size_pass(self):
        """Test minimum key size enforcement passes."""
        key = b'x' * 32
        SecurityPolicy.enforce_min_key_size(key, 32)  # Should not raise
    
    def test_enforce_min_key_size_fail(self):
        """Test minimum key size enforcement fails."""
        key = b'short'
        with pytest.raises(SecurityViolationError):
            SecurityPolicy.enforce_min_key_size(key, 32)
    
    def test_enforce_no_weak_keys_all_zero(self):
        """Test all-zero key detection."""
        key = b'\x00' * 32
        with pytest.raises(SecurityViolationError):
            SecurityPolicy.enforce_no_weak_keys(key)
    
    def test_enforce_no_weak_keys_all_same(self):
        """Test all-same-byte key detection."""
        key = b'\xFF' * 32
        with pytest.raises(SecurityViolationError):
            SecurityPolicy.enforce_no_weak_keys(key)
    
    def test_enforce_no_weak_keys_good(self):
        """Test good key passes."""
        key = b'x' * 16 + b'y' * 16
        SecurityPolicy.enforce_no_weak_keys(key)  # Should not raise
    
    def test_enforce_max_operations_pass(self):
        """Test operation rate passes."""
        SecurityPolicy.enforce_max_operations_per_second(500, 1000)  # Should not raise
    
    def test_enforce_max_operations_fail(self):
        """Test operation rate fails."""
        with pytest.raises(SecurityViolationError):
            SecurityPolicy.enforce_max_operations_per_second(1500, 1000)


class TestGlobalInstance:
    """Tests for global crypto_validator instance."""
    
    def test_global_instance_exists(self):
        """Test global validator instance exists."""
        assert crypto_validator is not None
        assert isinstance(crypto_validator, ValidatedCryptoWrapper)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
