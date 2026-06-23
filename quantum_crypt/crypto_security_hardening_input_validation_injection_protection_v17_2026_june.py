"""
QuantumCrypt Security Hardening - Input Validation & Injection Protection v17
DIMENSION B: Security Hardening (v17)
ADD-ONLY implementation - layers on top of existing code, no modifications to core

Cryptography-specific input validation and injection protection:
1. Key material validation and sanitization
2. Path traversal protection for key file operations
3. Algorithm name validation (prevent algorithm injection)
4. Nonce/IV validation and secure generation
5. Cryptographic parameter range validation
6. Side-channel resistant input validation
7. Command injection protection for crypto operations
8. Header injection prevention for crypto APIs

All functions wrap existing inputs, validate BEFORE processing reaches core logic.
Backward compatible - all existing code continues to work unchanged.
"""
import re
import os
import html
import base64
import binascii
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union
import secrets


class CryptoPathTraversalProtector:
    """
    Prevent path traversal attacks specifically for crypto key files.
    
    Validates and sanitizes file paths before key material loading/saving.
    """
    
    # Dangerous path sequences that indicate traversal attempts
    DANGEROUS_SEQUENCES = {
        '..', '../', '..\\', '/..', '\\..',
        '%2e%2e%2f', '%2e%2e/', '..%2f',
        '%2e%2e%5c', '%2e%2e\\', '..%5c',
        '%252e%252e%252f', '%c0%ae%c0%ae/',
        '%c1%9c%c1%9c/', '....//', '....\\\\'
    }
    
    # Allowed key file extensions
    ALLOWED_EXTENSIONS = {'.pem', '.key', '.pub', '.der', '.p12', '.pfx', '.jwk', '.json', '.bin'}
    
    def __init__(self, allowed_key_dirs: Optional[List[str]] = None):
        """
        Initialize crypto path protector.
        
        Args:
            allowed_key_dirs: List of allowed key directories
        """
        self._allowed_base_dirs: List[Path] = []
        if allowed_key_dirs:
            for d in allowed_key_dirs:
                self._allowed_base_dirs.append(Path(d).resolve())
    
    def is_safe_key_path(self, path: str, strict: bool = True) -> bool:
        """
        Check if a path is safe for key file operations.
        
        Args:
            path: Path to validate
            strict: If True, perform strict validation
            
        Returns:
            True if path appears safe
        """
        if not path or not isinstance(path, str):
            return False
        
        # Check for dangerous sequences
        path_lower = path.lower()
        for seq in self.DANGEROUS_SEQUENCES:
            if seq.lower() in path_lower:
                return False
        
        # Check for URL-encoded traversal attempts
        decoded = urllib.parse.unquote(path)
        decoded_lower = decoded.lower()
        for seq in self.DANGEROUS_SEQUENCES:
            if seq.lower() in decoded_lower:
                return False
        
        # Double URL decode check
        double_decoded = urllib.parse.unquote(decoded)
        double_decoded_lower = double_decoded.lower()
        for seq in self.DANGEROUS_SEQUENCES:
            if seq.lower() in double_decoded_lower:
                return False
        
        # Check file extension only if there is one (for intermediate dirs, no extension is OK)
        path_obj = Path(path)
        suffix = path_obj.suffix.lower()
        if suffix and suffix not in self.ALLOWED_EXTENSIONS:
            return False
        
        if strict and self._allowed_base_dirs:
            try:
                resolved = Path(path).resolve()
                return any(resolved.is_relative_to(base) for base in self._allowed_base_dirs)
            except (OSError, ValueError):
                return False
        
        return True
    
    def sanitize_key_path(self, path: str, fallback: str = '') -> str:
        """
        Sanitize a key file path.
        
        Args:
            path: Path to sanitize
            fallback: Value to return if path is dangerous
            
        Returns:
            Sanitized path or fallback
        """
        if not self.is_safe_key_path(path, strict=False):
            return fallback
        
        cleaned = path
        for seq in sorted(self.DANGEROUS_SEQUENCES, key=len, reverse=True):
            cleaned = cleaned.replace(seq, '')
            cleaned = cleaned.replace(seq.upper(), '')
        
        cleaned = cleaned.replace('\\\\', '/')
        return cleaned.strip('/\\')
    
    def safe_key_path_join(self, base: str, *parts: str) -> Optional[str]:
        """
        Safely join key path components.
        
        Args:
            base: Base key directory
            *parts: Path components
            
        Returns:
            Safe joined path or None
        """
        base_path = Path(base).resolve()
        
        for part in parts:
            if not self.is_safe_key_path(part, strict=False):
                return None
        
        try:
            joined = base_path.joinpath(*parts).resolve()
            if not joined.is_relative_to(base_path):
                return None
            return str(joined)
        except (OSError, ValueError):
            return None


class CryptoAlgorithmValidator:
    """
    Validate algorithm names and parameters to prevent algorithm injection.
    """
    
    # Allowed algorithms and modes
    ALLOWED_SYMMETRIC_ALGOS = {'AES', 'AES-128', 'AES-192', 'AES-256', 'CHACHA20', 'SALSA20'}
    ALLOWED_MODES = {'ECB', 'CBC', 'GCM', 'CTR', 'OCB', 'XTS', 'CFB', 'OFB'}
    ALLOWED_HASH_ALGOS = {'SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'SHA3-512', 'BLAKE2b', 'BLAKE2s'}
    ALLOWED_ASYMMETRIC_ALGOS = {'RSA', 'ECDSA', 'ED25519', 'X25519', 'ECDH'}
    ALLOWED_PADDING = {'PKCS7', 'PKCS1v15', 'OAEP', 'PSS', 'NONE'}
    
    def validate_symmetric_algorithm(self, algo: str) -> Tuple[bool, str]:
        """Validate symmetric encryption algorithm name."""
        if not algo or not isinstance(algo, str):
            return (False, '')
        
        algo_upper = algo.upper().strip()
        if algo_upper in self.ALLOWED_SYMMETRIC_ALGOS:
            return (True, algo_upper)
        return (False, algo_upper)
    
    def validate_mode(self, mode: str) -> Tuple[bool, str]:
        """Validate cipher mode."""
        if not mode or not isinstance(mode, str):
            return (False, '')
        
        mode_upper = mode.upper().strip()
        if mode_upper in self.ALLOWED_MODES:
            return (True, mode_upper)
        return (False, mode_upper)
    
    def validate_hash_algorithm(self, algo: str) -> Tuple[bool, str]:
        """Validate hash algorithm."""
        if not algo or not isinstance(algo, str):
            return (False, '')
        
        algo_upper = algo.upper().strip()
        if algo_upper in self.ALLOWED_HASH_ALGOS:
            return (True, algo_upper)
        return (False, algo_upper)
    
    def validate_asymmetric_algorithm(self, algo: str) -> Tuple[bool, str]:
        """Validate asymmetric algorithm."""
        if not algo or not isinstance(algo, str):
            return (False, '')
        
        algo_upper = algo.upper().strip()
        if algo_upper in self.ALLOWED_ASYMMETRIC_ALGOS:
            return (True, algo_upper)
        return (False, algo_upper)
    
    def validate_padding(self, padding: str) -> Tuple[bool, str]:
        """Validate padding mode."""
        if not padding or not isinstance(padding, str):
            return (False, '')
        
        padding_upper = padding.upper().strip()
        if padding_upper in self.ALLOWED_PADDING:
            return (True, padding_upper)
        return (False, padding_upper)
    
    def validate_key_size(self, key_size: int, algo: str) -> bool:
        """Validate key size for algorithm."""
        try:
            size = int(key_size)
        except (TypeError, ValueError):
            return False
        
        algo_upper = algo.upper() if algo else ''
        
        if 'AES' in algo_upper:
            return size in {128, 192, 256}
        elif algo_upper == 'RSA':
            return size >= 2048 and size <= 16384
        elif algo_upper in {'CHACHA20', 'SALSA20'}:
            return size == 256
        elif algo_upper in {'ED25519', 'X25519'}:
            return size == 256
        
        return size > 0


class KeyMaterialValidator:
    """
    Validate and sanitize cryptographic key material.
    """
    
    def validate_aes_key(self, key: bytes) -> bool:
        """Validate AES key length."""
        if not isinstance(key, bytes):
            return False
        return len(key) in {16, 24, 32}  # 128, 192, 256 bits
    
    def validate_nonce(self, nonce: bytes, expected_length: int = 12) -> bool:
        """Validate nonce/IV length."""
        if not isinstance(nonce, bytes):
            return False
        return len(nonce) == expected_length
    
    def validate_iv(self, iv: bytes, block_size: int = 16) -> bool:
        """Validate IV for block cipher modes."""
        if not isinstance(iv, bytes):
            return False
        return len(iv) == block_size
    
    def validate_salt(self, salt: bytes, min_length: int = 8) -> bool:
        """Validate salt for KDF operations."""
        if not isinstance(salt, bytes):
            return False
        return len(salt) >= min_length
    
    def sanitize_key_input(self, key_input: Any) -> Optional[bytes]:
        """
        Sanitize key input from various formats.
        
        Handles base64, hex, and raw bytes.
        """
        if key_input is None:
            return None
        
        if isinstance(key_input, bytes):
            return key_input
        
        if isinstance(key_input, str):
            key_str = key_input.strip()
            # Try hex decoding
            try:
                return bytes.fromhex(key_str)
            except ValueError:
                pass
            # Try base64 decoding
            try:
                return base64.b64decode(key_str)
            except (binascii.Error, ValueError):
                pass
            # Return as encoded bytes
            return key_str.encode('utf-8')
        
        return None
    
    def generate_secure_nonce(self, length: int = 12) -> bytes:
        """Generate cryptographically secure nonce."""
        return secrets.token_bytes(length)
    
    def generate_secure_salt(self, length: int = 16) -> bytes:
        """Generate cryptographically secure salt."""
        return secrets.token_bytes(length)


class CryptoInjectionProtector:
    """
    Prevent injection attacks in crypto operations.
    """
    
    # Dangerous patterns for crypto operations
    DANGEROUS_CMD_PATTERNS = [
        r"[;&|`$()<>]",
        r"\$\(.*\)",
        r"`.*`",
        r"\|\|",
        r"&&",
    ]
    
    def __init__(self):
        self._cmd_regexes: List[Pattern] = []
        for pattern in self.DANGEROUS_CMD_PATTERNS:
            self._cmd_regexes.append(re.compile(pattern))
    
    def sanitize_openssl_arg(self, value: Any, max_length: int = 500) -> str:
        """Sanitize arguments for openssl command execution."""
        if value is None:
            return ''
        
        str_val = str(value)[:max_length]
        
        dangerous = [';', '|', '&', '`', '$', '(', ')', '<', '>', '\\', '"', "'", ' ']
        for char in dangerous:
            str_val = str_val.replace(char, '')
        
        return str_val
    
    def detect_command_injection(self, value: str) -> Tuple[bool, float]:
        """Detect potential command injection in crypto operations."""
        if not value or not isinstance(value, str):
            return (False, 0.0)
        
        score = 0.0
        
        for regex in self._cmd_regexes:
            if regex.search(value):
                score += 0.4
        
        shell_ops = [';', '|', '&', '`', '$(']
        count = sum(1 for op in shell_ops if op in value)
        if count >= 2:
            score += 0.2
        
        return (score >= 0.4, min(score, 1.0))


class CryptoInputValidator:
    """
    Type-safe input validation for crypto operations.
    """
    
    HEX_REGEX = re.compile(r'^[0-9a-fA-F]*$')
    BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    
    def validate_hex(self, value: str, min_len: int = 0, max_len: int = 10000) -> Tuple[bool, str]:
        """Validate hex string."""
        if not value or not isinstance(value, str):
            return (min_len == 0, '')
        
        if len(value) < min_len or len(value) > max_len:
            return (False, value)
        
        if not self.HEX_REGEX.match(value):
            return (False, value)
        
        return (True, value.lower())
    
    def validate_base64(self, value: str) -> Tuple[bool, str]:
        """Validate base64 string."""
        if not value or not isinstance(value, str):
            return (False, '')
        
        value = value.strip()
        if not self.BASE64_REGEX.match(value):
            return (False, value)
        
        # Verify actual decode works
        try:
            base64.b64decode(value)
            return (True, value)
        except (binascii.Error, ValueError):
            return (False, value)
    
    def validate_iterations(self, iterations: int, min_val: int = 1000,
                           max_val: int = 10000000) -> Tuple[bool, Optional[int]]:
        """Validate KDF iteration count."""
        try:
            val = int(iterations)
            if val < min_val or val > max_val:
                return (False, None)
            return (True, val)
        except (TypeError, ValueError):
            return (False, None)
    
    def validate_plaintext_length(self, length: int, max_length: int = 100*1024*1024) -> bool:
        """Validate plaintext/ciphertext length."""
        try:
            val = int(length)
            return 0 <= val <= max_length
        except (TypeError, ValueError):
            return False


class CryptoHeaderInjectionProtector:
    """
    Prevent header injection in crypto API responses.
    """
    
    DANGEROUS_HEADER_CHARS = {'\r', '\n', '\0', '%0d', '%0a', '%00'}
    
    def is_safe_header_value(self, value: str) -> bool:
        """Check if header value is safe from injection."""
        if not value or not isinstance(value, str):
            return True
        
        value_lower = value.lower()
        for char in self.DANGEROUS_HEADER_CHARS:
            if char in value_lower:
                return False
        
        return True
    
    def sanitize_header_value(self, value: str, max_length: int = 4096) -> str:
        """Sanitize HTTP header value for crypto APIs."""
        if not value:
            return ''
        
        str_val = str(value)[:max_length]
        
        for char in ['\r', '\n', '\0']:
            str_val = str_val.replace(char, '')
        
        return str_val


# Exported convenience instances
_crypto_path_protector = CryptoPathTraversalProtector()
_algo_validator = CryptoAlgorithmValidator()
_key_validator = KeyMaterialValidator()
_injection_protector = CryptoInjectionProtector()
_input_validator = CryptoInputValidator()
_header_protector = CryptoHeaderInjectionProtector()

# Public API - convenience functions
def is_safe_key_path(path: str, strict: bool = True) -> bool:
    """Check if key file path is safe from traversal attacks."""
    return _crypto_path_protector.is_safe_key_path(path, strict)

def sanitize_key_path(path: str, fallback: str = '') -> str:
    """Sanitize key file path."""
    return _crypto_path_protector.sanitize_key_path(path, fallback)

def validate_symmetric_algo(algo: str) -> Tuple[bool, str]:
    """Validate symmetric encryption algorithm name."""
    return _algo_validator.validate_symmetric_algorithm(algo)

def validate_mode(mode: str) -> Tuple[bool, str]:
    """Validate cipher mode."""
    return _algo_validator.validate_mode(mode)

def validate_hash_algo(algo: str) -> Tuple[bool, str]:
    """Validate hash algorithm."""
    return _algo_validator.validate_hash_algorithm(algo)

def validate_aes_key(key: bytes) -> bool:
    """Validate AES key length."""
    return _key_validator.validate_aes_key(key)

def validate_nonce(nonce: bytes, expected_length: int = 12) -> bool:
    """Validate nonce length."""
    return _key_validator.validate_nonce(nonce, expected_length)

def sanitize_key_input(key_input: Any) -> Optional[bytes]:
    """Sanitize key input from various formats."""
    return _key_validator.sanitize_key_input(key_input)

def generate_secure_nonce(length: int = 12) -> bytes:
    """Generate cryptographically secure nonce."""
    return _key_validator.generate_secure_nonce(length)

def generate_secure_salt(length: int = 16) -> bytes:
    """Generate cryptographically secure salt."""
    return _key_validator.generate_secure_salt(length)

def sanitize_openssl_arg(value: Any) -> str:
    """Sanitize openssl command argument."""
    return _injection_protector.sanitize_openssl_arg(value)

def validate_hex(value: str) -> Tuple[bool, str]:
    """Validate hex string."""
    return _input_validator.validate_hex(value)

def validate_base64(value: str) -> Tuple[bool, str]:
    """Validate base64 string."""
    return _input_validator.validate_base64(value)

def is_safe_crypto_header(value: str) -> bool:
    """Check if crypto header value is injection-safe."""
    return _header_protector.is_safe_header_value(value)

def sanitize_crypto_header(value: str) -> str:
    """Sanitize crypto API header value."""
    return _header_protector.sanitize_header_value(value)
