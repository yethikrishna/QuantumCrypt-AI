"""
Test Suite for QuantumCrypt-AI Post-Quantum API Gateway Middleware
June 2026 - Production Grade Tests

Tests verify:
- API key generation and validation
- Request signature verification
- Replay protection via nonce validation
- Rate limiting functionality
- Tamper detection
- Audit logging integrity
- Thread safety
"""

import pytest
import time
import base64
import threading
from concurrent.futures import ThreadPoolExecutor

from quantum_crypt.post_quantum_api_gateway_middleware_2026_june import (
    PostQuantumAPIGatewayMiddleware,
    PostQuantumKeyManager,
    PostQuantumSignatureVerifier,
    RateLimiter,
    AuditLogger,
    SecurityPolicy,
    SecurityLevel,
    RateLimitConfig,
    ValidationResult,
    AlgorithmType
)


class TestPostQuantumKeyManager:
    """Test suite for Post-Quantum Key Manager"""
    
    def setup_method(self):
        self.key_manager = PostQuantumKeyManager()
    
    def test_generate_api_key(self):
        """Test API key generation"""
        api_key = self.key_manager.generate_api_key("test_client")
        
        assert api_key.startswith("pq_")
        assert len(api_key) > 20
    
    def test_validate_valid_api_key(self):
        """Test validation of valid API key"""
        api_key = self.key_manager.generate_api_key("client_123")
        valid, client_id = self.key_manager.validate_api_key(api_key)
        
        assert valid is True
        assert client_id == "client_123"
    
    def test_validate_invalid_api_key(self):
        """Test validation of invalid API key"""
        valid, client_id = self.key_manager.validate_api_key("invalid_key")
        
        assert valid is False
        assert client_id is None
    
    def test_revoke_api_key(self):
        """Test API key revocation"""
        api_key = self.key_manager.generate_api_key("client_123")
        
        # Initially valid
        valid, _ = self.key_manager.validate_api_key(api_key)
        assert valid is True
        
        # Revoke
        revoked = self.key_manager.revoke_api_key(api_key)
        assert revoked is True
        
        # Now invalid
        valid, _ = self.key_manager.validate_api_key(api_key)
        assert valid is False
    
    def test_rotate_api_key(self):
        """Test API key rotation"""
        old_key = self.key_manager.generate_api_key("client_123")
        new_key = self.key_manager.rotate_api_key(old_key)
        
        assert new_key is not None
        assert new_key != old_key
        
        # Old key should be invalid
        valid_old, _ = self.key_manager.validate_api_key(old_key)
        assert valid_old is False
        
        # New key should be valid
        valid_new, client_id = self.key_manager.validate_api_key(new_key)
        assert valid_new is True
        assert client_id == "client_123"
    
    def test_encrypt_decrypt_api_key(self):
        """Test API key encryption and decryption"""
        original = "pq_test_api_key_12345"
        encrypted = self.key_manager.encrypt_api_key(original)
        decrypted = self.key_manager.decrypt_api_key(encrypted)
        
        assert encrypted != original
        assert decrypted == original


class TestPostQuantumSignatureVerifier:
    """Test suite for Signature Verifier"""
    
    def setup_method(self):
        self.policy = SecurityPolicy()
        self.verifier = PostQuantumSignatureVerifier(self.policy)
        self.secret_key = b"test_secret_key_1234567890123456789012"
    
    def test_generate_and_verify_signature(self):
        """Test signature generation and verification"""
        method = "POST"
        path = "/api/v1/data"
        body = '{"data": "test"}'
        timestamp = str(int(time.time()))
        nonce = "abc123"
        
        signature = self.verifier.generate_signature(
            method, path, body, timestamp, nonce, self.secret_key
        )
        
        valid = self.verifier.verify_signature(
            method, path, body, timestamp, nonce, signature, self.secret_key
        )
        
        assert valid is True
    
    def test_verify_invalid_signature(self):
        """Test detection of invalid signature"""
        method = "POST"
        path = "/api/v1/data"
        body = '{"data": "test"}'
        timestamp = str(int(time.time()))
        nonce = "abc123"
        
        valid = self.verifier.verify_signature(
            method, path, body, timestamp, nonce, "wrong_signature", self.secret_key
        )
        
        assert valid is False
    
    def test_validate_valid_timestamp(self):
        """Test timestamp validation with current time"""
        timestamp = str(int(time.time()))
        valid = self.verifier.validate_timestamp(timestamp)
        
        assert valid is True
    
    def test_validate_expired_timestamp(self):
        """Test detection of expired timestamp"""
        # Timestamp from 1 hour ago
        old_timestamp = str(int(time.time()) - 3600)
        valid = self.verifier.validate_timestamp(old_timestamp)
        
        assert valid is False
    
    def test_validate_nonce_replay_protection(self):
        """Test nonce-based replay protection"""
        nonce = "unique_nonce_12345"
        
        # First use should be valid
        valid1 = self.verifier.validate_nonce(nonce)
        assert valid1 is True
        
        # Reuse should be invalid (replay detected)
        valid2 = self.verifier.validate_nonce(nonce)
        assert valid2 is False
    
    def test_detect_tampering(self):
        """Test tamper detection via content hash"""
        body = '{"data": "original"}'
        correct_hash = __import__('hashlib').sha256(body.encode()).hexdigest()
        
        # Valid hash
        valid = self.verifier.detect_tampering(body, correct_hash)
        assert valid is True
        
        # Tampered body
        tampered_body = '{"data": "tampered"}'
        valid = self.verifier.detect_tampering(tampered_body, correct_hash)
        assert valid is False
    
    def test_generate_nonce(self):
        """Test nonce generation"""
        nonce1 = self.verifier.generate_nonce()
        nonce2 = self.verifier.generate_nonce()
        
        assert len(nonce1) == 32  # 16 bytes hex
        assert nonce1 != nonce2


class TestRateLimiter:
    """Test suite for Rate Limiter"""
    
    def setup_method(self):
        config = RateLimitConfig(
            requests_per_minute=5,
            requests_per_hour=100,
            requests_per_day=1000
        )
        self.rate_limiter = RateLimiter(config)
    
    def test_rate_limit_not_exceeded(self):
        """Test rate limit within bounds"""
        for i in range(3):
            allowed, remaining = self.rate_limiter.check_rate_limit("client1")
            assert allowed is True
    
    def test_rate_limit_exceeded(self):
        """Test rate limit enforcement"""
        # Exhaust limit
        for i in range(5):
            self.rate_limiter.check_rate_limit("client1")
        
        # 6th request should be blocked
        allowed, remaining = self.rate_limiter.check_rate_limit("client1")
        assert allowed is False
        assert remaining == 0
    
    def test_get_usage_stats(self):
        """Test usage statistics reporting"""
        for i in range(3):
            self.rate_limiter.check_rate_limit("client1")
        
        stats = self.rate_limiter.get_usage_stats("client1")
        
        assert "minute" in stats
        assert "hour" in stats
        assert "day" in stats
        assert stats["minute"]["used"] == 3
    
    def test_thread_safety(self):
        """Test thread-safe rate limiting"""
        def make_request():
            return self.rate_limiter.check_rate_limit("concurrent_client")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [f.result() for f in futures]
        
        # Should not crash, should handle concurrency
        assert len(results) == 20


class TestAuditLogger:
    """Test suite for Audit Logger"""
    
    def setup_method(self):
        self.logger = AuditLogger()
    
    def test_log_request(self):
        """Test audit logging"""
        from quantum_crypt.post_quantum_api_gateway_middleware_2026_june import ValidationResponse
        
        validation = ValidationResponse(
            result=ValidationResult.VALID,
            status_code=200,
            message="OK",
            request_id="test123",
            client_id="client1"
        )
        
        request_details = {
            "method": "POST",
            "path": "/api/test",
            "ip_address": "192.168.1.1"
        }
        
        log_hash = self.logger.log_request(validation, request_details)
        
        assert len(log_hash) == 64  # SHA256
    
    def test_verify_integrity_clean(self):
        """Test integrity verification on clean log"""
        from quantum_crypt.post_quantum_api_gateway_middleware_2026_june import ValidationResponse
        
        for i in range(5):
            validation = ValidationResponse(
                result=ValidationResult.VALID,
                status_code=200,
                message="OK",
                request_id=f"test{i}",
                client_id="client1"
            )
            self.logger.log_request(validation, {"method": "GET", "path": "/"})
        
        valid, count = self.logger.verify_integrity()
        
        assert valid is True
        assert count == 5
    
    def test_get_logs(self):
        """Test log retrieval"""
        from quantum_crypt.post_quantum_api_gateway_middleware_2026_june import ValidationResponse
        
        for i in range(10):
            validation = ValidationResponse(
                result=ValidationResult.VALID,
                status_code=200,
                message="OK",
                request_id=f"test{i}",
                client_id="client1"
            )
            self.logger.log_request(validation, {"method": "GET", "path": "/"})
        
        logs = self.logger.get_logs(limit=5)
        
        assert len(logs) == 5
        assert all("entry_hash" in log for log in logs)


class TestPostQuantumAPIGatewayMiddleware:
    """Test suite for main API Gateway Middleware"""
    
    def setup_method(self):
        self.gateway = PostQuantumAPIGatewayMiddleware()
        self.client = self.gateway.register_client("test_client_001")
    
    def test_register_client(self):
        """Test client registration"""
        client = self.gateway.register_client("new_client")
        
        assert "client_id" in client
        assert "api_key" in client
        assert "secret_key" in client
        assert client["client_id"] == "new_client"
    
    def test_validate_request_valid(self):
        """Test validation of properly signed request"""
        method = "POST"
        path = "/api/v1/secure"
        body = '{"data": "secure_data"}'
        timestamp = str(int(time.time()))
        nonce = self.gateway.signature_verifier.generate_nonce()
        
        secret_key = base64.urlsafe_b64decode(self.client["secret_key"] + '==')
        signature = self.gateway.signature_verifier.generate_signature(
            method, path, body, timestamp, nonce, secret_key
        )
        
        headers = {
            "X-API-Key": self.client["api_key"],
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature
        }
        
        result = self.gateway.validate_request(method, path, body, headers)
        
        assert result.result == ValidationResult.VALID
        assert result.status_code == 200
        assert result.signature_valid is True
        assert result.nonce_valid is True
    
    def test_validate_request_missing_headers(self):
        """Test detection of missing security headers"""
        headers = {}  # Missing all security headers
        
        result = self.gateway.validate_request("GET", "/", "", headers)
        
        assert result.result == ValidationResult.MISSING_HEADERS
        assert result.status_code == 400
    
    def test_validate_request_invalid_api_key(self):
        """Test detection of invalid API key"""
        headers = {
            "X-API-Key": "invalid_key",
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": "abc123",
            "X-Signature": "signature"
        }
        
        result = self.gateway.validate_request("GET", "/", "", headers)
        
        assert result.result == ValidationResult.INVALID_API_KEY
        assert result.status_code == 401
    
    def test_validate_request_invalid_signature(self):
        """Test detection of invalid signature"""
        headers = {
            "X-API-Key": self.client["api_key"],
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": "abc123",
            "X-Signature": "wrong_signature"
        }
        
        result = self.gateway.validate_request("GET", "/", "", headers)
        
        assert result.result == ValidationResult.INVALID_SIGNATURE
        assert result.status_code == 401
    
    def test_validate_request_replay_attack(self):
        """Test replay attack detection"""
        method = "GET"
        path = "/"
        body = ""
        timestamp = str(int(time.time()))
        nonce = "replay_test_nonce"
        
        secret_key = base64.urlsafe_b64decode(self.client["secret_key"] + '==')
        signature = self.gateway.signature_verifier.generate_signature(
            method, path, body, timestamp, nonce, secret_key
        )
        
        headers = {
            "X-API-Key": self.client["api_key"],
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature
        }
        
        # First request - valid
        result1 = self.gateway.validate_request(method, path, body, headers)
        assert result1.result == ValidationResult.VALID
        
        # Replay - should be detected
        result2 = self.gateway.validate_request(method, path, body, headers)
        assert result2.result == ValidationResult.REPLAY_DETECTED
    
    def test_generate_security_headers(self):
        """Test security header generation"""
        headers = self.gateway.generate_security_headers("client1")
        
        assert "X-Security-Level" in headers
        assert "X-Algorithm" in headers
        assert "Strict-Transport-Security" in headers
        assert "X-Content-Type-Options" in headers
    
    def test_get_security_report(self):
        """Test security status reporting"""
        report = self.gateway.get_security_report()
        
        assert "policy" in report
        assert "rate_limits" in report
        assert "audit_log" in report
        assert "registered_clients" in report
        assert "active_api_keys" in report
        assert report["registered_clients"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
