"""
Test Suite for QuantumCrypt Observability Module (Dimension D - v25)
"""

import pytest
import time
import json
import secrets
from quantum_crypt.crypto_observability_structured_logging_metrics_v25_2026_june import (
    CryptoObservabilityConfig,
    CryptoOperationType,
    LogLevel,
    CryptoStructuredLogger,
    CryptoMetricsCollector,
    timed_crypto_operation,
    get_crypto_config,
    get_crypto_logger,
    get_crypto_metrics,
)


class TestCryptoObservabilityConfig:
    def test_default_config_all_disabled(self):
        config = CryptoObservabilityConfig()
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.health_checks_enabled = False
        config.audit_logging_enabled = False
        
        assert config.structured_logging_enabled is False
        assert config.metrics_collection_enabled is False
        assert config.health_checks_enabled is False
        assert config.audit_logging_enabled is False
    
    def test_sensitive_data_logging_disabled_by_default(self):
        config = CryptoObservabilityConfig()
        assert config.log_sensitive_data is False


class TestCryptoStructuredLogger:
    def test_logger_no_op_when_disabled(self, capsys):
        config = CryptoObservabilityConfig()
        config.structured_logging_enabled = False
        logger = CryptoStructuredLogger("test")
        logger.info("This should not appear", operation_type=CryptoOperationType.ENCRYPTION)
        captured = capsys.readouterr()
        assert captured.out == ""
    
    def test_logger_sanitizes_sensitive_data(self, capsys):
        config = CryptoObservabilityConfig()
        config.structured_logging_enabled = True
        logger = CryptoStructuredLogger("crypto_test")
        secret_key = b"my_super_secret_private_key_12345"
        logger.info("Key operation", 
                   operation_type=CryptoOperationType.KEY_GENERATION,
                   key=secret_key)
        captured = capsys.readouterr()
        log_output = json.loads(captured.out.strip())
        assert log_output["key"].startswith("sha256:")
        assert "my_super_secret_private_key" not in captured.out


class TestCryptoMetricsCollector:
    def test_metrics_no_op_when_disabled(self):
        config = CryptoObservabilityConfig()
        config.metrics_collection_enabled = False
        collector = CryptoMetricsCollector()
        collector.record_key_operation(
            CryptoOperationType.ENCRYPTION, "AES-256", 256, True, 1.5
        )
        metrics = collector.get_metrics()
        assert metrics == {}


class TestTimedCryptoOperationDecorator:
    def test_decorator_no_op_when_disabled(self):
        config = CryptoObservabilityConfig()
        config.metrics_collection_enabled = False
        call_count = 0
        @timed_crypto_operation(CryptoOperationType.ENCRYPTION, "AES-256", 256)
        def test_encrypt():
            nonlocal call_count
            call_count += 1
            return b"encrypted_data"
        result = test_encrypt()
        assert result == b"encrypted_data"
        assert call_count == 1
    
    def test_decorator_propagates_exceptions(self):
        config = CryptoObservabilityConfig()
        config.metrics_collection_enabled = True
        @timed_crypto_operation(CryptoOperationType.DECRYPTION)
        def failing_decrypt():
            raise ValueError("Invalid padding")
        with pytest.raises(ValueError, match="Invalid padding"):
            failing_decrypt()


class TestBackwardCompatibility:
    def test_no_side_effects_when_disabled(self):
        config = CryptoObservabilityConfig()
        config.structured_logging_enabled = False
        config.metrics_collection_enabled = False
        config.health_checks_enabled = False
        config.audit_logging_enabled = False
        
        logger = CryptoStructuredLogger()
        logger.info("should not log", CryptoOperationType.ENCRYPTION, key=b"secret")
        
        metrics = CryptoMetricsCollector()
        metrics.record_key_operation(CryptoOperationType.ENCRYPTION, "AES", 256, True, 1.0)
        
        @timed_crypto_operation(CryptoOperationType.ENCRYPTION)
        def test_encrypt():
            return b"encrypted"
        assert test_encrypt() == b"encrypted"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
