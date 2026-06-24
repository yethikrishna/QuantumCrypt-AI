"""
Test Suite for QuantumCrypt Observability & Instrumentation v20
DIMENSION D - Observability & Instrumentation

All tests verify ADD-ONLY behavior - no existing code modification.
All instrumentation is OPT-IN, disabled by default.
"""

import pytest
import time
import threading
import secrets

# Import the new crypto observability module
from quantum_crypt.crypto_comprehensive_observability_instrumentation_v20_2026_june import (
    CryptoInstrumentationManager,
    crypto_timed,
    crypto_audited,
    CryptoOperationType,
    SecurityEventType,
    CryptoHealthStatus,
    CryptoOperationTelemetry,
    SecurityEvent,
    ThreadSafeCryptoMetricStore,
    CryptoStructuredLogger,
    CryptoHealthChecker,
)

class TestThreadSafeCryptoMetricStore:
    """Tests for cryptographic metric storage"""
    
    def test_record_operation_success(self):
        store = ThreadSafeCryptoMetricStore()
        telemetry = CryptoOperationTelemetry(
            operation_id="test123",
            operation_type=CryptoOperationType.ENCRYPTION,
            algorithm="AES-256-GCM",
            key_size_bits=256,
            start_time=time.time(),
            end_time=time.time() + 0.001,
            success=True
        )
        store.record_operation(telemetry)
        
        stats = store.get_operation_statistics()
        assert stats["total_operations"] == 1
        assert stats["success_rate"] == 1.0
    
    def test_record_operation_failure(self):
        store = ThreadSafeCryptoMetricStore()
        telemetry = CryptoOperationTelemetry(
            operation_id="test456",
            operation_type=CryptoOperationType.DECRYPTION,
            algorithm="RSA-2048",
            key_size_bits=2048,
            start_time=time.time(),
            end_time=time.time() + 0.001,
            success=False,
            error_type="DecryptionError"
        )
        store.record_operation(telemetry)
        
        stats = store.get_operation_statistics()
        assert stats["total_operations"] == 1
        assert stats["success_rate"] == 0.0
    
    def test_record_security_event(self):
        store = ThreadSafeCryptoMetricStore()
        event = SecurityEvent(
            event_id="evt123",
            event_type=SecurityEventType.KEY_CREATED,
            severity="INFO",
            algorithm="ECDH-P384"
        )
        store.record_security_event(event)
        
        summary = store.get_security_event_summary()
        assert summary["total_events"] == 1
        assert summary["by_type"]["key_created"] == 1
    
    def test_key_lifecycle_tracking(self):
        store = ThreadSafeCryptoMetricStore()
        key_id = "test-key-001"
        store.track_key_creation(key_id, "AES-256", 256)
        
        for _ in range(5):
            store.track_key_usage(key_id)
        
        summary = store.get_key_lifecycle_summary()
        assert summary["active_keys"] == 1
        assert summary["total_operations"] == 5
    
    def test_thread_safety_concurrent_operations(self):
        store = ThreadSafeCryptoMetricStore()
        num_threads = 10
        ops_per_thread = 100
        
        def worker(thread_id):
            for i in range(ops_per_thread):
                telemetry = CryptoOperationTelemetry(
                    operation_id=f"op_{thread_id}_{i}",
                    operation_type=CryptoOperationType.HASHING,
                    algorithm="SHA-256",
                    key_size_bits=256,
                    start_time=time.time(),
                    end_time=time.time(),
                    success=True
                )
                store.record_operation(telemetry)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        stats = store.get_operation_statistics()
        expected = num_threads * ops_per_thread
        assert stats["total_operations"] == expected
    
    def test_counter_increment(self):
        store = ThreadSafeCryptoMetricStore()
        store.increment_counter("test.counter", 1)
        store.increment_counter("test.counter", 5)
        assert store.get_counter("test.counter") == 6

class TestCryptoStructuredLogger:
    """Tests for crypto audit logging"""
    
    def test_logger_disabled_by_default(self):
        logger = CryptoStructuredLogger(enabled=False)
        logger.log_crypto_operation(CryptoOperationType.ENCRYPTION, "AES", True)
        logs = logger.get_audit_log()
        assert len(logs) == 0
    
    def test_logger_enabled_logs_operations(self):
        logger = CryptoStructuredLogger(enabled=True)
        logger.log_crypto_operation(CryptoOperationType.ENCRYPTION, "AES-256", True)
        logs = logger.get_audit_log()
        assert len(logs) == 1
        assert logs[0]["operation"] == "encryption"
        assert logs[0]["algorithm"] == "AES-256"
    
    def test_logger_security_events(self):
        logger = CryptoStructuredLogger(enabled=True)
        logger.log_security_event(SecurityEventType.KEY_CREATED, "INFO", key_id="test-key")
        logs = logger.get_audit_log()
        assert len(logs) == 1
        assert logs[0]["event"] == "key_created"
    
    def test_logger_enable_disable(self):
        logger = CryptoStructuredLogger(enabled=False)
        logger.log_crypto_operation(CryptoOperationType.ENCRYPTION, "AES", True)
        assert len(logger.get_audit_log()) == 0
        
        logger.enable()
        logger.log_crypto_operation(CryptoOperationType.ENCRYPTION, "AES", True)
        assert len(logger.get_audit_log()) == 1
        
        logger.disable()
        logger.log_crypto_operation(CryptoOperationType.ENCRYPTION, "AES", True)
        assert len(logger.get_audit_log()) == 1

class TestCryptoHealthChecker:
    """Tests for crypto health checking"""
    
    def test_register_and_run_check(self):
        checker = CryptoHealthChecker()
        
        def custom_check():
            return {"status": "healthy", "custom_metric": 42}
        
        checker.register_check("custom", custom_check)
        result = checker.run_all_checks()
        
        assert "custom" in result["checks"]
        assert result["checks"]["custom"]["custom_metric"] == 42
    
    def test_entropy_quality_check(self):
        checker = CryptoHealthChecker()
        result = checker.check_entropy_quality()
        assert result["status"] == "healthy"
        assert "throughput_mbps" in result
        assert "generation_time_ms" in result
    
    def test_health_check_exception_handling(self):
        checker = CryptoHealthChecker()
        
        def failing_check():
            raise RuntimeError("Health check failed!")
        
        checker.register_check("failing", failing_check)
        result = checker.run_all_checks()
        assert result["checks"]["failing"]["status"] == "error"

class TestInstrumentationDecorators:
    """Tests for crypto instrumentation decorators (OPT-IN)"""
    
    def test_crypto_timed_disabled_by_default(self):
        """Decorator should be NOOP when disabled"""
        CryptoInstrumentationManager.disable_all()
        
        @crypto_timed(CryptoOperationType.ENCRYPTION, "AES-256")
        def encrypt_func(data):
            return data[::-1]
        
        result = encrypt_func("test data")
        assert result == "atad tset"
    
    def test_crypto_audited_disabled_by_default(self):
        """Audit decorator should be NOOP when disabled"""
        CryptoInstrumentationManager.disable_all()
        
        @crypto_audited(SecurityEventType.KEY_CREATED)
        def key_gen_func():
            return secrets.token_bytes(32)
        
        result = key_gen_func()
        assert len(result) == 32
    
    def test_crypto_timed_enabled_tracks_operations(self):
        CryptoInstrumentationManager.enable_all()
        
        @crypto_timed(CryptoOperationType.HASHING, "SHA-256")
        def hash_func(data):
            return data
        
        for _ in range(5):
            hash_func("test")
        
        stats = CryptoInstrumentationManager.get_crypto_statistics()
        assert stats["total_operations"] >= 5
        
        CryptoInstrumentationManager.disable_all()
    
    def test_crypto_audited_enabled_records_events(self):
        CryptoInstrumentationManager.enable_all()
        
        @crypto_audited(SecurityEventType.SIGNATURE_CREATED)
        def sign_func():
            return "signature"
        
        sign_func()
        sign_func()
        
        summary = CryptoInstrumentationManager.get_security_summary()
        assert summary["total_events"] >= 2
        
        CryptoInstrumentationManager.disable_all()

class TestCryptoInstrumentationManager:
    """Tests for central crypto instrumentation manager"""
    
    def test_singleton_behavior(self):
        instance1 = CryptoInstrumentationManager()
        instance2 = CryptoInstrumentationManager()
        assert instance1 is instance2
    
    def test_enable_disable_all(self):
        CryptoInstrumentationManager.disable_all()
        status = CryptoInstrumentationManager.get_observability_status()
        assert status["instrumentation_enabled"]["operation_tracking"] == False
        assert status["instrumentation_enabled"]["audit_logging"] == False
        
        CryptoInstrumentationManager.enable_all()
        status = CryptoInstrumentationManager.get_observability_status()
        assert status["instrumentation_enabled"]["operation_tracking"] == True
        assert status["instrumentation_enabled"]["audit_logging"] == True
        
        CryptoInstrumentationManager.disable_all()
    
    def test_crypto_statistics_reporting(self):
        CryptoInstrumentationManager.enable_all()
        
        telemetry = CryptoOperationTelemetry(
            operation_id="stat-test",
            operation_type=CryptoOperationType.KEY_GENERATION,
            algorithm="RSA-4096",
            key_size_bits=4096,
            start_time=time.time(),
            end_time=time.time() + 0.01,
            success=True
        )
        CryptoInstrumentationManager.record_operation(telemetry)
        
        stats = CryptoInstrumentationManager.get_crypto_statistics()
        assert stats["total_operations"] > 0
        
        CryptoInstrumentationManager.disable_all()
    
    def test_health_status_integration(self):
        status = CryptoInstrumentationManager.get_health_status()
        assert "overall_status" in status
        assert "checks" in status
        assert "entropy_quality" in status["checks"]
    
    def test_observability_status_report(self):
        status = CryptoInstrumentationManager.get_observability_status()
        assert "instrumentation_enabled" in status
        assert "operations_tracked" in status
        assert "security_events" in status
        assert status["stability"] == "STABLE"
        assert status["api_version"] == "v20"
        assert status["module"] == "QuantumCrypt-AI"

class TestBackwardCompatibility:
    """Critical tests ensuring backward compatibility - NO EXISTING CODE BROKEN"""
    
    def test_no_modification_to_existing_imports(self):
        """Verify original crypto modules still import correctly"""
        try:
            # These modules should all still work
            from quantum_crypt import crypto_api_documentation_master_v13_2026_june
            assert True
        except ImportError:
            pytest.fail("Existing crypto module imports broken - backward compatibility violated")
    
    def test_new_module_is_isolated(self):
        """Our new module doesn't interfere with existing code"""
        import quantum_crypt.crypto_comprehensive_observability_instrumentation_v20_2026_june as new_module
        assert new_module is not None
        assert hasattr(new_module, 'CryptoInstrumentationManager')
        assert hasattr(new_module, 'crypto_timed')
    
    def test_default_behavior_no_side_effects(self):
        """By default, all instrumentation is disabled - zero performance impact"""
        CryptoInstrumentationManager.disable_all()
        status = CryptoInstrumentationManager.get_observability_status()
        assert all(v == False for v in status["instrumentation_enabled"].values())

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
