"""
Tests for QuantumCrypt Enhanced Observability & SLO Monitoring V6
DIMENSION D: Observability & Instrumentation
"""

import pytest
import time
import threading
import secrets
from quantum_crypt.crypto_observability_enhanced_slo_tracing_v6_2026_june import (
    EnhancedCryptoObservability,
    ThreadLocalContext,
    LatencyHistogram,
    RandomnessQualityMonitor,
    SLOMonitor,
    SLOConfig,
    SLOStatus,
    CryptoOperationType,
    enable_crypto_observability,
    disable_crypto_observability,
    crypto_observability
)


class TestLatencyHistogram:
    def test_crypto_latency_recording(self):
        hist = LatencyHistogram("encryption")
        hist.record(0.001)  # 1ms
        hist.record(0.005)  # 5ms
        hist.record(0.0005)  # 0.5ms
        
        stats = hist.get_stats()
        assert stats["count"] == 3
        assert stats["avg"] > 0
    
    def test_crypto_percentiles(self):
        hist = LatencyHistogram("signing")
        for i in range(100):
            hist.record(i * 0.0001)
        
        stats = hist.get_stats()
        assert stats["p50"] <= stats["p95"] <= stats["p99"]


class TestRandomnessQualityMonitor:
    def test_recording_samples(self):
        monitor = RandomnessQualityMonitor()
        monitor.record_sample(b"\x01\x02\x03\x04")
        monitor.record_sample(secrets.token_bytes(32))
        
        metrics = monitor.get_quality_metrics()
        assert metrics["samples"] == 2
    
    def test_empty_monitor(self):
        monitor = RandomnessQualityMonitor()
        metrics = monitor.get_quality_metrics()
        assert metrics["samples"] == 0
        assert metrics["avg_entropy"] == 0.0
    
    def test_entropy_calculation(self):
        monitor = RandomnessQualityMonitor()
        # High entropy data
        high_entropy = secrets.token_bytes(256)
        entropy = monitor.calculate_entropy(high_entropy)
        assert 0 <= entropy <= 8.0


class TestSLOMonitor:
    def test_crypto_slo_registration(self):
        monitor = SLOMonitor()
        monitor.register_slo(SLOConfig("encryption_success", 99.99))
        
        status = monitor.get_slo_status("encryption_success")
        assert status is not None
        assert status.current_availability == 100.0
    
    def test_crypto_operation_events(self):
        monitor = SLOMonitor()
        monitor.register_slo(SLOConfig("crypto_ops", 99.9))
        
        for _ in range(1000):
            monitor.record_event("crypto_ops", is_error=False)
        
        status = monitor.get_slo_status("crypto_ops")
        assert status.window_events == 1000
        assert status.window_errors == 0
        assert status.status == SLOStatus.HEALTHY


class TestThreadLocalContext:
    def test_crypto_trace_context(self):
        ThreadLocalContext.set_current_trace_id("crypto-trace-123")
        assert ThreadLocalContext.get_current_trace_id() == "crypto-trace-123"
    
    def test_thread_isolation_for_crypto(self):
        results = {}
        
        def worker(thread_id):
            ThreadLocalContext.set_current_trace_id(f"crypto-{thread_id}")
            time.sleep(0.01)
            results[thread_id] = ThreadLocalContext.get_current_trace_id()
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert results[0] == "crypto-0"
        assert results[1] == "crypto-1"
        assert results[2] == "crypto-2"


class TestEnhancedCryptoObservability:
    def test_disabled_by_default(self):
        engine = EnhancedCryptoObservability(enabled=False)
        assert engine.enabled is False
        metrics = engine.get_metrics_summary()
        assert metrics["enabled"] is False
    
    def test_crypto_tracing_disabled_noop(self):
        engine = EnhancedCryptoObservability(enabled=False)
        span = engine.start_crypto_trace("aes_encrypt", CryptoOperationType.ENCRYPTION)
        assert span.trace_id == ""  # Noop
        engine.end_crypto_trace(span)  # Should not crash
    
    def test_crypto_tracing_enabled(self):
        engine = EnhancedCryptoObservability(enabled=True)
        span = engine.start_crypto_trace(
            "rsa_keygen",
            CryptoOperationType.KEY_GENERATION,
            attributes={"key_size": 2048}
        )
        assert span.trace_id != ""
        assert span.operation_type == CryptoOperationType.KEY_GENERATION
        time.sleep(0.001)
        engine.end_crypto_trace(span, {"key_id": "test-key-1"})
    
    def test_crypto_trace_decorator(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        @engine.crypto_trace(CryptoOperationType.ENCRYPTION, "aes_gcm_encrypt")
        def encrypt_data(data: bytes, key: bytes) -> bytes:
            return data  # Simulated
        
        result = encrypt_data(b"test", b"key123")
        assert result == b"test"
    
    def test_crypto_trace_decorator_with_exception(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        @engine.crypto_trace(CryptoOperationType.DECRYPTION)
        def failing_decrypt():
            raise ValueError("Invalid padding")
        
        with pytest.raises(ValueError):
            failing_decrypt()
    
    def test_key_registration_and_tracking(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        engine.register_key("key-001", "AES-256-GCM", 256)
        engine.increment_key_usage("key-001")
        engine.increment_key_usage("key-001")
        
        keys = engine.get_key_status()
        assert len(keys) == 1
        assert keys[0]["key_id"] == "key-001"
        assert keys[0]["operations"] == 2
        assert keys[0]["algorithm"] == "AES-256-GCM"
    
    def test_randomness_recording(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        for _ in range(10):
            engine.record_random_bytes(secrets.token_bytes(32))
        
        quality = engine.get_randomness_quality()
        assert quality["samples"] == 10
    
    def test_crypto_slo_recording(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        for _ in range(100):
            engine.record_slo_event("crypto_operation_availability", is_error=False)
        
        slos = engine.get_all_slo_status()
        assert len(slos) >= 3  # Default crypto SLOs
    
    def test_crypto_health_checks(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        def hsm_available():
            return True
        
        def entropy_pool_healthy():
            return True
        
        engine.register_health_check("hsm_connection", hsm_available)
        engine.register_health_check("entropy_pool", entropy_pool_healthy)
        
        result = engine.run_health_checks()
        assert result["overall_healthy"] is True
        assert "hsm_connection" in result["checks"]
        assert "entropy_pool" in result["checks"]
    
    def test_crypto_metrics_collection(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        engine.increment_counter("encryptions_total", 1, {"algorithm": "AES"})
        engine.increment_counter("encryptions_total", 1, {"algorithm": "RSA"})
        engine.set_gauge("active_keys", 42, {"type": "symmetric"})
        engine.record_crypto_latency("encryption", 0.0023)
        
        metrics = engine.get_metrics_summary()
        assert metrics["enabled"] is True
        assert len(metrics["counters"]) > 0
        assert len(metrics["gauges"]) > 0


class TestGlobalInstance:
    def test_global_crypto_observability(self):
        assert crypto_observability is not None
    
    def test_enable_disable_functions(self):
        original = crypto_observability.enabled
        enable_crypto_observability()
        assert crypto_observability.enabled is True
        disable_crypto_observability()
        assert crypto_observability.enabled is False
        crypto_observability.enabled = original


class TestCryptoOperationTypes:
    def test_all_operation_types_exist(self):
        assert CryptoOperationType.KEY_GENERATION.value == "key_generation"
        assert CryptoOperationType.ENCRYPTION.value == "encryption"
        assert CryptoOperationType.DECRYPTION.value == "decryption"
        assert CryptoOperationType.SIGNING.value == "signing"
        assert CryptoOperationType.VERIFICATION.value == "verification"
        assert CryptoOperationType.HASHING.value == "hashing"
        assert CryptoOperationType.KEY_EXCHANGE.value == "key_exchange"
        assert CryptoOperationType.RANDOM_GENERATION.value == "random_generation"


class TestIntegrationWorkflow:
    def test_full_crypto_pipeline_observability(self):
        engine = EnhancedCryptoObservability(enabled=True)
        
        # Simulate key generation - FIXED: correct parameter order
        keygen_span = engine.start_crypto_trace(
            "generate_rsa_keypair",
            CryptoOperationType.KEY_GENERATION,
            attributes={"key_size": 4096}
        )
        time.sleep(0.002)
        engine.end_crypto_trace(keygen_span, {"key_id": "rsa-4096-001"})
        
        engine.register_key("rsa-4096-001", "RSA", 4096)
        
        # Simulate encryption
        encrypt_span = engine.start_crypto_trace(
            "rsa_encrypt",
            CryptoOperationType.ENCRYPTION,
            attributes={"key_id": "rsa-4096-001", "data_size": 256}
        )
        time.sleep(0.001)
        engine.end_crypto_trace(encrypt_span, {"status": "success"})
        engine.increment_key_usage("rsa-4096-001")
        
        # Record SLO success
        engine.record_slo_event("crypto_operation_availability", is_error=False)
        
        # Record randomness quality
        engine.record_random_bytes(secrets.token_bytes(64))
        
        # Verify all captured
        metrics = engine.get_metrics_summary()
        assert metrics["keys_tracked"] == 1
        assert len(metrics["latency_by_operation"]) > 0
        
        keys = engine.get_key_status()
        assert keys[0]["operations"] == 1
        
        quality = engine.get_randomness_quality()
        assert quality["samples"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
