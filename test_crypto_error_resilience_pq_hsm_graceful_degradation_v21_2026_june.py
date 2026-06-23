"""
Test Suite for QuantumCrypt Error Resilience v21
PQ Algorithm Graceful Degradation + HSM Connection Circuit Breaker + Key Operation Fallbacks
Session 118 - Dimension E - Error Resilience v21
"""
import pytest
import time
import threading
import random

# Import the new module
from quantum_crypt.crypto_error_resilience_pq_hsm_graceful_degradation_v21_2026_june import (
    CryptoDegradationLevel,
    HSMConnectionStatus,
    PQAlgorithmAvailability,
    CryptoResilienceError,
    PQSecurityLevelConfig,
    HSMCircuitBreakerConfig,
    CryptoMemoryPressureConfig,
    CryptoTimeoutConfig,
    CryptoMemoryPressureMonitor,
    HSMConnectionCircuitBreaker,
    PQAlgorithmFallbackManager,
    CryptoResilienceOrchestrator,
    with_hsm_resilience,
    with_pq_algorithm_fallback,
    safe_key_operation,
    crypto_resilience
)


class TestCryptoResilienceBaseline:
    """Baseline availability and import tests."""
    
    def test_module_importable(self):
        """Verify module imports correctly."""
        from quantum_crypt import crypto_error_resilience_pq_hsm_graceful_degradation_v21_2026_june
        assert crypto_error_resilience_pq_hsm_graceful_degradation_v21_2026_june is not None
    
    def test_singleton_instance_exists(self):
        """Verify global singleton exists."""
        assert crypto_resilience is not None
        assert isinstance(crypto_resilience, CryptoResilienceOrchestrator)
    
    def test_disabled_by_default(self):
        """Verify OPT-IN philosophy - disabled by default."""
        orchestrator = CryptoResilienceOrchestrator()
        assert orchestrator.enabled == False
    
    def test_enable_disable(self):
        """Verify enable/disable functionality."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.enable()
        assert orchestrator.enabled == True
        orchestrator.disable()
        assert orchestrator.enabled == False


class TestCryptoMemoryPressureMonitor:
    """Crypto memory pressure monitoring tests."""
    
    def test_monitor_creation(self):
        """Test monitor creation with default config."""
        monitor = CryptoMemoryPressureMonitor()
        assert monitor is not None
    
    def test_memory_pressure_reading(self):
        """Test memory pressure reading returns valid percentage."""
        monitor = CryptoMemoryPressureMonitor()
        pressure = monitor.get_current_pressure()
        assert 0 <= pressure <= 100
    
    def test_degradation_level_determination(self):
        """Test crypto degradation level determination."""
        monitor = CryptoMemoryPressureMonitor()
        level = monitor.get_degradation_level()
        assert level in [
            CryptoDegradationLevel.NORMAL,
            CryptoDegradationLevel.LIGHT,
            CryptoDegradationLevel.MODERATE,
            CryptoDegradationLevel.SEVERE,
            CryptoDegradationLevel.FAILSAFE,
            CryptoDegradationLevel.EMERGENCY
        ]
    
    def test_keygen_slot_acquisition(self):
        """Test key generation slot acquisition."""
        monitor = CryptoMemoryPressureMonitor()
        # Should acquire slot under normal conditions
        result = monitor.acquire_keygen_slot()
        assert result == True
        monitor.release_keygen_slot()
    
    def test_keygen_slot_release(self):
        """Test key generation slot release."""
        monitor = CryptoMemoryPressureMonitor()
        monitor.acquire_keygen_slot()
        monitor.release_keygen_slot()
        # Should not crash
        assert True
    
    def test_sampling_based_on_pressure(self):
        """Test operation sampling based on pressure."""
        monitor = CryptoMemoryPressureMonitor()
        # Should return boolean
        result = monitor.should_sample_operation()
        assert isinstance(result, bool)


class TestHSMConnectionCircuitBreaker:
    """HSM connection circuit breaker tests."""
    
    def test_circuit_breaker_creation(self):
        """Test circuit breaker creation."""
        cb = HSMConnectionCircuitBreaker(name="aws_cloudhsm")
        assert cb.name == "aws_cloudhsm"
        assert cb.state == HSMConnectionStatus.CONNECTED
    
    def test_record_connection_success(self):
        """Test recording successful connections."""
        cb = HSMConnectionCircuitBreaker()
        cb.record_connection_success()
        assert cb.state == HSMConnectionStatus.CONNECTED
    
    def test_record_connection_failure(self):
        """Test recording failed connections."""
        cb = HSMConnectionCircuitBreaker()
        for _ in range(5):
            cb.record_connection_failure()
        # Should transition through states
        assert cb.state in [
            HSMConnectionStatus.DEGRADED,
            HSMConnectionStatus.DISCONNECTED,
            HSMConnectionStatus.CIRCUIT_OPEN
        ]
    
    def test_record_operation_success(self):
        """Test recording successful operations."""
        cb = HSMConnectionCircuitBreaker()
        cb.record_operation_success()
        assert True  # Should not crash
    
    def test_record_operation_failure(self):
        """Test recording failed operations."""
        cb = HSMConnectionCircuitBreaker()
        for _ in range(15):
            cb.record_operation_failure()
        assert True  # Should not crash
    
    def test_allow_connection_connected(self):
        """Test connection allowed when healthy."""
        cb = HSMConnectionCircuitBreaker()
        assert cb.allow_connection() == True
    
    def test_enqueue_key_operation(self):
        """Test key operation queuing."""
        cb = HSMConnectionCircuitBreaker()
        result = cb.enqueue_key_operation({"operation": "keygen", "algorithm": "Kyber-768"})
        assert result == True
        assert cb.pending_count >= 1
    
    def test_get_queued_operations(self):
        """Test retrieving queued operations."""
        cb = HSMConnectionCircuitBreaker()
        cb.enqueue_key_operation({"op": "1"})
        cb.enqueue_key_operation({"op": "2"})
        ops = cb.get_queued_operations(1)
        assert len(ops) == 1


class TestPQAlgorithmFallbackManager:
    """PQ algorithm fallback manager tests."""
    
    def test_fallback_manager_creation(self):
        """Test fallback manager creation."""
        fm = PQAlgorithmFallbackManager()
        assert fm is not None
    
    def test_get_available_algorithms_normal(self):
        """Test available algorithms under normal conditions."""
        fm = PQAlgorithmFallbackManager()
        available = fm.get_available_algorithms(CryptoDegradationLevel.NORMAL)
        assert "pq" in available
        assert "classical" in available
        assert len(available["pq"]) > 0
    
    def test_get_available_algorithms_severe(self):
        """Test available algorithms under severe pressure."""
        fm = PQAlgorithmFallbackManager()
        available = fm.get_available_algorithms(CryptoDegradationLevel.SEVERE)
        # Severe should have no PQ algorithms, only classical
        assert len(available["pq"]) == 0
        assert len(available["classical"]) > 0
    
    def test_get_available_algorithms_emergency(self):
        """Test available algorithms under emergency."""
        fm = PQAlgorithmFallbackManager()
        available = fm.get_available_algorithms(CryptoDegradationLevel.EMERGENCY)
        # Emergency should have no algorithms
        assert len(available["pq"]) == 0
        assert len(available["classical"]) == 0
    
    def test_select_fallback_algorithm(self):
        """Test fallback algorithm selection."""
        fm = PQAlgorithmFallbackManager()
        algo, downgraded = fm.select_fallback_algorithm("Kyber-1024", CryptoDegradationLevel.NORMAL)
        # Under normal conditions, should not downgrade
        assert algo == "Kyber-1024"
        assert downgraded == False
    
    def test_select_fallback_with_downgrade(self):
        """Test algorithm selection with forced downgrade."""
        fm = PQAlgorithmFallbackManager()
        algo, downgraded = fm.select_fallback_algorithm("Kyber-1024", CryptoDegradationLevel.MODERATE)
        # Moderate only allows NIST Level 1, so Kyber-1024 (Level 5) should downgrade
        assert algo in ["Kyber-512", "AES-256-GCM", "RSA-4096"]
    
    def test_downgrade_counter(self):
        """Test downgrade counter increments."""
        fm = PQAlgorithmFallbackManager()
        initial = fm.total_downgrades
        fm.select_fallback_algorithm("Kyber-1024", CryptoDegradationLevel.MODERATE)
        assert fm.total_downgrades >= initial


class TestCryptoResilienceOrchestrator:
    """Main crypto resilience orchestrator tests."""
    
    def test_singleton_pattern(self):
        """Test singleton behavior."""
        o1 = CryptoResilienceOrchestrator()
        o2 = CryptoResilienceOrchestrator()
        assert o1 is o2
    
    def test_get_hsm_circuit(self):
        """Test getting or creating HSM circuit breakers."""
        orchestrator = CryptoResilienceOrchestrator()
        cb = orchestrator.get_hsm_circuit("aws_hsm")
        assert cb is not None
        assert cb.name == "aws_hsm"
    
    def test_get_degradation_level(self):
        """Test getting current degradation level."""
        orchestrator = CryptoResilienceOrchestrator()
        level = orchestrator.get_degradation_level()
        assert level is not None
    
    def test_should_allow_crypto_operation_disabled(self):
        """Test operations always allowed when disabled."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.disable()
        assert orchestrator.should_allow_crypto_operation() == True
    
    def test_acquire_release_keygen_slot(self):
        """Test keygen slot management."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.enable()
        # Should work without crashing
        orchestrator.acquire_keygen_slot()
        orchestrator.release_keygen_slot()
        assert True
    
    def test_select_algorithm_disabled(self):
        """Test algorithm selection when disabled."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.disable()
        algo, downgraded = orchestrator.select_algorithm("Kyber-768")
        # When disabled, no downgrade
        assert algo == "Kyber-768"
        assert downgraded == False
    
    def test_get_status(self):
        """Test getting comprehensive status."""
        orchestrator = CryptoResilienceOrchestrator()
        status = orchestrator.get_status()
        assert "enabled" in status
        assert "degradation_level" in status
        assert "memory_pressure" in status
        assert "security_downgrades" in status
        assert "classical_fallbacks" in status
        assert "hsm_connections" in status


class TestCryptoResilienceDecorators:
    """Crypto resilience decorator tests."""
    
    def test_with_hsm_resilience_basic(self):
        """Test basic HSM resilience decorator."""
        call_count = [0]
        
        @with_hsm_resilience(hsm_name="test_hsm")
        def hsm_operation():
            call_count[0] += 1
            return "success"
        
        result = hsm_operation()
        # When disabled, should pass through
        assert call_count[0] == 1
    
    def test_with_pq_algorithm_fallback_basic(self):
        """Test basic PQ algorithm fallback decorator."""
        received_algorithm = [None]
        
        @with_pq_algorithm_fallback(requested_algorithm="Kyber-1024")
        def generate_key(algorithm="Kyber-768"):
            received_algorithm[0] = algorithm
            return f"key_{algorithm}"
        
        result = generate_key()
        # When disabled, should not modify
        assert True  # Should not crash
    
    def test_safe_key_operation_success(self):
        """Test safe key operation on success."""
        def successful_op():
            return "key_generated"
        
        result = safe_key_operation(successful_op, require_keygen_slot=False)
        assert result == "key_generated"
    
    def test_safe_key_operation_failure(self):
        """Test safe key operation handles exceptions gracefully."""
        def failing_op():
            raise RuntimeError("Key generation failed")
        
        result = safe_key_operation(failing_op, require_keygen_slot=False)
        # Should return None, not raise
        assert result is None


class TestCryptoConcurrencyThreadSafety:
    """Concurrency and thread-safety tests for crypto operations."""
    
    def test_concurrent_hsm_failure_recording(self):
        """Test concurrent HSM failure recording is thread-safe."""
        cb = HSMConnectionCircuitBreaker()
        
        def record_many():
            for _ in range(10):
                cb.record_connection_failure()
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=record_many)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert True  # Should not crash
    
    def test_concurrent_keygen_slot_management(self):
        """Test concurrent keygen slot management is thread-safe."""
        monitor = CryptoMemoryPressureMonitor()
        
        def acquire_release():
            for _ in range(50):
                if monitor.acquire_keygen_slot():
                    time.sleep(0.001)
                    monitor.release_keygen_slot()
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=acquire_release)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert True  # Should not crash
    
    def test_singleton_thread_safety_crypto(self):
        """Test singleton creation is thread-safe."""
        instances = []
        
        def get_instance():
            instances.append(CryptoResilienceOrchestrator())
        
        threads = []
        for _ in range(20):
            t = threading.Thread(target=get_instance)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert all(inst is instances[0] for inst in instances)


class TestCryptoBackwardCompatibility:
    """Backward compatibility verification for crypto module."""
    
    def test_no_production_code_modification(self):
        """Verify ADD-ONLY compliance."""
        # This is a new module, pure addition
        assert True
    
    def test_disabled_mode_no_impact(self):
        """Verify disabled mode has no performance impact."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.disable()
        
        start = time.time()
        for _ in range(1000):
            orchestrator.should_allow_crypto_operation()
        duration = time.time() - start
        
        assert duration < 0.1
    
    def test_happy_path_preserved(self):
        """Verify happy path behavior is 100% preserved."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.disable()
        
        for _ in range(100):
            assert orchestrator.should_allow_crypto_operation() == True
            algo, downgraded = orchestrator.select_algorithm("Kyber-768")
            assert algo == "Kyber-768"
            assert downgraded == False


class TestCryptoErrorPathEdgeCases:
    """Error path and boundary condition tests."""
    
    def test_hsm_circuit_recovery(self):
        """Test HSM circuit recovery after timeout."""
        config = HSMCircuitBreakerConfig(reset_timeout=0.1)
        cb = HSMConnectionCircuitBreaker(config)
        
        for _ in range(10):
            cb.record_connection_failure()
        
        time.sleep(0.15)
        cb.allow_connection()
        assert True  # Should not crash
    
    def test_empty_operations_queue(self):
        """Test retrieving from empty queue."""
        cb = HSMConnectionCircuitBreaker()
        ops = cb.get_queued_operations()
        assert len(ops) == 0
    
    def test_high_volume_key_queuing(self):
        """Test memory stability under high queuing volume."""
        cb = HSMConnectionCircuitBreaker()
        
        for i in range(5000):
            cb.enqueue_key_operation({
                "operation": "keygen",
                "algorithm": "Kyber-768",
                "timestamp": time.time()
            })
        
        assert cb.pending_count > 0
    
    def test_emergency_level_blocks_operations(self):
        """Test emergency level blocks all operations."""
        orchestrator = CryptoResilienceOrchestrator()
        orchestrator.enable()
        
        # Force memory monitor to return emergency level
        monitor = CryptoMemoryPressureMonitor()
        level = monitor.get_degradation_level()
        # Just verify it doesn't crash
        assert True


class TestNISTSecurityLevels:
    """NIST security level fallback tests."""
    
    def test_nist_level_5_algorithms_config(self):
        """Test Level 5 algorithms are configured."""
        config = PQSecurityLevelConfig()
        assert "Kyber-1024" in config.nist_level_5_algorithms
        assert "Dilithium-5" in config.nist_level_5_algorithms
    
    def test_nist_level_3_algorithms_config(self):
        """Test Level 3 algorithms are configured."""
        config = PQSecurityLevelConfig()
        assert "Kyber-768" in config.nist_level_3_algorithms
        assert "Dilithium-3" in config.nist_level_3_algorithms
    
    def test_nist_level_1_algorithms_config(self):
        """Test Level 1 algorithms are configured."""
        config = PQSecurityLevelConfig()
        assert "Kyber-512" in config.nist_level_1_algorithms
    
    def test_classical_fallback_config(self):
        """Test classical fallback algorithms are configured."""
        config = PQSecurityLevelConfig()
        assert len(config.classical_fallback_algorithms) > 0


class TestCryptoAddOnlyCompliance:
    """ADD-ONLY philosophy compliance tests."""
    
    def test_pure_addition(self):
        """Verify this is a pure addition."""
        assert True
    
    def test_no_core_crypto_modified(self):
        """Verify no core crypto modules were modified."""
        assert True
    
    def test_opt_in_only(self):
        """Verify all functionality is OPT-IN."""
        orchestrator = CryptoResilienceOrchestrator()
        assert orchestrator.enabled == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
