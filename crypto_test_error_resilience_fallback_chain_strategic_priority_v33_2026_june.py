"""
Test suite for QuantumCrypt AI - Crypto Strategic Priority Fallback Chain v33
DIMENSION E: ERROR RESILIENCE - Test Coverage Expansion

All tests verify:
1. Happy path behavior is preserved
2. Backward compatibility maintained
3. New crypto error resilience features work correctly
4. No existing code is broken
5. Security properties are maintained
"""

import unittest
import time
import threading
from quantum_crypt.crypto_error_resilience_fallback_chain_strategic_priority_v33_2026_june import (
    CryptoStrategicFallbackChain,
    CryptoFallbackStrategy,
    CryptoDegradationLevel,
    CryptoFallbackPriority,
    CryptoHealthStatus,
    CryptoHealthScore,
    SecurityStrength,
    CryptoDegradationTracker,
    crypto_strategic_fallback,
    secure_zeroize,
)


class TestSecureZeroize(unittest.TestCase):
    """Tests for secure memory zeroization."""
    
    def test_secure_zeroize_bytearray(self):
        """Test secure zeroization works."""
        sensitive = bytearray(b"secret_key_data_12345")
        original = bytes(sensitive)
        
        secure_zeroize(sensitive)
        
        # Verify all bytes are zero
        self.assertEqual(len(sensitive), len(original))
        self.assertTrue(all(b == 0 for b in sensitive))


class TestCryptoHealthScore(unittest.TestCase):
    """Tests for CryptoHealthScore health monitoring."""
    
    def test_crypto_health_score_initial_state(self):
        """Test initial health score is 1.0."""
        hs = CryptoHealthScore("hsm_module")
        self.assertEqual(hs.get_health_score(), 1.0)
        self.assertEqual(hs.get_health_status(), CryptoHealthStatus.OPERATIONAL)
    
    def test_crypto_health_score_hardware_error_penalty(self):
        """Test hardware errors apply additional penalty."""
        hs = CryptoHealthScore("hsm_module")
        
        # Record hardware errors
        for _ in range(5):
            hs.record_failure(100.0, is_hardware_error=True)
        
        score = hs.get_health_score()
        self.assertLess(score, 0.5)
        self.assertEqual(hs.get_health_status(), CryptoHealthStatus.HARDWARE_FAILURE)
    
    def test_crypto_health_score_key_errors(self):
        """Test key operation errors are tracked."""
        hs = CryptoHealthScore("kms_service")
        hs.record_failure(100.0, is_key_error=True)
        self.assertEqual(hs.key_operation_failures, 1)


class TestCryptoDegradationTracker(unittest.TestCase):
    """Tests for CryptoDegradationTracker security compliance."""
    
    def test_initial_crypto_degradation_level(self):
        """Test initial level is FULL_SECURITY."""
        dt = CryptoDegradationTracker()
        self.assertEqual(dt.get_current_level(), CryptoDegradationLevel.FULL_SECURITY)
    
    def test_security_compliance_violation_tracking(self):
        """Test compliance violations are tracked."""
        dt = CryptoDegradationTracker(minimum_security_strength=SecurityStrength.CLASSIC_128)
        dt.record_operation(security_strength_used=SecurityStrength.MINIMAL)
        self.assertEqual(dt.security_compliance_violations, 1)
    
    def test_security_availability_calculation(self):
        """Test secure availability calculation."""
        dt = CryptoDegradationTracker()
        dt.record_operation()  # Good
        dt.record_operation(failed=True)  # Failed
        dt.record_operation(security_strength_used=SecurityStrength.MINIMAL)  # Violation
        
        availability = dt.get_security_availability()
        self.assertLess(availability, 1.0)
        self.assertEqual(dt.total_crypto_operations, 3)


class TestCryptoFallbackStrategy(unittest.TestCase):
    """Tests for CryptoFallbackStrategy metadata."""
    
    def test_crypto_fallback_strategy_security_metadata(self):
        """Test strategy has security metadata."""
        def dummy_handler():
            return b"encrypted"
        
        strategy = CryptoFallbackStrategy(
            name="aes256_fallback",
            handler=dummy_handler,
            priority=CryptoFallbackPriority.CLASSIC_CRYPTO_FALLBACK,
            security_strength=SecurityStrength.CLASSIC_256
        )
        
        self.assertEqual(strategy.security_strength, SecurityStrength.CLASSIC_256)
        self.assertTrue(strategy.zeroize_on_failure)


class TestCryptoStrategicFallbackChain(unittest.TestCase):
    """Tests for CryptoStrategicFallbackChain core functionality."""
    
    def test_crypto_happy_path_primary_succeeds(self):
        """Test happy path - primary crypto operation succeeds."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def primary_encrypt():
            return b"encrypted_data_with_pqc"
        
        chain.register_primary_operation(primary_encrypt, security_strength=SecurityStrength.PQC_LEVEL_5)
        
        result, was_degraded, strategy_used, security = chain.execute()
        
        self.assertEqual(result, b"encrypted_data_with_pqc")
        self.assertFalse(was_degraded)
        self.assertEqual(strategy_used, "primary")
        self.assertEqual(security, SecurityStrength.PQC_LEVEL_5)
        self.assertEqual(chain.fallback_activations, 0)
    
    def test_crypto_primary_fails_fallback_succeeds(self):
        """Test fallback activation when primary crypto fails."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def failing_pqc():
            raise RuntimeError("Post-quantum module hardware error")
        
        def classic_crypto_fallback():
            return b"encrypted_with_aes256"
        
        chain.register_primary_operation(failing_pqc, security_strength=SecurityStrength.PQC_LEVEL_5)
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="aes256_classic",
            handler=classic_crypto_fallback,
            priority=CryptoFallbackPriority.CLASSIC_CRYPTO_FALLBACK,
            security_strength=SecurityStrength.CLASSIC_256
        ))
        
        result, was_degraded, strategy_used, security = chain.execute()
        
        self.assertEqual(result, b"encrypted_with_aes256")
        self.assertTrue(was_degraded)
        self.assertEqual(strategy_used, "aes256_classic")
        self.assertEqual(chain.fallback_activations, 1)
        self.assertEqual(chain.successful_fallbacks, 1)
        self.assertEqual(chain.security_downgrades, 0)  # Same strength level
    
    def test_crypto_security_downgrade_tracking(self):
        """Test security downgrades are tracked."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def failing_pqc():
            raise RuntimeError("PQC failed")
        
        def weaker_fallback():
            return b"encrypted_with_weak_algo"
        
        chain.register_primary_operation(failing_pqc, security_strength=SecurityStrength.PQC_LEVEL_5)
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="weaker_algo",
            handler=weaker_fallback,
            priority=CryptoFallbackPriority.SOFTWARE_ONLY,
            security_strength=SecurityStrength.CLASSIC_128
        ))
        
        chain.execute()
        
        self.assertEqual(chain.security_downgrades, 1)  # 256 -> 128 bit downgrade
    
    def test_crypto_priority_ordering(self):
        """Test crypto fallbacks execute in priority order."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        execution_order = []
        
        def failing_primary():
            raise RuntimeError("Primary failed")
        
        def make_fallback(name: str, should_fail: bool):
            def fallback():
                execution_order.append(name)
                if should_fail:
                    raise RuntimeError(f"{name} failed")
                return f"{name}_result"
            return fallback
        
        chain.register_primary_operation(failing_primary)
        
        # Add in reverse priority order
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="software_only",
            handler=make_fallback("software_only", True),
            priority=CryptoFallbackPriority.SOFTWARE_ONLY,
            security_strength=SecurityStrength.CLASSIC_128
        ))
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="classic_crypto",
            handler=make_fallback("classic_crypto", False),
            priority=CryptoFallbackPriority.CLASSIC_CRYPTO_FALLBACK,
            security_strength=SecurityStrength.CLASSIC_256
        ))
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="pqc_backup",
            handler=make_fallback("pqc_backup", True),
            priority=CryptoFallbackPriority.POST_QUANTUM_PRIMARY,
            security_strength=SecurityStrength.PQC_LEVEL_5
        ))
        
        chain.execute()
        
        # POST_QUANTUM_PRIMARY should execute first
        self.assertEqual(execution_order, ["pqc_backup", "classic_crypto"])
    
    def test_all_crypto_fallbacks_fail(self):
        """Test proper error when all crypto fallbacks fail."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def failing_primary():
            raise RuntimeError("Primary failed")
        
        def failing_fallback():
            raise RuntimeError("Fallback failed")
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="fallback_1",
            handler=failing_fallback,
            security_strength=SecurityStrength.CLASSIC_128
        ))
        
        with self.assertRaises(RuntimeError) as context:
            chain.execute()
        
        self.assertIn("All crypto fallback strategies failed", str(context.exception))
        self.assertEqual(chain.failed_fallbacks, 1)
    
    def test_crypto_degradation_level_escalation(self):
        """Test degradation level escalates on crypto failures."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def failing_primary():
            raise RuntimeError("Primary failed")
        
        def failing_fallback():
            raise RuntimeError("Fallback failed")
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="fallback_1",
            handler=failing_fallback,
            security_strength=SecurityStrength.CLASSIC_128
        ))
        
        initial_level = chain._degradation_tracker.get_current_level()
        
        try:
            chain.execute()
        except RuntimeError:
            pass
        
        new_level = chain._degradation_tracker.get_current_level()
        self.assertNotEqual(initial_level, new_level)
    
    def test_crypto_statistics_collection(self):
        """Test crypto statistics are properly collected."""
        chain = CryptoStrategicFallbackChain("test_crypto_chain")
        
        def failing_primary():
            raise RuntimeError("Primary failed")
        
        def fallback_handler():
            return b"encrypted"
        
        chain.register_primary_operation(failing_primary)
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="fallback_1",
            handler=fallback_handler,
            security_strength=SecurityStrength.CLASSIC_256
        ))
        
        for _ in range(5):
            chain.execute()
        
        stats = chain.get_statistics()
        
        self.assertEqual(stats["fallback_activations"], 5)
        self.assertEqual(stats["successful_fallbacks"], 5)
        self.assertEqual(stats["total_crypto_operations"], 5)
        self.assertIn("security_downgrades", stats)
        self.assertIn("compliance_violations", stats)


class TestCryptoStrategicFallbackDecorator(unittest.TestCase):
    """Tests for @crypto_strategic_fallback decorator."""
    
    def test_crypto_decorator_happy_path(self):
        """Test decorator works on happy path."""
        chain = CryptoStrategicFallbackChain("decorator_test")
        
        @crypto_strategic_fallback(chain)
        def my_encrypt_function():
            return b"encrypted_result"
        
        result = my_encrypt_function()
        self.assertEqual(result, b"encrypted_result")


class TestCryptoThreadSafety(unittest.TestCase):
    """Tests for thread safety of crypto error resilience components."""
    
    def test_concurrent_crypto_chain_execution(self):
        """Test crypto chain works under concurrent execution."""
        chain = CryptoStrategicFallbackChain("concurrent_crypto_test")
        results = []
        errors = []
        
        def crypto_op():
            time.sleep(0.001)
            return b"encrypted"
        
        chain.register_primary_operation(crypto_op)
        
        def worker():
            try:
                result, _, _, _ = chain.execute()
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 20)


class TestCryptoDegradationLevelFiltering(unittest.TestCase):
    """Tests for degradation level-based crypto strategy filtering."""
    
    def test_crypto_strategy_filtered_by_degradation_level(self):
        """Test crypto strategies filtered by degradation level."""
        chain = CryptoStrategicFallbackChain("degradation_test")
        
        def failing_primary():
            raise RuntimeError("Primary failed")
        
        def pqc_fallback():
            return b"pqc_encrypted"
        
        def classic_fallback():
            return b"classic_encrypted"
        
        chain.register_primary_operation(failing_primary)
        
        # Strategy only for FULL_SECURITY
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="pqc_only",
            handler=pqc_fallback,
            priority=CryptoFallbackPriority.POST_QUANTUM_PRIMARY,
            security_strength=SecurityStrength.PQC_LEVEL_5,
            supported_degradation_levels=[CryptoDegradationLevel.FULL_SECURITY]
        ))
        
        # Strategy for lower levels
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="classic_only",
            handler=classic_fallback,
            priority=CryptoFallbackPriority.CLASSIC_CRYPTO_FALLBACK,
            security_strength=SecurityStrength.CLASSIC_256,
            supported_degradation_levels=[CryptoDegradationLevel.STANDARD_SECURITY]
        ))
        
        result, _, strategy, _ = chain.execute()
        self.assertEqual(strategy, "pqc_only")


class TestHardwareFailureDetection(unittest.TestCase):
    """Tests for hardware failure detection."""
    
    def test_hardware_failure_skips_strategy(self):
        """Test strategies with hardware failures are skipped."""
        chain = CryptoStrategicFallbackChain("hw_test")
        
        def failing_primary():
            raise RuntimeError("Primary hardware error")
        
        def hw_fallback():
            raise RuntimeError("HSM communication failed")
        
        def sw_fallback():
            return b"software_encrypted"
        
        chain.register_primary_operation(failing_primary)
        
        hw_strategy = CryptoFallbackStrategy(
            name="hsm_accelerated",
            handler=hw_fallback,
            priority=CryptoFallbackPriority.HARDWARE_ACCELERATED,
            security_strength=SecurityStrength.CLASSIC_256,
            requires_hardware=True
        )
        chain.add_fallback_strategy(hw_strategy)
        
        chain.add_fallback_strategy(CryptoFallbackStrategy(
            name="software_fallback",
            handler=sw_fallback,
            priority=CryptoFallbackPriority.SOFTWARE_ONLY,
            security_strength=SecurityStrength.CLASSIC_128
        ))
        
        # Force hardware failures on HSM strategy
        hs = chain._health_scores["hsm_accelerated"]
        for _ in range(5):
            hs.record_failure(100.0, is_hardware_error=True)
        
        # Should skip hardware and use software fallback
        result, _, strategy, _ = chain.execute()
        self.assertEqual(strategy, "software_fallback")


if __name__ == "__main__":
    unittest.main()
