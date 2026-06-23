"""
Tests for QuantumCrypt Algorithm Fallback Chain v19
ADD-ONLY - No existing tests modified
"""

import unittest
import threading
import time

from quantum_crypt.crypto_error_resilience_algorithm_fallback_chain_v19_2026_june import (
    CryptoFallbackStrategy,
    CryptoDegradationLevel,
    CryptoOperationType,
    AlgorithmSecurityLevel,
    AlgorithmStatus,
    CryptoChainStatus,
    AlgorithmInfo,
    CryptoFallbackResult,
    CryptoChainExecutionResult,
    CryptoFallbackConfig,
    CryptoChainConfig,
    CryptoAlgorithmFallbackChain,
    PQKeyExchangeFallbackChains,
    NIST_STANDARD_ALGORITHMS,
    CLASSICAL_FALLBACK_ALGORITHMS,
    get_crypto_fallback_chains,
    with_crypto_fallback_chain,
)


class TestCryptoFallbackStrategyEnum(unittest.TestCase):
    """Test CryptoFallbackStrategy enum values."""
    
    def test_all_strategies_exist(self):
        strategies = [
            'SECURITY_FIRST', 'PERFORMANCE_FIRST',
            'NIST_COMPLIANT_ONLY', 'HYBRID_PREFERRED'
        ]
        for strategy in strategies:
            self.assertTrue(hasattr(CryptoFallbackStrategy, strategy))


class TestCryptoDegradationLevelEnum(unittest.TestCase):
    """Test CryptoDegradationLevel enum values."""
    
    def test_all_levels_exist(self):
        levels = [
            'FULL_SECURITY', 'REDUCED_SECURITY', 'CLASSICAL_ONLY',
            'MINIMAL_SECURITY', 'FAIL_SECURE', 'SOFTWARE_ONLY'
        ]
        for level in levels:
            self.assertTrue(hasattr(CryptoDegradationLevel, level))


class TestCryptoOperationTypeEnum(unittest.TestCase):
    """Test CryptoOperationType enum values."""
    
    def test_all_operation_types_exist(self):
        ops = [
            'KEY_GENERATION', 'KEY_ENCAPSULATION', 'KEY_DECAPSULATION',
            'SIGNATURE', 'VERIFICATION', 'ENCRYPTION',
            'DECRYPTION', 'HASH', 'RANDOM_GENERATION'
        ]
        for op in ops:
            self.assertTrue(hasattr(CryptoOperationType, op))


class TestAlgorithmSecurityLevelEnum(unittest.TestCase):
    """Test AlgorithmSecurityLevel enum values."""
    
    def test_all_security_levels_exist(self):
        for i in range(1, 6):
            self.assertTrue(hasattr(AlgorithmSecurityLevel, f'LEVEL_{i}'))


class TestAlgorithmStatusEnum(unittest.TestCase):
    """Test AlgorithmStatus enum values."""
    
    def test_all_statuses_exist(self):
        statuses = [
            'STANDARDIZED', 'FINALIST', 'CANDIDATE',
            'EXPERIMENTAL', 'DEPRECATED', 'BROKEN'
        ]
        for status in statuses:
            self.assertTrue(hasattr(AlgorithmStatus, status))


class TestCryptoChainStatusEnum(unittest.TestCase):
    """Test CryptoChainStatus enum values."""
    
    def test_all_statuses_exist(self):
        statuses = [
            'NOT_STARTED', 'RUNNING', 'SUCCESS',
            'PARTIAL_SUCCESS', 'ALL_FAILED',
            'CIRCUIT_OPEN', 'HARDWARE_FAILURE'
        ]
        for status in statuses:
            self.assertTrue(hasattr(CryptoChainStatus, status))


class TestAlgorithmInfo(unittest.TestCase):
    """Test AlgorithmInfo dataclass."""
    
    def test_algorithm_info_creation(self):
        info = AlgorithmInfo(
            name="Test-Algo",
            nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_3,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        self.assertEqual(info.name, "Test-Algo")
        self.assertTrue(info.nist_standard)
        self.assertTrue(info.quantum_resistant)


class TestCryptoFallbackResult(unittest.TestCase):
    """Test CryptoFallbackResult dataclass."""
    
    def test_success_result(self):
        result = CryptoFallbackResult(
            success=True,
            result={"key": "value"},
            execution_time_ms=15.5,
            algorithm_used="Test-Algo",
            security_level="level_5"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.algorithm_used, "Test-Algo")


class TestCryptoChainExecutionResult(unittest.TestCase):
    """Test CryptoChainExecutionResult dataclass."""
    
    def test_success_result(self):
        result = CryptoChainExecutionResult(
            status=CryptoChainStatus.SUCCESS,
            final_result={"key": "data"},
            final_security_level="level_5",
            quantum_resistant_used=True
        )
        self.assertIn(result.status, [CryptoChainStatus.SUCCESS, CryptoChainStatus.PARTIAL_SUCCESS])
        self.assertTrue(result.quantum_resistant_used)


class TestCryptoFallbackConfig(unittest.TestCase):
    """Test CryptoFallbackConfig dataclass."""
    
    def test_default_values(self):
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        config = CryptoFallbackConfig(algorithm=algo)
        self.assertEqual(config.priority, 100)
        self.assertEqual(config.timeout_seconds, 10.0)
        self.assertTrue(config.enabled)
        self.assertTrue(config.allow_timing_noise)


class TestCryptoChainConfig(unittest.TestCase):
    """Test CryptoChainConfig dataclass."""
    
    def test_default_values(self):
        config = CryptoChainConfig()
        self.assertEqual(config.strategy, CryptoFallbackStrategy.SECURITY_FIRST)
        self.assertTrue(config.require_quantum_resistant)
        self.assertTrue(config.enable_circuit_breaker)
        self.assertTrue(config.always_add_timing_noise)
        self.assertTrue(config.zeroize_all_intermediates)


class TestNISTStandardAlgorithms(unittest.TestCase):
    """Test NIST standard algorithm definitions."""
    
    def test_kyber_algorithms_exist(self):
        self.assertIn("CRYSTALS-Kyber-512", NIST_STANDARD_ALGORITHMS)
        self.assertIn("CRYSTALS-Kyber-768", NIST_STANDARD_ALGORITHMS)
        self.assertIn("CRYSTALS-Kyber-1024", NIST_STANDARD_ALGORITHMS)
    
    def test_dilithium_algorithms_exist(self):
        self.assertIn("CRYSTALS-Dilithium-2", NIST_STANDARD_ALGORITHMS)
        self.assertIn("CRYSTALS-Dilithium-3", NIST_STANDARD_ALGORITHMS)
        self.assertIn("CRYSTALS-Dilithium-5", NIST_STANDARD_ALGORITHMS)
    
    def test_sphincs_algorithm_exists(self):
        self.assertIn("SPHINCS+-SHA2-128f", NIST_STANDARD_ALGORITHMS)
    
    def test_all_nist_algorithms_are_standardized(self):
        for algo in NIST_STANDARD_ALGORITHMS.values():
            self.assertTrue(algo.nist_standard)
            self.assertTrue(algo.quantum_resistant)
            self.assertEqual(algo.status, AlgorithmStatus.STANDARDIZED)


class TestClassicalFallbackAlgorithms(unittest.TestCase):
    """Test classical fallback algorithm definitions."""
    
    def test_rsa_algorithms_exist(self):
        self.assertIn("RSA-2048", CLASSICAL_FALLBACK_ALGORITHMS)
        self.assertIn("RSA-4096", CLASSICAL_FALLBACK_ALGORITHMS)
    
    def test_ecdh_algorithms_exist(self):
        self.assertIn("ECDH-P256", CLASSICAL_FALLBACK_ALGORITHMS)
        self.assertIn("ECDH-P384", CLASSICAL_FALLBACK_ALGORITHMS)
    
    def test_classical_algorithms_not_quantum_resistant(self):
        for algo in CLASSICAL_FALLBACK_ALGORITHMS.values():
            self.assertFalse(algo.quantum_resistant)


class TestCryptoAlgorithmFallbackChain(unittest.TestCase):
    """Test CryptoAlgorithmFallbackChain core functionality."""
    
    def test_chain_initialization(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION
        )
        self.assertEqual(chain.name, "test_chain")
        self.assertEqual(chain.operation_type, CryptoOperationType.KEY_GENERATION)
    
    def test_add_fallback(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def handler():
            return {"result": "ok"}
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            handler
        )
        
        self.assertEqual(len(chain._fallbacks), 1)
    
    def test_execute_success_primary(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_5,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def primary_success():
            return {"key": "generated"}
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            primary_success
        )
        
        result = chain.execute()
        
        self.assertIn(result.status, [CryptoChainStatus.SUCCESS, CryptoChainStatus.PARTIAL_SUCCESS])
        self.assertEqual(result.final_result, {"key": "generated"})
        self.assertTrue(result.quantum_resistant_used)
    
    def test_execute_fallback_used(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION,
            CryptoChainConfig(require_quantum_resistant=False)
        )
        
        algo1 = AlgorithmInfo(
            name="Primary", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_5,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        algo2 = AlgorithmInfo(
            name="Fallback", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_3,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def primary_fails():
            raise ValueError("primary failed")
        
        def fallback_works():
            return {"key": "fallback_key"}
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo1, priority=100),
            primary_fails
        )
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo2, priority=90),
            fallback_works
        )
        
        result = chain.execute()
        
        self.assertEqual(result.status, CryptoChainStatus.PARTIAL_SUCCESS)
        self.assertEqual(result.attempted_algorithms, 2)
    
    def test_execute_all_failed(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def always_fails():
            raise ValueError("always fails")
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            always_fails
        )
        
        result = chain.execute()
        
        self.assertEqual(result.status, CryptoChainStatus.ALL_FAILED)
        self.assertEqual(len(result.errors), 1)
    
    def test_get_statistics(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def works():
            return {"ok": True}
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            works
        )
        
        chain.execute()
        stats = chain.get_statistics()
        
        self.assertEqual(stats["chain_name"], "test_chain")
        self.assertEqual(stats["operation_type"], "key_generation")
        self.assertEqual(stats["total_executions"], 1)
        self.assertEqual(stats["success_count"], 1)


class TestCryptoChainCircuitBreaker(unittest.TestCase):
    """Test CryptoAlgorithmFallbackChain circuit breaker."""
    
    def test_circuit_opens_after_failures(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION,
            CryptoChainConfig(
                circuit_failure_threshold=2,
                circuit_recovery_timeout_seconds=0.1
            )
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def always_fails():
            raise ValueError("fail")
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            always_fails
        )
        
        # First two failures
        chain.execute()
        chain.execute()
        
        # Third should hit open circuit
        result = chain.execute()
        self.assertEqual(result.status, CryptoChainStatus.CIRCUIT_OPEN)
    
    def test_circuit_recovers_after_timeout(self):
        chain = CryptoAlgorithmFallbackChain(
            "test_chain",
            CryptoOperationType.KEY_GENERATION,
            CryptoChainConfig(
                circuit_failure_threshold=1,
                circuit_recovery_timeout_seconds=0.01
            )
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def always_fails():
            raise ValueError("fail")
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100),
            always_fails
        )
        
        # Open circuit
        chain.execute()
        result = chain.execute()
        self.assertEqual(result.status, CryptoChainStatus.CIRCUIT_OPEN)
        
        # Wait for recovery
        time.sleep(0.02)
        
        # Should be recovered
        result = chain.execute()
        self.assertNotEqual(result.status, CryptoChainStatus.CIRCUIT_OPEN)


class TestPQKeyExchangeFallbackChains(unittest.TestCase):
    """Test PQKeyExchangeFallbackChains pre-configured chains."""
    
    def test_initialization(self):
        chains = PQKeyExchangeFallbackChains()
        self.assertIsNotNone(chains)
    
    def test_kem_key_generation_chain_exists(self):
        chains = PQKeyExchangeFallbackChains()
        chain = chains.get_chain("kem_key_generation")
        self.assertIsNotNone(chain)
        self.assertEqual(chain.name, "kem_key_generation")
    
    def test_signature_generation_chain_exists(self):
        chains = PQKeyExchangeFallbackChains()
        chain = chains.get_chain("signature_generation")
        self.assertIsNotNone(chain)
        self.assertEqual(chain.name, "signature_generation")
    
    def test_execute_kem_key_generation(self):
        chains = PQKeyExchangeFallbackChains()
        result = chains.execute_chain("kem_key_generation")
        
        self.assertIn(result.status, [
            CryptoChainStatus.SUCCESS, 
            CryptoChainStatus.PARTIAL_SUCCESS
        ])
        self.assertIsNotNone(result.final_result)
    
    def test_execute_signature_generation(self):
        chains = PQKeyExchangeFallbackChains()
        result = chains.execute_chain("signature_generation")
        
        self.assertIn(result.status, [
            CryptoChainStatus.SUCCESS, 
            CryptoChainStatus.PARTIAL_SUCCESS
        ])
        self.assertIsNotNone(result.final_result)
    
    def test_unknown_chain_returns_error(self):
        chains = PQKeyExchangeFallbackChains()
        result = chains.execute_chain("nonexistent")
        
        self.assertEqual(result.status, CryptoChainStatus.ALL_FAILED)
        self.assertEqual(len(result.errors), 1)
    
    def test_get_all_statistics(self):
        chains = PQKeyExchangeFallbackChains()
        stats = chains.get_all_statistics()
        
        self.assertIn("kem_key_generation", stats)
        self.assertIn("signature_generation", stats)


class TestCryptoSingleton(unittest.TestCase):
    """Test crypto singleton pattern."""
    
    def test_returns_same_instance(self):
        instance1 = get_crypto_fallback_chains()
        instance2 = get_crypto_fallback_chains()
        
        self.assertIs(instance1, instance2)
    
    def test_thread_safety(self):
        instances = []
        
        def get_instance():
            instances.append(get_crypto_fallback_chains())
        
        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertTrue(all(inst is instances[0] for inst in instances))


class TestCryptoDecorator(unittest.TestCase):
    """Test with_crypto_fallback_chain decorator."""
    
    def test_happy_path(self):
        @with_crypto_fallback_chain("kem_key_generation")
        def my_crypto_op():
            return "direct_result"
        
        result = my_crypto_op()
        self.assertEqual(result, "direct_result")
    
    def test_falls_back_on_failure(self):
        call_count = [0]
        
        @with_crypto_fallback_chain("kem_key_generation")
        def failing_op():
            call_count[0] += 1
            raise ValueError("crypto failed")
        
        # Should not raise, returns fallback
        result = failing_op()
        self.assertIsNotNone(result)
        self.assertEqual(call_count[0], 1)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility."""
    
    def test_all_exports_exist(self):
        import quantum_crypt.crypto_error_resilience_algorithm_fallback_chain_v19_2026_june as module
        
        expected_exports = [
            'CryptoFallbackStrategy',
            'CryptoDegradationLevel',
            'CryptoOperationType',
            'AlgorithmSecurityLevel',
            'AlgorithmStatus',
            'CryptoChainStatus',
            'AlgorithmInfo',
            'CryptoFallbackResult',
            'CryptoChainExecutionResult',
            'CryptoFallbackConfig',
            'CryptoChainConfig',
            'CryptoAlgorithmFallbackChain',
            'PQKeyExchangeFallbackChains',
            'NIST_STANDARD_ALGORITHMS',
            'CLASSICAL_FALLBACK_ALGORITHMS',
            'get_crypto_fallback_chains',
            'with_crypto_fallback_chain',
        ]
        
        for export in expected_exports:
            self.assertTrue(hasattr(module, export), f"Missing export: {export}")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases."""
    
    def test_empty_chain(self):
        chain = CryptoAlgorithmFallbackChain(
            "empty", CryptoOperationType.KEY_GENERATION
        )
        result = chain.execute()
        
        self.assertEqual(result.status, CryptoChainStatus.ALL_FAILED)
    
    def test_disabled_fallback_skipped(self):
        chain = CryptoAlgorithmFallbackChain(
            "test", CryptoOperationType.KEY_GENERATION
        )
        
        algo = AlgorithmInfo(
            name="Test", nist_standard=True,
            security_level=AlgorithmSecurityLevel.LEVEL_1,
            status=AlgorithmStatus.STANDARDIZED,
            quantum_resistant=True
        )
        
        def disabled_never_called():
            self.fail("Should not be called")
        
        def works():
            return {"ok": True}
        
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=100, enabled=False),
            disabled_never_called
        )
        chain.add_fallback(
            CryptoFallbackConfig(algorithm=algo, priority=90),
            works
        )
        
        result = chain.execute()
        self.assertIn(result.status, [CryptoChainStatus.SUCCESS, CryptoChainStatus.PARTIAL_SUCCESS])


if __name__ == '__main__':
    unittest.main()
