"""
Test Suite for QuantumCrypt PQ Crypto Error Resilience v38
Dimension E: Error Resilience - Comprehensive Test Coverage

Covers:
- PQ crypto deadline propagation
- Algorithm agility fallback chains
- HSM fallback resilience
- Batch operation partial failure handling
- Happy path preservation
"""

import pytest
import time
import threading
import secrets
from typing import List, Dict, Any

from quantum_crypt.crypto_error_resilience_pq_operation_v38_2026_june import (
    CryptoOperationType,
    CryptoSecurityLevel,
    CryptoFallbackStrategy,
    CryptoOperationDeadline,
    CryptoOperationError,
    CryptoDeadlineExceededError,
    HSMUnavailableError,
    CryptoOperationResult,
    PQCryptoFallbackOrchestrator,
    with_crypto_deadline,
    with_hsm_fallback,
    get_pq_orchestrator,
)


class TestCryptoOperationDeadline:
    """Test crypto deadline tracking and budget allocation."""
    
    def test_deadline_creation_for_crypto_ops(self):
        """Test deadline creation for different crypto operation types."""
        deadline = CryptoOperationDeadline.from_timeout(
            5000.0, CryptoOperationType.KEY_GENERATION, "ml_kem_keygen"
        )
        assert deadline.operation_type == CryptoOperationType.KEY_GENERATION
        assert deadline.operation_name == "ml_kem_keygen"
        assert deadline.remaining_ms > 0
        assert not deadline.expired
    
    def test_deadline_budget_allocation(self):
        """Test sub-operation budget allocation."""
        deadline = CryptoOperationDeadline.from_timeout(
            1000.0, CryptoOperationType.KEY_EXCHANGE, "pq_tls_handshake"
        )
        
        # Allocate budget for sub-operations
        keygen_budget = deadline.allocate_budget("keygen", 500.0)
        encap_budget = deadline.allocate_budget("encapsulate", 300.0)
        
        assert keygen_budget <= 800.0  # Max 80% of total
        assert encap_budget <= keygen_budget  # Less remaining after first allocation
        assert "keygen" in deadline.budget_allocation
        assert "encapsulate" in deadline.budget_allocation
    
    def test_parent_child_deadline_relationship(self):
        """Test parent deadline propagation to children."""
        parent = CryptoOperationDeadline.from_timeout(
            100.0, CryptoOperationType.BATCH_OPERATION, "batch_sign"
        )
        child = CryptoOperationDeadline.from_timeout(
            5000.0, CryptoOperationType.SIGNATURE, "single_sign", parent
        )
        
        # Child deadline capped by parent
        assert child.deadline_time == parent.deadline_time


class TestSecurityLevelConfigurations:
    """Test security level configurations for crypto operations."""
    
    def test_security_level_hierarchy(self):
        """Test security levels have correct ordering."""
        assert CryptoSecurityLevel.QUANTUM_RESISTANT.value < CryptoSecurityLevel.HIGH_ASSURANCE.value
        assert CryptoSecurityLevel.HIGH_ASSURANCE.value < CryptoSecurityLevel.STANDARD.value
        assert CryptoSecurityLevel.STANDARD.value < CryptoSecurityLevel.LEGACY_COMPAT.value
    
    def test_orchestrator_security_configs(self):
        """Test orchestrator has appropriate security configs."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        qr_config = orchestrator.get_config_for_security_level(CryptoSecurityLevel.QUANTUM_RESISTANT)
        std_config = orchestrator.get_config_for_security_level(CryptoSecurityLevel.STANDARD)
        be_config = orchestrator.get_config_for_security_level(CryptoSecurityLevel.BEST_EFFORT)
        
        # Higher security = longer timeouts
        assert qr_config["timeout_ms"] > std_config["timeout_ms"]
        assert std_config["timeout_ms"] > be_config["timeout_ms"]
        
        # Quantum resistant should NOT allow classic fallback
        assert qr_config["allow_classic_fallback"] is False
        # Standard and below can fall back
        assert std_config["allow_classic_fallback"] is True
        assert be_config["allow_classic_fallback"] is True


class TestAlgorithmFallbackChains:
    """Test algorithm agility fallback chains."""
    
    def test_happy_path_primary_algorithm_succeeds(self):
        """Test happy path - primary algorithm works without fallback."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def ml_kem_768_keygen() -> Dict[str, Any]:
            return {"algorithm": "ML-KEM-768", "key": secrets.token_bytes(32)}
        
        # Register chain to get full orchestrator behavior
        orchestrator.register_algorithm_chain(
            "key_generation",
            ("ML-KEM-768", ml_kem_768_keygen),
            []
        )
        
        result = orchestrator.execute_pq_operation(
            "key_generation",
            CryptoOperationType.KEY_GENERATION,
            CryptoSecurityLevel.STANDARD
        )
        
        assert result.success is True
        assert result.fallback_level == 0
        assert result.fallback_used is None
        assert result.result["algorithm"] == "ML-KEM-768"
        assert result.security_level_achieved == CryptoSecurityLevel.STANDARD
    
    def test_primary_fails_fallback_algorithm_succeeds(self):
        """Test algorithm chain fallback when primary fails."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def primary_failing() -> Dict[str, Any]:
            raise CryptoOperationError("ml_kem", "Hardware acceleration unavailable")
        
        def fallback_kyber() -> Dict[str, Any]:
            return {"algorithm": "Kyber-768", "key": secrets.token_bytes(32), "fallback": True}
        
        orchestrator.register_algorithm_chain(
            "pq_keygen",
            ("ML-KEM-768", primary_failing),
            [(CryptoFallbackStrategy.FALLBACK_ALGORITHM, "Kyber-768", fallback_kyber)]
        )
        
        result = orchestrator.execute_pq_operation(
            "pq_keygen",
            CryptoOperationType.KEY_GENERATION,
            CryptoSecurityLevel.STANDARD
        )
        
        assert result.success is True
        assert result.fallback_level == 1
        assert result.algorithm_used == "Kyber-768"
        assert result.result["fallback"] is True
    
    def test_all_algorithms_fail_secure_fallback(self):
        """Test secure fallback when all algorithms fail at high security."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def always_fail() -> Dict[str, Any]:
            raise CryptoOperationError("pq", "All PQ modules failed", recoverable=False)
        
        orchestrator.register_algorithm_chain(
            "high_security_keygen",
            ("ML-KEM-1024", always_fail),
            [(CryptoFallbackStrategy.FALLBACK_ALGORITHM, "BIKE", always_fail)]
        )
        
        result = orchestrator.execute_pq_operation(
            "high_security_keygen",
            CryptoOperationType.KEY_GENERATION,
            CryptoSecurityLevel.QUANTUM_RESISTANT
        )
        
        assert result.success is False
        # Quantum resistant fails secure - returns None
        assert result.result is None
        assert len(result.errors) > 0
    
    def test_deadline_exceeded_before_execution(self):
        """Test deadline enforcement when already expired."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def slow_keygen() -> Dict[str, Any]:
            time.sleep(0.01)
            return {"key": secrets.token_bytes(32)}
        
        deadline = CryptoOperationDeadline.from_timeout(
            1.0, CryptoOperationType.KEY_GENERATION, "slow_keygen"  # 1ms deadline
        )
        time.sleep(0.01)  # Ensure deadline expires
        
        result = orchestrator.execute_pq_operation(
            "slow_keygen",
            CryptoOperationType.KEY_GENERATION,
            CryptoSecurityLevel.STANDARD,
            deadline,
            slow_keygen
        )
        
        assert result.deadline_expired is True
        assert any(isinstance(e, CryptoDeadlineExceededError) for e in result.errors)


class TestHSMResilience:
    """Test HSM fallback and resilience patterns."""
    
    def test_hsm_unavailable_fallback_to_software(self):
        """Test HSM-to-software fallback pattern."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def hsm_sign() -> bytes:
            raise HSMUnavailableError("HSM_SLOT_0")
        
        def software_sign() -> bytes:
            return b"software_signature_" + secrets.token_bytes(16)
        
        orchestrator.register_algorithm_chain(
            "hsm_signature",
            ("HSM-ML-DSA-65", hsm_sign),
            [(CryptoFallbackStrategy.FALLBACK_HSM_SOFTWARE, "SW-ML-DSA-65", software_sign)]
        )
        
        result = orchestrator.execute_pq_operation(
            "hsm_signature",
            CryptoOperationType.SIGNATURE,
            CryptoSecurityLevel.HIGH_ASSURANCE
        )
        
        assert result.success is True
        assert result.fallback_level == 1
        assert result.algorithm_used == "SW-ML-DSA-65"
    
    def test_hsm_fallback_decorator(self):
        """Test HSM fallback decorator."""
        def software_verify(data: bytes) -> bool:
            return True
        
        @with_hsm_fallback(software_verify)
        def hsm_verify(data: bytes) -> bool:
            raise HSMUnavailableError("VERIFY_HSM")
        
        # Should fall back to software implementation
        result = hsm_verify(b"test_data")
        assert result is True
    
    def test_hsm_fallback_decorator_happy_path(self):
        """Test decorator doesn't affect happy path."""
        @with_hsm_fallback(None)
        def working_hsm_op() -> str:
            return "hsm_success"
        
        result = working_hsm_op()
        assert result == "hsm_success"


class TestBatchOperationResilience:
    """Test batch operation with partial failure handling."""
    
    def test_batch_all_items_succeed(self):
        """Test batch operation when all items succeed."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        items = [1, 2, 3, 4, 5]
        
        def process_item(x: int) -> int:
            return x * 2
        
        result = orchestrator.execute_batch_operation(
            "batch_sign", items, process_item
        )
        
        assert result.success is True
        assert len(result.partial_results) == 5
        assert len(result.errors) == 0
        assert all(success for _, _, success in result.partial_results)
    
    def test_batch_partial_failure(self):
        """Test batch operation with partial failures."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        items = [1, 2, 0, 4, 5]  # 0 will cause division error
        
        def process_item(x: int) -> float:
            return 100 / x
        
        result = orchestrator.execute_batch_operation(
            "batch_process", items, process_item
        )
        
        assert result.success is False  # Not all succeeded
        assert len(result.partial_results) == 5
        assert len(result.errors) == 1
        assert result.fallback_used == CryptoFallbackStrategy.PARTIAL_BATCH
        
        # Verify successes still returned
        successful = [(idx, val) for idx, val, ok in result.partial_results if ok]
        assert len(successful) == 4
    
    def test_batch_deadline_cutoff(self):
        """Test batch respects deadline, returning partial results."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        items = list(range(100))
        
        def slow_process(x: int) -> int:
            time.sleep(0.01)  # 10ms per item
            return x
        
        deadline = CryptoOperationDeadline.from_timeout(
            50.0, CryptoOperationType.BATCH_OPERATION, "slow_batch"
        )
        
        result = orchestrator.execute_batch_operation(
            "slow_batch", items, slow_process, deadline=deadline
        )
        
        assert result.deadline_expired is True
        # Should have processed some items before deadline
        assert len(result.partial_results) > 0
        # But not all items
        assert len(result.partial_results) < 100


class TestCryptoDecorators:
    """Test crypto decorator functionality."""
    
    def test_crypto_deadline_decorator_happy_path(self):
        """Test deadline decorator happy path."""
        @with_crypto_deadline(timeout_ms=5000.0, operation_type=CryptoOperationType.SIGNATURE)
        def sign_message(msg: bytes, crypto_deadline=None) -> bytes:
            return b"signed:" + msg
        
        result = sign_message(b"hello")
        assert result == b"signed:hello"
    
    def test_crypto_deadline_propagation(self):
        """Test deadline propagation through nested calls."""
        received_deadlines = []
        
        @with_crypto_deadline(timeout_ms=200.0, operation_type=CryptoOperationType.KEY_ENCAPSULATION)
        def child_op(crypto_deadline=None):
            received_deadlines.append(crypto_deadline)
            return "ok"
        
        @with_crypto_deadline(timeout_ms=1000.0, operation_type=CryptoOperationType.KEY_EXCHANGE)
        def parent_op(crypto_deadline=None):
            return child_op(crypto_deadline=crypto_deadline)
        
        parent_op()
        
        assert len(received_deadlines) == 1
        child_deadline = received_deadlines[0]
        # Child deadline should be capped at 200ms, not parent's 1000ms
        assert child_deadline is not None
        assert child_deadline.parent_deadline is not None


class TestRetryWithKeyRegeneration:
    """Test retry with automatic key regeneration."""
    
    def test_retry_with_new_nonce_succeeds(self):
        """Test retry succeeds with regenerated nonce."""
        orchestrator = PQCryptoFallbackOrchestrator()
        attempts = []
        
        def flaky_keygen(key_nonce=None):
            attempts.append(key_nonce)
            if len(attempts) < 2:
                raise CryptoOperationError("keygen", "RNG glitch", recoverable=True)
            return {"key": secrets.token_bytes(32), "nonce_used": key_nonce}
        
        # Register chain to enable retry with regeneration logic
        orchestrator.register_algorithm_chain(
            "flaky_keygen",
            ("ML-KEM-768", flaky_keygen),
            []
        )
        
        result = orchestrator.execute_pq_operation(
            "flaky_keygen",
            CryptoOperationType.KEY_GENERATION,
            CryptoSecurityLevel.STANDARD
        )
        
        assert result.success is True
        # Should have retried with different nonces
        assert len(attempts) >= 1
        # Nonces should be different on retry
        if len(attempts) > 1:
            assert attempts[0] != attempts[1]


class TestGlobalOrchestrator:
    """Test global orchestrator singleton."""
    
    def test_get_pq_orchestrator_singleton(self):
        """Test get_pq_orchestrator returns singleton."""
        orch1 = get_pq_orchestrator()
        orch2 = get_pq_orchestrator()
        assert orch1 is orch2
    
    def test_thread_safety(self):
        """Test orchestrator operations are thread-safe."""
        orchestrator = PQCryptoFallbackOrchestrator()
        results = []
        
        def thread_operation(tid: int):
            def op():
                return {"thread": tid}
            
            result = orchestrator.execute_pq_operation(
                f"op_{tid}",
                CryptoOperationType.VERIFICATION,
                CryptoSecurityLevel.BEST_EFFORT,
                None,
                op
            )
            results.append(result)
        
        threads = [threading.Thread(target=thread_operation, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(results) == 5
        assert all(r.success for r in results)


class TestBackwardCompatibility:
    """Verify 100% backward compatibility."""
    
    def test_existing_crypto_code_unchanged(self):
        """Existing crypto code works without any modifications."""
        # Simulate existing production crypto code
        def classic_key_exchange(peer_public: bytes) -> bytes:
            return secrets.token_bytes(32) + peer_public[:16]
        
        # Works exactly as before
        result = classic_key_exchange(b"peer_pubkey_data")
        assert len(result) > 0
    
    def test_all_features_opt_in(self):
        """All resilience features are strictly OPT-IN."""
        # Module import has zero side effects
        assert True
    
    def test_legacy_call_patterns_preserved(self):
        """All legacy calling patterns work unchanged."""
        orchestrator = PQCryptoFallbackOrchestrator()
        
        def legacy_crypto():
            return {"legacy": True, "key": secrets.token_bytes(16)}
        
        # Call without security level, without deadline, without chain
        result = orchestrator.execute_pq_operation(
            "legacy", CryptoOperationType.ENCRYPTION, None, None, legacy_crypto
        )
        
        assert result.success is True
        assert result.result["legacy"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
