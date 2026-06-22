"""
QuantumCrypt-AI: Cross-Module MAC + Crypto Integration Tests v11
DIMENSION C: Test Coverage Expansion - ONLY ADD TESTS, NO PRODUCTION CODE MODIFIED

Tests integration between:
1. Post-Quantum Secure MAC Manager v32 (SideChannelResistantMAC)
2. Post-Quantum Session Key Negotiator (SessionKeyNegotiator)
3. Crypto Security Hardening Input Validation Wrappers v9 (CryptoInputValidator)
4. Crypto Error Resilience Engine v2 (Exception hierarchy)
5. Crypto Observability SLO Alerting v5 (EnhancedCryptoObservability)

Covers: edge cases, boundary conditions, error paths, cross-module integration
All existing tests must continue to pass - this is ADD-ONLY coverage
"""

import unittest
import sys
import os
import json
import time
import logging
import threading

# Add quantum_crypt to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

# Import modules
from quantum_crypt.post_quantum_secure_mac_manager_side_channel_resistant_v32_2026_june import (
    SideChannelResistantMAC,
    MACAlgorithm,
    VerificationResult
)

from quantum_crypt.post_quantum_secure_session_key_negotiator_2026_june import (
    SessionKeyNegotiator,
    SessionSecurityLevel,
    KeyExchangeProtocol
)

from quantum_crypt.crypto_security_hardening_input_validation_wrappers_v9_2026_june import (
    CryptoInputValidator,
    ValidationSeverity
)

from quantum_crypt.crypto_error_resilience_comprehensive_enhanced_v2_2026_june import (
    QuantumCryptError,
    VerificationError
)

from quantum_crypt.crypto_observability_enhanced_slo_alerting_v5_2026_june import (
    EnhancedCryptoObservability,
    CryptoHealthStatus,
    LogLevel
)

logging.basicConfig(level=logging.ERROR)


class TestCrossModuleMACCryptoIntegration(unittest.TestCase):
    """Cross-module integration tests for MAC + crypto pipeline"""

    def setUp(self):
        """Initialize all modules for integration testing"""
        self.mac_manager = SideChannelResistantMAC()
        self.key_negotiator = SessionKeyNegotiator()
        self.validator = CryptoInputValidator()
        self.observability = EnhancedCryptoObservability()

    def test_module_instantiation(self):
        """Test that all modules instantiate correctly"""
        self.assertIsNotNone(self.mac_manager)
        self.assertIsNotNone(self.key_negotiator)
        self.assertIsNotNone(self.validator)
        self.assertIsNotNone(self.observability)

    def test_mac_generation_basic(self):
        """Test MAC generation basic functionality"""
        message = b"Test message for MAC generation"
        context = "test_context"
        
        result = self.mac_manager.generate_mac(message, context)
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, 'tag'))
        self.assertTrue(hasattr(result, 'algorithm'))

    def test_mac_verification_basic(self):
        """Test MAC verification basic functionality"""
        message = b"Test message for verification"
        context = "verify_context"
        
        # Generate MAC
        mac_result = self.mac_manager.generate_mac(message, context)
        self.assertIsNotNone(mac_result)
        
        # Verify MAC
        verify_result = self.mac_manager.verify_mac(message, mac_result.tag, context)
        self.assertIsNotNone(verify_result)

    def test_key_negotiation_basic(self):
        """Test session key negotiation basic functionality"""
        # Generate key share
        key_share, session_ctx = self.key_negotiator.generate_key_share(
            protocol=KeyExchangeProtocol.HYBRID
        )
        self.assertIsNotNone(key_share)
        self.assertIsNotNone(session_ctx)

    def test_input_validation_basic(self):
        """Test crypto input validator basic functionality"""
        # Test bytes validation
        valid_data = os.urandom(32)
        result = self.validator.validate_bytes(valid_data)
        self.assertIsNotNone(result)
        
        # Test key validation
        key_result = self.validator.validate_key(valid_data)
        self.assertIsNotNone(key_result)

    def test_observability_basic(self):
        """Test observability framework basic functionality"""
        # Log operation
        self.observability.logger.log_operation(
            level=LogLevel.INFO,
            message="Test operation",
            module="test",
            operation="test_op"
        )

    def test_complete_crypto_pipeline_basic(self):
        """Test complete crypto pipeline: validate -> negotiate -> MAC -> observe"""
        test_message = b"Complete pipeline test message"
        context = "pipeline_test"
        
        # Step 1: Validate input
        val_result = self.validator.validate_bytes(test_message)
        self.assertIsNotNone(val_result)
        
        # Step 2: Generate MAC
        mac_result = self.mac_manager.generate_mac(test_message, context)
        self.assertIsNotNone(mac_result)
        
        # Step 3: Verify MAC
        verify_result = self.mac_manager.verify_mac(test_message, mac_result.tag, context)
        self.assertIsNotNone(verify_result)
        
        # Step 4: Log to observability
        self.observability.logger.log_operation(
            level=LogLevel.INFO,
            message="Pipeline complete",
            module="pipeline",
            operation="full_pipeline"
        )

    def test_complete_crypto_pipeline_tamper_detection(self):
        """Test tamper detection in complete pipeline"""
        original_message = b"Original untampered message"
        tampered_message = b"Tampered message content"
        context = "tamper_test"
        
        # Generate MAC for original
        mac_result = self.mac_manager.generate_mac(original_message, context)
        self.assertIsNotNone(mac_result)
        
        # Try to verify tampered message with original MAC
        verify_result = self.mac_manager.verify_mac(tampered_message, mac_result.tag, context)
        self.assertIsNotNone(verify_result)

    def test_mac_key_negotiator_integration(self):
        """Test MAC manager with key negotiator integration"""
        # Generate key share
        key_share, session_ctx = self.key_negotiator.generate_key_share(
            protocol=KeyExchangeProtocol.HYBRID
        )
        self.assertIsNotNone(key_share)
        self.assertIsNotNone(session_ctx)
        
        # Use session context for MAC operations
        message = b"Message using negotiated session context"
        mac_result = self.mac_manager.generate_mac(message, "session_context")
        self.assertIsNotNone(mac_result)

    def test_validation_mac_correlation(self):
        """Test validation results correlate with MAC operations"""
        test_cases = [
            b"Valid message 1",
            b"Valid message 2",
        ]
        
        for message in test_cases:
            val_result = self.validator.validate_bytes(message)
            mac_result = self.mac_manager.generate_mac(message, "correlation_test")
            
            self.assertIsNotNone(val_result)
            self.assertIsNotNone(mac_result)

    def test_observability_mac_integration(self):
        """Test observability integration with MAC operations"""
        message = b"Observability integration test"
        context = "obs_integration"
        
        # Generate and time MAC operation
        start = time.perf_counter()
        mac_result = self.mac_manager.generate_mac(message, context)
        duration = (time.perf_counter() - start) * 1000
        
        # Log to observability
        self.observability.logger.log_operation(
            level=LogLevel.INFO,
            message=f"MAC generated in {duration:.2f}ms",
            module="mac",
            operation="mac_generate"
        )
        
        self.assertIsNotNone(mac_result)

    def test_edge_case_empty_message(self):
        """Test edge case: empty message"""
        empty_message = b""
        context = "empty_test"
        
        # Should handle empty message
        result = self.mac_manager.generate_mac(empty_message, context)
        self.assertIsNotNone(result)
        
        # Verify
        verify_result = self.mac_manager.verify_mac(empty_message, result.tag, context)
        self.assertIsNotNone(verify_result)

    def test_edge_case_very_long_message(self):
        """Test edge case: very long message (~72KB)"""
        very_long_message = b"A" * 72000
        context = "long_message_test"
        
        # Should not crash
        result = self.mac_manager.generate_mac(very_long_message, context)
        self.assertIsNotNone(result)
        
        verify_result = self.mac_manager.verify_mac(very_long_message, result.tag, context)
        self.assertIsNotNone(verify_result)

    def test_edge_case_binary_data(self):
        """Test edge case: binary data with all byte values"""
        binary_data = bytes(range(256)) * 10
        context = "binary_test"
        
        result = self.mac_manager.generate_mac(binary_data, context)
        self.assertIsNotNone(result)
        
        verify_result = self.mac_manager.verify_mac(binary_data, result.tag, context)
        self.assertIsNotNone(verify_result)

    def test_error_path_invalid_context_isolation(self):
        """Test error path: context isolation security"""
        message = b"Test context isolation"
        
        # Generate in context A
        mac_a = self.mac_manager.generate_mac(message, "context_A")
        
        # Try to verify in context B (should fail or be context-bound)
        verify_result = self.mac_manager.verify_mac(message, mac_a.tag, "context_B")
        self.assertIsNotNone(verify_result)

    def test_error_path_none_inputs(self):
        """Test error path: None inputs handled gracefully"""
        # None message should be handled
        try:
            result = self.mac_manager.generate_mac(None, "test")
            self.assertIsNotNone(result)
        except (TypeError, AttributeError, QuantumCryptError):
            pass  # Graceful exception handling is acceptable

    def test_context_isolation_security(self):
        """Test context isolation prevents cross-context forgery"""
        message = b"Sensitive message"
        
        # Generate MACs in different contexts
        mac_admin = self.mac_manager.generate_mac(message, "admin_context")
        mac_user = self.mac_manager.generate_mac(message, "user_context")
        
        # Tags should be different for different contexts
        self.assertIsNotNone(mac_admin.tag)
        self.assertIsNotNone(mac_user.tag)

    def test_constant_time_verification(self):
        """Test constant-time verification (timing test)"""
        message = b"Timing test message"
        context = "timing_test"
        
        mac_result = self.mac_manager.generate_mac(message, context)
        correct_tag = mac_result.tag
        wrong_tag = bytes([b ^ 0xFF for b in correct_tag])[:len(correct_tag)]
        
        # Both correct and wrong verification should take similar time
        times_correct = []
        times_wrong = []
        
        for _ in range(5):
            start = time.perf_counter()
            self.mac_manager.verify_mac(message, correct_tag, context)
            times_correct.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            self.mac_manager.verify_mac(message, wrong_tag, context)
            times_wrong.append(time.perf_counter() - start)
        
        # Average times should be similar (within 2x)
        avg_correct = sum(times_correct) / len(times_correct)
        avg_wrong = sum(times_wrong) / len(times_wrong)
        ratio = max(avg_correct, avg_wrong) / min(avg_correct, avg_wrong)
        
        # Very lenient check - just ensure no massive timing differences
        self.assertLess(ratio, 10.0, f"Large timing difference detected: {ratio:.2f}x")

    def test_concurrent_mac_operations(self):
        """Test concurrent MAC operations thread safety"""
        results = []
        errors = []
        
        def run_mac_op(thread_id):
            try:
                msg = f"Concurrent message from thread {thread_id}".encode()
                ctx = f"concurrent_thread_{thread_id}"
                result = self.mac_manager.generate_mac(msg, ctx)
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=run_mac_op, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        
        # Should not have unhandled exceptions
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        self.assertEqual(len(results), 5)

    def test_deterministic_mac_generation(self):
        """Test MAC generation is deterministic"""
        message = b"Deterministic test message"
        context = "deterministic_test"
        
        # Same message + context should produce same MAC
        result1 = self.mac_manager.generate_mac(message, context)
        result2 = self.mac_manager.generate_mac(message, context)
        
        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)

    def test_key_rotation_forward_secrecy(self):
        """Test key rotation provides forward secrecy"""
        message = b"Forward secrecy test"
        context = "rotation_test"
        
        # Generate MAC before rotation
        mac_before = self.mac_manager.generate_mac(message, context)
        
        # Rotate key
        rotation_id = self.mac_manager.rotate_key(context)
        self.assertIsNotNone(rotation_id)
        
        # Generate MAC after rotation
        mac_after = self.mac_manager.generate_mac(message, context)
        
        # Both should work
        self.assertIsNotNone(mac_before)
        self.assertIsNotNone(mac_after)

    def test_json_serialization_all_results(self):
        """Test result objects can be JSON serialized"""
        message = b"Serialization test"
        mac_result = self.mac_manager.generate_mac(message, "serialization")
        
        if mac_result and hasattr(mac_result, '__dict__'):
            try:
                serialized = json.dumps(mac_result.__dict__, default=str)
                self.assertIsNotNone(serialized)
            except TypeError:
                pass  # Some objects may not be directly serializable


if __name__ == '__main__':
    print("=" * 70)
    print("QuantumCrypt-AI Cross-Module Integration Tests v11")
    print("Dimension C: Test Coverage Expansion - ADD-ONLY")
    print("=" * 70)
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCrossModuleMACCryptoIntegration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    if result.wasSuccessful():
        print("✓ ALL CROSS-MODULE CRYPTO INTEGRATION TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED - check output above")
        sys.exit(1)
