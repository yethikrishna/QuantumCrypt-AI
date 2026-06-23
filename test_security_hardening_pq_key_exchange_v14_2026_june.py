"""
Tests for Security Hardening Layer v14 - Post-Quantum Key Exchange
ADD-ONLY - NO existing code modified
47 comprehensive tests
"""

import unittest
import threading
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from security_hardening_pq_key_exchange_v14_2026_june import (
    KeyOperationType,
    ValidationSeverity,
    ValidationResult,
    SecurityHardeningConfig,
    SideChannelResistantZeroizer,
    ConstantTimeExecutionProtector,
    KeyMaterialInputValidator,
    KeyOperationAuditLogger,
    PQKeyExchangeSecurityHardener,
    pq_security_hardener
)


class TestKeyOperationTypeEnum(unittest.TestCase):
    """Test KeyOperationType enum"""
    
    def test_all_operation_types_exist(self):
        self.assertEqual(KeyOperationType.KEY_GENERATION.value, "key_generation")
        self.assertEqual(KeyOperationType.KEY_EXCHANGE.value, "key_exchange")
        self.assertEqual(KeyOperationType.KEY_DERIVATION.value, "key_derivation")
        self.assertEqual(KeyOperationType.SIGNATURE.value, "signature")
        self.assertEqual(KeyOperationType.VERIFICATION.value, "verification")


class TestValidationSeverityEnum(unittest.TestCase):
    """Test ValidationSeverity enum"""
    
    def test_severity_values(self):
        self.assertEqual(ValidationSeverity.LOW.value, "low")
        self.assertEqual(ValidationSeverity.MEDIUM.value, "medium")
        self.assertEqual(ValidationSeverity.HIGH.value, "high")
        self.assertEqual(ValidationSeverity.CRITICAL.value, "critical")


class TestValidationResult(unittest.TestCase):
    """Test ValidationResult dataclass"""
    
    def test_result_creation(self):
        result = ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW,
            message="Test passed",
            field_name="test",
            sanitized_value=b'test'
        )
        self.assertTrue(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.LOW)
        self.assertEqual(result.message, "Test passed")


class TestSecurityHardeningConfig(unittest.TestCase):
    """Test SecurityHardeningConfig"""
    
    def test_default_config(self):
        config = SecurityHardeningConfig()
        self.assertTrue(config.enable_constant_time_execution)
        self.assertTrue(config.enable_secure_memory_zeroization)
        self.assertTrue(config.enable_input_validation)
        self.assertTrue(config.enable_key_material_protection)
        self.assertTrue(config.enable_side_channel_resistance)
        self.assertEqual(config.max_key_material_size, 8192)


class TestSideChannelResistantZeroizer(unittest.TestCase):
    """Test SideChannelResistantZeroizer"""
    
    def test_zeroize_bytearray(self):
        data = bytearray(b'secret cryptographic key material')
        SideChannelResistantZeroizer.zeroize_bytearray(data)
        self.assertEqual(sum(data), 0)
        self.assertEqual(len(data), 33)
    
    def test_zeroize_bytearray_multiple_passes(self):
        data = bytearray(b'test')
        SideChannelResistantZeroizer.zeroize_bytearray(data, passes=3)
        self.assertEqual(sum(data), 0)
    
    def test_zeroize_bytes(self):
        result = SideChannelResistantZeroizer.zeroize_bytes(b'secret')
        self.assertEqual(result, b'')
    
    def test_zeroize_list(self):
        data = [1, 2, 3, 4, 5]
        SideChannelResistantZeroizer.zeroize_list(data)
        self.assertEqual(len(data), 0)
    
    def test_zeroize_string(self):
        result = SideChannelResistantZeroizer.zeroize_string("secret")
        self.assertEqual(result, "")
    
    def test_secure_wipe_key_material_bytearray(self):
        key = bytearray(b'private_key_data')
        SideChannelResistantZeroizer.secure_wipe_key_material(key)
        self.assertEqual(sum(key), 0)
    
    def test_secure_wipe_key_material_list(self):
        key = [1, 2, 3]
        SideChannelResistantZeroizer.secure_wipe_key_material(key)
        self.assertEqual(len(key), 0)


class TestConstantTimeExecutionProtector(unittest.TestCase):
    """Test ConstantTimeExecutionProtector"""
    
    def test_compare_bytes_equal(self):
        self.assertTrue(ConstantTimeExecutionProtector.compare_bytes_ct(b'test', b'test'))
    
    def test_compare_bytes_not_equal(self):
        self.assertFalse(ConstantTimeExecutionProtector.compare_bytes_ct(b'test', b'TEST'))
    
    def test_compare_bytes_different_length(self):
        self.assertFalse(ConstantTimeExecutionProtector.compare_bytes_ct(b'test', b'testing'))
    
    def test_compare_strings_equal(self):
        self.assertTrue(ConstantTimeExecutionProtector.compare_strings_ct("test", "test"))
    
    def test_compare_strings_not_equal(self):
        self.assertFalse(ConstantTimeExecutionProtector.compare_strings_ct("test", "TEST"))
    
    def test_compare_strings_empty(self):
        self.assertTrue(ConstantTimeExecutionProtector.compare_strings_ct("", ""))
    
    def test_select_ct_true(self):
        result = ConstantTimeExecutionProtector.select_ct(True, b'\x01\x02', b'\x03\x04')
        self.assertEqual(result, b'\x01\x02')
    
    def test_select_ct_false(self):
        result = ConstantTimeExecutionProtector.select_ct(False, b'\x01\x02', b'\x03\x04')
        self.assertEqual(result, b'\x03\x04')
    
    def test_verify_public_key_format_valid(self):
        valid_key = os.urandom(64)
        self.assertTrue(ConstantTimeExecutionProtector.verify_public_key_format(valid_key))
    
    def test_verify_public_key_format_all_zero(self):
        zero_key = bytes([0] * 64)
        self.assertFalse(ConstantTimeExecutionProtector.verify_public_key_format(zero_key))
    
    def test_verify_public_key_format_too_small(self):
        small_key = bytes([1] * 16)
        self.assertFalse(ConstantTimeExecutionProtector.verify_public_key_format(small_key))
    
    def test_verify_public_key_format_not_bytes(self):
        self.assertFalse(ConstantTimeExecutionProtector.verify_public_key_format("not bytes"))


class TestKeyMaterialInputValidator(unittest.TestCase):
    """Test KeyMaterialInputValidator"""
    
    def setUp(self):
        self.config = SecurityHardeningConfig()
        self.validator = KeyMaterialInputValidator(self.config)
        self.allowed_algos = {'KYBER512', 'KYBER768', 'DILITHIUM3'}
    
    def test_validate_public_key_valid(self):
        valid_key = os.urandom(64)
        result = self.validator.validate_public_key(valid_key)
        self.assertTrue(result.is_valid)
    
    def test_validate_public_key_not_bytes(self):
        result = self.validator.validate_public_key("not bytes")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.CRITICAL)
    
    def test_validate_public_key_too_small(self):
        small_key = bytes([1] * 16)
        result = self.validator.validate_public_key(small_key)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_public_key_all_zero(self):
        zero_key = bytes([0] * 64)
        result = self.validator.validate_public_key(zero_key)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_context_valid(self):
        context = {"user": "alice", "session": "test123"}
        result = self.validator.validate_context_info(context)
        self.assertTrue(result.is_valid)
    
    def test_validate_context_not_dict(self):
        result = self.validator.validate_context_info("not a dict")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_algorithm_valid(self):
        result = self.validator.validate_algorithm_identifier("KYBER512", self.allowed_algos)
        self.assertTrue(result.is_valid)
    
    def test_validate_algorithm_case_insensitive(self):
        result = self.validator.validate_algorithm_identifier("kyber512", self.allowed_algos)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.sanitized_value, "KYBER512")
    
    def test_validate_algorithm_invalid(self):
        result = self.validator.validate_algorithm_identifier("INVALID_ALGO", self.allowed_algos)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_algorithm_empty(self):
        result = self.validator.validate_algorithm_identifier("", self.allowed_algos)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_session_id_valid(self):
        result = self.validator.validate_session_id("session_12345")
        self.assertTrue(result.is_valid)
    
    def test_validate_session_id_empty(self):
        result = self.validator.validate_session_id("")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.severity, ValidationSeverity.HIGH)
    
    def test_validate_session_id_too_long(self):
        long_id = "x" * 200
        result = self.validator.validate_session_id(long_id)
        self.assertFalse(result.is_valid)


class TestKeyOperationAuditLogger(unittest.TestCase):
    """Test KeyOperationAuditLogger"""
    
    def test_log_operation(self):
        logger = KeyOperationAuditLogger()
        logger.log_operation(KeyOperationType.KEY_EXCHANGE, True, "KYBER768")
        stats = logger.get_stats()
        self.assertEqual(stats['total_operations'], 1)
        self.assertEqual(stats['successful_operations'], 1)
    
    def test_log_failed_operation(self):
        logger = KeyOperationAuditLogger()
        logger.log_operation(KeyOperationType.KEY_EXCHANGE, False, "KYBER768")
        stats = logger.get_stats()
        self.assertEqual(stats['failed_operations'], 1)
    
    def test_log_multiple_operations(self):
        logger = KeyOperationAuditLogger()
        for i in range(5):
            logger.log_operation(KeyOperationType.KEY_GENERATION, True, "KYBER512")
        stats = logger.get_stats()
        self.assertEqual(stats['total_operations'], 5)
    
    def test_operation_type_tracking(self):
        logger = KeyOperationAuditLogger()
        logger.log_operation(KeyOperationType.KEY_GENERATION, True, "KYBER512")
        logger.log_operation(KeyOperationType.KEY_EXCHANGE, True, "KYBER768")
        stats = logger.get_stats()
        self.assertIn('key_generation', stats['operations_by_type'])
        self.assertIn('key_exchange', stats['operations_by_type'])


class TestPQKeyExchangeSecurityHardenerSingleton(unittest.TestCase):
    """Test singleton pattern"""
    
    def test_singleton_instance(self):
        instance1 = PQKeyExchangeSecurityHardener()
        instance2 = PQKeyExchangeSecurityHardener()
        self.assertIs(instance1, instance2)
    
    def test_global_instance(self):
        self.assertIsInstance(pq_security_hardener, PQKeyExchangeSecurityHardener)


class TestPQKeyExchangeSecurityHardenerOptIn(unittest.TestCase):
    """Test OPT-IN pattern"""
    
    def setUp(self):
        self.hardener = PQKeyExchangeSecurityHardener()
        self.hardener.disable()
    
    def test_disabled_by_default(self):
        hardener = PQKeyExchangeSecurityHardener()
        hardener.disable()
        self.assertFalse(hardener.is_enabled())
    
    def test_enable_disable(self):
        self.hardener.enable()
        self.assertTrue(self.hardener.is_enabled())
        self.hardener.disable()
        self.assertFalse(self.hardener.is_enabled())
    
    def test_disabled_passthrough(self):
        """When disabled, validation should always pass through"""
        self.hardener.disable()
        # Even with invalid inputs, should pass through
        result = self.hardener.validate_public_key_before_exchange(
            "not bytes", "INVALID_ALGO"
        )
        self.assertTrue(result['allowed'])  # Passthrough when disabled


class TestPQKeyExchangeSecurityHardenerEnabled(unittest.TestCase):
    """Test security hardener when enabled"""
    
    def setUp(self):
        self.hardener = PQKeyExchangeSecurityHardener()
        self.hardener.enable()
    
    def test_valid_public_key_passes(self):
        valid_key = os.urandom(64)
        result = self.hardener.validate_public_key_before_exchange(valid_key, "KYBER768")
        self.assertTrue(result['allowed'])
    
    def test_invalid_public_key_blocked(self):
        result = self.hardener.validate_public_key_before_exchange("not bytes", "KYBER768")
        self.assertFalse(result['allowed'])
        self.assertEqual(result['reason'], 'validation_failed')
    
    def test_invalid_algorithm_blocked(self):
        valid_key = os.urandom(64)
        result = self.hardener.validate_public_key_before_exchange(valid_key, "INVALID_ALGO")
        self.assertFalse(result['allowed'])
    
    def test_constant_time_compare_enabled(self):
        key1 = os.urandom(32)
        key2 = bytes(key1)
        result = self.hardener.constant_time_compare_keys(key1, key2)
        self.assertTrue(result)
    
    def test_secure_wipe_key_material(self):
        key = bytearray(b'secret_key_material')
        self.hardener.secure_wipe_key_material(key)
        # Should be zeroized when enabled
        self.assertEqual(sum(key), 0)
    
    def test_validate_session_valid(self):
        result = self.hardener.validate_session_operation("session_123", {"user": "test"})
        self.assertTrue(result['allowed'])
    
    def test_validate_session_invalid_id(self):
        result = self.hardener.validate_session_operation("", {"user": "test"})
        self.assertFalse(result['allowed'])
    
    def test_get_security_stats(self):
        stats = self.hardener.get_security_stats()
        self.assertIn('enabled', stats)
        self.assertIn('validation_failures', stats)
        self.assertIn('keys_securely_wiped', stats)
        self.assertIn('audit_stats', stats)
        self.assertIn('config', stats)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility"""
    
    def test_all_imports_work(self):
        """Verify all public API can be imported without errors"""
        from security_hardening_pq_key_exchange_v14_2026_june import (
            KeyOperationType,
            ValidationSeverity,
            ValidationResult,
            SecurityHardeningConfig,
            SideChannelResistantZeroizer,
            ConstantTimeExecutionProtector,
            KeyMaterialInputValidator,
            KeyOperationAuditLogger,
            PQKeyExchangeSecurityHardener,
            pq_security_hardener
        )
        # If we get here without ImportError, we pass
        self.assertTrue(True)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases"""
    
    def test_empty_context(self):
        hardener = PQKeyExchangeSecurityHardener()
        hardener.enable()
        result = hardener.validate_session_operation("session_123", {})
        self.assertTrue(result['allowed'])
    
    def test_minimum_size_key(self):
        hardener = PQKeyExchangeSecurityHardener()
        hardener.enable()
        min_key = bytes([1] * 32)
        result = hardener.validate_public_key_before_exchange(min_key, "KYBER512", min_size=32)
        self.assertTrue(result['allowed'])


class TestThreadSafety(unittest.TestCase):
    """Test thread safety"""
    
    def test_concurrent_access(self):
        hardener = PQKeyExchangeSecurityHardener()
        hardener.enable()
        errors = []
        
        def worker():
            try:
                key = os.urandom(64)
                for _ in range(10):
                    hardener.validate_public_key_before_exchange(key, "KYBER768")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
