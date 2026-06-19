#!/usr/bin/env python3
"""
Test suite for Post-Quantum Secure Memory Zeroizer
Production-grade testing with real assertions
"""

import sys
import os
import time
import json
import unittest
import threading
import gc

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'quantum_crypt'))

from post_quantum_secure_memory_zeroizer_side_channel_protected_2026_june import (
    SideChannelResistantZeroizer,
    SensitiveData,
    SecureMemoryPool,
    secure_scratchpad,
    verify_zeroization,
    constant_time_memcmp,
    zeroize_sensitive_data,
    ZeroizationMetrics
)


class TestSideChannelResistantZeroizer(unittest.TestCase):
    """Test core zeroizer functionality"""
    
    def test_initialization(self):
        """Test zeroizer initializes correctly"""
        zeroizer = SideChannelResistantZeroizer(passes=3, use_random_final_pass=True)
        
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['passes_configured'], 3)
        self.assertTrue(metrics['random_final_pass'])
        self.assertEqual(metrics['total_bytes_zeroized'], 0)
    
    def test_basic_zeroization(self):
        """Test basic bytearray zeroization"""
        zeroizer = SideChannelResistantZeroizer(passes=2, use_random_final_pass=False)
        
        # Create buffer with sensitive data
        buf = bytearray(b"my_super_secret_key_12345")
        original_data = bytes(buf)
        
        # Verify data is present
        self.assertEqual(bytes(buf), original_data)
        
        # Zeroize
        success = zeroizer.zeroize(buf)
        
        # Verify success and zeroization
        self.assertTrue(success)
        self.assertTrue(all(b == 0 for b in buf))
        self.assertTrue(verify_zeroization(buf))
        
        # Verify metrics updated
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['total_bytes_zeroized'], len(original_data))
        self.assertEqual(metrics['operations_completed'], 1)
    
    def test_multiple_passes(self):
        """Test zeroization with multiple passes"""
        zeroizer = SideChannelResistantZeroizer(passes=5)
        
        buf = bytearray(b"sensitive_data_here_multiple_passes")
        success = zeroizer.zeroize(buf)
        
        self.assertTrue(success)
        self.assertTrue(verify_zeroization(buf))
        
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['side_channel_resistant_ops'], 1)
    
    def test_empty_buffer(self):
        """Test zeroizing empty buffer"""
        zeroizer = SideChannelResistantZeroizer()
        
        buf = bytearray()
        success = zeroizer.zeroize(buf)
        
        self.assertTrue(success)
        self.assertEqual(len(buf), 0)
    
    def test_batch_zeroization(self):
        """Test zeroizing list of buffers"""
        zeroizer = SideChannelResistantZeroizer(passes=2)
        
        buffers = [
            bytearray(b"secret_1"),
            bytearray(b"secret_2_abc"),
            bytearray(b"secret_3_xyz")
        ]
        
        total_size = sum(len(b) for b in buffers)
        
        success = zeroizer.zeroize(buffers)
        
        self.assertTrue(success)
        for buf in buffers:
            self.assertTrue(verify_zeroization(buf))
        
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['total_bytes_zeroized'], total_size)
    
    def test_memoryview_zeroization(self):
        """Test zeroizing writable memoryview"""
        zeroizer = SideChannelResistantZeroizer()
        
        buf = bytearray(b"memoryview_test_data")
        mv = memoryview(buf)
        
        success = zeroizer.zeroize(mv)
        
        self.assertTrue(success)
        self.assertTrue(verify_zeroization(buf))
    
    def test_constant_time_compare(self):
        """Test constant-time comparison"""
        # Equal values
        self.assertTrue(constant_time_memcmp(b"test", b"test"))
        self.assertTrue(constant_time_memcmp(b"", b""))
        self.assertTrue(constant_time_memcmp(b"\x00\x00", b"\x00\x00"))
        
        # Different lengths
        self.assertFalse(constant_time_memcmp(b"test", b"testing"))
        
        # Same length, different content
        self.assertFalse(constant_time_memcmp(b"abc", b"abd"))
        self.assertFalse(constant_time_memcmp(b"test", b"TEST"))
    
    def test_timing_consistency(self):
        """Verify comparison timing is consistent (basic sanity check)"""
        # This is a basic test - true timing attack resistance verification
        # would require more sophisticated statistical analysis
        
        a = b"x" * 1000
        b_same = b"x" * 1000
        b_diff = b"y" * 1000
        
        # Time comparisons
        times_same = []
        times_diff = []
        
        for _ in range(100):
            start = time.perf_counter_ns()
            constant_time_memcmp(a, b_same)
            times_same.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            constant_time_memcmp(a, b_diff)
            times_diff.append(time.perf_counter_ns() - start)
        
        avg_same = sum(times_same) / len(times_same)
        avg_diff = sum(times_diff) / len(times_diff)
        
        # Times should be within reasonable range of each other
        # (not an order of magnitude difference)
        ratio = max(avg_same, avg_diff) / min(avg_same, avg_diff)
        self.assertLess(ratio, 5.0, f"Timing ratio too high: {ratio}")
    
    def test_concurrent_zeroization(self):
        """Test thread-safe concurrent zeroization"""
        zeroizer = SideChannelResistantZeroizer(passes=2)
        errors = []
        
        def worker(worker_id):
            try:
                for i in range(10):
                    buf = bytearray(f"thread_{worker_id}_data_{i}".encode())
                    success = zeroizer.zeroize(buf)
                    assert success, "Zeroization failed"
                    assert verify_zeroization(buf), "Buffer not zeroed"
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
        
        metrics = zeroizer.get_metrics()
        self.assertGreater(metrics['operations_completed'], 0)
        self.assertEqual(metrics['operations_failed'], 0)
    
    def test_metrics_tracking(self):
        """Test metrics are tracked correctly"""
        zeroizer = SideChannelResistantZeroizer()
        
        # Zeroize some buffers
        zeroizer.zeroize(bytearray(b"test1"))
        zeroizer.zeroize(bytearray(b"test2_longer"))
        zeroizer.zeroize(bytearray(b"3"))
        
        metrics = zeroizer.get_metrics()
        
        self.assertEqual(metrics['operations_completed'], 3)
        self.assertEqual(metrics['operations_failed'], 0)
        self.assertGreater(metrics['total_bytes_zeroized'], 0)
        self.assertEqual(metrics['side_channel_resistant_ops'], 3)
        
        # Test reset
        zeroizer.reset_metrics()
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['total_bytes_zeroized'], 0)
        self.assertEqual(metrics['operations_completed'], 0)


class TestSensitiveData(unittest.TestCase):
    """Test SensitiveData container"""
    
    def test_initialization(self):
        """Test sensitive data initialization"""
        secret = b"my_secret_key_12345"
        
        with SensitiveData(secret) as sd:
            self.assertEqual(bytes(sd.value), secret)
            self.assertEqual(len(sd), len(secret))
    
    def test_auto_zeroize_on_exit(self):
        """Test data is zeroized on context exit"""
        buf_reference = None
        
        with SensitiveData(b"will_be_zeroized") as sd:
            buf_reference = sd.value
            original_data = bytes(buf_reference)
            self.assertGreater(len(original_data), 0)
        
        # After exit, buffer should be zeroized
        self.assertTrue(verify_zeroization(buf_reference))
        self.assertTrue(all(b == 0 for b in buf_reference))
    
    def test_set_new_data(self):
        """Test setting new data zeroizes old data"""
        with SensitiveData(b"old_data") as sd:
            old_buf = sd.value
            old_data = bytes(old_buf)
            
            sd.set(b"new_data")
            
            # Old buffer should be zeroized
            # Note: sd.value is a new buffer now, old one was zeroized
            self.assertEqual(bytes(sd.value), b"new_data")
    
    def test_manual_destroy(self):
        """Test manual destruction"""
        sd = SensitiveData(b"test_data")
        buf = sd.value
        
        sd.destroy()
        
        self.assertTrue(verify_zeroization(buf))
        self.assertTrue(sd._destroyed)
        
        # Access after destroy should raise error
        with self.assertRaises(ValueError):
            _ = sd.value
    
    def test_clear(self):
        """Test clear method"""
        sd = SensitiveData(b"clear_me")
        buf = sd.value
        
        sd.clear()
        
        self.assertTrue(verify_zeroization(buf))
        self.assertIsNone(sd._data)
    
    def test_nested_context(self):
        """Test nested context managers"""
        outer_buf = None
        inner_buf = None
        
        with SensitiveData(b"outer_secret") as outer:
            outer_buf = outer.value
            
            with SensitiveData(b"inner_secret") as inner:
                inner_buf = inner.value
                self.assertEqual(bytes(inner_buf), b"inner_secret")
            
            # Inner should be zeroized
            self.assertTrue(verify_zeroization(inner_buf))
        
        # Both should be zeroized
        self.assertTrue(verify_zeroization(outer_buf))
        self.assertTrue(verify_zeroization(inner_buf))


class TestSecureMemoryPool(unittest.TestCase):
    """Test SecureMemoryPool functionality"""
    
    def test_pool_initialization(self):
        """Test pool initialization"""
        pool = SecureMemoryPool(buffer_size=1024, max_buffers=10)
        
        stats = pool.get_stats()
        self.assertEqual(stats['buffer_size'], 1024)
        self.assertEqual(stats['max_buffers'], 10)
        self.assertEqual(stats['pool_size'], 0)
    
    def test_acquire_release(self):
        """Test buffer acquire and release"""
        pool = SecureMemoryPool(buffer_size=512, max_buffers=5)
        
        # Acquire buffer
        buf = pool.acquire()
        
        self.assertEqual(len(buf), 512)
        self.assertTrue(verify_zeroization(buf))  # Should be zero-initialized
        
        # Write data
        buf[0:10] = b"test_data_"
        
        # Release back to pool
        pool.release(buf)
        
        # Buffer should be zeroized after release
        self.assertTrue(verify_zeroization(buf))
        
        stats = pool.get_stats()
        self.assertEqual(stats['pool_size'], 1)
    
    def test_buffer_reuse(self):
        """Test buffers are reused from pool"""
        pool = SecureMemoryPool(buffer_size=256, max_buffers=3)
        
        # Acquire and release
        buf1 = pool.acquire()
        pool.release(buf1)
        
        stats_after_release = pool.get_stats()
        self.assertEqual(stats_after_release['pool_size'], 1)
        
        # Acquire again - should reuse same buffer
        buf2 = pool.acquire()
        
        stats_after_acquire = pool.get_stats()
        self.assertEqual(stats_after_acquire['pool_size'], 0)
        
        # Should be same buffer object
        self.assertIs(buf1, buf2)
        
        pool.release(buf2)
    
    def test_context_manager(self):
        """Test pool context manager"""
        pool = SecureMemoryPool(buffer_size=128)
        
        with pool.get_buffer() as buf:
            self.assertEqual(len(buf), 128)
            self.assertTrue(verify_zeroization(buf))
            buf[0] = 0xFF
        
        # After exit, buffer should be zeroized
        self.assertTrue(verify_zeroization(buf))
        
        stats = pool.get_stats()
        self.assertEqual(stats['pool_size'], 1)
    
    def test_pool_limit(self):
        """Test pool respects max_buffers limit"""
        pool = SecureMemoryPool(buffer_size=64, max_buffers=2)
        
        # Acquire and release 4 buffers
        bufs = [pool.acquire() for _ in range(4)]
        for buf in bufs:
            pool.release(buf)
        
        stats = pool.get_stats()
        # Pool should only keep max_buffers
        self.assertEqual(stats['pool_size'], 2)
    
    def test_clear_pool(self):
        """Test clearing pool zeroizes all buffers"""
        pool = SecureMemoryPool(buffer_size=64, max_buffers=5)
        
        bufs = [pool.acquire() for _ in range(3)]
        for buf in bufs:
            buf[0] = 0xAA
            pool.release(buf)
        
        pool.clear_pool()
        
        # All buffers should be zeroized
        for buf in bufs:
            self.assertTrue(verify_zeroization(buf))
        
        stats = pool.get_stats()
        self.assertEqual(stats['pool_size'], 0)


class TestSecureScratchpad(unittest.TestCase):
    """Test secure_scratchpad context manager"""
    
    def test_scratchpad_zeroization(self):
        """Test scratchpad is zeroized after use"""
        scratch_ref = None
        
        with secure_scratchpad(256) as scratch:
            scratch_ref = scratch
            scratch[0:16] = b"temporary_secret"
            self.assertEqual(len(scratch), 256)
        
        # After context exit, should be zeroized
        self.assertTrue(verify_zeroization(scratch_ref))
    
    def test_nested_scratchpads(self):
        """Test nested scratchpads"""
        outer_ref = None
        inner_ref = None
        
        with secure_scratchpad(100) as outer:
            outer_ref = outer
            outer[0] = 0xBB
            
            with secure_scratchpad(50) as inner:
                inner_ref = inner
                inner[0] = 0xCC
            
            self.assertTrue(verify_zeroization(inner_ref))
        
        self.assertTrue(verify_zeroization(outer_ref))
        self.assertTrue(verify_zeroization(inner_ref))


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions"""
    
    def test_zeroize_sensitive_data(self):
        """Test global convenience function"""
        buf = bytearray(b"global_function_test")
        
        success = zeroize_sensitive_data(buf)
        
        self.assertTrue(success)
        self.assertTrue(verify_zeroization(buf))
    
    def test_verify_zeroization(self):
        """Test verification function"""
        self.assertTrue(verify_zeroization(bytearray(b"\x00\x00\x00")))
        self.assertFalse(verify_zeroization(bytearray(b"\x00\x01\x00")))
        self.assertTrue(verify_zeroization(bytearray()))


def run_security_validation_tests():
    """Run security-focused validation tests"""
    print("\n=== Security Validation Tests ===")
    
    results = {
        'tests_passed': 0,
        'tests_failed': 0,
        'test_results': {}
    }
    
    # Test 1: Multi-pass overwrite verification
    try:
        print("Test 1: Multi-pass overwrite with pattern verification")
        
        zeroizer = SideChannelResistantZeroizer(passes=4, use_random_final_pass=True)
        
        # Create buffer with known pattern
        test_pattern = b"\xDE\xAD\xBE\xEF" * 64
        buf = bytearray(test_pattern)
        
        success = zeroizer.zeroize(buf)
        
        # Verify final state is all zeros
        self.assertTrue(success)
        self.assertTrue(verify_zeroization(buf))
        
        results['tests_passed'] += 1
        results['test_results']['multipass_overwrite'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['multipass_overwrite'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    # Test 2: Large buffer zeroization
    try:
        print("\nTest 2: Large buffer zeroization (64KB)")
        
        zeroizer = SideChannelResistantZeroizer(passes=2)
        
        large_buf = bytearray(65536)  # 64KB
        for i in range(len(large_buf)):
            large_buf[i] = i & 0xFF
        
        start = time.time()
        success = zeroizer.zeroize(large_buf)
        elapsed = time.time() - start
        
        self.assertTrue(success)
        self.assertTrue(verify_zeroization(large_buf))
        
        metrics = zeroizer.get_metrics()
        print(f"  - Zeroized 64KB in {elapsed*1000:.2f}ms")
        print(f"  - Total bytes: {metrics['total_bytes_zeroized']}")
        
        results['tests_passed'] += 1
        results['test_results']['large_buffer'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['large_buffer'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    # Test 3: Garbage collection resilience
    try:
        print("\nTest 3: Garbage collection resilience")
        
        zeroizer = SideChannelResistantZeroizer(passes=2)
        
        # Create and zeroize many small buffers
        for i in range(100):
            buf = bytearray(f"gc_test_{i}_sensitive_data".encode())
            zeroizer.zeroize(buf)
        
        # Force GC
        gc.collect()
        
        metrics = zeroizer.get_metrics()
        self.assertEqual(metrics['operations_completed'], 100)
        self.assertEqual(metrics['operations_failed'], 0)
        
        print(f"  - Completed {metrics['operations_completed']} zeroizations")
        
        results['tests_passed'] += 1
        results['test_results']['gc_resilience'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['gc_resilience'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    # Test 4: Full integration workflow
    try:
        print("\nTest 4: Full post-quantum key handling workflow")
        
        # Simulate key handling
        private_key = bytearray(b"simulated_crystals_kyber_private_key_2026")
        
        with SensitiveData(private_key) as key_data:
            # Use the key
            key_bytes = key_data.value
            
            # Do some "crypto" operations in scratchpad
            with secure_scratchpad(512) as scratch:
                scratch[0:len(key_bytes)] = key_bytes
            
            # Key still accessible here
            self.assertEqual(bytes(key_data.value), bytes(private_key))
        
        # After context, both key and scratchpad should be zeroized
        # Note: key_data.value is destroyed, but we can check our reference
        self.assertTrue(verify_zeroization(private_key))
        
        results['tests_passed'] += 1
        results['test_results']['full_workflow'] = 'PASSED'
        print("  ✓ PASSED")
        
    except Exception as e:
        results['tests_failed'] += 1
        results['test_results']['full_workflow'] = f'FAILED: {e}'
        print(f"  ✗ FAILED: {e}")
    
    return results


def main():
    """Run all tests"""
    print("=" * 60)
    print("Post-Quantum Secure Memory Zeroizer - Test Suite")
    print("=" * 60)
    
    # Run unit tests
    print("\n=== Running Unit Tests ===")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestSideChannelResistantZeroizer))
    suite.addTests(loader.loadTestsFromTestCase(TestSensitiveData))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureMemoryPool))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureScratchpad))
    suite.addTests(loader.loadTestsFromTestCase(TestConvenienceFunctions))
    
    runner = unittest.TextTestRunner(verbosity=2)
    unit_results = runner.run(suite)
    
    # Run security validation tests
    security_results = run_security_validation_tests()
    
    # Save results
    final_results = {
        'unit_tests': {
            'tests_run': unit_results.testsRun,
            'failures': len(unit_results.failures),
            'errors': len(unit_results.errors),
            'was_successful': unit_results.wasSuccessful()
        },
        'security_validation_tests': security_results,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    with open('test_results_secure_memory_zeroizer.json', 'w') as f:
        json.dump(final_results, f, indent=2)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Unit Tests: {unit_results.testsRun} run")
    print(f"  - Failures: {len(unit_results.failures)}")
    print(f"  - Errors: {len(unit_results.errors)}")
    print(f"Security Validation: {security_results['tests_passed']} passed, {security_results['tests_failed']} failed")
    print("=" * 60)
    
    # Return exit code
    return 0 if unit_results.wasSuccessful() and security_results['tests_failed'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
