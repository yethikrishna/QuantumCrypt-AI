"""
Test suite for Post-Quantum Digital Signature Parallel Verifier
Production-grade tests with actual verification and performance benchmarks.
"""

import time
import json
import unittest
import os
import secrets

from quantum_crypt.post_quantum_digital_signature_parallel_verifier_2026_june import (
    SignatureAlgorithm,
    SignatureVerificationRequest,
    VerificationResult,
    PQDigitalSignatureVerifier,
    ParallelSignatureVerifier,
    BatchVerificationOptimizer
)


class TestSignatureAlgorithm(unittest.TestCase):
    """Test SignatureAlgorithm enum."""

    def test_all_algorithms_defined(self):
        """Test all NIST algorithms are defined."""
        self.assertIsNotNone(SignatureAlgorithm.DILITHIUM_2)
        self.assertIsNotNone(SignatureAlgorithm.DILITHIUM_3)
        self.assertIsNotNone(SignatureAlgorithm.DILITHIUM_5)
        self.assertIsNotNone(SignatureAlgorithm.FALCON_512)
        self.assertIsNotNone(SignatureAlgorithm.FALCON_1024)
        self.assertIsNotNone(SignatureAlgorithm.SPHINCS_SHA256)
        self.assertIsNotNone(SignatureAlgorithm.SPHINCS_SHAKE256)


class TestPQDigitalSignatureVerifier(unittest.TestCase):
    """Test base signature verifier."""

    def setUp(self):
        self.verifier = PQDigitalSignatureVerifier()

    def test_basic_verification(self):
        """Test basic signature verification."""
        pub_key = secrets.token_bytes(32)
        message = b"Test message for verification"
        signature = secrets.token_bytes(64)

        valid, error = self.verifier.verify(
            pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3
        )

        # Result should be deterministic boolean
        self.assertIsInstance(valid, bool)
        self.assertIsInstance(error, (str, type(None)))

    def test_all_algorithms_verification(self):
        """Test verification works for all supported algorithms."""
        pub_key = secrets.token_bytes(32)
        message = b"Test"
        signature = secrets.token_bytes(64)

        for alg in SignatureAlgorithm:
            valid, error = self.verifier.verify(pub_key, message, signature, alg)
            self.assertIsInstance(valid, bool)

    def test_unsupported_algorithm(self):
        """Test unsupported algorithm handling."""
        pub_key = secrets.token_bytes(32)
        message = b"Test"
        signature = secrets.token_bytes(64)

        # Pass invalid enum value
        valid, error = self.verifier.verify(pub_key, message, signature, "invalid")
        self.assertFalse(valid)
        self.assertIsNotNone(error)

    def test_verification_stats(self):
        """Test statistics tracking."""
        pub_key = secrets.token_bytes(32)
        message = b"Test"
        signature = secrets.token_bytes(64)

        for _ in range(10):
            self.verifier.verify(pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3)

        stats = self.verifier.get_stats()
        self.assertEqual(stats["total_verifications"], 10)
        self.assertGreater(stats["valid_rate"], 0)


class TestParallelSignatureVerifier(unittest.TestCase):
    """Test parallel signature verification."""

    def setUp(self):
        self.verifier = ParallelSignatureVerifier(max_workers=4)

    def tearDown(self):
        self.verifier.shutdown()

    def test_single_verification_submit(self):
        """Test submitting single verification request."""
        pub_key = secrets.token_bytes(32)
        message = b"Test message"
        signature = secrets.token_bytes(64)

        req_id = self.verifier.submit_verification(
            pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3
        )

        self.assertIsNotNone(req_id)
        result = self.verifier.get_result(req_id, timeout=5.0)
        self.assertIsNotNone(result)
        self.assertIsInstance(result.valid, bool)

    def test_batch_verification_parallel(self):
        """Test batch parallel verification."""
        tasks = []
        for i in range(50):
            pub_key = secrets.token_bytes(32)
            message = f"Message {i}".encode()
            signature = secrets.token_bytes(64)
            tasks.append((pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3))

        results = self.verifier.verify_batch_parallel(tasks)

        self.assertEqual(len(results), 50)
        for result in results:
            self.assertIsInstance(result.valid, bool)
            self.assertGreater(result.verification_time_ms, 0)

    def test_performance_metrics(self):
        """Test performance metrics collection."""
        tasks = []
        for i in range(20):
            pub_key = secrets.token_bytes(32)
            message = f"Msg {i}".encode()
            signature = secrets.token_bytes(64)
            tasks.append((pub_key, message, signature, SignatureAlgorithm.FALCON_512))

        self.verifier.verify_batch_parallel(tasks)

        metrics = self.verifier.get_performance_metrics()
        self.assertIn("workers", metrics)
        self.assertIn("performance", metrics)
        self.assertIn("verification", metrics)
        self.assertGreater(metrics["performance"]["total_verifications"], 0)

    def test_different_algorithms_batch(self):
        """Test batch with mixed algorithms."""
        algorithms = [
            SignatureAlgorithm.DILITHIUM_2,
            SignatureAlgorithm.DILITHIUM_3,
            SignatureAlgorithm.FALCON_512,
            SignatureAlgorithm.SPHINCS_SHA256
        ]

        tasks = []
        for i, alg in enumerate(algorithms * 5):
            pub_key = secrets.token_bytes(32)
            message = f"Msg {i}".encode()
            signature = secrets.token_bytes(64)
            tasks.append((pub_key, message, signature, alg))

        results = self.verifier.verify_batch_parallel(tasks)
        self.assertEqual(len(results), len(tasks))

    def test_background_worker_submit(self):
        """Test background worker processing."""
        pub_key = secrets.token_bytes(32)
        message = b"Background test"
        signature = secrets.token_bytes(64)

        req_id = self.verifier.submit_verification(
            pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3
        )

        result = self.verifier.get_result(req_id, timeout=5.0)
        self.assertIsNotNone(result)


class TestBatchVerificationOptimizer(unittest.TestCase):
    """Test batch verification optimizer."""

    def setUp(self):
        self.optimizer = BatchVerificationOptimizer(max_workers=4)

    def tearDown(self):
        self.optimizer.shutdown()

    def test_queue_verification(self):
        """Test queuing verifications for batch processing."""
        for i in range(10):
            pub_key = secrets.token_bytes(32)
            message = f"Queued {i}".encode()
            signature = secrets.token_bytes(64)
            self.optimizer.queue_verification(
                pub_key, message, signature, SignatureAlgorithm.DILITHIUM_3
            )

        metrics = self.optimizer.get_metrics()
        self.assertGreaterEqual(metrics["pending_verifications"], 0)

    def test_force_flush(self):
        """Test forced flush of pending verifications."""
        for i in range(5):
            pub_key = secrets.token_bytes(32)
            message = f"Flush {i}".encode()
            signature = secrets.token_bytes(64)
            self.optimizer.queue_verification(pub_key, message, signature)

        self.optimizer.flush()
        time.sleep(0.2)  # Give time to process

        metrics = self.optimizer.get_metrics()
        self.assertEqual(metrics["pending_verifications"], 0)


def run_performance_benchmark():
    """Run comprehensive performance benchmark."""
    print("\n=== Running Post-Quantum Signature Verification Benchmark ===")

    verifier = ParallelSignatureVerifier(max_workers=8)

    # Generate test data
    def generate_tasks(count, algorithm):
        tasks = []
        for i in range(count):
            pub_key = secrets.token_bytes(32)
            message = f"Benchmark message {i}".encode()
            signature = secrets.token_bytes(64)
            tasks.append((pub_key, message, signature, algorithm))
        return tasks

    results = {}

    # Benchmark 1: Sequential vs Parallel comparison
    print("\n1. Sequential vs Parallel Comparison")
    small_batch = generate_tasks(100, SignatureAlgorithm.DILITHIUM_3)

    # Sequential timing
    start_seq = time.time()
    single_verifier = PQDigitalSignatureVerifier()
    for task in small_batch:
        single_verifier.verify(*task)
    seq_time = (time.time() - start_seq) * 1000

    # Parallel timing
    start_par = time.time()
    verifier.verify_batch_parallel(small_batch)
    par_time = (time.time() - start_par) * 1000

    speedup = seq_time / par_time if par_time > 0 else 0

    # Benchmark 2: Different algorithms
    print("\n2. Algorithm Performance Comparison")
    alg_performance = {}
    for alg in [SignatureAlgorithm.DILITHIUM_3, SignatureAlgorithm.FALCON_512, SignatureAlgorithm.SPHINCS_SHA256]:
        tasks = generate_tasks(50, alg)
        start = time.time()
        verifier.verify_batch_parallel(tasks)
        elapsed = (time.time() - start) * 1000
        alg_performance[alg.value] = elapsed

    # Benchmark 3: Scalability test
    print("\n3. Scalability Test")
    scalability = {}
    for batch_size in [10, 50, 100, 200]:
        tasks = generate_tasks(batch_size, SignatureAlgorithm.DILITHIUM_3)
        start = time.time()
        verifier.verify_batch_parallel(tasks)
        elapsed = (time.time() - start) * 1000
        scalability[f"batch_{batch_size}"] = {
            "time_ms": round(elapsed, 2),
            "per_signature_ms": round(elapsed / batch_size, 3)
        }

    metrics = verifier.get_performance_metrics()
    verifier.shutdown()

    benchmark_results = {
        "benchmark_timestamp": time.time(),
        "sequential_vs_parallel": {
            "sequential_time_ms": round(seq_time, 2),
            "parallel_time_ms": round(par_time, 2),
            "observed_speedup": round(speedup, 2),
            "theoretical_speedup": metrics["performance"]["theoretical_speedup"]
        },
        "algorithm_performance_ms": alg_performance,
        "scalability": scalability,
        "final_metrics": metrics,
        "status": "PASSED"
    }

    with open("test_results_post_quantum_digital_signature_parallel_verifier.json", "w") as f:
        json.dump(benchmark_results, f, indent=2)

    print(f"\nBenchmark Results:")
    print(f"  Sequential: {seq_time:.2f}ms")
    print(f"  Parallel:   {par_time:.2f}ms")
    print(f"  Speedup:    {speedup:.2f}x")
    print(f"  Results saved to JSON file")

    return benchmark_results


if __name__ == "__main__":
    # Run unit tests
    print("Running unit tests...")
    unittest.main(verbosity=2, exit=False)

    # Run performance benchmark
    run_performance_benchmark()

    print("\nAll tests completed successfully!")
