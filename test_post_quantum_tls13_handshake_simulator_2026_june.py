"""
Test Suite for QuantumCrypt-AI Post-Quantum TLS 1.3 Handshake Simulator
June 2026 - Production Grade Tests

This test suite validates the Post-Quantum TLS 1.3 Handshake Simulator module
with comprehensive unit tests, integration tests, and edge cases.
"""
import json
import os
import tempfile
import pytest
from datetime import datetime

from quantum_crypt.post_quantum_tls13_handshake_simulator_2026_june import (
    TLS13HandshakeSimulator,
    TLSVersion,
    CipherSuite,
    KEMAlgorithm,
    SignatureAlgorithm,
    HandshakeState,
    HandshakeFailureReason,
    SecurityLevel,
)


class TestClientHello:
    """Test ClientHello message creation"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_client_hello_default(self):
        """Test default ClientHello creation"""
        ch = self.simulator.create_client_hello()
        
        assert len(ch.random_bytes) == 32
        assert len(ch.session_id) == 32
        assert len(ch.cipher_suites) > 0
        assert len(ch.kem_algorithms) > 0
        assert len(ch.signature_algorithms) > 0
        assert TLSVersion.TLS_1_3 in ch.supported_versions
        assert len(ch.key_share) > 0
    
    def test_client_hello_custom_kem(self):
        """Test ClientHello with custom KEM algorithms"""
        custom_kems = [KEMAlgorithm.KYBER_768, KEMAlgorithm.CLASSICAL_X25519]
        ch = self.simulator.create_client_hello(kem_algorithms=custom_kems)
        
        assert set(ch.kem_algorithms) == set(custom_kems)
        assert KEMAlgorithm.KYBER_768 in ch.key_share
        assert KEMAlgorithm.CLASSICAL_X25519 in ch.key_share
        assert len(ch.key_share[KEMAlgorithm.KYBER_768]) == 1184  # Kyber-768 pubkey bytes
    
    def test_client_hello_early_data(self):
        """Test ClientHello with early data enabled"""
        ch = self.simulator.create_client_hello(early_data=True)
        assert ch.early_data_capable is True


class TestServerHello:
    """Test ServerHello message processing"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_server_hello_post_quantum_preference(self):
        """Test server prefers post-quantum KEM when available"""
        ch = self.simulator.create_client_hello(kem_algorithms=[
            KEMAlgorithm.CLASSICAL_X25519,
            KEMAlgorithm.KYBER_768
        ])
        
        success, sh, failure = self.simulator.process_client_hello(
            ch, server_preference="post_quantum"
        )
        
        assert success is True
        assert failure is None
        assert sh.selected_kem == KEMAlgorithm.KYBER_768
        assert sh.selected_version == TLSVersion.TLS_1_3
    
    def test_server_hello_hybrid_preference(self):
        """Test server prefers hybrid KEM when available"""
        ch = self.simulator.create_client_hello(kem_algorithms=[
            KEMAlgorithm.CLASSICAL_X25519,
            KEMAlgorithm.HYBRID_X25519_KYBER768,
            KEMAlgorithm.KYBER_768
        ])
        
        success, sh, failure = self.simulator.process_client_hello(
            ch, server_preference="hybrid"
        )
        
        assert success is True
        assert sh.selected_kem == KEMAlgorithm.HYBRID_X25519_KYBER768
    
    def test_server_hello_classical_preference(self):
        """Test server prefers classical KEM"""
        ch = self.simulator.create_client_hello(kem_algorithms=[
            KEMAlgorithm.CLASSICAL_X25519,
            KEMAlgorithm.KYBER_768
        ])
        
        success, sh, failure = self.simulator.process_client_hello(
            ch, server_preference="classical"
        )
        
        assert success is True
        assert sh.selected_kem == KEMAlgorithm.CLASSICAL_X25519
    
    def test_server_hello_no_common_kem(self):
        """Test failure when no common KEM algorithm"""
        ch = self.simulator.create_client_hello(kem_algorithms=[
            KEMAlgorithm.KYBER_1024  # Only offer highest security
        ])
        
        # Server only supports classical
        success, sh, failure = self.simulator.process_client_hello(
            ch, server_preference="classical"
        )
        
        assert success is False
        assert failure == HandshakeFailureReason.KEY_EXCHANGE


class TestCertificateGeneration:
    """Test certificate generation"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_certificate_generation_classical(self):
        """Test classical certificate generation"""
        cert = self.simulator.generate_server_certificate(
            SignatureAlgorithm.ECDSA_SECP256R1,
            is_post_quantum=False
        )
        
        assert cert.subject.startswith("CN=")
        assert cert.issuer.startswith("CN=")
        assert cert.signature_algorithm == SignatureAlgorithm.ECDSA_SECP256R1
        assert cert.is_post_quantum is False
        assert cert.valid_to > cert.valid_from
    
    def test_certificate_generation_post_quantum(self):
        """Test post-quantum certificate generation"""
        cert = self.simulator.generate_server_certificate(
            SignatureAlgorithm.DILITHIUM_3,
            is_post_quantum=True
        )
        
        assert cert.signature_algorithm == SignatureAlgorithm.DILITHIUM_3
        assert cert.is_post_quantum is True
        assert len(cert.signature) == 3293  # Dilithium-3 signature bytes


class TestFullHandshake:
    """Test complete TLS 1.3 handshake"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_full_handshake_success_kyber(self):
        """Test successful handshake with Kyber-768"""
        result = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_768],
            server_preference="post_quantum"
        )
        
        assert result.success is True
        assert result.state == HandshakeState.COMPLETED
        assert result.kem_algorithm == KEMAlgorithm.KYBER_768
        assert result.is_post_quantum_secure is True
        assert result.is_hybrid_mode is False
        assert result.security_level == SecurityLevel.LEVEL_3
        assert len(result.master_secret) == 48
        assert result.metrics.total_bytes > 0
        assert result.metrics.timing.total_us > 0
    
    def test_full_handshake_success_hybrid(self):
        """Test successful handshake with hybrid mode"""
        result = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.HYBRID_X25519_KYBER768],
            server_preference="hybrid"
        )
        
        assert result.success is True
        assert result.kem_algorithm == KEMAlgorithm.HYBRID_X25519_KYBER768
        assert result.is_post_quantum_secure is True
        assert result.is_hybrid_mode is True
    
    def test_full_handshake_success_classical(self):
        """Test successful handshake with classical X25519"""
        result = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.CLASSICAL_X25519],
            server_preference="classical"
        )
        
        assert result.success is True
        assert result.kem_algorithm == KEMAlgorithm.CLASSICAL_X25519
        assert result.is_post_quantum_secure is False
    
    def test_full_handshake_injected_failure_cipher(self):
        """Test handshake failure - cipher suite"""
        result = self.simulator.perform_full_handshake(
            inject_failure=HandshakeFailureReason.CIPHER_SUITE
        )
        
        assert result.success is False
        assert result.state == HandshakeState.FAILED
        assert result.failure_reason == HandshakeFailureReason.CIPHER_SUITE
    
    def test_full_handshake_injected_failure_key_exchange(self):
        """Test handshake failure - key exchange"""
        result = self.simulator.perform_full_handshake(
            inject_failure=HandshakeFailureReason.KEY_EXCHANGE
        )
        
        assert result.success is False
        assert result.failure_reason == HandshakeFailureReason.KEY_EXCHANGE
    
    def test_full_handshake_injected_failure_signature(self):
        """Test handshake failure - invalid signature"""
        result = self.simulator.perform_full_handshake(
            inject_failure=HandshakeFailureReason.SIGNATURE_INVALID
        )
        
        assert result.success is False
        assert result.failure_reason == HandshakeFailureReason.SIGNATURE_INVALID
    
    def test_full_handshake_metrics_populated(self):
        """Test handshake metrics are properly populated"""
        result = self.simulator.perform_full_handshake()
        
        assert result.metrics.timing.client_hello_us > 0
        assert result.metrics.timing.server_hello_us > 0
        assert result.metrics.timing.certificate_us > 0
        assert result.metrics.timing.server_finished_us >= 0
        assert result.metrics.timing.client_finished_us >= 0
        assert result.metrics.timing.total_us > 0
        assert result.metrics.bytes_sent_client > 0
        assert result.metrics.bytes_sent_server > 0
        assert result.metrics.kem_operations >= 2
        assert result.metrics.signature_operations >= 1
        assert result.metrics.hash_operations >= 3
    
    def test_full_handshake_dilithium_certificate(self):
        """Test handshake with post-quantum Dilithium certificate"""
        result = self.simulator.perform_full_handshake(
            signature_alg=SignatureAlgorithm.DILITHIUM_3
        )
        
        assert result.success is True
        assert result.signature_algorithm == SignatureAlgorithm.DILITHIUM_3
    
    def test_handshake_history_recorded(self):
        """Test handshake history is maintained"""
        initial_count = len(self.simulator.handshake_history)
        
        self.simulator.perform_full_handshake()
        self.simulator.perform_full_handshake()
        
        assert len(self.simulator.handshake_history) == initial_count + 2


class TestBenchmarking:
    """Test batch handshake benchmarking"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_benchmark_small(self):
        """Test small benchmark run"""
        result = self.simulator.benchmark_handshakes(
            num_handshakes=20,
            failure_rate=0.0
        )
        
        assert result.total_handshakes == 20
        assert result.successful_handshakes == 20
        assert result.failed_handshakes == 0
        assert len(result.all_results) == 20
        assert result.average_latency_us > 0
        assert result.handshakes_per_second > 0
    
    def test_benchmark_with_failures(self):
        """Test benchmark with simulated failures"""
        result = self.simulator.benchmark_handshakes(
            num_handshakes=50,
            failure_rate=0.1  # 10% failure rate
        )
        
        assert result.total_handshakes == 50
        assert result.successful_handshakes + result.failed_handshakes == 50
        assert result.failed_handshakes > 0
    
    def test_benchmark_kem_comparison(self):
        """Test benchmark compares multiple KEM algorithms"""
        result = self.simulator.benchmark_handshakes(
            num_handshakes=40,
            kem_algorithms=[
                KEMAlgorithm.CLASSICAL_X25519,
                KEMAlgorithm.KYBER_512,
                KEMAlgorithm.KYBER_768,
                KEMAlgorithm.HYBRID_X25519_KYBER768,
            ],
            failure_rate=0.0
        )
        
        # Each KEM should have 10 handshakes
        assert KEMAlgorithm.CLASSICAL_X25519.value in result.results_by_kem
        assert KEMAlgorithm.KYBER_512.value in result.results_by_kem
        assert KEMAlgorithm.KYBER_768.value in result.results_by_kem
        assert KEMAlgorithm.HYBRID_X25519_KYBER768.value in result.results_by_kem
        
        # Classical should be fastest (lowest latency)
        x25519_latency = result.results_by_kem[KEMAlgorithm.CLASSICAL_X25519.value]["avg_latency"]
        kyber768_latency = result.results_by_kem[KEMAlgorithm.KYBER_768.value]["avg_latency"]
        assert x25519_latency < kyber768_latency  # Classical is faster
    
    def test_benchmark_percentiles(self):
        """Test benchmark percentile calculations"""
        result = self.simulator.benchmark_handshakes(
            num_handshakes=100,
            failure_rate=0.0
        )
        
        assert result.p50_latency_us <= result.p95_latency_us
        assert result.p95_latency_us <= result.p99_latency_us


class TestExportFunctions:
    """Test JSON and CSV export functionality"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_handshake_json_export(self):
        """Test single handshake JSON export"""
        result = self.simulator.perform_full_handshake()
        json_output = self.simulator.export_to_json(result)
        data = json.loads(json_output)
        
        assert "handshake_id" in data
        assert "success" in data
        assert "state" in data
        assert "kem_algorithm" in data
        assert "is_post_quantum_secure" in data
        assert "metrics" in data
        assert "timing_us" in data["metrics"]
    
    def test_handshake_json_export_to_file(self):
        """Test handshake JSON export to file"""
        result = self.simulator.perform_full_handshake()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            self.simulator.export_to_json(result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            assert data["success"] is True
        finally:
            os.unlink(filepath)
    
    def test_benchmark_json_export(self):
        """Test benchmark JSON export"""
        result = self.simulator.benchmark_handshakes(num_handshakes=10)
        json_output = self.simulator.export_to_json(result)
        data = json.loads(json_output)
        
        assert "benchmark_id" in data
        assert "total_handshakes" in data
        assert "successful_handshakes" in data
        assert "results_by_kem" in data
        assert "performance" in data
    
    def test_benchmark_csv_export(self):
        """Test benchmark CSV export"""
        result = self.simulator.benchmark_handshakes(num_handshakes=20)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            self.simulator.export_benchmark_to_csv(result, filepath)
            assert os.path.exists(filepath)
            
            with open(filepath, 'r') as f:
                lines = f.readlines()
            # Header + at least 1 KEM row
            assert len(lines) >= 2
        finally:
            os.unlink(filepath)


class TestSecurityProperties:
    """Test security property assessment"""
    
    def setup_method(self):
        self.simulator = TLS13HandshakeSimulator()
    
    def test_kyber_security_levels(self):
        """Test Kyber security level assignment"""
        # Kyber-512 = NIST-1
        result_512 = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_512]
        )
        assert result_512.security_level == SecurityLevel.LEVEL_1
        
        # Kyber-768 = NIST-3
        result_768 = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_768]
        )
        assert result_768.security_level == SecurityLevel.LEVEL_3
        
        # Kyber-1024 = NIST-5
        result_1024 = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_1024]
        )
        assert result_1024.security_level == SecurityLevel.LEVEL_5
    
    def test_post_quantum_flag(self):
        """Test post-quantum security flag"""
        # Classical - not PQ secure
        result_classical = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.CLASSICAL_X25519]
        )
        assert result_classical.is_post_quantum_secure is False
        
        # Kyber - PQ secure
        result_kyber = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_768]
        )
        assert result_kyber.is_post_quantum_secure is True
        
        # Hybrid - PQ secure
        result_hybrid = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.HYBRID_X25519_KYBER768]
        )
        assert result_hybrid.is_post_quantum_secure is True
    
    def test_hybrid_mode_flag(self):
        """Test hybrid mode detection"""
        # Pure Kyber - not hybrid
        result_pure = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.KYBER_768]
        )
        assert result_pure.is_hybrid_mode is False
        
        # Hybrid X25519+Kyber - hybrid
        result_hybrid = self.simulator.perform_full_handshake(
            client_kem_list=[KEMAlgorithm.HYBRID_X25519_KYBER768]
        )
        assert result_hybrid.is_hybrid_mode is True


class TestIntegration:
    """Integration tests for complete workflow"""
    
    def test_complete_benchmark_workflow(self):
        """Test complete benchmark workflow"""
        simulator = TLS13HandshakeSimulator()
        
        # 1. Run benchmark
        benchmark = simulator.benchmark_handshakes(
            num_handshakes=50,
            kem_algorithms=[
                KEMAlgorithm.CLASSICAL_X25519,
                KEMAlgorithm.KYBER_512,
                KEMAlgorithm.KYBER_768,
            ],
            failure_rate=0.02
        )
        
        assert benchmark.total_handshakes == 50
        
        # 2. Export results
        json_output = simulator.export_to_json(benchmark)
        assert len(json_output) > 0
        
        # 3. Verify handshake history
        assert len(simulator.handshake_history) >= 50
        
        # 4. Individual handshake analysis
        successful = [r for r in benchmark.all_results if r.success]
        for result in successful[:5]:
            assert result.handshake_id
            assert result.metrics.timing.total_us > 0


def run_tests():
    """Run all tests and return results"""
    import pytest
    import sys
    
    result = pytest.main([__file__, "-v", "--tb=short"])
    return result


if __name__ == "__main__":
    print("Running Post-Quantum TLS 1.3 Handshake Simulator Tests...")
    exit_code = run_tests()
    print(f"\nTest exit code: {exit_code}")
    
    # Also run a quick demo
    print("\n" + "="*60)
    print("DEMO: Post-Quantum TLS 1.3 Handshake Simulator")
    print("="*60)
    
    simulator = TLS13HandshakeSimulator()
    
    # Demo 1: Individual handshakes
    print("\n--- Individual Handshake Results ---")
    for kem in [KEMAlgorithm.CLASSICAL_X25519, KEMAlgorithm.KYBER_512, 
                KEMAlgorithm.KYBER_768, KEMAlgorithm.HYBRID_X25519_KYBER768]:
        result = simulator.perform_full_handshake(
            client_kem_list=[kem],
            network_latency_us=1000
        )
        print(f"\n{kem.value}:")
        print(f"  Success: {result.success}")
        print(f"  PQ Secure: {result.is_post_quantum_secure}")
        print(f"  Hybrid: {result.is_hybrid_mode}")
        print(f"  Security: {result.security_level.value}")
        print(f"  Latency: {result.metrics.timing.total_us} us")
        print(f"  Total Bytes: {result.metrics.total_bytes}")
    
    # Demo 2: Benchmark
    print("\n" + "-"*60)
    print("--- Benchmark Results (100 handshakes) ---")
    benchmark = simulator.benchmark_handshakes(
        num_handshakes=100,
        failure_rate=0.01
    )
    
    print(f"\nTotal: {benchmark.total_handshakes}")
    print(f"Successful: {benchmark.successful_handshakes}")
    print(f"Failed: {benchmark.failed_handshakes}")
    print(f"\nPerformance:")
    print(f"  Avg Latency: {benchmark.average_latency_us} us")
    print(f"  P50 Latency: {benchmark.p50_latency_us} us")
    print(f"  P95 Latency: {benchmark.p95_latency_us} us")
    print(f"  Handshakes/sec: {benchmark.handshakes_per_second}")
    
    print(f"\nBy KEM Algorithm:")
    for kem, data in benchmark.results_by_kem.items():
        success_rate = (data["success"] / data["count"] * 100) if data["count"] > 0 else 0
        print(f"  {kem}: {data['count']} handshakes, "
              f"{success_rate:.1f}% success, "
              f"{data['avg_latency']:.0f} us avg")
    
    # Save results
    simulator.export_to_json(benchmark, "test_results_tls13_handshake.json")
    print("\nResults saved to test_results_tls13_handshake.json")
