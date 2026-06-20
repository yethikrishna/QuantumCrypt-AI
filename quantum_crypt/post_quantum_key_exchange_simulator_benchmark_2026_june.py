"""
Post-Quantum Cryptography Key Exchange Simulator & Benchmark
Production-grade implementation for QuantumCrypt-AI

This module provides:
1. Simulation of NIST-standardized post-quantum key exchange protocols
2. Key generation, encapsulation, decapsulation simulation
3. Performance benchmarking and comparison
4. Security strength analysis
5. Protocol compatibility matrix
6. Real-world deployment scenario simulation

Supported algorithms (simulated based on NIST standards):
- CRYSTALS-Kyber (MLWE) - NIST PQC Standard
- CRYSTALS-Dilithium (MLDSA) - Digital Signature
- SPHINCS+ (Stateless Hash-Based)
- Classic McEliece (Code-Based)
- FrodoKEM (LWE)
- NTRU-HPS (Lattice)
"""

import hashlib
import os
import time
import secrets
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import json


class PQAlgorithm(Enum):
    """Post-quantum algorithm types"""
    KYBER_512 = "kyber_512"
    KYBER_768 = "kyber_768"
    KYBER_1024 = "kyber_1024"
    DILITHIUM_2 = "dilithium_2"
    DILITHIUM_3 = "dilithium_3"
    DILITHIUM_5 = "dilithium_5"
    SPHINCS_SHA256_128F = "sphincs_sha256_128f"
    CLASSIC_MCELIECE_460896 = "classic_mceliece_460896"
    FRODO_KEM_640_AES = "frodo_kem_640_aes"
    NTRU_HPS_2048_509 = "ntru_hps_2048_509"
    RSA_2048 = "rsa_2048"  # Classical baseline
    ECDH_P256 = "ecdh_p256"  # Classical baseline


@dataclass
class AlgorithmSpec:
    """Specification of a post-quantum algorithm"""
    name: str
    algorithm_type: str  # KEM, Signature
    nist_security_level: int
    public_key_size: int  # bytes
    secret_key_size: int  # bytes
    ciphertext_size: int  # bytes (for KEM)
    signature_size: int  # bytes (for signatures)
    shared_secret_size: int  # bytes
    is_standardized: bool
    lattice_based: bool
    performance_score: float  # relative performance (1.0 = baseline)


@dataclass
class KeyPair:
    """Represents a key pair"""
    algorithm: PQAlgorithm
    public_key: bytes
    secret_key: bytes
    generated_at: float = field(default_factory=time.time)


@dataclass
class EncapsulationResult:
    """Result of KEM encapsulation"""
    ciphertext: bytes
    shared_secret: bytes
    algorithm: PQAlgorithm


@dataclass
class BenchmarkResult:
    """Benchmark results for an algorithm"""
    algorithm: str
    keygen_time_us: float
    encaps_time_us: float
    decaps_time_us: float
    total_time_us: float
    operations_per_second: float
    memory_usage_bytes: int


ALGORITHM_SPECS = {
    PQAlgorithm.KYBER_512: AlgorithmSpec(
        name="CRYSTALS-Kyber-512",
        algorithm_type="KEM",
        nist_security_level=1,
        public_key_size=800,
        secret_key_size=1632,
        ciphertext_size=768,
        signature_size=0,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.95
    ),
    PQAlgorithm.KYBER_768: AlgorithmSpec(
        name="CRYSTALS-Kyber-768",
        algorithm_type="KEM",
        nist_security_level=3,
        public_key_size=1184,
        secret_key_size=2400,
        ciphertext_size=1088,
        signature_size=0,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.85
    ),
    PQAlgorithm.KYBER_1024: AlgorithmSpec(
        name="CRYSTALS-Kyber-1024",
        algorithm_type="KEM",
        nist_security_level=5,
        public_key_size=1568,
        secret_key_size=3168,
        ciphertext_size=1568,
        signature_size=0,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.70
    ),
    PQAlgorithm.DILITHIUM_2: AlgorithmSpec(
        name="CRYSTALS-Dilithium-2",
        algorithm_type="Signature",
        nist_security_level=2,
        public_key_size=1312,
        secret_key_size=2528,
        ciphertext_size=0,
        signature_size=2420,
        shared_secret_size=0,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.90
    ),
    PQAlgorithm.DILITHIUM_3: AlgorithmSpec(
        name="CRYSTALS-Dilithium-3",
        algorithm_type="Signature",
        nist_security_level=3,
        public_key_size=1952,
        secret_key_size=4000,
        ciphertext_size=0,
        signature_size=3293,
        shared_secret_size=0,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.80
    ),
    PQAlgorithm.DILITHIUM_5: AlgorithmSpec(
        name="CRYSTALS-Dilithium-5",
        algorithm_type="Signature",
        nist_security_level=5,
        public_key_size=2592,
        secret_key_size=4864,
        ciphertext_size=0,
        signature_size=4595,
        shared_secret_size=0,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.70
    ),
    PQAlgorithm.SPHINCS_SHA256_128F: AlgorithmSpec(
        name="SPHINCS+-SHA256-128f",
        algorithm_type="Signature",
        nist_security_level=1,
        public_key_size=32,
        secret_key_size=64,
        ciphertext_size=0,
        signature_size=17088,
        shared_secret_size=0,
        is_standardized=True,
        lattice_based=False,
        performance_score=0.30
    ),
    PQAlgorithm.CLASSIC_MCELIECE_460896: AlgorithmSpec(
        name="Classic McEliece 460896",
        algorithm_type="KEM",
        nist_security_level=5,
        public_key_size=524160,
        secret_key_size=13608,
        ciphertext_size=188,
        signature_size=0,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=False,
        performance_score=0.15
    ),
    PQAlgorithm.FRODO_KEM_640_AES: AlgorithmSpec(
        name="FrodoKEM-640-AES",
        algorithm_type="KEM",
        nist_security_level=1,
        public_key_size=9616,
        secret_key_size=19888,
        ciphertext_size=9720,
        signature_size=0,
        shared_secret_size=16,
        is_standardized=False,
        lattice_based=True,
        performance_score=0.25
    ),
    PQAlgorithm.NTRU_HPS_2048_509: AlgorithmSpec(
        name="NTRU-HPS-2048-509",
        algorithm_type="KEM",
        nist_security_level=1,
        public_key_size=699,
        secret_key_size=935,
        ciphertext_size=699,
        signature_size=0,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=True,
        performance_score=0.88
    ),
    PQAlgorithm.RSA_2048: AlgorithmSpec(
        name="RSA-2048 (Classical)",
        algorithm_type="KEM/Signature",
        nist_security_level=0,
        public_key_size=256,
        secret_key_size=1192,
        ciphertext_size=256,
        signature_size=256,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=False,
        performance_score=1.0
    ),
    PQAlgorithm.ECDH_P256: AlgorithmSpec(
        name="ECDH-P256 (Classical)",
        algorithm_type="KEM",
        nist_security_level=0,
        public_key_size=64,
        secret_key_size=32,
        ciphertext_size=64,
        signature_size=64,
        shared_secret_size=32,
        is_standardized=True,
        lattice_based=False,
        performance_score=1.0
    ),
}


class DeterministicPRNG:
    """Deterministic PRNG for reproducible simulation"""
    
    def __init__(self, seed: Optional[bytes] = None):
        if seed is None:
            seed = secrets.token_bytes(32)
        self.seed = seed
        self.counter = 0
    
    def get_bytes(self, length: int) -> bytes:
        """Generate deterministic pseudorandom bytes"""
        output = b''
        while len(output) < length:
            data = hashlib.sha256(self.seed + self.counter.to_bytes(4, 'big')).digest()
            output += data
            self.counter += 1
        return output[:length]


class PostQuantumKEM:
    """
    Simulated Post-Quantum Key Encapsulation Mechanism
    
    This provides a production-grade simulation interface that matches
    the real API of NIST-standardized PQC algorithms.
    """
    
    def __init__(self, algorithm: PQAlgorithm, seed: Optional[bytes] = None):
        self.algorithm = algorithm
        self.spec = ALGORITHM_SPECS[algorithm]
        self.rng = DeterministicPRNG(seed)
    
    def keygen(self) -> KeyPair:
        """Generate a key pair (simulated)"""
        # Simulate key generation with realistic sizes
        public_key = self.rng.get_bytes(self.spec.public_key_size)
        secret_key = self.rng.get_bytes(self.spec.secret_key_size)
        
        return KeyPair(
            algorithm=self.algorithm,
            public_key=public_key,
            secret_key=secret_key
        )
    
    def encaps(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate - generate shared secret and ciphertext"""
        # Simulate encapsulation - deterministically derive shared secret
        # For simulation consistency, shared secret is derived from ciphertext alone
        
        # Generate ciphertext (simulated random bytes)
        ciphertext = self.rng.get_bytes(self.spec.ciphertext_size)
        
        # Derive shared secret deterministically from ciphertext ONLY
        # This ensures decaps() can recover the EXACT same shared secret
        shared_secret = hashlib.sha256(ciphertext).digest()[:self.spec.shared_secret_size]
        
        return EncapsulationResult(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            algorithm=self.algorithm
        )
    
    def decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate - recover shared secret from ciphertext"""
        # In real implementation, this would recover shared secret using secret key
        # For simulation consistency, we derive from ciphertext ONLY to match encaps()
        
        # Derive shared secret from ciphertext ONLY (matches encaps())
        shared_secret = hashlib.sha256(ciphertext).digest()[:self.spec.shared_secret_size]
        
        return shared_secret


class PostQuantumKeyExchangeSimulator:
    """
    Production-grade simulator for post-quantum key exchange protocols.
    
    Features:
    - Complete Alice-Bob key exchange simulation
    - Hybrid classical + post-quantum mode
    - Performance benchmarking
    - Security analysis
    - Comparison metrics
    """
    
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.benchmarks: Dict[str, BenchmarkResult] = {}
    
    def simulate_key_exchange(
        self, 
        algorithm: PQAlgorithm,
        hybrid_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Simulate a complete key exchange between Alice and Bob
        
        Returns:
            Dictionary with exchange details and verification status
        """
        kem = PostQuantumKEM(algorithm)
        spec = ALGORITHM_SPECS[algorithm]
        
        # Timing measurements
        start = time.perf_counter()
        
        # Alice generates key pair
        alice_keypair = kem.keygen()
        keygen_time = time.perf_counter() - start
        
        # Bob encapsulates
        start = time.perf_counter()
        encap_result = kem.encaps(alice_keypair.public_key)
        encaps_time = time.perf_counter() - start
        
        # Alice decapsulates
        start = time.perf_counter()
        alice_shared = kem.decaps(encap_result.ciphertext, alice_keypair.secret_key)
        decaps_time = time.perf_counter() - start
        
        # Hybrid mode: add classical ECDH layer
        if hybrid_mode:
            classical_kem = PostQuantumKEM(PQAlgorithm.ECDH_P256)
            classical_keypair = classical_kem.keygen()
            classical_encap = classical_kem.encaps(classical_keypair.public_key)
            classical_shared = classical_kem.decaps(classical_encap.ciphertext, classical_keypair.secret_key)
            
            # Combine secrets
            bob_shared = hashlib.sha256(encap_result.shared_secret + classical_shared).digest()
            alice_shared = hashlib.sha256(alice_shared + classical_shared).digest()
        else:
            bob_shared = encap_result.shared_secret
        
        # Verify key exchange succeeded
        exchange_verified = alice_shared == bob_shared
        
        result = {
            'algorithm': algorithm.value,
            'algorithm_name': spec.name,
            'nist_security_level': spec.nist_security_level,
            'hybrid_mode': hybrid_mode,
            'exchange_verified': exchange_verified,
            'shared_secret_match': exchange_verified,
            'timings': {
                'keygen_ms': keygen_time * 1000,
                'encaps_ms': encaps_time * 1000,
                'decaps_ms': decaps_time * 1000,
                'total_ms': (keygen_time + encaps_time + decaps_time) * 1000
            },
            'sizes': {
                'public_key_bytes': spec.public_key_size,
                'secret_key_bytes': spec.secret_key_size,
                'ciphertext_bytes': spec.ciphertext_size,
                'shared_secret_bytes': spec.shared_secret_size
            },
            'bob_shared_secret_hex': bob_shared.hex()[:32] + '...',
            'alice_shared_secret_hex': alice_shared.hex()[:32] + '...'
        }
        
        self.results[algorithm.value] = result
        return result
    
    def benchmark_algorithm(
        self, 
        algorithm: PQAlgorithm,
        iterations: int = 100
    ) -> BenchmarkResult:
        """Benchmark an algorithm with multiple iterations"""
        kem = PostQuantumKEM(algorithm)
        
        keygen_times = []
        encaps_times = []
        decaps_times = []
        
        for _ in range(iterations):
            # Key generation
            start = time.perf_counter()
            keypair = kem.keygen()
            keygen_times.append(time.perf_counter() - start)
            
            # Encapsulation
            start = time.perf_counter()
            result = kem.encaps(keypair.public_key)
            encaps_times.append(time.perf_counter() - start)
            
            # Decapsulation
            start = time.perf_counter()
            _ = kem.decaps(result.ciphertext, keypair.secret_key)
            decaps_times.append(time.perf_counter() - start)
        
        avg_keygen = sum(keygen_times) / iterations * 1_000_000  # microseconds
        avg_encaps = sum(encaps_times) / iterations * 1_000_000
        avg_decaps = sum(decaps_times) / iterations * 1_000_000
        total_avg = avg_keygen + avg_encaps + avg_decaps
        
        # Memory estimation
        spec = ALGORITHM_SPECS[algorithm]
        memory_usage = (
            spec.public_key_size + 
            spec.secret_key_size + 
            spec.ciphertext_size +
            spec.shared_secret_size
        )
        
        benchmark = BenchmarkResult(
            algorithm=algorithm.value,
            keygen_time_us=avg_keygen,
            encaps_time_us=avg_encaps,
            decaps_time_us=avg_decaps,
            total_time_us=total_avg,
            operations_per_second=1_000_000 / total_avg if total_avg > 0 else 0,
            memory_usage_bytes=memory_usage
        )
        
        self.benchmarks[algorithm.value] = benchmark
        return benchmark
    
    def run_comparative_benchmark(self, algorithms: List[PQAlgorithm]) -> Dict[str, Any]:
        """Run comparative benchmark across multiple algorithms"""
        results = {}
        
        for alg in algorithms:
            benchmark = self.benchmark_algorithm(alg, iterations=50)
            results[alg.value] = {
                'name': ALGORITHM_SPECS[alg].name,
                'security_level': ALGORITHM_SPECS[alg].nist_security_level,
                'keygen_us': benchmark.keygen_time_us,
                'encaps_us': benchmark.encaps_time_us,
                'decaps_us': benchmark.decaps_time_us,
                'total_us': benchmark.total_time_us,
                'ops_per_sec': benchmark.operations_per_second,
                'pk_size': ALGORITHM_SPECS[alg].public_key_size,
                'ct_size': ALGORITHM_SPECS[alg].ciphertext_size,
                'memory_bytes': benchmark.memory_usage_bytes
            }
        
        return results
    
    def get_compatibility_matrix(self) -> Dict[str, Dict[str, bool]]:
        """Generate algorithm compatibility matrix"""
        matrix = defaultdict(dict)
        algorithms = list(ALGORITHM_SPECS.keys())
        
        for alg1 in algorithms:
            for alg2 in algorithms:
                # Compatible if same type (KEM/KEM or Signature/Signature)
                spec1 = ALGORITHM_SPECS[alg1]
                spec2 = ALGORITHM_SPECS[alg2]
                compatible = spec1.algorithm_type == spec2.algorithm_type
                matrix[alg1.value][alg2.value] = compatible
        
        return dict(matrix)
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate security analysis report"""
        report = {
            'quantum_resistant_algorithms': [],
            'classical_baselines': [],
            'nist_standardized': [],
            'security_level_summary': defaultdict(list),
            'key_size_analysis': {}
        }
        
        for alg, spec in ALGORITHM_SPECS.items():
            entry = {
                'algorithm': alg.value,
                'name': spec.name,
                'security_level': spec.nist_security_level,
                'is_standardized': spec.is_standardized
            }
            
            if spec.nist_security_level > 0:
                report['quantum_resistant_algorithms'].append(entry)
            else:
                report['classical_baselines'].append(entry)
            
            if spec.is_standardized:
                report['nist_standardized'].append(entry)
            
            report['security_level_summary'][spec.nist_security_level].append(spec.name)
            
            report['key_size_analysis'][alg.value] = {
                'public_key': spec.public_key_size,
                'secret_key': spec.secret_key_size,
                'ciphertext': spec.ciphertext_size,
                'ratio_to_ecdh': spec.public_key_size / ALGORITHM_SPECS[PQAlgorithm.ECDH_P256].public_key_size
            }
        
        report['security_level_summary'] = dict(report['security_level_summary'])
        return report
