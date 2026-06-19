"""
Post-Quantum Secure Checksum Verifier
Real production-grade implementation for QuantumCrypt-AI

This module provides cryptographic checksum and hash verification capabilities
using post-quantum resistant algorithms. Implements SHA-2/3, BLAKE2, and
hash-based verification with integrity checking suitable for post-quantum era.

Features:
- Multiple hash algorithm support (SHA-256, SHA-512, SHA3-256, BLAKE2b, BLAKE2s)
- File integrity verification
- Streaming hash computation for large files
- Hash chain verification
- HMAC support
- Checksum batch verification
"""

import hashlib
import hmac
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union, BinaryIO
from dataclasses import dataclass, asdict, field
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ChecksumResult:
    """Result of a checksum computation or verification"""
    file_path: str
    algorithm: str
    checksum: str
    file_size: int = 0
    computation_time_ms: float = 0.0
    verified: bool = False
    expected_checksum: Optional[str] = None
    timestamp: str = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


@dataclass
class HashChainEntry:
    """Entry in a hash chain"""
    index: int
    data_hash: str
    previous_hash: str
    chain_hash: str
    timestamp: str


class HashAlgorithms:
    """Supported hash algorithms"""
    
    SHA256 = 'sha256'
    SHA512 = 'sha512'
    SHA3_256 = 'sha3_256'
    SHA3_512 = 'sha3_512'
    BLAKE2B = 'blake2b'
    BLAKE2S = 'blake2s'
    
    ALL = [SHA256, SHA512, SHA3_256, SHA3_512, BLAKE2B, BLAKE2S]
    
    # Algorithms considered post-quantum resistant (hash-based)
    PQ_RESISTANT = [SHA3_256, SHA3_512, BLAKE2B, BLAKE2S, SHA512]
    
    @classmethod
    def is_supported(cls, algorithm: str) -> bool:
        return algorithm.lower() in cls.ALL
    
    @classmethod
    def is_post_quantum_resistant(cls, algorithm: str) -> bool:
        return algorithm.lower() in cls.PQ_RESISTANT


class ChecksumHasher:
    """Core hashing engine for checksum computation"""
    
    CHUNK_SIZE = 64 * 1024  # 64KB chunks for streaming
    
    def __init__(self, algorithm: str = HashAlgorithms.SHA3_256):
        algorithm = algorithm.lower()
        if not HashAlgorithms.is_supported(algorithm):
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of: {HashAlgorithms.ALL}")
        self.algorithm = algorithm
    
    def _get_hash_object(self):
        """Get appropriate hash object based on algorithm"""
        if self.algorithm == HashAlgorithms.SHA256:
            return hashlib.sha256()
        elif self.algorithm == HashAlgorithms.SHA512:
            return hashlib.sha512()
        elif self.algorithm == HashAlgorithms.SHA3_256:
            return hashlib.sha3_256()
        elif self.algorithm == HashAlgorithms.SHA3_512:
            return hashlib.sha3_512()
        elif self.algorithm == HashAlgorithms.BLAKE2B:
            return hashlib.blake2b()
        elif self.algorithm == HashAlgorithms.BLAKE2S:
            return hashlib.blake2s()
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")
    
    def hash_bytes(self, data: bytes) -> str:
        """Hash bytes data"""
        hash_obj = self._get_hash_object()
        hash_obj.update(data)
        return hash_obj.hexdigest()
    
    def hash_string(self, text: str, encoding: str = 'utf-8') -> str:
        """Hash string data"""
        return self.hash_bytes(text.encode(encoding))
    
    def hash_file(self, file_path: Union[str, Path]) -> Tuple[str, int]:
        """Hash file contents with streaming (memory efficient)"""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")
        
        hash_obj = self._get_hash_object()
        total_size = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                hash_obj.update(chunk)
                total_size += len(chunk)
        
        return hash_obj.hexdigest(), total_size
    
    def hash_stream(self, stream: BinaryIO) -> Tuple[str, int]:
        """Hash from a file-like stream"""
        hash_obj = self._get_hash_object()
        total_size = 0
        
        while True:
            chunk = stream.read(self.CHUNK_SIZE)
            if not chunk:
                break
            hash_obj.update(chunk)
            total_size += len(chunk)
        
        return hash_obj.hexdigest(), total_size
    
    def compute_hmac(self, data: bytes, key: bytes) -> str:
        """Compute HMAC for data"""
        # Map algorithm names to HMAC-compatible digestmod
        digest_map = {
            HashAlgorithms.SHA256: 'sha256',
            HashAlgorithms.SHA512: 'sha512',
            HashAlgorithms.SHA3_256: 'sha3_256',
            HashAlgorithms.SHA3_512: 'sha3_512',
        }
        
        if self.algorithm not in digest_map:
            raise ValueError(f"HMAC not supported for {self.algorithm}, use SHA-2 or SHA-3")
        
        return hmac.new(key, data, digest_map[self.algorithm]).hexdigest()


class ChecksumVerifier:
    """Checksum verification engine"""
    
    def __init__(self, default_algorithm: str = HashAlgorithms.SHA3_256):
        self.default_algorithm = default_algorithm
        self.stats = {
            'files_computed': 0,
            'files_verified': 0,
            'verifications_passed': 0,
            'verifications_failed': 0,
            'total_bytes_processed': 0,
        }
    
    def compute_checksum(self, 
                        file_path: Union[str, Path],
                        algorithm: Optional[str] = None) -> ChecksumResult:
        """Compute checksum for a single file"""
        algo = algorithm or self.default_algorithm
        hasher = ChecksumHasher(algo)
        start_time = time.time()
        
        checksum, file_size = hasher.hash_file(file_path)
        elapsed_ms = (time.time() - start_time) * 1000
        
        self.stats['files_computed'] += 1
        self.stats['total_bytes_processed'] += file_size
        
        return ChecksumResult(
            file_path=str(file_path),
            algorithm=algo,
            checksum=checksum,
            file_size=file_size,
            computation_time_ms=elapsed_ms
        )
    
    def verify_checksum(self,
                       file_path: Union[str, Path],
                       expected_checksum: str,
                       algorithm: Optional[str] = None) -> ChecksumResult:
        """Verify file checksum against expected value"""
        result = self.compute_checksum(file_path, algorithm)
        result.expected_checksum = expected_checksum
        result.verified = (result.checksum.lower() == expected_checksum.lower())
        
        self.stats['files_verified'] += 1
        if result.verified:
            self.stats['verifications_passed'] += 1
        else:
            self.stats['verifications_failed'] += 1
        
        return result
    
    def compute_directory(self,
                         directory: Union[str, Path],
                         algorithm: Optional[str] = None,
                         recursive: bool = True,
                         extensions: Optional[List[str]] = None) -> List[ChecksumResult]:
        """Compute checksums for all files in a directory"""
        directory = Path(directory)
        results = []
        
        pattern = '**/*' if recursive else '*'
        
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                if extensions:
                    if file_path.suffix.lower() not in [e.lower() for e in extensions]:
                        continue
                try:
                    result = self.compute_checksum(file_path, algorithm)
                    results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to hash {file_path}: {e}")
        
        return results
    
    def verify_manifest(self,
                       manifest_path: Union[str, Path],
                       base_dir: Optional[Union[str, Path]] = None) -> List[ChecksumResult]:
        """Verify files against a checksum manifest"""
        manifest_path = Path(manifest_path)
        base_dir = Path(base_dir) if base_dir else manifest_path.parent
        
        with open(manifest_path, 'r') as f:
            if manifest_path.suffix == '.json':
                manifest = json.load(f)
                entries = manifest.get('checksums', [])
            else:
                # Simple text format: checksum  filename
                entries = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            entries.append({
                                'checksum': parts[0],
                                'file_path': parts[1]
                            })
        
        results = []
        for entry in entries:
            file_path = base_dir / entry['file_path']
            if file_path.exists():
                algo = entry.get('algorithm', self.default_algorithm)
                result = self.verify_checksum(
                    file_path,
                    entry['checksum'],
                    algo
                )
                results.append(result)
        
        return results
    
    def generate_manifest(self,
                         results: List[ChecksumResult],
                         output_path: Union[str, Path]) -> bool:
        """Generate checksum manifest file"""
        try:
            manifest = {
                'generated_at': datetime.utcnow().isoformat() + "Z",
                'algorithm': self.default_algorithm,
                'total_files': len(results),
                'checksums': [
                    {
                        'file_path': r.file_path,
                        'checksum': r.checksum,
                        'algorithm': r.algorithm,
                        'file_size': r.file_size
                    }
                    for r in results
                ]
            }
            
            with open(output_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to generate manifest: {e}")
            return False


class HashChain:
    """Hash chain implementation for sequential integrity verification"""
    
    def __init__(self, algorithm: str = HashAlgorithms.SHA3_256):
        self.hasher = ChecksumHasher(algorithm)
        self.algorithm = algorithm
        self.chain: List[HashChainEntry] = []
        self.genesis_hash: Optional[str] = None
    
    def initialize(self, genesis_data: Union[str, bytes] = b"GENESIS") -> str:
        """Initialize hash chain with genesis block"""
        if isinstance(genesis_data, str):
            genesis_data = genesis_data.encode('utf-8')
        
        self.genesis_hash = self.hasher.hash_bytes(genesis_data)
        self.chain = []
        return self.genesis_hash
    
    def add_entry(self, data: Union[str, bytes]) -> HashChainEntry:
        """Add new entry to hash chain"""
        if not self.genesis_hash:
            self.initialize()
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        index = len(self.chain)
        data_hash = self.hasher.hash_bytes(data)
        
        previous_hash = self.chain[-1].chain_hash if self.chain else self.genesis_hash
        
        # Chain hash = H(previous_hash + data_hash)
        chain_input = previous_hash + data_hash
        chain_hash = self.hasher.hash_string(chain_input)
        
        entry = HashChainEntry(
            index=index,
            data_hash=data_hash,
            previous_hash=previous_hash,
            chain_hash=chain_hash,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )
        
        self.chain.append(entry)
        return entry
    
    def verify_chain(self) -> Tuple[bool, List[int]]:
        """Verify entire hash chain integrity"""
        if not self.genesis_hash:
            return False, [-1]
        
        invalid_indices = []
        previous_hash = self.genesis_hash
        
        for entry in self.chain:
            expected_chain_input = previous_hash + entry.data_hash
            expected_chain_hash = self.hasher.hash_string(expected_chain_input)
            
            if entry.chain_hash != expected_chain_hash:
                invalid_indices.append(entry.index)
            else:
                previous_hash = entry.chain_hash
        
        return len(invalid_indices) == 0, invalid_indices
    
    def get_root_hash(self) -> Optional[str]:
        """Get current chain root hash"""
        if self.chain:
            return self.chain[-1].chain_hash
        return self.genesis_hash
    
    def export_chain(self, filepath: Union[str, Path]) -> bool:
        """Export hash chain to JSON file"""
        try:
            data = {
                'algorithm': self.algorithm,
                'genesis_hash': self.genesis_hash,
                'root_hash': self.get_root_hash(),
                'chain_length': len(self.chain),
                'entries': [asdict(e) for e in self.chain]
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export chain: {e}")
            return False


class MultiAlgorithmVerifier:
    """Multi-algorithm verification for enhanced security"""
    
    def __init__(self, algorithms: Optional[List[str]] = None):
        self.algorithms = algorithms or HashAlgorithms.PQ_RESISTANT
        self.hashers = {algo: ChecksumHasher(algo) for algo in self.algorithms}
    
    def multi_hash(self, data: Union[bytes, str, Path]) -> Dict[str, str]:
        """Compute multiple hashes for the same data"""
        results = {}
        
        if isinstance(data, Path) or (isinstance(data, str) and os.path.isfile(data)):
            # It's a file
            file_path = Path(data)
            for algo, hasher in self.hashers.items():
                checksum, _ = hasher.hash_file(file_path)
                results[algo] = checksum
        elif isinstance(data, bytes):
            for algo, hasher in self.hashers.items():
                results[algo] = hasher.hash_bytes(data)
        elif isinstance(data, str):
            for algo, hasher in self.hashers.items():
                results[algo] = hasher.hash_string(data)
        
        return results
    
    def multi_verify(self,
                    data: Union[bytes, str, Path],
                    expected_hashes: Dict[str, str]) -> Tuple[bool, Dict[str, bool]]:
        """Verify against multiple expected hashes"""
        computed = self.multi_hash(data)
        results = {}
        all_passed = True
        
        for algo, expected in expected_hashes.items():
            if algo in computed:
                passed = computed[algo].lower() == expected.lower()
                results[algo] = passed
                if not passed:
                    all_passed = False
            else:
                results[algo] = False
                all_passed = False
        
        return all_passed, results


class PostQuantumChecksumEngine:
    """Main post-quantum checksum verification engine"""
    
    def __init__(self, algorithm: str = HashAlgorithms.SHA3_256):
        self.algorithm = algorithm
        self.verifier = ChecksumVerifier(algorithm)
        self.multi_verifier = MultiAlgorithmVerifier()
        self.hash_chain = HashChain(algorithm)
    
    def compute_file_checksum(self, file_path: str) -> ChecksumResult:
        """Compute checksum for a file"""
        return self.verifier.compute_checksum(file_path)
    
    def verify_file_checksum(self, file_path: str, expected: str) -> ChecksumResult:
        """Verify file checksum"""
        return self.verifier.verify_checksum(file_path, expected)
    
    def compute_string_hash(self, text: str) -> str:
        """Compute hash for a string"""
        hasher = ChecksumHasher(self.algorithm)
        return hasher.hash_string(text)
    
    def create_hash_chain(self, items: List[str]) -> HashChain:
        """Create a hash chain from list of items"""
        chain = HashChain(self.algorithm)
        chain.initialize()
        for item in items:
            chain.add_entry(item)
        return chain
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            'algorithm': self.algorithm,
            'pq_resistant': HashAlgorithms.is_post_quantum_resistant(self.algorithm),
            'supported_algorithms': HashAlgorithms.ALL,
            'pq_algorithms': HashAlgorithms.PQ_RESISTANT,
            'verifier_stats': self.verifier.stats,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }
    
    def get_security_report(self) -> Dict[str, Any]:
        """Get security assessment report"""
        return {
            'algorithm': self.algorithm,
            'post_quantum_resistant': HashAlgorithms.is_post_quantum_resistant(self.algorithm),
            'security_level': {
                HashAlgorithms.SHA256: '128-bit (classical), quantum-vulnerable',
                HashAlgorithms.SHA512: '256-bit (classical), partially quantum-resistant',
                HashAlgorithms.SHA3_256: '256-bit, NIST post-quantum standard',
                HashAlgorithms.SHA3_512: '512-bit, NIST post-quantum standard',
                HashAlgorithms.BLAKE2B: '512-bit, high-performance post-quantum',
                HashAlgorithms.BLAKE2S: '256-bit, high-performance post-quantum',
            }.get(self.algorithm, 'Unknown'),
            'nist_standard': self.algorithm.startswith('sha3'),
            'recommendation': 'SHA3-512 or BLAKE2b recommended for highest security',
        }


# Exports
__all__ = [
    'ChecksumResult',
    'HashChainEntry',
    'HashAlgorithms',
    'ChecksumHasher',
    'ChecksumVerifier',
    'HashChain',
    'MultiAlgorithmVerifier',
    'PostQuantumChecksumEngine',
]
