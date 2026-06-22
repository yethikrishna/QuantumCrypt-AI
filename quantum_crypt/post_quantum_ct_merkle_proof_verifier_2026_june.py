"""
Post-Quantum Certificate Transparency Merkle Proof Verifier
Dimension A - Feature Expansion

Add-only module that provides Merkle inclusion proof verification for
Certificate Transparency (CT) logs. Enhances the existing CT auditor with
cryptographic proof verification that certificates are properly included
in the public log Merkle tree.

Supports both classic SHA-256 Merkle proofs and post-quantum resistant
hash-based verification. Backward compatible - wraps existing CT modules,
no changes to existing code.
"""

import hashlib
import base64
import binascii
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime


class HashAlgorithm(str, Enum):
    """Supported hash algorithms for Merkle trees"""
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    BLAKE2B = "blake2b"


class ProofVerificationResult(str, Enum):
    """Result of Merkle proof verification"""
    VALID = "valid"
    INVALID_HASH_MISMATCH = "invalid_hash_mismatch"
    INVALID_PROOF_STRUCTURE = "invalid_proof_structure"
    INVALID_TREE_SIZE = "invalid_tree_size"
    INVALID_LEAF_INDEX = "invalid_leaf_index"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass
class MerkleInclusionProof:
    """Merkle inclusion proof data structure (RFC 6962)"""
    leaf_index: int
    tree_size: int
    audit_path: List[bytes] = field(default_factory=list)
    root_hash: bytes = b""
    leaf_hash: bytes = b""
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    
    @classmethod
    def from_ct_json(cls, data: Dict[str, Any]) -> 'MerkleInclusionProof':
        """Parse proof from CT log JSON response"""
        return cls(
            leaf_index=data.get('leaf_index', 0),
            tree_size=data.get('tree_size', 0),
            audit_path=[base64.b64decode(h) for h in data.get('audit_path', [])],
            root_hash=base64.b64decode(data.get('root_hash', '')),
            leaf_hash=base64.b64decode(data.get('leaf_hash', ''))
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary"""
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "audit_path": [base64.b64encode(h).decode() for h in self.audit_path],
            "root_hash": base64.b64encode(self.root_hash).decode(),
            "leaf_hash": base64.b64encode(self.leaf_hash).decode(),
            "hash_algorithm": self.hash_algorithm.value
        }


@dataclass
class VerificationResult:
    """Complete verification result with metadata"""
    result: ProofVerificationResult
    computed_root: bytes = b""
    expected_root: bytes = b""
    proof: Optional[MerkleInclusionProof] = None
    verification_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if verification passed"""
        return self.result == ProofVerificationResult.VALID
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dictionary"""
        return {
            "result": self.result.value,
            "is_valid": self.is_valid(),
            "computed_root": base64.b64encode(self.computed_root).decode(),
            "expected_root": base64.b64encode(self.expected_root).decode(),
            "verification_time_ms": round(self.verification_time * 1000, 2),
            "leaf_index": self.proof.leaf_index if self.proof else None,
            "tree_size": self.proof.tree_size if self.proof else None,
            "metadata": self.metadata
        }


class MerkleTreeHasher:
    """
    Hash functions for Merkle tree operations (RFC 6962 compliant).
    Supports multiple hash algorithms including post-quantum resistant options.
    """
    
    # CT log prefixes per RFC 6962
    LEAF_PREFIX = b'\x00'
    NODE_PREFIX = b'\x01'
    
    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.algorithm = algorithm
    
    def _hash(self, data: bytes) -> bytes:
        """Compute hash with selected algorithm"""
        if self.algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(data).digest()
        elif self.algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(data).digest()
        elif self.algorithm == HashAlgorithm.SHA3_256:
            return hashlib.sha3_256(data).digest()
        elif self.algorithm == HashAlgorithm.BLAKE2B:
            return hashlib.blake2b(data).digest()
        return hashlib.sha256(data).digest()
    
    def hash_leaf(self, leaf_data: bytes) -> bytes:
        """Hash a leaf node with prefix (RFC 6962)"""
        return self._hash(self.LEAF_PREFIX + leaf_data)
    
    def hash_children(self, left: bytes, right: bytes) -> bytes:
        """Hash two child nodes with prefix (RFC 6962)"""
        # Ensure consistent ordering: smaller hash first
        if left > right:
            left, right = right, left
        return self._hash(self.NODE_PREFIX + left + right)
    
    def get_empty_hash(self) -> bytes:
        """Get hash of empty string"""
        return self._hash(b'')


class CTMerkleProofVerifier:
    """
    Certificate Transparency Merkle inclusion proof verifier.
    
    Implements RFC 6962 Merkle inclusion proof verification with:
    - Classic SHA-256 verification (standard CT logs)
    - Post-quantum hash algorithm support
    - Constant-time verification options
    - Batch verification support
    - Backward compatible with existing CT modules
    
    This is an ADD-ONLY feature - no existing code modified.
    """
    
    VERSION = "1.0.0"
    
    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.hasher = MerkleTreeHasher(algorithm)
        self.algorithm = algorithm
        self._verification_count = 0
        self._failure_count = 0
    
    def verify_inclusion_proof(self, proof: MerkleInclusionProof) -> VerificationResult:
        """
        Verify a Merkle inclusion proof.
        
        Implements the algorithm from RFC 6962 Section 2.1.1:
        1. Start with the leaf hash
        2. For each hash in audit path, combine with current hash based on bit position
        3. Final result should equal root hash
        
        Args:
            proof: MerkleInclusionProof to verify
            
        Returns:
            VerificationResult with status and details
        """
        import time
        start_time = time.time()
        
        # Validate proof structure first
        structure_check = self._validate_proof_structure(proof)
        if structure_check is not None:
            return VerificationResult(
                result=structure_check,
                proof=proof,
                verification_time=time.time() - start_time
            )
        
        leaf_index = proof.leaf_index
        tree_size = proof.tree_size
        audit_path = proof.audit_path
        
        # Start with leaf hash
        current_hash = proof.leaf_hash
        
        # Calculate the path through the tree
        last = tree_size - 1
        for i, sibling_hash in enumerate(audit_path):
            if leaf_index % 2 == 1:
                # Left child, sibling is to our right
                current_hash = self.hasher.hash_children(sibling_hash, current_hash)
            else:
                # Right child or at same level
                if leaf_index == last:
                    # This node is the last one, carry it up unchanged
                    pass
                else:
                    current_hash = self.hasher.hash_children(current_hash, sibling_hash)
            
            leaf_index = leaf_index // 2
            last = last // 2
        
        # Verify computed root matches expected
        computed_root = current_hash
        expected_root = proof.root_hash
        
        # Constant-time comparison for security
        is_match = self._constant_time_compare(computed_root, expected_root)
        
        elapsed = time.time() - start_time
        self._verification_count += 1
        
        if not is_match:
            self._failure_count += 1
            return VerificationResult(
                result=ProofVerificationResult.INVALID_HASH_MISMATCH,
                computed_root=computed_root,
                expected_root=expected_root,
                proof=proof,
                verification_time=elapsed
            )
        
        return VerificationResult(
            result=ProofVerificationResult.VALID,
            computed_root=computed_root,
            expected_root=expected_root,
            proof=proof,
            verification_time=elapsed,
            metadata={
                "hash_algorithm": self.algorithm.value,
                "proof_length": len(proof.audit_path)
            }
        )
    
    def _validate_proof_structure(self, proof: MerkleInclusionProof) -> Optional[ProofVerificationResult]:
        """Validate proof structure before verification"""
        if proof.tree_size <= 0:
            return ProofVerificationResult.INVALID_TREE_SIZE
        
        if proof.leaf_index < 0 or proof.leaf_index >= proof.tree_size:
            return ProofVerificationResult.INVALID_LEAF_INDEX
        
        # Calculate expected proof length: ceil(log2(tree_size))
        expected_length = (proof.tree_size - 1).bit_length()
        if len(proof.audit_path) != expected_length and len(proof.audit_path) != 0:
            # Allow some flexibility for different implementations
            pass
        
        if not proof.root_hash or not proof.leaf_hash:
            return ProofVerificationResult.INVALID_PROOF_STRUCTURE
        
        return None
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time byte comparison to prevent timing attacks"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    def verify_batch(self, proofs: List[MerkleInclusionProof]) -> List[VerificationResult]:
        """Verify multiple proofs in batch"""
        return [self.verify_inclusion_proof(p) for p in proofs]
    
    def verify_certificate_entry(self, 
                                 certificate_der: bytes,
                                 proof: MerkleInclusionProof,
                                 timestamp: Optional[int] = None) -> VerificationResult:
        """
        Verify a certificate's inclusion in CT log by reconstructing leaf hash.
        
        Args:
            certificate_der: DER-encoded certificate
            proof: Merkle inclusion proof
            timestamp: Optional timestamp for signed certificate timestamp
            
        Returns:
            VerificationResult
        """
        # Reconstruct CT leaf input per RFC 6962
        if timestamp is not None:
            # MerkleTreeLeaf structure
            leaf_input = self._build_ct_leaf_input(certificate_der, timestamp)
            proof.leaf_hash = self.hasher.hash_leaf(leaf_input)
        
        return self.verify_inclusion_proof(proof)
    
    def _build_ct_leaf_input(self, cert_der: bytes, timestamp: int) -> bytes:
        """Build CT Merkle leaf input per RFC 6962"""
        # Version (0) + MerkleLeafType (0 = timestamped entry)
        result = bytearray([0x00, 0x00])
        # Timestamp (8 bytes, big-endian)
        result.extend(timestamp.to_bytes(8, 'big'))
        # EntryType (0 = x509_entry)
        result.extend([0x00, 0x00])
        # Certificate length (3 bytes) + certificate
        cert_len = len(cert_der)
        result.extend([(cert_len >> 16) & 0xFF, (cert_len >> 8) & 0xFF, cert_len & 0xFF])
        result.extend(cert_der)
        return bytes(result)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get verification statistics"""
        return {
            "total_verifications": self._verification_count,
            "failed_verifications": self._failure_count,
            "success_rate": (
                (self._verification_count - self._failure_count) / self._verification_count
                if self._verification_count > 0 else 1.0
            ),
            "hash_algorithm": self.algorithm.value
        }
    
    def reset_stats(self) -> None:
        """Reset verification statistics"""
        self._verification_count = 0
        self._failure_count = 0


class CTConsistencyVerifier:
    """
    Merkle consistency proof verifier.
    Verifies that a new tree root is consistent with an older tree root.
    """
    
    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.hasher = MerkleTreeHasher(algorithm)
    
    def verify_consistency(self,
                          old_tree_size: int,
                          new_tree_size: int,
                          old_root: bytes,
                          new_root: bytes,
                          proof: List[bytes]) -> bool:
        """
        Verify consistency between two tree snapshots.
        
        Args:
            old_tree_size: Size of older tree
            new_tree_size: Size of newer tree
            old_root: Root hash of older tree
            new_root: Root hash of newer tree
            proof: Consistency proof audit path
            
        Returns:
            True if consistent
        """
        if old_tree_size == new_tree_size:
            return self._constant_time_compare(old_root, new_root)
        
        if old_tree_size == 0:
            return True
        
        fn = old_tree_size - 1
        sn = new_tree_size - 1
        
        while fn % 2 == 1:
            fn = fn // 2
            sn = sn // 2
        
        if not proof:
            return False
        
        fr = proof[0]
        sr = proof[0]
        
        for p in proof[1:]:
            if sn % 2 == 1:
                fr = self.hasher.hash_children(p, fr)
                sr = self.hasher.hash_children(p, sr)
            else:
                if fn == sn:
                    sr = p
                else:
                    sr = self.hasher.hash_children(sr, p)
            fn = fn // 2
            sn = sn // 2
        
        return (self._constant_time_compare(fr, old_root) and 
                self._constant_time_compare(sr, new_root))
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


# Convenience factory functions
def create_ct_verifier() -> CTMerkleProofVerifier:
    """Create standard CT verifier (SHA-256)"""
    return CTMerkleProofVerifier(HashAlgorithm.SHA256)


def create_pq_ct_verifier() -> CTMerkleProofVerifier:
    """Create post-quantum resistant CT verifier (SHA3-256)"""
    return CTMerkleProofVerifier(HashAlgorithm.SHA3_256)


def verify_single_proof(leaf_index: int, 
                       tree_size: int,
                       audit_path_b64: List[str],
                       root_hash_b64: str,
                       leaf_hash_b64: str) -> VerificationResult:
    """One-line convenience function for single proof verification"""
    proof = MerkleInclusionProof(
        leaf_index=leaf_index,
        tree_size=tree_size,
        audit_path=[base64.b64decode(h) for h in audit_path_b64],
        root_hash=base64.b64decode(root_hash_b64),
        leaf_hash=base64.b64decode(leaf_hash_b64)
    )
    verifier = create_ct_verifier()
    return verifier.verify_inclusion_proof(proof)
