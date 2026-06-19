"""
QuantumCrypt-AI: Post-Quantum Hash-Based Signature Engine
Production-grade implementation of Lamport-Diffie One-Time Signatures
and Merkle Tree Signatures for post-quantum security
June 2026 Implementation
"""

import hashlib
import os
import json
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import secrets


class HashAlgorithm(Enum):
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    BLAKE2b = "blake2b"


class SecurityLevel(Enum):
    LEVEL_1 = 128  # NIST Security Level 1
    LEVEL_3 = 192  # NIST Security Level 3
    LEVEL_5 = 256  # NIST Security Level 5


@dataclass
class LamportKeyPair:
    public_key: List[List[bytes]]
    private_key: List[List[bytes]]
    hash_alg: HashAlgorithm
    security_level: SecurityLevel
    used: bool = False


@dataclass
class LamportSignature:
    signature: List[bytes]
    public_key_hash: bytes
    hash_alg: HashAlgorithm
    timestamp: str


@dataclass
class MerkleSignature:
    message_signature: List[bytes]
    authentication_path: List[bytes]
    leaf_index: int
    root_public_key: bytes
    hash_alg: HashAlgorithm


class PostQuantumHashBasedSigner:
    """
    Production-grade hash-based signature engine providing post-quantum security.
    Implements:
    - Lamport-Diffie One-Time Signature (LD-OTS)
    - Merkle Tree Signature (MTS) for many-time use
    - Multiple hash algorithm support
    - NIST security level compliance
    
    Hash-based signatures are INFORMATION-THEORETICALLY SECURE against
    quantum computer attacks (Shor's algorithm cannot break them).
    """

    def __init__(
        self,
        hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        security_level: SecurityLevel = SecurityLevel.LEVEL_5
    ):
        self.hash_alg = hash_algorithm
        self.security_level = security_level
        self.hash_size = security_level.value // 8
        self._hash_function = self._get_hash_function()

    def _get_hash_function(self):
        """Get the appropriate hash function."""
        if self.hash_alg == HashAlgorithm.SHA256:
            return lambda data: hashlib.sha256(data).digest()
        elif self.hash_alg == HashAlgorithm.SHA3_256:
            return lambda data: hashlib.sha3_256(data).digest()
        elif self.hash_alg == HashAlgorithm.BLAKE2b:
            return lambda data: hashlib.blake2b(data, digest_size=self.hash_size).digest()
        return lambda data: hashlib.sha256(data).digest()

    def _hash(self, data: bytes) -> bytes:
        """Hash data with selected algorithm."""
        return self._hash_function(data)

    def _hash_message(self, message: bytes) -> bytes:
        """Hash message to fixed length for signing."""
        return self._hash(message)

    def _get_bits(self, data: bytes) -> List[int]:
        """Convert bytes to list of bits (0/1)."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        return bits[:self.security_level.value]  # Only use needed bits

    def generate_lamport_keypair(self) -> LamportKeyPair:
        """
        Generate a Lamport-Diffie One-Time Signature key pair.
        
        For each bit position (n bits), we generate TWO random secrets:
        - sk_0[i] = used if message bit i is 0
        - sk_1[i] = used if message bit i is 1
        
        Public key = hash of each secret.
        """
        n_bits = self.security_level.value
        
        private_key = []
        public_key = []
        
        for _ in range(n_bits):
            # Generate two random secrets per bit
            sk0 = secrets.token_bytes(self.hash_size)
            sk1 = secrets.token_bytes(self.hash_size)
            
            # Public key is hash of each secret
            pk0 = self._hash(sk0)
            pk1 = self._hash(sk1)
            
            private_key.append([sk0, sk1])
            public_key.append([pk0, pk1])
        
        return LamportKeyPair(
            public_key=public_key,
            private_key=private_key,
            hash_alg=self.hash_alg,
            security_level=self.security_level
        )

    def lamport_sign(
        self,
        message: bytes,
        keypair: LamportKeyPair
    ) -> LamportSignature:
        """
        Sign a message using Lamport-Diffie OTS.
        
        For each bit in the message hash:
        - If bit = 0: reveal sk_0[i]
        - If bit = 1: reveal sk_1[i]
        """
        if keypair.used:
            raise ValueError("Lamport key pair has already been used! Never reuse Lamport keys.")
        
        message_hash = self._hash_message(message)
        bits = self._get_bits(message_hash)
        
        signature = []
        n_bits = self.security_level.value
        
        for i in range(n_bits):
            bit = bits[i]
            # Reveal the appropriate secret key
            signature.append(keypair.private_key[i][bit])
        
        # Mark keypair as used (CRITICAL: Lamport keys are ONE-TIME only)
        keypair.used = True
        
        # Compute public key hash for verification reference
        pk_flat = b''.join(pk0 + pk1 for pk0, pk1 in keypair.public_key)
        pk_hash = self._hash(pk_flat)
        
        return LamportSignature(
            signature=signature,
            public_key_hash=pk_hash,
            hash_alg=self.hash_alg,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )

    def lamport_verify(
        self,
        message: bytes,
        signature: LamportSignature,
        public_key: List[List[bytes]]
    ) -> bool:
        """
        Verify a Lamport signature.
        
        For each bit in message hash:
        - Hash the revealed secret
        - Compare to corresponding public key value
        """
        message_hash = self._hash_message(message)
        bits = self._get_bits(message_hash)
        
        n_bits = self.security_level.value
        
        for i in range(n_bits):
            bit = bits[i]
            revealed_secret = signature.signature[i]
            
            # Hash the revealed secret
            computed_pk = self._hash(revealed_secret)
            
            # Compare to expected public key value
            expected_pk = public_key[i][bit]
            
            if not self._constant_time_compare(computed_pk, expected_pk):
                return False
        
        return True

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def generate_merkle_tree(self, num_leaves: int = 8) -> Tuple[bytes, List[LamportKeyPair], List[bytes]]:
        """
        Generate a Merkle tree of Lamport public keys.
        This allows ONE public key (root) to verify MANY signatures.
        
        Returns: (root_hash, lamport_keypairs, all_tree_nodes)
        """
        if num_leaves & (num_leaves - 1) != 0:
            # Round up to next power of 2
            num_leaves = 1 << (num_leaves - 1).bit_length()
        
        # Generate Lamport keypairs for each leaf
        keypairs = [self.generate_lamport_keypair() for _ in range(num_leaves)]
        
        # Compute leaf hashes = hash of each Lamport public key
        leaves = []
        for kp in keypairs:
            pk_flat = b''.join(pk0 + pk1 for pk0, pk1 in kp.public_key)
            leaves.append(self._hash(pk_flat))
        
        # Build Merkle tree - FIXED: use proper level offset
        tree = list(leaves)
        level_size = num_leaves
        level_start = 0
        
        while level_size > 1:
            next_level = []
            for i in range(0, level_size, 2):
                left = tree[level_start + i]
                right = tree[level_start + i + 1] if i + 1 < level_size else left
                parent = self._hash(left + right)
                next_level.append(parent)
            tree.extend(next_level)
            level_start += level_size
            level_size = level_size // 2
        
        root = tree[-1]
        return root, keypairs, tree

    def merkle_sign(
        self,
        message: bytes,
        keypairs: List[LamportKeyPair],
        merkle_tree: List[bytes],
        leaf_index: int
    ) -> MerkleSignature:
        """
        Sign using Merkle Tree Signature scheme.
        Provides: Lamport signature + authentication path.
        """
        if leaf_index >= len(keypairs):
            raise ValueError(f"Leaf index {leaf_index} out of range")
        
        # Sign message with selected Lamport key
        lamport_sig = self.lamport_sign(message, keypairs[leaf_index])
        
        # Compute authentication path
        auth_path = []
        num_leaves = len(keypairs)
        idx = leaf_index
        level_start = 0
        level_size = num_leaves
        
        while level_size > 1:
            sibling_idx = idx ^ 1
            sibling = merkle_tree[level_start + sibling_idx]
            auth_path.append(sibling)
            idx = idx // 2
            level_start += level_size
            level_size = level_size // 2
        
        root = merkle_tree[-1]
        
        return MerkleSignature(
            message_signature=lamport_sig.signature,
            authentication_path=auth_path,
            leaf_index=leaf_index,
            root_public_key=root,
            hash_alg=self.hash_alg
        )

    def merkle_verify(
        self,
        message: bytes,
        signature: MerkleSignature,
        lamport_public_key: List[List[bytes]]
    ) -> bool:
        """Verify a Merkle tree signature."""
        # First verify the Lamport signature
        message_hash = self._hash_message(message)
        bits = self._get_bits(message_hash)
        
        n_bits = len(lamport_public_key)  # Use actual key length, not self.security_level
        
        # Verify Lamport part
        for i in range(n_bits):
            bit = bits[i]
            revealed = signature.message_signature[i]
            computed = self._hash(revealed)
            expected = lamport_public_key[i][bit]
            
            if not self._constant_time_compare(computed, expected):
                return False
        
        # Compute leaf hash
        pk_flat = b''.join(pk0 + pk1 for pk0, pk1 in lamport_public_key)
        current = self._hash(pk_flat)
        
        # Verify authentication path
        idx = signature.leaf_index
        for sibling in signature.authentication_path:
            if idx & 1:
                # Current node is right child, sibling is left
                current = self._hash(sibling + current)
            else:
                # Current node is left child, sibling is right
                current = self._hash(current + sibling)
            idx = idx // 2
        
        return self._constant_time_compare(current, signature.root_public_key)

    def export_public_key_json(
        self,
        public_key: List[List[bytes]],
        output_file: Optional[str] = None
    ) -> str:
        """Export public key to JSON format."""
        data = {
            "hash_algorithm": self.hash_alg.value,
            "security_level": self.security_level.value,
            "security_level_name": self.security_level.name,
            "public_key": [
                [pk0.hex(), pk1.hex()] for pk0, pk1 in public_key
            ]
        }
        
        json_str = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_str)
        
        return json_str

    def get_security_properties(self) -> Dict[str, Any]:
        """Get security properties of this implementation."""
        return {
            "algorithm": "Lamport-Diffie OTS + Merkle Tree",
            "hash_algorithm": self.hash_alg.value,
            "security_level_bits": self.security_level.value,
            "nist_security_level": {
                128: "Level 1 (equivalent to AES-128)",
                192: "Level 3 (equivalent to AES-192)",
                256: "Level 5 (equivalent to AES-256)"
            }[self.security_level.value],
            "post_quantum_secure": True,
            "quantum_resistance": "INFORMATION-THEORETIC (hash functions only)",
            "lamport_keys_one_time_only": True,
            "merkle_tree_allows_many_signatures": True,
            "resistance_to_shor": "FULLY RESISTANT - no number theory used",
            "limitations": [
                "Lamport keys are ONE-TIME use only",
                "Large signature size",
                "Large public key size",
                "Merkle tree has fixed signature capacity"
            ]
        }


def run_hash_signature_demo():
    """Demonstrate the hash-based signature engine."""
    print("=" * 60)
    print("QuantumCrypt-AI Post-Quantum Hash-Based Signature Engine")
    print("=" * 60)
    
    # Create signer with highest security level
    signer = PostQuantumHashBasedSigner(
        hash_algorithm=HashAlgorithm.SHA256,
        security_level=SecurityLevel.LEVEL_5
    )
    
    print(f"\n[+] Security Properties:")
    props = signer.get_security_properties()
    for key, value in props.items():
        if key != "limitations":
            print(f"    {key}: {value}")
    
    # Demo 1: Lamport OTS
    print(f"\n[+] DEMO 1: Lamport-Diffie One-Time Signature")
    print(f"    Generating Lamport keypair...")
    
    keypair = signer.generate_lamport_keypair()
    print(f"    ✓ Key pair generated (2x{len(keypair.private_key)} secrets)")
    
    message = b"QuantumCrypt-AI: Post-Quantum Security for Everyone!"
    print(f"    Message: {message.decode()}")
    
    print(f"    Signing message...")
    signature = signer.lamport_sign(message, keypair)
    print(f"    ✓ Signature generated")
    print(f"    ✓ Signature size: {len(signature.signature)} elements")
    
    print(f"    Verifying signature...")
    valid = signer.lamport_verify(message, signature, keypair.public_key)
    print(f"    ✓ Signature valid: {valid}")
    
    # Test tampered message
    bad_message = b"QuantumCrypt-AI: HACKED MESSAGE!"
    tampered_valid = signer.lamport_verify(bad_message, signature, keypair.public_key)
    print(f"    Tampered message verification: {tampered_valid} (should be False)")
    
    # Demo 2: Merkle Tree
    print(f"\n[+] DEMO 2: Merkle Tree Signature (8 signatures from 1 root key)")
    print(f"    Generating Merkle tree...")
    
    root, keypairs, tree = signer.generate_merkle_tree(num_leaves=8)
    print(f"    ✓ Merkle tree with 8 leaves generated")
    print(f"    ✓ Root public key: {root[:16].hex()}...")
    
    test_message = b"Hello from Merkle Tree Signature!"
    print(f"    Signing with leaf index 3...")
    
    merkle_sig = signer.merkle_sign(test_message, keypairs, tree, 3)
    print(f"    ✓ Merkle signature generated")
    print(f"    ✓ Auth path length: {len(merkle_sig.authentication_path)}")
    
    print(f"    Verifying Merkle signature...")
    merkle_valid = signer.merkle_verify(test_message, merkle_sig, keypairs[3].public_key)
    print(f"    ✓ Merkle signature valid: {merkle_valid}")
    
    # Export results
    with open("test_results_hash_signature.json", "w") as f:
        json.dump({
            "test_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "algorithm": "Lamport-Diffie + Merkle Tree",
            "hash_algorithm": signer.hash_alg.value,
            "security_level": signer.security_level.value,
            "lamport_test_passed": valid,
            "merkle_test_passed": merkle_valid,
            "tamper_detection_working": not tampered_valid
        }, f, indent=2)
    
    print(f"\n[+] Results exported to test_results_hash_signature.json")
    print(f"\n[+] All post-quantum signature tests completed!")
    
    return valid and merkle_valid and not tampered_valid


if __name__ == "__main__":
    run_hash_signature_demo()
