# QuantumCrypt-AI Usage Guide

> Comprehensive usage examples and API reference for post-quantum cryptography

---

## Table of Contents

1. [Key Encapsulation (KEM)](#key-encapsulation-kem)
2. [Key Derivation Functions](#key-derivation-functions)
3. [Message Authentication (MAC)](#message-authentication-mac)
4. [Secure Multi-Party Computation](#secure-multi-party-computation)
5. [Format-Preserving Encryption](#format-preserving-encryption)
6. [Side-Channel Resistance](#side-channel-resistance)
7. [Session Management](#session-management)
8. [Error Resilience](#error-resilience)
9. [Observability](#observability)

---

## Key Encapsulation (KEM)

### Basic Hybrid KEM

```python
from quantum_crypt import PostQuantumHybridKEM

# Initialize KEM engine
kem = PostQuantumHybridKEM(security_level=128)

# Alice generates keypair
alice_secret, alice_public = kem.generate_keypair()

# Bob encapsulates to Alice's public key
ciphertext, shared_secret_bob = kem.encapsulate(alice_public)

# Alice decapsulates using her secret key
shared_secret_alice = kem.decapsulate(ciphertext, alice_secret)

# Verify both parties have same shared secret
assert shared_secret_alice == shared_secret_bob
print("✅ Quantum-secure key exchange successful!")
print(f"Shared secret length: {len(shared_secret_alice)} bytes")
```

### Authenticated KEM with Labels

```python
from quantum_crypt import PostQuantumHybridKEM

kem = PostQuantumHybridKEM()

# Generate keys
sk, pk = kem.generate_keypair()

# Encapsulate with context label (binds ciphertext to context)
context = b"secure_channel_2026_alice_bob"
ct, ss_sender = kem.encapsulate(pk, context_label=context)

# Decapsulate requires same context
ss_receiver = kem.decapsulate(ct, sk, context_label=context)

assert ss_sender == ss_receiver
```

---

## Key Derivation Functions

### Standard HKDF

```python
from quantum_crypt import SecureKeyDerivationFunction

kdf = SecureKeyDerivationFunction(hash_algorithm="sha3-256")

# Input key material (from KEM or other source)
ikm = shared_secret_from_kem

# Derive multiple keys for different purposes
encryption_key = kdf.derive_key(
    ikm,
    salt=b"quantum_encryption_salt",
    info=b"aes-gcm-256-key",
    length=32
)

mac_key = kdf.derive_key(
    ikm,
    salt=b"quantum_mac_salt",
    info=b"hmac-key",
    length=32
)

print(f"Derived encryption key: {encryption_key.hex()[:16]}...")
print(f"Derived MAC key: {mac_key.hex()[:16]}...")
```

### Memory-Hard KDF (High Security)

```python
from quantum_crypt import PostQuantumSecureHKDFMemoryHard

memory_hard_kdf = PostQuantumSecureHKDFMemoryHard(
    memory_cost_mb=64,  # 64MB memory requirement
    iterations=3,
    parallelism=4
)

# Derive key with memory-hard properties
high_security_key = memory_hard_kdf.derive(
    password=b"user_password",
    salt=b"unique_salt_per_user",
    length=32
)

print(f"Memory-hard derived key: {high_security_key.hex()}")
```

### Key Diversification

```python
from quantum_crypt import SecureKeyDiversificationHKDF

master_key = get_root_key_from_hsm()

diversifier = SecureKeyDiversificationHKDF(master_key)

# Derive different keys for different purposes
database_key = diversifier.derive("database_encryption")
api_key = diversifier.derive("external_api_auth")
backup_key = diversifier.derive("backup_encryption_v1")

# Same inputs always produce same derived keys
assert diversifier.derive("database_encryption") == database_key
```

---

## Message Authentication (MAC)

### Post-Quantum Secure MAC

```python
from quantum_crypt import PostQuantumSecureMAC

mac = PostQuantumSecureMAC(key=secret_mac_key)

# Authenticate a message
message = b"Important transaction: transfer $1000"
tag = mac.generate(message)

# Verify later
if mac.verify(message, tag):
    print("✅ Message authentic - not tampered")
else:
    print("❌ WARNING: Message tampered or invalid key!")
```

### MAC with Associated Data

```python
from quantum_crypt import PostQuantumSecureMAC

mac = PostQuantumSecureMAC(key=secret_key)

message = b"Encrypted data here"
metadata = b"timestamp=1624567890,user=alice"

# MAC covers both message AND metadata
tag = mac.generate_with_ad(message, metadata)

# Verification requires same metadata
is_valid = mac.verify_with_ad(message, metadata, tag)
```

---

## Secure Multi-Party Computation

### Basic 2-of-3 Threshold MPC

```python
from quantum_crypt import PostQuantumSecureMPCEngine

# Initialize MPC for 3 parties with 2-of-3 threshold
mpc = PostQuantumSecureMPCEngine(
    num_parties=3,
    threshold=2,
    security_level=128
)

# Secret to share
secret_value = 1000

# Generate shares
shares = mpc.generate_shares(secret_value)
print(f"Generated {len(shares)} shares")

# Parties compute locally
party1_result = mpc.compute_party(shares[0], "add", 500)
party2_result = mpc.compute_party(shares[1], "add", 500)
party3_result = mpc.compute_party(shares[2], "add", 500)

# Reconstruct with ANY 2 shares
final = mpc.reconstruct([party1_result, party2_result])
assert final == 1500  # 1000 + 500
```

### MPC Session Management

```python
from quantum_crypt import PostQuantumSecureMPCSessionManager

session_manager = PostQuantumSecureMPCSessionManager()

# Create multi-party session
session = session_manager.create_session(
    party_ids=["alice", "bob", "charlie"],
    threshold=2,
    operation="secure_sum"
)

# Register each party
for party_id in ["alice", "bob", "charlie"]:
    session_manager.register_party(session.id, party_id)

# Submit inputs
session_manager.submit_input(session.id, "alice", 100)
session_manager.submit_input(session.id, "bob", 200)
session_manager.submit_input(session.id, "charlie", 300)

# Get result when threshold reached
result = session_manager.get_result(session.id)
print(f"Secure sum: {result}")  # Outputs 600
```

---

## Format-Preserving Encryption

### Credit Card Numbers

```python
from quantum_crypt import FormatPreservingEncryptionEngine

fpe = FormatPreservingEncryptionEngine(key=master_key)

# Encrypt credit card - preserves format
cc_number = "4111-1111-1111-1111"
encrypted = fpe.encrypt(cc_number, format="credit_card")
decrypted = fpe.decrypt(encrypted, format="credit_card")

print(f"Original:  {cc_number}")
print(f"Encrypted: {encrypted}")  # Same format, different digits
print(f"Decrypted: {decrypted}")  # Original restored
assert decrypted == cc_number
assert len(encrypted) == len(cc_number)
```

### Social Security Numbers

```python
from quantum_crypt import FormatPreservingEncryptionEngine

fpe = FormatPreservingEncryptionEngine(key=master_key)

ssn = "123-45-6789"
encrypted_ssn = fpe.encrypt(ssn, format="ssn")
decrypted_ssn = fpe.decrypt(encrypted_ssn, format="ssn")

print(f"Original SSN:  {ssn}")
print(f"Encrypted SSN: {encrypted_ssn}")  # Format: XXX-XX-XXXX preserved
assert decrypted_ssn == ssn
```

### Custom Formats

```python
from quantum_crypt import FormatPreservingEncryptionEngine

fpe = FormatPreservingEncryptionEngine(key=master_key)

# Define custom format
custom_format = {
    "pattern": r"[A-Z]{2}\d{6}",
    "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
}

member_id = "AB123456"
encrypted = fpe.encrypt(member_id, custom_format=custom_format)
decrypted = fpe.decrypt(encrypted, custom_format=custom_format)

assert decrypted == member_id
```

---

## Side-Channel Resistance

### Constant-Time Comparison

```python
from quantum_crypt import SideChannelResistantKeyWrapper

wrapper = SideChannelResistantKeyWrapper()

# Constant-time comparison - no timing leaks
a = b"secret_value_123"
b = b"secret_value_123"
c = b"different_value"

assert wrapper.constant_time_compare(a, b) == True
assert wrapper.constant_time_compare(a, c) == False
# Timing identical regardless of how early differences appear
```

### Secure Key Wrapping

```python
from quantum_crypt import SideChannelResistantKeyWrapper

wrapper = SideChannelResistantKeyWrapper(wrapping_key)

# Wrap key with side-channel protections
sensitive_key = b"very_secret_encryption_key"
wrapped = wrapper.wrap_key(sensitive_key)

# Unwrap later
unwrapped = wrapper.unwrap_key(wrapped)
assert unwrapped == sensitive_key

# Automatic zeroization after use
wrapper.zeroize_buffer(sensitive_key)
```

---

## Session Management

### Multi-Party Session Establishment

```python
from quantum_crypt import HybridKEMMultiPartySessionManager

session_manager = HybridKEMMultiPartySessionManager()

# Establish session between 3 parties
session = session_manager.create_session(
    participants=["server1", "server2", "server3"],
    session_lifetime=3600,  # 1 hour
    rekey_interval=300  # Rekey every 5 minutes
)

# Each party generates and exchanges public keys
for participant in session.participants:
    pk = session_manager.generate_participant_key(session.id, participant)
    distribute_to_other_participants(participant, pk)

# After key exchange, get shared session key
session_key = session_manager.get_session_key(session.id)
```

### Session Key Rotation

```python
from quantum_crypt import PostQuantumSecureSessionKeyManager

key_manager = PostQuantumSecureSessionKeyManager()

# Create session with automatic rotation
session = key_manager.create_session(
    rotation_interval_seconds=300,  # 5 minutes
    forward_secrecy=True
)

# Get current key
current_key = session.get_current_key()

# Force rotation (also happens automatically)
new_key = session.rotate_key()
print(f"Key rotated, old key zeroized")
```

---

## Error Resilience

```python
from quantum_crypt import CryptoErrorResilienceEngine

resilience = CryptoErrorResilienceEngine(
    max_retries=3,
    timeout_seconds=30,
    graceful_degradation=True
)

@resilience.with_timeout(5.0)
@resilience.with_retry()
def secure_encrypt(data, key):
    return encryption_engine.encrypt(data, key)

try:
    result = secure_encrypt(sensitive_data, encryption_key)
except TimeoutError:
    # Fallback to simpler encryption
    result = resilience.fallback_encrypt(data, key)
```

---

## Observability

```python
from quantum_crypt import ObservabilityEngine

observability = ObservabilityEngine(
    enable_latency_tracking=True,
    enable_failure_metrics=True,
    log_format="structured_json"
)

@observability.trace_operation("kem_keypair_gen")
def tracked_keygen():
    return kem.generate_keypair()

# Get security metrics
metrics = observability.get_crypto_metrics()
print(f"Operations total: {metrics['operations_total']}")
print(f"Failure rate: {metrics['failure_rate']:.2%}")
print(f"Avg KEM latency: {metrics['kem_latency_avg_ms']:.2f}ms")
```

---

## API Stability Reference

| Class | Stability | Since | Notes |
|-------|-----------|-------|-------|
| `PostQuantumHybridKEM` | STABLE | 2026.6.1 | Production ready |
| `SecureKeyDerivationFunction` | STABLE | 2026.6.1 | Production ready |
| `PostQuantumSecureMAC` | STABLE | 2026.6.5 | Production ready |
| `FormatPreservingEncryptionEngine` | STABLE | 2026.6.10 | Production ready |
| `SideChannelResistantKeyWrapper` | STABLE | 2026.6.15 | Production ready |
| `PostQuantumSecureMPCEngine` | BETA | 2026.6.20 | API stabilizing |
| `PostQuantumSecureHKDFMemoryHard` | BETA | 2026.6.22 | May be optimized |
| `CryptoErrorResilienceEngine` | BETA | 2026.6.22 | New module |
| `ObservabilityEngine` | BETA | 2026.6.22 | New module |

---

*Last Updated: June 22, 2026*
