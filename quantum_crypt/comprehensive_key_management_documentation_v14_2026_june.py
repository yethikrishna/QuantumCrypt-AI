"""
================================================================================
           QUANTUM KEY MANAGEMENT & ROTATION - COMPREHENSIVE DOCUMENTATION
================================================================================
Dimension F - Documentation & API Stability
ADD-ONLY: New documentation module, no modifications to existing code
================================================================================

API STABILITY MARKERS:
======================
- @STABLE: API is frozen, backward compatible, will not break
- @EXPERIMENTAL: API may change in future versions
- @DEPRECATED: API scheduled for removal, use alternative

MODULE: quantum_key_management_rotation_v13_2026_june.py
STABILITY: EXPERIMENTAL (v13 - first release, subject to refinement)
================================================================================
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass


class APIMaturity(Enum):
    """API Stability Levels"""
    STABLE = "stable"           # Frozen API - guaranteed backward compatibility
    EXPERIMENTAL = "experimental"  # New API - may change in future versions
    DEPRECATED = "deprecated"     # Scheduled for removal - use alternative


class DocumentationCategory(Enum):
    """Documentation categories"""
    GETTING_STARTED = "getting_started"
    API_REFERENCE = "api_reference"
    USAGE_EXAMPLES = "usage_examples"
    BEST_PRACTICES = "best_practices"
    SECURITY_CONSIDERATIONS = "security_considerations"
    TROUBLESHOOTING = "troubleshooting"


@dataclass
class APIStabilityMarker:
    """API Stability annotation for methods and classes"""
    stability: APIMaturity
    version: str
    deprecation_version: Optional[str] = None
    notes: str = ""


# ============================================================================
#                        API STABILITY CATALOG
# ============================================================================

KEY_MANAGEMENT_API_STABILITY = {
    # Enums
    "KeyStatus": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key lifecycle state machine - stable"
    ),
    "KeyAlgorithm": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Will add more post-quantum algorithms"
    ),
    "KeyPurpose": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Standard key usage classification"
    ),
    
    # Classes
    "CryptographicKey": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Core key metadata structure"
    ),
    "KeyDerivationFunction": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Standard HKDF implementation - RFC 5869 compliant"
    ),
    "QuantumResistantKeyWrapper": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Wrapping algorithm may be upgraded to proper AEAD"
    ),
    "KeyRotationManager": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Rotation policies may be extended"
    ),
    "SecureKeyStore": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="In-memory store - production should use HSM integration"
    ),
    "QuantumKeyManagementManager": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Public API facade - guaranteed stable interface"
    ),
    
    # Public Methods
    "SecureKeyStore.generate_key": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key generation API"
    ),
    "SecureKeyStore.get_key": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key metadata retrieval"
    ),
    "SecureKeyStore.get_key_material": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key material access"
    ),
    "SecureKeyStore.revoke_key": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key revocation API"
    ),
    "SecureKeyStore.list_keys": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Key enumeration"
    ),
    "KeyRotationManager.rotate_key": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Manual key rotation"
    ),
    "KeyRotationManager.check_and_rotate_all": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="Automated rotation check"
    ),
    "KeyDerivationFunction.derive_key": APIStabilityMarker(
        stability=APIMaturity.STABLE,
        version="v13",
        notes="HKDF key derivation"
    ),
    "KeyDerivationFunction.derive_key_hierarchy": APIStabilityMarker(
        stability=APIMaturity.EXPERIMENTAL,
        version="v13",
        notes="Hierarchical derivation API"
    ),
}


# ============================================================================
#                        GETTING STARTED GUIDE
# ============================================================================

GETTING_STARTED_GUIDE = """
================================================================================
                    GETTING STARTED WITH QUANTUM KEY MANAGEMENT
================================================================================

OVERVIEW:
---------
The Quantum-Resistant Key Management & Rotation Engine provides
enterprise-grade key lifecycle management with quantum-resistant
primitives, automated rotation, and hierarchical key derivation.

QUICK START:
------------

1. Import the manager:
   from quantum_crypt.quantum_key_management_rotation_v13_2026_june \\
       import QuantumKeyManagementManager

2. Initialize:
   km_manager = QuantumKeyManagementManager()

3. Create encryption key:
   key_id = km_manager.create_encryption_key(rotation_days=30)

4. Get key material:
   key_material = km_manager.get_key(key_id)

5. Rotate key:
   old_key, new_key = km_manager.rotate_key(key_id)

6. Get audit log:
   audit_log = km_manager.get_audit_log(key_id)

================================================================================
"""


# ============================================================================
#                        FULL API REFERENCE
# ============================================================================

API_REFERENCE = """
================================================================================
                        FULL API REFERENCE
================================================================================

=== QuantumKeyManagementManager ===

STABILITY: @STABLE (v13)

Main public interface for key management operations.

--- create_encryption_key(rotation_days=30) ---

STABILITY: @STABLE

Create a new AES-256-GCM encryption key.

Parameters:
  rotation_days: int - Auto-rotation period in days (default 30)

Returns: str - Unique key ID

--- create_signing_key(rotation_days=365) ---

STABILITY: @STABLE

Create a new signing key (longer rotation recommended).

Parameters:
  rotation_days: int - Auto-rotation period in days (default 365)

Returns: str - Unique key ID

--- get_key(key_id) ---

STABILITY: @STABLE

Get key material for active version.

Parameters:
  key_id: str - Key identifier

Returns: bytes - Key material (32 bytes typically)

--- get_key_metadata(key_id) ---

STABILITY: @STABLE

Get key metadata without accessing key material.

Parameters:
  key_id: str - Key identifier

Returns: Optional[CryptographicKey] - Key metadata or None

--- rotate_key(key_id) ---

STABILITY: @STABLE

Manually rotate a key - creates new version.

Parameters:
  key_id: str - Key to rotate

Returns: Tuple[Optional[CryptographicKey], Optional[CryptographicKey]]
  - (old_key_metadata, new_key_metadata)

--- revoke_key(key_id, reason="unspecified") ---

STABILITY: @STABLE

Revoke a compromised key.

Parameters:
  key_id: str - Key to revoke
  reason: str - Revocation reason for audit log

Returns: bool - Success indicator

--- check_auto_rotation() ---

STABILITY: @STABLE

Check all keys and auto-rotate those past rotation deadline.

Returns: List[Tuple[str, str]] - List of (key_id, new_version) rotated

--- list_all_keys(status_filter=None) ---

STABILITY: @STABLE

List all keys, optionally filtered by status.

Parameters:
  status_filter: Optional[str] - pending/active/rotated/deprecated/revoked

Returns: List[str] - Key IDs

--- get_audit_log(key_id=None, limit=100) ---

STABILITY: @STABLE

Get audit log entries.

Parameters:
  key_id: Optional[str] - Filter by specific key
  limit: int - Maximum entries to return (default 100)

Returns: List[Dict] - Audit log entries with timestamp, event_type, details

=== KeyDerivationFunction ===

STABILITY: @STABLE (v13)

--- derive_key(master_key, salt=None, info=b"", length=32) ---

STABILITY: @STABLE

HKDF-SHA256 key derivation (RFC 5869 compliant).

Parameters:
  master_key: bytes - Input key material
  salt: Optional[bytes] - Salt (recommended for multiple derivations)
  info: bytes - Context info for domain separation
  length: int - Output length in bytes

Returns: bytes - Derived key

--- derive_key_hierarchy(master_key, levels, length=32) ---

STABILITY: @EXPERIMENTAL

Derive hierarchical key chain.

Parameters:
  master_key: bytes - Root key
  levels: List[str] - Hierarchy level names
  length: int - Key length per level

Returns: Dict[str, bytes] - level_name -> derived_key

================================================================================
"""


# ============================================================================
#                        USAGE EXAMPLES
# ============================================================================

USAGE_EXAMPLES = """
================================================================================
                        USAGE EXAMPLES
================================================================================

EXAMPLE 1: Basic Key Lifecycle
-------------------------------

from quantum_crypt.quantum_key_management_rotation_v13_2026_june \\
    import QuantumKeyManagementManager

# Initialize
km = QuantumKeyManagementManager()

# Create encryption key (30 day rotation)
key_id = km.create_encryption_key(rotation_days=30)
print(f"Created key: {key_id}")

# Get key material for encryption
key = km.get_key(key_id)
print(f"Key length: {len(key)} bytes")

# Get metadata
metadata = km.get_key_metadata(key_id)
print(f"Status: {metadata.status.value}")
print(f"Version: {metadata.version}")

# Manual rotation
old_key, new_key = km.rotate_key(key_id)
print(f"Rotated from v{old_key.version} to v{new_key.version}")

EXAMPLE 2: Hierarchical Key Derivation
---------------------------------------

from quantum_crypt.quantum_key_management_rotation_v13_2026_june \\
    import KeyDerivationFunction
import secrets

# Create master key
master = secrets.token_bytes(32)

# Derive hierarchical keys
hierarchy = KeyDerivationFunction.derive_key_hierarchy(
    master_key=master,
    levels=["root", "tenant_123", "user_456", "session_789"],
    length=32
)

for level, key in hierarchy.items():
    print(f"{level}: {key.hex()[:16]}...")

EXAMPLE 3: Automated Key Rotation
----------------------------------

# Create keys with different rotation periods
daily_key = km.create_encryption_key(rotation_days=1)
monthly_key = km.create_encryption_key(rotation_days=30)
yearly_key = km.create_signing_key(rotation_days=365)

# Register rotation callback
def on_rotation(key_id, new_version):
    print(f"Key {key_id} rotated to {new_version}")
    # Update key references in your application

km.register_rotation_callback(on_rotation)

# Run periodic check (e.g., in cron job)
rotated = km.check_auto_rotation()
print(f"Auto-rotated {len(rotated)} keys")

EXAMPLE 4: Audit & Compliance
------------------------------

# Get full audit trail
all_logs = km.get_audit_log()
print(f"Total audit events: {len(all_logs)}")

# Get specific key audit log
key_logs = km.get_audit_log(key_id=key_id)
print(f"Events for {key_id}:")
for event in key_logs:
    print(f"  {event['timestamp']}: {event['event_type']}")
    if 'details' in event:
        print(f"    Details: {event['details']}")

# List keys by status
active_keys = km.list_all_keys(status_filter="active")
rotated_keys = km.list_all_keys(status_filter="rotated")
print(f"Active: {len(active_keys)}, Rotated: {len(rotated_keys)}")

================================================================================
"""


# ============================================================================
#                        BEST PRACTICES
# ============================================================================

BEST_PRACTICES = """
================================================================================
                        BEST PRACTICES
================================================================================

1. KEY ROTATION POLICIES
-------------------------
- Encryption keys: 30 days recommended
- Signing keys: 365 days recommended
- Root keys: 1-2 years (store offline)
- Session keys: Hours/days - derive per session
- Call check_auto_rotation() daily via cron

2. KEY DERIVATION
------------------
- Always use salt for HKDF when deriving multiple keys
- Use info parameter for domain separation
- Never reuse derived keys across different contexts
- Hierarchical derivation: root -> tenant -> user -> session
- Minimum 32 bytes (256 bits) for all keys

3. KEY STORAGE
--------------
- This implementation is IN-MEMORY ONLY
- Production: Integrate with HSM / KMS
- Key material is wrapped at rest (XOR + HMAC demo)
- Production: Use AES-GCM or ChaCha20-Poly1305 for wrapping
- Never log or persist raw key material

4. ACCESS CONTROL
-----------------
- Wrap get_key_material() with authorization checks
- Audit all key accesses
- Implement rate limiting on key retrieval
- Separate duties: key admin vs key user
- Revoke immediately on suspicion of compromise

5. ERROR HANDLING
-----------------
- Always check None returns from get_key()
- Handle key_not_found explicitly
- Validate key_id format before operations
- Log all failures with full context
- Fail closed - don't proceed without valid key

================================================================================
"""


# ============================================================================
#                        SECURITY CONSIDERATIONS
# ============================================================================

SECURITY_CONSIDERATIONS = """
================================================================================
                        SECURITY CONSIDERATIONS
================================================================================

CRITICAL SECURITY NOTES:
------------------------

1. DEMO IMPLEMENTATION WARNING:
   - QuantumResistantKeyWrapper uses XOR + HMAC for DEMO purposes
   - PRODUCTION MUST USE: AES-GCM / ChaCha20-Poly1305
   - This is NOT quantum-resistant yet - uses classical primitives
   - True post-quantum requires liboqs / Crystals-Kyber integration

2. MEMORY SECURITY:
   - Key material exists in Python memory (not zeroized)
   - Python GC may leave copies in memory
   - Production: Use secure memory (mlock / SecureString)
   - Zeroize after use (ctypes.memset on bytearray)

3. IN-MEMORY ONLY:
   - No persistence - keys lost on restart
   - No replication / redundancy
   - No backup / recovery mechanism
   - Production: Integrate with secure KMS

4. SIDE CHANNELS:
   - No constant-time guarantees
   - Timing attacks may be possible
   - Python runtime has inherent side channels
   - Critical operations should use C extensions

5. AUDIT LOG:
   - In-memory only - not persisted
   - No tamper protection
   - No digital signatures on log entries
   - Production: Write to immutable audit log

POST-QUANTUM READINESS:
-----------------------
- Algorithm enums include Kyber/Dilithium/Sphincs+
- Implementation uses classical crypto today
- API designed for future drop-in replacement
- Key wrapping layer is abstraction point
- When liboqs Python bindings available, swap implementation

================================================================================
"""


# ============================================================================
#                        TROUBLESHOOTING GUIDE
# ============================================================================

TROUBLESHOOTING = """
================================================================================
                        TROUBLESHOOTING GUIDE
================================================================================

COMMON ISSUES:
--------------

ISSUE: get_key() returns None
SOLUTION:
  - Verify key_id exists: km.list_all_keys()
  - Check key status: km.get_key_metadata(key_id)
  - Key may be revoked/rotated/deprecated
  - Version mismatch: specify version explicitly

ISSUE: Key rotation failing
SOLUTION:
  - Key must be in ACTIVE status
  - Key must have activated_at timestamp
  - Check key_store keys dict directly
  - Manual rotation always works (ignores schedule)

ISSUE: Audit log empty
SOLUTION:
  - Audit log is in-memory only
  - New manager instance = empty log
  - Persist log externally if needed
  - limit parameter defaults to 100 (most recent)

ISSUE: HKDF derivation not matching expected value
SOLUTION:
  - Verify salt is identical (None -> 32 zeros)
  - info parameter must match exactly
  - length parameter affects output
  - Use same Python version (hashlib consistency)

PERFORMANCE:
------------
- Key generation: ~0.01ms (secrets.token_bytes)
- Key derivation: ~0.1ms per level
- Key wrapping: ~0.05ms
- Auto-rotation check: O(N) over all keys
- Memory: ~1KB per key (metadata + wrapped material)

================================================================================
"""


# ============================================================================
#                        DOCUMENTATION MANAGER
# ============================================================================

class KeyManagementDocumentationManager:
    """
    Documentation manager for Quantum Key Management Engine
    
    STABILITY: @STABLE (v13)
    Provides programmatic access to all documentation.
    """
    
    def __init__(self):
        self.stability_catalog = KEY_MANAGEMENT_API_STABILITY
        self._module_version = "v13"
        self._module_name = "quantum_key_management_rotation"
    
    def get_stability(self, api_name: str) -> Optional[Dict[str, Any]]:
        """Get stability information for an API"""
        marker = self.stability_catalog.get(api_name)
        if marker:
            return {
                "api": api_name,
                "stability": marker.stability.value,
                "version": marker.version,
                "deprecation_version": marker.deprecation_version,
                "notes": marker.notes
            }
        return None
    
    def get_documentation(self, category: DocumentationCategory) -> str:
        """Get documentation by category"""
        docs = {
            DocumentationCategory.GETTING_STARTED: GETTING_STARTED_GUIDE,
            DocumentationCategory.API_REFERENCE: API_REFERENCE,
            DocumentationCategory.USAGE_EXAMPLES: USAGE_EXAMPLES,
            DocumentationCategory.BEST_PRACTICES: BEST_PRACTICES,
            DocumentationCategory.SECURITY_CONSIDERATIONS: SECURITY_CONSIDERATIONS,
            DocumentationCategory.TROUBLESHOOTING: TROUBLESHOOTING,
        }
        return docs.get(category, "Documentation category not found")
    
    def get_all_categories(self) -> List[str]:
        """List all available documentation categories"""
        return [c.value for c in DocumentationCategory]
    
    def list_stable_apis(self) -> List[str]:
        """List all APIs marked as STABLE"""
        return [
            name for name, marker in self.stability_catalog.items()
            if marker.stability == APIMaturity.STABLE
        ]
    
    def list_experimental_apis(self) -> List[str]:
        """List all APIs marked as EXPERIMENTAL"""
        return [
            name for name, marker in self.stability_catalog.items()
            if marker.stability == APIMaturity.EXPERIMENTAL
        ]
    
    def get_module_info(self) -> Dict[str, Any]:
        """Get module metadata"""
        return {
            "module": self._module_name,
            "version": self._module_version,
            "stability": "experimental",
            "total_apis": len(self.stability_catalog),
            "stable_apis": len(self.list_stable_apis()),
            "experimental_apis": len(self.list_experimental_apis()),
            "documentation_categories": len(DocumentationCategory),
            "dimension": "F - Documentation & API Stability",
            "backward_compatible": True,
            "add_only": True,
            "security_warning": "Demo implementation - not production ready",
            "post_quantum_status": "API ready - classical crypto today"
        }
    
    def print_security_warnings(self) -> None:
        """Print critical security warnings"""
        print("!" * 80)
        print("CRITICAL SECURITY WARNINGS - PRODUCTION DEPLOYMENT")
        print("!" * 80)
        print(SECURITY_CONSIDERATIONS)
        print("!" * 80)
    
    def print_full_documentation(self) -> None:
        """Print complete documentation to console"""
        print("=" * 80)
        print("QUANTUM KEY MANAGEMENT - FULL DOCUMENTATION")
        print("=" * 80)
        print()
        print(GETTING_STARTED_GUIDE)
        print(API_REFERENCE)
        print(USAGE_EXAMPLES)
        print(BEST_PRACTICES)
        print(SECURITY_CONSIDERATIONS)
        print(TROUBLESHOOTING)
        print("=" * 80)
        print("API STABILITY SUMMARY")
        print("=" * 80)
        print(f"STABLE APIs ({len(self.list_stable_apis())}):")
        for api in self.list_stable_apis():
            print(f"  ✓ {api}")
        print(f"\nEXPERIMENTAL APIs ({len(self.list_experimental_apis())}):")
        for api in self.list_experimental_apis():
            print(f"  ⚠ {api}")
        print("=" * 80)


# ============================================================================
#                        USAGE EXAMPLE (SELF-DOCUMENTING)
# ============================================================================

if __name__ == "__main__":
    # Example: Access documentation programmatically
    doc_manager = KeyManagementDocumentationManager()
    
    print("Module Info:")
    print(doc_manager.get_module_info())
    
    print("\nStable APIs:")
    print(doc_manager.list_stable_apis())
    
    print("\nSecurity Considerations (CRITICAL):")
    print(doc_manager.get_documentation(DocumentationCategory.SECURITY_CONSIDERATIONS)[:800], "...")
    
    # Print full documentation
    # doc_manager.print_full_documentation()
    
    # Print security warnings
    # doc_manager.print_security_warnings()
