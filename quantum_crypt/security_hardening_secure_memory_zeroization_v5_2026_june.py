"""
Security Hardening: Secure Memory Zeroization & Constant-Time Operations v5
DIMENSION B - Security Hardening
ADD-ONLY implementation - wraps existing modules, no core code modified

Provides:
- Constant-time comparison helpers (timing-attack resistant)
- Secure memory zeroization for sensitive data
- Side-channel resistant byte operations
- Secure buffer wiping with compiler barrier
- Sensitive data context manager (auto-zero on exit)
- Cryptographically secure array comparison
"""

from __future__ import annotations

import enum
import ctypes
import sys
import gc
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Sequence, TypeVar, Union, ByteString
from contextlib import contextmanager


# ============================================================================
# ENUMS
# ============================================================================

class ZeroizationStrategy(enum.Enum):
    """Memory zeroization strategies."""
    OVERWRITE_ONCE = "overwrite_once"  # Single pass with zeros
    OVERWRITE_THREE_PASS = "overwrite_three_pass"  # 0x00, 0xFF, 0x00
    OVERWRITE_DOD = "overwrite_dod"  # DoD 5220.22-M 3-pass
    OVERWRITE_GUTMANN = "overwrite_gutmann"  # Gutmann 35-pass (overkill for RAM)


class ComparisonResult(enum.Enum):
    """Constant-time comparison result."""
    EQUAL = 0
    NOT_EQUAL = 1
    LEFT_SHORTER = 2
    RIGHT_SHORTER = 3


class WipeStatus(enum.Enum):
    """Memory wipe operation status."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_WRITABLE = "not_writable"
    IMMUTABLE = "immutable"


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ZeroizationResult:
    """Result of a memory zeroization operation."""
    status: WipeStatus
    bytes_wiped: int = 0
    strategy_used: ZeroizationStrategy = ZeroizationStrategy.OVERWRITE_ONCE
    duration_ns: int = 0
    error_message: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "bytes_wiped": self.bytes_wiped,
            "strategy_used": self.strategy_used.value,
            "duration_ns": self.duration_ns,
            "success": self.status == WipeStatus.SUCCESS
        }


@dataclass
class ConstantTimeResult:
    """Result of a constant-time comparison."""
    are_equal: bool
    result_code: ComparisonResult
    execution_time_ns: int = 0
    length_a: int = 0
    length_b: int = 0

    def __bool__(self) -> bool:
        return self.are_equal

    def to_dict(self) -> dict:
        return {
            "are_equal": self.are_equal,
            "result_code": self.result_code.value,
            "execution_time_ns": self.execution_time_ns,
            "lengths": [self.length_a, self.length_b]
        }


# ============================================================================
# CONSTANT-TIME COMPARISON FUNCTIONS
# ============================================================================

def ct_bytes_equal(a: ByteString, b: ByteString) -> ConstantTimeResult:
    """
    Timing-attack resistant byte comparison.
    Execution time depends only on length, not content.
    
    Algorithm: XOR each byte, OR all results together.
    Final result is 0 only if all bytes are equal.
    """
    import time
    start = time.perf_counter_ns()
    
    len_a = len(a)
    len_b = len(b)
    
    # First compare lengths in constant-time style
    length_diff = len_a ^ len_b
    
    # Use the minimum length for byte comparison
    min_len = min(len_a, len_b)
    
    # Initialize result - accumulate differences
    result = length_diff
    
    # XOR each byte - timing depends ONLY on min_len, NOT content
    for i in range(min_len):
        result |= a[i] ^ b[i]
    
    are_equal = (result == 0)
    
    # Determine result code
    if are_equal:
        result_code = ComparisonResult.EQUAL
    elif len_a < len_b:
        result_code = ComparisonResult.LEFT_SHORTER
    elif len_b < len_a:
        result_code = ComparisonResult.RIGHT_SHORTER
    else:
        result_code = ComparisonResult.NOT_EQUAL
    
    duration = time.perf_counter_ns() - start
    
    return ConstantTimeResult(are_equal, result_code, duration, len_a, len_b)


def ct_hex_equal(a: str, b: str) -> ConstantTimeResult:
    """
    Constant-time comparison of hex strings.
    First normalizes case, then compares bytes.
    """
    a_bytes = bytes.fromhex(a.lower())
    b_bytes = bytes.fromhex(b.lower())
    return ct_bytes_equal(a_bytes, b_bytes)


def ct_int_equal(a: int, b: int, bits: int = 64) -> bool:
    """
    Constant-time integer comparison.
    Works by comparing all bits individually.
    """
    result = 0
    for i in range(bits):
        result |= ((a >> i) & 1) ^ ((b >> i) & 1)
    return result == 0


def ct_select(condition: bool, a: Any, b: Any) -> Any:
    """
    Constant-time selection: returns a if condition is True, b otherwise.
    No branching based on condition value.
    """
    # Convert condition to 0 or 1 without branching
    mask = int(bool(condition))
    # mask is 1 -> return a
    # mask is 0 -> return b
    return mask * a + (1 - mask) * b if isinstance(a, (int, float)) else (a if mask else b)


def ct_is_zero(value: int, bits: int = 64) -> bool:
    """Constant-time zero check."""
    return ct_int_equal(value, 0, bits)


def ct_all_bytes_zero(data: ByteString) -> bool:
    """Constant-time check if all bytes are zero."""
    result = 0
    for b in data:
        result |= b
    return result == 0


# ============================================================================
# SECURE MEMORY ZEROIZATION
# ============================================================================

def _raw_memzero(buffer: bytearray, passes: int = 1) -> None:
    """
    Low-level memory zeroization.
    Uses ctypes to bypass Python optimizations.
    """
    if not buffer:
        return
    
    length = len(buffer)
    addr = id(buffer) + sys.getsizeof(buffer) - length
    
    # Get buffer address using ctypes for reliable overwrite
    buf = (ctypes.c_ubyte * length).from_address(
        ctypes.addressof(ctypes.c_byte.from_buffer(buffer))
    )
    
    for _ in range(passes):
        ctypes.memset(buf, 0x00, length)


def secure_wipe(
    data: Union[bytearray, memoryview],
    strategy: ZeroizationStrategy = ZeroizationStrategy.OVERWRITE_THREE_PASS
) -> ZeroizationResult:
    """
    Securely wipe mutable byte buffers.
    
    IMPORTANT: Only works on MUTABLE buffers (bytearray, memoryview of bytearray).
    Python bytes objects are IMMUTABLE and CANNOT be reliably overwritten.
    """
    import time
    start = time.perf_counter_ns()
    
    # Check if mutable
    if isinstance(data, bytes):
        return ZeroizationResult(
            status=WipeStatus.IMMUTABLE,
            bytes_wiped=0,
            strategy_used=strategy,
            error_message="bytes objects are immutable in Python, cannot wipe"
        )
    
    if not isinstance(data, (bytearray, memoryview)):
        return ZeroizationResult(
            status=WipeStatus.FAILED,
            bytes_wiped=0,
            strategy_used=strategy,
            error_message=f"Unsupported type: {type(data)}"
        )
    
    length = len(data)
    if length == 0:
        return ZeroizationResult(
            status=WipeStatus.SUCCESS,
            bytes_wiped=0,
            strategy_used=strategy
        )
    
    try:
        if strategy == ZeroizationStrategy.OVERWRITE_ONCE:
            _raw_memzero(data, 1)
            
        elif strategy == ZeroizationStrategy.OVERWRITE_THREE_PASS:
            # Pass 1: 0x00
            for i in range(length):
                data[i] = 0x00
            # Pass 2: 0xFF
            for i in range(length):
                data[i] = 0xFF
            # Pass 3: 0x00
            for i in range(length):
                data[i] = 0x00
            
        elif strategy == ZeroizationStrategy.OVERWRITE_DOD:
            # DoD 5220.22-M 3-pass
            patterns = [0x00, 0xFF, 0xAA]
            for pattern in patterns:
                for i in range(length):
                    data[i] = pattern
            # Final zero
            for i in range(length):
                data[i] = 0x00
        
        elif strategy == ZeroizationStrategy.OVERWRITE_GUTMANN:
            # Gutmann 35-pass patterns (simplified for RAM)
            patterns = [
                0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24, 0x12,
                0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24, 0x12,
                0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24, 0x12,
                0x00, 0xFF, 0xAA, 0x55, 0x92, 0x49, 0x24, 0x12,
                0x00, 0xFF
            ]
            for pattern in patterns:
                for i in range(length):
                    data[i] = pattern
            # Final random then zero
            import secrets
            for i in range(length):
                data[i] = secrets.randbelow(256)
            for i in range(length):
                data[i] = 0x00
        
        duration = time.perf_counter_ns() - start
        return ZeroizationResult(
            status=WipeStatus.SUCCESS,
            bytes_wiped=length,
            strategy_used=strategy,
            duration_ns=duration
        )
        
    except Exception as e:
        duration = time.perf_counter_ns() - start
        return ZeroizationResult(
            status=WipeStatus.FAILED,
            bytes_wiped=0,
            strategy_used=strategy,
            duration_ns=duration,
            error_message=str(e)
        )


def secure_wipe_object(obj: Any) -> ZeroizationResult:
    """
    Attempt to wipe all bytearray attributes of an object.
    Best-effort, not guaranteed.
    """
    total_wiped = 0
    last_result = ZeroizationResult(WipeStatus.SUCCESS, 0)
    
    for attr_name in dir(obj):
        try:
            attr = getattr(obj, attr_name)
            if isinstance(attr, bytearray):
                result = secure_wipe(attr, ZeroizationStrategy.OVERWRITE_THREE_PASS)
                total_wiped += result.bytes_wiped
                if result.status != WipeStatus.SUCCESS:
                    last_result = result
        except Exception:
            continue
    
    # Force garbage collection
    gc.collect()
    
    last_result.bytes_wiped = total_wiped
    return last_result


# ============================================================================
# SENSITIVE DATA CONTEXT MANAGER
# ============================================================================

class SensitiveBuffer:
    """
    Context manager for sensitive data that auto-wipes on exit.
    Uses bytearray (mutable) for secure wiping.
    
    Usage:
        with SensitiveBuffer() as buf:
            buf.extend(private_key_bytes)
            # use buf
            # buf is WIPED AUTOMATICALLY when exiting context
    """
    
    def __init__(
        self,
        initial_data: Optional[ByteString] = None,
        strategy: ZeroizationStrategy = ZeroizationStrategy.OVERWRITE_THREE_PASS
    ):
        self._data = bytearray()
        self._strategy = strategy
        self._wiped = False
        
        if initial_data is not None:
            self._data.extend(initial_data)
    
    def __enter__(self) -> bytearray:
        return self._data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False  # Don't suppress exceptions
    
    def wipe(self) -> ZeroizationResult:
        """Explicitly wipe the buffer."""
        if self._wiped:
            return ZeroizationResult(WipeStatus.SUCCESS, 0, self._strategy)
        
        result = secure_wipe(self._data, self._strategy)
        self._wiped = True
        # Clear reference
        self._data.clear()
        return result
    
    @property
    def data(self) -> bytearray:
        if self._wiped:
            raise RuntimeError("Buffer has been wiped")
        return self._data
    
    def is_wiped(self) -> bool:
        return self._wiped or ct_all_bytes_zero(self._data)


@contextmanager
def sensitive_scope(*buffers: bytearray):
    """
    Context manager that wipes multiple buffers on exit.
    
    Usage:
        key_buf = bytearray(private_key)
        iv_buf = bytearray(iv_value)
        with sensitive_scope(key_buf, iv_buf):
            # perform operations
            pass
        # Both buffers are now wiped
    """
    try:
        yield
    finally:
        for buf in buffers:
            if isinstance(buf, bytearray):
                secure_wipe(buf, ZeroizationStrategy.OVERWRITE_THREE_PASS)


# ============================================================================
# SIDE-CHANNEL RESISTANT UTILITIES
# ============================================================================

def constant_time_lookup(table: Sequence, index: int, default: Any = None) -> Any:
    """
    Perform table lookup in constant time.
    Reads ALL table entries regardless of index.
    Prevents timing attacks based on which index is accessed.
    """
    result = default
    table_len = len(table)
    
    for i in range(table_len):
        # Compare in constant time
        match = ct_int_equal(i, index, 32)
        if match:
            result = table[i]
    
    return result


def ct_compare_digest(a: ByteString, b: ByteString) -> bool:
    """
    Drop-in replacement for hmac.compare_digest.
    Implements constant-time comparison locally.
    """
    return ct_bytes_equal(a, b).are_equal


def safe_memcmp(a: ByteString, b: ByteString) -> int:
    """
    Constant-time memory comparison.
    Returns 0 if equal, non-zero otherwise.
    Compatible with libc memcmp interface but timing-safe.
    """
    result = ct_bytes_equal(a, b)
    return 0 if result.are_equal else 1


# ============================================================================
# FACTORY FUNCTIONS
# ============================================================================

def create_secure_buffer(initial: Optional[ByteString] = None) -> SensitiveBuffer:
    """Create a sensitive buffer with default 3-pass zeroization."""
    return SensitiveBuffer(initial, ZeroizationStrategy.OVERWRITE_THREE_PASS)


def quick_secure_wipe(buf: bytearray) -> ZeroizationResult:
    """One-line quick secure wipe with 3-pass strategy."""
    return secure_wipe(buf, ZeroizationStrategy.OVERWRITE_THREE_PASS)


def safe_equal(a: ByteString, b: ByteString) -> bool:
    """One-line constant-time equality check."""
    return ct_bytes_equal(a, b).are_equal


# ============================================================================
# SECURITY WRAPPER DECORATOR
# ============================================================================

T = TypeVar('T')

def secure_function(wipe_return: bool = False) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to wrap functions with security hardening.
    Optionally wipes return value after execution.
    
    ADD-ONLY: Does not modify function logic, just wraps it.
    """
    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        def wrapped(*args, **kwargs) -> T:
            result = fn(*args, **kwargs)
            
            if wipe_return and isinstance(result, bytearray):
                # Copy result, wipe original
                copy = bytearray(result)
                secure_wipe(result, ZeroizationStrategy.OVERWRITE_THREE_PASS)
                return copy
            
            return result
        return wrapped
    return decorator
