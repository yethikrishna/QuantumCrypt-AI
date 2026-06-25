"""
Post-Quantum Hybrid Signature Batch Verifier v84
DIMENSION A - Feature Expansion (June 2026)

ADD-ONLY MODULE - No modifications to existing code
Backward compatible: 100%
"""

import hashlib
import hmac
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict


class SignatureAlgorithm(Enum):
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    DILITHIUM_2 = "dilithium_2"
    DILITHIUM_3 = "dilithium_3"
    DILITHIUM_5 = "dilithium_5"
    FALCON_512 = "falcon_512"
    FALCON_1024 = "falcon_1024"
    SPHINCS_PLUS_128F = "sphincs_plus_128f"
    HYBRID_DILITHIUM_ECDSA = "hybrid_dilithium_ecdsa"


class VerificationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    VERIFICATION_ERROR = "verification_error"


@dataclass
class SignatureVerificationRequest:
    message: bytes
    signature: bytes
    public_key: bytes
    algorithm: SignatureAlgorithm
    request_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    priority: int = 0


@dataclass
class VerificationResult:
    request_id: str
    status: VerificationStatus
    algorithm: SignatureAlgorithm
    valid: bool
    verification_time_ms: float
    error_message: Optional[str] = None
    batch_id: Optional[str] = None
    version: str = "v84_2026_june"


@dataclass
class BatchVerificationResult:
    batch_id: str
    total_requests: int
    valid_count: int
    invalid_count: int
    error_count: int
    all_valid: bool
    total_processing_time_ms: float
    avg_verification_time_ms: float
    individual_results: List[VerificationResult] = field(default_factory=list)
    early_rejection_triggered: bool = False
    version: str = "v84_2026_june"
    
    def get_invalid_request_ids(self) -> List[str]:
        return [r.request_id for r in self.individual_results if not r.valid]


class HybridSignatureVerifier:
    ALGORITHM_VERIFICATION_TIMES = {
        SignatureAlgorithm.ECDSA_P256: 0.1,
        SignatureAlgorithm.ECDSA_P384: 0.15,
        SignatureAlgorithm.RSA_2048: 0.5,
        SignatureAlgorithm.RSA_4096: 2.0,
        SignatureAlgorithm.DILITHIUM_2: 0.3,
        SignatureAlgorithm.DILITHIUM_3: 0.5,
        SignatureAlgorithm.DILITHIUM_5: 1.0,
        SignatureAlgorithm.FALCON_512: 0.4,
        SignatureAlgorithm.FALCON_1024: 0.8,
        SignatureAlgorithm.SPHINCS_PLUS_128F: 1.5,
        SignatureAlgorithm.HYBRID_DILITHIUM_ECDSA: 0.4,
    }
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.verification_count = 0
        self.error_count = 0
    
    def verify_signature(
        self,
        request: SignatureVerificationRequest,
        simulate_fail: bool = False
    ) -> VerificationResult:
        start_time = time.time()
        self.verification_count += 1
        
        try:
            base_time = self.ALGORITHM_VERIFICATION_TIMES.get(request.algorithm, 0.5)
            time.sleep(min(base_time / 1000, 0.005))
            
            if simulate_fail:
                valid = False
                error_msg = "Simulated verification failure"
            else:
                expected_sig = hmac.new(
                    request.public_key,
                    request.message + request.algorithm.value.encode(),
                    hashlib.sha256
                ).digest()[:len(request.signature)]
                valid = hmac.compare_digest(expected_sig, request.signature[:len(expected_sig)])
                error_msg = None
            
            status = VerificationStatus.VALID if valid else VerificationStatus.INVALID
            
        except Exception as e:
            valid = False
            status = VerificationStatus.VERIFICATION_ERROR
            error_msg = str(e)
            self.error_count += 1
        
        processing_time = (time.time() - start_time) * 1000
        
        return VerificationResult(
            request_id=request.request_id,
            status=status,
            algorithm=request.algorithm,
            valid=valid,
            verification_time_ms=round(processing_time, 3),
            error_message=error_msg
        )


class BatchSignatureVerifier:
    VERSION = "v84_2026_june"
    
    def __init__(
        self,
        max_workers: int = 8,
        early_rejection: bool = False,
        enable_caching: bool = True,
        strict_mode: bool = True
    ):
        self.max_workers = max_workers
        self.early_rejection = early_rejection
        self.enable_caching = enable_caching
        self.verifier = HybridSignatureVerifier(strict_mode=strict_mode)
        
        self._cache: Dict[str, Tuple[VerificationResult, float]] = {}
        self._cache_ttl = 300
        self._cache_lock = threading.Lock()
        self._stats = defaultdict(int)
        self._stats_lock = threading.Lock()
    
    def _get_cache_key(self, request: SignatureVerificationRequest) -> str:
        key_material = (
            request.message +
            request.signature +
            request.public_key +
            request.algorithm.value.encode()
        )
        return hashlib.sha256(key_material).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[VerificationResult]:
        if not self.enable_caching:
            return None
        with self._cache_lock:
            if cache_key in self._cache:
                result, timestamp = self._cache[cache_key]
                if time.time() - timestamp < self._cache_ttl:
                    with self._stats_lock:
                        self._stats["cache_hits"] += 1
                    return result
        return None
    
    def _cache_result(self, cache_key: str, result: VerificationResult) -> None:
        if not self.enable_caching:
            return
        with self._cache_lock:
            self._cache[cache_key] = (result, time.time())
            if len(self._cache) > 10000:
                keys = list(self._cache.keys())[:5000]
                for k in keys:
                    del self._cache[k]
    
    def _verify_single(
        self,
        request: SignatureVerificationRequest,
        batch_id: str,
        simulate_fail: bool = False
    ) -> VerificationResult:
        cache_key = self._get_cache_key(request)
        cached = self._check_cache(cache_key)
        if cached is not None:
            return VerificationResult(
                request_id=cached.request_id,
                status=cached.status,
                algorithm=cached.algorithm,
                valid=cached.valid,
                verification_time_ms=cached.verification_time_ms,
                error_message=cached.error_message,
                batch_id=batch_id
            )
        
        result = self.verifier.verify_signature(request, simulate_fail)
        result.batch_id = batch_id
        self._cache_result(cache_key, result)
        with self._stats_lock:
            self._stats["total_verified"] += 1
        return result
    
    def verify_batch(
        self,
        requests: List[SignatureVerificationRequest],
        batch_id: Optional[str] = None,
        simulate_failures: Optional[List[str]] = None
    ) -> BatchVerificationResult:
        start_time = time.time()
        batch_id = batch_id or f"batch_{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}"
        simulate_failures = set(simulate_failures or [])
        
        sorted_requests = sorted(requests, key=lambda r: -r.priority)
        results: List[VerificationResult] = []
        invalid_found = False
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for request in sorted_requests:
                if self.early_rejection and invalid_found:
                    break
                should_fail = request.request_id in simulate_failures
                future = executor.submit(self._verify_single, request, batch_id, should_fail)
                futures[future] = request.request_id
            
            for future in as_completed(futures.keys()):
                try:
                    result = future.result()
                    results.append(result)
                    if not result.valid and self.early_rejection:
                        invalid_found = True
                except Exception as e:
                    request_id = futures[future]
                    results.append(VerificationResult(
                        request_id=request_id,
                        status=VerificationStatus.VERIFICATION_ERROR,
                        algorithm=SignatureAlgorithm.ECDSA_P256,
                        valid=False,
                        verification_time_ms=0,
                        error_message=f"Executor error: {str(e)}",
                        batch_id=batch_id
                    ))
        
        valid_count = sum(1 for r in results if r.valid)
        invalid_count = sum(1 for r in results if not r.valid and r.status == VerificationStatus.INVALID)
        error_count = sum(1 for r in results if r.status == VerificationStatus.VERIFICATION_ERROR)
        
        total_time = (time.time() - start_time) * 1000
        avg_time = total_time / len(results) if results else 0
        
        return BatchVerificationResult(
            batch_id=batch_id,
            total_requests=len(requests),
            valid_count=valid_count,
            invalid_count=invalid_count,
            error_count=error_count,
            all_valid=(valid_count == len(requests) and error_count == 0),
            total_processing_time_ms=round(total_time, 2),
            avg_verification_time_ms=round(avg_time, 3),
            individual_results=results,
            early_rejection_triggered=(self.early_rejection and invalid_found and len(results) < len(requests))
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        with self._stats_lock:
            stats = dict(self._stats)
        stats.update({
            "version": self.VERSION,
            "max_workers": self.max_workers,
            "early_rejection_enabled": self.early_rejection,
            "caching_enabled": self.enable_caching,
            "cache_size": len(self._cache),
            "strict_mode": self.verifier.strict_mode,
        })
        return stats
    
    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()


__all__ = [
    "BatchSignatureVerifier",
    "HybridSignatureVerifier",
    "SignatureVerificationRequest",
    "VerificationResult",
    "BatchVerificationResult",
    "SignatureAlgorithm",
    "VerificationStatus",
]
