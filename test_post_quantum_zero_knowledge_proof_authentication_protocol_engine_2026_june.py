#!/usr/bin/env python3
"""
Test suite for Post-Quantum Zero-Knowledge Proof Authentication Protocol Engine
Production-grade testing with comprehensive coverage.
"""
import json
import sys
import time
from datetime import datetime, timezone, timedelta

# Add quantum_crypt to path
sys.path.insert(0, '/home/user/autonomous-developer/QuantumCrypt-AI')

from quantum_crypt.post_quantum_zero_knowledge_proof_authentication_protocol_engine_2026_june import (
    PostQuantumZKPAuthenticationEngine,
    ZKPProofType,
    AuthenticationStatus
)


def run_tests():
    """Run all ZKP authentication engine tests"""
    print("=" * 70)
    print("QuantumCrypt AI - Post-Quantum ZKP Authentication Engine Tests")
    print("=" * 70)
    
    test_results = []
    
    # Test 1: Engine initialization
    print("\n[TEST 1] Engine Initialization")
    try:
        engine = PostQuantumZKPAuthenticationEngine()
        params = engine.export_public_parameters()
        assert params["system_parameters"]["hash_algorithm"] == "SHA3-256"
        print("  ✓ Engine initialized successfully")
        print(f"  ✓ Security level: {params['system_parameters']['security_level']} bits")
        print(f"  ✓ Hash algorithm: {params['system_parameters']['hash_algorithm']}")
        test_results.append(("Engine Initialization", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Engine Initialization", False, str(e)))
        return test_results
    
    # Test 2: Credential generation
    print("\n[TEST 2] Credential Generation")
    try:
        credential = engine.generate_credential(
            subject_id="user-12345",
            attributes={
                "username": "alice",
                "role": "admin",
                "department": "engineering",
                "clearance_level": 3
            },
            validity_days=90
        )
        
        assert credential.subject_id == "user-12345"
        assert credential.attributes["username"] == "alice"
        assert len(credential.commitment) == 64  # SHA3-256 hex = 64 chars
        assert credential.expiry_timestamp > datetime.now(timezone.utc)
        
        print(f"  ✓ Credential generated: {credential.credential_id[:16]}...")
        print(f"  ✓ Subject: {credential.subject_id}")
        print(f"  ✓ Commitment: {credential.commitment[:32]}...")
        print(f"  ✓ Valid until: {credential.expiry_timestamp.date()}")
        test_results.append(("Credential Generation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Credential Generation", False, str(e)))
    
    # Test 3: Challenge generation
    print("\n[TEST 3] Challenge Generation")
    try:
        challenge, session_id = engine.generate_challenge()
        
        assert len(challenge) == 64  # 32 bytes hex
        assert len(session_id) == 32  # 16 bytes hex
        
        print(f"  ✓ Challenge generated: {challenge[:32]}...")
        print(f"  ✓ Session ID: {session_id}")
        test_results.append(("Challenge Generation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Challenge Generation", False, str(e)))
    
    # Test 4: ZKP Proof creation
    print("\n[TEST 4] Zero-Knowledge Proof Creation")
    try:
        challenge, session_id = engine.generate_challenge()
        
        proof = engine.create_proof(
            credential=credential,
            challenge=challenge,
            disclosed_attributes=["username", "role"],
            proof_type=ZKPProofType.KNOWLEDGE_OF_PREIMAGE
        )
        
        assert proof.proof_type == ZKPProofType.KNOWLEDGE_OF_PREIMAGE
        assert proof.challenge == challenge
        assert "username" in proof.disclosed_attributes
        assert "role" in proof.disclosed_attributes
        assert "fiat_shamir_response" in proof.response
        
        print(f"  ✓ Proof created: {proof.proof_id}")
        print(f"  ✓ Disclosed attributes: {proof.disclosed_attributes}")
        print(f"  ✓ Fiat-Shamir response present")
        test_results.append(("ZKP Proof Creation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("ZKP Proof Creation", False, str(e)))
    
    # Test 5: Proof verification (full authentication)
    print("\n[TEST 5] Proof Verification & Authentication")
    try:
        challenge, session_id = engine.generate_challenge()
        
        proof = engine.create_proof(
            credential=credential,
            challenge=challenge,
            disclosed_attributes=["username", "role"]
        )
        
        result = engine.verify_proof(proof, credential, session_id)
        
        assert result.status == AuthenticationStatus.SUCCESS
        assert result.proof_valid == True
        assert result.subject_id == "user-12345"
        assert result.session_token is not None
        assert result.session_key is not None
        assert result.verified_attributes["username"] == "alice"
        assert result.verified_attributes["role"] == "admin"
        
        print(f"  ✓ Authentication SUCCESS")
        print(f"  ✓ Subject verified: {result.subject_id}")
        print(f"  ✓ Session token: {result.session_token[:16]}...")
        print(f"  ✓ Session key: {result.session_key[:16]}...")
        print(f"  ✓ Verified attributes: {result.verified_attributes}")
        test_results.append(("Proof Verification", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Proof Verification", False, str(e)))
    
    # Test 6: Selective disclosure (privacy preservation)
    print("\n[TEST 6] Selective Attribute Disclosure")
    try:
        challenge, session_id = engine.generate_challenge()
        
        # Only disclose 'username', NOT 'role' or 'clearance_level'
        proof = engine.create_proof(
            credential=credential,
            challenge=challenge,
            disclosed_attributes=["username"]  # Only disclose one attribute
        )
        
        result = engine.verify_proof(proof, credential, session_id)
        
        assert result.status == AuthenticationStatus.SUCCESS
        assert "username" in result.verified_attributes
        assert "role" not in result.verified_attributes  # NOT disclosed
        assert "clearance_level" not in result.verified_attributes  # NOT disclosed
        
        print(f"  ✓ Selective disclosure working correctly")
        print(f"  ✓ Disclosed: username")
        print(f"  ✓ Hidden: role, clearance_level, department")
        print(f"  ✓ Privacy preserved - only requested attributes revealed")
        test_results.append(("Selective Disclosure", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Selective Disclosure", False, str(e)))
    
    # Test 7: Stateless authentication
    print("\n[TEST 7] Stateless Authentication")
    try:
        nonce = "fresh-verifier-nonce-12345"
        result = engine.authenticate_stateless(credential, nonce)
        
        assert result.status == AuthenticationStatus.SUCCESS
        assert result.proof_valid == True
        
        print(f"  ✓ Stateless authentication successful")
        print(f"  ✓ No prior challenge exchange required")
        test_results.append(("Stateless Authentication", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Stateless Authentication", False, str(e)))
    
    # Test 8: Credential revocation
    print("\n[TEST 8] Credential Revocation")
    try:
        revoked_cred = engine.generate_credential(
            subject_id="compromised-user",
            attributes={"username": "bad_actor"},
            validity_days=90
        )
        
        # Revoke the credential
        revoke_success = engine.revoke_credential(revoked_cred.credential_id)
        assert revoke_success == True
        
        # Try to authenticate with revoked credential
        challenge, session_id = engine.generate_challenge()
        proof = engine.create_proof(revoked_cred, challenge)
        result = engine.verify_proof(proof, revoked_cred, session_id)
        
        assert result.status == AuthenticationStatus.REVOKED
        assert result.proof_valid == False
        
        print(f"  ✓ Credential revoked successfully")
        print(f"  ✓ Revoked credential authentication rejected")
        test_results.append(("Credential Revocation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Credential Revocation", False, str(e)))
    
    # Test 9: Session token validation
    print("\n[TEST 9] Session Token Validation")
    try:
        # Get valid token from previous authentication
        challenge, session_id = engine.generate_challenge()
        proof = engine.create_proof(credential, challenge)
        result = engine.verify_proof(proof, credential, session_id)
        
        valid_token = result.session_token
        assert engine.validate_session_token(valid_token) == True
        
        # Test invalid tokens
        assert engine.validate_session_token("invalid-token") == False
        assert engine.validate_session_token("") == False
        assert engine.validate_session_token("g" * 64) == False  # Non-hex chars
        
        print(f"  ✓ Valid session token accepted")
        print(f"  ✓ Invalid tokens correctly rejected")
        test_results.append(("Session Token Validation", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Session Token Validation", False, str(e)))
    
    # Test 10: Statistics and reporting
    print("\n[TEST 10] Verification Statistics")
    try:
        stats = engine.get_verification_statistics()
        
        assert stats["total_verifications"] > 0
        assert stats["successful_verifications"] > 0
        assert stats["active_credentials"] > 0
        
        print(f"  ✓ Total verifications: {stats['total_verifications']}")
        print(f"  ✓ Success rate: {stats['success_rate']:.1%}")
        print(f"  ✓ Active credentials: {stats['active_credentials']}")
        print(f"  ✓ Revoked credentials: {stats['revoked_credentials']}")
        test_results.append(("Statistics Reporting", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Statistics Reporting", False, str(e)))
    
    # Test 11: Session cleanup
    print("\n[TEST 11] Expired Session Cleanup")
    try:
        # Generate some sessions
        for i in range(3):
            engine.generate_challenge()
        
        initial_count = len(engine._active_sessions)
        
        # Manually expire sessions for testing
        for session in engine._active_sessions.values():
            session["expires_at"] = time.time() - 3600  # Expired 1 hour ago
        
        cleaned = engine.cleanup_expired_sessions()
        
        assert cleaned > 0
        assert len(engine._active_sessions) == 0
        
        print(f"  ✓ Cleaned {cleaned} expired sessions")
        print(f"  ✓ Session management working correctly")
        test_results.append(("Session Cleanup", True, ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Session Cleanup", False, str(e)))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in test_results if success)
    total = len(test_results)
    
    for test_name, success, error in test_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {test_name}")
        if error:
            print(f"       Error: {error}")
    
    print(f"\n  Total: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    # Save results
    results_data = {
        "test_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": total,
        "passed_tests": passed,
        "pass_rate": passed / total,
        "engine_info": engine.export_public_parameters(),
        "results": [
            {"test": name, "passed": success, "error": error}
            for name, success, error in test_results
        ]
    }
    
    with open("/home/user/autonomous-developer/QuantumCrypt-AI/test_results_post_quantum_zkp_authentication_engine.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n  Results saved to test_results_post_quantum_zkp_authentication_engine.json")
    
    return test_results


if __name__ == "__main__":
    results = run_tests()
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    sys.exit(0 if passed == total else 1)
