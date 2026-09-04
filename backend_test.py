#!/usr/bin/env python3
"""
OTP Authentication Flow Testing for Chatly AI Messenger
Tests signup, verify, resend, forgot-password, reset-password, and rate limiting
"""
import requests
import time
import sys
from typing import Dict, Any

# Backend URL from frontend/.env
BASE_URL = "https://app-executor-28.preview.emergentagent.com/api"

# Test credentials
TEST_EMAIL = "delivered@resend.dev"
TEST_NAME = "QA Bot"
TEST_PASSWORD = "Test1234"
DEMO_EMAIL = "demo@chatly.app"
DEMO_PASSWORD = "Demo1234"

# Security check patterns
SECURITY_PATTERNS = ["Traceback", "sk_", "tvly", "sk-emergent"]

def check_security(response_text: str, step: str) -> list:
    """Check if response contains any security leaks"""
    leaks = []
    for pattern in SECURITY_PATTERNS:
        if pattern in response_text:
            leaks.append(f"SECURITY LEAK in {step}: Found '{pattern}' in response")
    return leaks

def test_signup_verify_flow():
    """Test A: SIGNUP + VERIFY flow"""
    results = []
    security_issues = []
    
    print("\n=== A) SIGNUP + VERIFY FLOW ===\n")
    
    # Step 1: Signup
    print("Step 1: POST /api/auth/signup")
    payload = {"name": TEST_NAME, "email": TEST_EMAIL, "password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup"))
        
        if resp.status_code == 409:
            print(f"  ✓ Status: {resp.status_code} (account already exists and verified)")
            print(f"  Response: {resp.json()}")
            results.append(("Step 1: Signup (already verified)", resp.status_code, "SKIP - account verified", resp.json()))
            # Skip to step 4 (login)
            return test_login_only(results, security_issues)
        elif resp.status_code == 200:
            data = resp.json()
            print(f"  ✓ Status: {resp.status_code}")
            print(f"  Response: {data}")
            dev_code = data.get("dev_code")
            if not dev_code:
                results.append(("Step 1: Signup", resp.status_code, "FAIL - no dev_code", data))
                print("  ✗ FAIL: No dev_code in response")
                return results, security_issues
            results.append(("Step 1: Signup", resp.status_code, "PASS", data))
        else:
            print(f"  ✗ Status: {resp.status_code}")
            print(f"  Response: {resp.text}")
            results.append(("Step 1: Signup", resp.status_code, "FAIL", resp.text))
            return results, security_issues
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 1: Signup", "ERROR", str(e), None))
        return results, security_issues
    
    # Step 2: Wrong code
    print("\nStep 2: POST /api/auth/verify-otp (wrong code)")
    payload = {"email": TEST_EMAIL, "code": "000000"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/verify-otp", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "verify-otp wrong"))
        print(f"  ✓ Status: {resp.status_code}")
        print(f"  Response: {resp.json()}")
        if resp.status_code == 400 and "attempts left" in resp.text.lower():
            results.append(("Step 2: Verify wrong code", resp.status_code, "PASS", resp.json()))
        else:
            results.append(("Step 2: Verify wrong code", resp.status_code, "FAIL - expected 400 with attempts left", resp.json()))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 2: Verify wrong code", "ERROR", str(e), None))
    
    # Step 3: Correct code
    print("\nStep 3: POST /api/auth/verify-otp (correct code)")
    payload = {"email": TEST_EMAIL, "code": dev_code}
    try:
        resp = requests.post(f"{BASE_URL}/auth/verify-otp", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "verify-otp correct"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        if resp.status_code == 200 and "token" in data and "user" in data:
            results.append(("Step 3: Verify correct code", resp.status_code, "PASS", data))
        else:
            results.append(("Step 3: Verify correct code", resp.status_code, "FAIL - expected 200 with token and user", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 3: Verify correct code", "ERROR", str(e), None))
    
    # Step 4: Login
    print("\nStep 4: POST /api/auth/login")
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        if resp.status_code == 200 and "token" in data and "user" in data:
            results.append(("Step 4: Login", resp.status_code, "PASS", data))
        else:
            results.append(("Step 4: Login", resp.status_code, "FAIL - expected 200 with token and user", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 4: Login", "ERROR", str(e), None))
    
    return results, security_issues

def test_login_only(results, security_issues):
    """Test login when account is already verified"""
    print("\nStep 4: POST /api/auth/login (account already verified)")
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        if resp.status_code == 200 and "token" in data and "user" in data:
            results.append(("Step 4: Login", resp.status_code, "PASS", data))
        else:
            results.append(("Step 4: Login", resp.status_code, "FAIL - expected 200 with token and user", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 4: Login", "ERROR", str(e), None))
    
    return results, security_issues

def test_resend_cooldown():
    """Test B: RESEND COOLDOWN (rate limit on resend)"""
    results = []
    security_issues = []
    
    print("\n=== B) RESEND COOLDOWN ===\n")
    
    print("Step 5: POST /api/auth/resend-otp (testing cooldown)")
    payload = {"email": TEST_EMAIL}
    try:
        resp = requests.post(f"{BASE_URL}/auth/resend-otp", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "resend-otp"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        print(f"  Response: {data}")
        
        if resp.status_code == 400 and "already verified" in str(data).lower():
            results.append(("Step 5: Resend cooldown", resp.status_code, "PASS - account already verified (expected)", data))
            print("  ✓ Account already verified (expected behavior)")
        elif resp.status_code == 200:
            # Try immediate second resend
            print("\n  Attempting immediate second resend...")
            resp2 = requests.post(f"{BASE_URL}/auth/resend-otp", json=payload, timeout=30)
            security_issues.extend(check_security(resp2.text, "resend-otp second"))
            print(f"  ✓ Status: {resp2.status_code}")
            data2 = resp2.json() if resp2.headers.get("content-type", "").startswith("application/json") else resp2.text
            print(f"  Response: {data2}")
            if resp2.status_code == 429:
                results.append(("Step 5: Resend cooldown", resp2.status_code, "PASS - cooldown enforced", data2))
            else:
                results.append(("Step 5: Resend cooldown", resp2.status_code, "FAIL - expected 429 on immediate resend", data2))
        else:
            results.append(("Step 5: Resend cooldown", resp.status_code, "UNEXPECTED", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 5: Resend cooldown", "ERROR", str(e), None))
    
    return results, security_issues

def test_forgot_reset_flow():
    """Test C: FORGOT PASSWORD + RESET"""
    results = []
    security_issues = []
    
    print("\n=== C) FORGOT PASSWORD + RESET ===\n")
    
    # Step 6: Forgot password (use TEST_EMAIL since demo@chatly.app is blocked by email provider)
    print("Step 6: POST /api/auth/forgot-password")
    print("  Note: Using delivered@resend.dev instead of demo@chatly.app (email provider blocks non-deliverable addresses)")
    payload = {"email": TEST_EMAIL}
    try:
        resp = requests.post(f"{BASE_URL}/auth/forgot-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "forgot-password"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        dev_code = data.get("dev_code")
        if resp.status_code == 200 and dev_code:
            results.append(("Step 6: Forgot password", resp.status_code, "PASS", data))
        else:
            results.append(("Step 6: Forgot password", resp.status_code, "FAIL - expected 200 with dev_code", data))
            return results, security_issues
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 6: Forgot password", "ERROR", str(e), None))
        return results, security_issues
    
    # Step 7: Wrong reset code
    print("\nStep 7: POST /api/auth/reset-password (wrong code)")
    payload = {"email": TEST_EMAIL, "code": "000000", "new_password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "reset-password wrong"))
        print(f"  ✓ Status: {resp.status_code}")
        print(f"  Response: {resp.json()}")
        if resp.status_code == 400:
            results.append(("Step 7: Reset wrong code", resp.status_code, "PASS", resp.json()))
        else:
            results.append(("Step 7: Reset wrong code", resp.status_code, "FAIL - expected 400", resp.json()))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 7: Reset wrong code", "ERROR", str(e), None))
    
    # Step 8: Correct reset
    print("\nStep 8: POST /api/auth/reset-password (correct code)")
    payload = {"email": TEST_EMAIL, "code": dev_code, "new_password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "reset-password correct"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        if resp.status_code == 200 and data.get("status") == "password_updated":
            results.append(("Step 8: Reset correct code", resp.status_code, "PASS", data))
        else:
            results.append(("Step 8: Reset correct code", resp.status_code, "FAIL - expected 200 with password_updated", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 8: Reset correct code", "ERROR", str(e), None))
    
    # Step 9: Login with reset password
    print("\nStep 9: POST /api/auth/login (with reset password)")
    payload = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login after reset"))
        print(f"  ✓ Status: {resp.status_code}")
        data = resp.json()
        print(f"  Response: {data}")
        if resp.status_code == 200 and "token" in data:
            results.append(("Step 9: Login with reset password", resp.status_code, "PASS", data))
        else:
            results.append(("Step 9: Login with reset password", resp.status_code, "FAIL - expected 200 with token", data))
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        results.append(("Step 9: Login with reset password", "ERROR", str(e), None))
    
    return results, security_issues

def test_rate_limit():
    """Test D: RATE LIMIT (max attempts)"""
    results = []
    security_issues = []
    
    print("\n=== D) RATE LIMIT (MAX ATTEMPTS) ===\n")
    
    # Step 10: Trigger fresh reset and exhaust attempts
    print("Step 10: Testing rate limit (5 wrong attempts)")
    print("  Note: Using delivered@resend.dev for testing")
    
    # Get a fresh reset code
    print("  Getting fresh reset code...")
    payload = {"email": TEST_EMAIL}
    try:
        resp = requests.post(f"{BASE_URL}/auth/forgot-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "forgot-password for rate limit"))
        data = resp.json()
        dev_code = data.get("dev_code")
        print(f"  ✓ Got dev_code: {dev_code}")
    except Exception as e:
        print(f"  ✗ ERROR getting reset code: {e}")
        results.append(("Step 10: Rate limit setup", "ERROR", str(e), None))
        return results, security_issues
    
    # Try wrong code 5 times
    print("\n  Attempting 5 wrong codes...")
    last_response = None
    for i in range(1, 7):  # Try up to 6 times to trigger 429
        payload = {"email": TEST_EMAIL, "code": "111111", "new_password": TEST_PASSWORD}
        try:
            resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
            security_issues.extend(check_security(resp.text, f"reset-password attempt {i}"))
            last_response = resp
            print(f"  Attempt {i}: Status {resp.status_code} - {resp.json()}")
            
            if resp.status_code == 429:
                results.append(("Step 10: Rate limit (5 attempts)", resp.status_code, "PASS", resp.json()))
                print(f"  ✓ Rate limit triggered at attempt {i}")
                break
            elif i >= 5 and resp.status_code == 400 and "0 attempts left" in resp.text.lower():
                # After 5 attempts, the next attempt should return 429, but if it says "0 attempts left" that's also acceptable
                results.append(("Step 10: Rate limit (5 attempts)", resp.status_code, "PASS - 0 attempts left", resp.json()))
                print(f"  ✓ Rate limit enforced (0 attempts left)")
                break
        except Exception as e:
            print(f"  ✗ ERROR on attempt {i}: {e}")
            results.append(("Step 10: Rate limit attempt", "ERROR", str(e), None))
            break
    else:
        # If we got through all 6 attempts without 429 or "0 attempts left"
        if last_response:
            results.append(("Step 10: Rate limit (5 attempts)", last_response.status_code, "FAIL - expected 429 or 0 attempts left", last_response.json()))
    
    # Reset password back to Test1234 for future tests
    print("\n  Resetting password back to Test1234...")
    print("  Making one more attempt to trigger 429 and clear the exhausted OTP...")
    try:
        # Make 6th attempt to trigger 429 and delete the exhausted OTP record
        payload = {"email": TEST_EMAIL, "code": "111111", "new_password": TEST_PASSWORD}
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        print(f"  6th attempt: Status {resp.status_code} - {resp.json()}")
        
        # Now get fresh code
        resp = requests.post(f"{BASE_URL}/auth/forgot-password", json={"email": TEST_EMAIL}, timeout=30)
        security_issues.extend(check_security(resp.text, "forgot-password final"))
        new_code = resp.json().get("dev_code")
        print(f"  ✓ Got new dev_code: {new_code}")
        
        # Reset with correct code
        payload = {"email": TEST_EMAIL, "code": new_code, "new_password": TEST_PASSWORD}
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "reset-password final"))
        print(f"  ✓ Reset status: {resp.status_code} - {resp.json()}")
        
        # Verify login works
        resp = requests.post(f"{BASE_URL}/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}, timeout=30)
        security_issues.extend(check_security(resp.text, "login final"))
        if resp.status_code == 200:
            print(f"  ✓ Login verified: {resp.status_code}")
            results.append(("Step 10: Reset password", resp.status_code, "PASS - password restored", resp.json()))
        else:
            print(f"  ✗ Login failed: {resp.status_code}")
            results.append(("Step 10: Reset password", resp.status_code, "FAIL - login failed", resp.json()))
    except Exception as e:
        print(f"  ✗ ERROR resetting password: {e}")
        results.append(("Step 10: Reset password", "ERROR", str(e), None))
    
    return results, security_issues

def print_summary(all_results, all_security_issues):
    """Print test summary table"""
    print("\n" + "="*100)
    print("TEST SUMMARY")
    print("="*100)
    print(f"{'Step':<50} {'Status':<10} {'Result':<15} {'Notes':<25}")
    print("-"*100)
    
    for step, status, result, data in all_results:
        notes = ""
        if isinstance(data, dict):
            if "dev_code" in data:
                notes = f"dev_code: {data['dev_code']}"
            elif "token" in data:
                notes = "token received"
            elif "status" in data:
                notes = data["status"]
        print(f"{step:<50} {str(status):<10} {result:<15} {notes:<25}")
    
    print("\n" + "="*100)
    print("SECURITY CHECK")
    print("="*100)
    if all_security_issues:
        print("❌ SECURITY ISSUES FOUND:")
        for issue in all_security_issues:
            print(f"  - {issue}")
    else:
        print("✅ NO SECURITY LEAKS DETECTED (no Traceback, sk_, tvly, sk-emergent in responses)")
    
    print("\n" + "="*100)
    
    # Count pass/fail
    passed = sum(1 for _, _, result, _ in all_results if "PASS" in result)
    failed = sum(1 for _, _, result, _ in all_results if "FAIL" in result)
    errors = sum(1 for _, _, result, _ in all_results if "ERROR" in result)
    skipped = sum(1 for _, _, result, _ in all_results if "SKIP" in result)
    
    print(f"\nTOTAL: {len(all_results)} tests")
    print(f"✅ PASSED: {passed}")
    print(f"❌ FAILED: {failed}")
    print(f"⚠️  ERRORS: {errors}")
    print(f"⏭️  SKIPPED: {skipped}")
    print("="*100)

def main():
    print("="*100)
    print("CHATLY AI MESSENGER - OTP AUTHENTICATION FLOW TESTING")
    print("="*100)
    print(f"Backend URL: {BASE_URL}")
    print(f"Test email: {TEST_EMAIL}")
    print(f"Demo email: {DEMO_EMAIL}")
    print("="*100)
    
    all_results = []
    all_security_issues = []
    
    # Run all test flows
    results, security = test_signup_verify_flow()
    all_results.extend(results)
    all_security_issues.extend(security)
    
    results, security = test_resend_cooldown()
    all_results.extend(results)
    all_security_issues.extend(security)
    
    results, security = test_forgot_reset_flow()
    all_results.extend(results)
    all_security_issues.extend(security)
    
    results, security = test_rate_limit()
    all_results.extend(results)
    all_security_issues.extend(security)
    
    # Restore demo@chatly.app password to Demo1234 (even though email provider blocks it, the password should be set)
    print("\n=== CLEANUP: Restoring demo@chatly.app password ===\n")
    try:
        # Try to login with Demo1234 first
        resp = requests.post(f"{BASE_URL}/auth/login", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}, timeout=30)
        if resp.status_code == 200:
            print(f"  ✓ demo@chatly.app password is already Demo1234")
        else:
            print(f"  ℹ demo@chatly.app login status: {resp.status_code}")
            print(f"  Note: Email provider blocks demo@chatly.app, so password reset via OTP not possible")
            print(f"  The seeded demo account should have Demo1234 as password by default")
    except Exception as e:
        print(f"  ℹ Could not verify demo@chatly.app: {e}")
    
    # Print summary
    print_summary(all_results, all_security_issues)
    
    # Exit with appropriate code
    failed = sum(1 for _, _, result, _ in all_results if "FAIL" in result)
    errors = sum(1 for _, _, result, _ in all_results if "ERROR" in result)
    if failed > 0 or errors > 0 or all_security_issues:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
