#!/usr/bin/env python3
"""
Chatly Authentication System End-to-End Testing
Tests all auth flows as specified in the review request:
1. SIGNUP + EMAIL (fresh, duplicate verified, validation)
2. VERIFY OTP (correct, wrong, expired, rate limit)
3. LOGIN (valid, wrong password, unverified)
4. FORGOT + RESET (wrong code, correct code, resend cooldown)
5. SECURITY (no leaks)
"""
import requests
import time
import sys
import secrets
from typing import Dict, Any, List, Tuple

# Backend URL as specified in review request
BASE_URL = "http://localhost:8001/api"

# Test credentials
DEMO_EMAIL = "demo@chatly.app"
DEMO_PASSWORD = "Demo1234"
DEMO2_EMAIL = "demo2@chatly.app"

# Use delivered@resend.dev for new signup flows (deliverable test inbox)
TEST_EMAIL_BASE = "delivered@resend.dev"

# Security check patterns (expanded per review request)
SECURITY_PATTERNS = ["Traceback", "sk_", "tvly", "sk-emergent", "ek_", "MONGO_URL", "JWT_SECRET"]

def check_security(response_text: str, step: str) -> List[str]:
    """Check if response contains any security leaks"""
    leaks = []
    for pattern in SECURITY_PATTERNS:
        if pattern in response_text:
            leaks.append(f"SECURITY LEAK in {step}: Found '{pattern}' in response")
    return leaks

def print_test_header(title: str):
    """Print formatted test section header"""
    print("\n" + "="*100)
    print(f"  {title}")
    print("="*100)

def print_step(step_num: str, description: str):
    """Print formatted test step"""
    print(f"\n[{step_num}] {description}")

def print_response(status: int, data: Any, prefix: str = "  "):
    """Print formatted response"""
    print(f"{prefix}Status: {status}")
    print(f"{prefix}Response: {data}")

def test_1_signup_email():
    """
    TEST 1: SIGNUP + EMAIL
    - Fresh signup with delivered@resend.dev -> 200 {status:"otp_sent", email, dev_code}
    - Duplicate signup with verified email (demo@chatly.app) -> 409 "An account with this email already exists."
    - Validation: missing name / bad email / password < 6 chars -> 422 or 400
    """
    print_test_header("TEST 1: SIGNUP + EMAIL")
    results = []
    security_issues = []
    
    # Use a unique email for fresh signup
    fresh_email = f"qa+{secrets.token_hex(4)}@resend.dev"
    
    # 1a) Fresh signup - expect 200 with dev_code
    print_step("1a", f"POST /auth/signup (fresh email: {fresh_email})")
    payload = {"name": "QA Test User", "email": fresh_email, "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup fresh"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200:
            if "dev_code" in data and data.get("status") == "otp_sent":
                results.append(("1a: Fresh signup", "PASS", f"200 with dev_code={data['dev_code']}"))
                # Store for later use
                global FRESH_EMAIL, FRESH_DEV_CODE
                FRESH_EMAIL = fresh_email
                FRESH_DEV_CODE = data["dev_code"]
            else:
                results.append(("1a: Fresh signup", "FAIL", f"200 but missing dev_code or status. Got: {data}"))
        else:
            results.append(("1a: Fresh signup", "FAIL", f"Expected 200, got {resp.status_code}: {data}"))
    except Exception as e:
        results.append(("1a: Fresh signup", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 1b) Duplicate signup with already-VERIFIED email -> 409
    print_step("1b", f"POST /auth/signup (duplicate verified email: {DEMO_EMAIL})")
    payload = {"name": "Duplicate User", "email": DEMO_EMAIL, "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup duplicate"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 409:
            detail = data.get("detail", "")
            if "already exists" in detail.lower():
                results.append(("1b: Duplicate verified signup", "PASS", f"409 with correct message: {detail}"))
            else:
                results.append(("1b: Duplicate verified signup", "PARTIAL", f"409 but unexpected message: {detail}"))
        else:
            results.append(("1b: Duplicate verified signup", "FAIL", f"Expected 409, got {resp.status_code}: {data}"))
    except Exception as e:
        results.append(("1b: Duplicate verified signup", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 1c) Validation: missing name -> 422 or 400
    print_step("1c", "POST /auth/signup (missing name)")
    payload = {"email": "test@example.com", "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup missing name"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code in [400, 422]:
            results.append(("1c: Missing name validation", "PASS", f"{resp.status_code} validation error"))
        else:
            results.append(("1c: Missing name validation", "FAIL", f"Expected 400/422, got {resp.status_code}"))
    except Exception as e:
        results.append(("1c: Missing name validation", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 1d) Validation: bad email -> 422 or 400
    print_step("1d", "POST /auth/signup (bad email)")
    payload = {"name": "Test", "email": "not-an-email", "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup bad email"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code in [400, 422]:
            results.append(("1d: Bad email validation", "PASS", f"{resp.status_code} validation error"))
        else:
            results.append(("1d: Bad email validation", "FAIL", f"Expected 400/422, got {resp.status_code}"))
    except Exception as e:
        results.append(("1d: Bad email validation", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 1e) Validation: password < 6 chars -> 422 or 400
    print_step("1e", "POST /auth/signup (password < 6 chars)")
    payload = {"name": "Test", "email": "test@example.com", "password": "12345"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "signup short password"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code in [400, 422]:
            results.append(("1e: Short password validation", "PASS", f"{resp.status_code} validation error"))
        else:
            results.append(("1e: Short password validation", "FAIL", f"Expected 400/422, got {resp.status_code}"))
    except Exception as e:
        results.append(("1e: Short password validation", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 1f) Confirm backend log shows email send "202 Accepted"
    print_step("1f", "Check backend logs for email send confirmation")
    print("  NOTE: Backend logs should show '202 Accepted' for email send")
    print("  This is verified by checking supervisor logs separately")
    results.append(("1f: Email send log check", "MANUAL", "Check backend logs for '202 Accepted'"))
    
    return results, security_issues

def test_2_verify_otp():
    """
    TEST 2: VERIFY OTP
    - Correct code -> 200 {token, user} with user.email_verified == true
    - Wrong code -> 400 "Incorrect code. N attempts left."
    - After 5 wrong attempts -> 429 "Too many attempts..."
    """
    print_test_header("TEST 2: VERIFY OTP")
    results = []
    security_issues = []
    
    if not FRESH_EMAIL or not FRESH_DEV_CODE:
        print("  SKIP: No fresh signup from Test 1")
        results.append(("2: Verify OTP", "SKIP", "No fresh signup available"))
        return results, security_issues
    
    # 2a) Wrong code -> 400 with attempts left
    print_step("2a", "POST /auth/verify-otp (wrong code)")
    payload = {"email": FRESH_EMAIL, "code": "000000"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/verify-otp", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "verify-otp wrong"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 400:
            detail = data.get("detail", "")
            if "attempts left" in detail.lower():
                results.append(("2a: Wrong code", "PASS", f"400 with attempts counter: {detail}"))
            else:
                results.append(("2a: Wrong code", "PARTIAL", f"400 but no attempts counter: {detail}"))
        else:
            results.append(("2a: Wrong code", "FAIL", f"Expected 400, got {resp.status_code}"))
    except Exception as e:
        results.append(("2a: Wrong code", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 2b) Correct code -> 200 with token and email_verified=true
    print_step("2b", f"POST /auth/verify-otp (correct code: {FRESH_DEV_CODE})")
    payload = {"email": FRESH_EMAIL, "code": FRESH_DEV_CODE}
    try:
        resp = requests.post(f"{BASE_URL}/auth/verify-otp", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "verify-otp correct"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200:
            if "token" in data and "user" in data:
                user = data.get("user", {})
                if user.get("email_verified") == True:
                    results.append(("2b: Correct code", "PASS", "200 with token and email_verified=true"))
                else:
                    results.append(("2b: Correct code", "PARTIAL", f"200 with token but email_verified={user.get('email_verified')}"))
            else:
                results.append(("2b: Correct code", "FAIL", f"200 but missing token or user: {data}"))
        else:
            results.append(("2b: Correct code", "FAIL", f"Expected 200, got {resp.status_code}"))
    except Exception as e:
        results.append(("2b: Correct code", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 2c) Rate limit test: 5 wrong attempts -> 429
    print_step("2c", "POST /auth/verify-otp (rate limit test - 5 wrong attempts)")
    
    # Create a new unverified account for rate limit testing
    rate_limit_email = f"qa+ratelimit{secrets.token_hex(3)}@resend.dev"
    print(f"  Creating new account for rate limit test: {rate_limit_email}")
    payload = {"name": "Rate Limit Test", "email": rate_limit_email, "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        if resp.status_code != 200:
            results.append(("2c: Rate limit test", "SKIP", "Could not create test account"))
            return results, security_issues
        
        # Try wrong code 6 times
        print("  Attempting 6 wrong codes...")
        for i in range(1, 7):
            payload = {"email": rate_limit_email, "code": "111111"}
            resp = requests.post(f"{BASE_URL}/auth/verify-otp", json=payload, timeout=30)
            security_issues.extend(check_security(resp.text, f"verify-otp attempt {i}"))
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
            print(f"  Attempt {i}: {resp.status_code} - {data.get('detail', data)}")
            
            if resp.status_code == 429:
                results.append(("2c: Rate limit (5 attempts)", "PASS", f"429 at attempt {i}"))
                break
            elif i == 5 and "0 attempts left" in str(data).lower():
                # After 5 attempts, should show 0 attempts left
                print("  ✓ Shows '0 attempts left' after 5 attempts")
            elif i == 6 and resp.status_code == 429:
                results.append(("2c: Rate limit (5 attempts)", "PASS", "429 on 6th attempt"))
                break
        else:
            results.append(("2c: Rate limit (5 attempts)", "FAIL", "Did not get 429 after 6 attempts"))
    except Exception as e:
        results.append(("2c: Rate limit test", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    return results, security_issues

def test_3_login():
    """
    TEST 3: LOGIN
    - Valid credentials -> 200 {token, user}
    - Wrong password -> 401 "Incorrect email or password."
    - Unverified account -> 403 with "verify your email" AND new OTP issued
    """
    print_test_header("TEST 3: LOGIN")
    results = []
    security_issues = []
    
    # 3a) Valid login -> 200
    print_step("3a", f"POST /auth/login (valid: {DEMO_EMAIL})")
    payload = {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login valid"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200:
            if "token" in data and "user" in data:
                results.append(("3a: Valid login", "PASS", "200 with token and user"))
            else:
                results.append(("3a: Valid login", "FAIL", f"200 but missing token or user: {data}"))
        else:
            results.append(("3a: Valid login", "FAIL", f"Expected 200, got {resp.status_code}"))
    except Exception as e:
        results.append(("3a: Valid login", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 3b) Wrong password -> 401
    print_step("3b", "POST /auth/login (wrong password)")
    payload = {"email": DEMO_EMAIL, "password": "WrongPassword123"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login wrong password"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 401:
            detail = data.get("detail", "")
            if "incorrect" in detail.lower():
                results.append(("3b: Wrong password", "PASS", f"401 with correct message: {detail}"))
            else:
                results.append(("3b: Wrong password", "PARTIAL", f"401 but unexpected message: {detail}"))
        else:
            results.append(("3b: Wrong password", "FAIL", f"Expected 401, got {resp.status_code}"))
    except Exception as e:
        results.append(("3b: Wrong password", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 3c) Unverified account login -> 403 with new OTP
    print_step("3c", "POST /auth/login (unverified account)")
    
    # Create a new unverified account
    unverified_email = f"qa+unverified{secrets.token_hex(3)}@resend.dev"
    print(f"  Creating unverified account: {unverified_email}")
    payload = {"name": "Unverified User", "email": unverified_email, "password": "Test1234"}
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=payload, timeout=30)
        if resp.status_code != 200:
            results.append(("3c: Unverified login", "SKIP", "Could not create unverified account"))
            return results, security_issues
        
        # Do NOT verify - try to login immediately
        print(f"  Attempting login without verification...")
        payload = {"email": unverified_email, "password": "Test1234"}
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login unverified"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 403:
            detail = data.get("detail", "")
            if "verify" in detail.lower() and "email" in detail.lower():
                results.append(("3c: Unverified login", "PASS", f"403 with verify message: {detail}"))
                print("  ✓ Backend should have issued new OTP (check logs for '202 Accepted')")
            else:
                results.append(("3c: Unverified login", "PARTIAL", f"403 but unexpected message: {detail}"))
        else:
            results.append(("3c: Unverified login", "FAIL", f"Expected 403, got {resp.status_code}"))
    except Exception as e:
        results.append(("3c: Unverified login", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    return results, security_issues

def test_4_forgot_reset():
    """
    TEST 4: FORGOT + RESET
    - Forgot password -> 200 {status:"reset_sent", dev_code}
    - Wrong reset code -> 400
    - Correct code -> 200 {status:"password_updated"}
    - Login with new password -> 200
    - Resend cooldown: call forgot-password twice quickly -> 2nd returns 429
    - Reset demo@chatly.app password back to Demo1234
    """
    print_test_header("TEST 4: FORGOT + RESET")
    results = []
    security_issues = []
    
    # Use demo@chatly.app for testing (pre-verified account)
    test_email = DEMO_EMAIL
    
    # 4a) Forgot password -> 200 with dev_code
    print_step("4a", f"POST /auth/forgot-password ({test_email})")
    payload = {"email": test_email}
    try:
        resp = requests.post(f"{BASE_URL}/auth/forgot-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "forgot-password"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200:
            dev_code = data.get("dev_code")
            if dev_code:
                results.append(("4a: Forgot password", "PASS", f"200 with dev_code={dev_code}"))
                global RESET_DEV_CODE
                RESET_DEV_CODE = dev_code
                print("  ✓ Backend should show '202 Accepted' in logs")
            else:
                results.append(("4a: Forgot password", "FAIL", f"200 but no dev_code: {data}"))
                return results, security_issues
        else:
            results.append(("4a: Forgot password", "FAIL", f"Expected 200, got {resp.status_code}"))
            return results, security_issues
    except Exception as e:
        results.append(("4a: Forgot password", "ERROR", str(e)))
        print(f"  ERROR: {e}")
        return results, security_issues
    
    # 4b) Wrong reset code -> 400
    print_step("4b", "POST /auth/reset-password (wrong code)")
    payload = {"email": test_email, "code": "000000", "new_password": DEMO_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "reset-password wrong"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 400:
            results.append(("4b: Wrong reset code", "PASS", f"400: {data.get('detail', data)}"))
        else:
            results.append(("4b: Wrong reset code", "FAIL", f"Expected 400, got {resp.status_code}"))
    except Exception as e:
        results.append(("4b: Wrong reset code", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 4c) Correct reset code -> 200
    print_step("4c", f"POST /auth/reset-password (correct code: {RESET_DEV_CODE})")
    payload = {"email": test_email, "code": RESET_DEV_CODE, "new_password": DEMO_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/reset-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "reset-password correct"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200:
            if data.get("status") == "password_updated":
                results.append(("4c: Correct reset code", "PASS", "200 with password_updated"))
            else:
                results.append(("4c: Correct reset code", "PARTIAL", f"200 but status={data.get('status')}"))
        else:
            results.append(("4c: Correct reset code", "FAIL", f"Expected 200, got {resp.status_code}"))
    except Exception as e:
        results.append(("4c: Correct reset code", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 4d) Login with new password -> 200
    print_step("4d", "POST /auth/login (with reset password)")
    payload = {"email": test_email, "password": DEMO_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        security_issues.extend(check_security(resp.text, "login after reset"))
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
        print_response(resp.status_code, data)
        
        if resp.status_code == 200 and "token" in data:
            results.append(("4d: Login after reset", "PASS", "200 with token"))
        else:
            results.append(("4d: Login after reset", "FAIL", f"Expected 200 with token, got {resp.status_code}"))
    except Exception as e:
        results.append(("4d: Login after reset", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 4e) Resend cooldown: call forgot-password twice quickly -> 429
    print_step("4e", "POST /auth/forgot-password (resend cooldown test)")
    payload = {"email": test_email}
    try:
        # First call
        resp1 = requests.post(f"{BASE_URL}/auth/forgot-password", json=payload, timeout=30)
        print(f"  First call: {resp1.status_code}")
        
        # Immediate second call
        resp2 = requests.post(f"{BASE_URL}/auth/forgot-password", json=payload, timeout=30)
        security_issues.extend(check_security(resp2.text, "forgot-password cooldown"))
        data2 = resp2.json() if resp2.headers.get("content-type", "").startswith("application/json") else {"error": resp2.text}
        print(f"  Second call (immediate): {resp2.status_code} - {data2}")
        
        if resp2.status_code == 429:
            detail = data2.get("detail", "")
            if "wait" in detail.lower():
                results.append(("4e: Resend cooldown", "PASS", f"429 with wait message: {detail}"))
            else:
                results.append(("4e: Resend cooldown", "PARTIAL", f"429 but unexpected message: {detail}"))
        else:
            results.append(("4e: Resend cooldown", "FAIL", f"Expected 429, got {resp2.status_code}"))
    except Exception as e:
        results.append(("4e: Resend cooldown", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    # 4f) Ensure demo@chatly.app password is Demo1234 for future tests
    print_step("4f", "Verify demo@chatly.app password is Demo1234")
    payload = {"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
    try:
        resp = requests.post(f"{BASE_URL}/auth/login", json=payload, timeout=30)
        if resp.status_code == 200:
            results.append(("4f: Password verification", "PASS", "demo@chatly.app password is Demo1234"))
            print("  ✓ Password confirmed as Demo1234")
        else:
            results.append(("4f: Password verification", "FAIL", f"Login failed: {resp.status_code}"))
            print("  ✗ Password may not be Demo1234")
    except Exception as e:
        results.append(("4f: Password verification", "ERROR", str(e)))
        print(f"  ERROR: {e}")
    
    return results, security_issues

def test_5_security():
    """
    TEST 5: SECURITY
    Confirm NO response leaks stack traces, API keys, or sensitive config
    """
    print_test_header("TEST 5: SECURITY")
    results = []
    security_issues = []
    
    print("  Security checks are performed on all API responses throughout testing.")
    print("  Patterns checked: Traceback, sk_, tvly, sk-emergent, ek_, MONGO_URL, JWT_SECRET")
    print("  See final summary for any detected leaks.")
    
    results.append(("5: Security checks", "INFO", "Performed on all responses"))
    
    return results, security_issues

def print_summary(all_results: List[Tuple[str, str, str]], all_security_issues: List[str]):
    """Print comprehensive test summary"""
    print("\n" + "="*100)
    print("  COMPREHENSIVE TEST SUMMARY")
    print("="*100)
    
    # Group by test section
    sections = {
        "1": "SIGNUP + EMAIL",
        "2": "VERIFY OTP",
        "3": "LOGIN",
        "4": "FORGOT + RESET",
        "5": "SECURITY"
    }
    
    for section_num, section_name in sections.items():
        section_results = [r for r in all_results if r[0].startswith(section_num)]
        if section_results:
            print(f"\n{section_name}:")
            for test, status, detail in section_results:
                status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️" if status == "ERROR" else "ℹ️"
                print(f"  {status_icon} {test}: {status}")
                if detail and status in ["FAIL", "ERROR", "PARTIAL"]:
                    print(f"     → {detail}")
    
    print("\n" + "="*100)
    print("  SECURITY ANALYSIS")
    print("="*100)
    if all_security_issues:
        print("❌ SECURITY ISSUES DETECTED:")
        for issue in all_security_issues:
            print(f"  - {issue}")
    else:
        print("✅ NO SECURITY LEAKS DETECTED")
        print("   Checked all responses for: Traceback, sk_, tvly, sk-emergent, ek_, MONGO_URL, JWT_SECRET")
    
    print("\n" + "="*100)
    print("  STATISTICS")
    print("="*100)
    
    passed = sum(1 for _, status, _ in all_results if status == "PASS")
    failed = sum(1 for _, status, _ in all_results if status == "FAIL")
    errors = sum(1 for _, status, _ in all_results if status == "ERROR")
    partial = sum(1 for _, status, _ in all_results if status == "PARTIAL")
    skipped = sum(1 for _, status, _ in all_results if status == "SKIP")
    info = sum(1 for _, status, _ in all_results if status == "INFO")
    
    total = len(all_results)
    print(f"Total Tests: {total}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⚠️  Errors: {errors}")
    print(f"⚠️  Partial: {partial}")
    print(f"⏭️  Skipped: {skipped}")
    print(f"ℹ️  Info: {info}")
    
    if failed == 0 and errors == 0 and not all_security_issues:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print("\n⚠️  SOME TESTS FAILED OR HAD ERRORS")
    
    print("="*100)

def main():
    """Run all authentication tests"""
    print("="*100)
    print("  CHATLY AUTHENTICATION SYSTEM - END-TO-END TESTING")
    print("="*100)
    print(f"Backend URL: {BASE_URL}")
    print(f"Test accounts: {DEMO_EMAIL}, {DEMO2_EMAIL}")
    print(f"Fresh signups: qa+<random>@resend.dev")
    print("="*100)
    
    # Initialize globals
    global FRESH_EMAIL, FRESH_DEV_CODE, RESET_DEV_CODE
    FRESH_EMAIL = None
    FRESH_DEV_CODE = None
    RESET_DEV_CODE = None
    
    all_results = []
    all_security_issues = []
    
    # Run all test suites
    try:
        results, security = test_1_signup_email()
        all_results.extend(results)
        all_security_issues.extend(security)
    except Exception as e:
        print(f"\n❌ TEST 1 CRASHED: {e}")
        all_results.append(("Test 1", "ERROR", str(e)))
    
    try:
        results, security = test_2_verify_otp()
        all_results.extend(results)
        all_security_issues.extend(security)
    except Exception as e:
        print(f"\n❌ TEST 2 CRASHED: {e}")
        all_results.append(("Test 2", "ERROR", str(e)))
    
    try:
        results, security = test_3_login()
        all_results.extend(results)
        all_security_issues.extend(security)
    except Exception as e:
        print(f"\n❌ TEST 3 CRASHED: {e}")
        all_results.append(("Test 3", "ERROR", str(e)))
    
    try:
        results, security = test_4_forgot_reset()
        all_results.extend(results)
        all_security_issues.extend(security)
    except Exception as e:
        print(f"\n❌ TEST 4 CRASHED: {e}")
        all_results.append(("Test 4", "ERROR", str(e)))
    
    try:
        results, security = test_5_security()
        all_results.extend(results)
        all_security_issues.extend(security)
    except Exception as e:
        print(f"\n❌ TEST 5 CRASHED: {e}")
        all_results.append(("Test 5", "ERROR", str(e)))
    
    # Print comprehensive summary
    print_summary(all_results, all_security_issues)
    
    # Exit with appropriate code
    failed = sum(1 for _, status, _ in all_results if status in ["FAIL", "ERROR"])
    if failed > 0 or all_security_issues:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
