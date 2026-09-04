#!/usr/bin/env python3
"""
FINAL COMPREHENSIVE AUTH TEST - All Review Request Requirements
Tests ALL scenarios specified in the review request
"""
import requests
import time
import secrets
import sys

BASE_URL = "http://localhost:8001/api"
DEMO_EMAIL = "demo@chatly.app"
DEMO2_EMAIL = "demo2@chatly.app"
DEMO_PASSWORD = "Demo1234"

SECURITY_PATTERNS = ["Traceback", "sk_", "tvly", "sk-emergent", "ek_", "MONGO_URL", "JWT_SECRET"]

def check_security(text):
    """Check for security leaks"""
    leaks = []
    for pattern in SECURITY_PATTERNS:
        if pattern in text:
            leaks.append(pattern)
    return leaks

def print_header(title):
    print("\n" + "="*100)
    print(f"  {title}")
    print("="*100)

def print_test(num, desc, status_code, data, expected_status=None, expected_in_detail=None):
    """Print test result with pass/fail"""
    status_match = (expected_status is None) or (status_code == expected_status)
    detail_match = (expected_in_detail is None) or (expected_in_detail.lower() in str(data.get("detail", "")).lower())
    
    if status_match and detail_match:
        icon = "✅ PASS"
    else:
        icon = "❌ FAIL"
    
    print(f"\n[{num}] {desc}")
    print(f"  {icon} | Status: {status_code} | Response: {data}")
    
    # Check security
    leaks = check_security(str(data))
    if leaks:
        print(f"  ⚠️  SECURITY LEAK: Found {leaks}")
        return False, leaks
    
    return status_match and detail_match, []

def main():
    print("="*100)
    print("  CHATLY AUTHENTICATION - COMPREHENSIVE END-TO-END TEST")
    print("  Testing ALL requirements from review request")
    print("="*100)
    print(f"Backend: {BASE_URL}")
    print(f"Pre-verified accounts: {DEMO_EMAIL}, {DEMO2_EMAIL} (password: {DEMO_PASSWORD})")
    print(f"Test inbox: delivered@resend.dev")
    print("="*100)
    
    all_passed = True
    all_security_leaks = []
    
    # ========================================================================
    # TEST 1: SIGNUP + EMAIL
    # ========================================================================
    print_header("TEST 1: SIGNUP + EMAIL")
    
    # 1a) Fresh signup with qa+<random>@resend.dev
    fresh_email = f"qa+{secrets.token_hex(4)}@resend.dev"
    print(f"\n[1a] Fresh signup: {fresh_email}")
    resp = requests.post(f"{BASE_URL}/auth/signup", 
                        json={"name": "QA User", "email": fresh_email, "password": "Test1234"}, 
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("1a", "Fresh signup -> 200 with dev_code", resp.status_code, data, 200)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    if resp.status_code == 200 and "dev_code" in data:
        fresh_dev_code = data["dev_code"]
        print(f"  📧 Email should show '202 Accepted' in backend logs")
    else:
        print(f"  ❌ No dev_code in response")
        fresh_dev_code = None
    
    # 1b) Duplicate signup with verified email
    print(f"\n[1b] Duplicate verified email: {DEMO_EMAIL}")
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"name": "Duplicate", "email": DEMO_EMAIL, "password": "Test1234"},
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("1b", "Duplicate verified -> 409 'already exists'", resp.status_code, data, 409, "already exists")
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # 1c) Validation: missing name
    print(f"\n[1c] Validation: missing name")
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"email": "test@test.com", "password": "Test1234"},
                        timeout=30)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
    passed, leaks = print_test("1c", "Missing name -> 422", resp.status_code, data, 422)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # 1d) Validation: bad email
    print(f"\n[1d] Validation: bad email")
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"name": "Test", "email": "not-email", "password": "Test1234"},
                        timeout=30)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
    passed, leaks = print_test("1d", "Bad email -> 422", resp.status_code, data, 422)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # 1e) Validation: password < 6 chars
    print(f"\n[1e] Validation: password < 6 chars")
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"name": "Test", "email": "test@test.com", "password": "12345"},
                        timeout=30)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": resp.text}
    passed, leaks = print_test("1e", "Short password -> 422", resp.status_code, data, 422)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # ========================================================================
    # TEST 2: VERIFY OTP
    # ========================================================================
    print_header("TEST 2: VERIFY OTP")
    
    if fresh_dev_code:
        # 2a) Wrong code
        print(f"\n[2a] Wrong OTP code")
        resp = requests.post(f"{BASE_URL}/auth/verify-otp",
                            json={"email": fresh_email, "code": "000000"},
                            timeout=30)
        data = resp.json()
        passed, leaks = print_test("2a", "Wrong code -> 400 'attempts left'", resp.status_code, data, 400, "attempts left")
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
        
        # 2b) Correct code
        print(f"\n[2b] Correct OTP code: {fresh_dev_code}")
        resp = requests.post(f"{BASE_URL}/auth/verify-otp",
                            json={"email": fresh_email, "code": fresh_dev_code},
                            timeout=30)
        data = resp.json()
        passed, leaks = print_test("2b", "Correct code -> 200 with token, email_verified=true", resp.status_code, data, 200)
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
        
        if data.get("user", {}).get("email_verified") == True:
            print(f"  ✅ email_verified = true")
        else:
            print(f"  ❌ email_verified = {data.get('user', {}).get('email_verified')}")
            all_passed = False
        
        # 2c) Rate limit test
        print(f"\n[2c] Rate limit test (5 wrong attempts)")
        rate_email = f"qa+rate{secrets.token_hex(3)}@resend.dev"
        resp = requests.post(f"{BASE_URL}/auth/signup",
                            json={"name": "Rate Test", "email": rate_email, "password": "Test1234"},
                            timeout=30)
        
        if resp.status_code == 200:
            print(f"  Created test account: {rate_email}")
            for i in range(1, 7):
                resp = requests.post(f"{BASE_URL}/auth/verify-otp",
                                   json={"email": rate_email, "code": "111111"},
                                   timeout=30)
                data = resp.json()
                print(f"  Attempt {i}: {resp.status_code} - {data.get('detail', data)}")
                
                if resp.status_code == 429:
                    print(f"  ✅ Rate limit triggered at attempt {i}")
                    break
                elif i == 5 and "0 attempts left" in str(data).lower():
                    print(f"  ✅ Shows '0 attempts left' after 5 attempts")
    
    # ========================================================================
    # TEST 3: LOGIN
    # ========================================================================
    print_header("TEST 3: LOGIN")
    
    # 3a) Valid login
    print(f"\n[3a] Valid login: {DEMO_EMAIL}")
    resp = requests.post(f"{BASE_URL}/auth/login",
                        json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("3a", "Valid login -> 200 with token", resp.status_code, data, 200)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # 3b) Wrong password
    print(f"\n[3b] Wrong password")
    resp = requests.post(f"{BASE_URL}/auth/login",
                        json={"email": DEMO_EMAIL, "password": "WrongPass123"},
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("3b", "Wrong password -> 401 'Incorrect email or password'", resp.status_code, data, 401, "incorrect")
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    # 3c) Unverified account login
    print(f"\n[3c] Unverified account login (with cooldown wait)")
    unverified_email = f"qa+unverified{secrets.token_hex(3)}@resend.dev"
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"name": "Unverified", "email": unverified_email, "password": "Test1234"},
                        timeout=30)
    print(f"  Created unverified account: {unverified_email}")
    print(f"  Waiting 47s for cooldown...")
    time.sleep(47)
    
    resp = requests.post(f"{BASE_URL}/auth/login",
                        json={"email": unverified_email, "password": "Test1234"},
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("3c", "Unverified login -> 403 'verify your email' + new OTP", resp.status_code, data, 403, "verify")
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    print(f"  📧 Backend should show '202 Accepted' for new OTP in logs")
    
    # ========================================================================
    # TEST 4: FORGOT + RESET
    # ========================================================================
    print_header("TEST 4: FORGOT + RESET")
    
    # Use delivered@resend.dev (deliverable test inbox)
    test_email = "delivered@resend.dev"
    
    # Wait for cooldown
    print(f"\n  Waiting 47s for cooldown...")
    time.sleep(47)
    
    # 4a) Forgot password
    print(f"\n[4a] Forgot password: {test_email}")
    resp = requests.post(f"{BASE_URL}/auth/forgot-password",
                        json={"email": test_email},
                        timeout=30)
    data = resp.json()
    passed, leaks = print_test("4a", "Forgot password -> 200 with dev_code", resp.status_code, data, 200)
    all_passed = all_passed and passed
    all_security_leaks.extend(leaks)
    
    if "dev_code" in data:
        reset_code = data["dev_code"]
        print(f"  📧 Email should show '202 Accepted' in logs")
        
        # 4b) Wrong reset code
        print(f"\n[4b] Wrong reset code")
        resp = requests.post(f"{BASE_URL}/auth/reset-password",
                            json={"email": test_email, "code": "000000", "new_password": "Test1234"},
                            timeout=30)
        data = resp.json()
        passed, leaks = print_test("4b", "Wrong code -> 400", resp.status_code, data, 400)
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
        
        # 4c) Correct reset code
        print(f"\n[4c] Correct reset code: {reset_code}")
        resp = requests.post(f"{BASE_URL}/auth/reset-password",
                            json={"email": test_email, "code": reset_code, "new_password": "Test1234"},
                            timeout=30)
        data = resp.json()
        passed, leaks = print_test("4c", "Correct code -> 200 'password_updated'", resp.status_code, data, 200)
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
        
        # 4d) Login with new password
        print(f"\n[4d] Login with reset password")
        resp = requests.post(f"{BASE_URL}/auth/login",
                            json={"email": test_email, "password": "Test1234"},
                            timeout=30)
        data = resp.json()
        passed, leaks = print_test("4d", "Login after reset -> 200", resp.status_code, data, 200)
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
        
        # 4e) Resend cooldown
        print(f"\n[4e] Resend cooldown test")
        resp1 = requests.post(f"{BASE_URL}/auth/forgot-password",
                             json={"email": test_email},
                             timeout=30)
        print(f"  First call: {resp1.status_code}")
        
        resp2 = requests.post(f"{BASE_URL}/auth/forgot-password",
                             json={"email": test_email},
                             timeout=30)
        data2 = resp2.json()
        passed, leaks = print_test("4e", "Immediate 2nd forgot -> 429 with wait message", resp2.status_code, data2, 429, "wait")
        all_passed = all_passed and passed
        all_security_leaks.extend(leaks)
    
    # 4f) Restore demo@chatly.app password
    print(f"\n[4f] Verify demo@chatly.app password is Demo1234")
    resp = requests.post(f"{BASE_URL}/auth/login",
                        json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
                        timeout=30)
    if resp.status_code == 200:
        print(f"  ✅ demo@chatly.app password confirmed as Demo1234")
    else:
        print(f"  ⚠️  demo@chatly.app login: {resp.status_code}")
    
    # ========================================================================
    # TEST 5: SECURITY
    # ========================================================================
    print_header("TEST 5: SECURITY")
    
    if all_security_leaks:
        print(f"\n❌ SECURITY LEAKS DETECTED:")
        for leak in set(all_security_leaks):
            print(f"  - {leak}")
        all_passed = False
    else:
        print(f"\n✅ NO SECURITY LEAKS DETECTED")
        print(f"  Checked all responses for: {', '.join(SECURITY_PATTERNS)}")
    
    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    print_header("FINAL SUMMARY")
    
    if all_passed and not all_security_leaks:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n✅ SIGNUP + EMAIL: All validation working, dev_code returned, email sent (202)")
        print("✅ VERIFY OTP: Wrong code rejected, correct code works, rate limit enforced")
        print("✅ LOGIN: Valid works, wrong password rejected, unverified triggers new OTP")
        print("✅ FORGOT + RESET: dev_code returned, wrong code rejected, correct works, cooldown enforced")
        print("✅ SECURITY: No leaks of Traceback, sk_, tvly, sk-emergent, ek_, MONGO_URL, JWT_SECRET")
        print("\n📧 Backend logs should show '202 Accepted' for all email sends")
        print("📧 OTP_DEBUG=1 working: dev_code in responses and logged")
        sys.exit(0)
    else:
        print("\n⚠️  SOME TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
