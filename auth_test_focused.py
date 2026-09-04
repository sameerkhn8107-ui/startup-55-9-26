#!/usr/bin/env python3
"""
Focused auth testing based on review request requirements
"""
import requests
import time
import secrets

BASE_URL = "http://localhost:8001/api"
DEMO_EMAIL = "demo@chatly.app"
DEMO_PASSWORD = "Demo1234"

def test_unverified_login_with_wait():
    """Test 3c: Unverified login with proper cooldown handling"""
    print("\n" + "="*80)
    print("TEST: Unverified Account Login (with cooldown wait)")
    print("="*80)
    
    # Create unverified account
    unverified_email = f"qa+unverified{secrets.token_hex(4)}@resend.dev"
    print(f"\n1. Creating unverified account: {unverified_email}")
    resp = requests.post(f"{BASE_URL}/auth/signup", 
                        json={"name": "Unverified Test", "email": unverified_email, "password": "Test1234"},
                        timeout=30)
    print(f"   Signup: {resp.status_code}")
    if resp.status_code != 200:
        print(f"   ERROR: Could not create account: {resp.json()}")
        return
    
    # Wait for cooldown (45 seconds + 2 second buffer)
    print("\n2. Waiting 47 seconds for OTP cooldown to expire...")
    time.sleep(47)
    
    # Try to login without verification
    print(f"\n3. Attempting login without verification...")
    resp = requests.post(f"{BASE_URL}/auth/login",
                        json={"email": unverified_email, "password": "Test1234"},
                        timeout=30)
    data = resp.json()
    print(f"   Status: {resp.status_code}")
    print(f"   Response: {data}")
    
    if resp.status_code == 403:
        detail = data.get("detail", "")
        if "verify" in detail.lower() and "email" in detail.lower():
            print(f"\n   ✅ PASS: Got 403 with verify message")
            print(f"   ✅ Backend should have issued new OTP (check logs for '202 Accepted')")
        else:
            print(f"\n   ⚠️  PARTIAL: Got 403 but unexpected message: {detail}")
    else:
        print(f"\n   ❌ FAIL: Expected 403, got {resp.status_code}")

def test_forgot_reset_with_deliverable_email():
    """Test 4: Forgot + Reset using deliverable email"""
    print("\n" + "="*80)
    print("TEST: Forgot Password + Reset (using deliverable email)")
    print("="*80)
    
    # Use the fresh verified account from earlier tests
    test_email = "delivered@resend.dev"
    test_password = "Test1234"
    
    # First, ensure account exists and is verified
    print(f"\n1. Ensuring {test_email} exists and is verified...")
    resp = requests.post(f"{BASE_URL}/auth/signup",
                        json={"name": "Test User", "email": test_email, "password": test_password},
                        timeout=30)
    if resp.status_code == 409:
        print(f"   Account already exists (verified)")
    elif resp.status_code == 200:
        data = resp.json()
        dev_code = data.get("dev_code")
        print(f"   Account created, verifying with code: {dev_code}")
        resp = requests.post(f"{BASE_URL}/auth/verify-otp",
                           json={"email": test_email, "code": dev_code},
                           timeout=30)
        print(f"   Verify: {resp.status_code}")
    
    # Wait for cooldown
    print("\n2. Waiting 47 seconds for cooldown...")
    time.sleep(47)
    
    # Test forgot password
    print(f"\n3. POST /auth/forgot-password")
    resp = requests.post(f"{BASE_URL}/auth/forgot-password",
                        json={"email": test_email},
                        timeout=30)
    data = resp.json()
    print(f"   Status: {resp.status_code}")
    print(f"   Response: {data}")
    
    if resp.status_code == 200:
        dev_code = data.get("dev_code")
        if dev_code:
            print(f"\n   ✅ PASS: Got 200 with dev_code={dev_code}")
            print(f"   ✅ Backend should show '202 Accepted' in logs")
            
            # Test wrong code
            print(f"\n4. POST /auth/reset-password (wrong code)")
            resp = requests.post(f"{BASE_URL}/auth/reset-password",
                               json={"email": test_email, "code": "000000", "new_password": test_password},
                               timeout=30)
            print(f"   Status: {resp.status_code} - {resp.json()}")
            if resp.status_code == 400:
                print(f"   ✅ PASS: Wrong code rejected with 400")
            
            # Test correct code
            print(f"\n5. POST /auth/reset-password (correct code)")
            resp = requests.post(f"{BASE_URL}/auth/reset-password",
                               json={"email": test_email, "code": dev_code, "new_password": test_password},
                               timeout=30)
            print(f"   Status: {resp.status_code} - {resp.json()}")
            if resp.status_code == 200:
                print(f"   ✅ PASS: Password reset successful")
                
                # Test login
                print(f"\n6. POST /auth/login (with reset password)")
                resp = requests.post(f"{BASE_URL}/auth/login",
                                   json={"email": test_email, "password": test_password},
                                   timeout=30)
                print(f"   Status: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"   ✅ PASS: Login successful after reset")
        else:
            print(f"\n   ❌ FAIL: Got 200 but no dev_code")
            print(f"   This likely means email send failed (check backend logs)")
    elif resp.status_code == 429:
        print(f"\n   ⚠️  Got 429 (cooldown) - wait longer and retry")
    else:
        print(f"\n   ❌ FAIL: Expected 200, got {resp.status_code}")

def test_resend_cooldown():
    """Test 4e: Resend cooldown on forgot-password"""
    print("\n" + "="*80)
    print("TEST: Forgot Password Resend Cooldown")
    print("="*80)
    
    test_email = "delivered@resend.dev"
    
    print(f"\n1. First forgot-password call")
    resp1 = requests.post(f"{BASE_URL}/auth/forgot-password",
                         json={"email": test_email},
                         timeout=30)
    print(f"   Status: {resp1.status_code}")
    
    print(f"\n2. Immediate second forgot-password call")
    resp2 = requests.post(f"{BASE_URL}/auth/forgot-password",
                         json={"email": test_email},
                         timeout=30)
    data2 = resp2.json()
    print(f"   Status: {resp2.status_code}")
    print(f"   Response: {data2}")
    
    if resp2.status_code == 429:
        detail = data2.get("detail", "")
        if "wait" in detail.lower():
            print(f"\n   ✅ PASS: Got 429 with wait message")
        else:
            print(f"\n   ⚠️  PARTIAL: Got 429 but unexpected message: {detail}")
    else:
        print(f"\n   ❌ FAIL: Expected 429, got {resp2.status_code}")

def check_backend_logs():
    """Check backend logs for email send confirmations"""
    print("\n" + "="*80)
    print("BACKEND LOG CHECK")
    print("="*80)
    
    import subprocess
    result = subprocess.run(
        ["tail", "-n", "50", "/var/log/supervisor/backend.err.log"],
        capture_output=True,
        text=True
    )
    
    logs = result.stdout
    
    # Count 202 Accepted
    accepted_count = logs.count("202 Accepted")
    print(f"\nEmail sends (202 Accepted): {accepted_count}")
    
    # Check for OTP_DEBUG logs
    otp_logs = [line for line in logs.split("\n") if "OTP_DEBUG" in line]
    print(f"\nRecent OTP codes generated: {len(otp_logs)}")
    for log in otp_logs[-5:]:
        print(f"  {log}")
    
    # Check for email failures
    failures = [line for line in logs.split("\n") if "Email send failed" in line]
    if failures:
        print(f"\nEmail send failures: {len(failures)}")
        for fail in failures[-3:]:
            print(f"  {fail}")

if __name__ == "__main__":
    print("="*80)
    print("CHATLY AUTH - FOCUSED TESTING")
    print("="*80)
    
    # Run focused tests
    test_unverified_login_with_wait()
    test_forgot_reset_with_deliverable_email()
    test_resend_cooldown()
    check_backend_logs()
    
    print("\n" + "="*80)
    print("TESTING COMPLETE")
    print("="*80)
