#!/usr/bin/env python3
"""
Test multiple OTP endpoint variations to find the correct one.
"""
import requests
import json

# Test configuration (using latest values from logs)
XID = "4087618809"  # From latest attempt
OTPKEY = "7110"  # Not used anymore, but kept for reference

BASE_URL = "https://kiaconnect.ca"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-CA,en-US;q=0.8,en;q=0.5,fr;q=0.3",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json;charset=UTF-8",
    "from": "CWP",
    "offset": "-5",
    "language": "0",
    "Origin": "https://kiaconnect.ca",
    "Connection": "keep-alive",
    "Referer": "https://kiaconnect.ca/login",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=0",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "client_id": "HATAHSPACA0232141ED9722C67715A0B",
}

# Endpoint variations to test
ENDPOINTS_TO_TEST = [
    # Original attempts
    "/tods/api/cmm/sendOTP",
    "/tods/api/v2/cmm/sendOTP",

    # Alternative paths
    "/tods/api/otp/send",
    "/tods/api/v2/otp/send",
    "/tods/api/auth/sendOTP",
    "/tods/api/v2/auth/sendOTP",

    # Without cmm prefix
    "/tods/api/sendOTP",
    "/tods/api/v2/sendOTP",

    # Different structure
    "/tods/v2/api/cmm/sendOTP",
    "/api/cmm/sendOTP",
    "/api/v2/cmm/sendOTP",

    # USA-style path (for comparison)
    "/apigw/v1/cmm/gf/sendOTP",
]

def test_endpoint(path, with_headers=True):
    """Test a single endpoint path."""
    url = BASE_URL + path
    headers = HEADERS.copy()

    if with_headers:
        # NOTE: Not sending otpkey anymore - Canada doesn't use it
        headers["notifytype"] = "email"
        headers["xid"] = XID

    print(f"\n{'='*80}")
    print(f"Testing: {path}")
    print(f"With OTP headers: {with_headers}")
    print(f"{'='*80}")

    try:
        response = requests.post(url, json={}, headers=headers, timeout=10)

        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")

        # Try to parse as JSON
        try:
            body = response.json()
            print(f"JSON Response: {json.dumps(body, indent=2)}")
        except:
            print(f"Raw Response (first 500 chars): {response.text[:500]}")

        # Check if we got a non-HTML response
        if response.status_code == 200 or (response.status_code < 500 and "DOCTYPE" not in response.text):
            print("✅ POTENTIAL SUCCESS - Got non-HTML response!")
            return True

    except Exception as e:
        print(f"❌ Error: {e}")

    return False

if __name__ == "__main__":
    print("Testing OTP endpoint variations for Kia Canada")
    print(f"XID: {XID}")
    print(f"OTPKEY: {OTPKEY}")

    successful = []

    # Test each endpoint WITH OTP headers
    for endpoint in ENDPOINTS_TO_TEST:
        if test_endpoint(endpoint, with_headers=True):
            successful.append(endpoint)

    # Also test a few without OTP headers to see if endpoint exists
    print("\n\n" + "="*80)
    print("Testing WITHOUT OTP headers (to check if endpoint exists)")
    print("="*80)

    for endpoint in ["/tods/api/v2/cmm/sendOTP", "/tods/api/cmm/sendOTP", "/tods/api/otp/send"]:
        test_endpoint(endpoint, with_headers=False)

    print("\n\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    if successful:
        print("✅ Successful endpoints:")
        for ep in successful:
            print(f"   - {ep}")
    else:
        print("❌ No successful endpoints found")
        print("\nThis suggests:")
        print("1. The OTP endpoint path is completely different")
        print("2. OR error 7110 doesn't actually trigger email/SMS OTP")
        print("3. OR additional authentication is required first")
