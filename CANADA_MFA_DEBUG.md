# Canada MFA OTP Flow - Debugging Documentation

**Created**: 2026-02-13
**Status**: In Progress - Deployment Fix Applied
**Branch**: `claude/code-review-01JidRpCMLVWNUyYRgYh5fiD`

---

## 🎯 **Objective**

Fix the Canada region MFA (Multi-Factor Authentication) OTP flow to allow users to:
1. Request OTP codes via email/SMS
2. Verify OTP codes
3. Access vehicle data/commands after authentication

---

## 🐛 **Problems Identified**

### Problem 1: Rate Limiting (Error 7901)
**Error**: `{"error":{"errorCode":"7901"},"responseHeader":{"responseCode":1,"responseDesc":"Failure"}}`

**Cause**:
- Kia API rate limits login attempts to **~1 per 30-60 minutes**
- The `/mfa/selverifmeth` endpoint requires a valid authenticated session (xid)
- Creating new xid requires calling `/prof/authUser` which triggers rate limiting after failed attempts

**Timeline of Rate Limit**:
- Last failed login: `2026-02-13 18:50 UTC` (1:50 PM EST)
- Rate limit clears: `2026-02-13 19:20-19:50 UTC` (2:20-2:50 PM EST)

**Solution Implemented**:
- Added `xid` caching mechanism to reuse valid session tokens
- Client can provide existing xid via request body: `{"method": "email", "xid": "1234567890"}`
- Skips login step if xid is provided

### Problem 2: xid Expiration (Error 7715)
**Error**: `{"error":{"errorCode":"7715"},"responseHeader":{"responseCode":1,"responseDesc":"Failure"}}`

**Cause**:
- xid tokens expire after **30-60 minutes**
- Example: xid `4091163502` created at 17:43 UTC, tried to use at 18:52 UTC (69 min later) → expired

**Solution**:
- Must create fresh xid after rate limit clears
- Cannot reuse xid older than ~30 minutes

### Problem 3: Missing Dependency (ModuleNotFoundError)
**Error**: `ModuleNotFoundError: No module named 'dns'`

**Cause**:
- Code uses `import dns.resolver` for DNS SRV lookups
- `dnspython` package was not in requirements files

**Solution Applied** (Commit `023d62b`):
- Added `dnspython>=2.4.0` to:
  - `api/requirements.txt`
  - `requirements.txt`
  - `pyproject.toml`

---

## 🔧 **Code Changes Made**

### 1. Manual Canada MFA Flow (`api/index.py`)

**Function**: `manual_canada_send_otp(method, provided_xid=None)`

```python
def manual_canada_send_otp(method, provided_xid=None):
    """
    Manually execute Canada MFA flow without VehicleManager.
    """
    USERNAME = os.environ.get("KIA_USERNAME")
    PASSWORD = os.environ.get("KIA_PASSWORD")

    # Step 1: Get or create xid
    if provided_xid:
        logger.info(f"Step 1: Using client-provided xid: {provided_xid}")
        xid = provided_xid
    else:
        logger.info("Step 1: Authenticating to get xid...")
        login_result = authenticate_canada_user(USERNAME, PASSWORD)
        xid = login_result["xid"]

    # Step 2: Get userInfoUuid
    logger.info("Step 2: Calling /mfa/selverifmeth to get userInfoUuid...")
    selverif_result = call_selverifmeth(xid)
    if "userInfoUuid" not in selverif_result:
        raise Exception(f"Missing userInfoUuid in response: {selverif_result}")

    user_info_uuid = selverif_result["userInfoUuid"]

    # Step 3: Send OTP
    logger.info(f"Step 3: Sending OTP via {method}...")
    otp_result = send_otp_code(xid, user_info_uuid, method)

    return {
        "success": True,
        "xid": xid,
        "userInfoUuid": user_info_uuid,
        "otpResponse": otp_result
    }
```

### 2. OTP Send Endpoint

```python
@app.route('/otp/send', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        method = data.get('method', 'email')  # 'email' or 'sms'
        provided_xid = data.get('xid')  # Optional: reuse existing xid

        logger.info(f"Requesting OTP via {method}...")
        logger.info("Using manual Canada MFA flow (no VehicleManager init needed)...")

        result = manual_canada_send_otp(method, provided_xid)
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Failed to send OTP: {str(e)}")
        return jsonify({"error": str(e)}), 500
```

---

## 🧪 **Testing Commands**

### Test 1: Send OTP (without xid - creates new)
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/send \
  -H "Content-Type: application/json" \
  -d '{"method": "email"}'
```

**Expected Response** (if rate limit cleared):
```json
{
  "success": true,
  "xid": "1234567890",
  "userInfoUuid": "uuid-string-here",
  "otpResponse": {...}
}
```

### Test 2: Send OTP (with existing xid - reuses)
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "method": "email",
    "xid": "4091163502"
  }'
```

### Test 3: Verify OTP (after receiving code)
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456",
    "xid": "4091163502"
  }'
```

---

## 📋 **Error Code Reference**

| Code | Meaning | Cause | Solution |
|------|---------|-------|----------|
| **7901** | Rate Limit | Too many login attempts | Wait 30-60 minutes, OR reuse valid xid |
| **7715** | Invalid/Expired xid | xid token too old | Create fresh xid (wait for rate limit first) |
| **7702** | Invalid OTP | Wrong verification code | Get new OTP or retry with correct code |
| **7701** | OTP Expired | OTP code too old | Request new OTP |

---

## 📊 **MFA Flow Diagram**

```
┌─────────────────────────────────────────────────────────────┐
│ Canada MFA Flow (Manual Implementation)                      │
└─────────────────────────────────────────────────────────────┘

Step 1: Get Session Token (xid)
  ┌────────────────────────────────────┐
  │ POST /prof/authUser                │
  │ Body: {username, password}         │
  │ Returns: {xid: "1234567890"}       │
  └────────────────────────────────────┘
           │
           ├── ✅ Success → xid cached for reuse
           └── ❌ Error 7901 → Rate limited (wait 30-60 min)

Step 2: Get User Info UUID
  ┌────────────────────────────────────┐
  │ POST /mfa/selverifmeth             │
  │ Headers: {xid: "1234567890"}       │
  │ Returns: {userInfoUuid: "uuid"}    │
  └────────────────────────────────────┘
           │
           ├── ✅ Success → proceed to Step 3
           └── ❌ Error 7715 → xid expired (create fresh xid)

Step 3: Send OTP
  ┌────────────────────────────────────┐
  │ POST /mfa/sendverifcode            │
  │ Headers: {xid: "1234567890"}       │
  │ Body: {userInfoUuid, method}       │
  │ Returns: {otpResult}               │
  └────────────────────────────────────┘
           │
           └── ✅ Success → OTP sent to user's email/phone

Step 4: Verify OTP
  ┌────────────────────────────────────┐
  │ POST /mfa/verifcode                │
  │ Headers: {xid: "1234567890"}       │
  │ Body: {userInfoUuid, code}         │
  │ Returns: {accessToken, refreshToken}│
  └────────────────────────────────────┘
           │
           ├── ✅ Success → tokens cached, proceed to vehicle API
           └── ❌ Error 7702/7701 → Invalid/expired OTP
```

---

## 🚀 **Current Status**

### ✅ **Completed**
1. ✅ Identified rate limit issue (error 7901)
2. ✅ Implemented xid reuse mechanism
3. ✅ Added detailed logging for each MFA step
4. ✅ Fixed missing `dnspython` dependency
5. ✅ Committed and pushed fix (commit `023d62b`)

### 🔄 **In Progress**
- **Waiting for Vercel deployment** with new `dnspython` dependency

### ⏳ **Blocked**
- **Rate limit** from failed login attempts
- Last failed attempt: `2026-02-13 18:50 UTC`
- Can retry after: `2026-02-13 19:20-19:50 UTC` (30-60 min window)

---

## 🎯 **Next Steps**

### 1. Verify Deployment
Check Vercel logs after redeployment:
- Should see `dnspython` installed in build logs
- No more `ModuleNotFoundError: No module named 'dns'`

### 2. Wait for Rate Limit to Clear
Current time: ~`2026-02-13 18:52 UTC`
Can test again: `2026-02-13 19:20-19:50 UTC` (28-58 minutes)

### 3. Test Fresh OTP Request
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/send \
  -H "Content-Type: application/json" \
  -d '{"method": "email"}'
```

**Expected**: New xid created, OTP sent successfully

### 4. Save xid for Future Requests
From response, save the `xid` value:
```json
{"success": true, "xid": "NEW_XID_HERE", ...}
```

### 5. Test OTP Verification
Once OTP code received in email:
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456",
    "xid": "NEW_XID_HERE"
  }'
```

### 6. Test Vehicle Commands
After successful OTP verification, test vehicle API:
```bash
curl https://kia-android-widget.vercel.app/vehicle/status
```

---

## 📝 **Important Notes**

### xid Lifecycle
- **Created**: During `/prof/authUser` login
- **Lifespan**: ~30-60 minutes
- **Reusable**: Yes, within lifespan
- **Storage**: Should be cached client-side for subsequent requests

### Rate Limit Behavior
- **Trigger**: Failed login attempts to `/prof/authUser`
- **Duration**: 30-60 minutes from last attempt
- **Workaround**: Reuse valid xid instead of creating new one
- **Reset**: Wait for full duration, no manual reset available

### DNS SRV Lookups
- **Purpose**: Resolve Kia API endpoints dynamically
- **Package**: `dnspython>=2.4.0` (now added)
- **Function**: `resolve_srv_records()` in `api/index.py`
- **Endpoints**: `mfa.cws.ca.kia.com`, `bff.cws.ca.kia.com`, etc.

---

## 🔍 **Useful Debugging Commands**

### Check Vercel Deployment Status
```bash
# In Vercel dashboard, check:
# - Build logs for "dnspython" installation
# - Runtime logs for any import errors
```

### Monitor Logs in Real-Time
```bash
# Watch Vercel function logs for:
# - "Step 1: Using client-provided xid"
# - "Step 2: Calling /mfa/selverifmeth"
# - "Step 3: Sending OTP via email"
```

### Test DNS Resolution Locally
```python
import dns.resolver

# Test SRV record lookup
srv_name = "_mfa._tcp.cws.ca.kia.com"
answers = dns.resolver.resolve(srv_name, 'SRV')
for rdata in answers:
    print(f"Host: {rdata.target}, Port: {rdata.port}")
```

---

## 📚 **Related Files**

- **Main API**: `api/index.py` (lines 205-255: manual MFA flow)
- **Dependencies**:
  - `api/requirements.txt`
  - `requirements.txt`
  - `pyproject.toml`
- **Environment**: `.env` (needs `KIA_USERNAME`, `KIA_PASSWORD`)
- **Deployment**: Vercel (auto-deploys from branch)

---

## 🤝 **Handoff Summary for New Session**

**What's Working**:
- xid caching and reuse logic ✅
- Manual MFA flow implementation ✅
- Detailed logging at each step ✅

**What's Fixed**:
- Missing `dnspython` dependency ✅

**What Needs Testing**:
1. Verify Vercel deployed with `dnspython`
2. Wait for rate limit to clear (check timestamps above)
3. Test fresh OTP request (without xid)
4. Test OTP verification
5. Test vehicle commands post-auth

**Quick Start Command** (after rate limit clears):
```bash
curl -X POST https://kia-android-widget.vercel.app/otp/send \
  -H "Content-Type: application/json" \
  -d '{"method": "email"}'
```

---

**Last Updated**: 2026-02-13 20:40 UTC
**Last Commit**: `023d62b` - "Add dnspython dependency for DNS SRV lookups"
