## HTTP Host Header Attacks

- **What they are**
  - Attacks that exploit applications' unsafe handling of the HTTP Host header
  - Target vulnerabilities where applications implicitly trust the Host header value
  - Exploit the header's use in server-side logic, URL generation, or routing
  - Involve manipulating the Host header or using additional override headers
  - Can be used to bypass security controls, access internal resources, or inject malicious payloads
  - Primarily focus on the header that identifies which back-end component a client wants to access
  - Can involve both direct manipulation and header override techniques

- **How they arise**
  - Flawed assumption that the Host header is not user-controllable
  - Inadequate validation or escaping of the header value
  - Using the Host header to generate URLs for emails, redirects, or other functions
  - Relying on the Host header for business logic decisions
  - Supporting multiple hostnames on a single server (virtual hosting)
  - Using load balancers or reverse proxies that introduce additional headers
  - Accepting alternative headers that can override the Host header (X-Forwarded-Host, X-Host, etc.)
  - Third-party components or frameworks with insecure default configurations
  - Failure to configure infrastructure components securely

- **Impact**
  - Web cache poisoning allowing stored XSS or other malicious content
  - Password reset poisoning redirecting sensitive links to attacker-controlled domains
  - Server-side request forgery (SSRF) exploiting internal routing mechanisms
  - Circumvention of authentication and access controls
  - Access to virtual hosts not intended to be publicly accessible
  - Cross-site scripting via injected host values
  - SQL injection or other injection attacks through the header
  - Information leakage about internal systems
  - Potential access to internal services and resources

- **How to identify them**
  - Manual testing with Host header manipulation
    1. Change the Host header to arbitrary values and monitor application behavior
    2. Check if application accepts arbitrary Host headers without validation
    3. Observe responses for any leakage or error information
    4. Look for reflections of the Host header in the response
  - Test for Host header override techniques
    1. Try using X-Forwarded-Host, X-Host, X-Original-Host, X-Rewrite-URL headers
    2. Include multiple Host headers in a single request
    3. Test for header-value duplicates (Host: real.com, evil.com)
    4. Use line wrapping techniques with headers
  - Examine URL generation for emails, password resets, etc.
  - Check for inconsistent validation across different endpoints
  - Look for unusual routing behavior when Host header is modified

- **Using Burp Suite for detection**
  - Basic Host header testing:
    1. Capture a request in Burp Proxy
    2. Send to Repeater (Ctrl+R)
    3. Modify the Host header to arbitrary/malicious values
    4. Analyze responses for different behaviors
  - Scanning for vulnerabilities:
    1. Use Burp Scanner with the header manipulation checks enabled
    2. Check audit results for host header issues
    3. Review highlighted vulnerabilities in responses
  - Automated testing:
    1. Use Intruder to test multiple Host header values
    2. Create payload lists with malicious host values
    3. Grep for interesting responses or behaviors
  - Testing for alternate headers:
    1. Use Repeater to add headers like X-Forwarded-Host
    2. Try multiple header combinations
    3. Look for headers reflected in responses

- **Step-by-step exploitation techniques**

  - **Password reset poisoning**
    1. **Identify vulnerable password reset functionality**:
       - Step 1: Initiate a legitimate password reset for your account
       - Step 2: Capture the request using an intercepting proxy
       - Step 3: Examine the response and any emails received
       - Step 4: Look for URLs in emails that use the Host header value
       - Step 5: Check if reset tokens are tied to specific domains
       - Example: Observe if password reset email contains a link with the domain from the Host header

    2. **Basic Host header manipulation for password reset**:
       - Step 1: Initiate a password reset for your account
       - Step 2: Capture the request using an intercepting proxy
       - Step 3: Change the Host header to an attacker-controlled domain (e.g., `attacker.com`)
       - Step 4: Forward the modified request
       - Step 5: Check if the password reset link in the email contains your malicious domain
       - Example: Change `Host: example.com` to `Host: attacker.com`

    3. **Using Host override headers for password reset poisoning**:
       - Step 1: Initiate a password reset for your account
       - Step 2: Capture the request using an intercepting proxy
       - Step 3: Keep the original Host header but add `X-Forwarded-Host: attacker.com`
       - Step 4: Forward the modified request
       - Step 5: Check if the reset link uses the value from X-Forwarded-Host
       - Example: Add `X-Forwarded-Host: attacker.com` while keeping `Host: example.com`

    4. **Exploiting ambiguous Host header parsing**:
       - Step 1: Initiate password reset for your account
       - Step 2: Capture the request using an intercepting proxy
       - Step 3: Try duplicate Host headers (`Host: example.com` and `Host: attacker.com`)
       - Step 4: Try comma-separated hosts (`Host: attacker.com, example.com`)
       - Step 5: Check which domain is used in the password reset link
       - Example: `Host: attacker.com` followed by another `Host: example.com` header

    5. **Exploiting against real users**:
       - Step 1: Set up a domain with a web server to capture incoming requests
       - Step 2: Identify the target user's email address
       - Step 3: Use the password reset poisoning technique against their account
       - Step 4: When they click the link, capture their reset token
       - Step 5: Use the captured token to reset their password
       - Example: Initiate password reset for victim@example.com with `Host: attacker.com`

  - **Web cache poisoning via Host header**
    1. **Identifying cacheable responses**:
       - Step 1: Send a request to the target application
       - Step 2: Look for cache-related headers in the response (Age, Cache-Control, etc.)
       - Step 3: Send identical requests and check if you receive the same response with updated Age header
       - Step 4: Identify which parts of the request are used in the cache key
       - Step 5: Determine if the Host header is excluded from the cache key
       - Example: Send repeated requests and observe cache hit indicators

    2. **Basic Host header cache poisoning**:
       - Step 1: Identify a page that reflects the Host header in its content
       - Step 2: Verify that the response is cached (check cache headers)
       - Step 3: Send a request with a malicious Host header containing a payload
       - Step 4: Check if your malicious content is stored in the cache
       - Step 5: Verify cache poisoning by sending a normal request and seeing if it returns the poisoned response
       - Example: `Host: example.com"><script>alert(1)</script>`

    3. **Using Host override headers for cache poisoning**:
       - Step 1: Identify a cacheable page that doesn't reflect the Host header
       - Step 2: Try various Host header override techniques (X-Forwarded-Host, etc.)
       - Step 3: Check if any of these headers are reflected in the response
       - Step 4: Insert a malicious payload into the reflected header
       - Step 5: Verify that the poisoned response is cached
       - Example: `X-Forwarded-Host: example.com"><script>alert(1)</script>`

    4. **Exploiting inconsistent cache/application behavior**:
       - Step 1: Identify if the cache and application treat Host headers differently
       - Step 2: Find unkeyed inputs that affect the response
       - Step 3: Test combinations of Host headers and override headers
       - Step 4: Exploit differences in parsing between the cache and application
       - Step 5: Insert a malicious payload that gets cached
       - Example: Cache might use only the first Host header while application uses the last one

  - **Routing-based SSRF exploitation**
    1. **Identifying potential routing-based SSRF**:
       - Step 1: Map the target infrastructure to identify potential internal systems
       - Step 2: Test changing the Host header to internal IP addresses or hostnames
       - Step 3: Look for timing differences, success responses, or error messages
       - Step 4: Check if you can route requests to internal services
       - Step 5: Identify any whitelisting or validation mechanisms
       - Example: Change `Host: example.com` to `Host: 192.168.0.1` or `Host: internal-service.local`

    2. **Exploiting load balancer misconfigurations**:
       - Step 1: Test if the load balancer forwards requests based on the Host header
       - Step 2: Try accessing internal systems by changing the Host header
       - Step 3: Test for partial host matching (e.g., Host: internal-app.internal.example.com)
       - Step 4: Combine with path traversal to access sensitive files
       - Step 5: Check responses for information leakage about internal systems
       - Example: `Host: internal-api` might reach an internal API service

    3. **Exploiting absolute URL parsing**:
       - Step 1: Identify if the application accepts absolute URLs in the request line
       - Step 2: Send a request with an absolute URL pointing to an internal resource
       - Step 3: Test if this bypasses Host header validation
       - Step 4: Try combinations of absolute URLs and various Host headers
       - Step 5: Check if you can access internal systems
       - Example: `GET http://internal-system/ HTTP/1.1` with `Host: example.com`

    4. **Using non-standard request headers for SSRF**:
       - Step 1: Try headers that might influence routing (X-Forwarded-For, X-Original-URL, etc.)
       - Step 2: Test combinations with internal IP addresses or hostnames
       - Step 3: Look for unusual responses indicating successful connections
       - Step 4: Probe for internal services on various ports
       - Step 5: Map accessible internal network
       - Example: `X-Forwarded-For: 127.0.0.1` combined with `Host: internal-service`

  - **Authentication bypass techniques**
    1. **Identifying host-based access controls**:
       - Step 1: Map different functionality across subdomains
       - Step 2: Identify if certain features are only available on specific subdomains
       - Step 3: Test if access controls are based on the Host header
       - Step 4: Look for admin or internal functionality on separate subdomains
       - Step 5: Check if you can access restricted features by changing the Host header
       - Example: Public site at example.com, admin site at admin.example.com

    2. **Basic Host header authentication bypass**:
       - Step 1: Identify a restricted area or feature
       - Step 2: Send a request with a modified Host header to match an admin subdomain
       - Step 3: Check if authentication requirements are bypassed
       - Step 4: Test different variations of subdomains and hostnames
       - Step 5: Look for partial subdomain matching vulnerabilities
       - Example: Change `Host: example.com` to `Host: admin.example.com`

    3. **Using Host override headers for authentication bypass**:
       - Step 1: Keep the original Host header intact
       - Step 2: Add X-Forwarded-Host, X-Original-Host or other override headers
       - Step 3: Set these headers to admin subdomains or internal hostnames
       - Step 4: Check if the application grants elevated access
       - Step 5: Test different header combinations
       - Example: Add `X-Forwarded-Host: admin.example.com` while keeping `Host: example.com`

    4. **Exploiting host-matching inconsistencies**:
       - Step 1: Test for inconsistent subdomain matching
       - Step 2: Try requests with Host headers like `Host: admin.example.com.attacker.com`
       - Step 3: Test for port-based bypasses (e.g., `Host: admin.example.com:80`)
       - Step 4: Try trailing dot notation (`Host: admin.example.com.`)
       - Step 5: Check each variant for changes in access control
       - Example: Try `Host: admin.example.com.example.com` to confuse subdomain matching

  - **Virtual host brute-forcing**
    1. **Discovering hidden virtual hosts**:
       - Step 1: Gather a list of potential subdomain and hostname patterns
       - Step 2: Create a wordlist for common internal hostnames
       - Step 3: Send requests with different Host headers using this wordlist
       - Step 4: Look for differences in responses (status codes, content length, error messages)
       - Step 5: Analyze responses to identify valid internal hosts
       - Example script (Python with requests):
```python
import requests
from concurrent.futures import ThreadPoolExecutor

def test_host(host):
    headers = {'Host': host}
    response = requests.get('https://example.com', headers=headers, verify=False)
    return host, response.status_code, len(response.text)

wordlist = ['internal', 'admin', 'staging', 'dev', 'test', 'intranet', ...]
results = []

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(test_host, f"{word}.example.com") for word in wordlist]
    for future in futures:
        host, status, length = future.result()
        results.append((host, status, length))

# Sort and analyze results to find anomalies
```

    2. **Exploiting inconsistent error messages**:
       - Step 1: Send requests with invalid Host headers and analyze error messages
       - Step 2: Look for error messages that reveal information about valid hosts
       - Step 3: Use this information to refine your brute-force attempts
       - Step 4: Check for timing differences in responses
       - Step 5: Build a map of internal virtual hosts
       - Example: An error like "Unknown virtual host" vs "Access denied" reveals host existence

    3. **Testing for internal domain naming patterns**:
       - Step 1: Research the organization to identify naming conventions
       - Step 2: Test patterns based on the organization's structure
       - Step 3: Use information from public sources about internal systems
       - Step 4: Try abbreviations and common internal naming schemes
       - Step 5: Test discovered hosts for vulnerabilities
       - Example: If company name is "ABC Corp", try hosts like "internal-abc", "abc-admin"

  - **Exploiting classic server-side vulnerabilities**
    1. **SQL injection via Host header**:
       - Step 1: Identify if the Host header is used in database queries
       - Step 2: Test basic SQL injection payloads in the Host header
       - Step 3: Look for database error messages or behavioral changes
       - Step 4: Refine payloads based on the database type
       - Step 5: Extract data using appropriate SQL injection techniques
       - Example: `Host: example.com' OR 1=1--`

    2. **Server-side template injection**:
       - Step 1: Test template syntax in the Host header
       - Step 2: Look for template evaluation in the response
       - Step 3: Identify the template engine in use
       - Step 4: Craft payloads specific to that template engine
       - Step 5: Achieve code execution via template injection
       - Example: `Host: {{7*7}}.example.com` might return computation results

    3. **Server-side request forgery (SSRF)**:
       - Step 1: Identify if the Host header is used to make server-side requests
       - Step 2: Test Host headers pointing to internal services or localhost
       - Step 3: Check for responses containing data from internal services
       - Step 4: Probe different ports and protocols
       - Step 5: Escalate to access sensitive internal resources
       - Example: `Host: localhost:25` might trigger SMTP probing

    4. **OS command injection**:
       - Step 1: Test command injection payloads in the Host header
       - Step 2: Look for unusual delays or responses
       - Step 3: Use timing-based techniques to confirm blind injection
       - Step 4: Leverage injection to execute system commands
       - Step 5: Establish more stable access if possible
       - Example: `Host: example.com$(sleep 10)` causes a 10-second delay if vulnerable

  - **Connection state attacks**
    1. **HTTP request smuggling via Host header**:
       - Step 1: Identify frontend and backend server combinations
       - Step 2: Test for CL.TE or TE.CL vulnerabilities
       - Step 3: Use the Host header as part of smuggled requests
       - Step 4: Craft requests that confuse the server chain
       - Step 5: Leverage this confusion to access restricted resources
       - Example: Smuggling attack with malicious Host in the second request

    2. **Exploiting timeout disparities**:
       - Step 1: Identify timeout differences between components
       - Step 2: Establish a connection that the frontend maintains but backend drops
       - Step 3: Use the Host header to control routing behavior
       - Step 4: Exploit the connection state inconsistency
       - Step 5: Gain access to unintended backend systems
       - Example: Hold connection open longer than backend timeout, then send new request

- **Advanced exploitation by server architecture**

  - **Microservice architecture exploitation**
    1. **Internal service discovery**:
       - Step 1: Map externally accessible services
       - Step 2: Test Host headers for each discovered service
       - Step 3: Look for references to internal service names
       - Step 4: Attempt to access internal services directly via Host header
       - Step 5: Build a map of the internal service architecture
       - Example: Use Host headers like `internal-payment-api`, `user-service.internal`

    2. **Exploiting loose internal routing**:
       - Step 1: Identify gateway/router components
       - Step 2: Test if internal routing is based solely on the Host header
       - Step 3: Attempt to route requests to internal services
       - Step 4: Look for services with weaker security controls
       - Step 5: Access internal functionality not meant for external users
       - Example: `Host: logging-service.internal` might access internal logging APIs

  - **Cloud environment exploitation**
    1. **Testing cloud provider metadata services**:
       - Step 1: Identify the cloud provider being used
       - Step 2: Try accessing cloud metadata services via Host header
       - Step 3: Test known metadata endpoints for different providers
       - Step 4: Look for SSRF vulnerabilities to metadata services
       - Step 5: Extract sensitive information like credentials or tokens
       - Example: `Host: 169.254.169.254` for AWS metadata service

    2. **Exploiting cloud load balancer configurations**:
       - Step 1: Identify the load balancer technology
       - Step 2: Test different header combinations supported by that balancer
       - Step 3: Look for misconfigurations in routing rules
       - Step 4: Exploit loose hostname matching to access internal services
       - Step 5: Bypass access controls through routing manipulation
       - Example: Some cloud load balancers have default configurations that can be exploited

  - **Proxy and CDN bypass techniques**
    1. **Identifying origin servers behind CDNs**:
       - Step 1: Gather information about the CDN in use
       - Step 2: Try direct connections to origin IP addresses if known
       - Step 3: Test Host header modifications that might bypass CDN rules
       - Step 4: Look for origin-specific headers or cookies
       - Step 5: Attempt to communicate directly with origin servers
       - Example: Changing Host to the internal hostname of the origin server

    2. **X-Original-URL and X-Rewrite-URL exploitation**:
       - Step 1: Send a request with a normal URL and Host header
       - Step 2: Add X-Original-URL or X-Rewrite-URL headers with path to restricted resource
       - Step 3: Check if the application routes based on these headers
       - Step 4: Test access to admin or internal paths
       - Step 5: Bypass frontend access controls to reach backend directly
       - Example: GET / with `X-Original-URL: /admin/users`

- **Combining techniques for advanced exploitation**
  1. **Multi-stage Host header attacks**:
     - Step 1: Use virtual host enumeration to discover internal services
     - Step 2: Identify a routing-based SSRF vulnerability
     - Step 3: Leverage SSRF to probe internal services
     - Step 4: Use cache poisoning to store a malicious payload
     - Step 5: Chain the vulnerabilities to expand access
     - Example chain:
       1. Discover internal admin interface through host enumeration
       2. Use routing-based SSRF to access the admin interface
       3. Exploit XSS via Host header in the admin interface
       4. Capture admin credentials

  2. **Combining with other vulnerability classes**:
     - Step 1: Identify a Host header vulnerability
     - Step 2: Look for other vulnerabilities in the application
     - Step 3: Test how the Host header vulnerability can enhance other vulnerabilities
     - Step 4: Create attack chains that leverage multiple issues
     - Step 5: Escalate impact through combined exploitation
     - Example: Use Host header manipulation to bypass CSRF protection, then execute CSRF attack

- **Detection evasion strategies**
  1. **Obfuscating Host header attacks**:
     - Step 1: Use encoded values in Host header
     - Step 2: Try unicode representations of characters
     - Step 3: Use different header capitalization (Host vs host)
     - Step 4: Test partial header matching behaviors
     - Step 5: Combine with HTTP header obfuscation techniques
     - Example: `Host: admin%2eexample%2ecom` instead of `Host: admin.example.com`

  2. **Evading WAF and security controls**:
     - Step 1: Identify WAF or security measure patterns
     - Step 2: Test which variations of attacks are blocked
     - Step 3: Try uncommon Host header override techniques
     - Step 4: Use HTTP request smuggling to bypass controls
     - Step 5: Employ timing and distributed testing to avoid detection
     - Example: Instead of obvious payloads, use subtle variations that pass filters

- **Prevention and mitigation**
  1. **Proper Host header validation**:
     - Implement strict validation against a whitelist of allowed hosts
     - Reject requests with unexpected Host header values
     - Do not support Host override headers unless absolutely necessary
     - Validate Host header format and content
     - Deploy a reverse proxy to standardize Host header handling

  2. **Avoiding Host header in application logic**:
     - Never use the Host header for generating links or redirects
     - Configure trusted hostnames in application configuration
     - Use relative URLs when possible
     - For absolute URLs, use hardcoded domains from configuration
     - Never make security decisions based on the Host header

  3. **Infrastructure configuration**:
     - Configure virtual hosts with explicit bindings
     - Implement proper network segmentation
     - Use separate servers for internal and external applications
     - Configure web servers to reject requests with unknown Host headers
     - Implement application-layer firewalls with Host header rules

  4. **Security headers and controls**:
     - Implement Content-Security-Policy headers
     - Use strict CORS policies
     - Configure proper X-Frame-Options
     - Implement proper cache control headers
     - Use HTTP Strict Transport Security (HSTS)
