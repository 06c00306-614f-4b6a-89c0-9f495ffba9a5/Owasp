## Access Control Vulnerabilities and Privilege Escalation

- **What access control is**
  - Restrictions on who or what can perform actions or access resources
  - Dependent on authentication (verifying identity) and session management (tracking user's session)
  - Mechanism that enforces authorization rules after authentication is complete
  - Critical for security as broken access controls often lead to complete compromise
  - Complex and dynamic challenge involving business, organizational, and legal constraints
  - Implemented through various security models (RBAC, ABAC, MAC, DAC, etc.)

- **Types of access control**
  
  - **Vertical access controls**
    - Restrict access to specific functions based on user type/role
    - Example: Admin users can delete accounts while regular users cannot
    - Enforce principles like separation of duties and least privilege
    - Usually implemented through role-based systems
  
  - **Horizontal access controls**
    - Restrict access to resources to specific users
    - Example: Users can only view their own profile and data
    - Prevent users from accessing others' data of the same type
    - Implemented through resource ownership checks
  
  - **Context-dependent access controls**
    - Restrict access based on application state or user interaction history
    - Example: Users cannot modify orders after payment is processed
    - Enforce proper business process flows
    - Often implemented as state-based checks

- **Vertical privilege escalation vulnerabilities**
  
  - **Unprotected sensitive functionality**
    
    - **Unprotected admin pages**
      - Administrative functions accessible via direct URL
      - No access control checks performed
      - Example: `/admin`, `/management`, `/console`, `/administrator`
      - Detection: Test direct access to admin URLs
      - Exploitation: Navigate directly to the administrative URL
    
    - **Obscured functionality ("security by obscurity")**
      - Sensitive functions hidden behind non-obvious URLs
      - URLs may be disclosed in JavaScript, HTML comments, or source code
      - Example: `/administrator-panel-yb556`, `/secret_control_system`
      - Detection: Check page source, JavaScript files, and robots.txt
      - Exploitation: Access revealed obscured URLs directly
    
    - **Platform configuration mistakes**
      - Misconfigured access controls at web server or framework level
      - Example: Access rules applied inconsistently across HTTP methods
      - Detection: Try alternative HTTP methods (GET vs POST vs PUT)
      - Exploitation: Send requests with allowed methods to bypass restrictions
    
    - **URL-matching discrepancies**
      - Inconsistent path matching between access control and resource handler
      - Examples:
        - Case sensitivity differences: `/admin` vs `/ADMIN`
        - Trailing slash differences: `/admin` vs `/admin/`
        - Extension handling: `/admin` vs `/admin.json`
      - Detection: Test URL variations to identify inconsistencies
      - Exploitation: Use the URL format that bypasses access controls
  
  - **Parameter-based access control flaws**
    
    - **User roles in request parameters**
      - Application determines access rights based on user-controllable parameters
      - Example: `/home?admin=false`, `/login?role=user`
      - Detection: Identify and modify role-indicating parameters
      - Exploitation: Change parameter values to assume higher privileges:
        ```
        /home?admin=false  -->  /home?admin=true
        /account?role=1    -->  /account?role=0
        ```
    
    - **User roles in cookies**
      - Access rights stored in cookies on client side
      - Example: Cookie containing `role=user` or `isAdmin=false`
      - Detection: Examine cookies for role indicators
      - Exploitation: Modify cookie values to gain higher privileges:
        ```
        Cookie: role=user    -->  Cookie: role=admin
        Cookie: isAdmin=0    -->  Cookie: isAdmin=1
        ```
    
    - **User roles in hidden form fields**
      - Access control decisions based on hidden HTML form fields
      - Example: `<input type="hidden" name="userRole" value="customer">`
      - Detection: Inspect HTML source for hidden fields
      - Exploitation: Submit forms with modified hidden field values
  
  - **Access control bypass techniques**
    
    - **HTTP header manipulation**
      - Application uses custom headers to override URL or access rules
      - Example headers: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`
      - Detection: Test adding custom headers to requests
      - Exploitation: Add headers to bypass restrictions:
        ```
        GET / HTTP/1.1
        X-Original-URL: /admin/deleteUser
        ```
    
    - **HTTP method switching**
      - Access controls differ based on HTTP method used
      - Detection: Try same URL with different methods (GET, POST, PUT, etc.)
      - Exploitation: Use an alternate method to bypass restrictions
        ```
        POST /admin/deleteUser HTTP/1.1   (Blocked)
        GET /admin/deleteUser HTTP/1.1    (Allowed)
        ```
    
    - **Forced browsing**
      - Bypassing intended application flow to access pages directly
      - Detection: Identify predictable URL patterns
      - Exploitation: Access URLs directly, skipping prerequisite steps

- **Horizontal privilege escalation vulnerabilities**
  
  - **Insecure Direct Object References (IDOR)**
    
    - **User IDs in URLs**
      - User-controlled parameters directly reference user objects
      - Example: `/account?id=123`, `/profile/123`, `/user/123/settings`
      - Detection: Identify and modify object reference parameters
      - Exploitation: Change ID values to access others' resources:
        ```
        /myaccount?id=123   -->   /myaccount?id=456
        /profile/123        -->   /profile/456
        ```
    
    - **Predictable resource locations**
      - Resources stored at predictable locations
      - Example: `/users/123/documents/statement_2023.pdf`
      - Detection: Analyze URL patterns for resource locations
      - Exploitation: Modify resource path components
    
    - **Insecure access control in APIs**
      - APIs relying solely on client-supplied parameters for authorization
      - Example: `/api/v1/users/123/data`
      - Detection: Intercept and analyze API requests
      - Exploitation: Change ID or reference values in API requests
    
    - **Unpredictable IDs without proper checks**
      - Application uses UUIDs or GUIDs but fails to validate ownership
      - Example: `/document/a1b2c3d4-e5f6-7890-abcd-ef1234567890`
      - Detection: Collect valid GUIDs from the application (user messages, shared resources)
      - Exploitation: Replace UUIDs with known valid ones from other users
  
  - **Information disclosure in responses**
    
    - **Data leakage in redirects**
      - Application redirects unauthorized requests but includes sensitive data in response
      - Detection: Analyze full responses including those with 302 status codes
      - Exploitation: Extract sensitive data from redirect responses
    
    - **Error messages exposing data**
      - Verbose error messages containing sensitive information
      - Detection: Force errors by requesting inaccessible resources
      - Exploitation: Gather information from error messages
    
    - **Response differences**
      - Different responses indicate existence of resources
      - Detection: Compare responses for existent vs. non-existent resources
      - Exploitation: Use timing, response size, or content differences

- **Horizontal to vertical privilege escalation**
  
  - **Targeting admin users**
    - Escalate horizontally to an administrative account
    - Detection: Identify admin users (look for indicators in user listings)
    - Exploitation: Use horizontal access techniques on admin user IDs
  
  - **Credential disclosure via horizontal access**
    - Access password reset functionality of privileged users
    - Access stored credentials through horizontal escalation
    - Detection: Look for credential information in account pages
    - Exploitation:
      ```
      1. Perform horizontal escalation to admin user's account page
      2. Extract or reset admin credentials
      3. Login with admin credentials
      ```
  
  - **Chaining vulnerabilities**
    - Combine horizontal privilege escalation with other flaws
    - Example: Leveraging XSS in user profiles to steal admin session cookies
    - Detection: Test for multiple vulnerabilities and potential chains
    - Exploitation: Use horizontal access as a stepping stone to vertical access

- **Advanced exploitation techniques**
  
  - **Multi-step process vulnerabilities**
    
    - **Missing access controls on specific steps**
      - Applications implement controls on initial steps but not on later ones
      - Example: Controls on form page but not on form submission endpoint
      - Detection: Map all steps in multi-step processes
      - Exploitation: Skip initial steps and directly access latter steps:
        ```
        1. Identify complete process flow (e.g., user creation)
        2. Determine parameters needed for final step
        3. Submit request directly to final step URL
        ```
    
    - **Access controls dependent on request history**
      - Application checking authorization based on previous requests
      - Detection: Try accessing later steps directly
      - Exploitation: Send requests for sensitive operations directly
  
  - **Referer-based access controls**
    
    - **Referer header verification flaws**
      - Application allows access if Referer header contains authorized URL
      - Detection: Analyze requests for Referer header usage
      - Exploitation: Forge requests with spoofed Referer header:
        ```
        GET /admin/deleteUser HTTP/1.1
        Referer: https://example.com/admin
        ```
    
    - **Referer header manipulation**
      - Applications trusting client-supplied Referer header for authorization
      - Detection: Modify Referer header and observe behavior
      - Exploitation: Set Referer to expected trusted URLs
  
  - **Location-based access controls**
    
    - **Geolocation restrictions**
      - Access controls based on user's geographical location
      - Detection: Test access from different locations/IPs
      - Exploitation: Use proxies, VPNs, or IP spoofing techniques
    
    - **IP-based restrictions**
      - Access allowed only from specific IP addresses
      - Detection: Test access using different IP addresses
      - Exploitation: 
        - Use headers like X-Forwarded-For
        - Proxy through allowed networks
        - Use IP spoofing techniques
  
  - **Client-side access controls**
    
    - **JavaScript-based enforcement**
      - Access controls implemented in client-side JavaScript
      - Detection: Analyze JavaScript for UI rendering based on roles
      - Exploitation: 
        - Modify DOM to show hidden elements
        - Bypass client-side checks by sending direct requests
    
    - **Hidden UI elements**
      - Interface elements hidden from unauthorized users via CSS or JavaScript
      - Detection: Inspect DOM for hidden elements
      - Exploitation: Modify DOM to reveal hidden elements or craft requests directly

- **Identifying access control vulnerabilities**
  
  - **Manual testing techniques**
    
    - **Mapping application roles**
      - Understand different user roles in the application
      - Create accounts with different privilege levels
      - Document accessible functionality for each role
    
    - **Mapping accessible resources**
      - Enumerate accessible endpoints
      - Identify URL patterns
      - Create matrix of resources and required permissions
    
    - **Parameter analysis**
      - Identify parameters controlling access
      - Test modification of:
        - URL parameters
        - Hidden form fields
        - Cookies
        - Headers
    
    - **Forced browsing testing**
      - Skip application flow to access resources directly
      - Attempt to access administrative functionality
      - Try predictable admin URLs (admin, administrator, console, etc.)
  
  - **Automated testing approaches**
    
    - **Authorization testing with multiple roles**
      - Use automated tools to compare access across user roles
      - Analyze differences in responses
    
    - **Parameter fuzzing**
      - Automated testing of parameters controlling authorization
      - Manipulate IDs, roles, and permission flags
    
    - **Automated scanners**
      - Burp Suite Professional scanner
      - OWASP ZAP access control testing
      - Custom scripts for role-based access testing

- **Preventing access control vulnerabilities**
  
  - **Secure architecture design**
    
    - **Centralized access control**
      - Implement single application-wide mechanism
      - Avoid custom checks in individual functions
      - Example frameworks:
        - Spring Security (Java)
        - Laravel Gates/Policies (PHP)
        - Django Permissions (Python)
    
    - **Defense in depth**
      - Multiple layers of access controls
      - Independent mechanisms at different architectural levels
    
    - **Deny by default**
      - Require explicit granting of access
      - Block access to all resources by default
  
  - **Server-side validation**
    
    - **Re-verify authorization on every request**
      - Check permissions on each request, not just when session starts
      - Don't trust client-side state or previous authorization
    
    - **Use authorization tokens properly**
      - Implement proper OAuth or JWT handling
      - Validate token permissions server-side
    
    - **Indirect reference maps**
      - Use indirect references instead of direct resource identifiers
      - Map internal resource references to user-specific tokens
      - Example:
        ```
        // Instead of
        GET /api/document/53
        
        // Use
        GET /api/document/TOKEN123
        // Where TOKEN123 is server-side mapped to document 53 for the specific user
        ```
  
  - **Proper role and permission management**
    
    - **Principle of least privilege**
      - Grant minimal access required for each role
      - Regularly review and remove unnecessary permissions
    
    - **Separation of duties**
      - Critical functions require multiple people
      - Prevent privilege concentration
    
    - **Data-level access controls**
      - Enforce permissions at data level, not just function level
      - Use row-level security in databases
      - Example in SQL:
        ```sql
        -- Row-level security in PostgreSQL
        CREATE POLICY user_data ON accounts
            USING (account_owner = current_user());
        ```
  
  - **Technical implementation**
    
    - **Use mature frameworks**
      - Leverage battle-tested authorization frameworks
      - Avoid building custom access control
    
    - **Server-side session validation**
      - Maintain and verify session state server-side
      - Don't rely on client-side indicators of session state
    
    - **Contextual access checks**
      - Verify not just role but appropriate context
      - Check business rules and process state
      - Example:
        ```
        // Check not just if user is authorized but if the order is in the right state
        if (userCanCancelOrders && order.status == "PENDING")
        ```
  
  - **Testing and verification**
    
    - **Regular access control audits**
      - Periodically review access control implementation
      - Test from all user perspectives
    
    - **Automated testing of authorization**
      - Create test suites specifically for access control
      - Test both positive and negative cases
    
    - **Implement logging and monitoring**
      - Log access control decisions and violations
      - Monitor for unusual access patterns
