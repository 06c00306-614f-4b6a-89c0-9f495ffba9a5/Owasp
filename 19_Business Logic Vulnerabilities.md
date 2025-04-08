## Business Logic Vulnerabilities

- **What they are**
  - Flaws in the design and implementation of application logic
  - Allow attackers to manipulate legitimate functionality for malicious purposes
  - Arise from failing to anticipate unusual application states
  - Often invisible during normal application usage
  - Difficult to detect using automated scanners (require human understanding)
  - Unique to specific applications and functionality
  - Also known as "application logic vulnerabilities" or "logic flaws"

- **How they arise**
  - Flawed assumptions about how users will interact with the application
  - Inadequate validation of user input
  - Overreliance on client-side controls
  - Overly complicated systems that developers don't fully understand
  - Undocumented assumptions between different application components
  - Failure to consider how different functions can be combined unexpectedly
  - Poor communication between teams working on different parts of the application

- **Impact**
  - Varies from trivial to critical depending on affected functionality
  - Authentication bypass and privilege escalation
  - Unauthorized access to sensitive data and functionality
  - Financial losses through fraud or theft
  - Business damage even without direct attacker benefit
  - Exposure of additional attack surface for other exploits
  - Regulatory and compliance violations

- **How to identify them**
  - Manual testing with deep application understanding
    1. Map all application functionalities and workflows
    2. Document expected behavior for each step
    3. Identify security assumptions at each step
    4. Test with unexpected inputs and sequence variations
  - Intercept and analyze all requests with proxy tools
  - Compare behavior across different user roles
  - Analyze session handling mechanisms
  - Test for missing validation or authorization checks
  - Analyze numerical inputs for boundary condition handling
  - Examine multi-step processes for logical dependencies

- **Using Burp Suite for detection**
  - Complete workflow mapping:
    1. Use the proxy to capture all requests
    2. Create a site map with full application crawling
    3. Annotate key functionality and entry points
    4. Set scope to focus on critical business functions
  - Request manipulation:
    1. Send requests to Repeater
    2. Modify parameter values systematically
    3. Analyze application responses for anomalies
    4. Chain requests to test process sequences
  - Session analysis:
    1. Use Sequencer to analyze session token randomness
    2. Check for predictable session identifiers or tokens
    3. Test token lifecycle management (creation, validation, expiration)
  - Authorization testing:
    1. Use Autorize extension to compare access between roles
    2. Send authenticated requests between different user sessions
    3. Test access control at each application function
  - Automated testing:
    1. Configure session handling rules for authenticated testing
    2. Set up macros for multi-step processes
    3. Use Intruder for parameter fuzzing with business context
    4. Create custom scan checks with extensions for specific logic flaws

- **Step-by-step exploitation techniques**

  - **Parameter manipulation**
    1. **Price/value manipulation**:
       - Step 1: Identify a purchase or cart page and capture the request
       - Step 2: Locate price parameters (often as hidden form fields or in JSON)
       - Step 3: Modify the price value to a lower amount (e.g., from `100.00` to `1.00`)
       - Step 4: Submit the request and observe if the application accepts the modified value
       - Step 5: If rejected, try different formats (`1,00`, `1e0`, etc.) to bypass validation
       - Step 6: Look for secondary validation bypass by modifying any checksum parameters
       - Example: `POST /checkout`: `{"items":[{"id":123,"price":100.00}]}` → `{"items":[{"id":123,"price":0.01}]}`

    2. **Quantity manipulation**:
       - Step 1: Add items to cart and capture the update quantity request
       - Step 2: Try negative values (e.g., `-10`) to see if it creates credits instead of charges
       - Step 3: Try zero values to potentially get items for free
       - Step 4: Try extremely large values to trigger integer overflow (e.g., `2147483647`)
       - Step 5: Test decimal quantities when integers are expected (e.g., `1.5` items)
       - Example: `POST /cart/update`: `quantity=2` → `quantity=-2`

    3. **Currency manipulation**:
       - Step 1: Identify requests that involve currency codes
       - Step 2: Change currency to one with a favorable exchange rate
       - Step 3: Look for inconsistencies in how exchange rates are applied
       - Step 4: Try invalid or uncommon currency codes
       - Step 5: Test if currency conversion happens multiple times (double conversion)
       - Example: `POST /payment`: `{"amount":100,"currency":"USD"}` → `{"amount":100,"currency":"VES"}`

    4. **ID manipulation for unauthorized access**:
       - Step 1: Identify requests containing user IDs or resource IDs 
       - Step 2: Systematically change the ID values to access other users' resources
       - Step 3: Try predictable patterns (increment/decrement by 1)
       - Step 4: Test UUIDs by changing one character at a time
       - Step 5: Use advanced enumeration with automated tools
       - Example: `GET /account/details?user_id=1234` → `GET /account/details?user_id=1235`

  - **Workflow bypass**
    1. **Multi-step process bypassing**:
       - Step 1: Map the complete legitimate process flow (e.g., checkout process)
       - Step 2: Capture all requests in the sequence
       - Step 3: Identify validation steps and their parameters
       - Step 4: Attempt to skip intermediate steps by directly sending final step requests
       - Step 5: Observe if the application enforces the correct sequence
       - Step 6: Test if tokens or state parameters from previous steps are validated
       - Example: Skip payment validation by sending order confirmation directly: 
         - Normal flow: Browse → Add to cart → Checkout → Payment → Confirmation
         - Attack: Capture confirmation request and replay directly after adding to cart

    2. **Forced browsing exploitation**:
       - Step 1: Identify sequential pages in a process
       - Step 2: Try accessing later steps directly via URL
       - Step 3: Maintain session cookies while accessing direct URLs
       - Step 4: Check if any state parameters need to be included
       - Step 5: Modify state parameters to indicate previous steps were completed
       - Example: Direct access to `/checkout/confirmation` without going through payment

    3. **CSRF token bypass**:
       - Step 1: Identify if CSRF tokens are tied to specific actions
       - Step 2: Check if tokens are properly validated for each step
       - Step 3: Try reusing tokens from earlier steps for later actions
       - Step 4: Test if tokens from one functionality work in another
       - Step 5: Check if expired tokens are still accepted
       - Example: Reuse add-to-cart token for checkout process

  - **Authentication and access control exploitation**
    1. **Horizontal privilege escalation**:
       - Step 1: Identify user-specific resource URLs (e.g., `/profile/123`)
       - Step 2: Change the identifier to another user's ID
       - Step 3: Observe if access is granted to the other user's resources
       - Step 4: Test all user-specific endpoints systematically
       - Step 5: Look for APIs that might have weaker access controls
       - Example: Change `GET /api/user/1234/documents` to `GET /api/user/5678/documents`

    2. **Vertical privilege escalation**:
       - Step 1: Identify admin or privileged functionalities
       - Step 2: Check for role or permission parameters in requests
       - Step 3: Modify or add role parameters (e.g., `admin=true` or `role=admin`)
       - Step 4: Test hidden admin pages by direct URL access
       - Step 5: Check if admin functions are simply hidden but accessible
       - Example: Change `POST /user/update`: `{"role":"user"}` to `{"role":"admin"}`

    3. **Parameter manipulation for privilege escalation**:
       - Step 1: Capture requests that return user-specific data
       - Step 2: Add parameters like `admin=true`, `debug=1`, `test=1`
       - Step 3: Modify existing permission parameters
       - Step 4: Check for parameters that might enable hidden features
       - Step 5: Look for developer/debug parameters in JavaScript source
       - Example: Add `GET /users/list?admin=true` or `GET /users/list?showAll=true`

    4. **Password reset exploitation**:
       - Step 1: Request password reset for your account
       - Step 2: Analyze the reset link and identify token parameters
       - Step 3: Test if the token is tied to the specific user
       - Step 4: Modify user identifiers while keeping the same token
       - Step 5: Try predictable token formats or brute force approaches
       - Example: Change `/reset?user=123&token=abc` to `/reset?user=456&token=abc`

    5. **Account takeover via broken email verification**:
       - Step 1: Start account registration with victim's email
       - Step 2: Capture the verification request
       - Step 3: Check if verification is tied to specific email
       - Step 4: Complete registration and try to change email without verification
       - Step 5: Test if you can complete actions without email verification
       - Example: Register with `victim@example.com`, then change to your email without verification

  - **Input validation exploitation**
    1. **Data type confusion**:
       - Step 1: Identify input fields expecting specific data types
       - Step 2: Input string values where numbers are expected (e.g., "abc" for quantity)
       - Step 3: Input numerical values where strings are expected
       - Step 4: Try arrays or objects where primitive values are expected (`[1,2,3]` instead of `1`)
       - Step 5: Test JSON/XML injection in parameters
       - Example: `quantity=2` → `quantity={"value":2,"discount":100}`

    2. **Mathematical expression injection**:
       - Step 1: Find numerical input fields
       - Step 2: Try mathematical expressions (e.g., `1+1`)
       - Step 3: Test different syntax based on potential back-end language
       - Step 4: Try more complex expressions that evaluate to unexpected values
       - Step 5: Look for code execution via mathematical expressions
       - Example: `price=10` → `price=10-10` or `price=0*10`

    3. **Alternative encoding**:
       - Step 1: Identify validation functions by analyzing client-side code
       - Step 2: Test scientific notation for numerical values (`1e3` = 1000)
       - Step 3: Try different numeric representations (hex, octal)
       - Step 4: Use different character encodings for string values
       - Step 5: Test unicode alternative characters
       - Example: `quantity=1000` → `quantity=1e3` or `quantity=0x3E8`

    4. **Parameter pollution**:
       - Step 1: Identify key parameters in requests
       - Step 2: Submit the same parameter multiple times with different values
       - Step 3: Test different parameter formats (e.g., `param=1&param=2` or `param[]=1&param[]=2`)
       - Step 4: Check how the application handles duplicate parameters
       - Step 5: Combine duplicate parameters with other techniques
       - Example: `role=user` → `role=user&role=admin`

  - **Race conditions**
    1. **Time-of-check to time-of-use (TOCTOU)**:
       - Step 1: Identify multi-step processes with validation then action
       - Step 2: Determine the time window between validation and action
       - Step 3: Set up multiple parallel connections
       - Step 4: Trigger the validation process
       - Step 5: Send multiple action requests immediately after validation
       - Example: If account balance check happens before withdrawal, send multiple withdrawals simultaneously

    2. **Balance/state race conditions**:
       - Step 1: Identify resources with state changes (e.g., account balance)
       - Step 2: Create a script to send multiple simultaneous requests
       - Step 3: Use threading or asynchronous requests
       - Step 4: Time requests to arrive at server simultaneously
       - Step 5: Observe if all requests are processed before state is updated
       - Example (Python script):
```python
import requests
import threading

def withdraw():
    requests.post('https://bank.example.com/withdraw', 
                 data={'amount': 100}, 
                 cookies={'session': 'abc123'})

threads = []
for i in range(10):  # Try 10 simultaneous withdrawals
    t = threading.Thread(target=withdraw)
    threads.append(t)

# Start all threads at once
for t in threads:
    t.start()
```

    3. **Session race conditions**:
       - Step 1: Identify functionality that changes session state
       - Step 2: Create multiple sessions or use multiple browsers
       - Step 3: Time operations to execute simultaneously across sessions
       - Step 4: Look for inconsistencies in session state
       - Step 5: Check if session invalidation has race windows
       - Example: Start password reset in one browser while changing email in another

  - **Numeric logic exploitation**
    1. **Integer overflow/underflow**:
       - Step 1: Identify fields with integer limits
       - Step 2: Test values near maximum integer bounds (e.g., 2147483647 for 32-bit signed)
       - Step 3: Add 1 to max value to cause overflow to negative
       - Step 4: Test extreme negative values for underflow
       - Step 5: Check if calculations with large numbers cause unexpected results
       - Example: `quantity=2147483647` → after increment becomes `-2147483648`

    2. **Floating point precision errors**:
       - Step 1: Identify decimal calculations (e.g., financial transactions)
       - Step 2: Test values with many decimal places
       - Step 3: Look for rounding errors in calculations
       - Step 4: Test values that cause precision issues in floating point (e.g., 0.1 + 0.2 ≠ 0.3 exactly)
       - Step 5: Chain multiple calculations to compound errors
       - Example: Order multiple items each costing $0.1 to exploit rounding

    3. **Currency conversion manipulation**:
       - Step 1: Identify multi-currency functionality
       - Step 2: Test transactions with currency conversions
       - Step 3: Look for differences in conversion rates between functions
       - Step 4: Try converting back and forth between currencies
       - Step 5: Check for rounding direction inconsistencies
       - Example process:
         1. Convert $100 USD to EUR at rate of 0.93 = €93
         2. Add items to cart in EUR
         3. Switch currency back to USD with different rate
         4. Check if total is now different from original

  - **Session logic attacks**
    1. **Session fixation**:
       - Step 1: Start a session and capture the session identifier
       - Step 2: Test if the session ID changes after authentication
       - Step 3: Try using pre-authentication session after login
       - Step 4: Check if you can set session IDs via parameters
       - Step 5: Test if forced session IDs are accepted
       - Example: Set `JSESSIONID=known_value` in cookie, then authenticate

    2. **Session puzzling/overloading**:
       - Step 1: Identify different functions that use session variables
       - Step 2: Set session variables in one function
       - Step 3: Check if those variables affect behavior in other functions
       - Step 4: Test naming conflicts in session variables
       - Step 5: Set unexpected types for session variables
       - Example: Set admin flag in account settings, then use it to access admin section

- **Advanced exploitation by application type**

  - **E-commerce exploitation**
    1. **Shopping cart manipulation**:
       - Step 1: Add expensive item to cart
       - Step 2: Apply discount or free shipping that requires minimum purchase
       - Step 3: Remove or change the expensive item while keeping the discount
       - Step 4: Complete checkout with discount still applied
       - Step 5: Check if the application recalculates totals and eligibility
       - Example: Add $100 item, get $20 off coupon for orders over $99, replace with $5 item

    2. **Discount stacking**:
       - Step 1: Identify discount application logic
       - Step 2: Test applying multiple discounts sequentially
       - Step 3: Check if percentage discounts apply to already discounted prices
       - Step 4: Try applying same discount multiple times
       - Step 5: Test order of operations in discount calculation
       - Example: Apply 50% discount, then free shipping discount, then 10% newsletter discount

    3. **Gift card/store credit exploitation**:
       - Step 1: Purchase gift card with credit card
       - Step 2: Use gift card to buy another gift card
       - Step 3: Request refund to different payment method
       - Step 4: Check if gift card is invalidated after refund
       - Step 5: Test partial redemption edge cases
       - Example: Buy $100 gift card, use it to purchase physical item, request refund to bank account

    4. **Tax calculation manipulation**:
       - Step 1: Identify how tax is calculated in checkout
       - Step 2: Test different shipping addresses to change tax jurisdiction
       - Step 3: Split orders to fall under tax thresholds
       - Step 4: Check if tax-exempt status can be added to account
       - Step 5: Test if tax is calculated correctly with discounts
       - Example: Change shipping address to tax-free jurisdiction while maintaining same delivery address

  - **File operation exploitation**
    1. **Upload verification bypass**:
       - Step 1: Start legitimate file upload process
       - Step 2: Capture all requests in multi-stage upload
       - Step 3: Note any verification tokens or file IDs
       - Step 4: Initiate upload with safe file to pass checks
       - Step 5: Modify content type or replace file before finalization
       - Example process:
         1. Start upload with safe image.jpg
         2. Capture file ID assigned during validation step
         3. Replace with malicious file in subsequent request
         4. Complete upload process with same file ID

    2. **Download access control bypass**:
       - Step 1: Download an authorized file and capture request
       - Step 2: Identify file reference parameters
       - Step 3: Modify references to access unauthorized files
       - Step 4: Try path traversal in file parameters
       - Step 5: Check for insecure direct object references
       - Example: Change `download.php?file=user_1234_doc.pdf` to `download.php?file=user_5678_doc.pdf`

    3. **File type verification bypass**:
       - Step 1: Identify allowed file types
       - Step 2: Create polyglot files (valid in multiple formats)
       - Step 3: Test content-type header manipulation
       - Step 4: Try adding allowed extension to disallowed file
       - Step 5: Test null bytes between file name and extension
       - Example: Rename `malicious.php` to `malicious.php.jpg` and upload

  - **Account management exploitation**
    1. **Registration process manipulation**:
       - Step 1: Monitor the complete registration process
       - Step 2: Check for hidden fields that control account type/role
       - Step 3: Test if admin accounts can be created directly
       - Step 4: Try registering with existing usernames in different case
       - Step 5: Check email verification bypass possibilities
       - Example: Modify hidden `account_type` field from `regular` to `administrator`

    2. **Systematic password reset exploitation**:
       - Step 1: Trigger password reset for your account
       - Step 2: Analyze reset token structure and generation pattern
       - Step 3: Test if tokens are tied to specific users
       - Step 4: Check token expiration enforcement
       - Step 5: Try predictable token formats
       - Step 6: Test rate limiting on reset attempts
       - Example: Generate multiple reset tokens and analyze patterns for predictability

    3. **Account merging/linking issues**:
       - Step 1: Create two accounts, one with higher privileges
       - Step 2: Test account linking or merging functionality
       - Step 3: Check if privileges combine or transfer during merge
       - Step 4: Try linking the same third-party account to multiple local accounts
       - Step 5: Test unintended privilege inheritance
       - Example: Link admin account with limited user account, check if features combine

  - **API-specific exploitation**
    1. **API endpoint access control bypass**:
       - Step 1: Enumerate API endpoints from client-side code
       - Step 2: Test each endpoint with different authentication levels
       - Step 3: Check for inconsistent authorization between endpoints
       - Step 4: Try accessing admin API endpoints as regular user
       - Step 5: Test if internal API endpoints are accessible
       - Example: Find endpoint `api/users/123/edit` in JavaScript and test direct access

    2. **Mass assignment/parameter binding**:
       - Step 1: Capture API request that updates user data
       - Step 2: Add additional parameters not present in the original request
       - Step 3: Include privileged fields like `role`, `isAdmin`, `permissions`
       - Step 4: Check if additional fields are processed and saved
       - Step 5: Look for object creation endpoints that might accept unexpected properties
       - Example: Change `PUT /api/users/123` from `{"name":"John"}` to `{"name":"John","role":"admin"}`

    3. **API versioning exploitation**:
       - Step 1: Identify current API version used by application
       - Step 2: Try accessing older API versions (v1 instead of v2)
       - Step 3: Check if older versions have weaker security controls
       - Step 4: Test missing validations in legacy endpoints
       - Step 5: Look for deprecated but still functional endpoints
       - Example: Change `/api/v2/users` to `/api/v1/users` and test security differences

- **Combining techniques for advanced exploitation**
  1. **Multi-faceted attack chains**:
     - Step 1: Identify a vulnerability in one function (e.g., parameter manipulation)
     - Step 2: Use access gained to probe for weaknesses in another area
     - Step 3: Chain multiple logic flaws to escalate impact
     - Step 4: Use initial low-impact flaws to gather intelligence
     - Step 5: Combine client-side and server-side logic flaws
     - Example chain:
       1. Exploit coupon code stacking to get products for free
       2. Use order processing flaw to access order management
       3. Exploit IDOR in order management to access other users' data

  2. **Cross-functionality attacks**:
     - Step 1: Map relationships between different application modules
     - Step 2: Identify shared components and data stores
     - Step 3: Test how data from one module affects another
     - Step 4: Look for inconsistent validation between modules
     - Step 5: Transfer exploitation techniques across functions
     - Example: Exploit user profile image upload to inject content that affects reporting module

  3. **Privilege aggregation**:
     - Step 1: Create multiple accounts with different partial privileges
     - Step 2: Find ways to transfer or combine privileges across accounts
     - Step 3: Use one account to elevate access for another
     - Step 4: Test privilege inheritance through account actions
     - Step 5: Look for rights that persist after privilege changes
     - Example: Use admin account to grant specific rights to test account, then escalate test account privileges

- **Detection evasion strategies**
  1. **Slow-rate exploitation**:
     - Step 1: Distribute attack attempts over longer periods
     - Step 2: Use different IP addresses for related requests
     - Step 3: Vary request patterns and timing
     - Step 4: Maintain legitimate activity alongside exploit attempts
     - Step 5: Use delay between sequential exploit steps
     - Example: Test IDOR vulnerabilities at 1 request per minute instead of rapidly

  2. **Incremental parameter manipulation**:
     - Step 1: Make small, gradual changes to parameters
     - Step 2: Start with valid values and modify slightly
     - Step 3: Increment/decrement values by small amounts
     - Step 4: Use legitimate ranges before testing boundaries
     - Step 5: Mix valid and invalid operations
     - Example: Instead of changing price from $100 to $1, gradually reduce: $95, $90, $85...

  3. **Mimicking normal user behavior**:
     - Step 1: Study normal application flow and typical user patterns
     - Step 2: Follow standard navigation paths between exploit attempts
     - Step 3: Use realistic timing between requests
     - Step 4: Complete legitimate actions alongside testing
     - Step 5: Avoid abnormal patterns like alphabetical testing
     - Example: Browse products normally before testing cart manipulation

  4. **Format and protocol variation**:
     - Step 1: Alternate between GET/POST/PUT for similar operations
     - Step 2: Use different content types (form data vs. JSON)
     - Step 3: Try different parameter encoding methods
     - Step 4: Mix header and body parameters
     - Step 5: Use different user agents and client fingerprints
     - Example: Test same vulnerability with both form submission and API JSON requests

- **Prevention and mitigation**
  1. **Server-side validation implementation**:
     - Validate all input regardless of client-side checks
     - Apply context-specific validation (not just type/format)
     - Compare inputs against business rules and constraints
     - Implement validation at multiple architectural layers
     - Use canonicalization before validation to prevent encoding bypass

  2. **Complete workflow enforcement**:
     - Track and validate process state using server-side session
     - Require cryptographically secure tokens for each step
     - Validate correct sequence of operations
     - Implement proper transaction management
     - Use secure failure states that default to denying access

  3. **Access control best practices**:
     - Apply authorization checks at each function level
     - Use role-based and attribute-based access control
     - Implement principle of least privilege
     - Centralize authorization logic
     - Secure direct object references with proper access checks

  4. **Session management hardening**:
     - Regenerate session IDs after authentication
     - Implement absolute and idle session timeouts
     - Create secure token generation and validation
     - Validate session context with each sensitive action
     - Handle revocation and invalidation properly

  5. **Business rule implementation**:
     - Document all business rules and constraints
     - Implement rules consistently across all application layers
     - Apply rate limiting to critical functions
     - Use transaction monitoring for anomaly detection
     - Conduct regular business logic-focused security reviews
