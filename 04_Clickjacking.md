## Clickjacking (UI Redressing)

- **What it is**
  - An interface-based attack where users are tricked into clicking actionable content on a hidden website
  - Works by overlaying invisible, actionable elements over visible decoy content
  - Differs from CSRF as it requires user interaction (clicking) rather than forging entire requests
  - Not mitigated by CSRF tokens since all requests happen on-domain within a legitimate session
  - Exploits trust in web interfaces rather than web applications themselves

- **How to identify vulnerable applications**
  - Test if the target website can be framed:
    - Create a simple HTML page with an iframe containing the target website
    - If the page loads in the iframe, it may be vulnerable
  - Check for absence of protective headers:
    - Missing X-Frame-Options header
    - Missing or weak Content-Security-Policy frame-ancestors directive
  - Test if frame busting scripts can be bypassed:
    - Try using iframe with sandbox attribute: `sandbox="allow-forms allow-scripts"`
    - If the website still loads, frame busting may be ineffective

- **How to construct a basic clickjacking attack**
  - Create an HTML page with two layers:
    - Bottom layer: Decoy website content (visible to user)
    - Top layer: Target website in transparent iframe (invisible to user)
  - Basic HTML structure:
    ```html
    <head>
      <style>
        #target_website {
          position: relative;
          width: 128px;
          height: 128px;
          opacity: 0.00001;
          z-index: 2;
        }
        #decoy_website {
          position: absolute;
          width: 300px;
          height: 400px;
          z-index: 1;
        }
      </style>
    </head>
    <body>
      <div id="decoy_website">
        <!-- Decoy content (e.g., "Click here to win a prize!") -->
        <button>Click me!</button>
      </div>
      <iframe id="target_website" src="https://vulnerable-website.com"></iframe>
    </body>
    ```
  - Position the transparent iframe precisely over the decoy element to capture clicks
  - Use absolute and relative positioning to ensure precise overlap regardless of screen size
  - Set z-index to control stacking order (iframe above decoy content)
  - Use opacity near 0 to make iframe invisible (typically 0.00001 to avoid browser protections)

- **Using Burp Suite's Clickbandit tool**
  - Automates creation of clickjacking proofs of concept
  - Usage steps:
    - Launch Clickbandit from Burp Suite
    - Use your browser to perform the desired actions on the frameable page
    - Clickbandit records the clicks and creates an HTML file with the clickjacking overlay
    - Use the generated HTML as an interactive proof of concept

- **Advanced exploitation techniques**
  
  - **Clickjacking with prefilled form input**
    - Target websites that allow form prepopulation via GET parameters
    - Modify target URL to incorporate attacker's values: `https://vulnerable-website.com/form?input=malicious-value`
    - Overlay transparent "submit" button on decoy site
    - Example payload:
      ```html
      <iframe id="target_website" src="https://vulnerable-website.com/form?input=malicious-value" style="opacity:0.00001;position:relative;z-index:2;"></iframe>
      ```

  - **Bypassing frame busting scripts**
    - Use HTML5 iframe sandbox attribute to neutralize frame busters:
      ```html
      <iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms allow-scripts"></iframe>
      ```
    - Include `allow-forms` and/or `allow-scripts` but omit `allow-top-navigation`
    - This prevents the frame buster from checking if it's the top window
    - Common script bypass techniques:
      - Set iframe display style to `display:none`
      - Use onbeforeunload event to prevent frame breaking
      - Trap frame busting attempts with double framing (nested iframes)

  - **Combining clickjacking with DOM XSS**
    - Identify a DOM XSS vulnerability in the target website
    - Include the XSS payload in the iframe target URL
    - Position the iframe so the user clicks the button/link that triggers the XSS
    - Example:
      ```html
      <iframe id="target_website" src="https://vulnerable-website.com/page?input=<script>malicious-code</script>" style="opacity:0.00001;position:relative;z-index:2;"></iframe>
      ```
    - When user clicks, the DOM XSS is executed in the context of the target website

  - **Multistep clickjacking**
    - Create multiple divisions or iframes for sequences requiring multiple user actions
    - Use CSS to show/hide different layers at different steps
    - Can be used for complex attacks like:
      - Adding items to cart then completing purchase
      - Navigating through multiple screens before taking action
      - Completing form fields across multiple pages
    - Example sequence structure:
      ```html
      <style>
        #step1 { display: block; }
        #step2 { display: none; }
      </style>
      <div id="step1">
        <div id="decoy1">Click to continue</div>
        <iframe id="target1" src="https://victim.com/step1"></iframe>
      </div>
      <div id="step2">
        <div id="decoy2">Click to claim prize</div>
        <iframe id="target2" src="https://victim.com/step2"></iframe>
      </div>
      <script>
        function showStep2() {
          document.getElementById("step1").style.display = "none";
          document.getElementById("step2").style.display = "block";
        }
      </script>
      ```

  - **Clickjacking on mobile devices**
    - Mobile interfaces may have different behaviors and protections
    - Touch events can be more complex than clicks (swipes, multi-touch)
    - Techniques for mobile clickjacking:
      - Use touchstart/touchend events instead of click events
      - Account for mobile viewport scaling
      - Consider mobile-specific UI elements like swipe gestures

- **Testing for clickjacking vulnerabilities**
  - Manual testing:
    - Create test HTML file with iframe targeting the website
    - Test if site loads in the iframe
    - Test various sandbox attribute combinations
    - Try to interact with elements through the iframe
  - Tools for testing:
    - Burp Suite Clickbandit
    - Browser developer tools to adjust iframe opacity and position
    - Automated scanning tools that check for frame protection headers

- **Prevention mechanisms and how to bypass them**
  
  - **X-Frame-Options header bypasses**
    - Different browsers implement X-Frame-Options inconsistently
    - `X-Frame-Options: deny` - Prohibits all framing
    - `X-Frame-Options: sameorigin` - Restricts framing to same origin
    - `X-Frame-Options: allow-from https://example.com` - Restricts to specific origin
    - Bypass attempts:
      - Double-framing attacks (for older browsers)
      - Using documents without X-Frame-Options in the same origin
      - Exploiting inconsistent implementation across browsers

  - **Content Security Policy (CSP) bypasses**
    - `Content-Security-Policy: frame-ancestors 'none'` - Similar to X-Frame-Options: deny
    - `Content-Security-Policy: frame-ancestors 'self'` - Similar to X-Frame-Options: sameorigin
    - `Content-Security-Policy: frame-ancestors example.com` - Allows framing from specific domain
    - Bypass attempts:
      - Look for inconsistent CSP implementation across site
      - Find pages without CSP rules or with more permissive rules
      - Use embedded objects instead of iframes if not covered by CSP

  - **Frame busting script bypasses**
    - Common frame buster implementations:
      ```javascript
      // Type 1
      if (top != self) top.location = self.location;
      
      // Type 2
      if (top.location != self.location) top.location = self.location;
      
      // Type 3
      if (parent.frames.length > 0) top.location = self.location;
      ```
    - Bypass using the sandbox attribute:
      ```html
      <iframe sandbox="allow-forms allow-scripts" src="https://vulnerable-website.com"></iframe>
      ```
    - Other bypass techniques:
      - Intercepting and redefining JavaScript objects and properties
      - Onbeforeunload handler to prevent navigation
      - Design mode manipulation
      - Disabling JavaScript in the iframe context

- **Real-world impact of clickjacking**
  - Account takeover via password change or email update
  - Unwanted actions like purchases, posts, or following accounts
  - Social engineering vector combined with other attacks
  - Data exfiltration when combined with other vulnerabilities
  - Cryptocurrency transfer or financial fraud
  - Webcam/microphone activation via permission dialogs
  - Malware distribution via download buttons

- **Mitigation recommendations**
  - Implement both X-Frame-Options and Content-Security-Policy headers
  - Use SameSite cookies to prevent cross-origin framing
  - Implement CSRF tokens for sensitive actions
  - Require additional confirmation for critical operations
  - Use JS frame-busting as a secondary defense, not primary protection
  - Consider implementing user interaction heuristics (timing, mouse movement)
  - Apply UI randomization for critical elements to prevent predictable positioning
