---
layout: post
title: "Advanced XSS Techniques"
date: 2025-01-03 15:00:00 +0000
categories: [web-security, xss]
excerpt: "Explore advanced Cross-Site Scripting techniques and bypass methods."
---

# Advanced XSS Techniques

Cross-Site Scripting (XSS) remains one of the most prevalent web vulnerabilities. This post explores advanced techniques used by security researchers and attackers.

## XSS Categories

### 1. Reflected XSS
Reflected XSS occurs when malicious input is immediately reflected back to the user without proper sanitization.

```javascript
// Vulnerable code example
document.write("Hello " + userInput);
```

### 2. Stored XSS
Stored XSS persists malicious code in the database and affects all users who view the infected page.

### 3. DOM-based XSS
DOM-based XSS occurs when JavaScript modifies the DOM with untrusted input.

## Advanced Bypass Techniques

### Filter Evasion
```javascript
// Common bypass patterns
<ScRiPt>alert(1)</ScRiPt>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
```

### Encoding Bypasses
```javascript
// HTML encoding
&#60;script&#62;alert(1)&#60;/script&#62;

// URL encoding
%3Cscript%3Ealert(1)%3C/script%3E

// Unicode encoding
\u003Cscript\u003Ealert(1)\u003C/script\u003E
```

## Real-World Examples

### Case Study: Social Media Platform
A major social media platform was vulnerable to stored XSS through profile bio fields. Attackers could inject malicious JavaScript that would execute for all users viewing the profile.

### Impact Assessment
- Session hijacking
- Credential theft
- Malicious redirects
- Data exfiltration

## Prevention Strategies

1. **Input Validation**: Validate all user input
2. **Output Encoding**: Encode output based on context
3. **Content Security Policy**: Implement CSP headers
4. **Regular Testing**: Conduct regular security assessments

## Interactive Demo

Try the XSS demo in the Cybersecurity Tools section to see these techniques in action!
