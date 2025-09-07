// Interactive Demos for Windows 95 Blog
class SecurityDemos {
    constructor() {
        this.init();
    }

    init() {
        // Initialize demos when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupDemos());
        } else {
            this.setupDemos();
        }
    }

    setupDemos() {
        // Look for demo containers in post content
        this.setupXSSDemo();
        this.setupSQLiDemo();
        this.setupCSRFDemo();
    }

    setupXSSDemo() {
        const xssContainer = document.querySelector('.xss-demo');
        if (!xssContainer) return;

        const input = xssContainer.querySelector('.xss-input');
        const output = xssContainer.querySelector('.xss-output');
        const executeBtn = xssContainer.querySelector('.xss-execute');

        if (!input || !output || !executeBtn) return;

        executeBtn.addEventListener('click', () => {
            const payload = input.value;
            this.executeXSSDemo(payload, output);
        });

        // Also execute on Enter key
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.executeXSSDemo(input.value, output);
            }
        });
    }

    executeXSSDemo(payload, outputElement) {
        // Simulate a vulnerable comment system
        const safePayload = this.sanitizeXSS(payload);
        const vulnerablePayload = payload; // This is what would happen without sanitization

        outputElement.innerHTML = `
            <div class="demo-result">
                <h4>Vulnerable Output (No Sanitization):</h4>
                <div class="vulnerable-output">${vulnerablePayload}</div>
                <h4>Safe Output (With Sanitization):</h4>
                <div class="safe-output">${safePayload}</div>
                <div class="demo-explanation">
                    <strong>Explanation:</strong> The vulnerable output shows how XSS payloads can execute, 
                    while the safe output shows proper sanitization.
                </div>
            </div>
        `;

        // Show achievement for trying XSS
        if (payload.toLowerCase().includes('<script>') || payload.toLowerCase().includes('javascript:')) {
            this.showAchievement('XSS Explorer');
        }
    }

    sanitizeXSS(input) {
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    setupSQLiDemo() {
        const sqliContainer = document.querySelector('.sqli-demo');
        if (!sqliContainer) return;

        const usernameInput = sqliContainer.querySelector('.sqli-username');
        const passwordInput = sqliContainer.querySelector('.sqli-password');
        const loginBtn = sqliContainer.querySelector('.sqli-login');
        const resultDiv = sqliContainer.querySelector('.sqli-result');

        if (!usernameInput || !passwordInput || !loginBtn || !resultDiv) return;

        loginBtn.addEventListener('click', () => {
            const username = usernameInput.value;
            const password = passwordInput.value;
            this.executeSQLiDemo(username, password, resultDiv);
        });

        // Also execute on Enter key
        [usernameInput, passwordInput].forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.executeSQLiDemo(usernameInput.value, passwordInput.value, resultDiv);
                }
            });
        });
    }

    executeSQLiDemo(username, password, resultElement) {
        // Simulate SQL injection
        const isSQLi = this.detectSQLi(username) || this.detectSQLi(password);
        
        if (isSQLi) {
            resultElement.innerHTML = `
                <div class="sqli-success">
                    <h4>🚨 SQL Injection Detected!</h4>
                    <div class="query-display">
                        <strong>Malicious Query:</strong><br>
                        <code>SELECT * FROM users WHERE username='${username}' AND password='${password}'</code>
                    </div>
                    <div class="sqli-explanation">
                        <strong>What happened:</strong> The input contains SQL injection payloads that could 
                        manipulate the database query. In a real application, this could lead to:
                        <ul>
                            <li>Unauthorized access to user accounts</li>
                            <li>Data extraction from the database</li>
                            <li>Database manipulation or deletion</li>
                        </ul>
                    </div>
                </div>
            `;
            this.showAchievement('SQL Injection Master');
        } else {
            // Simulate normal login attempt
            const isValid = this.simulateLogin(username, password);
            resultElement.innerHTML = `
                <div class="login-result ${isValid ? 'success' : 'failed'}">
                    <h4>${isValid ? '✅ Login Successful' : '❌ Login Failed'}</h4>
                    <div class="query-display">
                        <strong>Query:</strong><br>
                        <code>SELECT * FROM users WHERE username='${username}' AND password='${password}'</code>
                    </div>
                    <div class="login-explanation">
                        ${isValid ? 
                            'Valid credentials provided.' : 
                            'Invalid username or password. Try SQL injection payloads like: <code>\' OR \'1\'=\'1</code>'
                        }
                    </div>
                </div>
            `;
        }
    }

    detectSQLi(input) {
        const sqliPatterns = [
            /' OR '1'='1/i,
            /' OR 1=1/i,
            /' UNION SELECT/i,
            /' DROP TABLE/i,
            /' DELETE FROM/i,
            /' INSERT INTO/i,
            /' UPDATE SET/i,
            /' OR 'x'='x/i,
            /' OR 'a'='a/i,
            /' OR 1=1--/i,
            /' OR 1=1#/i,
            /' OR 1=1\/\*/i
        ];
        
        return sqliPatterns.some(pattern => pattern.test(input));
    }

    simulateLogin(username, password) {
        // Simulate a few valid logins for demo purposes
        const validLogins = [
            { user: 'admin', pass: 'admin123' },
            { user: 'user', pass: 'password' },
            { user: 'test', pass: 'test123' }
        ];
        
        return validLogins.some(login => 
            login.user === username && login.pass === password
        );
    }

    setupCSRFDemo() {
        const csrfContainer = document.querySelector('.csrf-demo');
        if (!csrfContainer) return;

        const transferBtn = csrfContainer.querySelector('.csrf-transfer');
        const resultDiv = csrfContainer.querySelector('.csrf-result');

        if (!transferBtn || !resultDiv) return;

        transferBtn.addEventListener('click', () => {
            this.executeCSRFDemo(resultDiv);
        });
    }

    executeCSRFDemo(resultElement) {
        resultElement.innerHTML = `
            <div class="csrf-demo-result">
                <h4>🔄 CSRF Attack Simulation</h4>
                <div class="csrf-explanation">
                    <p><strong>What just happened:</strong></p>
                    <p>This button simulated a Cross-Site Request Forgery (CSRF) attack. In a real scenario:</p>
                    <ul>
                        <li>An attacker could trick you into clicking a malicious link</li>
                        <li>That link would make a request to a vulnerable website on your behalf</li>
                        <li>If you were logged in, the action would be performed without your knowledge</li>
                    </ul>
                    <p><strong>Common CSRF targets:</strong></p>
                    <ul>
                        <li>Password changes</li>
                        <li>Money transfers</li>
                        <li>Account deletions</li>
                        <li>Data modifications</li>
                    </ul>
                </div>
                <div class="csrf-protection">
                    <h5>🛡️ Protection Methods:</h5>
                    <ul>
                        <li>CSRF tokens</li>
                        <li>SameSite cookies</li>
                        <li>Origin header validation</li>
                        <li>Referer header checking</li>
                    </ul>
                </div>
            </div>
        `;
        this.showAchievement('CSRF Investigator');
    }

    showAchievement(title) {
        // Use the existing achievement system from win95.js
        // Wait for win95Blog to be available
        const tryShowAchievement = () => {
            if (window.win95Blog && window.win95Blog.unlockAchievement) {
                window.win95Blog.unlockAchievement(title);
            } else {
                // Fallback achievement display
                const achievement = document.createElement('div');
                achievement.className = 'achievement-popup';
                achievement.innerHTML = `
                    <div class="achievement-content">
                        <h4>🏆 Achievement Unlocked!</h4>
                        <p>${title}</p>
                    </div>
                `;
                achievement.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: #c0c0c0;
                    border: 2px outset #c0c0c0;
                    padding: 16px;
                    z-index: 2000;
                    box-shadow: 2px 2px 10px rgba(0,0,0,0.3);
                `;
                document.body.appendChild(achievement);
                setTimeout(() => achievement.remove(), 3000);
            }
        };
        
        // Try immediately, then retry after a short delay
        tryShowAchievement();
        setTimeout(tryShowAchievement, 100);
    }
}

// Initialize demos
new SecurityDemos();
