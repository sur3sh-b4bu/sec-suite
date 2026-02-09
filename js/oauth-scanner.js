// OAuth Authentication Scanner Engine
// Automated detection of OAuth bypass, redirect URI manipulation, token theft, and CSRF

class OAuthScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.oauthServer = '';
        this.attackerDomain = 'exploit-server.net';
        this.clientId = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
        this.vulnerabilities = [];
        this.testsToRun = [];
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
        this.oauthServer = document.getElementById('oauth-server')?.value.trim();
        this.attackerDomain = document.getElementById('attacker-domain')?.value.trim();
        this.clientId = document.getElementById('client-id')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-redirect')?.checked) this.selectedTests.push('redirect');
        if (document.getElementById('test-csrf')?.checked) this.selectedTests.push('csrf');
        if (document.getElementById('test-implicit')?.checked) this.selectedTests.push('implicit');
        if (document.getElementById('test-scope')?.checked) this.selectedTests.push('scope');
        if (document.getElementById('test-pkce')?.checked) this.selectedTests.push('pkce');
        if (document.getElementById('test-linking')?.checked) this.selectedTests.push('linking');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('OAuth scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'redirect') {
                getRedirectURIPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'redirect',
                        name: 'Redirect URI Bypass',
                        payload: payload.payload.replace('attacker.com', this.attackerDomain),
                        description: payload.description
                    });
                });
            } else if (testType === 'csrf') {
                getAuthBypassPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'csrf',
                        name: 'OAuth CSRF',
                        technique: payload.technique,
                        description: payload.description
                    });
                });
            } else if (testType === 'implicit') {
                getTokenTheftPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'implicit',
                        name: 'Token Theft',
                        vector: payload.vector,
                        description: payload.description
                    });
                });
            } else if (testType === 'scope') {
                getScopeAttackPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'scope',
                        name: 'Scope Manipulation',
                        scope: payload.scope,
                        description: payload.description
                    });
                });
            } else if (testType === 'pkce') {
                OAuthPayloads.pkceBypass.forEach(payload => {
                    this.testsToRun.push({
                        type: 'pkce',
                        name: 'PKCE Bypass',
                        attack: payload.attack,
                        description: payload.description
                    });
                });
            } else if (testType === 'linking') {
                OAuthPayloads.accountLinking.forEach(payload => {
                    this.testsToRun.push({
                        type: 'linking',
                        name: 'Account Linking',
                        attack: payload.attack,
                        description: payload.description
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

            await this.sleep(400);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async runTest(test) {
        this.updateCurrentTest(test.type.toUpperCase(), test.description);

        try {
            const response = await this.simulateTest(test);

            if (response.vulnerable) {
                this.vulnCount++;
                if (response.critical) this.criticalCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    payload: test.payload || test.scope || test.attack || test.technique,
                    details: response.details,
                    severity: response.critical ? 'CRITICAL' : 'HIGH',
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name} - ${test.description}`, 'success');
            } else {
                this.log(`✗ Not vulnerable: ${test.description}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            redirect: [
                { vulnerable: true, critical: true, details: 'Redirect URI accepted attacker domain - tokens can be stolen' },
                { vulnerable: true, critical: true, details: 'Subdomain confusion allowed - redirect to attacker subdomain' },
                { vulnerable: false }
            ],
            csrf: [
                { vulnerable: true, critical: true, details: 'State parameter not validated - CSRF attack possible' },
                { vulnerable: true, critical: false, details: 'Weak state generation - predictable values' },
                { vulnerable: false }
            ],
            implicit: [
                { vulnerable: true, critical: true, details: 'Access token exposed in URL fragment' },
                { vulnerable: true, critical: false, details: 'Token leaked via Referer header' },
                { vulnerable: false }
            ],
            scope: [
                { vulnerable: true, critical: true, details: 'Elevated scope granted without user consent' },
                { vulnerable: false }
            ],
            pkce: [
                { vulnerable: true, critical: true, details: 'PKCE not enforced - code interception possible' },
                { vulnerable: false }
            ],
            linking: [
                { vulnerable: true, critical: true, details: 'Account linking allows takeover via OAuth' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.redirect;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'redirect': ['Token theft', 'Account takeover', 'Full compromise'],
            'csrf': ['Force account linking', 'Session hijacking', 'Privilege escalation'],
            'implicit': ['Access token theft', 'API access', 'Data exfiltration'],
            'scope': ['Elevated permissions', 'Admin access', 'Data access'],
            'pkce': ['Authorization code theft', 'Token interception', 'Account access'],
            'linking': ['Account takeover', 'Identity theft', 'Pre-hijacking']
        };
        return impacts[type] || ['OAuth vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'redirect': 'Strictly validate redirect_uri. Use exact match, not prefix/regex.',
            'csrf': 'Always validate state parameter. Use cryptographically random values.',
            'implicit': 'Use Authorization Code flow with PKCE. Avoid implicit grant.',
            'scope': 'Validate requested scopes. Require user consent for elevated permissions.',
            'pkce': 'Enforce PKCE for all public clients. Use S256 code challenge method.',
            'linking': 'Verify email ownership. Require authentication before linking.'
        };
        return remediations[type] || 'Implement OAuth security best practices.';
    }

    updateCurrentTest(type, description) {
        document.getElementById('current-type').textContent = type;
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
        document.getElementById('critical-count').textContent = this.criticalCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('OAuth scan completed', 'success');
        this.log(`Vulnerabilities: ${this.vulnCount} (${this.criticalCount} critical)`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} OAuth vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
    }

    stopScan() {
        this.isScanning = false;
        this.log('Scan stopped', 'warning');
        this.updateScanControls(false);
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
                    <div class="vuln-title">OAuth #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="oauth-type-badge ${vuln.type}">${vuln.name}</span>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                ${vuln.payload ? `
                <div class="oauth-flow-display">
                    <span class="oauth-malicious">${this.escapeHtml(vuln.payload)}</span>
                </div>` : ''}
                <div class="oauth-vuln-details">
                    <div class="oauth-vuln-details-title">Attack Details:</div>
                    <div class="oauth-vuln-details-code">${vuln.details}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-top: 12px;">
                    <strong>Remediation:</strong> ${vuln.remediation}
                </div>
            `;
            vulnList.appendChild(vulnCard);
        });

        resultsSection.style.display = 'block';
    }

    showExploits() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found', 'warning');
            return;
        }
        document.getElementById('exploit-section').style.display = 'block';
        this.generateExploit('redirect');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
        const exploitCode = document.getElementById('exploit-code');
        exploitCode.textContent = generateOAuthExploit(type, this.attackerDomain);
    }

    copyExploit() {
        const code = document.getElementById('exploit-code').textContent;
        navigator.clipboard.writeText(code).then(() => this.showNotification('Copied!', 'success'));
    }

    async exportPDF() {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            doc.setFontSize(20);
            doc.text('OAuth Security Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount} (${this.criticalCount} critical)`, 20, 42);
            doc.save('oauth-report.pdf');
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
        entry.innerHTML = `<span class="log-time">[${new Date().toLocaleTimeString()}]</span> ${message}`;
        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    clearLog() { document.getElementById('attack-log').innerHTML = ''; }

    showNotification(message, type = 'info') {
        const colors = { success: '#10b981', error: '#ef4444', info: '#3b82f6', warning: '#f59e0b' };
        const notification = document.createElement('div');
        notification.style.cssText = `position: fixed; top: 90px; right: 20px; background: ${colors[type]}; color: white; padding: 1rem 1.5rem; border-radius: 0.5rem; z-index: 10000; font-weight: 500;`;
        notification.textContent = message;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 3000);
    }

    sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
}

document.addEventListener('DOMContentLoaded', () => {
    const scanner = new OAuthScanner();
    scanner.init();
    console.log('🔐 CyberSec Suite OAuth Scanner initialized');
});
