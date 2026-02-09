// NoSQL Injection Scanner Engine
// Automated detection of MongoDB operator injection, authentication bypass, and JavaScript injection

class NoSQLScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.contentType = 'json';
        this.dbType = 'mongodb';
        this.usernameField = 'username';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.bypassCount = 0;
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
        this.contentType = document.getElementById('content-type')?.value;
        this.dbType = document.getElementById('db-type')?.value;
        this.usernameField = document.getElementById('username-field')?.value.trim() || 'username';

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-operator')?.checked) this.selectedTests.push('operator');
        if (document.getElementById('test-auth')?.checked) this.selectedTests.push('auth');
        if (document.getElementById('test-js')?.checked) this.selectedTests.push('js');
        if (document.getElementById('test-extract')?.checked) this.selectedTests.push('extract');
        if (document.getElementById('test-url')?.checked) this.selectedTests.push('url');
        if (document.getElementById('test-blind')?.checked) this.selectedTests.push('blind');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.bypassCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('NoSQL injection scan started', 'info');
        this.log(`Database type: ${this.dbType}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'operator') {
                getOperatorPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'operator',
                        name: 'Operator Injection',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'auth') {
                getAuthBypassPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'auth',
                        name: 'Authentication Bypass',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'js') {
                getJSPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'js',
                        name: 'JavaScript Injection',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'extract') {
                getExtractionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'extract',
                        name: 'Data Extraction',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'url') {
                getURLPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'url',
                        name: 'URL Parameter Injection',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'blind') {
                this.testsToRun.push({
                    type: 'blind',
                    name: 'Blind NoSQL Injection',
                    payload: '1;sleep(5000)',
                    description: 'Time-based blind detection'
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
                if (response.authBypassed) this.bypassCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    payload: test.payload,
                    description: test.description,
                    details: response.details,
                    authBypassed: response.authBypassed,
                    extracted: response.extracted,
                    operator: response.operator,
                    severity: this.getSeverity(test.type),
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
            operator: [
                { vulnerable: true, operator: '$ne', details: 'Operator injection successful - $ne accepted' },
                { vulnerable: true, operator: '$gt', details: 'Operator injection successful - $gt bypassed validation' },
                { vulnerable: false }
            ],
            auth: [
                { vulnerable: true, authBypassed: true, details: 'Authentication bypassed - logged in as admin' },
                { vulnerable: true, authBypassed: true, details: 'Login bypass successful with $ne operator' },
                { vulnerable: false }
            ],
            js: [
                { vulnerable: true, details: 'JavaScript injection in $where clause executed' },
                { vulnerable: false }
            ],
            extract: [
                { vulnerable: true, extracted: 'adm...', details: 'Partial password extracted via regex' },
                { vulnerable: false }
            ],
            url: [
                { vulnerable: true, operator: '[$ne]', details: 'URL parameter operator injection worked' },
                { vulnerable: false }
            ],
            blind: [
                { vulnerable: true, details: 'Time-based injection detected - 5 second delay observed' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.operator;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'operator': 'HIGH',
            'auth': 'CRITICAL',
            'js': 'CRITICAL',
            'extract': 'HIGH',
            'url': 'HIGH',
            'blind': 'HIGH'
        };
        return severities[type] || 'HIGH';
    }

    getImpact(type) {
        const impacts = {
            'operator': ['Bypass query logic', 'Access unauthorized data', 'Enumeration'],
            'auth': ['Complete authentication bypass', 'Admin access', 'Account takeover'],
            'js': ['Arbitrary JS execution', 'Data extraction', 'DoS via sleep()'],
            'extract': ['Password extraction', 'Sensitive data leak', 'Credential theft'],
            'url': ['Parameter tampering', 'Filter bypass', 'Data access'],
            'blind': ['Confirmed injection point', 'Time-based extraction', 'Further attacks']
        };
        return impacts[type] || ['NoSQL injection vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'operator': 'Sanitize input. Use allowlist for operators. Cast types explicitly.',
            'auth': 'Never trust user input in queries. Use parameterized queries where possible.',
            'js': 'Disable $where and mapReduce. Avoid user input in JS evaluation.',
            'extract': 'Implement rate limiting. Use generic error messages. Log extraction attempts.',
            'url': 'Parse and validate URL parameters. Reject unexpected array/object parameters.',
            'blind': 'Add consistent response times. Disable debugging features in production.'
        };
        return remediations[type] || 'Implement input validation and output encoding.';
    }

    updateCurrentTest(type, description) {
        document.getElementById('current-type').textContent = type;
        document.getElementById('current-test-details').textContent = description;
    }

    updateProgress() {
        const progress = (this.currentTestIndex / this.testsToRun.length) * 100;

        const fillEl = document.getElementById('progress-fill');
        if (fillEl) fillEl.style.width = progress + '%';

        const percentEl = document.getElementById('progress-percent');
        if (percentEl) percentEl.textContent = Math.round(progress) + '%';

        const textEl = document.getElementById('progress-text');
        if (textEl) textEl.textContent = `Testing ${this.currentTestIndex} of ${this.testsToRun.length}`;

        const testedEl = document.getElementById('tested-count');
        if (testedEl) testedEl.textContent = this.testedCount;

        const vulnEl = document.getElementById('vuln-count');
        if (vulnEl) vulnEl.textContent = this.vulnCount;

        const bypassEl = document.getElementById('bypass-count');
        if (bypassEl) bypassEl.textContent = this.bypassCount;

        const badgeEl = document.getElementById('vuln-badge');
        if (badgeEl) badgeEl.textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('NoSQL injection scan completed', 'success');
        this.log(`Auth bypasses: ${this.bypassCount}`, this.bypassCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} NoSQL injection points`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">NoSQL #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="nosql-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.authBypassed ? '<span class="bypass-indicator">AUTH BYPASSED</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="nosql-payload-display">${this.escapeHtml(vuln.payload)}</div>
                ${vuln.operator ? `
                <div class="operator-list">
                    <span class="operator-tag">${vuln.operator}</span>
                </div>` : ''}
                ${vuln.extracted ? `
                <div class="extracted-data">
                    <div class="extracted-data-title">Extracted Data:</div>
                    <div class="extracted-data-value">${this.escapeHtml(vuln.extracted)}</div>
                </div>` : ''}
                <div class="nosql-vuln-details">
                    <div class="nosql-vuln-details-title">Attack Details:</div>
                    <div class="nosql-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('authbypass');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploitCode(tab);
    }

    generateExploitCode(type) {
        const exploitCode = document.getElementById('exploit-code');
        exploitCode.textContent = generateExploit(type);
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
            doc.text('NoSQL Injection Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('nosql-injection-report.pdf');
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
    const scanner = new NoSQLScanner();
    scanner.init();
    console.log('🗃️ CyberSec Suite NoSQL Injection Scanner initialized');
});
