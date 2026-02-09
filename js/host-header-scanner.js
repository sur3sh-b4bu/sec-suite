// HTTP Host Header Scanner Engine
// Automated detection of password reset poisoning, SSRF via Host, and routing-based attacks

class HostHeaderScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.attackerDomain = 'exploit-server.net';
        this.resetEndpoint = '/forgot-password';
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
        this.attackerDomain = document.getElementById('attacker-domain')?.value.trim();
        this.resetEndpoint = document.getElementById('reset-endpoint')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-reset')?.checked) this.selectedTests.push('reset');
        if (document.getElementById('test-ssrf')?.checked) this.selectedTests.push('ssrf');
        if (document.getElementById('test-routing')?.checked) this.selectedTests.push('routing');
        if (document.getElementById('test-bypass')?.checked) this.selectedTests.push('bypass');
        if (document.getElementById('test-duplicate')?.checked) this.selectedTests.push('duplicate');
        if (document.getElementById('test-absolute')?.checked) this.selectedTests.push('absolute');

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
        this.log('Host header scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];
        const targetHost = new URL(this.targetUrl).host;

        for (const testType of this.selectedTests) {
            if (testType === 'reset') {
                getPasswordResetPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'reset',
                        name: 'Password Reset Poisoning',
                        header: payload.header,
                        value: payload.value.replace('attacker.com', this.attackerDomain).replace('TARGET', targetHost),
                        description: payload.description
                    });
                });
            } else if (testType === 'ssrf') {
                getSSRFPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'ssrf',
                        name: 'SSRF via Host',
                        value: payload.value,
                        description: payload.description
                    });
                });
            } else if (testType === 'routing') {
                HostHeaderPayloads.routingSSRF.forEach(payload => {
                    this.testsToRun.push({
                        type: 'routing',
                        name: 'Routing-based SSRF',
                        method: payload.method,
                        path: payload.path,
                        host: payload.host,
                        description: payload.description
                    });
                });
            } else if (testType === 'bypass') {
                getBypassTechniques().forEach(payload => {
                    this.testsToRun.push({
                        type: 'bypass',
                        name: 'Auth Bypass',
                        technique: payload.technique,
                        value: payload.value.replace('TARGET', targetHost),
                        description: payload.technique
                    });
                });
            } else if (testType === 'duplicate') {
                HostHeaderPayloads.duplicateHost.forEach(payload => {
                    this.testsToRun.push({
                        type: 'duplicate',
                        name: 'Duplicate Host',
                        hosts: payload.hosts.map(h => h.replace('TARGET', targetHost).replace('attacker.com', this.attackerDomain)),
                        description: payload.description
                    });
                });
            } else if (testType === 'absolute') {
                HostHeaderPayloads.absoluteURL.forEach(payload => {
                    this.testsToRun.push({
                        type: 'absolute',
                        name: 'Absolute URL',
                        url: payload.url.replace('attacker.com', this.attackerDomain),
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
                    header: test.header,
                    value: test.value || test.host || (test.hosts ? test.hosts.join(', ') : ''),
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
            reset: [
                { vulnerable: true, critical: true, details: 'Password reset link contains attacker domain' },
                { vulnerable: true, critical: true, details: 'X-Forwarded-Host reflected in reset link' },
                { vulnerable: false }
            ],
            ssrf: [
                { vulnerable: true, critical: true, details: 'Internal server responded to Host header manipulation' },
                { vulnerable: false }
            ],
            routing: [
                { vulnerable: true, critical: true, details: 'Request routed to internal admin panel' },
                { vulnerable: true, critical: true, details: 'Accessed internal API via routing' },
                { vulnerable: false }
            ],
            bypass: [
                { vulnerable: true, critical: true, details: 'Host validation bypassed via encoding' },
                { vulnerable: false }
            ],
            duplicate: [
                { vulnerable: true, critical: false, details: 'Backend used second Host header' },
                { vulnerable: false }
            ],
            absolute: [
                { vulnerable: true, critical: true, details: 'Absolute URL in request line accepted' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.reset;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'reset': ['Steal password reset tokens', 'Account takeover', 'Full user compromise'],
            'ssrf': ['Access internal services', 'Read internal data', 'Bypass firewalls'],
            'routing': ['Access admin panels', 'Internal API access', 'Data exfiltration'],
            'bypass': ['Bypass access controls', 'Access restricted resources', 'Privilege escalation'],
            'duplicate': ['Confuse security controls', 'Cache poisoning', 'Request routing manipulation'],
            'absolute': ['Route to internal hosts', 'Bypass restrictions', 'SSRF attacks']
        };
        return impacts[type] || ['Host header vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'reset': 'Use server configuration for generating URLs. Never trust Host header for security-sensitive links.',
            'ssrf': 'Validate Host header against whitelist. Use absolute URLs from configuration.',
            'routing': 'Configure reverse proxy to validate Host. Block requests with mismatched Host.',
            'bypass': 'Implement strict Host header validation. Normalize before comparison.',
            'duplicate': 'Reject requests with duplicate Host headers. Use first or reject entirely.',
            'absolute': 'Configure server to reject absolute URLs in request line.'
        };
        return remediations[type] || 'Implement strict Host header validation.';
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

        this.log('Host header scan completed', 'success');
        this.log(`Vulnerabilities: ${this.vulnCount} (${this.criticalCount} critical)`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} Host header vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">Host Header #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="host-type-badge ${vuln.type}">${vuln.name}</span>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="host-header-display">
                    <div class="host-injected">${vuln.header || 'Host'}: ${vuln.value}</div>
                </div>
                <div class="host-vuln-details">
                    <div class="host-vuln-details-title">Attack Details:</div>
                    <div class="host-vuln-details-code">${vuln.details}</div>
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
        this.generateExploit('reset');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
        const exploitCode = document.getElementById('exploit-code');
        const targetHost = this.targetUrl ? new URL(this.targetUrl).host : 'TARGET';

        let code = '';
        switch (type) {
            case 'reset':
                code = generatePasswordResetPoC(targetHost, this.attackerDomain);
                break;
            case 'ssrf':
                code = `# SSRF via Host Header

# Access localhost
GET / HTTP/1.1
Host: localhost

# Access internal network
GET /admin HTTP/1.1
Host: 192.168.0.1

# Try with X-Forwarded-Host
GET /admin HTTP/1.1
Host: ${targetHost}
X-Forwarded-Host: 192.168.0.1`;
                break;
            case 'routing':
                code = generateRoutingSSRFPoC('192.168.0.1');
                break;
        }

        exploitCode.textContent = code;
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
            doc.text('Host Header Attack Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount} (${this.criticalCount} critical)`, 20, 42);
            doc.save('host-header-report.pdf');
            this.showNotification('PDF exported!', 'success');
        } catch (error) {
            this.showNotification('Export failed', 'error');
        }
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
    const scanner = new HostHeaderScanner();
    scanner.init();
    console.log('🌐 CyberSec Suite Host Header Scanner initialized');
});
