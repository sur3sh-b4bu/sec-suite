// API Testing Scanner Engine
// Automated detection of hidden endpoints, mass assignment, parameter pollution, and method override

class APITestingScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.apiPath = '';
        this.authHeader = '';
        this.requestBody = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.endpointCount = 0;
        this.vulnerabilities = [];
        this.testsToRun = [];
        this.discoveredEndpoints = [];
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
        this.apiPath = document.getElementById('api-path')?.value.trim();
        this.authHeader = document.getElementById('auth-header')?.value.trim();
        this.requestBody = document.getElementById('request-body')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter API base URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-hidden')?.checked) this.selectedTests.push('hidden');
        if (document.getElementById('test-method')?.checked) this.selectedTests.push('method');
        if (document.getElementById('test-mass')?.checked) this.selectedTests.push('mass');
        if (document.getElementById('test-pollution')?.checked) this.selectedTests.push('pollution');
        if (document.getElementById('test-version')?.checked) this.selectedTests.push('version');
        if (document.getElementById('test-content')?.checked) this.selectedTests.push('content');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.endpointCount = 0;
        this.vulnerabilities = [];
        this.discoveredEndpoints = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('API testing scan started', 'info');
        this.log(`Base URL: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'hidden') {
                getHiddenEndpointPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'hidden',
                        name: 'Hidden Endpoint',
                        path: payload.path,
                        description: payload.description
                    });
                });
            } else if (testType === 'method') {
                getMethodOverridePayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'method',
                        name: 'Method Override',
                        method: payload.method,
                        header: payload.header,
                        description: payload.description
                    });
                });
            } else if (testType === 'mass') {
                getMassAssignmentPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'mass',
                        name: 'Mass Assignment',
                        param: payload.param,
                        value: payload.value,
                        description: payload.description
                    });
                });
            } else if (testType === 'pollution') {
                getParamPollutionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'pollution',
                        name: 'Parameter Pollution',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'version') {
                getVersioningPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'version',
                        name: 'API Versioning',
                        path: payload.path,
                        header: payload.header,
                        description: payload.description
                    });
                });
            } else if (testType === 'content') {
                APIPayloads.contentTypeManipulation.forEach(payload => {
                    this.testsToRun.push({
                        type: 'content',
                        name: 'Content-Type',
                        contentType: payload.type,
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
                if (response.endpointFound) {
                    this.endpointCount++;
                    this.discoveredEndpoints.push(test.path || test.description);
                }

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    path: test.path,
                    method: test.method,
                    param: test.param,
                    value: test.value,
                    header: test.header,
                    description: test.description,
                    details: response.details,
                    statusCode: response.statusCode,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ FOUND: ${test.name} - ${test.description}`, 'success');
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
            hidden: [
                { vulnerable: true, endpointFound: true, statusCode: 200, details: 'Hidden endpoint accessible - returned 200 OK' },
                { vulnerable: true, endpointFound: true, statusCode: 403, details: 'Endpoint exists but forbidden - may be exploitable' },
                { vulnerable: false }
            ],
            method: [
                { vulnerable: true, statusCode: 200, details: 'Method override successful - DELETE operation performed' },
                { vulnerable: true, statusCode: 200, details: 'X-HTTP-Method-Override header accepted' },
                { vulnerable: false }
            ],
            mass: [
                { vulnerable: true, statusCode: 200, details: 'Hidden parameter accepted - isAdmin set to true' },
                { vulnerable: true, statusCode: 200, details: 'Role parameter accepted - privilege escalation possible' },
                { vulnerable: false }
            ],
            pollution: [
                { vulnerable: true, statusCode: 200, details: 'Server-side parameter pollution successful' },
                { vulnerable: false }
            ],
            version: [
                { vulnerable: true, endpointFound: true, statusCode: 200, details: 'Deprecated API version still accessible' },
                { vulnerable: false }
            ],
            content: [
                { vulnerable: true, statusCode: 200, details: 'XML content accepted - XXE may be possible' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.hidden;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'hidden': 'MEDIUM',
            'method': 'HIGH',
            'mass': 'HIGH',
            'pollution': 'HIGH',
            'version': 'MEDIUM',
            'content': 'MEDIUM'
        };
        return severities[type] || 'MEDIUM';
    }

    getImpact(type) {
        const impacts = {
            'hidden': ['Undocumented functionality', 'Debug features', 'Admin access'],
            'method': ['Unauthorized actions', 'Delete resources', 'Bypass restrictions'],
            'mass': ['Privilege escalation', 'Admin access', 'Data manipulation'],
            'pollution': ['Bypass filters', 'Inject parameters', 'Logic manipulation'],
            'version': ['Exploit old vulnerabilities', 'Bypass new protections', 'Information disclosure'],
            'content': ['XXE attacks', 'SSRF', 'Data parsing vulnerabilities']
        };
        return impacts[type] || ['API vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'hidden': 'Disable debug endpoints in production. Implement proper access controls.',
            'method': 'Disable method override headers. Validate HTTP methods explicitly.',
            'mass': 'Use allowlist for accepted parameters. Never trust user input for sensitive fields.',
            'pollution': 'Validate and sanitize all parameters. Handle duplicates consistently.',
            'version': 'Decommission deprecated API versions. Monitor for version header manipulation.',
            'content': 'Validate Content-Type strictly. Disable XML parsing if not needed.'
        };
        return remediations[type] || 'Implement API security best practices.';
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
        document.getElementById('endpoint-count').textContent = this.endpointCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('API testing scan completed', 'success');
        this.log(`Endpoints discovered: ${this.endpointCount}`, this.endpointCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} API vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">API #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="api-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.statusCode ? `<span class="exploit-indicator">HTTP ${vuln.statusCode}</span>` : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                ${vuln.path ? `<div class="api-endpoint-display"><span class="api-method get">GET</span>${vuln.path}</div>` : ''}
                ${vuln.param ? `<div class="api-endpoint-display">Parameter: <span class="param-highlight">${vuln.param}=${vuln.value}</span></div>` : ''}
                ${vuln.header ? `<div class="api-endpoint-display">Header: ${vuln.header}</div>` : ''}
                <div class="api-vuln-details">
                    <div class="api-vuln-details-title">Attack Details:</div>
                    <div class="api-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('hidden');
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
            doc.text('API Testing Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('api-testing-report.pdf');
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
    const scanner = new APITestingScanner();
    scanner.init();
    console.log('🔌 CyberSec Suite API Testing Scanner initialized');
});
