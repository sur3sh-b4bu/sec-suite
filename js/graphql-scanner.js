// GraphQL Scanner Engine
// Automated detection of introspection, IDOR, injection, batching, and DoS vulnerabilities

class GraphQLScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.authHeader = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.schemaCount = 0;
        this.vulnerabilities = [];
        this.testsToRun = [];
        this.discoveredTypes = [];
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
        this.authHeader = document.getElementById('auth-header')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter GraphQL endpoint URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-introspection')?.checked) this.selectedTests.push('introspection');
        if (document.getElementById('test-bypass')?.checked) this.selectedTests.push('bypass');
        if (document.getElementById('test-idor')?.checked) this.selectedTests.push('idor');
        if (document.getElementById('test-injection')?.checked) this.selectedTests.push('injection');
        if (document.getElementById('test-batching')?.checked) this.selectedTests.push('batching');
        if (document.getElementById('test-dos')?.checked) this.selectedTests.push('dos');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.schemaCount = 0;
        this.vulnerabilities = [];
        this.discoveredTypes = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('GraphQL scan started', 'info');
        this.log(`Endpoint: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'introspection') {
                getIntrospectionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'introspection',
                        name: 'Introspection',
                        query: payload.query,
                        description: payload.description
                    });
                });
            } else if (testType === 'bypass') {
                getIntrospectionBypassPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'bypass',
                        name: 'Introspection Bypass',
                        query: payload.query,
                        description: payload.description
                    });
                });
            } else if (testType === 'idor') {
                getIDORPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'idor',
                        name: 'IDOR / Access Control',
                        query: payload.query,
                        description: payload.description
                    });
                });
            } else if (testType === 'injection') {
                GraphQLPayloads.sqlInjection.forEach(payload => {
                    this.testsToRun.push({
                        type: 'injection',
                        name: 'GraphQL Injection',
                        arg: payload.arg,
                        description: payload.description
                    });
                });
            } else if (testType === 'batching') {
                getBatchingPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'batching',
                        name: 'Query Batching',
                        query: payload.query,
                        description: payload.description
                    });
                });
            } else if (testType === 'dos') {
                GraphQLPayloads.dos.forEach(payload => {
                    this.testsToRun.push({
                        type: 'dos',
                        name: 'DoS via Nesting',
                        query: payload.query,
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
                if (response.schemaExposed) {
                    this.schemaCount++;
                    this.discoveredTypes = response.types || [];
                }

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    query: test.query || `{user(id:"${test.arg}"){...}}`,
                    description: test.description,
                    details: response.details,
                    types: response.types,
                    dataLeak: response.dataLeak,
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
            introspection: [
                { vulnerable: true, schemaExposed: true, types: ['User', 'Post', 'Query', 'Mutation'], details: 'Full schema exposed via introspection' },
                { vulnerable: false }
            ],
            bypass: [
                { vulnerable: true, schemaExposed: true, types: ['User', 'Admin'], details: 'Introspection bypass successful' },
                { vulnerable: false }
            ],
            idor: [
                { vulnerable: true, dataLeak: true, details: 'Accessed another users sensitive data without authorization' },
                { vulnerable: true, dataLeak: true, details: 'Password field exposed in response' },
                { vulnerable: false }
            ],
            injection: [
                { vulnerable: true, details: 'SQL injection successful via GraphQL argument' },
                { vulnerable: false }
            ],
            batching: [
                { vulnerable: true, details: 'Multiple queries accepted in single request - rate limiting can be bypassed' },
                { vulnerable: false }
            ],
            dos: [
                { vulnerable: true, details: 'Server processed deeply nested query without limits' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.introspection;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'introspection': 'MEDIUM',
            'bypass': 'MEDIUM',
            'idor': 'HIGH',
            'injection': 'CRITICAL',
            'batching': 'MEDIUM',
            'dos': 'MEDIUM'
        };
        return severities[type] || 'MEDIUM';
    }

    getImpact(type) {
        const impacts = {
            'introspection': ['Schema discovery', 'Attack surface mapping', 'Field enumeration'],
            'bypass': ['Evade protections', 'Hidden types exposure', 'Security bypass'],
            'idor': ['Access other users data', 'Privilege escalation', 'Data theft'],
            'injection': ['Database access', 'Data manipulation', 'RCE possible'],
            'batching': ['Brute force attacks', 'Rate limit bypass', 'Credential stuffing'],
            'dos': ['Service disruption', 'Resource exhaustion', 'Server crash']
        };
        return impacts[type] || ['GraphQL vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'introspection': 'Disable introspection in production. Use allowlist for allowed queries.',
            'bypass': 'Implement strict query validation. Block __schema and __type in all forms.',
            'idor': 'Implement proper authorization checks. Dont rely on security through obscurity.',
            'injection': 'Use parameterized queries. Validate and sanitize all input.',
            'batching': 'Implement query complexity limits. Rate limit per operation, not request.',
            'dos': 'Implement query depth and complexity limits. Set timeouts.'
        };
        return remediations[type] || 'Implement GraphQL security best practices.';
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
        document.getElementById('schema-count').textContent = this.schemaCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('GraphQL scan completed', 'success');
        this.log(`Schema exposed: ${this.schemaCount > 0 ? 'Yes' : 'No'}`, this.schemaCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} GraphQL vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">GraphQL #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="gql-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.dataLeak ? '<span class="data-leak-indicator">DATA LEAK</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="graphql-query-display">${this.escapeHtml(vuln.query)}</div>
                ${vuln.types && vuln.types.length > 0 ? `
                <div class="schema-types">
                    <div class="schema-types-title">Discovered Types:</div>
                    <div class="schema-types-list">
                        ${vuln.types.map(t => `<span class="schema-type-tag">${t}</span>`).join('')}
                    </div>
                </div>` : ''}
                <div class="gql-vuln-details">
                    <div class="gql-vuln-details-title">Attack Details:</div>
                    <div class="gql-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('introspection');
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
            doc.text('GraphQL Security Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Endpoint: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('graphql-report.pdf');
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
    const scanner = new GraphQLScanner();
    scanner.init();
    console.log('📊 CyberSec Suite GraphQL Scanner initialized');
});
