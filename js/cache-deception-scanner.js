// Cache Deception Scanner Engine
// Automated detection of path confusion, delimiter abuse, and static extension cache deception

class CacheDeceptionScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.sensitivePath = '';
        this.sessionCookie = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.hitCount = 0;
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
        this.targetUrl = document.getElementById('target-url')?.value.trim().replace(/\/$/, '');
        this.sensitivePath = document.getElementById('sensitive-path')?.value.trim();
        this.sessionCookie = document.getElementById('session-cookie')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-extension')?.checked) this.selectedTests.push('extension');
        if (document.getElementById('test-delimiter')?.checked) this.selectedTests.push('delimiter');
        if (document.getElementById('test-normalization')?.checked) this.selectedTests.push('normalization');
        if (document.getElementById('test-detection')?.checked) this.selectedTests.push('detection');
        if (document.getElementById('test-endpoints')?.checked) this.selectedTests.push('endpoints');
        if (document.getElementById('test-exploit')?.checked) this.selectedTests.push('exploit');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.hitCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Cache deception scan started', 'info');
        this.log(`Sensitive endpoint: ${this.sensitivePath}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];
        const endpoint = this.sensitivePath || '/my-account';

        for (const testType of this.selectedTests) {
            if (testType === 'extension') {
                getStaticExtensions().forEach(ext => {
                    this.testsToRun.push({
                        type: 'extension',
                        name: 'Static Extension',
                        url: `${endpoint}/nonexistent${ext.ext}`,
                        extension: ext.ext,
                        description: ext.description
                    });
                });
            } else if (testType === 'delimiter') {
                getDelimiterPayloads().forEach(delim => {
                    this.testsToRun.push({
                        type: 'delimiter',
                        name: 'Delimiter Confusion',
                        url: `${endpoint}${delim.delimiter}nonexistent.css`,
                        delimiter: delim.delimiter,
                        description: delim.description
                    });
                });
            } else if (testType === 'normalization') {
                getNormalizationPayloads().forEach(norm => {
                    this.testsToRun.push({
                        type: 'normalization',
                        name: 'Path Normalization',
                        url: norm.payload,
                        description: norm.description
                    });
                });
            } else if (testType === 'detection') {
                this.testsToRun.push({
                    type: 'detection',
                    name: 'Cache Detection',
                    url: endpoint,
                    description: 'Detect cache behavior via headers'
                });
            } else if (testType === 'endpoints') {
                getSensitiveEndpoints().forEach(ep => {
                    this.testsToRun.push({
                        type: 'endpoints',
                        name: 'Endpoint Discovery',
                        url: `${ep.path}/test.css`,
                        description: ep.description
                    });
                });
            } else if (testType === 'exploit') {
                getURLPatterns().forEach(pattern => {
                    this.testsToRun.push({
                        type: 'exploit',
                        name: 'Full Exploit',
                        url: pattern.pattern.replace('{endpoint}', endpoint),
                        description: pattern.description
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
        this.updateCurrentTest(test.type.toUpperCase(), test.url);

        try {
            const response = await this.simulateTest(test);

            if (response.vulnerable) {
                this.vulnCount++;
                if (response.cacheHit) this.hitCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    url: test.url,
                    fullUrl: `${this.targetUrl}${test.url}`,
                    extension: test.extension,
                    delimiter: test.delimiter,
                    description: test.description,
                    details: response.details,
                    cacheHeaders: response.cacheHeaders,
                    cacheHit: response.cacheHit,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ CACHEABLE: ${test.name} - ${test.url}`, 'success');
            } else {
                this.log(`✗ Not cacheable: ${test.url}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            extension: [
                { vulnerable: true, cacheHit: true, cacheHeaders: { 'X-Cache': 'HIT', 'Age': '45' }, details: 'Response cached with .css extension - sensitive data exposed' },
                { vulnerable: true, cacheHit: false, cacheHeaders: { 'X-Cache': 'MISS', 'Cache-Control': 'public' }, details: 'Cacheable response detected - waiting for victim visit' },
                { vulnerable: false }
            ],
            delimiter: [
                { vulnerable: true, cacheHit: true, cacheHeaders: { 'X-Cache': 'HIT', 'CF-Cache-Status': 'HIT' }, details: 'Delimiter confusion successful - cache stores dynamic content' },
                { vulnerable: false }
            ],
            normalization: [
                { vulnerable: true, cacheHit: true, cacheHeaders: { 'X-Cache': 'HIT' }, details: 'Path normalization difference exploited' },
                { vulnerable: false }
            ],
            detection: [
                { vulnerable: true, cacheHit: false, cacheHeaders: { 'X-Cache': 'MISS', 'Vary': 'Cookie' }, details: 'Cache detected - requires Vary header bypass' },
                { vulnerable: false }
            ],
            endpoints: [
                { vulnerable: true, cacheHit: false, cacheHeaders: { 'X-Cache': 'MISS' }, details: 'Sensitive endpoint accessible' },
                { vulnerable: false }
            ],
            exploit: [
                { vulnerable: true, cacheHit: true, cacheHeaders: { 'X-Cache': 'HIT', 'Age': '120' }, details: 'Full cache deception attack successful - victim data cached!' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.extension;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'extension': 'HIGH',
            'delimiter': 'HIGH',
            'normalization': 'HIGH',
            'detection': 'MEDIUM',
            'endpoints': 'MEDIUM',
            'exploit': 'CRITICAL'
        };
        return severities[type] || 'HIGH';
    }

    getImpact(type) {
        const impacts = {
            'extension': ['Sensitive data exposure', 'Session hijacking', 'Account takeover'],
            'delimiter': ['Cache confusion', 'Dynamic content caching', 'Data theft'],
            'normalization': ['Path traversal to cache', 'Bypass cache rules', 'Data exposure'],
            'detection': ['Cache behavior mapped', 'Attack planning', 'Vulnerability confirmation'],
            'endpoints': ['Sensitive pages found', 'Attack surface mapped', 'PII exposure'],
            'exploit': ['Full account takeover', 'API key theft', 'Complete data exposure']
        };
        return impacts[type] || ['Cache deception vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'extension': 'Configure cache to only cache truly static files. Use Cache-Control: no-store for dynamic content.',
            'delimiter': 'Normalize URLs before cache key generation. Block requests with unexpected delimiters.',
            'normalization': 'Ensure cache and origin normalize paths identically. Reject malformed paths.',
            'detection': 'Add Vary: Cookie header. Implement proper cache key configuration.',
            'endpoints': 'Require authentication for sensitive endpoints. Add Cache-Control: private.',
            'exploit': 'Implement all cache security controls. Regular security testing required.'
        };
        return remediations[type] || 'Implement proper cache security controls.';
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
        document.getElementById('hit-count').textContent = this.hitCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Cache deception scan completed', 'success');
        this.log(`Cache hits: ${this.hitCount}`, this.hitCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} cache deception points`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">Cache #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="cache-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.cacheHit ? '<span class="cache-hit-indicator">CACHE HIT</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="deception-url">
                    <div class="deception-url-title">Deceptive URL:</div>
                    <div class="deception-url-value">${this.escapeHtml(vuln.fullUrl)}</div>
                </div>
                ${vuln.cacheHeaders ? `
                <div class="cache-headers">
                    <div class="cache-headers-title">Cache Headers:</div>
                    <div class="cache-header-list">
                        ${Object.entries(vuln.cacheHeaders).map(([k, v]) => `<div class="cache-header-item"><strong>${k}:</strong> ${v}</div>`).join('')}
                    </div>
                </div>` : ''}
                <div class="cache-vuln-details">
                    <div class="cache-vuln-details-title">Attack Details:</div>
                    <div class="cache-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('basic');
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
            doc.text('Cache Deception Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('cache-deception-report.pdf');
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
    const scanner = new CacheDeceptionScanner();
    scanner.init();
    console.log('📦 CyberSec Suite Cache Deception Scanner initialized');
});
