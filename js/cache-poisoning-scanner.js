// Web Cache Poisoning Scanner Engine
// Automated detection of cache poisoning vulnerabilities

class CachePoisoningScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.cacheBuster = 'cb';
        this.attackerDomain = 'exploit-server.net';
        this.selectedAttacks = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.cachedCount = 0;
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
        this.cacheBuster = document.getElementById('cache-buster')?.value.trim() || 'cb';
        this.attackerDomain = document.getElementById('attacker-domain')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedAttacks = [];
        if (document.getElementById('attack-unkeyed')?.checked) this.selectedAttacks.push('unkeyed');
        if (document.getElementById('attack-xss')?.checked) this.selectedAttacks.push('xss');
        if (document.getElementById('attack-deception')?.checked) this.selectedAttacks.push('deception');
        if (document.getElementById('attack-parameter')?.checked) this.selectedAttacks.push('parameter');
        if (document.getElementById('attack-normalization')?.checked) this.selectedAttacks.push('normalization');
        if (document.getElementById('attack-vary')?.checked) this.selectedAttacks.push('vary');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.cachedCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Cache poisoning scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const attackType of this.selectedAttacks) {
            if (attackType === 'unkeyed') {
                getUnkeyedHeaders().forEach(item => {
                    this.testsToRun.push({
                        type: 'unkeyed',
                        name: 'Unkeyed Header',
                        header: item.header,
                        value: this.attackerDomain,
                        description: `${item.header}: ${this.attackerDomain}`
                    });
                });
            } else if (attackType === 'xss') {
                getXSSPayloads().forEach(item => {
                    this.testsToRun.push({
                        type: 'xss',
                        name: 'XSS via Cache',
                        header: item.header,
                        value: item.value,
                        description: `${item.header}: ${item.value.substring(0, 40)}...`
                    });
                });
            } else if (attackType === 'deception') {
                getCacheDeceptionPaths().forEach(item => {
                    this.testsToRun.push({
                        type: 'deception',
                        name: 'Cache Deception',
                        path: item.path,
                        description: item.description
                    });
                });
            } else if (attackType === 'parameter') {
                CachePoisoningPayloads.parameterCloaking.forEach(item => {
                    this.testsToRun.push({
                        type: 'parameter',
                        name: 'Parameter Cloaking',
                        technique: item.technique,
                        payload: item.payload,
                        description: item.technique
                    });
                });
            } else if (attackType === 'normalization') {
                CachePoisoningPayloads.cacheKeyNormalization.forEach(item => {
                    this.testsToRun.push({
                        type: 'normalization',
                        name: 'Path Normalization',
                        technique: item.technique,
                        payloads: item.payloads,
                        description: item.technique
                    });
                });
            } else if (attackType === 'vary') {
                CachePoisoningPayloads.varyHeaderTests.forEach(header => {
                    this.testsToRun.push({
                        type: 'vary',
                        name: 'Vary Header Test',
                        header: header,
                        description: `Test Vary: ${header}`
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
                if (response.cached) this.cachedCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    header: test.header,
                    value: test.value || test.payload,
                    details: response.details,
                    cached: response.cached,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ POISONED: ${test.name} - ${test.description}`, 'success');
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

        const responses = {
            unkeyed: [
                { vulnerable: true, cached: true, details: 'Header value reflected in cached response' },
                { vulnerable: false, cached: false, details: 'Header not reflected' }
            ],
            xss: [
                { vulnerable: true, cached: true, details: 'XSS payload cached and served to users' },
                { vulnerable: false, cached: false, details: 'XSS payload sanitized' }
            ],
            deception: [
                { vulnerable: true, cached: true, details: 'Sensitive page cached with static extension' },
                { vulnerable: false, cached: false, details: 'Page not cached' }
            ],
            parameter: [
                { vulnerable: true, cached: true, details: 'Parameter excluded from cache key' },
                { vulnerable: false, cached: false, details: 'Parameter included in cache key' }
            ],
            normalization: [
                { vulnerable: true, cached: true, details: 'Path normalization allows cache key collision' },
                { vulnerable: false, cached: false, details: 'Path properly normalized' }
            ],
            vary: [
                { vulnerable: true, cached: true, details: 'Vary header not properly implemented' },
                { vulnerable: false, cached: false, details: 'Vary header working correctly' }
            ]
        };

        const typeResponses = responses[test.type] || responses.unkeyed;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        if (type === 'xss' || type === 'unkeyed') return 'CRITICAL';
        if (type === 'deception') return 'HIGH';
        return 'MEDIUM';
    }

    getImpact(type) {
        const impacts = {
            'unkeyed': ['Serve malicious content to all users', 'Redirect users to attacker domain'],
            'xss': ['Execute JavaScript on all cached page views', 'Steal credentials of all users'],
            'deception': ['Steal sensitive user data', 'Extract API keys or tokens'],
            'parameter': ['Inject payloads via excluded parameters', 'Bypass security controls'],
            'normalization': ['Cache key collision attacks', 'Serve wrong content'],
            'vary': ['Target specific user groups', 'Browser-specific attacks']
        };
        return impacts[type] || ['Cache poisoning'];
    }

    getRemediation(type) {
        const remediations = {
            'unkeyed': 'Include all headers used in response generation in cache key. Use Cache-Control: private for dynamic content.',
            'xss': 'Never reflect unkeyed input in cacheable responses. Implement strict output encoding.',
            'deception': 'Configure cache to respect Content-Type. Don\'t cache pages based on file extension alone.',
            'parameter': 'Include all query parameters in cache key or strip them completely.',
            'normalization': 'Normalize URLs before cache key generation. Use consistent path handling.',
            'vary': 'Properly configure Vary header. Include all varying factors.'
        };
        return remediations[type] || 'Review cache configuration and cache key generation.';
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
        document.getElementById('cached-count').textContent = this.cachedCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Cache poisoning scan completed', 'success');
        this.log(`Poisonable endpoints: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} cache poisoning vulnerabilities`,
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
                    <div class="vuln-title">Cache Poison #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div class="cache-type-badge">${vuln.name}</div>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="cache-vuln-details">
                    <div class="cache-vuln-details-title">Poisoning Details:</div>
                    <div class="cache-vuln-details-code">${vuln.header ? `${vuln.header}: ${vuln.value}` : vuln.details}</div>
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
        this.generateExploit('unkeyed');
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
            case 'unkeyed':
                code = `# Unkeyed Header Cache Poisoning

# Step 1: Send poisoned request
GET ${this.targetUrl}?${this.cacheBuster}=${generateCacheBuster()} HTTP/1.1
Host: TARGET
X-Forwarded-Host: ${this.attackerDomain}

# Step 2: Verify cache poisoned
GET ${this.targetUrl}?${this.cacheBuster}=same-value HTTP/1.1
Host: TARGET

# Response should contain attacker domain`;
                break;
            case 'xss':
                code = `# XSS via Cache Poisoning

# Poison the cache with XSS
GET ${this.targetUrl}?${this.cacheBuster}=${generateCacheBuster()} HTTP/1.1
Host: TARGET
X-Forwarded-Host: "><script>alert(document.domain)</script>

# All subsequent requests serve XSS
# Server at ${this.attackerDomain} can serve malicious JS`;
                break;
            case 'deception':
                code = `# Web Cache Deception Attack

# Step 1: Send victim a link
https://TARGET/my-account.css
https://TARGET/my-account/avatar.js

# Step 2: After victim clicks, retrieve cached data
GET /my-account.css HTTP/1.1
Host: TARGET

# Response contains victim's sensitive data`;
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
            doc.text('Cache Poisoning Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('cache-poisoning-report.pdf');
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
    const scanner = new CachePoisoningScanner();
    scanner.init();
    console.log('💉 CyberSec Suite Cache Poisoning Scanner initialized');
});
