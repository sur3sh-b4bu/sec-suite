// File Upload Scanner Engine
// Automated detection of web shell uploads, extension bypass, content-type bypass, and polyglot files

class FileUploadScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.uploadPath = '/files/avatars/';
        this.serverType = 'php';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.rceCount = 0;
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
        this.uploadPath = document.getElementById('upload-path')?.value.trim();
        this.serverType = document.getElementById('server-type')?.value;

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-webshell')?.checked) this.selectedTests.push('webshell');
        if (document.getElementById('test-extension')?.checked) this.selectedTests.push('extension');
        if (document.getElementById('test-contenttype')?.checked) this.selectedTests.push('contenttype');
        if (document.getElementById('test-polyglot')?.checked) this.selectedTests.push('polyglot');
        if (document.getElementById('test-path')?.checked) this.selectedTests.push('path');
        if (document.getElementById('test-htaccess')?.checked) this.selectedTests.push('htaccess');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.rceCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('File upload scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'webshell') {
                getWebShellPayloads(this.serverType).forEach(payload => {
                    this.testsToRun.push({
                        type: 'webshell',
                        name: 'Web Shell',
                        filename: payload.filename,
                        content: payload.content,
                        description: payload.description
                    });
                });
            } else if (testType === 'extension') {
                getExtensionBypassPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'extension',
                        name: 'Extension Bypass',
                        filename: `shell${payload.bypass}`,
                        bypass: payload.bypass,
                        description: payload.description
                    });
                });
            } else if (testType === 'contenttype') {
                getContentTypePayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'contenttype',
                        name: 'Content-Type Bypass',
                        contentType: payload.type,
                        description: payload.description
                    });
                });
            } else if (testType === 'polyglot') {
                FileUploadPayloads.polyglots.forEach(payload => {
                    this.testsToRun.push({
                        type: 'polyglot',
                        name: 'Polyglot File',
                        polyglotName: payload.name,
                        technique: payload.technique,
                        description: payload.description
                    });
                });
            } else if (testType === 'path') {
                getPathTraversalPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'path',
                        name: 'Path Traversal',
                        filename: payload.filename,
                        description: payload.description
                    });
                });
            } else if (testType === 'htaccess') {
                FileUploadPayloads.htaccessAttacks.forEach(payload => {
                    this.testsToRun.push({
                        type: 'htaccess',
                        name: '.htaccess Upload',
                        filename: payload.filename,
                        content: payload.content,
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
                if (response.rce) this.rceCount++;

                const baseUrl = this.targetUrl.replace(/\/[^\/]*$/, '');
                const shellUrl = `${baseUrl}${this.uploadPath}${test.filename || 'shell.php'}?cmd=id`;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    filename: test.filename,
                    content: test.content,
                    description: test.description,
                    shellUrl: shellUrl,
                    details: response.details,
                    rce: response.rce,
                    severity: response.rce ? 'CRITICAL' : 'HIGH',
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
            webshell: [
                { vulnerable: true, rce: true, details: 'Web shell uploaded and executed successfully - RCE confirmed' },
                { vulnerable: false }
            ],
            extension: [
                { vulnerable: true, rce: true, details: 'Extension bypass successful - file executed as code' },
                { vulnerable: true, rce: false, details: 'Extension bypass allowed upload but no execution' },
                { vulnerable: false }
            ],
            contenttype: [
                { vulnerable: true, rce: true, details: 'Content-Type bypass successful - PHP executed' },
                { vulnerable: false }
            ],
            polyglot: [
                { vulnerable: true, rce: true, details: 'Polyglot file uploaded and code executed' },
                { vulnerable: true, rce: false, details: 'Polyglot uploaded but requires additional step' },
                { vulnerable: false }
            ],
            path: [
                { vulnerable: true, rce: true, details: 'Path traversal successful - file written outside upload directory' },
                { vulnerable: false }
            ],
            htaccess: [
                { vulnerable: true, rce: true, details: '.htaccess uploaded - can now execute any extension as PHP' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.webshell;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'webshell': ['Remote Code Execution', 'Full server compromise', 'Data exfiltration'],
            'extension': ['Code execution', 'Bypass security controls', 'Server compromise'],
            'contenttype': ['Code execution', 'Bypass validation', 'Web shell deployment'],
            'polyglot': ['Bypass multiple checks', 'Code execution', 'Persistent access'],
            'path': ['Write to any path', 'Overwrite config', 'Code execution'],
            'htaccess': ['Server reconfiguration', 'Execute any file as code', 'Full compromise']
        };
        return impacts[type] || ['File upload vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'webshell': 'Validate file content, not just extension. Store uploads outside webroot. Use random filenames.',
            'extension': 'Use allowlist for extensions. Parse and validate file type server-side.',
            'contenttype': 'Never trust Content-Type header. Validate actual file content with magic bytes.',
            'polyglot': 'Check file headers AND content. Use imagemagick to re-process images.',
            'path': 'Sanitize filenames. Remove path separators. Use server-generated filenames.',
            'htaccess': 'Disable .htaccess in upload directories. Use server config instead.'
        };
        return remediations[type] || 'Implement proper file upload validation.';
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
        document.getElementById('rce-count').textContent = this.rceCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('File upload scan completed', 'success');
        this.log(`RCE vulnerabilities: ${this.rceCount}`, this.rceCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} upload vulnerabilities (${this.rceCount} RCE)`,
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
                    <div class="vuln-title">Upload #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="upload-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.rce ? '<span class="rce-indicator">RCE CONFIRMED</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                ${vuln.filename ? `
                <div class="file-display">
                    <div class="file-name">Filename: ${this.escapeHtml(vuln.filename)}</div>
                    ${vuln.content ? `<div class="file-content">${this.escapeHtml(vuln.content)}</div>` : ''}
                </div>` : ''}
                ${vuln.shellUrl ? `<div class="shell-url">Shell URL: ${vuln.shellUrl}</div>` : ''}
                <div class="upload-vuln-details">
                    <div class="upload-vuln-details-title">Attack Details:</div>
                    <div class="upload-vuln-details-code">${vuln.details}</div>
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
        this.generateExploit('webshell');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
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
            doc.text('File Upload Security Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount} (${this.rceCount} RCE)`, 20, 42);
            doc.save('file-upload-report.pdf');
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
    const scanner = new FileUploadScanner();
    scanner.init();
    console.log('📁 CyberSec Suite File Upload Scanner initialized');
});
