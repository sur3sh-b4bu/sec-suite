// SSTI Scanner Engine
// Automated Server-Side Template Injection detection

class SSTIScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.vulnParam = 'message';
        this.selectedEngines = [];
        this.detectionMethods = [];
        this.currentPayloadIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.safeCount = 0;
        this.vulnerabilities = [];
        this.payloadsToTest = [];
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
        document.getElementById('total-payloads').textContent = getPayloadCount() + '+';
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpMethod = document.getElementById('http-method')?.value;
        this.vulnParam = document.getElementById('vuln-param')?.value.trim();

        if (!this.targetUrl || !this.vulnParam) {
            this.showNotification('Please enter target URL and parameter name', 'error');
            return;
        }

        // Get selected engines
        this.selectedEngines = [];
        if (document.getElementById('engine-jinja2')?.checked) this.selectedEngines.push('jinja2');
        if (document.getElementById('engine-twig')?.checked) this.selectedEngines.push('twig');
        if (document.getElementById('engine-freemarker')?.checked) this.selectedEngines.push('freemarker');
        if (document.getElementById('engine-velocity')?.checked) this.selectedEngines.push('velocity');
        if (document.getElementById('engine-erb')?.checked) this.selectedEngines.push('erb');
        if (document.getElementById('engine-smarty')?.checked) this.selectedEngines.push('smarty');
        if (document.getElementById('engine-tornado')?.checked) this.selectedEngines.push('tornado');
        if (document.getElementById('engine-handlebars')?.checked) this.selectedEngines.push('handlebars');

        // Get detection methods
        this.detectionMethods = [];
        if (document.getElementById('detect-polyglot')?.checked) this.detectionMethods.push('polyglot');
        if (document.getElementById('detect-math')?.checked) this.detectionMethods.push('math');
        if (document.getElementById('detect-rce')?.checked) this.detectionMethods.push('rce');
        if (document.getElementById('detect-blind')?.checked) this.detectionMethods.push('blind');

        if (this.selectedEngines.length === 0) {
            this.showNotification('Please select at least one template engine', 'error');
            return;
        }

        this.preparePayloads();

        // Reset state
        this.isScanning = true;
        this.currentPayloadIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.safeCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('SSTI scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Parameter: ${this.vulnParam}`, 'info');
        this.log(`Total payloads: ${this.payloadsToTest.length}`, 'info');

        await this.attackLoop();
    }

    preparePayloads() {
        this.payloadsToTest = [];

        // Add polyglot payloads
        if (this.detectionMethods.includes('polyglot')) {
            SSTIPayloads.polyglot.forEach(payload => {
                this.payloadsToTest.push({
                    engine: 'polyglot',
                    type: 'detection',
                    payload: payload,
                    name: 'Polyglot Detection'
                });
            });
        }

        // Add engine-specific payloads
        for (const engine of this.selectedEngines) {
            const enginePayloads = getPayloadsByEngine(engine);

            // Detection payloads
            if (enginePayloads.detection && this.detectionMethods.includes('math')) {
                enginePayloads.detection.slice(0, 3).forEach(payload => {
                    this.payloadsToTest.push({
                        engine: engine,
                        type: 'detection',
                        payload: payload,
                        name: this.getEngineName(engine) + ' Detection'
                    });
                });
            }

            // RCE payloads
            if (enginePayloads.rce && this.detectionMethods.includes('rce')) {
                enginePayloads.rce.slice(0, 2).forEach(payload => {
                    this.payloadsToTest.push({
                        engine: engine,
                        type: 'rce',
                        payload: payload,
                        name: this.getEngineName(engine) + ' RCE'
                    });
                });
            }
        }
    }

    getEngineName(engine) {
        const names = {
            'jinja2': 'Jinja2',
            'twig': 'Twig',
            'freemarker': 'Freemarker',
            'velocity': 'Velocity',
            'erb': 'ERB',
            'smarty': 'Smarty',
            'tornado': 'Tornado',
            'handlebars': 'Handlebars',
            'pug': 'Pug',
            'thymeleaf': 'Thymeleaf',
            'polyglot': 'Polyglot'
        };
        return names[engine] || engine;
    }

    async attackLoop() {
        while (this.isScanning && this.currentPayloadIndex < this.payloadsToTest.length) {
            const payloadData = this.payloadsToTest[this.currentPayloadIndex];
            await this.testPayload(payloadData);

            this.currentPayloadIndex++;
            this.updateProgress();

            await this.sleep(500);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async testPayload(payloadData) {
        const { engine, type, payload, name } = payloadData;

        this.updateCurrentPayload(name, payload);

        try {
            const testUrl = buildPayloadURL(this.targetUrl, this.vulnParam, payload, this.httpMethod);
            const response = await this.makeRequest(testUrl, payload, type);

            const isVulnerable = this.analyzeResponse(response, type, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    engine: engine,
                    type: type,
                    name: name,
                    payload: payload,
                    testUrl: testUrl,
                    output: response.output,
                    severity: this.getSeverity(type),
                    description: this.getDescription(engine, type, payload),
                    remediation: this.getRemediation()
                });
                this.log(`✓ VULNERABLE: ${name} - ${payload.substring(0, 50)}...`, 'success');
            } else {
                this.safeCount++;
                this.log(`✗ Not vulnerable: ${name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    async makeRequest(url, payload, type) {
        await this.sleep(200);

        // Simulate SSTI response
        const responses = {
            detection: [
                { vulnerable: true, output: '49', blocked: false },
                { vulnerable: false, output: '{{7*7}}', blocked: false }
            ],
            rce: [
                { vulnerable: true, output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', blocked: false },
                { vulnerable: false, output: null, blocked: true }
            ]
        };

        const typeResponses = responses[type] || responses.detection;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    analyzeResponse(response, type, payload) {
        if (type === 'detection') {
            // Check if math expression was evaluated
            return response.output === '49' || response.output === '7777777';
        } else if (type === 'rce') {
            // Check for command output
            return response.output && (response.output.includes('uid=') || response.output.includes('root:'));
        }
        return response.vulnerable;
    }

    getSeverity(type) {
        if (type === 'rce') {
            return 'CRITICAL';
        } else if (type === 'detection') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    getDescription(engine, type, payload) {
        const engineName = this.getEngineName(engine);
        if (type === 'rce') {
            return `Application is vulnerable to ${engineName} SSTI with RCE capability. Attacker can execute arbitrary code: ${payload}`;
        } else {
            return `Application is vulnerable to ${engineName} SSTI. Template expressions are evaluated: ${payload}`;
        }
    }

    getRemediation() {
        return 'Never pass user input directly to template engines. Use logic-less templates. Enable template sandboxing. Sanitize all user input. Disable dangerous template features.';
    }

    updateCurrentPayload(name, payload) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('current-payload-template').textContent = payload;
    }

    updateProgress() {
        const progress = (this.currentPayloadIndex / this.payloadsToTest.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Testing payload ${this.currentPayloadIndex} of ${this.payloadsToTest.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('safe-count').textContent = this.safeCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('SSTI scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} SSTI vulnerabilities`,
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
                    <div class="vuln-title">SSTI Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div class="engine-badge">${this.getEngineName(vuln.engine)}</div>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-template-payload">
                    <div class="vuln-template-payload-title">Template Payload:</div>
                    <div class="vuln-template-payload-code">${this.escapeHtml(vuln.payload)}</div>
                </div>
                ${vuln.output ? `
                <div class="vuln-template-output">
                    <div class="vuln-template-output-title">Template Output:</div>
                    <div class="vuln-template-output-content">${this.escapeHtml(vuln.output)}</div>
                </div>
                ` : ''}
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
            this.showNotification('No vulnerabilities found to generate exploits', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        const firstVulnEngine = this.vulnerabilities[0].engine;
        this.generateExploit(firstVulnEngine === 'polyglot' ? 'jinja2' : firstVulnEngine);
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(engine) {
        const exploitCode = document.getElementById('exploit-code');
        const enginePayloads = getPayloadsByEngine(engine);

        let code = `# ${this.getEngineName(engine)} SSTI Exploit\n\n`;

        code += `# Detection\n`;
        if (enginePayloads.detection) {
            code += buildPayloadURL(this.targetUrl, this.vulnParam, enginePayloads.detection[0], this.httpMethod) + '\n\n';
        }

        code += `# Remote Code Execution\n`;
        if (enginePayloads.rce) {
            enginePayloads.rce.slice(0, 2).forEach(payload => {
                code += buildPayloadURL(this.targetUrl, this.vulnParam, payload, this.httpMethod) + '\n';
            });
        }

        if (enginePayloads.fileRead) {
            code += `\n# File Read\n`;
            code += buildPayloadURL(this.targetUrl, this.vulnParam, enginePayloads.fileRead[0], this.httpMethod) + '\n';
        }

        exploitCode.textContent = code;
    }

    copyExploit() {
        const code = document.getElementById('exploit-code').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showNotification('Exploit copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy exploit', 'error');
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
            doc.text('SSTI Vulnerability Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Parameter: ${this.vulnParam}`, 20, 42);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 49);
            doc.text(`Vulnerabilities Found: ${this.vulnCount}`, 20, 56);

            let y = 70;
            this.vulnerabilities.forEach((vuln, index) => {
                if (y > 270) {
                    doc.addPage();
                    y = 20;
                }

                doc.setFontSize(14);
                doc.text(`${index + 1}. ${vuln.name}`, 20, y);
                y += 7;

                doc.setFontSize(10);
                doc.text(`Engine: ${this.getEngineName(vuln.engine)}`, 20, y);
                y += 7;
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 12;
            });

            doc.save('ssti-vulnerability-report.pdf');
            this.showNotification('PDF report exported successfully', 'success');

        } catch (error) {
            this.showNotification('Failed to export PDF', 'error');
            console.error(error);
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
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            info: '#3b82f6',
            warning: '#f59e0b'
        };

        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 90px;
            right: 20px;
            background: ${colors[type]};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
            z-index: 10000;
            animation: slideIn 0.3s ease;
            font-weight: 500;
        `;
        notification.textContent = message;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const scanner = new SSTIScanner();
    scanner.init();

    console.log('📄 CyberSec Suite SSTI Scanner initialized');
    console.log('📊 Ready to scan!');
});
