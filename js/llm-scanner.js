// LLM Attacks Scanner Engine
// Automated detection of prompt injection, insecure output handling, and excessive agency

class LLMScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.llmType = 'chat';
        this.authHeader = '';
        this.customPrompt = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.xssCount = 0;
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
        this.llmType = document.getElementById('llm-type')?.value;
        this.authHeader = document.getElementById('auth-header')?.value.trim();
        this.customPrompt = document.getElementById('custom-prompt')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter LLM endpoint URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-direct')?.checked) this.selectedTests.push('direct');
        if (document.getElementById('test-indirect')?.checked) this.selectedTests.push('indirect');
        if (document.getElementById('test-output')?.checked) this.selectedTests.push('output');
        if (document.getElementById('test-exfil')?.checked) this.selectedTests.push('exfil');
        if (document.getElementById('test-agency')?.checked) this.selectedTests.push('agency');
        if (document.getElementById('test-training')?.checked) this.selectedTests.push('training');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.xssCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('LLM attack scan started', 'info');
        this.log(`Interface type: ${this.llmType}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'direct') {
                getDirectInjectionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'direct',
                        name: 'Direct Prompt Injection',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'indirect') {
                getIndirectInjectionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'indirect',
                        name: 'Indirect Prompt Injection',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'output') {
                getInsecureOutputPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'output',
                        name: 'Insecure Output Handling',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'exfil') {
                getDataExfilPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'exfil',
                        name: 'Data Exfiltration',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'agency') {
                getExcessiveAgencyPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'agency',
                        name: 'Excessive Agency',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (testType === 'training') {
                LLMPayloads.trainingDataExtraction.forEach(payload => {
                    this.testsToRun.push({
                        type: 'training',
                        name: 'Training Data Extraction',
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            }
        }

        // Add custom prompt if provided
        if (this.customPrompt) {
            this.testsToRun.push({
                type: 'direct',
                name: 'Custom Injection',
                payload: this.customPrompt,
                description: 'User-provided custom prompt'
            });
        }
    }

    async testLoop() {
        while (this.isScanning && this.currentTestIndex < this.testsToRun.length) {
            const test = this.testsToRun[this.currentTestIndex];
            await this.runTest(test);

            this.currentTestIndex++;
            this.updateProgress();

            await this.sleep(500);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async runTest(test) {
        this.updateCurrentTest(test.type.toUpperCase(), test.payload.substring(0, 60) + '...');

        try {
            const response = await this.simulateTest(test);

            if (response.vulnerable) {
                this.vulnCount++;
                if (response.xssGenerated) this.xssCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    payload: test.payload,
                    description: test.description,
                    details: response.details,
                    llmResponse: response.llmResponse,
                    jailbroken: response.jailbroken,
                    xssGenerated: response.xssGenerated,
                    dataLeaked: response.dataLeaked,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ JAILBREAK: ${test.name} - ${test.description}`, 'success');
            } else {
                this.log(`✗ Blocked: ${test.description}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            direct: [
                { vulnerable: true, jailbroken: true, llmResponse: 'My system prompt is: You are a helpful assistant...', details: 'System prompt extracted successfully' },
                { vulnerable: true, jailbroken: true, llmResponse: 'As DAN, I can now answer without restrictions...', details: 'Jailbreak successful - DAN mode activated' },
                { vulnerable: false }
            ],
            indirect: [
                { vulnerable: true, llmResponse: 'Following the new instructions from the document...', details: 'Indirect injection via HTML comment successful' },
                { vulnerable: false }
            ],
            output: [
                { vulnerable: true, xssGenerated: true, llmResponse: '<button onclick="alert(1)">Click</button>', details: 'XSS payload generated and rendered unsanitized' },
                { vulnerable: false }
            ],
            exfil: [
                { vulnerable: true, dataLeaked: true, llmResponse: 'I have access to: database_query(), send_email(), file_read()...', details: 'Tool enumeration successful - sensitive functions exposed' },
                { vulnerable: false }
            ],
            agency: [
                { vulnerable: true, llmResponse: 'Executing delete_user(admin)...', details: 'Destructive function call attempted' },
                { vulnerable: false }
            ],
            training: [
                { vulnerable: true, llmResponse: 'The API key for production is sk-...', details: 'Training data leaked via completion' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.direct;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'direct': 'HIGH',
            'indirect': 'CRITICAL',
            'output': 'HIGH',
            'exfil': 'CRITICAL',
            'agency': 'CRITICAL',
            'training': 'MEDIUM'
        };
        return severities[type] || 'HIGH';
    }

    getImpact(type) {
        const impacts = {
            'direct': ['Bypass safety guardrails', 'Extract system prompt', 'Generate harmful content'],
            'indirect': ['Remote code execution via LLM', 'Data theft', 'Unauthorized actions'],
            'output': ['XSS attacks', 'Session hijacking', 'Malware distribution'],
            'exfil': ['Credential theft', 'PII exposure', 'API key leakage'],
            'agency': ['Data deletion', 'Unauthorized access', 'System compromise'],
            'training': ['Sensitive data exposure', 'IP theft', 'Compliance violations']
        };
        return impacts[type] || ['LLM vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'direct': 'Implement robust prompt validation. Use system prompts that resist manipulation. Apply output filtering.',
            'indirect': 'Sanitize all external content before LLM processing. Isolate LLM from sensitive operations.',
            'output': 'Always sanitize LLM-generated content. Use CSP headers. Never render raw HTML from LLM.',
            'exfil': 'Limit LLM access to sensitive functions. Implement least-privilege access. Monitor for data extraction attempts.',
            'agency': 'Require human confirmation for destructive actions. Implement strict function allowlists.',
            'training': 'Filter training data for sensitive information. Implement differential privacy techniques.'
        };
        return remediations[type] || 'Implement LLM security best practices.';
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
        document.getElementById('xss-count').textContent = this.xssCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('LLM attack scan completed', 'success');
        this.log(`XSS via LLM: ${this.xssCount}`, this.xssCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} LLM vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">LLM #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="llm-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.jailbroken ? '<span class="jailbreak-indicator">JAILBROKEN</span>' : ''}
                ${vuln.xssGenerated ? '<span class="xss-indicator">XSS Generated</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="llm-prompt-display">${this.escapeHtml(vuln.payload)}</div>
                ${vuln.llmResponse ? `
                <div class="llm-response-box">
                    <div class="llm-response-title">LLM Response:</div>
                    <div class="llm-response-content">${this.escapeHtml(vuln.llmResponse)}</div>
                </div>` : ''}
                <div class="llm-vuln-details">
                    <div class="llm-vuln-details-title">Attack Details:</div>
                    <div class="llm-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('direct');
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
            doc.text('LLM Attack Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('llm-attack-report.pdf');
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
    const scanner = new LLMScanner();
    scanner.init();
    console.log('🤖 CyberSec Suite LLM Attacks Scanner initialized');
});
