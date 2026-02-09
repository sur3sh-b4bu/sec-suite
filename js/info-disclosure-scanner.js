// Information Disclosure Scanner Engine
// Automated detection of error messages, debug endpoints, backup files, and sensitive data exposure

class InfoDisclosureScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.testParam = 'productId';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
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
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportPDF());
    }

    updateStats() {
        document.getElementById('total-tests').textContent = getPayloadCount() + '+';
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.testParam = document.getElementById('test-param')?.value.trim() || 'productId';

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-errors')?.checked) this.selectedTests.push('errors');
        if (document.getElementById('test-files')?.checked) this.selectedTests.push('files');
        if (document.getElementById('test-backup')?.checked) this.selectedTests.push('backup');
        if (document.getElementById('test-debug')?.checked) this.selectedTests.push('debug');
        if (document.getElementById('test-headers')?.checked) this.selectedTests.push('headers');
        if (document.getElementById('test-vcs')?.checked) this.selectedTests.push('vcs');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Information disclosure scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'errors') {
                getErrorPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'error',
                        name: 'Error Message Test',
                        path: `?${this.testParam}=${encodeURIComponent(payload.payload)}`,
                        description: payload.description
                    });
                });
            } else if (testType === 'files') {
                getSensitiveFiles().forEach(file => {
                    this.testsToRun.push({
                        type: 'file',
                        name: 'Sensitive File',
                        path: file.path,
                        description: file.description
                    });
                });
            } else if (testType === 'backup') {
                const basePaths = ['/index.php', '/app.py', '/config.json', '/settings.py'];
                basePaths.forEach(base => {
                    getBackupExtensions().slice(0, 4).forEach(ext => {
                        this.testsToRun.push({
                            type: 'backup',
                            name: 'Backup File',
                            path: base + ext.pattern,
                            description: `${base} ${ext.description}`
                        });
                    });
                });
            } else if (testType === 'debug') {
                getDebugParams().forEach(param => {
                    param.values.slice(0, 2).forEach(value => {
                        this.testsToRun.push({
                            type: 'debug',
                            name: 'Debug Parameter',
                            path: `?${param.param}=${value}`,
                            description: `${param.param}=${value}`
                        });
                    });
                });
            } else if (testType === 'headers') {
                this.testsToRun.push({
                    type: 'header',
                    name: 'Response Headers',
                    path: '/',
                    description: 'Check for revealing headers'
                });
            } else if (testType === 'vcs') {
                InfoDisclosurePayloads.versionControl.forEach(vcs => {
                    this.testsToRun.push({
                        type: 'vcs',
                        name: `${vcs.type} Exposure`,
                        path: vcs.path,
                        description: `${vcs.type} repository exposed`
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

            await this.sleep(300);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    async runTest(test) {
        this.updateCurrentTest(test.type.toUpperCase(), test.path);

        try {
            const response = await this.simulateTest(test);

            if (response.vulnerable) {
                this.vulnCount++;
                if (response.critical) this.criticalCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    path: test.path,
                    description: test.description,
                    disclosedData: response.disclosedData,
                    headers: response.headers,
                    severity: response.critical ? 'CRITICAL' : 'HIGH',
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ FOUND: ${test.name} - ${test.path}`, 'success');
            } else {
                this.log(`✗ Not exposed: ${test.path}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            error: [
                { vulnerable: true, critical: true, disclosedData: 'Stack trace with internal paths:\n/var/www/html/app.php:123\nPDO::query() failed: SQLSTATE[42000]' },
                { vulnerable: true, critical: false, disclosedData: 'Warning: Undefined index in /app/index.php' },
                { vulnerable: false }
            ],
            file: [
                { vulnerable: true, critical: true, disclosedData: 'SECRET_KEY=abc123\nDATABASE_URL=mysql://root:password@localhost/db' },
                { vulnerable: false }
            ],
            backup: [
                { vulnerable: true, critical: true, disclosedData: '<?php\n$db_password = "super_secret_123";\n$api_key = "sk-...' },
                { vulnerable: false }
            ],
            debug: [
                { vulnerable: true, critical: true, disclosedData: 'Debug Mode: ON\nSession: {...}\nEnvironment: production\nSecretKey: abc123' },
                { vulnerable: false }
            ],
            header: [
                { vulnerable: true, critical: false, headers: ['Server: Apache/2.4.41', 'X-Powered-By: PHP/7.4.3', 'X-Debug-Token: abc123'] },
                { vulnerable: false }
            ],
            vcs: [
                { vulnerable: true, critical: true, disclosedData: '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:company/app.git' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.error;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'error': ['Reveals internal paths', 'Exposes technology stack', 'Database info leaked'],
            'file': ['Credentials exposed', 'API keys leaked', 'Configuration revealed'],
            'backup': ['Source code exposed', 'Hardcoded secrets', 'Business logic revealed'],
            'debug': ['Session data exposed', 'Internal variables', 'Security tokens'],
            'header': ['Server version exposed', 'Technology fingerprinting', 'Attack surface identified'],
            'vcs': ['Full source code access', 'Commit history', 'Internal documentation']
        };
        return impacts[type] || ['Information exposed'];
    }

    getRemediation(type) {
        const remediations = {
            'error': 'Disable verbose error messages in production. Use custom error pages.',
            'file': 'Remove sensitive files from web root. Use proper access controls.',
            'backup': 'Never store backup files in web root. Configure server to block backup extensions.',
            'debug': 'Disable debug mode in production. Remove debug endpoints.',
            'header': 'Configure server to hide version headers. Remove X-Powered-By.',
            'vcs': 'Block access to .git/.svn directories. Never deploy VCS folders.'
        };
        return remediations[type] || 'Implement proper access controls.';
    }

    updateCurrentTest(type, path) {
        document.getElementById('current-type').textContent = type;
        document.getElementById('current-test-details').textContent = path;
    }

    updateProgress() {
        const progress = (this.currentTestIndex / this.testsToRun.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Testing ${this.currentTestIndex} of ${this.testsToRun.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('critical-count').textContent = this.criticalCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Information disclosure scan completed', 'success');
        this.log(`Info leaks found: ${this.vulnCount} (${this.criticalCount} critical)`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} information leaks`, this.vulnCount > 0 ? 'success' : 'info');
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

            let contentHtml = '';
            if (vuln.disclosedData) {
                contentHtml = `<div class="disclosed-data">${this.escapeHtml(vuln.disclosedData)}</div>`;
            } else if (vuln.headers) {
                contentHtml = `<div class="header-list">${vuln.headers.map(h => `<span class="header-badge">${this.escapeHtml(h)}</span>`).join('')}</div>`;
            }

            // Build impact list
            const impactList = vuln.impact.map(i => `<li>${i}</li>`).join('');

            vulnCard.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span style="color: var(--clr-accent);">#${index + 1}</span> ${vuln.name}
                    </div>
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <span class="leak-type-badge ${vuln.type}">${vuln.type.toUpperCase()}</span>
                <div style="color: #94a3b8; margin: 1rem 0; line-height: 1.6;">
                    <div style="margin-bottom: 0.5rem;">
                        <strong style="color: #e2e8f0;">Path:</strong> 
                        <code style="background: rgba(139, 92, 246, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa;">${this.escapeHtml(vuln.path)}</code>
                    </div>
                    <div>${vuln.description}</div>
                </div>
                ${contentHtml}
                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
                    <div style="margin-bottom: 0.75rem;">
                        <strong style="color: #f87171;">Potential Impact:</strong>
                        <ul style="margin: 0.5rem 0 0 1.25rem; color: #94a3b8; line-height: 1.8;">
                            ${impactList}
                        </ul>
                    </div>
                    <div>
                        <strong style="color: #34d399;">Remediation:</strong>
                        <p style="margin: 0.5rem 0 0 0; color: #94a3b8;">${vuln.remediation}</p>
                    </div>
                </div>
            `;
            vulnList.appendChild(vulnCard);
        });

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async exportPDF() {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            // Header
            doc.setFillColor(15, 23, 42);
            doc.rect(0, 0, 210, 40, 'F');

            doc.setTextColor(255, 255, 255);
            doc.setFontSize(22);
            doc.setFont('helvetica', 'bold');
            doc.text('INFORMATION DISCLOSURE REPORT', 105, 18, { align: 'center' });

            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.text('CyberSec Suite Security Assessment', 105, 28, { align: 'center' });
            doc.text(`Generated: ${new Date().toLocaleString()}`, 105, 35, { align: 'center' });

            // Summary section
            let y = 50;
            doc.setTextColor(30, 41, 59);
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.text('SCAN SUMMARY', 20, y);

            y += 10;
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.text(`Target URL: ${this.targetUrl}`, 20, y);
            y += 7;
            doc.text(`Total Information Leaks Found: ${this.vulnCount}`, 20, y);
            y += 7;
            doc.text(`Critical Findings: ${this.criticalCount}`, 20, y);
            y += 7;
            doc.text(`Tests Executed: ${this.testedCount}`, 20, y);

            // Draw summary box
            doc.setDrawColor(59, 130, 246);
            doc.setLineWidth(0.5);
            doc.rect(15, 45, 180, 30);

            // Vulnerabilities section
            y += 15;
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.text('DISCOVERED INFORMATION LEAKS', 20, y);
            y += 5;

            // Draw line
            doc.setDrawColor(100, 116, 139);
            doc.line(20, y, 190, y);
            y += 10;

            // List each vulnerability
            this.vulnerabilities.forEach((vuln, index) => {
                // Check if we need a new page
                if (y > 260) {
                    doc.addPage();
                    y = 20;
                }

                // Severity color
                if (vuln.severity === 'CRITICAL') {
                    doc.setFillColor(239, 68, 68);
                } else if (vuln.severity === 'HIGH') {
                    doc.setFillColor(249, 115, 22);
                } else {
                    doc.setFillColor(234, 179, 8);
                }

                // Severity badge
                doc.roundedRect(20, y - 4, 20, 7, 1, 1, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(7);
                doc.setFont('helvetica', 'bold');
                doc.text(vuln.severity, 30, y, { align: 'center' });

                // Title
                doc.setTextColor(30, 41, 59);
                doc.setFontSize(11);
                doc.setFont('helvetica', 'bold');
                doc.text(`#${index + 1} - ${vuln.name}`, 45, y);
                y += 8;

                // Path
                doc.setFontSize(9);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(71, 85, 105);
                doc.text(`Path: ${vuln.path}`, 25, y);
                y += 6;

                // Description
                doc.text(`Description: ${vuln.description}`, 25, y);
                y += 6;

                // Disclosed data
                if (vuln.disclosedData) {
                    doc.setFont('helvetica', 'bold');
                    doc.text('Disclosed Data:', 25, y);
                    y += 5;
                    doc.setFont('courier', 'normal');
                    doc.setFontSize(8);
                    doc.setTextColor(239, 68, 68);

                    const dataLines = vuln.disclosedData.split('\n').slice(0, 4);
                    dataLines.forEach(line => {
                        if (y > 270) { doc.addPage(); y = 20; }
                        doc.text(line.substring(0, 80), 25, y);
                        y += 4;
                    });
                    y += 2;
                }

                // Headers
                if (vuln.headers && vuln.headers.length > 0) {
                    doc.setFont('helvetica', 'bold');
                    doc.setFontSize(9);
                    doc.setTextColor(71, 85, 105);
                    doc.text('Exposed Headers:', 25, y);
                    y += 5;
                    doc.setFont('courier', 'normal');
                    doc.setFontSize(8);
                    doc.setTextColor(249, 115, 22);
                    vuln.headers.forEach(header => {
                        doc.text(`  ${header}`, 25, y);
                        y += 4;
                    });
                    y += 2;
                }

                // Remediation
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(9);
                doc.setTextColor(16, 185, 129);
                doc.text('Remediation:', 25, y);
                y += 5;
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(71, 85, 105);

                const remLines = doc.splitTextToSize(vuln.remediation, 160);
                remLines.forEach(line => {
                    doc.text(line, 25, y);
                    y += 4;
                });

                y += 8;

                // Separator line
                doc.setDrawColor(226, 232, 240);
                doc.line(25, y - 4, 185, y - 4);
            });

            // Footer on last page
            const pageCount = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(148, 163, 184);
                doc.text(`CyberSec Suite | Page ${i} of ${pageCount}`, 105, 290, { align: 'center' });
            }

            doc.save(`info-disclosure-report-${Date.now()}.pdf`);
            this.showNotification('PDF Report exported successfully!', 'success');
        } catch (error) {
            console.error('PDF Export error:', error);
            this.showNotification('Export failed: ' + error.message, 'error');
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
    const scanner = new InfoDisclosureScanner();
    scanner.init();
    console.log('🔍 CyberSec Suite Information Disclosure Scanner initialized');
});
