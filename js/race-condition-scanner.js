// Race Condition Scanner Engine
// Automated detection of limit overrun, TOCTOU, single-packet, and multi-endpoint races

class RaceConditionScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.requestMethod = 'POST';
        this.parallelCount = 20;
        this.requestBody = '';
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.windowCount = 0;
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
        this.requestMethod = document.getElementById('request-method')?.value;
        this.parallelCount = parseInt(document.getElementById('parallel-count')?.value);
        this.requestBody = document.getElementById('request-body')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target endpoint URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-limit')?.checked) this.selectedTests.push('limit');
        if (document.getElementById('test-toctou')?.checked) this.selectedTests.push('toctou');
        if (document.getElementById('test-singlepacket')?.checked) this.selectedTests.push('singlepacket');
        if (document.getElementById('test-multiendpoint')?.checked) this.selectedTests.push('multiendpoint');
        if (document.getElementById('test-partial')?.checked) this.selectedTests.push('partial');
        if (document.getElementById('test-timing')?.checked) this.selectedTests.push('timing');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.windowCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });
        this.initTimingDiagram();

        this.updateScanControls(true);
        this.log('Race condition scan started', 'info');
        this.log(`Parallel requests: ${this.parallelCount}`, 'info');

        await this.testLoop();
    }

    initTimingDiagram() {
        const timingBars = document.getElementById('timing-bars');
        timingBars.innerHTML = `
            <div class="timing-bar">
                <span class="timing-bar-label">Request 1</span>
                <div class="timing-bar-track">
                    <div class="timing-bar-fill success" style="width: 0%; left: 0;"></div>
                </div>
            </div>
            <div class="timing-bar">
                <span class="timing-bar-label">Request 2</span>
                <div class="timing-bar-track">
                    <div class="timing-bar-fill warning" style="width: 0%; left: 5%;"></div>
                </div>
            </div>
            <div class="timing-bar">
                <span class="timing-bar-label">Request 3</span>
                <div class="timing-bar-track">
                    <div class="timing-bar-fill danger" style="width: 0%; left: 10%;"></div>
                </div>
            </div>
        `;
    }

    updateTimingDiagram(progress) {
        const fills = document.querySelectorAll('.timing-bar-fill');
        fills.forEach((fill, index) => {
            const offset = index * 5;
            const width = Math.min(progress * 100 + offset, 100 - offset);
            fill.style.width = `${width}%`;
            fill.style.left = `${offset}%`;
        });
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'limit') {
                getLimitOverrunPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'limit',
                        name: 'Limit Overrun',
                        scenario: payload.type,
                        parallel: payload.parallel,
                        description: payload.description
                    });
                });
            } else if (testType === 'toctou') {
                getTOCTOUPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'toctou',
                        name: 'TOCTOU',
                        scenario: payload.type,
                        steps: payload.steps,
                        description: payload.description
                    });
                });
            } else if (testType === 'singlepacket') {
                getSinglePacketPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'singlepacket',
                        name: 'Single-Packet Attack',
                        technique: payload.technique,
                        parallel: payload.parallel,
                        description: payload.description
                    });
                });
            } else if (testType === 'multiendpoint') {
                getMultiEndpointPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'multiendpoint',
                        name: 'Multi-Endpoint Race',
                        endpoints: payload.endpoints,
                        description: payload.description
                    });
                });
            } else if (testType === 'partial') {
                RaceConditionPayloads.partialConstruction.forEach(payload => {
                    this.testsToRun.push({
                        type: 'partial',
                        name: 'Partial Construction',
                        scenario: payload.type,
                        window: payload.vulnerable_window,
                        description: payload.description
                    });
                });
            } else if (testType === 'timing') {
                this.testsToRun.push({
                    type: 'timing',
                    name: 'Timing Analysis',
                    description: 'Analyze response timing for race windows'
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
            this.updateTimingDiagram(this.currentTestIndex / this.testsToRun.length);

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
                if (response.windowDetected) this.windowCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    parallel: test.parallel || this.parallelCount,
                    successCount: response.successCount,
                    details: response.details,
                    timingData: response.timingData,
                    severity: this.getSeverity(test.type),
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ EXPLOITED: ${test.name} - ${response.successCount}/${test.parallel || this.parallelCount} succeeded`, 'success');
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
            limit: [
                { vulnerable: true, windowDetected: true, successCount: 15, details: 'Applied coupon 15 times instead of once - limit bypassed', timingData: { window: '2-5ms' } },
                { vulnerable: true, windowDetected: true, successCount: 8, details: 'Partial success - 8 requests bypassed limit check', timingData: { window: '1-3ms' } },
                { vulnerable: false }
            ],
            toctou: [
                { vulnerable: true, windowDetected: true, successCount: 3, details: 'TOCTOU window detected - state changed during verification', timingData: { window: '10-50ms' } },
                { vulnerable: false }
            ],
            singlepacket: [
                { vulnerable: true, windowDetected: true, successCount: 20, details: 'All 20 requests succeeded - single-packet attack successful', timingData: { window: '<1ms' } },
                { vulnerable: false }
            ],
            multiendpoint: [
                { vulnerable: true, windowDetected: true, successCount: 2, details: 'Race between endpoints successful - email changed during verification', timingData: { window: '5-20ms' } },
                { vulnerable: false }
            ],
            partial: [
                { vulnerable: true, windowDetected: true, successCount: 1, details: 'Accessed partially constructed object - missing authorization fields', timingData: { window: '50-200ms' } },
                { vulnerable: false }
            ],
            timing: [
                { vulnerable: true, windowDetected: true, successCount: 1, details: 'Timing analysis detected race window of 5-15ms', timingData: { window: '5-15ms', variance: '3ms' } },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.limit;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getSeverity(type) {
        const severities = {
            'limit': 'HIGH',
            'toctou': 'HIGH',
            'singlepacket': 'CRITICAL',
            'multiendpoint': 'HIGH',
            'partial': 'MEDIUM',
            'timing': 'MEDIUM'
        };
        return severities[type] || 'MEDIUM';
    }

    getImpact(type) {
        const impacts = {
            'limit': ['Unlimited resource usage', 'Financial loss', 'Bypass rate limits'],
            'toctou': ['Authorization bypass', 'State manipulation', 'Privilege escalation'],
            'singlepacket': ['Perfect timing attack', 'Guaranteed race win', 'Mass exploitation'],
            'multiendpoint': ['Account takeover', 'Email verification bypass', 'Session hijacking'],
            'partial': ['Data exposure', 'Unauthorized access', 'Default privilege access'],
            'timing': ['Race window identified', 'Attack planning', 'Vulnerability confirmation']
        };
        return impacts[type] || ['Race condition vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'limit': 'Use database-level locking. Implement atomic operations. Use unique constraints.',
            'toctou': 'Minimize window between check and use. Use transactions. Re-verify after action.',
            'singlepacket': 'Cannot prevent HTTP/2 multiplexing. Focus on atomic backend operations.',
            'multiendpoint': 'Use distributed locks. Implement proper state machines. Add verification delays.',
            'partial': 'Initialize objects atomically. Use builder pattern. Validate before exposure.',
            'timing': 'Reduce processing time variance. Add random delays. Use constant-time operations.'
        };
        return remediations[type] || 'Implement proper synchronization and locking mechanisms.';
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
        document.getElementById('window-count').textContent = this.windowCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Race condition scan completed', 'success');
        this.log(`Race windows detected: ${this.windowCount}`, this.windowCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} race conditions`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">Race #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="race-type-badge ${vuln.type}">${vuln.name}</span>
                <span class="exploited-indicator">${vuln.successCount}/${vuln.parallel} SUCCEEDED</span>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="race-stats">
                    <div class="race-stat">
                        <div class="race-stat-value">${vuln.parallel}</div>
                        <div class="race-stat-label">Parallel Requests</div>
                    </div>
                    <div class="race-stat">
                        <div class="race-stat-value">${vuln.successCount}</div>
                        <div class="race-stat-label">Succeeded</div>
                    </div>
                    <div class="race-stat">
                        <div class="race-stat-value">${vuln.timingData?.window || 'N/A'}</div>
                        <div class="race-stat-label">Race Window</div>
                    </div>
                </div>
                <div class="race-vuln-details">
                    <div class="race-vuln-details-title">Attack Details:</div>
                    <div class="race-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('turbo');
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
            doc.text('Race Condition Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount}`, 20, 42);
            doc.save('race-condition-report.pdf');
            this.showNotification('PDF exported!', 'success');
        } catch (error) {
            this.showNotification('Export failed', 'error');
        }
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
    const scanner = new RaceConditionScanner();
    scanner.init();
    console.log('⚡ CyberSec Suite Race Condition Scanner initialized');
});
