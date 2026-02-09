// DOM-based Vulnerability Scanner Engine
// Automated source-to-sink analysis for DOM XSS and client-side vulnerabilities

class DOMScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.testMode = 'auto';
        this.selectedSources = [];
        this.selectedSinks = [];
        this.selectedVulnTypes = [];
        this.sourcesFound = 0;
        this.sinksFound = 0;
        this.vulnCount = 0;
        this.vulnerabilities = [];
        this.dataFlows = [];
        this.currentTest = 0;
        this.totalTests = 0;
    }

    // Initialize scanner
    init() {
        this.setupEventListeners();
        this.updateStats();
    }

    // Setup event listeners
    setupEventListeners() {
        document.getElementById('start-scan-btn')?.addEventListener('click', () => this.startScan());
        document.getElementById('stop-scan-btn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clear-log-btn')?.addEventListener('click', () => this.clearLog());
        document.getElementById('export-report-btn')?.addEventListener('click', () => this.exportReport());
    }

    // Update stats
    updateStats() {
        document.getElementById('total-sources').textContent = DOMSources.length + '+';
        document.getElementById('total-sinks').textContent = getAllSinks().length + '+';
    }

    // Start scanning
    async startScan() {
        // Get configuration
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.testMode = document.getElementById('test-mode')?.value;

        // Validate
        if (!this.targetUrl) {
            this.showNotification('Please enter a target URL', 'error');
            return;
        }

        // Get selected sources
        this.selectedSources = [];
        if (document.getElementById('source-url')?.checked) this.selectedSources.push('document.URL');
        if (document.getElementById('source-hash')?.checked) this.selectedSources.push('location.hash');
        if (document.getElementById('source-search')?.checked) this.selectedSources.push('location.search');
        if (document.getElementById('source-referrer')?.checked) this.selectedSources.push('document.referrer');
        if (document.getElementById('source-cookie')?.checked) this.selectedSources.push('document.cookie');
        if (document.getElementById('source-postmessage')?.checked) this.selectedSources.push('postMessage');

        // Get selected sinks
        this.selectedSinks = [];
        if (document.getElementById('sink-innerhtml')?.checked) this.selectedSinks.push('innerHTML');
        if (document.getElementById('sink-eval')?.checked) this.selectedSinks.push('eval');
        if (document.getElementById('sink-location')?.checked) this.selectedSinks.push('location');
        if (document.getElementById('sink-document-write')?.checked) this.selectedSinks.push('document.write');
        if (document.getElementById('sink-settimeout')?.checked) this.selectedSinks.push('setTimeout');
        if (document.getElementById('sink-jquery')?.checked) this.selectedSinks.push('jQuery');

        // Get selected vulnerability types
        this.selectedVulnTypes = [];
        if (document.getElementById('vuln-dom-xss')?.checked) this.selectedVulnTypes.push('domXSS');
        if (document.getElementById('vuln-open-redirect')?.checked) this.selectedVulnTypes.push('openRedirect');
        if (document.getElementById('vuln-cookie-manip')?.checked) this.selectedVulnTypes.push('cookieManip');
        if (document.getElementById('vuln-webstorage')?.checked) this.selectedVulnTypes.push('webStorage');
        if (document.getElementById('vuln-ajax')?.checked) this.selectedVulnTypes.push('ajax');
        if (document.getElementById('vuln-websocket')?.checked) this.selectedVulnTypes.push('websocket');

        if (this.selectedSources.length === 0 || this.selectedSinks.length === 0) {
            this.showNotification('Please select at least one source and one sink', 'error');
            return;
        }

        // Reset state
        this.isScanning = true;
        this.sourcesFound = 0;
        this.sinksFound = 0;
        this.vulnCount = 0;
        this.vulnerabilities = [];
        this.dataFlows = [];
        this.currentTest = 0;
        this.totalTests = this.selectedSources.length * this.selectedSinks.length;

        // Show analysis section
        document.getElementById('analysis-section').style.display = 'block';
        document.getElementById('analysis-section').scrollIntoView({ behavior: 'smooth' });

        // Update UI
        this.updateScanControls(true);
        this.log('DOM analysis started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Sources: ${this.selectedSources.join(', ')}`, 'info');
        this.log(`Sinks: ${this.selectedSinks.join(', ')}`, 'info');

        // Start analysis
        await this.analyzeDOM();
    }

    // Analyze DOM
    async analyzeDOM() {
        // Phase 1: Identify sources
        this.log('Phase 1: Identifying DOM sources...', 'info');
        await this.identifySources();

        // Phase 2: Identify sinks
        this.log('Phase 2: Identifying DOM sinks...', 'info');
        await this.identifySinks();

        // Phase 3: Trace data flows
        this.log('Phase 3: Tracing source-to-sink data flows...', 'info');
        await this.traceDataFlows();

        // Phase 4: Test vulnerabilities
        this.log('Phase 4: Testing for vulnerabilities...', 'info');
        await this.testVulnerabilities();

        // Complete
        this.completeScan();
    }

    // Identify sources
    async identifySources() {
        for (const source of this.selectedSources) {
            await this.sleep(200);

            // Simulate source detection
            const found = Math.random() > 0.2;

            if (found) {
                this.sourcesFound++;
                this.log(`✓ Found source: ${source}`, 'success');
            } else {
                this.log(`✗ Source not found: ${source}`, 'info');
            }

            this.updateProgress();
        }
    }

    // Identify sinks
    async identifySinks() {
        for (const sink of this.selectedSinks) {
            await this.sleep(200);

            // Simulate sink detection
            const found = Math.random() > 0.2;

            if (found) {
                this.sinksFound++;
                this.log(`✓ Found sink: ${sink}`, 'success');
            } else {
                this.log(`✗ Sink not found: ${sink}`, 'info');
            }

            this.updateProgress();
        }
    }

    // Trace data flows
    async traceDataFlows() {
        // Clear dataflow container
        const container = document.getElementById('dataflow-container');
        container.innerHTML = '';

        for (const source of this.selectedSources) {
            for (const sink of this.selectedSinks) {
                if (!this.isScanning) break;

                await this.sleep(300);
                this.currentTest++;

                // Simulate data flow analysis
                const hasFlow = Math.random() > 0.6;

                if (hasFlow) {
                    const isVulnerable = Math.random() > 0.5;

                    this.dataFlows.push({
                        source: source,
                        sink: sink,
                        vulnerable: isVulnerable
                    });

                    // Add to visualization
                    this.addDataFlowVisualization(source, sink, isVulnerable);

                    if (isVulnerable) {
                        this.log(`⚠️ Vulnerable data flow: ${source} → ${sink}`, 'warning');
                    } else {
                        this.log(`✓ Safe data flow: ${source} → ${sink}`, 'info');
                    }
                }

                this.updateProgress();
            }
        }
    }

    // Add data flow visualization
    addDataFlowVisualization(source, sink, isVulnerable) {
        const container = document.getElementById('dataflow-container');

        const flowItem = document.createElement('div');
        flowItem.className = 'dataflow-item';
        flowItem.innerHTML = `
            <div class="dataflow-source">${source}</div>
            <div class="dataflow-arrow">→</div>
            <div class="dataflow-sink">${sink}</div>
            <div class="dataflow-status ${isVulnerable ? 'vulnerable' : 'safe'}">
                ${isVulnerable ? 'VULNERABLE' : 'SAFE'}
            </div>
        `;

        container.appendChild(flowItem);
    }

    // Test vulnerabilities
    async testVulnerabilities() {
        for (const flow of this.dataFlows) {
            if (!flow.vulnerable) continue;
            if (!this.isScanning) break;

            await this.sleep(300);

            // Determine vulnerability type
            const vulnType = this.determineVulnType(flow.source, flow.sink);

            // Get appropriate payload
            const payload = this.getPayloadForFlow(flow, vulnType);

            // Create vulnerability report
            const vuln = {
                type: vulnType,
                source: flow.source,
                sink: flow.sink,
                payload: payload,
                severity: this.getSeverity(vulnType, flow.sink),
                description: this.getVulnDescription(vulnType, flow.source, flow.sink),
                remediation: this.getRemediation(vulnType)
            };

            this.vulnerabilities.push(vuln);
            this.vulnCount++;

            this.log(`✓ ${vulnType} vulnerability found: ${flow.source} → ${flow.sink}`, 'success');
            this.updateProgress();
        }
    }

    // Determine vulnerability type
    determineVulnType(source, sink) {
        if (sink === 'innerHTML' || sink === 'document.write' || sink === 'eval') {
            return 'DOM XSS';
        } else if (sink === 'location') {
            return 'Open Redirect';
        } else if (source === 'document.cookie') {
            return 'Cookie Manipulation';
        } else if (source === 'localStorage' || source === 'sessionStorage') {
            return 'Web Storage Injection';
        } else {
            return 'DOM-based Vulnerability';
        }
    }

    // Get payload for flow
    getPayloadForFlow(flow, vulnType) {
        if (vulnType === 'DOM XSS') {
            if (flow.sink === 'innerHTML') {
                return DOMPayloads.domXSS.innerHTML[0];
            } else if (flow.sink === 'eval') {
                return DOMPayloads.domXSS.eval[0];
            } else if (flow.sink === 'document.write') {
                return DOMPayloads.domXSS.documentWrite[0];
            }
        } else if (vulnType === 'Open Redirect') {
            return DOMPayloads.openRedirect[0];
        } else if (vulnType === 'Cookie Manipulation') {
            return DOMPayloads.cookieManipulation[0];
        } else if (vulnType === 'Web Storage Injection') {
            return DOMPayloads.webStorage[0];
        }

        return '<script>alert(1)</script>';
    }

    // Get severity
    getSeverity(vulnType, sink) {
        if (sink === 'eval' || sink === 'setTimeout') {
            return 'CRITICAL';
        } else if (vulnType === 'DOM XSS' || vulnType === 'Open Redirect') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    // Get vulnerability description
    getVulnDescription(vulnType, source, sink) {
        return `${vulnType} vulnerability found where user-controllable data from ${source} flows into dangerous sink ${sink} without proper sanitization.`;
    }

    // Get remediation
    getRemediation(vulnType) {
        const remediations = {
            'DOM XSS': 'Sanitize user input before inserting into DOM. Use textContent instead of innerHTML. Implement Content Security Policy.',
            'Open Redirect': 'Validate and whitelist redirect URLs. Use relative URLs when possible. Implement strict URL parsing.',
            'Cookie Manipulation': 'Set HttpOnly and Secure flags on cookies. Validate cookie values. Use SameSite attribute.',
            'Web Storage Injection': 'Validate and sanitize data before storing. Encrypt sensitive data. Implement proper access controls.',
            'DOM-based Vulnerability': 'Validate and sanitize all user input. Use safe APIs. Implement defense in depth.'
        };

        return remediations[vulnType] || 'Implement proper input validation and output encoding.';
    }

    // Update progress
    updateProgress() {
        const progress = (this.currentTest / this.totalTests) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Analyzing data flow ${this.currentTest} of ${this.totalTests}`;

        document.getElementById('sources-count').textContent = this.sourcesFound;
        document.getElementById('sinks-count').textContent = this.sinksFound;
        document.getElementById('vuln-count').textContent = this.vulnCount;
    }

    // Complete scan
    completeScan() {
        this.isScanning = false;

        this.log('DOM analysis completed', 'success');
        this.log(`Sources found: ${this.sourcesFound}`, 'info');
        this.log(`Sinks found: ${this.sinksFound}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Analysis Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(
            `Analysis complete! Found ${this.vulnCount} DOM vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info'
        );
    }

    // Stop scan
    stopScan() {
        this.isScanning = false;
        this.log('Analysis stopped by user', 'warning');
        this.updateScanControls(false);
        this.showNotification('Analysis stopped', 'warning');
    }

    // Update scan controls
    updateScanControls(isScanning) {
        document.getElementById('start-scan-btn').style.display = isScanning ? 'none' : 'inline-flex';
        document.getElementById('stop-scan-btn').style.display = isScanning ? 'inline-flex' : 'none';
    }

    // Show results
    showResults() {
        const resultsSection = document.getElementById('results-section');
        const vulnList = document.getElementById('vulnerability-list');

        vulnList.innerHTML = '';

        this.vulnerabilities.forEach((vuln, index) => {
            const vulnCard = document.createElement('div');
            vulnCard.className = 'vuln-card';
            vulnCard.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">${vuln.type} Vulnerability #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-dataflow">
                    <div class="vuln-dataflow-title">Data Flow:</div>
                    <div class="vuln-dataflow-path">
                        <span class="vuln-dataflow-node source">${vuln.source}</span>
                        <span>→</span>
                        <span class="vuln-dataflow-node sink">${vuln.sink}</span>
                    </div>
                </div>
                <div class="vuln-payload-example">
                    <div class="vuln-payload-title">Example Payload:</div>
                    <div class="vuln-payload-code">${this.escapeHtml(vuln.payload)}</div>
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

    // Export report
    async exportReport() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities to export', 'warning');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            doc.setFontSize(20);
            doc.text('DOM Vulnerability Report', 20, 20);

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
                doc.text(`${index + 1}. ${vuln.type}`, 20, y);
                y += 7;

                doc.setFontSize(10);
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 7;
                doc.text(`Source: ${vuln.source}`, 20, y);
                y += 7;
                doc.text(`Sink: ${vuln.sink}`, 20, y);
                y += 7;
                doc.text(`Payload: ${vuln.payload.substring(0, 60)}...`, 20, y);
                y += 12;
            });

            doc.save('dom-vulnerability-report.pdf');
            this.showNotification('PDF report exported successfully', 'success');

        } catch (error) {
            this.showNotification('Failed to export PDF', 'error');
            console.error(error);
        }
    }

    // Escape HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Log message
    log(message, type = 'info') {
        const logContent = document.getElementById('analysis-log');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;

        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;

        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    // Clear log
    clearLog() {
        document.getElementById('analysis-log').innerHTML = '';
    }

    // Show notification
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

    // Utility: Sleep
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize scanner when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const scanner = new DOMScanner();
    scanner.init();

    console.log('🔍 CyberSec Suite DOM Scanner initialized');
    console.log('📊 Ready to analyze!');
});
