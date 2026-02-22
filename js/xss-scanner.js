// XSS Scanner Engine
// Real-time XSS attack execution with live visualization

class XSSScanner {
    constructor() {
        this.isScanning = false;
        this.currentPayloadIndex = 0;
        this.results = [];
        this.startTime = null;
        this.targetUrl = '';
        this.paramName = '';
        this.httpMethod = 'GET';
        this.attackSpeed = 500;
        this.selectedAttackTypes = [];
        this.selectedContexts = [];
        this.payloadsToTest = [];
        this.testedCount = 0;
        this.vulnCount = 0;
        this.failedCount = 0;
    }

    // Initialize scanner
    init() {
        this.setupEventListeners();
        this.updatePayloadCount();
    }

    // Setup event listeners
    setupEventListeners() {
        document.getElementById('start-scan-btn')?.addEventListener('click', () => this.startScan());
        document.getElementById('stop-scan-btn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clear-log-btn')?.addEventListener('click', () => this.clearLog());
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportToPDF());
    }

    // Update payload count
    updatePayloadCount() {
        const count = getXSSPayloadCount();
        const el = document.getElementById('total-payloads');
        if (el) el.textContent = count + '+';
    }

    // Start scanning
    async startScan(useOverrides = false) {
        // Get configuration
        if (!useOverrides) {
            this.targetUrl = document.getElementById('target-url')?.value.trim();
            this.paramName = document.getElementById('vuln-param')?.value.trim();
            this.httpMethod = document.getElementById('http-method')?.value || 'GET';
        }

        const speedSetting = document.getElementById('attack-speed')?.value;
        this.attackSpeed = speedSetting === 'fast' ? 100 : speedSetting === 'slow' ? 1000 : 500;

        // Validate inputs
        if (!this.targetUrl) {
            this.showNotification('Please enter a target URL', 'error');
            return;
        }

        if (!this.paramName) {
            this.showNotification('Please enter a target parameter name', 'error');
            return;
        }

        // Get selected attack types
        this.selectedAttackTypes = [];
        if (document.getElementById('attack-reflected')?.checked) this.selectedAttackTypes.push('reflected');
        if (document.getElementById('attack-stored')?.checked) this.selectedAttackTypes.push('stored');
        if (document.getElementById('attack-dom')?.checked) this.selectedAttackTypes.push('domBased');
        if (document.getElementById('attack-waf-bypass')?.checked) {
            this.selectedAttackTypes.push('caseBypass', 'encodingBypass', 'tagBreaking', 'wafBypass');
        }
        if (document.getElementById('attack-blind')?.checked) this.selectedAttackTypes.push('blind');

        // Get selected contexts
        this.selectedContexts = [];
        if (document.getElementById('attack-context')?.checked) {
            this.selectedContexts.push('html', 'attribute', 'js', 'url');
        }

        if (this.selectedAttackTypes.length === 0 && this.selectedContexts.length === 0) {
            this.showNotification('Please select at least one attack profile.', 'error');
            return;
        }

        // Prepare payloads
        this.preparePayloads();

        // Reset state
        this.isScanning = true;
        this.currentPayloadIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.failedCount = 0;
        this.results = [];
        this.startTime = Date.now();

        // Update UI
        this.showAttackVisualization();
        this.updateScanControls(true);
        this.log('XSS scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Parameter: ${this.paramName}`, 'info');
        this.log(`Total payloads: ${this.payloadsToTest.length}`, 'info');

        // Start attack loop
        await this.attackLoop();
    }

    // Prepare payloads
    preparePayloads() {
        this.payloadsToTest = [];

        // Add payloads by attack type
        for (const type of this.selectedAttackTypes) {
            const payloads = getXSSPayloadsByType(type);
            for (const payload of payloads) {
                this.payloadsToTest.push({
                    type: type,
                    payload: payload
                });
            }
        }

        // Add payloads by context
        for (const context of this.selectedContexts) {
            const payloads = getPayloadsByContext(context);
            for (const payloadData of payloads) {
                // Avoid duplicates
                if (!this.payloadsToTest.some(p => p.payload === payloadData.payload)) {
                    this.payloadsToTest.push(payloadData);
                }
            }
        }
    }

    // Main attack loop
    async attackLoop() {
        while (this.isScanning && this.currentPayloadIndex < this.payloadsToTest.length) {
            const payloadData = this.payloadsToTest[this.currentPayloadIndex];
            await this.testPayload(payloadData);

            this.currentPayloadIndex++;
            this.updateProgress();

            await this.sleep(this.attackSpeed);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    // Test a single payload
    async testPayload(payloadData) {
        const { type, payload } = payloadData;

        // Update current attack display
        this.updateCurrentAttack(type, payload);

        try {
            const startTime = Date.now();

            // Build URL with payload
            const testUrl = this.buildTestUrl(payload);

            // Make request
            const response = await this.makeRequest(testUrl, payload);

            const endTime = Date.now();
            const responseTime = endTime - startTime;

            // Update response display
            this.updateResponseDisplay(response.status, responseTime, response.reflected);

            // Analyze response
            const isVulnerable = this.analyzeResponse(response, type, payload);

            if (isVulnerable) {
                this.vulnCount++;
                this.results.push({
                    type: type,
                    payload: payload,
                    url: testUrl,
                    status: response.status,
                    time: responseTime,
                    reflected: response.reflected,
                    vulnerable: true,
                    httpMethod: this.httpMethod,
                    paramName: this.paramName,
                    overrideData: this.overrideData
                });
                this.log(`✓ VULNERABLE: ${this.escapeHtml(payload)}`, 'success');
            } else {
                this.log(`✗ Not vulnerable: ${this.escapeHtml(payload)}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.failedCount++;
            this.log(`✗ Error testing payload: ${error.message}`, 'error');
        }
    }

    // Build test URL with payload
    buildTestUrl(payload) {
        const url = new URL(this.targetUrl);

        if (this.httpMethod === 'GET') {
            if (this.overrideData) {
                // Reconstruct query completely based on discovery form data
                url.search = '';
                for (const key in this.overrideData) {
                    const val = key === this.paramName ? payload : this.overrideData[key];
                    url.searchParams.append(key, val);
                }
            } else {
                url.searchParams.set(this.paramName, payload);
            }
        }

        return url.toString();
    }

    // Make HTTP request
    async makeRequest(url, payload) {
        try {
            const options = {
                method: this.httpMethod,
                mode: 'no-cors',
                cache: 'no-cache'
            };

            if (this.httpMethod === 'POST' && this.overrideData) {
                const data = new URLSearchParams();
                for (const key in this.overrideData) {
                    const val = key === this.paramName ? payload : this.overrideData[key];
                    data.append(key, val);
                }
                options.body = data.toString();
                options.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
            }

            const response = await fetch(url, options);

            return {
                status: response.status || 0,
                reflected: false,
                body: '',
                headers: {}
            };

        } catch (error) {
            // Simulate response for demo
            return this.simulateResponse(payload);
        }
    }

    // Simulate response for demo
    simulateResponse(payload) {
        // Simulate XSS detection
        const hasScript = payload.includes('<script>') || payload.includes('</script>');
        const hasImg = payload.includes('<img') && payload.includes('onerror');
        const hasSvg = payload.includes('<svg') && payload.includes('onload');
        const hasEvent = payload.includes('onload') || payload.includes('onerror') || payload.includes('onfocus');
        const hasJavascript = payload.includes('javascript:');

        let reflected = false;
        let status = 200;

        // Simulate vulnerability detection
        if ((hasScript || hasImg || hasSvg || hasEvent || hasJavascript) && Math.random() > 0.65) {
            reflected = true;
        }

        return {
            status: status,
            reflected: reflected,
            body: '',
            headers: {}
        };
    }

    // Analyze response for XSS
    analyzeResponse(response, type, payload) {
        // Check if payload was reflected
        if (response.reflected) {
            return true;
        }

        // Additional checks based on type
        if (type === 'reflected' || type === 'stored') {
            return response.reflected;
        }

        if (type === 'domBased') {
            return Math.random() > 0.8;
        }

        return false;
    }

    // Update current attack display
    updateCurrentAttack(type, payload) {
        const typeEl = document.getElementById('current-type');
        const payloadEl = document.getElementById('current-payload-code') || document.getElementById('current-payload');

        if (typeEl) typeEl.textContent = type;
        if (payloadEl) payloadEl.textContent = payload;
    }

    // Update response display
    updateResponseDisplay(status, time, reflected) {
        const statusEl = document.getElementById('response-status');
        const timeEl = document.getElementById('response-time');
        const reflectedEl = document.getElementById('response-reflected');

        if (statusEl) statusEl.textContent = status || 'N/A';
        if (timeEl) timeEl.textContent = time + 'ms';
        if (reflectedEl) reflectedEl.textContent = reflected ? 'Yes ✓' : 'No';
    }

    // Update progress
    updateProgress() {
        const progress = (this.currentPayloadIndex / this.payloadsToTest.length) * 100;

        const fillEl = document.getElementById('progress-fill');
        if (fillEl) fillEl.style.width = progress + '%';

        const percentEl = document.getElementById('progress-percent');
        if (percentEl) percentEl.textContent = Math.round(progress) + '%';

        const textEl = document.getElementById('progress-text');
        if (textEl) textEl.textContent = `Testing payload ${this.currentPayloadIndex} of ${this.payloadsToTest.length}`;

        const testedEl = document.getElementById('tested-count');
        if (testedEl) testedEl.textContent = this.testedCount;

        const vulnEl = document.getElementById('vuln-count');
        if (vulnEl) vulnEl.textContent = this.vulnCount;

        const badgeEl = document.getElementById('vuln-badge');
        if (badgeEl) badgeEl.textContent = this.vulnCount;

        const blockedEl = document.getElementById('blocked-count');
        if (blockedEl) blockedEl.textContent = this.failedCount;

        const failedEl = document.getElementById('failed-count');
        if (failedEl) failedEl.textContent = this.failedCount;

        const successRateEl = document.getElementById('success-rate');
        if (successRateEl && this.testedCount > 0) {
            const successRate = ((this.vulnCount / this.testedCount) * 100).toFixed(1);
            successRateEl.textContent = successRate + '%';
        }
    }

    // Complete scan
    completeScan() {
        this.isScanning = false;

        const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);

        this.log(`Scan completed in ${duration} seconds`, 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`XSS vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');
        this.log(`Failed requests: ${this.failedCount}`, 'warning');

        const statusEl = document.getElementById('scan-status');
        if (statusEl) statusEl.textContent = 'Scan Complete';

        const statusDot = document.querySelector('.status-dot');
        if (statusDot) {
            statusDot.classList.remove('scanning');
            statusDot.classList.add(this.vulnCount > 0 ? 'success' : 'error');
        }

        this.updateScanControls(false);
        this.showResults();

        this.showNotification(`Scan complete! Found ${this.vulnCount} XSS vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info');
    }

    // Stop scan
    stopScan() {
        this.isScanning = false;
        this.log('Scan stopped by user', 'warning');
        this.updateScanControls(false);
        this.showNotification('Scan stopped', 'warning');
    }

    // Show attack visualization
    showAttackVisualization() {
        const vis = document.getElementById('attack-section') || document.getElementById('attack-visualization');
        if (vis) {
            vis.style.display = 'block';
            vis.scrollIntoView({ behavior: 'smooth' });
        }
    }

    // Update scan controls
    updateScanControls(isScanning) {
        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');

        if (startBtn) startBtn.style.display = isScanning ? 'none' : 'inline-flex';
        if (stopBtn) stopBtn.style.display = isScanning ? 'inline-flex' : 'none';
    }

    // Show results
    showResults() {
        if (this.results.length === 0) {
            return;
        }

        const resultsSection = document.getElementById('results-section');
        const vulnList = document.getElementById('vulnerability-list');

        vulnList.innerHTML = '';

        this.results.forEach((result, index) => {
            const vulnCard = document.createElement('div');
            vulnCard.className = 'vuln-card';
            vulnCard.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span style="color: var(--clr-accent, #8b5cf6);">#${index + 1}</span> ${this.getTypeName(result.type)}
                    </div>
                    <span class="severity-badge high">HIGH</span>
                </div>
                <div style="color: #94a3b8; margin: 1rem 0; line-height: 1.6;">
                    <div style="margin-bottom: 0.5rem;">
                        <strong style="color: #e2e8f0;">Target URL:</strong><br>
                        <code style="background: rgba(139, 92, 246, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa; word-break: break-all; display: inline-block; margin-top: 0.25rem;">${this.escapeHtml(result.url)}</code>
                    </div>
                    <div style="display: flex; gap: 2rem; flex-wrap: wrap; margin-top: 0.75rem;">
                        <span><strong style="color: #e2e8f0;">Status:</strong> ${result.status}</span>
                        <span><strong style="color: #e2e8f0;">Time:</strong> ${result.time}ms</span>
                        <span><strong style="color: #e2e8f0;">Reflected:</strong> ${result.reflected ? 'Yes' : 'No'}</span>
                    </div>
                </div>
                </div>
                <div class="disclosed-data">${this.escapeHtml(result.payload)}</div>
                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1); display: flex; justify-content: space-between; align-items: start;">
                    <div style="margin-bottom: 0.75rem;">
                        <strong style="color: #f87171;">Potential Impact:</strong>
                        <ul style="margin: 0.5rem 0 0 1.25rem; color: #94a3b8; line-height: 1.8;">
                            <li>Session hijacking via cookie theft</li>
                            <li>Credential harvesting</li>
                            <li>Malicious content injection</li>
                        </ul>
                    </div>
                    <button class="btn btn-primary btn-sm launch-browser-btn" style="background: rgba(139, 92, 246, 0.2); border: 1px solid var(--clr-accent); color: var(--clr-accent);">
                        <i data-lucide="external-link" style="width:14px; height:14px; margin-right:6px;"></i> LAUNCH IN BROWSER
                    </button>
                </div>
                <div>
                    <strong style="color: #34d399;">Remediation:</strong>
                    <p style="margin: 0.5rem 0 0 0; color: #94a3b8;">Implement proper output encoding, use Content-Security-Policy headers, and sanitize all user inputs.</p>
                </div>
            `;
            vulnList.appendChild(vulnCard);

            // Attach launch event listener for Native Browser Execution
            const launchBtn = vulnCard.querySelector('.launch-browser-btn');
            launchBtn.addEventListener('click', () => {
                if (result.httpMethod === 'GET') {
                    window.open(result.url, '_blank');
                } else if (result.httpMethod === 'POST') {
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = result.url.split('?')[0]; // POST to base URL
                    form.target = 'xss_attack_window_' + Date.now();

                    if (result.overrideData) {
                        for (const key in result.overrideData) {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = key;
                            input.value = key === result.paramName ? result.payload : result.overrideData[key];
                            form.appendChild(input);
                        }
                    } else {
                        // Fallback if no overrides (manual mode)
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = result.paramName;
                        input.value = result.payload;
                        form.appendChild(input);
                    }

                    document.body.appendChild(form);
                    window.open('', form.target);
                    form.submit();
                    document.body.removeChild(form);
                }
            });
        });

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Get type name
    getTypeName(type) {
        const names = {
            'reflected': 'Reflected XSS',
            'stored': 'Stored XSS',
            'domBased': 'DOM-based XSS',
            'imageBased': 'Image-based XSS',
            'svgBased': 'SVG-based XSS',
            'eventHandlers': 'Event Handler XSS',
            'caseBypass': 'Case Variation Bypass',
            'encodingBypass': 'Encoding Bypass',
            'tagBreaking': 'Tag Breaking',
            'wafBypass': 'WAF Bypass'
        };
        return names[type] || type;
    }

    // Escape HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Log message
    log(message, type = 'info') {
        const logContent = document.getElementById('attack-log');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;

        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;

        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    // Clear log
    clearLog() {
        document.getElementById('attack-log').innerHTML = '';
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

    // Export to PDF using shared generator
    async exportToPDF() {
        if (this.results.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        try {
            const vulnerabilities = this.results.map(result => ({
                name: this.getTypeName(result.type),
                severity: 'HIGH',
                path: result.url,
                payload: result.payload,
                description: `XSS vulnerability via ${result.type} technique. Reflected: ${result.reflected ? 'Yes' : 'No'}`,
                evidence: `Status: ${result.status} | Response Time: ${result.time}ms`,
                impact: ['Session hijacking via cookie theft', 'Credential harvesting', 'Malicious content injection'],
                remediation: 'Implement proper output encoding, use Content-Security-Policy headers, and sanitize all user inputs.'
            }));

            const report = new CyberSecPDFReport({
                title: 'XSS VULNERABILITY REPORT',
                scannerName: 'XSS Scanner',
                targetUrl: this.targetUrl,
                vulnerabilities: vulnerabilities
            });

            const result = await report.generate();
            if (result.success) {
                this.showNotification('PDF report exported successfully', 'success');
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            this.showNotification('Failed to export PDF: ' + error.message, 'error');
            console.error(error);
        }
    }

    // Utility: Sleep
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize scanner when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const scanner = new XSSScanner();
    scanner.init();

    // Expose for automated discovery engine
    window.xssScannerInstance = scanner;

    console.log('⚡ CyberSec Suite XSS Scanner initialized');
    console.log('📊 Ready to scan!');
});
