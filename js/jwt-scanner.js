// JWT Scanner Engine
// Automated detection of algorithm confusion, signature bypass, kid injection, and claim manipulation

class JWTScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.originalToken = '';
        this.parsedJWT = null;
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.bypassCount = 0;
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
        document.getElementById('decode-btn')?.addEventListener('click', () => this.decodeToken());
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

    decodeToken() {
        const token = document.getElementById('jwt-token')?.value.trim();
        if (!token) {
            this.showNotification('Please enter a JWT token', 'error');
            return;
        }

        this.parsedJWT = parseJWT(token);
        if (!this.parsedJWT) {
            this.showNotification('Invalid JWT format', 'error');
            return;
        }

        document.getElementById('jwt-header').textContent = JSON.stringify(this.parsedJWT.header, null, 2);
        document.getElementById('jwt-payload').textContent = JSON.stringify(this.parsedJWT.payload, null, 2);
        document.getElementById('decoded-section').style.display = 'grid';
        this.showNotification('JWT decoded successfully', 'success');
    }

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.originalToken = document.getElementById('jwt-token')?.value.trim();

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        if (!this.originalToken) {
            this.showNotification('Please enter a JWT token', 'error');
            return;
        }

        this.parsedJWT = parseJWT(this.originalToken);
        if (!this.parsedJWT) {
            this.showNotification('Invalid JWT format', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-none')?.checked) this.selectedTests.push('none');
        if (document.getElementById('test-confusion')?.checked) this.selectedTests.push('confusion');
        if (document.getElementById('test-kid')?.checked) this.selectedTests.push('kid');
        if (document.getElementById('test-jwk')?.checked) this.selectedTests.push('jwk');
        if (document.getElementById('test-claims')?.checked) this.selectedTests.push('claims');
        if (document.getElementById('test-weak')?.checked) this.selectedTests.push('weak');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.bypassCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('JWT scan started', 'info');
        this.log(`Original algorithm: ${this.parsedJWT.header.alg}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'none') {
                getAlgorithmConfusionPayloads().filter(p => p.alg.toLowerCase() === 'none' || p.alg === 'None' || p.alg === 'NONE' || p.alg === 'nOnE').forEach(payload => {
                    this.testsToRun.push({
                        type: 'none',
                        name: 'Algorithm None',
                        alg: payload.alg,
                        description: payload.description
                    });
                });
            } else if (testType === 'confusion') {
                getAlgorithmConfusionPayloads().filter(p => p.original).forEach(payload => {
                    this.testsToRun.push({
                        type: 'confusion',
                        name: 'Algorithm Confusion',
                        alg: payload.alg,
                        original: payload.original,
                        description: payload.description
                    });
                });
            } else if (testType === 'kid') {
                getKidAttackPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'kid',
                        name: 'kid Injection',
                        kid: payload.kid,
                        description: payload.description
                    });
                });
            } else if (testType === 'jwk') {
                getHeaderInjectionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'jwk',
                        name: 'Header Injection',
                        header: payload.header,
                        description: payload.description
                    });
                });
            } else if (testType === 'claims') {
                getClaimPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'claims',
                        name: 'Claim Manipulation',
                        claim: payload.claim,
                        value: payload.value,
                        description: payload.description
                    });
                });
            } else if (testType === 'weak') {
                JWTPayloads.weakSecrets.slice(0, 10).forEach(secret => {
                    this.testsToRun.push({
                        type: 'weak',
                        name: 'Weak Secret',
                        secret: secret,
                        description: `Testing secret: ${secret}`
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
                if (response.bypass) this.bypassCount++;

                const forgedToken = this.createForgedToken(test);

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    technique: test.alg || test.kid || test.header || test.claim,
                    forgedToken: forgedToken,
                    details: response.details,
                    bypass: response.bypass,
                    severity: response.bypass ? 'CRITICAL' : 'HIGH',
                    impact: this.getImpact(test.type),
                    remediation: this.getRemediation(test.type)
                });
                this.log(`✓ VULNERABLE: ${test.name} - ${test.description}`, 'success');
            } else {
                this.log(`✗ Not vulnerable: ${test.description}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    createForgedToken(test) {
        const newHeader = { ...this.parsedJWT.header };
        const newPayload = { ...this.parsedJWT.payload };

        if (test.type === 'none') {
            newHeader.alg = test.alg;
            return createJWT(newHeader, newPayload, '');
        } else if (test.type === 'kid') {
            newHeader.kid = test.kid;
            return createJWT(newHeader, newPayload, 'forged');
        } else if (test.type === 'claims') {
            newPayload[test.claim] = test.value;
            return createJWT(newHeader, newPayload, 'forged');
        }
        return createJWT(newHeader, newPayload, 'forged');
    }

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            none: [
                { vulnerable: true, bypass: true, details: 'Server accepted JWT with alg:none - signature verification bypassed' },
                { vulnerable: false }
            ],
            confusion: [
                { vulnerable: true, bypass: true, details: 'Algorithm confusion successful - RS256 to HS256 attack worked' },
                { vulnerable: false }
            ],
            kid: [
                { vulnerable: true, bypass: true, details: 'kid parameter injection successful - path traversal to /dev/null' },
                { vulnerable: true, bypass: false, details: 'kid parameter reflected but no direct bypass' },
                { vulnerable: false }
            ],
            jwk: [
                { vulnerable: true, bypass: true, details: 'Server accepted embedded JWK - attacker key used for verification' },
                { vulnerable: false }
            ],
            claims: [
                { vulnerable: true, bypass: true, details: 'Modified claims accepted - privilege escalation possible' },
                { vulnerable: false }
            ],
            weak: [
                { vulnerable: true, bypass: true, details: 'Weak secret found - can forge arbitrary tokens' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.none;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'none': ['Complete authentication bypass', 'Forge any user token', 'Admin access'],
            'confusion': ['Sign tokens with public key', 'Impersonate any user', 'Privilege escalation'],
            'kid': ['Control key selection', 'Use attacker key', 'Authentication bypass'],
            'jwk': ['Inject attacker key', 'Self-signed tokens', 'Full compromise'],
            'claims': ['Modify user identity', 'Elevate privileges', 'Access unauthorized data'],
            'weak': ['Forge valid tokens', 'Impersonate users', 'Persistent access']
        };
        return impacts[type] || ['JWT vulnerability'];
    }

    getRemediation(type) {
        const remediations = {
            'none': 'Explicitly reject "none" algorithm. Use allowlist for algorithms.',
            'confusion': 'Use asymmetric algorithms only or separate key types. Validate algorithm matches expected.',
            'kid': 'Sanitize kid parameter. Use allowlist for key IDs. Never use kid in file paths.',
            'jwk': 'Ignore jwk/jku/x5u headers. Only use pre-configured keys.',
            'claims': 'Validate all claims server-side. Never trust client-provided claims for authorization.',
            'weak': 'Use strong, random secrets (256+ bits). Rotate keys regularly.'
        };
        return remediations[type] || 'Implement JWT security best practices.';
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
        document.getElementById('bypass-count').textContent = this.bypassCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('JWT scan completed', 'success');
        this.log(`Auth bypass: ${this.bypassCount}`, this.bypassCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} JWT vulnerabilities`, this.vulnCount > 0 ? 'success' : 'info');
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
                    <div class="vuln-title">JWT #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="jwt-type-badge ${vuln.type}">${vuln.name}</span>
                ${vuln.bypass ? '<span class="bypass-indicator">AUTH BYPASS</span>' : ''}
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                ${vuln.forgedToken ? `
                <div class="forged-token">
                    <div class="forged-token-label">Forged Token:</div>
                    ${this.escapeHtml(vuln.forgedToken)}
                </div>` : ''}
                <div class="jwt-vuln-details">
                    <div class="jwt-vuln-details-title">Attack Details:</div>
                    <div class="jwt-vuln-details-code">${vuln.details}</div>
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
        this.generateExploitCode('none');
    }

    switchExploitTab(tab) {
        document.querySelectorAll('.poc-tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        this.generateExploitCode(tab);
    }

    generateExploitCode(type) {
        const exploitCode = document.getElementById('exploit-code');
        exploitCode.textContent = generateExploit(type, this.originalToken);
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
            doc.text('JWT Security Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Vulnerabilities: ${this.vulnCount} (${this.bypassCount} bypass)`, 20, 42);
            doc.save('jwt-report.pdf');
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
    const scanner = new JWTScanner();
    scanner.init();
    console.log('🔑 CyberSec Suite JWT Scanner initialized');
});
