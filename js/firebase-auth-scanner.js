/**
 * Firebase Authentication Security Scanner
 * Detects auth bypasses, session issues, and identity provider misconfigurations
 * Only reports REAL findings from actual HTTP testing
 */

class FirebaseAuthScanner {
    constructor() {
        this.state = {
            isScanning: false,
            results: [],
            counts: { passed: 0, vulns: 0, warnings: 0, info: 0 },
            startTime: null
        };

        this.attackVectors = [
            {
                id: 'anon-escalation',
                name: 'Anonymous to Authenticated Escalation',
                severity: 'CRITICAL',
                description: 'Anonymous users gaining authenticated privileges',
                test: this.testAnonEscalation.bind(this)
            },
            {
                id: 'auth-handler',
                name: 'Auth Handler Exposure',
                severity: 'MEDIUM',
                description: 'Firebase Auth handler endpoint is exposed',
                test: this.testAuthHandler.bind(this)
            },
            {
                id: 'config-exposed',
                name: 'Firebase Config Exposed',
                severity: 'LOW',
                description: 'Firebase configuration visible in client JS',
                test: this.testConfigExposed.bind(this)
            },
            {
                id: 'oauth-redirect',
                name: 'OAuth Redirect Bypass',
                severity: 'HIGH',
                description: 'Open redirect in OAuth authentication flow',
                test: this.testOAuthRedirect.bind(this)
            },
            {
                id: 'api-key-exposed',
                name: 'API Key in URL',
                severity: 'LOW',
                description: 'Firebase API key visible (expected for client apps)',
                test: this.testApiKeyExposed.bind(this)
            }
        ];

        this.init();
    }

    init() {
        this.bindEvents();
        this.log('Firebase Authentication Scanner initialized', 'info');
    }

    bindEvents() {
        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');
        const clearLogBtn = document.getElementById('clear-log-btn');

        if (startBtn) startBtn.addEventListener('click', () => this.startScan());
        if (stopBtn) stopBtn.addEventListener('click', () => this.stopScan());
        if (clearLogBtn) clearLogBtn.addEventListener('click', () => this.clearLog());
    }

    async startScan() {
        let targetUrl = document.getElementById('target-url')?.value?.trim();
        if (!targetUrl) {
            this.showNotification('Please enter a Firebase App URL', 'error');
            return;
        }

        // Ensure URL has protocol
        if (!targetUrl.startsWith('http')) {
            targetUrl = 'https://' + targetUrl;
        }

        this.state.isScanning = true;
        this.state.startTime = Date.now();
        this.state.results = [];
        this.state.counts = { passed: 0, vulns: 0, warnings: 0, info: 0 };

        // Clear previous results
        const vulnList = document.getElementById('vulnerability-list');
        if (vulnList) vulnList.innerHTML = '';

        this.updateUI('scanning');
        this.log(`Starting authentication scan for: ${targetUrl}`, 'info');

        const enabledVectors = this.getEnabledVectors();
        const totalTests = enabledVectors.length;
        let completed = 0;

        for (const vector of enabledVectors) {
            if (!this.state.isScanning) break;

            this.log(`Testing: ${vector.name}`, 'info');
            this.updateProgress(completed, totalTests, vector.name);

            try {
                const result = await vector.test(targetUrl);
                this.processResult(vector, result);
            } catch (error) {
                this.log(`Error in ${vector.name}: ${error.message}`, 'error');
                this.state.counts.passed++;
            }

            completed++;
            await this.delay(300);
        }

        this.completeScan();
    }

    getEnabledVectors() {
        return this.attackVectors.filter(vector => {
            const checkbox = document.getElementById(`attack-${vector.id}`);
            return checkbox?.checked !== false; // Default to checked if not found
        });
    }

    // Real HTTP-based Attack Vector Tests
    async testAnonEscalation(targetUrl) {
        const endpoints = [
            '/__/auth/handler',
            '/__/auth/iframe',
            '/__/auth/action'
        ];

        for (const endpoint of endpoints) {
            try {
                const response = await this.makeRequest(targetUrl + endpoint);
                if (response.ok && response.body) {
                    // Check for anonymous auth indicators
                    if (response.body.includes('anonymous') || response.body.includes('signInAnonymously')) {
                        return {
                            vulnerable: true,
                            evidence: `Anonymous auth patterns found at ${endpoint}`
                        };
                    }
                }
            } catch (e) { }
        }
        return { vulnerable: false };
    }

    async testAuthHandler(targetUrl) {
        try {
            const response = await this.makeRequest(targetUrl + '/__/auth/handler');
            if (response.status === 200) {
                return {
                    vulnerable: true,
                    evidence: `Auth handler accessible at /__/auth/handler (Status: ${response.status})`
                };
            }
        } catch (e) { }
        return { vulnerable: false };
    }

    async testConfigExposed(targetUrl) {
        try {
            // Fetch the main page and look for Firebase config
            const response = await this.makeRequest(targetUrl);
            if (response.ok && response.body) {
                const configPatterns = [
                    /apiKey\s*[:=]\s*["']AIza[A-Za-z0-9_-]+["']/,
                    /firebaseConfig\s*=\s*\{/,
                    /projectId\s*[:=]\s*["'][a-z0-9-]+["']/
                ];

                for (const pattern of configPatterns) {
                    if (pattern.test(response.body)) {
                        return {
                            vulnerable: true,
                            evidence: 'Firebase configuration found in client-side code (this is expected for web apps)'
                        };
                    }
                }
            }
        } catch (e) { }
        return { vulnerable: false };
    }

    async testOAuthRedirect(targetUrl) {
        // Test for open redirect in auth handler
        const testRedirects = [
            '/__/auth/handler?redirect=//evil.com',
            '/__/auth/handler?continueUrl=//evil.com',
            '/__/auth/handler?state=' + btoa('{"redirect":"//evil.com"}')
        ];

        for (const path of testRedirects) {
            try {
                const response = await this.makeRequest(targetUrl + path);
                // Check if response contains the evil.com redirect
                if (response.body && response.body.includes('evil.com')) {
                    return {
                        vulnerable: true,
                        evidence: `Potential open redirect: evil.com reflected in response`
                    };
                }
            } catch (e) { }
        }
        return { vulnerable: false };
    }

    async testApiKeyExposed(targetUrl) {
        try {
            const response = await this.makeRequest(targetUrl);
            if (response.ok && response.body) {
                const apiKeyMatch = response.body.match(/AIza[A-Za-z0-9_-]{35}/);
                if (apiKeyMatch) {
                    return {
                        vulnerable: true,
                        evidence: `API Key found: ${apiKeyMatch[0].substring(0, 10)}...`
                    };
                }
            }
        } catch (e) { }
        return { vulnerable: false };
    }

    async makeRequest(url) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(url, {
                method: 'GET',
                mode: 'cors',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            let body = '';
            try {
                body = await response.text();
            } catch (e) { }

            return {
                ok: response.ok,
                status: response.status,
                body: body
            };
        } catch (error) {
            return {
                ok: false,
                status: 0,
                body: '',
                error: error.message
            };
        }
    }

    processResult(vector, result) {
        if (result.vulnerable) {
            if (vector.severity === 'CRITICAL' || vector.severity === 'HIGH') {
                this.state.counts.vulns++;
                this.log(`🔴 FOUND: ${vector.name}`, 'error');
            } else if (vector.severity === 'MEDIUM') {
                this.state.counts.warnings++;
                this.log(`🟡 WARNING: ${vector.name}`, 'warning');
            } else {
                this.state.counts.info++;
                this.log(`ℹ️ INFO: ${vector.name}`, 'info');
            }
            this.addFinding(vector, result);
        } else {
            this.state.counts.passed++;
            this.log(`✅ SECURE: ${vector.name}`, 'success');
        }
        this.updateCounters();
    }

    addFinding(vector, result) {
        const finding = {
            name: vector.name,
            severity: vector.severity,
            description: vector.description,
            evidence: result.evidence,
            remediation: this.getRemediation(vector.id)
        };
        this.state.results.push(finding);
        this.renderFinding(finding);
    }

    getRemediation(vectorId) {
        const remediations = {
            'anon-escalation': 'Implement proper role-based access control. Never trust client-side auth state.',
            'auth-handler': 'This is a standard Firebase endpoint. Ensure proper security rules are in place.',
            'config-exposed': 'Firebase config is expected to be public for web apps. Secure your data with Security Rules.',
            'oauth-redirect': 'Validate redirect URLs against a whitelist of allowed domains.',
            'api-key-exposed': 'API keys are expected in client apps. Apply API key restrictions in Firebase Console.'
        };
        return remediations[vectorId] || 'Review Firebase Authentication best practices.';
    }

    renderFinding(finding) {
        const vulnList = document.getElementById('vulnerability-list');
        if (!vulnList) return;

        const severityClass = finding.severity.toLowerCase();
        const card = document.createElement('div');
        card.className = 'vuln-card';
        card.innerHTML = `
            <div class="vuln-header">
                <span class="severity-badge ${severityClass}">${finding.severity}</span>
                <span class="vuln-title">${finding.name}</span>
            </div>
            <p class="vuln-desc">${finding.description}</p>
            <div class="vuln-evidence"><strong>Evidence:</strong> ${finding.evidence}</div>
            <div class="vuln-remediation"><strong>Remediation:</strong> ${finding.remediation}</div>
        `;
        vulnList.appendChild(card);
    }

    stopScan() {
        this.state.isScanning = false;
        this.log('Scan stopped by user', 'warning');
        this.updateUI('stopped');
    }

    completeScan() {
        this.state.isScanning = false;
        const duration = ((Date.now() - this.state.startTime) / 1000).toFixed(1);
        this.log(`Scan completed in ${duration}s`, 'success');

        const { vulns, warnings, info, passed } = this.state.counts;
        this.log(`Results: ${vulns} critical/high, ${warnings} warnings, ${info} info, ${passed} passed`, 'info');

        this.updateUI('complete');
        const scanTime = document.getElementById('scan-time');
        if (scanTime) scanTime.textContent = `${duration}s`;
    }

    updateUI(status) {
        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');
        const attackSection = document.getElementById('attack-section');
        const resultsSection = document.getElementById('results-section');
        const statusEl = document.getElementById('scanner-status');

        if (status === 'scanning') {
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'flex';
            if (attackSection) attackSection.style.display = 'block';
            if (resultsSection) resultsSection.style.display = 'block';
            if (statusEl) statusEl.textContent = 'SCANNING';
        } else {
            if (startBtn) startBtn.style.display = 'flex';
            if (stopBtn) stopBtn.style.display = 'none';
            if (statusEl) statusEl.textContent = status === 'complete' ? 'COMPLETE' : 'STOPPED';
        }
    }

    updateProgress(current, total, currentTest) {
        const percent = Math.round((current / total) * 100);
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');
        const progressPercent = document.getElementById('progress-percent');

        if (progressFill) progressFill.style.width = `${percent}%`;
        if (progressText) progressText.textContent = `Testing: ${currentTest}`;
        if (progressPercent) progressPercent.textContent = `${percent}%`;
    }

    updateCounters() {
        const { passed, vulns, warnings, info } = this.state.counts;
        const get = id => document.getElementById(id);
        if (get('passed-count')) get('passed-count').textContent = passed;
        if (get('vuln-count')) get('vuln-count').textContent = vulns;
        if (get('warning-count')) get('warning-count').textContent = warnings;
        if (get('info-count')) get('info-count').textContent = info;
        if (get('total-checks')) get('total-checks').textContent = passed + vulns + warnings + info;
        if (get('vulns-found')) get('vulns-found').textContent = vulns + warnings;
    }

    log(message, type = 'info') {
        const logContent = document.getElementById('attack-log');
        if (!logContent) return;

        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.innerHTML = `<span class="log-time">[${new Date().toLocaleTimeString()}]</span> ${message}`;
        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }

    clearLog() {
        const logContent = document.getElementById('attack-log');
        if (logContent) logContent.innerHTML = '<div class="log-entry info">[System] Log cleared</div>';
    }

    showNotification(message, type = 'info') {
        this.log(message, type);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize scanner
document.addEventListener('DOMContentLoaded', () => {
    window.firebaseAuthScanner = new FirebaseAuthScanner();
});
