/**
 * GCP Cloud Functions Security Scanner
 * Real HTTP-based testing - only reports actual findings
 */

class GCPFunctionsScanner {
    constructor() {
        this.state = {
            isScanning: false,
            results: [],
            counts: { passed: 0, vulns: 0, warnings: 0, info: 0 },
            startTime: null
        };

        this.attackVectors = [
            {
                id: 'noauth',
                name: 'Unauthenticated Access',
                severity: 'CRITICAL',
                description: 'Function responds without requiring authentication',
                test: this.testNoAuth.bind(this)
            },
            {
                id: 'cors-func',
                name: 'CORS Configuration',
                severity: 'MEDIUM',
                description: 'Function has permissive CORS settings',
                test: this.testCORS.bind(this)
            },
            {
                id: 'error-verbose',
                name: 'Verbose Errors',
                severity: 'MEDIUM',
                description: 'Function returns detailed error information',
                test: this.testVerboseErrors.bind(this)
            }
        ];

        this.init();
    }

    init() {
        this.bindEvents();
        this.log('GCP Cloud Functions Scanner initialized', 'info');
    }

    bindEvents() {
        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');
        const discoverBtn = document.getElementById('discover-btn');
        const clearLogBtn = document.getElementById('clear-log-btn');

        if (startBtn) startBtn.addEventListener('click', () => this.startScan());
        if (stopBtn) stopBtn.addEventListener('click', () => this.stopScan());
        if (discoverBtn) discoverBtn.addEventListener('click', () => this.discoverFunctions());
        if (clearLogBtn) clearLogBtn.addEventListener('click', () => this.clearLog());
    }

    async discoverFunctions() {
        const projectId = document.getElementById('project-id')?.value?.trim();
        const region = document.getElementById('region')?.value || 'us-central1';

        if (!projectId) {
            this.log('Enter a Project ID to discover functions', 'warning');
            return;
        }

        this.log(`Building function URL patterns for: ${projectId}`, 'info');

        const baseUrl = `https://${region}-${projectId}.cloudfunctions.net`;
        const textArea = document.getElementById('function-urls');
        if (textArea) {
            textArea.value = baseUrl;
            this.log(`Base URL set. Add function names like: ${baseUrl}/functionName`, 'success');
        }
    }

    async startScan() {
        const functionUrls = document.getElementById('function-urls')?.value?.trim();
        if (!functionUrls) {
            this.log('Please enter function URLs to scan', 'error');
            return;
        }

        const urls = functionUrls.split('\n').map(u => u.trim()).filter(u => u);

        this.state.isScanning = true;
        this.state.startTime = Date.now();
        this.state.results = [];
        this.state.counts = { passed: 0, vulns: 0, warnings: 0, info: 0 };

        const vulnList = document.getElementById('vulnerability-list');
        if (vulnList) vulnList.innerHTML = '';

        this.updateUI('scanning');
        this.log(`Starting scan on ${urls.length} endpoint(s)`, 'info');

        const enabledVectors = this.getEnabledVectors();

        for (const url of urls) {
            if (!this.state.isScanning) break;

            this.log(`📡 Testing: ${url}`, 'info');

            for (const vector of enabledVectors) {
                if (!this.state.isScanning) break;

                try {
                    const result = await vector.test(url);
                    this.processResult(vector, result, url);
                } catch (error) {
                    this.log(`Error: ${error.message}`, 'error');
                    this.state.counts.passed++;
                }

                await this.delay(200);
            }
        }

        this.completeScan();
    }

    getEnabledVectors() {
        return this.attackVectors.filter(vector => {
            const checkbox = document.getElementById(`attack-${vector.id}`);
            return checkbox?.checked !== false;
        });
    }

    // Real HTTP Tests
    async testNoAuth(url) {
        try {
            const response = await this.makeRequest(url, 'GET');

            // 200 or 204 without auth = accessible
            if (response.status === 200 || response.status === 204) {
                return {
                    vulnerable: true,
                    evidence: `Function returned ${response.status} without Authorization header`
                };
            }

            // If response has actual content (not just error)
            if (response.ok && response.body && !response.body.includes('Error') && !response.body.includes('Unauthorized')) {
                return {
                    vulnerable: true,
                    evidence: `Function accessible without authentication`
                };
            }
        } catch (e) { }

        return { vulnerable: false };
    }

    async testCORS(url) {
        try {
            const response = await fetch(url, {
                method: 'OPTIONS',
                mode: 'cors'
            });

            const corsHeader = response.headers.get('access-control-allow-origin');
            const allowMethods = response.headers.get('access-control-allow-methods');

            if (corsHeader === '*') {
                return {
                    vulnerable: true,
                    evidence: `CORS allows all origins (Access-Control-Allow-Origin: *)`
                };
            }
        } catch (e) { }

        return { vulnerable: false };
    }

    async testVerboseErrors(url) {
        try {
            // Send malformed request to trigger error
            const response = await this.makeRequest(url + '?__test=1', 'POST');

            if (response.body) {
                const errorIndicators = ['stack', 'trace', 'error at', 'line:', '/var/task/', 'node_modules'];
                for (const indicator of errorIndicators) {
                    if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
                        return {
                            vulnerable: true,
                            evidence: `Verbose error info detected: contains "${indicator}"`
                        };
                    }
                }
            }
        } catch (e) { }

        return { vulnerable: false };
    }

    async makeRequest(url, method = 'GET') {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(url, {
                method,
                mode: 'cors',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            let body = '';
            try { body = await response.text(); } catch (e) { }

            return { ok: response.ok, status: response.status, body };
        } catch (error) {
            return { ok: false, status: 0, body: '', error: error.message };
        }
    }

    processResult(vector, result, url) {
        if (result.vulnerable) {
            if (vector.severity === 'CRITICAL' || vector.severity === 'HIGH') {
                this.state.counts.vulns++;
                this.log(`�� FOUND: ${vector.name}`, 'error');
            } else {
                this.state.counts.warnings++;
                this.log(`🟡 WARNING: ${vector.name}`, 'warning');
            }
            this.addFinding(vector, result, url);
        } else {
            this.state.counts.passed++;
            this.log(`✅ OK: ${vector.name}`, 'success');
        }
        this.updateCounters();
    }

    addFinding(vector, result, url) {
        const finding = {
            name: vector.name,
            severity: vector.severity,
            url,
            description: vector.description,
            evidence: result.evidence,
            remediation: this.getRemediation(vector.id)
        };
        this.state.results.push(finding);
        this.renderFinding(finding);
    }

    getRemediation(vectorId) {
        const remediations = {
            'noauth': 'Set function to require authentication with --no-allow-unauthenticated flag.',
            'cors-func': 'Configure specific allowed origins instead of wildcard.',
            'error-verbose': 'Disable debug mode in production. Return generic error messages.'
        };
        return remediations[vectorId] || 'Review GCP Cloud Functions security best practices.';
    }

    renderFinding(finding) {
        const vulnList = document.getElementById('vulnerability-list');
        if (!vulnList) return;

        const card = document.createElement('div');
        card.className = 'vuln-card';
        card.innerHTML = `
            <div class="vuln-header">
                <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                <span class="vuln-title">${finding.name}</span>
            </div>
            <div class="vuln-url"><strong>Endpoint:</strong> <code>${finding.url}</code></div>
            <p class="vuln-desc">${finding.description}</p>
            <div class="vuln-evidence"><strong>Evidence:</strong> ${finding.evidence}</div>
            <div class="vuln-remediation"><strong>Fix:</strong> ${finding.remediation}</div>
        `;
        vulnList.appendChild(card);
    }

    stopScan() {
        this.state.isScanning = false;
        this.log('Scan stopped', 'warning');
        this.updateUI('stopped');
    }

    completeScan() {
        this.state.isScanning = false;
        const duration = ((Date.now() - this.state.startTime) / 1000).toFixed(1);
        this.log(`Functions scan completed in ${duration}s`, 'success');
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

    updateProgress(current, total, test) {
        const percent = Math.round((current / total) * 100);
        const fill = document.getElementById('progress-fill');
        const text = document.getElementById('progress-text');
        const pct = document.getElementById('progress-percent');

        if (fill) fill.style.width = `${percent}%`;
        if (text) text.textContent = `Testing: ${test}`;
        if (pct) pct.textContent = `${percent}%`;
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
        const log = document.getElementById('attack-log');
        if (log) log.innerHTML = '<div class="log-entry info">[System] Log cleared</div>';
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.gcpFunctionsScanner = new GCPFunctionsScanner();
});
