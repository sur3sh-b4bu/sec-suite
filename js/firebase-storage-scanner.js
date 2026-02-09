/**
 * Firebase Storage Security Scanner
 * Detects storage misconfigurations via real HTTP testing
 * Only reports REAL findings - no simulated results
 */

class FirebaseStorageScanner {
    constructor() {
        this.state = {
            isScanning: false,
            results: [],
            counts: { passed: 0, vulns: 0, warnings: 0, info: 0 },
            startTime: null
        };

        this.attackVectors = [
            {
                id: 'bucket-list',
                name: 'Bucket Listing',
                severity: 'CRITICAL',
                description: 'Bucket contents can be listed without authentication',
                test: this.testBucketListing.bind(this)
            },
            {
                id: 'public-download',
                name: 'Public Download Access',
                severity: 'HIGH',
                description: 'Files are publicly downloadable without authentication',
                test: this.testPublicDownload.bind(this)
            },
            {
                id: 'bucket-cors',
                name: 'CORS Configuration',
                severity: 'MEDIUM',
                description: 'Check for permissive CORS settings',
                test: this.testCORSConfig.bind(this)
            }
        ];

        this.init();
    }

    init() {
        this.bindEvents();
        this.log('Firebase Storage Scanner initialized', 'info');
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
        const bucket = document.getElementById('storage-bucket')?.value?.trim();
        if (!bucket) {
            this.showNotification('Please enter a Storage Bucket name', 'error');
            return;
        }

        this.state.isScanning = true;
        this.state.startTime = Date.now();
        this.state.results = [];
        this.state.counts = { passed: 0, vulns: 0, warnings: 0, info: 0 };

        const vulnList = document.getElementById('vulnerability-list');
        if (vulnList) vulnList.innerHTML = '';

        this.updateUI('scanning');
        this.log(`Starting storage scan for bucket: ${bucket}`, 'info');

        const enabledVectors = this.getEnabledVectors();
        const totalTests = enabledVectors.length;
        let completed = 0;

        for (const vector of enabledVectors) {
            if (!this.state.isScanning) break;

            this.log(`Testing: ${vector.name}`, 'info');
            this.updateProgress(completed, totalTests, vector.name);

            try {
                const result = await vector.test(bucket);
                this.processResult(vector, result);
            } catch (error) {
                this.log(`Error in ${vector.name}: ${error.message}`, 'error');
                this.state.counts.passed++;
            }

            completed++;
            await this.delay(400);
        }

        this.completeScan();
    }

    getEnabledVectors() {
        return this.attackVectors.filter(vector => {
            const checkbox = document.getElementById(`attack-${vector.id}`);
            return checkbox?.checked !== false;
        });
    }

    // Real HTTP-based Tests
    async testBucketListing(bucket) {
        // Test Firebase Storage API endpoint
        const url = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o`;

        try {
            const response = await this.makeRequest(url);

            if (response.ok) {
                // Parse response to check if it returns objects
                try {
                    const data = JSON.parse(response.body);
                    if (data.items && data.items.length > 0) {
                        return {
                            vulnerable: true,
                            evidence: `Bucket listing returned ${data.items.length} items publicly`
                        };
                    }
                    if (response.status === 200) {
                        return {
                            vulnerable: true,
                            evidence: 'Bucket endpoint accessible (Status: 200)'
                        };
                    }
                } catch (e) {
                    // Response wasn't JSON but was accessible
                    if (response.status === 200) {
                        return {
                            vulnerable: true,
                            evidence: 'Bucket endpoint accessible without authentication'
                        };
                    }
                }
            }
        } catch (error) {
            this.log(`Request failed: ${error.message}`, 'info');
        }

        return { vulnerable: false };
    }

    async testPublicDownload(bucket) {
        // Test common public paths
        const testPaths = ['public', 'uploads', 'images', 'files'];

        for (const path of testPaths) {
            const url = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o/${path}`;

            try {
                const response = await this.makeRequest(url);

                if (response.ok && response.status === 200) {
                    return {
                        vulnerable: true,
                        evidence: `Public path "/${path}" accessible (Status: ${response.status})`
                    };
                }
            } catch (e) { }
        }

        return { vulnerable: false };
    }

    async testCORSConfig(bucket) {
        const url = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o`;

        try {
            const response = await fetch(url, {
                method: 'OPTIONS',
                mode: 'cors'
            });

            const corsHeader = response.headers.get('access-control-allow-origin');

            if (corsHeader === '*') {
                return {
                    vulnerable: true,
                    evidence: 'CORS allows all origins (Access-Control-Allow-Origin: *)'
                };
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
            try { body = await response.text(); } catch (e) { }

            return { ok: response.ok, status: response.status, body };
        } catch (error) {
            return { ok: false, status: 0, body: '', error: error.message };
        }
    }

    processResult(vector, result) {
        if (result.vulnerable) {
            if (vector.severity === 'CRITICAL' || vector.severity === 'HIGH') {
                this.state.counts.vulns++;
                this.log(`�� FOUND: ${vector.name}`, 'error');
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
            'bucket-list': 'Disable public listing in Security Rules: allow list: if request.auth != null;',
            'public-download': 'Require authentication for downloads: allow read: if request.auth != null;',
            'bucket-cors': 'Configure CORS to allow only your domain origins.'
        };
        return remediations[vectorId] || 'Review Firebase Storage security rules.';
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
        this.log(`Storage scan completed in ${duration}s`, 'success');
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
        const fill = document.getElementById('progress-fill');
        const text = document.getElementById('progress-text');
        const pct = document.getElementById('progress-percent');

        if (fill) fill.style.width = `${percent}%`;
        if (text) text.textContent = `Testing: ${currentTest}`;
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

    showNotification(message, type) {
        this.log(message, type);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.firebaseStorageScanner = new FirebaseStorageScanner();
});
