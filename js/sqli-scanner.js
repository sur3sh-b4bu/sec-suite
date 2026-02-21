// SQL Injection Scanner Engine
// Real-time attack execution with live visualization

// SQL error signatures to detect real SQL injection vulnerabilities
const SQL_ERROR_SIGNATURES = [
    // MySQL
    /you have an error in your sql syntax/i,
    /warning.*?\bmysql_/i,
    /mysql_fetch/i,
    /mysql_num_rows/i,
    /valid mysql result/i,
    /mysqlclient\./i,
    /mysqli?[_\.]/i,
    // PostgreSQL
    /pg_query/i,
    /pg_exec/i,
    /postgresql.*?error/i,
    /unterminated quoted string/i,
    /ERROR:\s+syntax error at or near/i,
    // MSSQL
    /microsoft sql native client error/i,
    /\[microsoft\]\[odbc sql server driver\]/i,
    /mssql_query/i,
    /unclosed quotation mark after the character string/i,
    /microsoft ole db provider for sql server/i,
    // Oracle
    /ora-\d{5}/i,
    /oracle.*?error/i,
    /quoted string not properly terminated/i,
    // SQLite
    /sqlite3::query/i,
    /sqlite\.s3db/i,
    /sqlite_error/i,
    /\[sqlite_error\]/i,
    // Generic
    /sql syntax.*?error/i,
    /sqlstate\[/i,
    /syntax error.*?sql/i,
    /sql command not properly ended/i,
    /unexpected end of sql command/i,
    /dynamic sql error/i,
    /odbc.*?driver.*?error/i,
    /db2_/i,
    /sybase/i,
    /\bSQL\b.*?\berror\b/i
];

// Patterns that indicate data leakage from UNION/data extraction attacks
const SQL_DATA_LEAK_SIGNATURES = [
    /information_schema/i,
    /table_name/i,
    /column_name/i,
    /@@version/i,
    /@@datadir/i,
    /@@hostname/i,
    /pg_tables/i,
    /sys\.tables/i,
    /all_tables/i,
    /v\$version/i
];

// Login success indicators
const LOGIN_SUCCESS_KEYWORDS = [
    /\bLog out\b/i,
    /\bLogout\b/i,
    /\bSign out\b/i,
    /\bMy account\b/i,
    /\bYour username is\b/i,
    /\bWelcome\b/i,
    /\bDashboard\b/i,
    /href="\/logout"/i,
    /href="\/my-account"/i
];

// Typical login error messages that might DISAPPEAR on success
const LOGIN_ERROR_KEYWORDS = [
    /invalid\s*username/i,
    /invalid\s*password/i,
    /incorrect\s*username/i,
    /incorrect\s*password/i,
    /login\s*failed/i,
    /authentication\s*failed/i,
    /unknown\s*user/i,
    /access\s*denied/i,
    /invalid\s*credentials/i,
    /user\s*not\s*found/i
];

class SQLiScanner {
    constructor() {
        this.isScanning = false;
        this.currentPayloadIndex = 0;
        this.results = [];
        this.startTime = null;
        this.targetUrl = '';
        this.paramName = '';
        this.httpMethod = 'GET';
        this.attackSpeed = 500; // ms delay between requests
        this.selectedAttackTypes = [];
        this.payloadsToTest = [];
        this.testedCount = 0;
        this.vulnCount = 0;
        this.failedCount = 0;
        this.corsProxyUrl = ''; // CORS proxy prefix for cross-origin requests

        // Baseline response fingerprint (set before scanning starts)
        this.baseline = {
            status: null,
            length: 0,
            body: '',
            responseTime: 0,
            url: null, // Store baseline URL to detect redirects
            available: false // whether we got a valid baseline
        };

        this.useAutoProxy = false; // Internal flag for CORS auto-detection
        this.baseValue = ''; // Explicit base value for payloads (e.g. username)
        this.csrfToken = null; // Stored CSRF token
        this.defaultPassword = ''; // Default password for POST login requests
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

    // Update payload count in UI
    updatePayloadCount() {
        const count = getPayloadCount();
        document.getElementById('total-payloads').textContent = count + '+';
    }

    // Start scanning
    async startScan() {
        // Get configuration
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.paramName = document.getElementById('vuln-param')?.value.trim();
        this.baseValue = document.getElementById('vuln-param-value')?.value.trim() || '';
        this.defaultPassword = document.getElementById('vuln-param-password')?.value.trim() || 'test';
        this.httpMethod = document.getElementById('http-method')?.value || 'GET';

        // Auto-CORS handled internally during fetchBaseline
        this.useAutoProxy = false;
        // Capture original parameter value for appending-style payloads
        try {
            const urlObj = new URL(this.targetUrl);
            this.originalParamValue = urlObj.searchParams.get(this.paramName) || '';
        } catch (e) {
            this.originalParamValue = '';
        }

        // Read CORS proxy URL - REMOVED
        // this.corsProxyUrl = document.getElementById('cors-proxy-url')?.value.trim() || '';

        const speedSetting = document.getElementById('attack-speed')?.value;
        this.attackSpeed = speedSetting === 'fast' ? 100 : speedSetting === 'slow' ? 1000 : 500;

        // Validate inputs
        if (!this.targetUrl) {
            this.showNotification('Please enter a target URL', 'error');
            return;
        }

        if (!this.paramName) {
            this.showNotification('Please enter a parameter name', 'error');
            return;
        }

        // Get selected attack types
        this.selectedAttackTypes = [];
        if (document.getElementById('attack-boolean')?.checked) this.selectedAttackTypes.push('boolean');
        if (document.getElementById('attack-union')?.checked) this.selectedAttackTypes.push('union');
        if (document.getElementById('attack-time')?.checked) this.selectedAttackTypes.push('timeBased');
        if (document.getElementById('attack-error')?.checked) this.selectedAttackTypes.push('errorBased');

        if (this.selectedAttackTypes.length === 0) {
            this.showNotification('Please select at least one attack type', 'error');
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
        this.log('Scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');
        this.log(`Parameter: ${this.paramName}`, 'info');
        this.log(`Attack types: ${this.selectedAttackTypes.join(', ')}`, 'info');
        // if (this.corsProxyUrl) { // REMOVED
        //     this.log(`CORS Proxy: ${this.corsProxyUrl}`, 'info'); // REMOVED
        // } // REMOVED

        // Fetch baseline response before scanning
        this.log('Fetching baseline response...', 'info');
        await this.fetchBaseline();

        if (!this.baseline.available) {
            this.log('Warning: Could not establish baseline (CORS or network error). Detection accuracy may be reduced — only error-signature matching will be used.', 'warning');
        } else {
            this.log(`Baseline established: status=${this.baseline.status}, length=${this.baseline.length}, time=${this.baseline.responseTime}ms`, 'info');
        }

        this.log(`Total payloads: ${this.payloadsToTest.length}`, 'info');

        // Start attack loop
        await this.attackLoop();
    }

    // Prepare payloads based on selected attack types
    preparePayloads() {
        this.payloadsToTest = [];

        for (const type of this.selectedAttackTypes) {
            const payloads = getPayloadsByType(type);
            for (const payload of payloads) {
                this.payloadsToTest.push({
                    type: type,
                    payload: payload
                });
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

            // Delay between requests
            await this.sleep(this.attackSpeed);
        }

        if (this.isScanning) {
            this.completeScan();
        }
    }

    // Apply CORS proxy prefix to a URL if logical detection enabled it
    applyProxy(url) {
        if (!this.useAutoProxy) return url;
        const proxyPrefix = 'https://corsproxy.io/?';
        return proxyPrefix + encodeURIComponent(url);
    }

    // Fetch baseline response (clean request without attack payloads)
    async fetchBaseline() {
        const maxRetries = 2; // Per attempt type
        let lastError = null;

        // Stage 0: CSRF Harvesting (for POST requests)
        if (this.httpMethod === 'POST') {
            await this.harvestCSRF();
        }

        // Stage 1: Try Direct Fetch
        try {
            this.log('Attempting direct baseline fetch...', 'info');
            const url = this.getBaselineUrl();
            const result = await this.executeBaselineRequest(url);
            this.baseline = result;
            this.log('Direct baseline established! (CORS not required)', 'success');
            return;
        } catch (error) {
            this.log(`Direct fetch failed: ${error.message}. Checking CORS eligibility...`, 'warning');
            lastError = error;
        }

        // Stage 2: Try with Auto-Proxy
        try {
            this.log('CORS block suspected. Enabling auto-proxy (corsproxy.io)...', 'info');
            this.useAutoProxy = true;
            const url = this.getBaselineUrl();
            const result = await this.executeBaselineRequest(url);
            this.baseline = result;
            this.log('Baseline established via auto-proxy!', 'success');
            return;
        } catch (error) {
            this.log(`Auto-proxy fetch failed: ${error.message}`, 'error');
            lastError = error;
        }

        // Final failure state
        this.baseline = {
            status: null, length: 0, body: '', responseTime: 0, url: null, available: false
        };
        this.log(`Failed to establish baseline: ${lastError?.message}`, 'error');
    }

    // Attempt to extract CSRF token from the target page
    async harvestCSRF() {
        this.log('Searching for CSRF tokens (POST target)...', 'info');
        try {
            // Use proxy if we already know we need it, otherwise try direct
            const target = this.applyProxy(this.targetUrl);
            const response = await fetch(target, { cache: 'no-cache' });
            if (!response.ok) return;

            const html = await response.text();

            // Log a snippet for debugging CSRF presence
            if (html.length > 0) {
                const snippet = html.substring(0, 500).replace(/\s+/g, ' ');
                this.log(`Page content snippet: ${snippet}...`, 'info');
            }

            // Regex patterns for common CSRF tokens
            const patterns = [
                /name="csrf" value="([^"]+)"/i,
                /name="_csrf" value="([^"]+)"/i,
                /name="authenticity_token" value="([^"]+)"/i,
                /value="([^"]+)" name="csrf"/i,
                /csrfToken\s*[:=]\s*['"]([^'"]+)['"]/i
            ];

            for (const pattern of patterns) {
                const match = html.match(pattern);
                if (match && match[1]) {
                    this.csrfToken = match[1];
                    this.log(`CSRF Token harvested: ${this.csrfToken.substring(0, 8)}...`, 'success');
                    return;
                }
            }
            this.log('No CSRF token found in HTML.', 'info');
        } catch (e) {
            this.log('CSRF harvest failed (might require proxy).', 'warning');

            // If direct failed, try with proxy immediately during harvest
            if (!this.useAutoProxy) {
                this.useAutoProxy = true;
                await this.harvestCSRF();
            }
        }
    }

    // Helper to generate baseline URL
    getBaselineUrl() {
        const url = new URL(this.targetUrl);
        if (this.httpMethod === 'GET') {
            url.searchParams.set(this.paramName, `test${Date.now()}`);
        }
        return url.toString();
    }

    // Actual network execution for baseline
    async executeBaselineRequest(targetUrl) {
        const proxiedUrl = this.applyProxy(targetUrl);
        const startTime = Date.now();

        const fetchOptions = {
            method: this.httpMethod,
            cache: 'no-cache',
            credentials: 'omit', // Default to omit for public proxies
            headers: { 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' }
        };

        // If not using proxy, try to include credentials for session support
        if (!this.useAutoProxy) {
            fetchOptions.credentials = 'include';
        }

        if (this.httpMethod === 'POST') {
            const testValue = `test${Date.now()}`;
            const params = new URLSearchParams();

            if (this.csrfToken) params.append('csrf', this.csrfToken);
            params.append(this.paramName, testValue);
            params.append('password', this.defaultPassword);

            fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            fetchOptions.body = params.toString();
        }

        const response = await fetch(proxiedUrl, fetchOptions);
        if (!response.ok) {
            throw new Error(`Response status ${response.status}`);
        }

        const body = await response.text();
        if (body.length === 0) throw new Error('Empty response');

        return {
            status: response.status,
            length: body.length,
            body: body,
            responseTime: Date.now() - startTime,
            url: response.url,
            available: true
        };
    }

    // Test a single payload
    async testPayload(payloadData) {
        const { type, payload } = payloadData;

        // Update current attack display
        this.updateCurrentAttack(type, payload);

        try {
            // Build URL with payload
            const testUrl = this.buildTestUrl(payload);

            // Make request and measure time
            const response = await this.makeRequest(testUrl);

            // Update response display
            this.updateResponseDisplay(response.status, response.responseTime, response.length);

            // Analyze response for real vulnerability indicators
            const isVulnerable = this.analyzeResponse(response, type, response.responseTime);

            if (isVulnerable) {
                this.vulnCount++;
                this.results.push({
                    type: type,
                    payload: payload,
                    url: testUrl,
                    status: response.status,
                    time: response.responseTime,
                    length: response.length,
                    vulnerable: true
                });
                this.log(`✓ VULNERABLE: ${payload}`, 'success');
            } else {
                this.log(`✗ Not vulnerable: ${payload}`, 'info');
            }

            this.testedCount++;

        } catch (error) {
            this.failedCount++;
            this.log(`✗ Error: ${error.message}`, 'error');
        }
    }

    // Build test URL with payload
    buildTestUrl(payload) {
        const url = new URL(this.targetUrl);
        let finalPayload = payload;

        // Smart Injection Strategy:
        if (this.baseValue) {
            // Case 1: Payload starts with quotes/prefix indicators -> PREPEND
            if (payload.startsWith("'") || payload.startsWith('"')) {
                finalPayload = this.baseValue + payload;
            }
            // Case 2: Payload starts with generic 'admin' -> REPLACE 'admin' with baseValue
            else if (payload.startsWith('admin')) {
                finalPayload = payload.replace(/^admin/, this.baseValue);
            }
        } else if (this.originalParamValue) {
            // Fallback: Append to original param value if it starts with quote
            if (payload.startsWith("'") || payload.startsWith('"')) {
                finalPayload = this.originalParamValue + payload;
            }
        }

        if (this.httpMethod === 'GET') {
            url.searchParams.set(this.paramName, finalPayload);
        }

        return url.toString();
    }

    // Make HTTP request — returns actual response data
    async makeRequest(url) {
        const startTime = Date.now();
        const proxiedUrl = this.applyProxy(url);

        try {
            const fetchOptions = {
                method: this.httpMethod,
                cache: 'no-cache',
                credentials: this.useAutoProxy ? 'omit' : 'include',
                headers: {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            };

            // For POST requests, include payload in body
            if (this.httpMethod === 'POST') {
                const urlObj = new URL(url);
                const payload = urlObj.searchParams.get(this.paramName);
                const params = new URLSearchParams();

                if (this.csrfToken) params.append('csrf', this.csrfToken);
                params.append(this.paramName, payload || '');
                params.append('password', this.defaultPassword);

                fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
                fetchOptions.body = params.toString();
            }

            const response = await fetch(proxiedUrl, fetchOptions);
            const body = await response.text();
            const responseTime = Date.now() - startTime;

            return {
                status: response.status,
                length: body.length,
                body: body,
                responseTime: responseTime,
                headers: Object.fromEntries(response.headers.entries()),
                url: response.url, // Capture final URL (after redirects)
                error: false
            };

        } catch (error) {
            const responseTime = Date.now() - startTime;
            // CORS or network error — return error state, NOT fake data
            return {
                status: 0,
                length: 0,
                body: '',
                responseTime: responseTime,
                headers: {},
                error: true,
                errorMessage: error.message || 'Request blocked (CORS or network error)'
            };
        }
    }

    // Check if response body contains SQL error signatures
    containsSQLErrors(body) {
        if (!body || body.length === 0) return false;
        return SQL_ERROR_SIGNATURES.some(pattern => pattern.test(body));
    }

    // Check if response body contains SQL data leak patterns
    containsDataLeaks(body) {
        if (!body || body.length === 0) return false;
        return SQL_DATA_LEAK_SIGNATURES.some(pattern => pattern.test(body));
    }

    // Analyze response for REAL vulnerability indicators (no randomness)
    analyzeResponse(response, type, responseTime) {
        // If the request completely failed (CORS/network), we cannot determine vulnerability
        if (response.error) {
            return false;
        }

        // First: check for SQL error signatures in the response body (applies to ALL attack types)
        // This is the strongest and most reliable indicator
        if (this.containsSQLErrors(response.body)) {
            return true;
        }

        // REDIRECT DETECTION (Login Bypass)
        if (this.baseline.available && response.url && this.baseline.url) {
            try {
                const baseObj = new URL(this.baseline.url);
                const respObj = new URL(response.url);

                if (baseObj.href !== respObj.href) {
                    // Log path changes for debugging
                    if (baseObj.pathname !== respObj.pathname) {
                        this.log(`Redirect detected: ${baseObj.pathname} -> ${respObj.pathname}`, 'info');
                        return true;
                    }
                }
            } catch (e) {
                // Ignore URL parsing errors
            }
        }

        // INVERSE ERROR MATCHING (Login Bypass Detection)
        // If the baseline has a login error (e.g., "Invalid password") but the payload response
        // DOES NOT, it strongly suggests the injection bypassed the authentication check.
        if (this.baseline.available && this.baseline.body && response.body) {
            for (const pattern of LOGIN_ERROR_KEYWORDS) {
                const errorInBaseline = pattern.test(this.baseline.body);
                const errorInResponse = pattern.test(response.body);

                // Signal: Error was present in baseline, but is GONE in the response
                if (errorInBaseline && !errorInResponse && response.status === 200) {
                    this.log(`Login bypass detected: Error message "${pattern.source}" disappeared.`, 'success');
                    return true;
                }
            }
        }

        // SUCCESS KEYWORD MATCHING (Login Bypass Detection)
        // If keywords like "Logout" or "Welcome" appear in the response but were NOT in the baseline,
        // it indicates we successfully logged in.
        if (this.baseline.available && this.baseline.body && response.body) {
            for (const pattern of LOGIN_SUCCESS_KEYWORDS) {
                const foundInBaseline = pattern.test(this.baseline.body);
                const foundInResponse = pattern.test(response.body);

                // Signal: Success keyword appeared where it wasn't before
                if (!foundInBaseline && foundInResponse && response.status === 200) {
                    this.log(`Login bypass detected: Found success keyword "${pattern.source}".`, 'success');
                    return true;
                }
            }
        }

        // Type-specific detection logic
        switch (type) {
            case 'boolean': {
                // Boolean-based: compare response body length against baseline
                // A significant length difference suggests the SQL condition altered query results
                if (!this.baseline.available) return false;

                const baselineLen = this.baseline.length;
                const responseLen = response.length;

                // Ignore tiny responses or zero-length (likely errors)
                if (baselineLen === 0 || responseLen === 0) return false;

                const lengthDiff = Math.abs(responseLen - baselineLen);
                const diffPercent = (lengthDiff / baselineLen) * 100;

                // Flag if body length differs by >15% from baseline AND status is still 200
                // This indicates the injected boolean condition changed the query output
                if (diffPercent > 15 && response.status === 200) {
                    return true;
                }

                return false;
            }

            case 'union': {
                // UNION-based: look for data leak patterns AND significant length increase
                if (this.containsDataLeaks(response.body)) {
                    return true;
                }

                // If baseline available, check for significant content length increase
                // UNION injections append extra data rows, so response gets noticeably larger
                if (this.baseline.available && this.baseline.length > 0) {
                    const lengthDiff = response.length - this.baseline.length;
                    const diffPercent = (lengthDiff / this.baseline.length) * 100;

                    // Response must be significantly larger (>25% increase) and contain
                    // body content that wasn't in baseline (not just padding/whitespace)
                    if (diffPercent > 25 && response.status === 200) {
                        // Additional check: make sure the extra content isn't just the same page
                        // Look for new content that wasn't in the baseline
                        const baseSnippet = this.baseline.body.substring(0, 500);
                        const respSnippet = response.body.substring(0, 500);
                        if (baseSnippet !== respSnippet) {
                            return true;
                        }
                    }
                }

                return false;
            }

            case 'timeBased': {
                // Time-based: response must take significantly longer than baseline
                // SLEEP(5) / WAITFOR DELAY should add ~5 seconds to response time
                const baselineTime = this.baseline.available ? this.baseline.responseTime : 1000;
                const timeDelta = responseTime - baselineTime;

                // Flag if response took at least 4 seconds longer than baseline
                if (timeDelta >= 4000) {
                    return true;
                }

                return false;
            }

            case 'errorBased': {
                // Error-based: look for SQL errors in response body (already checked above)
                // Additionally: if baseline was 200 and this returned 500, it could indicate
                // the SQL payload caused a server-side SQL error
                if (this.baseline.available && this.baseline.status === 200 && response.status === 500) {
                    // A status change from 200 to 500 when injecting SQL error payloads
                    // is a strong indicator, but only flag if body content also changed
                    if (response.body.length !== this.baseline.length) {
                        return true;
                    }
                }

                return false;
            }

            default:
                return false;
        }
    }

    // Update current attack display
    updateCurrentAttack(type, payload) {
        const typeNames = {
            'boolean': 'Boolean-based',
            'union': 'UNION-based',
            'timeBased': 'Time-based',
            'errorBased': 'Error-based'
        };

        const container = document.getElementById('current-payload-code');
        if (container) {
            container.textContent = payload;
        }
    }

    // Update response display
    updateResponseDisplay(status, time, length) {
        const statusEl = document.getElementById('response-status');
        const timeEl = document.getElementById('response-time');
        const lengthEl = document.getElementById('response-length');

        if (statusEl) statusEl.textContent = status || 'N/A';
        if (timeEl) timeEl.textContent = time + 'ms';
        if (lengthEl) lengthEl.textContent = length + ' bytes';
    }

    // Update progress
    updateProgress() {
        const progress = (this.currentPayloadIndex / this.payloadsToTest.length) * 100;

        if (document.getElementById('tested-count')) document.getElementById('tested-count').textContent = this.testedCount;
        if (document.getElementById('vuln-count')) document.getElementById('vuln-count').textContent = this.vulnCount;
        if (document.getElementById('diff-count')) document.getElementById('diff-count').textContent = this.failedCount;
        if (document.getElementById('vuln-badge')) document.getElementById('vuln-badge').textContent = this.vulnCount;

        // Update success rate
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
        this.log(`Vulnerabilities found: ${this.vulnCount}`, this.vulnCount > 0 ? 'success' : 'info');
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

        this.showNotification(`Scan complete! Found ${this.vulnCount} vulnerabilities`,
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
        const vis = document.getElementById('attack-section');
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
                        <code style="background: rgba(139, 92, 246, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa; word-break: break-all; display: inline-block; margin-top: 0.25rem;">${result.url}</code>
                    </div>
                    <div style="display: flex; gap: 2rem; margin-top: 0.75rem;">
                        <span><strong style="color: #e2e8f0;">Status:</strong> ${result.status}</span>
                        <span><strong style="color: #e2e8f0;">Time:</strong> ${result.time}ms</span>
                        <span><strong style="color: #e2e8f0;">Length:</strong> ${result.length} bytes</span>
                    </div>
                </div>
                <div class="disclosed-data">${result.payload}</div>
                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
                    <div style="margin-bottom: 0.75rem;">
                        <strong style="color: #f87171;">Potential Impact:</strong>
                        <ul style="margin: 0.5rem 0 0 1.25rem; color: #94a3b8; line-height: 1.8;">
                            <li>Database information disclosure</li>
                            <li>Authentication bypass</li>
                            <li>Data manipulation or deletion</li>
                        </ul>
                    </div>
                    <div>
                        <strong style="color: #34d399;">Remediation:</strong>
                        <p style="margin: 0.5rem 0 0 0; color: #94a3b8;">Use parameterized queries or prepared statements. Implement input validation and escape special characters.</p>
                    </div>
                </div>
            `;
            vulnList.appendChild(vulnCard);
        });

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Get type name
    getTypeName(type) {
        const names = {
            'boolean': 'Boolean-based SQL Injection',
            'union': 'UNION-based SQL Injection',
            'timeBased': 'Time-based Blind SQL Injection',
            'errorBased': 'Error-based SQL Injection'
        };
        return names[type] || type;
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
            // Convert results to standard vulnerability format
            const vulnerabilities = this.results.map(result => ({
                name: this.getTypeName(result.type),
                severity: 'HIGH',
                path: result.url,
                payload: result.payload,
                description: `SQL Injection via ${result.type} technique`,
                evidence: `Status: ${result.status} | Response Time: ${result.time}ms | Content Length: ${result.length} bytes`,
                impact: ['Database information disclosure', 'Authentication bypass', 'Data manipulation or deletion'],
                remediation: 'Use parameterized queries or prepared statements. Implement input validation and escape special characters.'
            }));

            const report = new CyberSecPDFReport({
                title: 'SQL INJECTION REPORT',
                scannerName: 'SQL Injection Scanner',
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
    const scanner = new SQLiScanner();
    scanner.init();

    console.log('🔐 CyberSec Suite SQLi Scanner initialized');
    console.log('📊 Ready to scan!');
});
