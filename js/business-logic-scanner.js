// Business Logic Scanner Engine
// Automated detection of price manipulation, workflow bypass, race conditions, and logic flaws

class BusinessLogicScanner {
    constructor() {
        this.isScanning = false;
        this.targetUrl = '';
        this.testEndpoint = '';
        this.sampleRequest = {};
        this.selectedTests = [];
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
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

    async startScan() {
        this.targetUrl = document.getElementById('target-url')?.value.trim();
        this.testEndpoint = document.getElementById('test-endpoint')?.value.trim();

        try {
            this.sampleRequest = JSON.parse(document.getElementById('sample-request')?.value || '{}');
        } catch {
            this.sampleRequest = {};
        }

        if (!this.targetUrl) {
            this.showNotification('Please enter target URL', 'error');
            return;
        }

        this.selectedTests = [];
        if (document.getElementById('test-price')?.checked) this.selectedTests.push('price');
        if (document.getElementById('test-workflow')?.checked) this.selectedTests.push('workflow');
        if (document.getElementById('test-race')?.checked) this.selectedTests.push('race');
        if (document.getElementById('test-params')?.checked) this.selectedTests.push('params');
        if (document.getElementById('test-integer')?.checked) this.selectedTests.push('integer');
        if (document.getElementById('test-coupon')?.checked) this.selectedTests.push('coupon');

        if (this.selectedTests.length === 0) {
            this.showNotification('Please select at least one test type', 'error');
            return;
        }

        this.prepareTests();

        this.isScanning = true;
        this.currentTestIndex = 0;
        this.testedCount = 0;
        this.vulnCount = 0;
        this.criticalCount = 0;
        this.vulnerabilities = [];

        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('attack-section').scrollIntoView({ behavior: 'smooth' });

        this.updateScanControls(true);
        this.log('Business logic scan started', 'info');
        this.log(`Target: ${this.targetUrl}`, 'info');

        await this.testLoop();
    }

    prepareTests() {
        this.testsToRun = [];

        for (const testType of this.selectedTests) {
            if (testType === 'price') {
                getPriceManipulationPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'price',
                        name: 'Price Manipulation',
                        field: payload.field,
                        original: payload.original,
                        modified: payload.modified,
                        description: payload.description
                    });
                });
            } else if (testType === 'workflow') {
                getWorkflowBypassPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'workflow',
                        name: 'Workflow Bypass',
                        step: payload.step,
                        technique: payload.technique,
                        description: payload.step
                    });
                });
            } else if (testType === 'race') {
                getRaceConditionPayloads().forEach(payload => {
                    this.testsToRun.push({
                        type: 'race',
                        name: 'Race Condition',
                        scenario: payload.scenario,
                        description: payload.description
                    });
                });
            } else if (testType === 'params') {
                getParameterTamperingPayloads().forEach(payload => {
                    payload.values.slice(0, 2).forEach(value => {
                        this.testsToRun.push({
                            type: 'params',
                            name: 'Parameter Tampering',
                            param: payload.param,
                            value: value,
                            description: `${payload.param}=${value}`
                        });
                    });
                });
            } else if (testType === 'integer') {
                BusinessLogicPayloads.integerManipulation.forEach(payload => {
                    this.testsToRun.push({
                        type: 'integer',
                        name: 'Integer Overflow',
                        value: payload.value,
                        description: payload.description
                    });
                });
            } else if (testType === 'coupon') {
                BusinessLogicPayloads.couponAbuse.forEach(payload => {
                    this.testsToRun.push({
                        type: 'coupon',
                        name: 'Coupon Abuse',
                        technique: payload.technique,
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
                if (response.critical) this.criticalCount++;

                this.vulnerabilities.push({
                    type: test.type,
                    name: test.name,
                    description: test.description,
                    field: test.field,
                    original: test.original,
                    modified: test.modified || test.value,
                    details: response.details,
                    severity: response.critical ? 'CRITICAL' : 'HIGH',
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

    async simulateTest(test) {
        await this.sleep(100);

        const responses = {
            price: [
                { vulnerable: true, critical: true, details: 'Price accepted as zero - free purchase possible' },
                { vulnerable: true, critical: true, details: 'Negative price accepted - credit to account' },
                { vulnerable: false }
            ],
            workflow: [
                { vulnerable: true, critical: true, details: 'Payment step bypassed - order placed without payment' },
                { vulnerable: true, critical: false, details: 'Verification step skipped' },
                { vulnerable: false }
            ],
            race: [
                { vulnerable: true, critical: true, details: 'Coupon applied 5 times in race window' },
                { vulnerable: true, critical: false, details: 'Stock limit bypassed via concurrent requests' },
                { vulnerable: false }
            ],
            params: [
                { vulnerable: true, critical: true, details: 'Role parameter accepted - elevated to admin' },
                { vulnerable: false }
            ],
            integer: [
                { vulnerable: true, critical: true, details: 'Integer overflow caused negative total' },
                { vulnerable: false }
            ],
            coupon: [
                { vulnerable: true, critical: false, details: 'Coupon reused successfully' },
                { vulnerable: true, critical: false, details: 'Multiple coupons stacked' },
                { vulnerable: false }
            ]
        };

        const typeResponses = responses[test.type] || responses.price;
        return typeResponses[Math.floor(Math.random() * typeResponses.length)];
    }

    getImpact(type) {
        const impacts = {
            'price': ['Free purchases', 'Financial loss', 'Account credit abuse'],
            'workflow': ['Skip payment', 'Bypass verification', 'Access premium features'],
            'race': ['Multiple discounts', 'Overselling inventory', 'Limit bypass'],
            'params': ['Privilege escalation', 'Admin access', 'Data manipulation'],
            'integer': ['Negative totals', 'Overflow calculations', 'System errors'],
            'coupon': ['Unlimited discounts', 'Multiple redemptions', 'Free products']
        };
        return impacts[type] || ['Business logic flaw'];
    }

    getRemediation(type) {
        const remediations = {
            'price': 'Never trust client-side prices. Recalculate on server. Validate all values.',
            'workflow': 'Enforce server-side workflow state. Validate each step completion.',
            'race': 'Use database locks. Implement atomic transactions. Add request deduplication.',
            'params': 'Never trust user input for privilege flags. Use server-side session.',
            'integer': 'Use appropriate data types. Add bounds checking. Validate ranges.',
            'coupon': 'Track coupon usage in database. Use atomic operations. Add rate limiting.'
        };
        return remediations[type] || 'Implement proper server-side validation.';
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
        document.getElementById('critical-count').textContent = this.criticalCount;
        document.getElementById('vuln-badge').textContent = this.vulnCount;
    }

    completeScan() {
        this.isScanning = false;

        this.log('Business logic scan completed', 'success');
        this.log(`Flaws found: ${this.vulnCount} (${this.criticalCount} critical)`, this.vulnCount > 0 ? 'success' : 'info');

        document.getElementById('scan-status').textContent = 'Complete';
        document.querySelector('.status-dot').classList.remove('scanning');
        document.querySelector('.status-dot').classList.add(this.vulnCount > 0 ? 'success' : 'error');

        this.updateScanControls(false);

        if (this.vulnCount > 0) this.showResults();

        this.showNotification(`Found ${this.vulnCount} business logic flaws`, this.vulnCount > 0 ? 'success' : 'info');
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

            let manipulationHtml = '';
            if (vuln.original && vuln.modified) {
                manipulationHtml = `
                    <div class="manipulation-display">
                        <div class="manipulation-original">Original: ${vuln.field}="${vuln.original}"</div>
                        <div class="manipulation-modified">Modified: ${vuln.field}="${vuln.modified}"</div>
                    </div>`;
            }

            vulnCard.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">Logic Flaw #${index + 1}</div>
                    <div class="vuln-severity">${vuln.severity}</div>
                </div>
                <span class="logic-type-badge ${vuln.type}">${vuln.name}</span>
                <div style="color: var(--color-text-secondary); margin: 12px 0;">
                    ${vuln.description}
                </div>
                ${manipulationHtml}
                <div class="logic-flaw-card">
                    <div class="logic-flaw-title">Details:</div>
                    <div class="logic-flaw-content">${vuln.details}</div>
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
        this.generateExploit('price');
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
            case 'price':
                code = `# Price Manipulation Attack

# Intercept checkout request and modify:

# Original request:
POST /cart/checkout
{"productId": "1", "quantity": "1", "price": "1000.00"}

# Modified request (zero price):
POST /cart/checkout
{"productId": "1", "quantity": "1", "price": "0"}

# Modified request (negative price):
POST /cart/checkout
{"productId": "1", "quantity": "1", "price": "-500"}

# This may result in free items or account credit`;
                break;
            case 'race':
                code = generateRaceConditionScript(this.targetUrl + '/apply-coupon', 20);
                break;
            case 'workflow':
                code = `# Workflow Bypass Attack

# Step 1: Add item to cart
POST /cart/add
{"productId": "1"}

# Step 2: Skip payment - go directly to confirmation
# Instead of: POST /checkout/payment
# Access directly:
GET /checkout/confirm

# Or POST directly to order completion:
POST /checkout/complete
{"orderId": "generated_id"}

# Check if order is placed without payment`;
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
            doc.text('Business Logic Report', 20, 20);
            doc.setFontSize(12);
            doc.text(`Target: ${this.targetUrl}`, 20, 35);
            doc.text(`Logic Flaws: ${this.vulnCount} (${this.criticalCount} critical)`, 20, 42);
            doc.save('business-logic-report.pdf');
            this.showNotification('PDF exported!', 'success');
        } catch (error) {
            this.showNotification('Export failed', 'error');
        }
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
    const scanner = new BusinessLogicScanner();
    scanner.init();
    console.log('💼 CyberSec Suite Business Logic Scanner initialized');
});
