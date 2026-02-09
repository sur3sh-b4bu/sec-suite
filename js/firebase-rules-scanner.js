/**
 * Firebase Security Rules Analyzer
 * Static analysis of Firestore, RTDB, and Storage security rules
 */

class FirebaseRulesScanner {
    constructor() {
        this.state = {
            results: [],
            counts: { passed: 0, vulns: 0, warnings: 0, info: 0 }
        };

        this.dangerousPatterns = [
            {
                id: 'allow-all',
                name: 'Allow All Access',
                pattern: /allow\s+(read|write|read,\s*write|get|list|create|update|delete).*:\s*if\s+true\s*;?/gi,
                severity: 'CRITICAL',
                description: 'Rule allows all access without any conditions',
                remediation: 'Replace "if true" with proper authentication and authorization checks.'
            },
            {
                id: 'wildcard',
                name: 'Overly Broad Wildcard',
                pattern: /\{document=\*\*\}/g,
                severity: 'HIGH',
                description: 'Recursive wildcard matches all documents in collection',
                remediation: 'Use specific path patterns instead of {document=**}.'
            },
            {
                id: 'missing-auth',
                name: 'Missing Auth Check',
                pattern: /allow\s+(read|write|get|list|create|update|delete)[^;]*(?!request\.auth)/g,
                severity: 'HIGH',
                description: 'Rule does not verify request.auth',
                remediation: 'Add request.auth != null to ensure user is authenticated.'
            },
            {
                id: 'uid-trust',
                name: 'Client UID Trust',
                pattern: /resource\.data\.uid\s*==\s*request\.auth\.uid/g,
                severity: 'MEDIUM',
                description: 'Trusting client-writable UID field for authorization',
                remediation: 'UID should be set server-side or in a protected field.'
            },
            {
                id: 'admin-flag',
                name: 'Admin Flag in Client Data',
                pattern: /resource\.data\.(isAdmin|admin|role)/gi,
                severity: 'CRITICAL',
                description: 'Checking admin status from client-writable data',
                remediation: 'Store roles in custom claims or a protected admin collection.'
            },
            {
                id: 'write-own',
                name: 'Write Without Read Validation',
                pattern: /allow\s+write[^;]*(?!resource)/g,
                severity: 'MEDIUM',
                description: 'Write permission without checking existing data',
                remediation: 'Use resource.data to validate against existing document.'
            },
            {
                id: 'timestamp',
                name: 'Missing Server Timestamp',
                pattern: /allow\s+(create|update)[^;]*(?!timestamp)/g,
                severity: 'LOW',
                description: 'No server timestamp enforcement on writes',
                remediation: 'Require request.resource.data.timestamp == request.time.'
            },
            {
                id: 'size-limit',
                name: 'Missing Size Limits',
                pattern: /allow\s+write[^;]*(?!size)/g,
                severity: 'MEDIUM',
                description: 'No resource size validation for uploads',
                remediation: 'Add request.resource.size < MAX_SIZE validation.'
            },
            {
                id: 'content-type',
                name: 'No Content Type Check',
                pattern: /allow\s+write[^;]*(?!contentType)/g,
                severity: 'MEDIUM',
                description: 'Missing content type validation for storage',
                remediation: 'Validate request.resource.contentType.matches("image/.*").'
            },
            {
                id: 'delete-all',
                name: 'Unrestricted Delete',
                pattern: /allow\s+delete\s*:\s*if\s+(true|request\.auth\s*!=\s*null)\s*;?/gi,
                severity: 'HIGH',
                description: 'Any authenticated user can delete documents',
                remediation: 'Restrict delete to document owners or admins.'
            },
            {
                id: 'rtdb-public',
                name: 'RTDB Public Access',
                pattern: /"\.read"\s*:\s*(true|"true")/g,
                severity: 'CRITICAL',
                description: 'Realtime Database allows public read',
                remediation: 'Change to ".read": "auth != null".'
            },
            {
                id: 'rtdb-write',
                name: 'RTDB Public Write',
                pattern: /"\.write"\s*:\s*(true|"true")/g,
                severity: 'CRITICAL',
                description: 'Realtime Database allows public write',
                remediation: 'Restrict writes with ".write": "auth != null && auth.uid == $uid".'
            }
        ];

        this.sampleRules = {
            firestore: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // DANGEROUS: Allow all access
    match /{document=**} {
      allow read, write: if true;
    }
    
    // DANGEROUS: Admin check in client data
    match /admin/{doc} {
      allow write: if resource.data.isAdmin == true;
    }
    
    // DANGEROUS: Missing auth check
    match /public/{doc} {
      allow read;
      allow write: if request.resource.data.size() < 1;
    }
  }
}`,
            rtdb: `{
  "rules": {
    ".read": true,
    ".write": true,
    "users": {
      "$uid": {
        ".read": "auth != null",
        ".write": "auth.uid == $uid"
      }
    }
  }
}`,
            storage: `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true;
    }
  }
}`
        };

        this.init();
    }

    init() {
        this.bindEvents();
        this.log('Firebase Rules Analyzer initialized', 'info');
    }

    bindEvents() {
        const startBtn = document.getElementById('start-scan-btn');
        const loadSampleBtn = document.getElementById('load-sample-btn');
        const clearLogBtn = document.getElementById('clear-log-btn');

        if (startBtn) startBtn.addEventListener('click', () => this.analyzeRules());
        if (loadSampleBtn) loadSampleBtn.addEventListener('click', () => this.loadSample());
        if (clearLogBtn) clearLogBtn.addEventListener('click', () => this.clearLog());
    }

    loadSample() {
        const rulesType = document.getElementById('rules-type')?.value || 'firestore';
        const rulesInput = document.getElementById('rules-input');
        if (rulesInput) {
            rulesInput.value = this.sampleRules[rulesType];
            this.log(`Loaded vulnerable ${rulesType} sample rules`, 'warning');
        }
    }

    async analyzeRules() {
        const rulesContent = document.getElementById('rules-input')?.value?.trim();
        if (!rulesContent) {
            this.showNotification('Please paste security rules to analyze', 'error');
            return;
        }

        const rulesType = document.getElementById('rules-type')?.value || 'firestore';

        this.state.results = [];
        this.state.counts = { passed: 0, vulns: 0, warnings: 0, info: 0 };

        document.getElementById('vulnerability-list').innerHTML = '';
        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('results-section').style.display = 'block';

        this.log(`Analyzing ${rulesType} security rules...`, 'info');

        const enabledPatterns = this.getEnabledPatterns();

        for (const pattern of enabledPatterns) {
            await this.delay(100);
            this.testPattern(rulesContent, pattern);
        }

        this.summarize();
    }

    getEnabledPatterns() {
        return this.dangerousPatterns.filter(p => {
            const checkbox = document.getElementById(`pattern-${p.id}`);
            return checkbox?.checked !== false; // Default to checked
        });
    }

    testPattern(rulesContent, patternDef) {
        const matches = rulesContent.match(patternDef.pattern);

        if (matches && matches.length > 0) {
            this.log(`🔴 Found: ${patternDef.name} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`, 'error');

            if (patternDef.severity === 'CRITICAL' || patternDef.severity === 'HIGH') {
                this.state.counts.vulns++;
            } else if (patternDef.severity === 'MEDIUM') {
                this.state.counts.warnings++;
            } else {
                this.state.counts.info++;
            }

            this.addFinding({
                name: patternDef.name,
                severity: patternDef.severity,
                description: patternDef.description,
                evidence: `Matched pattern: ${matches.slice(0, 3).join(', ')}${matches.length > 3 ? '...' : ''}`,
                remediation: patternDef.remediation
            });
        } else {
            this.state.counts.passed++;
            this.log(`✅ Clear: ${patternDef.name}`, 'success');
        }

        this.updateCounters();
    }

    addFinding(finding) {
        this.state.results.push(finding);
        this.renderFinding(finding);
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
            <div class="vuln-evidence"><strong>Match:</strong> <code>${finding.evidence}</code></div>
            <div class="vuln-remediation"><strong>Fix:</strong> ${finding.remediation}</div>
        `;
        vulnList.appendChild(card);
    }

    summarize() {
        const { passed, vulns, warnings, info } = this.state.counts;
        const total = vulns + warnings;

        if (total === 0) {
            this.log('✅ No dangerous patterns detected in rules', 'success');
        } else {
            this.log(`Analysis complete: ${vulns} critical/high, ${warnings} medium, ${info} low issues`, 'warning');
        }
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
        alert(message);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.firebaseRulesScanner = new FirebaseRulesScanner();
});
