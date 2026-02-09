class BruteForceScanner {
    constructor() {
        this.currentPath = '';
        this.selectedFile = null;
        this.payloads = [];
        this.isScanning = false;
        this.results = [];
        this.history = []; // Stores {id, payload, request, response, status, time, isMatch}
        this.stats = { sent: 0, matches: 0, errors: 0, totalTime: 0 };
        this.startTime = null;
    }

    init() {
        this.loadDirectory('');
        this.setupEventListeners();
        this.injectLogStyles();
    }

    injectLogStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .log-entry {
                cursor: pointer;
                border-left: 3px solid transparent;
                transition: all 0.2s;
                position: relative;
            }
            .log-entry:hover {
                background: rgba(255,255,255,0.05);
                border-left-color: var(--clr-accent);
            }
            .log-entry .inspect-hint {
                position: absolute;
                right: 15px;
                font-size: 0.65rem;
                opacity: 0;
                color: var(--clr-accent);
            }
            .log-entry:hover .inspect-hint { opacity: 1; }
            .log-match { border-left-color: var(--clr-success) !important; background: rgba(52, 211, 153, 0.05); }
        `;
        document.head.appendChild(style);
    }

    setupEventListeners() {
        document.getElementById('up-dir-btn').addEventListener('click', () => this.goBack());
        document.getElementById('start-scan-btn').addEventListener('click', () => this.startAttack());
        document.getElementById('stop-scan-btn').addEventListener('click', () => this.stopAttack());
        document.getElementById('clear-log-btn').addEventListener('click', () => {
            document.getElementById('attack-log').innerHTML = '';
            this.history = [];
        });
        document.getElementById('export-pdf-btn').addEventListener('click', () => this.exportPDF());

        // New Features
        document.getElementById('preview-payload-btn').addEventListener('click', () => this.showPreview());
        document.getElementById('close-preview-btn').addEventListener('click', () => {
            document.getElementById('preview-modal').style.display = 'none';
        });
        document.getElementById('close-modal-btn').addEventListener('click', () => {
            document.getElementById('response-modal').style.display = 'none';
        });
        document.getElementById('log-filter-status').addEventListener('change', (e) => this.filterLog(e.target.value));

        // Quick Category Links
        document.querySelectorAll('.quick-link').forEach(btn => {
            btn.addEventListener('click', () => {
                const path = btn.getAttribute('data-path');
                this.loadDirectory(path);
            });
        });

        document.getElementById('insert-payload-btn').addEventListener('click', () => {
            const textarea = document.getElementById('request-input');
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const text = textarea.value;
            const before = text.substring(0, start);
            const after = text.substring(end, text.length);
            textarea.value = before + '§payload§' + after;
            textarea.focus();
            textarea.selectionStart = textarea.selectionEnd = start + 9; // Move cursor after §payload§
        });

        // Escape to close modals
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.getElementById('response-modal').style.display = 'none';
                document.getElementById('preview-modal').style.display = 'none';
            }
        });
    }

    async loadDirectory(path) {
        const listEl = document.getElementById('file-list');
        const pathDisplay = document.getElementById('current-path-display');
        listEl.innerHTML = '<div class="browser-item">Loading...</div>';

        try {
            const response = await fetch(`/api/seclists/ls?path=${encodeURIComponent(path)}`);

            // Handle non-JSON responses (usually 404 HTML pages)
            const contentType = response.headers.get("content-type");
            if (!contentType || !contentType.includes("application/json")) {
                throw new Error("Server returned HTML. Please RESTART your server (npm run dev) to enable the API.");
            }

            const data = await response.json();
            this.currentPath = path;
            pathDisplay.textContent = '/' + path;
            listEl.innerHTML = '';

            data.forEach(item => {
                const div = document.createElement('div');
                div.className = 'browser-item';
                div.innerHTML = `
                    ${item.isDir ? '<i data-lucide="folder" style="color:#eab308"></i>' : '<i data-lucide="file-text"></i>'}
                    <span>${item.name}</span>
                `;
                div.onclick = () => item.isDir ? this.loadDirectory(item.path) : this.selectFile(item);
                listEl.appendChild(div);
            });
            lucide.createIcons();
        } catch (err) {
            listEl.innerHTML = `<div class="browser-item" style="color:#ef4444; flex-direction:column; align-items:flex-start; height:auto; padding:1.5rem; gap:10px;">
                <div style="font-weight:700;">📂 API CONNECTION ERROR</div>
                <div style="font-size:0.8rem; line-height:1.4; opacity:0.8;">${err.message}</div>
                <button onclick="location.reload()" class="btn btn-ghost btn-sm" style="margin-top:10px; border:1px solid rgba(239, 68, 68, 0.3);">Retry Connection</button>
            </div>`;
        }
    }

    goBack() {
        if (!this.currentPath) return;
        const parts = this.currentPath.split('/');
        parts.pop();
        this.loadDirectory(parts.join('/'));
    }

    async selectFile(item) {
        const items = document.querySelectorAll('.browser-item');
        items.forEach(el => el.classList.remove('active'));
        event.currentTarget.classList.add('active');

        this.selectedFile = item;
        document.getElementById('selected-file-info').style.display = 'flex';
        document.getElementById('active-filename').textContent = item.name;

        try {
            const response = await fetch(`/api/seclists/cat?path=${encodeURIComponent(item.path)}`);

            // Safety check for non-updated server
            const contentType = response.headers.get("content-type");
            if (response.status === 404 || (contentType && contentType.includes("text/html"))) {
                throw new Error("File API not found. Please restart server.");
            }

            const content = await response.text();
            this.payloads = content.split('\n').map(l => l.trim()).filter(l => l);
            document.getElementById('total-payloads').textContent = this.payloads.length;

            // Show preview badge
            const previewBadge = document.getElementById('payload-preview-badge');
            previewBadge.style.display = 'block';
            previewBadge.textContent = `PREVIEW: ${this.payloads[0].substring(0, 10)}${this.payloads[0].length > 10 ? '...' : ''}`;

            this.log(`Loaded ${this.payloads.length} payloads.`, 'success');
        } catch (err) {
            this.log(`Error: ${err.message}`, 'error');
        }
    }

    showPreview() {
        const input = document.getElementById('request-input').value.trim();
        if (!input || this.payloads.length === 0) return alert('Select wordlist and enter template first.');

        const previewContent = document.getElementById('preview-content');
        previewContent.innerHTML = '';

        this.payloads.slice(0, 5).forEach((p, i) => {
            const req = input.replace(/§payload§/g, p);
            const div = document.createElement('div');
            div.style.cssText = 'background:rgba(0,0,0,0.2); padding:1rem; border-radius:6px; border-left:3px solid var(--clr-accent);';
            div.innerHTML = `<div style="color:var(--clr-accent); font-size:0.7rem; margin-bottom:5px;">REQUEST #${i + 1} [Payload: ${p}]</div>
                             <code style="font-size:0.8rem; color:#94a3b8;">${req.substring(0, 100)}...</code>`;
            previewContent.appendChild(div);
        });

        document.getElementById('preview-modal').style.display = 'block';
    }

    async startAttack() {
        const input = document.getElementById('request-input').value.trim();
        if (!input || this.payloads.length === 0) return alert('Wordlist and template required.');

        this.isScanning = true;
        this.results = [];
        this.history = [];
        this.stats = { sent: 0, matches: 0, errors: 0, totalTime: 0 };
        this.startTime = Date.now();

        this.updateStats();
        document.getElementById('attack-section').style.display = 'block';
        document.getElementById('start-scan-btn').style.display = 'none';
        document.getElementById('stop-scan-btn').style.display = 'inline-flex';
        document.getElementById('results-section').style.display = 'none';
        document.getElementById('attack-log').innerHTML = '';

        this.log('Attack sequence started.', 'info');

        const delay = parseInt(document.getElementById('thread-delay').value);
        const successRegex = document.getElementById('success-regex').value.trim();
        const regex = successRegex ? new RegExp(successRegex, 'i') : null;

        for (let i = 0; i < this.payloads.length; i++) {
            if (!this.isScanning) break;
            const payload = this.payloads[i];
            const requestBody = input.replace(/§payload§/g, payload);
            await this.executeProbe(requestBody, payload, regex);

            const progress = ((i + 1) / this.payloads.length) * 100;
            document.getElementById('progress-fill').style.width = progress + '%';
            document.getElementById('progress-percent').textContent = Math.round(progress) + '%';
            if (delay > 0) await new Promise(r => setTimeout(r, delay));
        }

        this.completeAttack();
    }

    async executeProbe(reqContent, payload, regex) {
        const start = Date.now();
        this.createVisualPacket('outbound');
        let entryId = this.history.length;

        try {
            const config = reqContent.startsWith('http') ? { url: reqContent, method: 'GET' } : this.parseRawRequest(reqContent);

            const response = await fetch(config.url, {
                method: config.method || 'GET',
                headers: config.headers || {}
            });

            const text = await response.text();
            const latency = Date.now() - start;
            this.createVisualPacket(response.ok ? 'inbound-success' : 'inbound-error');

            this.stats.sent++;
            this.stats.totalTime += latency;
            const isMatch = regex ? regex.test(text) : response.ok;

            // Record History
            this.history.push({
                id: entryId,
                payload: payload,
                request: reqContent,
                response: `HTTP/1.1 ${response.status} ${response.statusText}\n` +
                    [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n') +
                    '\n\n' + text,
                status: response.status,
                time: latency,
                isMatch: isMatch
            });

            if (isMatch) {
                this.stats.matches++;
                this.results.push({
                    name: 'Brute Force Match',
                    severity: 'HIGH',
                    payload: payload,
                    path: config.url,
                    evidence: `Response Status: ${response.status} | Match Found`,
                    impact: ['Account Takeover', 'Unauthorized access'],
                    remediation: 'Implement lockout policies and MFA.'
                });
                this.log(`MATCH found: ${payload} (${response.status} / ${latency}ms)`, 'success', entryId);
            } else {
                this.log(`Probe: ${payload} -> ${response.status} (${latency}ms)`, 'info', entryId);
            }
        } catch (err) {
            this.stats.errors++;
            this.createVisualPacket('inbound-error');
            this.log(`Error [${payload}]: ${err.message}`, 'error');
        }
        this.updateStats();
    }

    log(msg, type, historyId = null) {
        const log = document.getElementById('attack-log');
        const div = document.createElement('div');
        div.className = `log-entry ${type} ${type === 'success' ? 'log-match' : ''}`;
        if (historyId !== null) div.setAttribute('data-id', historyId);

        const statusClass = type === 'success' ? '2xx' : (msg.includes(' 3') ? '3xx' : (msg.includes(' 4') ? '4xx' : '5xx'));
        div.classList.add(`status-${statusClass}`);

        div.innerHTML = `<span>[${new Date().toLocaleTimeString()}] ${msg}</span><span class="inspect-hint">INSPECT_HUD</span>`;

        if (historyId !== null) {
            div.onclick = () => this.showInspector(historyId);
        }

        log.appendChild(div);
        log.scrollTop = log.scrollHeight;

        // Apply current filter
        const filter = document.getElementById('log-filter-status').value;
        if (filter !== 'all') this.applyFilterToEntry(div, filter);
    }

    showInspector(id) {
        const record = this.history.find(h => h.id === id);
        if (!record) return;

        document.getElementById('modal-title').textContent = `INSPECTOR // PAYLOAD: ${record.payload} [SEQ_${record.id}]`;
        document.getElementById('modal-request').textContent = record.request;
        document.getElementById('modal-response').textContent = record.response;
        document.getElementById('response-modal').style.display = 'block';
    }

    filterLog(type) {
        const entries = document.querySelectorAll('.log-entry');
        entries.forEach(entry => this.applyFilterToEntry(entry, type));
    }

    applyFilterToEntry(entry, type) {
        if (type === 'all') {
            entry.style.display = 'block';
        } else if (type === 'match') {
            entry.style.display = entry.classList.contains('log-match') ? 'block' : 'none';
        } else {
            entry.style.display = entry.classList.contains(`status-${type}`) ? 'block' : 'none';
        }
    }

    parseRawRequest(raw) {
        const lines = raw.split('\n');
        const firstLine = lines[0].split(' ');
        const method = firstLine[0] || 'GET';
        let path = firstLine[1] || '/';
        const headers = {};
        let host = '';
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) break;
            const split = line.indexOf(':');
            if (split !== -1) {
                const key = line.substring(0, split).trim();
                const val = line.substring(split + 1).trim();
                headers[key] = val;
                if (key.toLowerCase() === 'host') host = val;
            }
        }
        let fullUrl = path;
        if (host && !path.startsWith('http')) {
            const protocol = host.includes('localhost') ? 'http' : 'https';
            fullUrl = `${protocol}://${host}${path}`;
        }
        return { url: fullUrl, method, headers };
    }

    createVisualPacket(type) {
        const stream = document.getElementById('packet-stream');
        if (!stream) return;
        const p = document.createElement('div');
        const colors = { 'outbound': '#3b82f6', 'inbound-success': '#10b981', 'inbound-error': '#ef4444' };
        p.style.cssText = `width:8px; height:8px; background:${colors[type]}; box-shadow:0 0 10px ${colors[type]}; border-radius:2px; position:absolute; left:${type === 'outbound' ? '0' : '100%'}; filter:blur(1px); transition:all 0.5s ease-in-out; opacity:0.8;`;
        stream.appendChild(p);
        setTimeout(() => { p.style.left = type === 'outbound' ? '100%' : '0'; setTimeout(() => p.remove(), 500); }, 10);
    }

    updateStats() {
        document.getElementById('packets-sent').textContent = this.stats.sent;
        document.getElementById('match-count').textContent = this.stats.matches;
        document.getElementById('error-count').textContent = this.stats.errors;
        if (this.stats.sent > 0) {
            const avg = Math.round(this.stats.totalTime / this.stats.sent);
            document.getElementById('avg-time').textContent = avg + ' ms';
        }
    }

    stopAttack() { this.isScanning = false; this.log('Attack terminated.', 'warning'); }

    completeAttack() {
        this.isScanning = false;
        document.getElementById('start-scan-btn').style.display = 'inline-flex';
        document.getElementById('stop-scan-btn').style.display = 'none';
        document.getElementById('scan-status').textContent = 'COMPLETED';
        if (this.results.length > 0) {
            document.getElementById('results-section').style.display = 'block';
            CyberSecResultsRenderer.render('#vulnerability-list', this.results);
        }
        this.log(`Complete. Found ${this.stats.matches} matches.`, 'success');
    }

    async exportPDF() {
        const report = new CyberSecPDFReport({
            title: 'BRUTE FORCE ASSESSMENT',
            scannerName: 'Brute Force Nexus',
            targetUrl: document.getElementById('request-input').value.substring(0, 50),
            vulnerabilities: this.results
        });
        await report.generate();
    }
}

document.addEventListener('DOMContentLoaded', () => { new BruteForceScanner().init(); });
