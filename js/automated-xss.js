/**
 * Automated XSS Form Discovery Engine
 * Handles fetching target URLs, bypassing CORS via proxy for discovery,
 * parsing forms, and generating the Interactive Form Mapping UI for the XSS module.
 */

class AutomatedXSSScanner {
    constructor(targetUrl) {
        this.targetUrl = targetUrl;
        this.forms = [];
        this.useProxy = false;
        this.isDirect = false;
    }

    applyProxy(url) {
        if (!this.useProxy) return url;
        const proxyPrefix = 'https://corsproxy.io/?';
        return proxyPrefix + encodeURIComponent(url);
    }

    async discover() {
        const log = (msg, type = 'info') => { if (window.automatedLogCallback) window.automatedLogCallback(msg, type); };
        log(`[DISCOVERY] Fetching: ${this.targetUrl}`, 'info');

        this.forms = [];

        // Extract URL Parameters (GET-Query based)
        try {
            const urlObj = new URL(this.targetUrl);
            const queryParams = Array.from(urlObj.searchParams.entries());
            if (queryParams.length > 0) {
                const urlInputs = queryParams.map(([name, value]) => ({
                    name, type: 'url-param', value
                }));
                this.forms.push({
                    index: 99, action: urlObj.origin + urlObj.pathname,
                    method: 'GET', inputs: urlInputs, isSearch: true, isUrlQuery: true
                });
                log(`[DISCOVERY] Extracted URL Parameters: ${urlInputs.map(i => i.name).join(', ')}`, 'success');
            }
        } catch (e) {
            log(`[ERROR] Invalid URL format.`, 'error');
        }

        // Try DIRECT fetch first (works with --disable-web-security)
        try {
            const response = await fetch(this.targetUrl, { cache: 'no-cache', credentials: 'include' });
            const html = await response.text();
            this.useProxy = false;
            this.isDirect = true;
            this.parseForms(html);
            this.updateSecurityStatus('#10b981', 'DIRECT MODE ✓');
            log('[DISCOVERY] Direct fetch succeeded! Full session support available.', 'success');
            return true;
        } catch (error) {
            log(`[DISCOVERY] Direct fetch blocked (CORS). Using proxy for form discovery...`, 'warning');
            this.isDirect = false;
            this.updateSecurityStatus('#f59e0b', 'PROXY MODE (CORS)');
        }

        // Try PROXY fetch for form discovery only
        try {
            this.useProxy = true;
            const response = await fetch(this.applyProxy(this.targetUrl), { cache: 'no-cache', credentials: 'omit' });
            const html = await response.text();
            this.parseForms(html);
            return true;
        } catch (error) {
            log(`[ERROR] Discovery failed: ${error.message}`, 'error');
            this.updateSecurityStatus('#ef4444', 'ERROR');
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
                isSearch: inputs.some(i => i.name?.toLowerCase().match(/q|search|query|id|comment/))
            });

            if (window.automatedLogCallback) {
                const paramList = inputs.map(i => `${i.name || '[unnamed]'} (${i.type})`).join(', ');
                window.automatedLogCallback(`[DISCOVERY] Form ${index} (${method}): ${paramList}`, 'info');
            }
        });
    }
}

// Global UI Hook
document.addEventListener('DOMContentLoaded', () => {
    const startBtn = document.getElementById('automated-scan-btn');
    const resumeBtn = document.getElementById('resume-audit-btn');
    const addParamBtn = document.getElementById('add-param-btn');
    const targetUrlInput = document.getElementById('target-url');

    const overrideSection = document.getElementById('form-override-section');
    const paramsContainer = document.getElementById('form-params-container');

    let currentScanner = null;

    window.automatedLogCallback = (message, type = 'info', context = null) => {
        const logContent = document.getElementById('attack-log');
        if (!logContent) return;

        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        const time = new Date().toLocaleTimeString();

        let html = `<span class="log-time">[${time}]</span> ${message}`;
        if (context) {
            html += `<div style="font-size:0.75rem; color:var(--clr-dim); margin-top:0.3rem; padding-left:1.5rem; font-family:var(--font-mono);">`;
            html += `Action: ${context.action} | Method: ${context.method} <br> Data: ${JSON.stringify(context.data)}`;
            html += `</div>`;
        }

        entry.innerHTML = html;
        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    };

    if (startBtn) {
        startBtn.addEventListener('click', async () => {
            const url = targetUrlInput.value.trim();
            if (!url) {
                alert('Please enter a Target URL first.');
                return;
            }

            overrideSection.style.display = 'none';
            paramsContainer.innerHTML = '';

            const logContent = document.getElementById('attack-log');
            if (logContent) logContent.innerHTML = '';

            window.automatedLogCallback(`Initializing Smart Discovery for ${url}...`, 'info');

            currentScanner = new AutomatedXSSScanner(url);
            const success = await currentScanner.discover();

            if (!success) {
                window.automatedLogCallback('Discovery halted. Please check URL or network.', 'error');
                return;
            }

            if (currentScanner.forms.length === 0) {
                window.automatedLogCallback('No forms or URL parameters discovered. Please create parameters manually.', 'warning');
            } else {
                window.automatedLogCallback(`Found ${currentScanner.forms.length} interactive endpoint(s). Generating Interactive Mapping...`, 'success');
            }

            // Prioritize forms with search/query keywords, or the first one
            const form = currentScanner.forms.find(f => f.isSearch) || currentScanner.forms[0] || {
                action: url, method: 'GET', inputs: [] // Empty fallback
            };

            const createParamRow = (nameStr = '', valStr = '', isTarget = false) => {
                const rowId = `param-${Math.random().toString(36).substr(2, 9)}`;
                const row = document.createElement('div');
                row.className = 'param-row';
                row.style.cssText = 'display:flex; gap:0.5rem; align-items:center; background:rgba(0,0,0,0.2); padding:0.5rem; border-radius:4px;';

                row.innerHTML = `
                    <input type="radio" name="xss-target-param" class="param-target" value="${rowId}" ${isTarget ? 'checked' : ''} style="margin:0 0.5rem;">
                    <div style="flex:1;"><input type="text" class="input param-name" value="${nameStr}" placeholder="Param Name" style="width:100%; padding:0.4rem; font-size:0.8rem;"></div>
                    <div style="flex:1;"><input type="text" class="input param-value" value="${valStr}" placeholder="Default Value" style="width:100%; padding:0.4rem; font-size:0.8rem;"></div>
                    <button class="btn btn-ghost rm-param" style="padding:0.3rem;"><i data-lucide="trash-2" style="width:14px;height:14px;color:var(--clr-danger);"></i></button>
                `;

                row.querySelector('.rm-param').addEventListener('click', () => row.remove());
                paramsContainer.appendChild(row);
                if (window.lucide) window.lucide.createIcons();
            };

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
                    createParamRow(input.name, input.value, input.name?.toLowerCase().match(/q|search|query|id|comment/) || (i === 0));
                });
            }

            overrideSection.style.display = 'block';
            overrideSection.scrollIntoView({ behavior: 'smooth' });
            if (window.lucide) window.lucide.createIcons();
        });
    }

    if (addParamBtn) addParamBtn.addEventListener('click', () => {
        // Find existing definition of createParamRow to reuse or duplicate here
        const rowId = `param-${Math.random().toString(36).substr(2, 9)}`;
        const row = document.createElement('div');
        row.className = 'param-row';
        row.style.cssText = 'display:flex; gap:0.5rem; align-items:center; background:rgba(0,0,0,0.2); padding:0.5rem; border-radius:4px;';

        row.innerHTML = `
            <input type="radio" name="xss-target-param" class="param-target" value="${rowId}" style="margin:0 0.5rem;">
            <div style="flex:1;"><input type="text" class="input param-name" value="" placeholder="Param Name" style="width:100%; padding:0.4rem; font-size:0.8rem;"></div>
            <div style="flex:1;"><input type="text" class="input param-value" value="" placeholder="Default Value" style="width:100%; padding:0.4rem; font-size:0.8rem;"></div>
            <button class="btn btn-ghost rm-param" style="padding:0.3rem;"><i data-lucide="trash-2" style="width:14px;height:14px;color:var(--clr-danger);"></i></button>
        `;

        row.querySelector('.rm-param').addEventListener('click', () => row.remove());
        paramsContainer.appendChild(row);
        if (window.lucide) window.lucide.createIcons();
    });

    if (resumeBtn) {
        resumeBtn.addEventListener('click', async () => {
            const overrideData = {};
            let targetField = '';

            const targetAction = document.getElementById('hud-target-action').value.trim();
            const targetMethod = document.getElementById('hud-target-method').value;

            paramsContainer.querySelectorAll('.param-row').forEach(row => {
                const name = row.querySelector('.param-name').value.trim();
                const value = row.querySelector('.param-value').value;
                if (name) {
                    overrideData[name] = value;
                    if (row.querySelector('.param-target').checked) targetField = name;
                }
            });

            if (!targetField) { alert('Select a target parameter.'); return; }

            overrideSection.style.display = 'none';
            window.automatedLogCallback(`Auditing ${targetAction} [${targetMethod}] — injecting "${targetField}"...`, 'info');

            // Pass the configuration to the global XSSScanner instance
            if (window.xssScannerInstance) {
                window.xssScannerInstance.targetUrl = targetAction;
                window.xssScannerInstance.httpMethod = targetMethod;
                window.xssScannerInstance.paramName = targetField;
                window.xssScannerInstance.overrideData = overrideData;
                window.xssScannerInstance.startScan(true); // Trigger the main scanner loop with overrides
            } else {
                window.automatedLogCallback('Error: XSSScanner instance not found.', 'error');
            }
        });
    }
});
