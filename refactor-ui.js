const fs = require('fs');
const path = require('path');

const htmlDir = path.join(__dirname, 'html');
const jsDir = path.join(__dirname, 'js');

const htmlFiles = fs.readdirSync(htmlDir).filter(f => f.endsWith('.html') && f !== 'index.html' && f !== 'sqli.html' && f !== 'xss.html');

// The replacement HTML blocks for the Smart Discovery UI
const targetConfigRegex = /<div class="config-grid">[\s\S]*?<label for="target-url">Target [^<]+<\/label>[\s\S]*?<input type="url" id="target-url" class="input"[^>]+>[\s\S]*?<\/div>[\s\S]*?<div class="form-group">[\s\S]*?<label for="http-method">[^<]+<\/label>[\s\S]*?<select id="http-method" class="input">[\s\S]*?<\/select>[\s\S]*?<\/div>[\s\S]*?<\/div>[\s\S]*?<div class="form-group"[^>]*>[\s\S]*?<label for="vuln-param">[^<]+<\/label>[\s\S]*?<input type="text" id="vuln-param" class="input"[^>]+>[\s\S]*?<\/div>/i;

const replacementConfigHTML = `
                <div class="config-grid">
                    <div class="form-group" style="grid-column: span 2;">
                        <label for="target-url">Target Endpoint URL</label>
                        <input type="url" id="target-url" class="input" placeholder="https://api.system.com/endpoint?param=test">
                    </div>
                </div>`;

const scanControlsRegex = /<div class="scan-controls">[\s\S]*?<button id="start-scan-btn" class="btn btn-primary btn-lg">[\s\S]*?<svg[^>]+>[\s\S]*?<\/svg>[\s\S]*?Initialize [^<]+<\/button>[\s\S]*?<button id="stop-scan-btn"[^>]+>Terminate Sequence<\/button>[\s\S]*?<\/div>/i;

const replacementControlsHTML = `
                <div class="scan-controls" style="margin-top:2rem;">
                    <button id="automated-scan-btn" class="btn btn-accent btn-lg" style="background: var(--clr-secondary);">
                        <i data-lucide="bot" style="margin-right: 10px;"></i> Start Smart Discovery
                    </button>
                    <!-- Legacy buttons kept hidden for programmatic access -->
                    <button id="start-scan-btn" style="display:none;">Initialize Audit</button>
                    <button id="stop-scan-btn" class="btn btn-danger" style="display:none;">Terminate Sequence</button>
                </div>
            </div>

            <!-- Form Parameter Override Section (Smart Discovery) -->
            <div id="form-override-section" class="card" style="display:none; margin: 1.5rem 0; background: rgba(0,0,0,0.3); border: 1px dashed var(--clr-accent);">
                <div class="card-header" style="padding: 1rem;">
                    <h4 style="font-size:0.9rem; color:var(--clr-accent); margin:0;">📋 INTERACTIVE FORM MAPPING</h4>
                    <small style="color:var(--clr-dim);">Verify or correct the discovered parameters below.</small>
                    <span id="security-status" style="font-size:0.65rem; padding: 2px 6px; border-radius: 4px; background: rgba(0,0,0,0.3); color: var(--clr-dim); font-family:var(--font-mono); margin-left: auto;">STANDBY</span>
                </div>
                <div id="form-params-container" style="padding: 1rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                </div>
                <div style="padding: 1rem; text-align: right; border-top: 1px solid rgba(255,255,255,0.1);">
                    <button id="add-param-btn" class="btn btn-outline" style="font-size: 0.75rem; padding: 0.4rem 0.8rem; margin-right: 8px;">
                        <i data-lucide="plus" style="width:14px; height:14px; margin-right:4px;"></i> Add Manual Param
                    </button>
                    <button id="resume-audit-btn" class="btn btn-success">
                        <i data-lucide="play" style="margin-right:8px;"></i> Continue Attack Sequence
                    </button>
                </div>
            </div>`;


console.log(`Found ${htmlFiles.length} HTML modules to process.`);

let successCount = 0;

for (const file of htmlFiles) {
    const htmlPath = path.join(htmlDir, file);
    let htmlContent = fs.readFileSync(htmlPath, 'utf8');

    // 1. Replace the top config inputs
    if (targetConfigRegex.test(htmlContent)) {
        htmlContent = htmlContent.replace(targetConfigRegex, replacementConfigHTML);
    } else {
        console.log(`[!] Regex miss for target config in ${file}`);
        continue; // Skip if structure entirely different
    }

    // 2. Replace the scan buttons with Smart Discovery + Hidden legacy
    if (scanControlsRegex.test(htmlContent)) {
        htmlContent = htmlContent.replace(scanControlsRegex, replacementControlsHTML);
    } else {
        console.log(`[!] Regex miss for scan controls in ${file}`);
        continue;
    }

    // 3. Inject the Automated Script tag
    const scriptTag = `<script src="../js/automated-xss.js"></script>\n    <script src="../js/${file.replace('.html', '-scanner.js')}"></script>`;
    const scannerScriptRegex = new RegExp(`<script src="\\.\\.\\/js\\/${file.replace('.html', '-scanner.js')}"><\\/script>`);

    if (scannerScriptRegex.test(htmlContent)) {
        htmlContent = htmlContent.replace(scannerScriptRegex, scriptTag);
    }

    fs.writeFileSync(htmlPath, htmlContent);
    successCount++;
}

console.log(`Successfully updated ${successCount} HTML files!`);

// Note: JS refactoring logic omitted for brevity in this initial test script
// because different scanners have radically different startScan() logic.
