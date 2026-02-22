import os
import re

html_dir = os.path.join(os.path.dirname(__file__), 'html')

html_files = [f for f in os.listdir(html_dir) if f.endswith('.html') and f not in ['index.html', 'sqli.html', 'xss.html']]

target_config_regex = re.compile(
    r'<div class="config-grid">[\s\S]*?<label for="target-url">Target [^<]+</label>[\s\S]*?<input type="url" id="target-url" class="input"[^>]+>[\s\S]*?</div>[\s\S]*?<div class="form-group">[\s\S]*?<label for="http-method">[^<]+</label>[\s\S]*?<select id="http-method" class="input">[\s\S]*?</select>[\s\S]*?</div>[\s\S]*?</div>[\s\S]*?<div class="form-group"[^>]*>[\s\S]*?<label for="vuln-param">[^<]+</label>[\s\S]*?<input type="text" id="vuln-param" class="input"[^>]+>[\s\S]*?</div>',
    re.IGNORECASE
)

replacement_config_html = """
                <div class="config-grid">
                    <div class="form-group" style="grid-column: span 2;">
                        <label for="target-url">Target Endpoint URL</label>
                        <input type="url" id="target-url" class="input" placeholder="https://api.system.com/endpoint?param=test">
                    </div>
                </div>"""

scan_controls_regex = re.compile(
    r'<div class="scan-controls">[\s\S]*?<button id="start-scan-btn" class="btn btn-primary btn-lg">[\s\S]*?<svg[^>]+>[\s\S]*?</svg>[\s\S]*?Initialize [^<]+</button>[\s\S]*?<button id="stop-scan-btn"[^>]+>Terminate Sequence</button>[\s\S]*?</div>',
    re.IGNORECASE
)

replacement_controls_html = """
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
            </div>"""

print(f"Found {len(html_files)} HTML modules to process.")
success_count = 0

for file_name in html_files:
    file_path = os.path.join(html_dir, file_name)
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Replace config inputs
    if target_config_regex.search(content):
        content = target_config_regex.sub(replacement_config_html, content)
    else:
        print(f"[!] Regex miss for target config in {file_name}")
        continue

    # 2. Replace scan controls
    if scan_controls_regex.search(content):
        content = scan_controls_regex.sub(replacement_controls_html, content)
    else:
        print(f"[!] Regex miss for scan controls in {file_name}")
        continue

    # 3. Inject js/automated-xss.js right before the specific module scanner
    scanner_name = file_name.replace('.html', '-scanner.js')
    script_regex = re.compile(rf'<script src="\.\./js/{scanner_name}"></script>')
    if script_regex.search(content):
        replacement_script = f'<script src="../js/automated-xss.js"></script>\n    <script src="../js/{scanner_name}"></script>'
        content = script_regex.sub(replacement_script, content)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    success_count += 1

print(f"Successfully updated {success_count} HTML files!")
