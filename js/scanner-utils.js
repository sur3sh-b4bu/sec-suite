// CyberSec Suite - Scanner PDF Export Updater
// This script provides standard functions that can be mixed into any scanner

// Standard Result Card HTML Generator
function generateVulnCardHTML(result, index, options = {}) {
    const {
        typeName = result.type || 'Vulnerability',
        severity = result.severity || 'HIGH',
        urlLabel = 'Path/Payload',
        url = result.url || result.path || result.payload || '',
        stats = [],
        evidence = result.evidence || result.payload || result.disclosedData || '',
        impacts = result.impact || [],
        remediation = result.remediation || ''
    } = options;

    let statsHtml = '';
    if (stats.length > 0) {
        statsHtml = `
            <div style="display: flex; gap: 2rem; flex-wrap: wrap; margin-top: 0.75rem;">
                ${stats.map(s => `<span><strong style="color: #e2e8f0;">${s.label}:</strong> ${s.value}</span>`).join('')}
            </div>
        `;
    }

    let impactHtml = '';
    if (impacts.length > 0) {
        impactHtml = `
            <div style="margin-bottom: 0.75rem;">
                <strong style="color: #f87171;">Potential Impact:</strong>
                <ul style="margin: 0.5rem 0 0 1.25rem; color: #94a3b8; line-height: 1.8;">
                    ${impacts.map(i => `<li>${i}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    return `
        <div class="vuln-header">
            <div class="vuln-title">
                <span style="color: var(--clr-accent, #8b5cf6);">#${index + 1}</span> ${typeName}
            </div>
            <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>
        </div>
        <div style="color: #94a3b8; margin: 1rem 0; line-height: 1.6;">
            <div style="margin-bottom: 0.5rem;">
                <strong style="color: #e2e8f0;">${urlLabel}:</strong><br>
                <code style="background: rgba(139, 92, 246, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa; word-break: break-all; display: inline-block; margin-top: 0.25rem;">${url}</code>
            </div>
            ${statsHtml}
        </div>
        ${evidence ? `<div class="disclosed-data">${evidence}</div>` : ''}
        <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
            ${impactHtml}
            ${remediation ? `
                <div>
                    <strong style="color: #34d399;">Remediation:</strong>
                    <p style="margin: 0.5rem 0 0 0; color: #94a3b8;">${remediation}</p>
                </div>
            ` : ''}
        </div>
    `;
}

// Standard Export Function using CyberSecPDFReport
async function exportScanResults(options = {}) {
    const {
        results = [],
        title = 'SECURITY SCAN REPORT',
        scannerName = 'Security Scanner',
        targetUrl = '',
        mapResultToVuln = (r) => r,
        onSuccess = () => { },
        onError = () => { }
    } = options;

    if (results.length === 0) {
        return { success: false, error: 'No results to export' };
    }

    try {
        const vulnerabilities = results.map(mapResultToVuln);

        const report = new CyberSecPDFReport({
            title: title,
            scannerName: scannerName,
            targetUrl: targetUrl,
            vulnerabilities: vulnerabilities
        });

        const result = await report.generate();

        if (result.success) {
            onSuccess();
            return { success: true, filename: result.filename };
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        onError(error);
        return { success: false, error: error.message };
    }
}

// Export for use
window.generateVulnCardHTML = generateVulnCardHTML;
window.exportScanResults = exportScanResults;

console.log('🔧 CyberSec Suite Scanner Utilities loaded');
