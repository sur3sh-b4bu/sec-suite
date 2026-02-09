// CyberSec Suite - Shared PDF Report Generator
// Professional PDF export for all scanner modules

class CyberSecPDFReport {
    constructor(options = {}) {
        this.title = options.title || 'Security Scan Report';
        this.scannerName = options.scannerName || 'Security Scanner';
        this.targetUrl = options.targetUrl || '';
        this.vulnerabilities = options.vulnerabilities || [];
        this.stats = options.stats || {};
    }

    async generate() {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            // Header
            this.drawHeader(doc);

            // Summary
            let y = this.drawSummary(doc, 50);

            // Vulnerabilities
            y = this.drawVulnerabilities(doc, y + 15);

            // Footer on all pages
            this.drawFooter(doc);

            // Save
            const filename = `${this.scannerName.toLowerCase().replace(/\s+/g, '-')}-report-${Date.now()}.pdf`;
            doc.save(filename);

            return { success: true, filename };
        } catch (error) {
            console.error('PDF Generation Error:', error);
            return { success: false, error: error.message };
        }
    }

    drawHeader(doc) {
        // Dark header background
        doc.setFillColor(15, 23, 42);
        doc.rect(0, 0, 210, 40, 'F');

        // Accent line
        doc.setFillColor(139, 92, 246);
        doc.rect(0, 40, 210, 2, 'F');

        // Title
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(22);
        doc.setFont('helvetica', 'bold');
        doc.text(this.title.toUpperCase(), 105, 18, { align: 'center' });

        // Subtitle
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.text('CyberSec Suite Security Assessment', 105, 28, { align: 'center' });
        doc.text(`Generated: ${new Date().toLocaleString()}`, 105, 35, { align: 'center' });
    }

    drawSummary(doc, startY) {
        let y = startY;

        // Section title
        doc.setTextColor(30, 41, 59);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('SCAN SUMMARY', 20, y);

        // Summary box
        doc.setDrawColor(139, 92, 246);
        doc.setLineWidth(0.5);
        doc.roundedRect(15, y + 5, 180, 35, 3, 3, 'S');

        y += 15;
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);

        doc.text(`Target URL: ${this.targetUrl || 'N/A'}`, 20, y);
        y += 7;
        doc.text(`Scanner: ${this.scannerName}`, 20, y);
        y += 7;

        // Stats
        const vulnCount = this.vulnerabilities.length;
        const criticalCount = this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
        const highCount = this.vulnerabilities.filter(v => v.severity === 'HIGH').length;

        doc.text(`Total Findings: ${vulnCount}`, 20, y);
        doc.text(`Critical: ${criticalCount}`, 80, y);
        doc.text(`High: ${highCount}`, 120, y);

        return y + 20;
    }

    drawVulnerabilities(doc, startY) {
        let y = startY;

        // Section title
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(30, 41, 59);
        doc.text('DISCOVERED VULNERABILITIES', 20, y);
        y += 3;

        // Line
        doc.setDrawColor(100, 116, 139);
        doc.setLineWidth(0.3);
        doc.line(20, y, 190, y);
        y += 10;

        if (this.vulnerabilities.length === 0) {
            doc.setFontSize(10);
            doc.setFont('helvetica', 'italic');
            doc.setTextColor(100, 116, 139);
            doc.text('No vulnerabilities discovered during this scan.', 20, y);
            return y + 20;
        }

        // Each vulnerability
        this.vulnerabilities.forEach((vuln, index) => {
            // Check for page break
            if (y > 250) {
                doc.addPage();
                y = 20;
            }

            // Severity badge
            this.drawSeverityBadge(doc, 20, y - 4, vuln.severity);

            // Title
            doc.setTextColor(30, 41, 59);
            doc.setFontSize(11);
            doc.setFont('helvetica', 'bold');
            doc.text(`#${index + 1} - ${vuln.name || vuln.type || 'Vulnerability'}`, 45, y);
            y += 8;

            // Details
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(71, 85, 105);

            if (vuln.path || vuln.payload) {
                const path = vuln.path || vuln.payload || '';
                const truncatedPath = path.length > 70 ? path.substring(0, 67) + '...' : path;
                doc.text(`Path/Payload: ${truncatedPath}`, 25, y);
                y += 5;
            }

            if (vuln.description) {
                const descLines = doc.splitTextToSize(vuln.description, 160);
                descLines.slice(0, 2).forEach(line => {
                    doc.text(line, 25, y);
                    y += 4;
                });
            }

            // Evidence/Data
            if (vuln.evidence || vuln.disclosedData || vuln.response) {
                doc.setFont('helvetica', 'bold');
                doc.text('Evidence:', 25, y);
                y += 4;
                doc.setFont('courier', 'normal');
                doc.setFontSize(8);
                doc.setTextColor(239, 68, 68);

                const evidence = vuln.evidence || vuln.disclosedData || vuln.response || '';
                const evidenceLines = evidence.split('\n').slice(0, 3);
                evidenceLines.forEach(line => {
                    if (y > 270) { doc.addPage(); y = 20; }
                    doc.text(line.substring(0, 80), 25, y);
                    y += 4;
                });
                y += 2;
            }

            // Impact
            if (vuln.impact) {
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(9);
                doc.setTextColor(239, 68, 68);
                doc.text('Impact:', 25, y);
                y += 4;
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(71, 85, 105);

                const impacts = Array.isArray(vuln.impact) ? vuln.impact : [vuln.impact];
                impacts.slice(0, 3).forEach(impact => {
                    doc.text(`• ${impact}`, 28, y);
                    y += 4;
                });
            }

            // Remediation
            if (vuln.remediation) {
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(9);
                doc.setTextColor(16, 185, 129);
                doc.text('Remediation:', 25, y);
                y += 4;
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(71, 85, 105);

                const remLines = doc.splitTextToSize(vuln.remediation, 155);
                remLines.slice(0, 2).forEach(line => {
                    doc.text(line, 25, y);
                    y += 4;
                });
            }

            y += 6;

            // Separator
            doc.setDrawColor(226, 232, 240);
            doc.setLineWidth(0.2);
            doc.line(25, y - 3, 185, y - 3);
        });

        return y;
    }

    drawSeverityBadge(doc, x, y, severity) {
        const colors = {
            'CRITICAL': [239, 68, 68],
            'HIGH': [249, 115, 22],
            'MEDIUM': [234, 179, 8],
            'LOW': [34, 197, 94],
            'INFO': [59, 130, 246]
        };

        const color = colors[severity] || colors['INFO'];
        doc.setFillColor(...color);
        doc.roundedRect(x, y, 22, 7, 2, 2, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.text(severity || 'N/A', x + 11, y + 5, { align: 'center' });
    }

    drawFooter(doc) {
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);

            // Footer line
            doc.setDrawColor(139, 92, 246);
            doc.setLineWidth(0.5);
            doc.line(20, 285, 190, 285);

            // Footer text
            doc.setFontSize(8);
            doc.setTextColor(148, 163, 184);
            doc.setFont('helvetica', 'normal');
            doc.text('CyberSec Suite | Security Assessment Report', 20, 290);
            doc.text(`Page ${i} of ${pageCount}`, 190, 290, { align: 'right' });
        }
    }
}

// Shared Results Renderer
class CyberSecResultsRenderer {
    static render(containerSelector, vulnerabilities, options = {}) {
        const container = document.querySelector(containerSelector);
        if (!container) return;

        container.innerHTML = '';

        if (vulnerabilities.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 3rem; color: #94a3b8;">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin: 0 auto 1rem;">
                        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <p style="font-size: 1.1rem;">No vulnerabilities discovered</p>
                    <p style="font-size: 0.9rem; opacity: 0.7;">The target appears to be secure against tested vectors</p>
                </div>
            `;
            return;
        }

        vulnerabilities.forEach((vuln, index) => {
            const card = document.createElement('div');
            card.className = 'vuln-card';

            // Build evidence HTML
            let evidenceHtml = '';
            if (vuln.evidence || vuln.disclosedData || vuln.response) {
                const evidence = vuln.evidence || vuln.disclosedData || vuln.response;
                evidenceHtml = `<div class="disclosed-data">${this.escapeHtml(evidence)}</div>`;
            }

            // Build headers HTML
            if (vuln.headers && Array.isArray(vuln.headers)) {
                evidenceHtml = `<div class="header-list">${vuln.headers.map(h =>
                    `<span class="header-badge">${this.escapeHtml(h)}</span>`
                ).join('')}</div>`;
            }

            // Build impact HTML
            let impactHtml = '';
            if (vuln.impact) {
                const impacts = Array.isArray(vuln.impact) ? vuln.impact : [vuln.impact];
                impactHtml = `
                    <div style="margin-bottom: 0.75rem;">
                        <strong style="color: #f87171;">Potential Impact:</strong>
                        <ul style="margin: 0.5rem 0 0 1.25rem; color: #94a3b8; line-height: 1.8;">
                            ${impacts.map(i => `<li>${this.escapeHtml(i)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            card.innerHTML = `
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span style="color: var(--clr-accent, #8b5cf6);">#${index + 1}</span> 
                        ${this.escapeHtml(vuln.name || vuln.type || 'Vulnerability')}
                    </div>
                    <span class="severity-badge ${(vuln.severity || 'INFO').toLowerCase()}">${vuln.severity || 'INFO'}</span>
                </div>
                ${vuln.type ? `<span class="leak-type-badge ${vuln.type}">${vuln.type.toUpperCase()}</span>` : ''}
                <div style="color: #94a3b8; margin: 1rem 0; line-height: 1.6;">
                    ${vuln.path || vuln.payload ? `
                        <div style="margin-bottom: 0.5rem;">
                            <strong style="color: #e2e8f0;">Path/Payload:</strong> 
                            <code style="background: rgba(139, 92, 246, 0.2); padding: 0.25rem 0.5rem; border-radius: 4px; color: #a78bfa; word-break: break-all;">${this.escapeHtml(vuln.path || vuln.payload)}</code>
                        </div>
                    ` : ''}
                    ${vuln.description ? `<div>${this.escapeHtml(vuln.description)}</div>` : ''}
                </div>
                ${evidenceHtml}
                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
                    ${impactHtml}
                    ${vuln.remediation ? `
                        <div>
                            <strong style="color: #34d399;">Remediation:</strong>
                            <p style="margin: 0.5rem 0 0 0; color: #94a3b8;">${this.escapeHtml(vuln.remediation)}</p>
                        </div>
                    ` : ''}
                </div>
            `;

            container.appendChild(card);
        });
    }

    static escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Export for use
window.CyberSecPDFReport = CyberSecPDFReport;
window.CyberSecResultsRenderer = CyberSecResultsRenderer;

console.log('📄 CyberSec Suite PDF Report Generator loaded');
