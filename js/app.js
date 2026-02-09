// Main Application Module
import { authManager } from './auth.js';
import { analyzer } from './analyzer.js';
import { patternsManager } from './patterns.js';
import { historyManager } from './history.js';

class App {
    constructor() {
        this.currentSection = 'analyzer';
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupKeyboardShortcuts();
        this.displayWelcomeMessage();
    }

    setupNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        const sections = document.querySelectorAll('.section');

        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('href').substring(1);

                // Update active link
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');

                // Show target section
                sections.forEach(section => {
                    if (section.id === targetId) {
                        section.style.display = 'block';
                        this.currentSection = targetId;

                        // Trigger section-specific actions
                        this.onSectionChange(targetId);
                    } else {
                        section.style.display = 'none';
                    }
                });

                // Scroll to top
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        });
    }

    onSectionChange(sectionId) {
        switch (sectionId) {
            case 'patterns':
                patternsManager.displayPatterns();
                break;
            case 'history':
                if (authManager.currentUser) {
                    historyManager.loadHistory();
                }
                break;
            case 'docs':
                this.loadDocumentation();
                break;
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to analyze
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (this.currentSection === 'analyzer') {
                    const analyzeBtn = document.getElementById('analyzeBtn');
                    if (analyzeBtn) analyzeBtn.click();
                }
            }

            // Ctrl/Cmd + S to save
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                const saveBtn = document.getElementById('saveResultsBtn');
                if (saveBtn && saveBtn.offsetParent !== null) {
                    saveBtn.click();
                }
            }
        });
    }

    displayWelcomeMessage() {
        console.log('%c🔐 CyberSec Suite Auth Vulnerability Tester', 'font-size: 20px; font-weight: bold; color: #6366f1;');
        console.log('%cWelcome to the automated vulnerability analysis platform!', 'font-size: 14px; color: #10b981;');
        console.log('%c\nKeyboard Shortcuts:', 'font-size: 12px; font-weight: bold;');
        console.log('%c  Ctrl/Cmd + Enter: Analyze vulnerability', 'font-size: 12px;');
        console.log('%c  Ctrl/Cmd + S: Save results', 'font-size: 12px;');
        console.log('%c\nFor educational purposes only. Use responsibly!', 'font-size: 12px; color: #f59e0b;');
    }

    loadDocumentation() {
        // Documentation is already in HTML, but we can enhance it
        const docsContent = document.querySelector('#docs .docs-content');
        if (!docsContent) return;

        // Add additional documentation cards if needed
        const additionalDocs = `
            <div class="card" style="margin-top: 24px;">
                <div class="card-header">
                    <h3 class="card-title">Supported Vulnerability Types</h3>
                </div>
                <div class="card-body">
                    <ul class="docs-list">
                        <li><strong>Username Enumeration:</strong> Timing-based, message-based, and subtle response differences</li>
                        <li><strong>Brute-Force Attacks:</strong> Password guessing, rate limit bypass, account lockout bypass</li>
                        <li><strong>Multi-Factor Authentication:</strong> 2FA bypass, broken logic, brute-force</li>
                        <li><strong>Password Reset:</strong> Host header poisoning, token leakage</li>
                        <li><strong>Session Handling:</strong> Stay-logged-in cookies, offline password cracking</li>
                        <li><strong>Logic Flaws:</strong> Password change vulnerabilities, parameter manipulation</li>
                    </ul>
                </div>
            </div>

            <div class="card" style="margin-top: 24px;">
                <div class="card-header">
                    <h3 class="card-title">Tips for Best Results</h3>
                </div>
                <div class="card-body">
                    <ul class="docs-list">
                        <li>Include complete HTTP headers in your request/response</li>
                        <li>Paste the full lab description for better pattern matching</li>
                        <li>For timing-based attacks, include multiple request/response pairs</li>
                        <li>Sign in to save your analysis history</li>
                        <li>Review the "Lab Patterns" section to understand detection criteria</li>
                        <li>Always test on authorized targets only (CyberSec Suite labs)</li>
                    </ul>
                </div>
            </div>

            <div class="card" style="margin-top: 24px;">
                <div class="card-header">
                    <h3 class="card-title">Firebase & Google Cloud Features</h3>
                </div>
                <div class="card-body">
                    <ul class="docs-list">
                        <li><strong>Authentication:</strong> Secure Google Sign-In via Firebase Auth</li>
                        <li><strong>Database:</strong> Analysis history stored in Cloud Firestore</li>
                        <li><strong>Storage:</strong> Request/response files saved in Cloud Storage</li>
                        <li><strong>Hosting:</strong> Global CDN delivery via Firebase Hosting</li>
                        <li><strong>Security:</strong> Firestore security rules protect user data</li>
                        <li><strong>Scalability:</strong> Serverless architecture scales automatically</li>
                    </ul>
                </div>
            </div>
        `;

        // Only add if not already present
        if (!docsContent.querySelector('.card:nth-child(2)')) {
            docsContent.insertAdjacentHTML('beforeend', additionalDocs);
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new App();

    // Make analyzer available globally for history module
    window.analyzer = analyzer;

    console.log('Application initialized successfully');
});

export { App };
