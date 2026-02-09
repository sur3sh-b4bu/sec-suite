// Lab Patterns Module
import { authManager } from './auth.js';
import { db, collection, getDocs } from './firebase-config.js';

class PatternsManager {
    constructor() {
        this.patterns = [];
        this.init();
    }

    async init() {
        // Load patterns from Firestore or use defaults
        this.patterns = this.getDefaultPatterns();
    }

    getDefaultPatterns() {
        return [
            {
                id: 1,
                name: 'Username Enumeration via Response Timing',
                category: 'Brute Force',
                description: 'Application response time differs based on whether username exists',
                indicators: ['Timing differences', 'Response delays', 'Variable processing time'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 2,
                name: 'Username Enumeration via Different Responses',
                category: 'Brute Force',
                description: 'Error messages reveal whether username exists',
                indicators: ['Different error messages', 'Invalid username vs incorrect password'],
                difficulty: 'Apprentice',
                color: '#10b981'
            },
            {
                id: 3,
                name: 'Username Enumeration via Subtly Different Responses',
                category: 'Brute Force',
                description: 'Subtle differences in responses (e.g., extra space, punctuation)',
                indicators: ['Content-Length differences', 'Minor HTML variations'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 4,
                name: 'Broken Brute-Force Protection (IP Block)',
                category: 'Brute Force',
                description: 'IP-based rate limiting can be bypassed',
                indicators: ['X-Forwarded-For header', 'IP rotation', 'Rate limit bypass'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 5,
                name: 'Broken Brute-Force Protection (Account Lock)',
                category: 'Brute Force',
                description: 'Account lockout can be bypassed by inserting valid credentials',
                indicators: ['Account lockout', 'Valid login resets counter'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 6,
                name: '2FA Simple Bypass',
                category: 'Multi-Factor Authentication',
                description: '2FA can be bypassed by directly accessing post-login page',
                indicators: ['Direct URL access', 'Missing verification check'],
                difficulty: 'Apprentice',
                color: '#10b981'
            },
            {
                id: 7,
                name: '2FA Broken Logic',
                category: 'Multi-Factor Authentication',
                description: '2FA verification uses user parameter that can be manipulated',
                indicators: ['User parameter in cookie/request', 'Parameter manipulation'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 8,
                name: '2FA Bypass via Brute Force',
                category: 'Multi-Factor Authentication',
                description: '2FA code can be brute-forced due to missing rate limiting',
                indicators: ['No rate limiting on 2FA', '4-digit code', 'Unlimited attempts'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 9,
                name: 'Password Reset Poisoning',
                category: 'Password Reset',
                description: 'Host header injection in password reset functionality',
                indicators: ['X-Forwarded-Host', 'Host header', 'Reset link generation'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 10,
                name: 'Password Reset Token Leak via Referer',
                category: 'Password Reset',
                description: 'Reset token leaked via Referer header',
                indicators: ['Referer header', 'External resources', 'Token in URL'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 11,
                name: 'Broken "Stay Logged In" Cookie',
                category: 'Session Handling',
                description: 'Stay-logged-in cookie uses weak encoding (base64)',
                indicators: ['Base64 encoded cookie', 'Predictable format', 'username:password'],
                difficulty: 'Apprentice',
                color: '#10b981'
            },
            {
                id: 12,
                name: 'Offline Password Cracking',
                category: 'Session Handling',
                description: 'Cookie contains crackable password hash',
                indicators: ['MD5/SHA1 hash', 'Weak hashing', 'Cookie contains hash'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 13,
                name: 'Password Change Broken Logic',
                category: 'Logic Flaws',
                description: 'Password change doesn\'t verify current password or user',
                indicators: ['Missing current password check', 'User parameter manipulation'],
                difficulty: 'Apprentitioner',
                color: '#10b981'
            },
            {
                id: 14,
                name: 'Password Brute-Force via Password Change',
                category: 'Logic Flaws',
                description: 'Password change reveals current password via error messages',
                indicators: ['Current password verification', 'Error message enumeration'],
                difficulty: 'Practitioner',
                color: '#f59e0b'
            },
            {
                id: 15,
                name: 'OAuth Account Hijacking',
                category: 'OAuth',
                description: 'OAuth flow vulnerable to account hijacking',
                indicators: ['OAuth callback', 'State parameter', 'CSRF'],
                difficulty: 'Expert',
                color: '#ef4444'
            }
        ];
    }

    displayPatterns() {
        const patternsList = document.getElementById('patternsList');
        if (!patternsList) return;

        patternsList.innerHTML = this.patterns.map(pattern => `
            <div class="pattern-card" style="border-left: 4px solid ${pattern.color}">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                    <h3 style="font-size: 1.125rem; font-weight: 600; color: var(--color-text-primary); margin: 0;">
                        ${pattern.name}
                    </h3>
                    <span style="padding: 4px 12px; background: ${pattern.color}; color: white; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">
                        ${pattern.difficulty}
                    </span>
                </div>
                <div style="margin-bottom: 12px;">
                    <span style="display: inline-block; padding: 4px 8px; background: var(--color-bg-secondary); color: var(--color-primary-light); border-radius: 4px; font-size: 0.75rem; font-weight: 500;">
                        ${pattern.category}
                    </span>
                </div>
                <p style="color: var(--color-text-secondary); margin-bottom: 12px; line-height: 1.6;">
                    ${pattern.description}
                </p>
                <div style="margin-top: 12px;">
                    <strong style="color: var(--color-text-secondary); font-size: 0.875rem;">Key Indicators:</strong>
                    <ul style="margin-top: 8px; padding-left: 20px; color: var(--color-text-muted); font-size: 0.875rem;">
                        ${pattern.indicators.map(ind => `<li>${ind}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `).join('');
    }
}

// Initialize patterns manager
const patternsManager = new PatternsManager();

// Display patterns when section is shown
document.addEventListener('DOMContentLoaded', () => {
    const patternsLink = document.querySelector('a[href="#patterns"]');
    if (patternsLink) {
        patternsLink.addEventListener('click', () => {
            setTimeout(() => patternsManager.displayPatterns(), 100);
        });
    }
});

export { patternsManager };
