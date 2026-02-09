// Information Disclosure Payloads
// Comprehensive payload database for information disclosure testing

const InfoDisclosurePayloads = {
    // Common sensitive files and paths
    sensitiveFiles: [
        { path: '/robots.txt', description: 'Robots exclusion file' },
        { path: '/sitemap.xml', description: 'XML sitemap' },
        { path: '/.git/config', description: 'Git configuration' },
        { path: '/.git/HEAD', description: 'Git HEAD reference' },
        { path: '/.svn/entries', description: 'SVN entries' },
        { path: '/.env', description: 'Environment variables' },
        { path: '/config.php', description: 'PHP configuration' },
        { path: '/wp-config.php', description: 'WordPress config' },
        { path: '/web.config', description: 'IIS configuration' },
        { path: '/phpinfo.php', description: 'PHP info page' },
        { path: '/server-status', description: 'Apache server status' },
        { path: '/debug', description: 'Debug endpoint' },
        { path: '/trace', description: 'Trace endpoint' },
        { path: '/actuator', description: 'Spring Boot actuator' },
        { path: '/actuator/env', description: 'Spring environment' },
        { path: '/actuator/health', description: 'Spring health' },
        { path: '/api/swagger.json', description: 'Swagger API docs' },
        { path: '/swagger-ui.html', description: 'Swagger UI' },
        { path: '/graphql', description: 'GraphQL endpoint' }
    ],

    // Backup files
    backupFiles: [
        { pattern: '.bak', description: 'Backup file' },
        { pattern: '.old', description: 'Old file' },
        { pattern: '.orig', description: 'Original file' },
        { pattern: '.swp', description: 'Vim swap file' },
        { pattern: '~', description: 'Backup tilde' },
        { pattern: '.copy', description: 'Copy file' },
        { pattern: '.backup', description: 'Backup file' },
        { pattern: '.save', description: 'Save file' },
        { pattern: '_backup', description: 'Backup suffix' }
    ],

    // Error-inducing payloads
    errorPayloads: [
        { payload: "'", description: 'Single quote for SQL error' },
        { payload: '"', description: 'Double quote for error' },
        { payload: '{{}}', description: 'Template syntax error' },
        { payload: '${7*7}', description: 'Expression error' },
        { payload: '../../../../../etc/passwd', description: 'Path traversal error' },
        { payload: 'undefined', description: 'Undefined reference' },
        { payload: 'null', description: 'Null reference' },
        { payload: '[]', description: 'Empty array' },
        { payload: '{}', description: 'Empty object' }
    ],

    // Debug parameters
    debugParams: [
        { param: 'debug', values: ['true', '1', 'on', 'yes'] },
        { param: 'test', values: ['true', '1'] },
        { param: 'verbose', values: ['true', '1'] },
        { param: 'trace', values: ['true', '1'] },
        { param: 'dev', values: ['true', '1'] }
    ],

    // HTTP methods for info disclosure
    httpMethods: [
        'TRACE',
        'TRACK',
        'OPTIONS',
        'DEBUG'
    ],

    // Headers that may reveal information
    infoHeaders: [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Runtime',
        'X-Version',
        'X-Generator',
        'Via',
        'X-Backend-Server',
        'X-Debug-Token',
        'X-Debug-Token-Link'
    ],

    // Source code disclosure paths
    sourceCodePaths: [
        { path: '/index.php~', description: 'PHP backup' },
        { path: '/index.php.bak', description: 'PHP backup' },
        { path: '/app.py.swp', description: 'Python swap' },
        { path: '/config.yml.old', description: 'Config backup' },
        { path: '/.DS_Store', description: 'macOS metadata' },
        { path: '/Thumbs.db', description: 'Windows thumbnails' }
    ],

    // Version control exposure
    versionControl: [
        { path: '/.git/', type: 'Git' },
        { path: '/.svn/', type: 'SVN' },
        { path: '/.hg/', type: 'Mercurial' },
        { path: '/.bzr/', type: 'Bazaar' },
        { path: '/CVS/', type: 'CVS' }
    ],

    // Error message indicators
    errorIndicators: [
        'stack trace',
        'exception',
        'error in',
        'syntax error',
        'parse error',
        'warning:',
        'notice:',
        'fatal error',
        'undefined index',
        'undefined variable',
        'SQL syntax',
        'mysql_',
        'pg_',
        'ORA-',
        'Microsoft OLE DB',
        'ODBC',
        'Internal Server Error',
        'Debug'
    ]
};

// Helper functions
function getSensitiveFiles() {
    return InfoDisclosurePayloads.sensitiveFiles;
}

function getBackupExtensions() {
    return InfoDisclosurePayloads.backupFiles;
}

function getErrorPayloads() {
    return InfoDisclosurePayloads.errorPayloads;
}

function getDebugParams() {
    return InfoDisclosurePayloads.debugParams;
}

function getPayloadCount() {
    return InfoDisclosurePayloads.sensitiveFiles.length +
        InfoDisclosurePayloads.backupFiles.length +
        InfoDisclosurePayloads.errorPayloads.length +
        InfoDisclosurePayloads.debugParams.length +
        InfoDisclosurePayloads.httpMethods.length +
        InfoDisclosurePayloads.sourceCodePaths.length +
        InfoDisclosurePayloads.versionControl.length;
}

function checkForErrorIndicators(response) {
    const lowerResponse = response.toLowerCase();
    return InfoDisclosurePayloads.errorIndicators.filter(indicator =>
        lowerResponse.includes(indicator.toLowerCase())
    );
}

function generateBackupPaths(originalPath) {
    return InfoDisclosurePayloads.backupFiles.map(ext =>
        originalPath + ext.pattern
    );
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        InfoDisclosurePayloads,
        getSensitiveFiles,
        getBackupExtensions,
        getErrorPayloads,
        getDebugParams,
        getPayloadCount,
        checkForErrorIndicators,
        generateBackupPaths
    };
}
