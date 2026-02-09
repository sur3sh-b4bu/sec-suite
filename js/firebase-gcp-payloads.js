/**
 * Firebase & GCP Security Scanner - Payload Definitions
 * 
 * This file contains all test vectors and payloads for detecting
 * Firebase and GCP misconfigurations in an ethical, non-exploitative manner.
 * 
 * IMPORTANT: These payloads are designed for DETECTION ONLY.
 * They do NOT exploit, brute-force, or bypass authentication illegally.
 */

// =============================================================================
// FIREBASE DETECTION PATTERNS
// =============================================================================

const FIREBASE_DETECTION = {
    // Patterns to detect Firebase usage in frontend JavaScript
    configPatterns: [
        /firebaseConfig\s*=\s*\{[^}]+\}/gi,
        /firebase\.initializeApp\s*\(\s*\{[^}]+\}/gi,
        /initializeApp\s*\(\s*\{[^}]+\}/gi,
        /apiKey\s*:\s*["'][A-Za-z0-9_-]+["']/gi,
        /authDomain\s*:\s*["'][^"']+\.firebaseapp\.com["']/gi,
        /projectId\s*:\s*["'][^"']+["']/gi,
        /databaseURL\s*:\s*["']https:\/\/[^"']+\.firebaseio\.com["']/gi,
        /storageBucket\s*:\s*["'][^"']+\.appspot\.com["']/gi
    ],

    // Firebase SDK URLs to detect
    sdkUrls: [
        'firebase.google.com',
        'firebaseapp.com',
        'firebaseio.com',
        'appspot.com',
        'cloudfunctions.net',
        'firebasestorage.googleapis.com'
    ],

    // Config key patterns
    configKeys: {
        apiKey: /["']?apiKey["']?\s*:\s*["']([A-Za-z0-9_-]+)["']/i,
        authDomain: /["']?authDomain["']?\s*:\s*["']([^"']+)["']/i,
        projectId: /["']?projectId["']?\s*:\s*["']([^"']+)["']/i,
        databaseURL: /["']?databaseURL["']?\s*:\s*["']([^"']+)["']/i,
        storageBucket: /["']?storageBucket["']?\s*:\s*["']([^"']+)["']/i,
        messagingSenderId: /["']?messagingSenderId["']?\s*:\s*["']([^"']+)["']/i,
        appId: /["']?appId["']?\s*:\s*["']([^"']+)["']/i
    }
};

// =============================================================================
// GCP DETECTION PATTERNS
// =============================================================================

const GCP_DETECTION = {
    // Endpoints that indicate GCP usage
    endpointPatterns: [
        /https?:\/\/[a-z0-9-]+\.cloudfunctions\.net\/[a-zA-Z0-9_-]+/gi,
        /https?:\/\/[a-z0-9-]+-[a-z0-9]+\.a\.run\.app/gi,
        /https?:\/\/storage\.googleapis\.com\/[^\/\s"']+/gi,
        /https?:\/\/[^\/\s"']+\.storage\.googleapis\.com/gi,
        /https?:\/\/[a-z0-9-]+\.appspot\.com/gi
    ],

    // GCP API patterns
    apiPatterns: [
        'googleapis.com',
        'cloud.google.com',
        'run.app',
        'cloudfunctions.net'
    ],

    // Metadata endpoint (for SSRF detection only)
    metadataEndpoint: 'http://169.254.169.254/computeMetadata/v1/'
};

// =============================================================================
// FIRESTORE SECURITY TESTS
// =============================================================================

const FIRESTORE_TESTS = {
    // Common collection names to probe for public access
    commonCollections: [
        'users',
        'posts',
        'messages',
        'comments',
        'orders',
        'products',
        'items',
        'data',
        'content',
        'config',
        'settings',
        'profiles',
        'documents',
        'files',
        'uploads',
        'notifications',
        'logs',
        'events',
        'sessions',
        'tokens'
    ],

    // Test document for write access detection
    testDocument: {
        _securityTest: true,
        timestamp: Date.now(),
        source: 'security-scanner',
        type: 'write-permission-test'
    },

    // Build Firestore REST API URL
    buildUrl: (projectId, collectionPath) => {
        return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collectionPath}`;
    },

    // Indicators of successful unauthorized read
    readSuccessIndicators: [
        'documents',
        'fields',
        'createTime',
        'updateTime'
    ],

    // Indicators of access denial
    accessDeniedIndicators: [
        'PERMISSION_DENIED',
        'Missing or insufficient permissions',
        'unauthorized',
        '403',
        '401'
    ]
};

// =============================================================================
// REALTIME DATABASE SECURITY TESTS
// =============================================================================

const RTDB_TESTS = {
    // Common paths to test
    commonPaths: [
        '',  // Root
        'users',
        'data',
        'public',
        'config',
        'messages',
        'posts',
        'content',
        'settings'
    ],

    // Build Realtime Database URL
    buildUrl: (databaseUrl, path = '') => {
        const cleanUrl = databaseUrl.replace(/\/$/, '');
        const cleanPath = path.replace(/^\//, '');
        return `${cleanUrl}/${cleanPath}.json`;
    },

    // Success indicators
    successIndicators: {
        read: ['[', '{', '"'],  // Valid JSON response
        rulesExposed: ['rules', 'read', 'write', 'validate']
    },

    // Failure indicators
    failureIndicators: [
        'Permission denied',
        'null',
        'error'
    ]
};

// =============================================================================
// FIREBASE STORAGE SECURITY TESTS
// =============================================================================

const STORAGE_TESTS = {
    // Common folder paths to test
    commonPaths: [
        '',
        'uploads/',
        'images/',
        'files/',
        'documents/',
        'public/',
        'users/',
        'assets/',
        'media/',
        'data/'
    ],

    // Test file for upload detection
    testFileContent: 'security-test-file-for-upload-permission-check',
    testFileName: '_security_test_upload.txt',

    // Build Storage URL
    buildUrl: (bucket, path = '') => {
        return `https://firebasestorage.googleapis.com/v0/b/${bucket}/o?prefix=${encodeURIComponent(path)}`;
    },

    // Build direct object URL
    buildObjectUrl: (bucket, objectPath) => {
        return `https://firebasestorage.googleapis.com/v0/b/${bucket}/o/${encodeURIComponent(objectPath)}?alt=media`;
    },

    // Success indicators for listing
    listSuccessIndicators: [
        'items',
        'prefixes',
        'name',
        'bucket'
    ],

    // Success indicators for download
    downloadSuccessIndicators: [
        200,
        'content-type',
        'content-length'
    ]
};

// =============================================================================
// CLOUD FUNCTION SECURITY TESTS
// =============================================================================

const CLOUD_FUNCTION_TESTS = {
    // Common function names to discover
    commonFunctionNames: [
        'api',
        'webhook',
        'handler',
        'process',
        'callback',
        'auth',
        'login',
        'register',
        'validateUser',
        'createUser',
        'getUser',
        'updateUser',
        'deleteUser',
        'getData',
        'setData',
        'sendEmail',
        'sendNotification',
        'processPayment',
        'uploadFile',
        'downloadFile'
    ],

    // Test payloads for parameter manipulation
    testPayloads: {
        // Test objects that could reveal parameter handling issues
        emptyObject: {},
        testUserId: { userId: 'test-user-id' },
        testAdmin: { admin: true, role: 'admin' },
        testData: { data: 'test' }
    },

    // Build Cloud Function URL
    buildUrl: (region, projectId, functionName) => {
        return `https://${region}-${projectId}.cloudfunctions.net/${functionName}`;
    },

    // Regions to check
    commonRegions: [
        'us-central1',
        'us-east1',
        'us-west1',
        'europe-west1',
        'asia-east1'
    ],

    // Success indicators (unauthenticated access)
    unauthAccessIndicators: [
        200,
        201,
        'application/json',
        'text/html'
    ],

    // Indicators of proper auth enforcement
    authEnforcedIndicators: [
        401,
        403,
        'Unauthorized',
        'Forbidden',
        'authentication required',
        'missing authentication'
    ]
};

// =============================================================================
// ANONYMOUS AUTH ABUSE TESTS
// =============================================================================

const ANONYMOUS_AUTH_TESTS = {
    // Test scenarios for anonymous auth misuse
    scenarios: [
        {
            name: 'Anonymous User Creation',
            description: 'Check if anonymous auth is enabled',
            type: 'creation'
        },
        {
            name: 'Anonymous to Privileged Escalation',
            description: 'Check if anonymous users can access privileged resources',
            type: 'escalation'
        },
        {
            name: 'Anonymous Data Access',
            description: 'Check if anonymous users can access user-specific data',
            type: 'dataAccess'
        }
    ],

    // Indicators of problematic anonymous auth
    vulnerabilityIndicators: [
        'anonymous user created',
        'uid',
        'accessToken',
        'idToken'
    ]
};

// =============================================================================
// UID TRUST ABUSE TESTS
// =============================================================================

const UID_TRUST_TESTS = {
    // Test UID values
    testUIDs: [
        'test-uid-1234',
        'admin',
        'root',
        'system',
        '00000000-0000-0000-0000-000000000000',
        '../admin',
        'user/../admin'
    ],

    // Scenarios to test
    scenarios: [
        {
            name: 'UID in URL Path',
            description: 'Client-provided UID used directly in database path',
            testPattern: '/users/{uid}/data'
        },
        {
            name: 'UID in Request Body',
            description: 'UID from request body trusted without verification',
            testPattern: '{ "uid": "attacker-controlled" }'
        },
        {
            name: 'UID Header Injection',
            description: 'UID passed via custom header',
            testPattern: 'X-User-ID: attacker-uid'
        }
    ]
};

// =============================================================================
// GCP CLOUD STORAGE TESTS
// =============================================================================

const GCS_TESTS = {
    // Common bucket naming patterns
    bucketPatterns: [
        '{projectId}',
        '{projectId}-public',
        '{projectId}-data',
        '{projectId}-uploads',
        '{projectId}-assets',
        '{projectId}-backup',
        '{projectId}-staging',
        '{projectId}-prod'
    ],

    // Build GCS list URL
    buildListUrl: (bucket) => {
        return `https://storage.googleapis.com/storage/v1/b/${bucket}/o`;
    },

    // Build direct object URL
    buildObjectUrl: (bucket, object) => {
        return `https://storage.googleapis.com/${bucket}/${object}`;
    },

    // Public access indicators
    publicAccessIndicators: [
        'items',
        'kind',
        'storage#objects'
    ],

    // Access controlled indicators
    accessControlledIndicators: [
        'AccessDeniedException',
        403,
        401,
        'Anonymous caller does not have'
    ]
};

// =============================================================================
// SSRF TO METADATA DETECTION
// =============================================================================

const SSRF_METADATA_TESTS = {
    // This module only checks for SSRF sinks, does NOT attempt to exploit

    // URL fetch indicators in JavaScript
    urlFetchIndicators: [
        'fetch(',
        'axios.',
        'XMLHttpRequest',
        'http.get',
        'request(',
        'got(',
        'superagent'
    ],

    // Parameters that commonly accept URLs
    urlParameters: [
        'url',
        'link',
        'href',
        'src',
        'source',
        'redirect',
        'return',
        'callback',
        'next',
        'target',
        'destination',
        'uri',
        'path',
        'file',
        'load',
        'fetch'
    ],

    // Safe test URL (not metadata - for detection only)
    safeTestUrl: 'https://example.com/ssrf-test-indicator',

    // Metadata URL patterns (for report only, not for exploitation)
    metadataPatterns: [
        '169.254.169.254',
        'metadata.google.internal'
    ]
};

// =============================================================================
// ENVIRONMENT VARIABLE LEAKAGE DETECTION
// =============================================================================

const ENV_LEAK_TESTS = {
    // Endpoints that commonly expose env vars
    commonLeakEndpoints: [
        '/debug',
        '/env',
        '/config',
        '/settings',
        '/info',
        '/status',
        '/health',
        '/healthz',
        '/version',
        '/.env',
        '/phpinfo.php',
        '/server-status',
        '/actuator/env',
        '/actuator/configprops'
    ],

    // Response patterns indicating env var exposure
    leakIndicators: [
        'GOOGLE_CLOUD_PROJECT',
        'FIREBASE_CONFIG',
        'DATABASE_URL',
        'API_KEY',
        'SECRET',
        'PASSWORD',
        'TOKEN',
        'PRIVATE_KEY',
        'AWS_',
        'GCP_',
        'FIREBASE_'
    ],

    // Safe indicators (not leaking)
    safeIndicators: [
        '404',
        'Not Found',
        'Cannot GET',
        '403',
        'Forbidden'
    ]
};

// =============================================================================
// SIGNED URL DETECTION
// =============================================================================

const SIGNED_URL_TESTS = {
    // Patterns to detect signed URLs
    signedUrlPatterns: [
        /https:\/\/storage\.googleapis\.com\/[^?]+\?.*Signature=/gi,
        /https:\/\/[^\/]+\.storage\.googleapis\.com\/[^?]+\?.*Signature=/gi,
        /GoogleAccessId=/gi,
        /X-Goog-Signature=/gi
    ],

    // Parameters that indicate overly permissive signed URLs
    permissiveIndicators: [
        // Expiry far in the future (over 7 days)
        'Expires=',
        // Content disposition allowing any download
        'response-content-disposition='
    ],

    // Check expiry timestamp
    checkExpiry: (expiryTimestamp) => {
        const now = Math.floor(Date.now() / 1000);
        const sevenDays = 7 * 24 * 60 * 60;
        return (expiryTimestamp - now) > sevenDays;
    }
};

// =============================================================================
// SEVERITY DEFINITIONS
// =============================================================================

const SEVERITY = {
    CRITICAL: {
        level: 'critical',
        score: 9.0,
        color: '#ef4444',
        description: 'Immediate exploitation possible with severe impact'
    },
    HIGH: {
        level: 'high',
        score: 7.0,
        color: '#f97316',
        description: 'Significant security risk requiring urgent attention'
    },
    MEDIUM: {
        level: 'medium',
        score: 5.0,
        color: '#f59e0b',
        description: 'Moderate security risk with potential for escalation'
    },
    LOW: {
        level: 'low',
        score: 3.0,
        color: '#3b82f6',
        description: 'Low security impact, informational finding'
    },
    INFO: {
        level: 'info',
        score: 0.0,
        color: '#06b6d4',
        description: 'Informational finding, no direct security impact'
    }
};

// =============================================================================
// CONFIDENCE LEVELS
// =============================================================================

const CONFIDENCE = {
    HIGH: {
        level: 'high',
        description: 'Confirmed with definitive evidence'
    },
    MEDIUM: {
        level: 'medium',
        description: 'Likely vulnerable based on indicators'
    },
    LOW: {
        level: 'low',
        description: 'Possible vulnerability, requires manual verification'
    }
};

// =============================================================================
// MODULE DEFINITIONS
// =============================================================================

const MODULES = {
    FIREBASE: {
        FIRESTORE_READ: {
            id: 'mod-firestore-read',
            name: 'Firestore Unauthenticated Read',
            category: 'Firebase',
            description: 'Detects if Firestore collections allow public read access without authentication',
            severity: SEVERITY.HIGH,
            impact: 'Unauthorized access to potentially sensitive data stored in Firestore',
            remediation: 'Configure Firestore Security Rules to require authentication for read operations'
        },
        FIRESTORE_WRITE: {
            id: 'mod-firestore-write',
            name: 'Firestore Unauthenticated Write',
            category: 'Firebase',
            description: 'Tests for write permissions to Firestore without authentication',
            severity: SEVERITY.CRITICAL,
            impact: 'Attackers can modify or corrupt data in the database',
            remediation: 'Configure Firestore Security Rules to require authentication and validate writes'
        },
        RTDB_PUBLIC: {
            id: 'mod-rtdb-read',
            name: 'Realtime Database Public Access',
            category: 'Firebase',
            description: 'Checks if Firebase Realtime Database allows public reads',
            severity: SEVERITY.HIGH,
            impact: 'Complete database contents may be exposed to any internet user',
            remediation: 'Configure Realtime Database Rules to require authentication'
        },
        STORAGE_PUBLIC: {
            id: 'mod-storage-public',
            name: 'Firebase Storage Public Read',
            category: 'Firebase',
            description: 'Detects publicly accessible Firebase Storage buckets',
            severity: SEVERITY.MEDIUM,
            impact: 'Files stored in Firebase Storage may be accessible without authentication',
            remediation: 'Configure Firebase Storage Rules to require authentication for downloads'
        },
        STORAGE_UPLOAD: {
            id: 'mod-storage-upload',
            name: 'Firebase Storage Unrestricted Upload',
            category: 'Firebase',
            description: 'Tests for unrestricted file upload capabilities',
            severity: SEVERITY.HIGH,
            impact: 'Attackers can upload malicious content or exhaust storage quota',
            remediation: 'Configure Firebase Storage Rules to restrict uploads by file type and user'
        },
        CLOUD_FUNC: {
            id: 'mod-cloud-func',
            name: 'Cloud Function Auth Bypass',
            category: 'Firebase',
            description: 'Detects unauthenticated Cloud Function invocations',
            severity: SEVERITY.HIGH,
            impact: 'Backend functions can be invoked by any user without authentication',
            remediation: 'Add authentication checks at the start of each Cloud Function'
        },
        ANONYMOUS_AUTH: {
            id: 'mod-anonymous-auth',
            name: 'Anonymous Auth Misuse',
            category: 'Firebase',
            description: 'Checks for improper anonymous authentication handling',
            severity: SEVERITY.MEDIUM,
            impact: 'Anonymous users may access data they should not have access to',
            remediation: 'Restrict anonymous user permissions in Security Rules'
        },
        UID_TRUST: {
            id: 'mod-uid-trust',
            name: 'UID Trust Abuse',
            category: 'Firebase',
            description: 'Detects client-controlled UID vulnerabilities',
            severity: SEVERITY.HIGH,
            impact: 'Attackers can impersonate other users by manipulating UIDs',
            remediation: 'Always verify UID server-side using Firebase Admin SDK'
        },
        DOC_PATH: {
            id: 'mod-doc-path',
            name: 'Document Path Manipulation',
            category: 'Firebase',
            description: 'Tests for client-controlled document path abuse',
            severity: SEVERITY.MEDIUM,
            impact: 'Users may access documents belonging to other users',
            remediation: 'Validate document paths in Security Rules'
        }
    },
    GCP: {
        PUBLIC_FUNCTIONS: {
            id: 'mod-gcp-functions',
            name: 'Public Cloud Functions',
            category: 'GCP',
            description: 'Identifies unauthenticated GCP Cloud Functions',
            severity: SEVERITY.HIGH,
            impact: 'Sensitive backend logic exposed without authentication',
            remediation: 'Configure IAM to require authentication for Cloud Functions'
        },
        GCS_PUBLIC: {
            id: 'mod-gcp-storage',
            name: 'GCS Public Objects',
            category: 'GCP',
            description: 'Detects publicly accessible Cloud Storage buckets',
            severity: SEVERITY.MEDIUM,
            impact: 'Files may be accessible to anyone on the internet',
            remediation: 'Remove public access from Cloud Storage buckets'
        },
        UNAUTH_API: {
            id: 'mod-gcp-api',
            name: 'Unauthenticated APIs',
            category: 'GCP',
            description: 'Discovers exposed API endpoints without authentication',
            severity: SEVERITY.MEDIUM,
            impact: 'API endpoints accessible without proper authentication',
            remediation: 'Implement authentication for all API endpoints'
        },
        SIGNED_URL: {
            id: 'mod-signed-url',
            name: 'Signed URL Misuse',
            category: 'GCP',
            description: 'Checks for overly permissive signed URLs',
            severity: SEVERITY.LOW,
            impact: 'Long-lived signed URLs may provide persistent unauthorized access',
            remediation: 'Use short-lived signed URLs with minimal permissions'
        },
        SSRF_METADATA: {
            id: 'mod-ssrf-metadata',
            name: 'SSRF to Metadata Detection',
            category: 'GCP',
            description: 'Detects SSRF sinks that could expose GCP metadata',
            severity: SEVERITY.CRITICAL,
            impact: 'Access to GCP metadata can lead to credential theft and full compromise',
            remediation: 'Validate and sanitize all user-supplied URLs'
        },
        ENV_LEAK: {
            id: 'mod-env-leak',
            name: 'Environment Variable Leakage',
            category: 'GCP',
            description: 'Detects exposed environment variables and secrets',
            severity: SEVERITY.CRITICAL,
            impact: 'Exposed secrets can lead to full application compromise',
            remediation: 'Remove debug endpoints and secure environment variables'
        }
    }
};

// =============================================================================
// EXPORT FUNCTIONS
// =============================================================================

/**
 * Get all enabled modules based on checkbox states
 */
function getEnabledModules() {
    const enabledModules = [];

    for (const category of Object.values(MODULES)) {
        for (const module of Object.values(category)) {
            const checkbox = document.getElementById(module.id);
            if (checkbox && checkbox.checked) {
                enabledModules.push(module);
            }
        }
    }

    return enabledModules;
}

/**
 * Get Firestore test configuration
 */
function getFirestoreTestConfig() {
    return FIRESTORE_TESTS;
}

/**
 * Get Realtime Database test configuration
 */
function getRtdbTestConfig() {
    return RTDB_TESTS;
}

/**
 * Get Storage test configuration
 */
function getStorageTestConfig() {
    return STORAGE_TESTS;
}

/**
 * Get Cloud Function test configuration
 */
function getCloudFunctionTestConfig() {
    return CLOUD_FUNCTION_TESTS;
}

/**
 * Get Firebase detection patterns
 */
function getFirebaseDetectionPatterns() {
    return FIREBASE_DETECTION;
}

/**
 * Get GCP detection patterns
 */
function getGcpDetectionPatterns() {
    return GCP_DETECTION;
}

/**
 * Get all modules
 */
function getAllModules() {
    return MODULES;
}

/**
 * Get severity info
 */
function getSeverityInfo(level) {
    return SEVERITY[level.toUpperCase()] || SEVERITY.INFO;
}

/**
 * Get confidence info
 */
function getConfidenceInfo(level) {
    return CONFIDENCE[level.toUpperCase()] || CONFIDENCE.LOW;
}

// Make functions available globally
window.getEnabledModules = getEnabledModules;
window.getFirestoreTestConfig = getFirestoreTestConfig;
window.getRtdbTestConfig = getRtdbTestConfig;
window.getStorageTestConfig = getStorageTestConfig;
window.getCloudFunctionTestConfig = getCloudFunctionTestConfig;
window.getFirebaseDetectionPatterns = getFirebaseDetectionPatterns;
window.getGcpDetectionPatterns = getGcpDetectionPatterns;
window.getAllModules = getAllModules;
window.getSeverityInfo = getSeverityInfo;
window.getConfidenceInfo = getConfidenceInfo;
window.FIREBASE_DETECTION = FIREBASE_DETECTION;
window.GCP_DETECTION = GCP_DETECTION;
window.FIRESTORE_TESTS = FIRESTORE_TESTS;
window.RTDB_TESTS = RTDB_TESTS;
window.STORAGE_TESTS = STORAGE_TESTS;
window.CLOUD_FUNCTION_TESTS = CLOUD_FUNCTION_TESTS;
window.GCS_TESTS = GCS_TESTS;
window.ENV_LEAK_TESTS = ENV_LEAK_TESTS;
window.SSRF_METADATA_TESTS = SSRF_METADATA_TESTS;
window.SIGNED_URL_TESTS = SIGNED_URL_TESTS;
window.MODULES = MODULES;
window.SEVERITY = SEVERITY;
window.CONFIDENCE = CONFIDENCE;
