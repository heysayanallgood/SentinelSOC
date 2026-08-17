TECHNIQUES = {

"T1059":{
"name":"Command and Scripting Interpreter",
"tactic":"Execution",
"platform":"Windows Linux macOS",
"description":"Execute commands using PowerShell, CMD and Bash.",
"detection":"Monitor PowerShell and process creation.",
"mitigation":"Application Control"
},

"T1566":{
"name":"Phishing",
"tactic":"Initial Access",
"platform":"Windows Linux macOS",
"description":"Malicious email attachments and phishing links.",
"detection":"Email gateway monitoring.",
"mitigation":"Security Awareness"
},

"T1071":{
"name":"Application Layer Protocol",
"tactic":"Command and Control",
"platform":"Windows Linux",
"description":"HTTP HTTPS DNS communication.",
"detection":"Network IDS.",
"mitigation":"Firewall Monitoring"
},

"T1027":{
"name":"Obfuscated Files or Information",
"tactic":"Defense Evasion",
"platform":"All",
"description":"Encoded malware.",
"detection":"Behavior Analysis.",
"mitigation":"Endpoint Protection"
},

"T1105":{
"name":"Ingress Tool Transfer",
"tactic":"Command and Control",
"platform":"Windows Linux",
"description":"Download tools from remote server.",
"detection":"Monitor downloads.",
"mitigation":"Restrict outbound traffic"
},

"T1055":{
"name":"Process Injection",
"tactic":"Privilege Escalation",
"platform":"Windows",
"description":"Inject into legitimate process.",
"detection":"EDR monitoring.",
"mitigation":"Exploit Protection"
}

}
