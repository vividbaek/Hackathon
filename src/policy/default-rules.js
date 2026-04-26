const remediation = {
  prompt: 'Remove the unsafe instruction and restate the task with explicit safe boundaries.',
  command: 'Review the command manually before execution and replace it with a scoped, reversible operation.',
  output: 'Redact the sensitive value before showing or storing terminal output.',
  llm: 'Do not persist or forward this LLM content; route it through policy review and keep forensic evidence.',
  os: 'Keep the OS event in audit logs and require explicit review before allowing the process to continue sensitive activity.'
};

export const defaultRules = [
  {
    id: 'image-hidden-instruction',
    appliesTo: ['image', 'vision_observation'],
    severity: 'high',
    category: 'visual_prompt_injection',
    pattern: '\\b(?:hidden|invisible|small text|white text|ocr)\\b.{0,80}\\b(?:instruction|prompt|command)\\b',
    rationale: 'Image appears to contain hidden or OCR-targeted instructions.',
    remediation: 'Quarantine the image observation and require human review before passing it to an agent.'
  },
  {
    id: 'image-agent-command-injection',
    appliesTo: ['image', 'vision_observation'],
    severity: 'critical',
    category: 'visual_prompt_injection',
    pattern: '\\b(?:agent|assistant|model)\\b.{0,80}\\b(?:must|should|will)\\b.{0,80}\\b(?:run|execute|call)\\b.{0,60}\\b(?:shell|command|tool|terminal)\\b',
    rationale: 'Image text attempts to instruct an agent to execute tools or commands.',
    remediation: 'Do not pass this visual instruction into the agent context; log the source image and extracted text.'
  },
  {
    id: 'image-qr-exfiltration-hint',
    appliesTo: ['image', 'vision_observation'],
    severity: 'high',
    category: 'visual_exfiltration',
    pattern: '\\b(?:qr|barcode)\\b.{0,80}\\b(?:token|secret|password|exfil|upload|send)\\b',
    rationale: 'Image observation references QR/barcode-based secret movement.',
    remediation: 'Block downstream tool use and preserve image hash plus extracted text for review.'
  },
  {
    id: 'llm-injection-attempt',
    appliesTo: ['llm'],
    severity: 'high',
    category: 'prompt_injection',
    pattern: '\\b(?:ignore|disregard|forget|override)\\b.{0,80}\\b(?:previous|prior|above|all)\\b.{0,60}\\b(?:instructions?|rules?|policy|context|system)\\b',
    rationale: 'LLM output contains a prompt injection pattern targeting prior instructions.',
    remediation: 'Do not forward this output to another agent; flag it as a handoff poisoning attempt.'
  },
  {
    id: 'llm-guardrail-disable-attempt',
    appliesTo: ['llm'],
    severity: 'critical',
    category: 'guardrail_tampering',
    pattern: '\\b(?:disable|remove|bypass|shutdown|turn off)\\b.{0,80}\\b(?:guardrail|scanner|policy|404gent|safety|monitor|hook)\\b',
    rationale: 'LLM output attempts to disable runtime guardrails or safety monitors.',
    remediation: remediation.llm
  },
  {
    id: 'llm-memory-poisoning',
    appliesTo: ['llm'],
    severity: 'high',
    category: 'memory_poisoning',
    pattern: '\\b(?:remember|store in memory|save this instruction)\\b.{0,100}\\b(?:ignore|override|bypass|disable)\\b',
    rationale: 'LLM text attempts to poison future agent memory or policy behavior.',
    remediation: 'Do not persist this instruction to memory; record it as a poisoning attempt.'
  },
  {
    id: 'llm-agent-handoff-override',
    appliesTo: ['llm'],
    severity: 'high',
    category: 'agent_handoff_abuse',
    pattern: '\\b(?:next agent|other agents?|subagents?|worker agent|supervisor)\\b.{0,120}\\b(?:ignore|override|bypass|disable)\\b.{0,80}\\b(?:policy|guardrail|scanner|instruction|system)\\b',
    rationale: 'LLM content attempts to carry an override into another agent handoff.',
    remediation: remediation.llm
  },
  {
    id: 'llm-tool-call-injection',
    appliesTo: ['llm'],
    severity: 'critical',
    category: 'tool_call_injection',
    pattern: '\\b(?:call|invoke|use|run|execute)\\b.{0,80}\\b(?:tool|function|shell|terminal|browser|http request)\\b.{0,120}\\b(?:without asking|silently|do not ask|no confirmation|auto-approve)\\b',
    rationale: 'LLM content attempts to force tool execution without user approval.',
    remediation: remediation.llm
  },
  {
    id: 'llm-secret-exfiltration',
    appliesTo: ['llm'],
    severity: 'critical',
    category: 'secret_exfiltration',
    pattern: '\\b(?:send|post|upload|exfiltrate|forward)\\b.{0,120}\\b(?:\\.env|api key|token|password|private key|credentials?)\\b.{0,120}\\b(?:http|webhook|slack|discord|email|external|remote)\\b',
    rationale: 'LLM content attempts to move secrets to an external destination.',
    remediation: remediation.llm
  },
  {
    id: 'llm-rag-retrieval-poisoning',
    appliesTo: ['llm'],
    severity: 'high',
    category: 'retrieval_poisoning',
    pattern: '\\b(?:retrieved document|knowledge base|vector db|embedding|rag context)\\b.{0,160}\\b(?:ignore|override|replace|poison|trust this instead)\\b',
    rationale: 'LLM content attempts to poison or override retrieval-augmented context.',
    remediation: remediation.llm
  },
  {
    id: 'llm-policy-tampering',
    appliesTo: ['llm'],
    severity: 'critical',
    category: 'policy_tampering',
    pattern: '\\b(?:modify|rewrite|delete|relax|lower)\\b.{0,100}\\b(?:policy|rule|ruleset|block severity|guardrail)\\b',
    rationale: 'LLM content attempts to weaken or rewrite policy controls.',
    remediation: remediation.llm
  },
  {
    id: 'llm-korean-memory-poisoning',
    appliesTo: ['llm'],
    severity: 'high',
    category: 'memory_poisoning',
    pattern: '(기억|메모리|저장).{0,80}(이전|기존|앞선).{0,40}(지시|정책|규칙).{0,40}(무시|우회|삭제)',
    rationale: 'Korean LLM content attempts to poison future memory or policy behavior.',
    remediation: remediation.llm
  },
  {
    id: 'os-sensitive-file-open',
    appliesTo: ['os'],
    severity: 'critical',
    category: 'sensitive_file_access',
    pattern: '\\bos\\s+open\\b[^\\n]*(?:path="?[^"\\s]*(?:\\.env(?:\\.(?:local|production|development))?|credentials\\.json|secrets\\.json|\\.npmrc|\\.pypirc|\\.netrc|\\.kube/config)|/(?:\\.ssh|\\.aws|\\.gnupg)/)',
    rationale: 'OS Guard observed a process opening a file that commonly contains credentials.',
    remediation: remediation.os
  },
  {
    id: 'os-private-key-open',
    appliesTo: ['os'],
    severity: 'critical',
    category: 'private_key_access',
    pattern: '\\bos\\s+open\\b[^\\n]*(?:id_rsa|id_ed25519|id_ecdsa|\\.pem|\\.key|\\.p12|\\.pfx|certificate|private[_ -]?key)',
    rationale: 'OS Guard observed a process opening private key or certificate material.',
    remediation: remediation.os
  },
  {
    id: 'os-cloud-credentials-open',
    appliesTo: ['os'],
    severity: 'critical',
    category: 'cloud_credential_access',
    pattern: '\\bos\\s+open\\b[^\\n]*(?:aws_credentials|\\.aws/credentials|gcp_credentials|google_application_credentials|service-account\\.json|service_account\\.json|application_default_credentials\\.json)',
    rationale: 'OS Guard observed a process opening cloud provider credentials.',
    remediation: remediation.os
  },
  {
    id: 'os-network-tool-exec',
    appliesTo: ['os'],
    severity: 'medium',
    category: 'network_execution',
    pattern: '\\bos\\s+exec\\b[^\\n]*\\b(?:curl|wget|nc|netcat|scp|rsync)\\b',
    rationale: 'OS Guard observed execution of a network transfer tool.',
    remediation: remediation.os
  },
  {
    id: 'os-destructive-exec',
    appliesTo: ['os'],
    severity: 'critical',
    category: 'destructive_execution',
    pattern: '\\bos\\s+exec\\b[^\\n]*(?:\\brm\\b[^\\n]*\\s-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)|\\b(?:mkfs|fdisk)\\b|\\bdiskutil\\s+erase\\b|\\bdd\\s+if=)',
    rationale: 'OS Guard observed a destructive executable or destructive arguments.',
    remediation: remediation.os
  },
  {
    id: 'os-reverse-shell-exec',
    appliesTo: ['os'],
    severity: 'critical',
    category: 'reverse_shell',
    pattern: '\\bos\\s+exec\\b[^\\n]*(?:\\bnc\\b[^\\n]*\\s-e\\s|/dev/tcp/|mkfifo\\s+/tmp)',
    rationale: 'OS Guard observed reverse-shell-like execution arguments.',
    remediation: remediation.os
  },
  {
    id: 'prompt-injection-english',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'prompt_injection',
    pattern: '\\b(ignore|disregard|forget|override)\\b.{0,80}\\b(previous|system|developer)\\b.{0,40}\\b(instructions?|messages?|rules?)\\b',
    rationale: 'Prompt attempts to override higher-priority instructions.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-injection-korean',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'prompt_injection',
    pattern: '(이전|앞선|기존).{0,30}(지시|명령|규칙).{0,30}(무시|우회|삭제)',
    rationale: 'Korean prompt attempts to ignore or bypass prior instructions.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-jailbreak-roleplay',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'jailbreak',
    pattern: '\\b(DAN|developer mode|jailbreak|disable safety)\\b',
    rationale: 'Prompt asks the model to enter an unsafe role or disable safeguards.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-hidden-disclosure',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'hidden_prompt_disclosure',
    pattern: '\\b(system prompt|developer message|hidden instruction|chain of thought reveal|reveal chain of thought)\\b',
    rationale: 'Prompt requests hidden instructions or private reasoning.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-secret-exfiltration',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'secret_exfiltration',
    pattern: '\\b(print|show|dump|send)\\b.{0,80}(\\.env|api key|token|password|private key)',
    rationale: 'Prompt asks to expose secrets.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-secret-exfiltration-korean',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'secret_exfiltration',
    pattern: '(\\.env|API\\s*키|토큰|비밀번호|개인키|프라이빗\\s*키).{0,40}(출력|보여|덤프|전송|보내)',
    rationale: 'Korean prompt asks to expose secrets.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-tool-bypass',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'tool_bypass',
    pattern: '\\b(without asking|silently run)\\b.{0,60}\\b(shell command|command)\\b',
    rationale: 'Prompt asks to bypass user confirmation for tool execution.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-guardrail-tampering',
    appliesTo: ['prompt'],
    severity: 'critical',
    category: 'guardrail_tampering',
    pattern: '\\b(disable|remove|bypass)\\b.{0,60}\\b(guardrail|scanner|404gent|cmux)\\b',
    rationale: 'Prompt attempts to tamper with runtime guardrails.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-malware',
    appliesTo: ['prompt'],
    severity: 'critical',
    category: 'malware',
    pattern: '\\b(malware|reverse shell|keylogger|ransomware)\\b',
    rationale: 'Prompt requests malware or intrusive capability.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-phishing-social-engineering',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'social_engineering',
    pattern: '\\b(phishing|credential harvest|social engineering|impersonate)\\b',
    rationale: 'Prompt requests phishing or social engineering behavior.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-backdoor-data-poisoning',
    appliesTo: ['prompt'],
    severity: 'critical',
    category: 'supply_chain_abuse',
    pattern: '\\b(backdoor|data poisoning|poison the training data)\\b',
    rationale: 'Prompt requests backdoor or data poisoning behavior.',
    remediation: remediation.prompt
  },
  {
    id: 'prompt-pii-harvesting',
    appliesTo: ['prompt'],
    severity: 'high',
    category: 'privacy',
    pattern: '\\b(PII harvesting|collect personal information|scrape personal data|harvest emails)\\b',
    rationale: 'Prompt requests collection of personal data.',
    remediation: remediation.prompt
  },
  {
    id: 'command-destructive-rm',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'destructive_command',
    pattern: '\\brm\\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\\s+(?:(?:/|~|\\$HOME|\\.|\\.\\.|\\*)(?:\\s|$)|[^\\n]*(?:workspace|Desktop|Documents|Downloads))',
    rationale: 'Command may recursively delete critical files.',
    remediation: remediation.command
  },
  {
    id: 'command-disk-destruction',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'disk_destruction',
    pattern: '\\b(mkfs(?:\\.[a-z0-9]+)?|fdisk|diskutil\\s+erase|dd\\s+if=)\\b',
    rationale: 'Command can destroy disks or filesystems.',
    remediation: remediation.command
  },
  {
    id: 'command-fork-bomb',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'resource_exhaustion',
    pattern: '(:\\s*\\(\\)\\s*\\{\\s*:\\|:\\s*&\\s*\\}\\s*;\\s*:|\\byes\\b\\s*\\|\\s*\\byes\\b)',
    rationale: 'Command can exhaust system resources.',
    remediation: remediation.command
  },
  {
    id: 'command-git-destructive',
    appliesTo: ['command'],
    severity: 'high',
    category: 'destructive_command',
    pattern: '\\bgit\\s+(?:reset\\s+--hard|clean\\s+-dfx|checkout\\s+--\\s+\\.)\\b',
    rationale: 'Command can discard local work.',
    remediation: remediation.command
  },
  {
    id: 'command-secrets-to-network',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'secret_exfiltration',
    pattern: '(?:cat|grep|sed|awk|tail|head)?[^\\n]*(?:\\.env|id_rsa|credentials|secrets?|private[_ -]?key|token|password)[^\\n]*(?:\\||>|\\s)\\s*(?:curl|wget|nc|netcat|scp|rsync)\\b',
    rationale: 'Command appears to send secrets to a network tool.',
    remediation: remediation.command
  },
  {
    id: 'command-sensitive-files-to-network',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'data_exfiltration',
    pattern: '\\b(?:curl|wget|nc|netcat|scp|rsync)\\b[^\\n]*(?:\\.ssh|\\.aws|\\.kube|keychain|credentials|secrets?|\\.env)',
    rationale: 'Command may transfer sensitive files over the network.',
    remediation: remediation.command
  },
  {
    id: 'command-read-secret-files',
    appliesTo: ['command'],
    severity: 'medium',
    category: 'secret_access',
    pattern: '\\b(?:cat|less|more|grep|sed|awk|tail|head)\\b[^\\n]*(?:\\.env|id_rsa|\\.npmrc|credentials|private[_ -]?key)',
    rationale: 'Command reads secret-bearing files.',
    remediation: remediation.command
  },
  {
    id: 'command-download-pipe-shell',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'remote_code_execution',
    pattern: '\\b(?:curl|wget)\\b[^\\n]*(?:\\||\\$\\()[^\\n]*\\b(?:sh|bash|zsh|python|ruby|perl)\\b',
    rationale: 'Command pipes downloaded content into an interpreter.',
    remediation: remediation.command
  },
  {
    id: 'command-reverse-shell',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'reverse_shell',
    pattern: '(\\bnc\\b[^\\n]*\\s-e\\s|/dev/tcp/|mkfifo\\s+/tmp)',
    rationale: 'Command contains reverse shell patterns.',
    remediation: remediation.command
  },
  {
    id: 'command-persistence',
    appliesTo: ['command'],
    severity: 'high',
    category: 'persistence',
    pattern: '(?:>>|>)\\s*(?:~/?\\.bashrc|~/?\\.zshrc|~/?\\.profile)|\\bcrontab\\b',
    rationale: 'Command may establish shell or cron persistence.',
    remediation: remediation.command
  },
  {
    id: 'command-world-writable',
    appliesTo: ['command'],
    severity: 'high',
    category: 'permission_weakening',
    pattern: '\\bchmod\\s+-R\\s+777\\b',
    rationale: 'Command makes files recursively world-writable.',
    remediation: remediation.command
  },
  {
    id: 'command-privilege-escalation',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'privilege_escalation',
    pattern: '(\\bsudo\\s+(?:su|bash|sh|zsh)\\b|\\bchmod\\s+u\\+s\\b)',
    rationale: 'Command attempts privileged shell or setuid behavior.',
    remediation: remediation.command
  },
  {
    id: 'command-recon-tools',
    appliesTo: ['command'],
    severity: 'medium',
    category: 'reconnaissance',
    pattern: '\\b(nmap|masscan|sqlmap|hydra|ffuf|gobuster)\\b',
    rationale: 'Command invokes reconnaissance or offensive security tooling.',
    remediation: remediation.command
  },
  {
    id: 'command-cloud-destructive-delete',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'cloud_destruction',
    pattern: '\\b(?:aws\\b[^\\n]*\\b(?:delete|terminate|destroy|remove)|gcloud\\b[^\\n]*\\b(?:delete|destroy|remove)|kubectl\\b[^\\n]*\\bdelete\\b|terraform\\b[^\\n]*\\b(?:destroy|apply\\s+-destroy))\\b',
    rationale: 'Command can delete cloud or infrastructure resources.',
    remediation: remediation.command
  },
  {
    id: 'command-macos-keychain',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'macos_sensitive_access',
    pattern: '\\bsecurity\\s+(?:find-generic-password|find-internet-password|dump-keychain)\\b',
    rationale: 'Command accesses macOS Keychain secrets.',
    remediation: remediation.command
  },
  {
    id: 'command-macos-tcc',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'macos_sensitive_access',
    pattern: 'TCC\\.db|com\\.apple\\.TCC',
    rationale: 'Command accesses macOS TCC privacy database.',
    remediation: remediation.command
  },
  {
    id: 'command-macos-quarantine-bypass',
    appliesTo: ['command'],
    severity: 'critical',
    category: 'macos_gatekeeper_bypass',
    pattern: '\\bxattr\\b[^\\n]*(?:^|\\s)-d(?:\\s|=)[^\\n]*com\\.apple\\.quarantine',
    rationale: 'Command bypasses macOS Gatekeeper quarantine.',
    remediation: remediation.command
  },
  {
    id: 'command-macos-launchagent',
    appliesTo: ['command'],
    severity: 'high',
    category: 'macos_persistence',
    pattern: 'LaunchAgents|launchctl\\s+(?:load|bootstrap|enable)',
    rationale: 'Command may establish macOS LaunchAgent persistence.',
    remediation: remediation.command
  },
  {
    id: 'command-macos-applescript-automation',
    appliesTo: ['command'],
    severity: 'high',
    category: 'macos_automation',
    pattern: '\\bosascript\\b[^\\n]*(?:System Events|keystroke|tell application)',
    rationale: 'Command uses AppleScript automation that can manipulate user apps.',
    remediation: remediation.command
  },
  {
    id: 'output-private-key',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '-----BEGIN [A-Z ]*PRIVATE KEY-----',
    rationale: 'Output contains a private key block.',
    remediation: remediation.output
  },
  {
    id: 'output-environment-secret',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\\s*=\\s*[^\\s]+',
    rationale: 'Output contains environment-style secrets.',
    remediation: remediation.output
  },
  {
    id: 'output-database-url-credentials',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\\s:/]+:[^\\s@]+@[^\\s]+',
    rationale: 'Output contains a database URL with credentials.',
    remediation: remediation.output
  },
  {
    id: 'output-cookie-session-token',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\b(?:Cookie|Set-Cookie):[^\\n]*(?:session|token|auth|sid)=',
    rationale: 'Output contains cookie session material.',
    remediation: remediation.output
  },
  {
    id: 'output-bearer-token',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\bBearer\\s+[A-Za-z0-9._~+/-]+=*',
    rationale: 'Output contains a bearer token.',
    remediation: remediation.output
  },
  {
    id: 'output-jwt',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\beyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b',
    rationale: 'Output contains a JWT.',
    remediation: remediation.output
  },
  {
    id: 'output-aws-access-key',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b',
    rationale: 'Output contains an AWS access key id.',
    remediation: remediation.output
  },
  {
    id: 'output-google-api-key',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\bAIza[0-9A-Za-z_-]{35}\\b',
    rationale: 'Output contains a Google API key.',
    remediation: remediation.output
  },
  {
    id: 'output-service-token',
    appliesTo: ['output'],
    severity: 'critical',
    category: 'secret_leak',
    pattern: '\\b(?:ghp_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\\b',
    rationale: 'Output contains a service access token.',
    remediation: remediation.output
  },
  {
    id: 'output-ssn',
    appliesTo: ['output'],
    severity: 'high',
    category: 'pii',
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
    rationale: 'Output contains a US SSN-like value.',
    remediation: remediation.output
  },
  {
    id: 'output-korean-rrn',
    appliesTo: ['output'],
    severity: 'high',
    category: 'pii',
    pattern: '\\b\\d{6}-[1-4]\\d{6}\\b',
    rationale: 'Output contains a Korean RRN-like value.',
    remediation: remediation.output
  },
  {
    id: 'output-credit-card',
    appliesTo: ['output'],
    severity: 'high',
    category: 'pii',
    pattern: '\\b(?:\\d[ -]*?){13,19}\\b',
    rationale: 'Output contains a credit card-like number.',
    remediation: remediation.output
  }
];
