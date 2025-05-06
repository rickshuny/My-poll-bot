import os  # You need to import os
import requests
import json
import time
from datetime import datetime
from flask import Flask

app = Flask(__name__)

# Get environment variables properly
BOT_TOKEN = os.getenv('BOT_TOKEN')  # Remove your actual token here
CHAT_ID = os.getenv('CHAT_ID')      # Remove your actual chat ID here
BASE_URL = f'https://api.telegram.org/bot{BOT_TOKEN}/'



polls = [

    {
        "question": "What is the term for an ethical hacker? 😊",
        "options": ['Black hat', 'White hat', 'Grey hat', 'Red hat'],
        "correct_option": 1,
        "explanation": "<b>White hat</b> hackers are security professionals who use their skills ethically."
    },
    {
        "question": "Which protocol is vulnerable to MITM attacks? 💻",
        "options": ['HTTP', 'ARP', 'FTP', 'SSH'],
        "correct_option": 1,
        "explanation": "<b>ARP</b> is vulnerable because it doesn't verify response authenticity."
    },
    {
        "question": "What attack involves sending excessive data? 🎵",
        "options": ['Phishing', 'Buffer overflow', 'SQL injection', 'XSS'],
        "correct_option": 1,
        "explanation": "<b>Buffer overflow</b> occurs when more data is sent than a buffer can handle."
    },
    {
        "question": "Which tool is used for network scanning?",
        "options": ['Wireshark', 'Nmap', 'Metasploit', 'John the Ripper'],
        "correct_option": 1,
        "explanation": "<b>Nmap</b> is the standard tool for network discovery and port scanning."
    },
        {
        "question": "What does SQL injection target?",
        "options": ['Network ports', 'Databases', 'Firewalls', 'User passwords'],
        "correct_option": 1,
        "explanation": "<b>Databases</b> are vulnerable when input isn't properly sanitized."
    },
    {
        "question": "What is a zero-day vulnerability?",
        "options": ['A bug with no patch', 'Newly discovered attack', 'Both', 'Neither'],
        "correct_option": 2,
        "explanation": "A <b>zero-day</b> is both a newly discovered vulnerability and one without an available patch."
    },
    {
        "question": "Which encryption is asymmetric?",
        "options": ['AES', 'RSA', 'DES', 'Blowfish'],
        "correct_option": 1,
        "explanation": "<b>RSA</b> uses public/private key pairs, making it asymmetric."
    },
    {
        "question": "What does CIA stand for in security?",
        "options": ['Confidentiality, Integrity, Availability', 'Central Intelligence Agency', 'Cyber Investigation Agency', 'Critical Infrastructure Assessment'],
        "correct_option": 0,
        "explanation": "The security triad is <b>Confidentiality, Integrity, Availability</b>."
    },
    {
        "question": "Which is NOT a firewall type?",
        "options": ['Packet-filtering', 'Proxy', 'Stateful', 'DNS'],
        "correct_option": 3,
        "explanation": "<b>DNS</b> is a naming system, not a firewall type."
    },
    {
        "question": "What does VPN stand for?",
        "options": ['Virtual Private Network', 'Verified Public Node', 'Virtual Proxy Node', 'Verified Private Network'],
        "correct_option": 0,
        "explanation": "A <b>Virtual Private Network</b> creates secure connections over public networks."
    },
    {
        "question": "Which is a hashing algorithm?",
        "options": ['RSA', 'SHA-256', 'AES', 'SSL'],
        "correct_option": 1,
        "explanation": "<b>SHA-256</b> is a cryptographic hash function."
    },
    {
        "question": "What does XSS stand for?",
        "options": ['Cross Site Scripting', 'Extra Secure Socket', 'Xtra Server Security', 'Extended Security System'],
        "correct_option": 0,
        "explanation": "<b>Cross Site Scripting</b> injects malicious scripts into web pages."
    },
    {
        "question": "Which port does HTTPS use?",
        "options": ['80', '22', '443', '53'],
        "correct_option": 2,
        "explanation": "<b>443</b> is the standard port for HTTPS traffic."
    },
    {
        "question": "What is a honeypot?",
        "options": ['Malware', 'Decoy system', 'Encryption tool', 'Firewall'],
        "correct_option": 1,
        "explanation": "A <b>honeypot</b> is a trap set to detect or deflect attacks."
    },
    {
        "question": "Which is NOT a malware type?",
        "options": ['Virus', 'Worm', 'Firewall', 'Trojan'],
        "correct_option": 2,
        "explanation": "A <b>firewall</b> is a security system, not malware."
    },
    {
        "question": "What does DDoS stand for?",
        "options": ['Direct Denial of Service', 'Distributed Denial of Service', 'Data Destruction of System', 'Digital Defense of Security'],
        "correct_option": 1,
        "explanation": "<b>Distributed Denial of Service</b> overwhelms systems with traffic from multiple sources."
    },
    {
        "question": "Which is a Linux security module?",
        "options": ['SELinux', 'Windows Defender', 'McAfee', 'Norton'],
        "correct_option": 0,
        "explanation": "<b>SELinux</b> provides access control security policies in Linux."
    },
    {
        "question": "What is phishing?",
        "options": ['Network scanning', 'Fishing for passwords', 'Social engineering attack', 'Port scanning'],
        "correct_option": 2,
        "explanation": "<b>Phishing</b> uses deceptive communications to trick users."
    },
    {
        "question": "Which is a container security tool?",
        "options": ['Docker Bench', 'Nessus', 'Wireshark', 'Metasploit'],
        "correct_option": 0,
        "explanation": "<b>Docker Bench</b> checks for security best practices in containers."
    },
    {
        "question": "What is two-factor authentication?",
        "options": ['Password only', 'Password + SMS code', 'Fingerprint only', 'No authentication'],
        "correct_option": 1,
        "explanation": "<b>2FA</b> requires two different authentication factors."
    },
    # Additional 80 questions would follow the same pattern
    # ...
    {
        "question": "What is the purpose of salting passwords?",
        "options": ['Make them tasty', 'Prevent rainbow table attacks', 'Encrypt passwords', 'Speed up hashing'],
        "correct_option": 1,
        "explanation": "<b>Salting</b> adds random data to prevent precomputed hash attacks."
    },

    {
        "question": "Which of these is NOT a common password cracking technique?",
        "options": ['Brute force', 'Rainbow tables', 'SQL injection', 'Dictionary attack'],
        "correct_option": 2,
        "explanation": "<b>SQL injection</b> targets databases, not password hashes directly."
    },
    {
        "question": "What does TLS stand for?",
        "options": ['Transport Layer Security', 'Transparent Link System', 'Terminal License Server', 'Two-Level Security'],
        "correct_option": 0,
        "explanation": "<b>Transport Layer Security</b> is the successor to SSL for encrypted communications."
    },
    {
        "question": "Which header helps prevent XSS attacks?",
        "options": ['Content-Security-Policy', 'X-Forwarded-For', 'Accept-Encoding', 'Cache-Control'],
        "correct_option": 0,
        "explanation": "<b>Content-Security-Policy</b> header restricts sources of executable scripts."
    },
    {
        "question": "What is the primary purpose of Kerberos?",
        "options": ['Network scanning', 'Authentication', 'Data encryption', 'Malware detection'],
        "correct_option": 1,
        "explanation": "<b>Kerberos</b> provides secure authentication in distributed systems."
    },
    {
        "question": "Which of these is a container security best practice?",
        "options": ['Run as root', 'Use latest images', 'Disable logging', 'Share host network'],
        "correct_option": 1,
        "explanation": "Using <b>latest images</b> ensures known vulnerabilities are patched."
    },
    {
        "question": "What does CSRF stand for?",
        "options": ['Cross-Site Request Forgery', 'Client-Side Remote Function', 'Certificate Signing Request Form', 'Common Security Risk Framework'],
        "correct_option": 0,
        "explanation": "<b>Cross-Site Request Forgery</b> tricks users into executing unwanted actions."
    },
    {
        "question": "Which tool is used for vulnerability scanning?",
        "options": ['Nessus', 'Wireshark', 'John the Ripper', 'Ghidra'],
        "correct_option": 0,
        "explanation": "<b>Nessus</b> is a comprehensive vulnerability scanner."
    },
    {
        "question": "What is the purpose of non-repudiation?",
        "options": ['Prevent denial of actions', 'Encrypt data', 'Block attacks', 'Monitor traffic'],
        "correct_option": 0,
        "explanation": "<b>Non-repudiation</b> ensures parties cannot deny their actions."
    },
    {
        "question": "Which encryption mode is vulnerable to bit-flipping attacks?",
        "options": ['ECB', 'CBC', 'GCM', 'OFB'],
        "correct_option": 1,
        "explanation": "<b>CBC</b> mode without integrity checks is vulnerable to bit-flipping."
    },
    {
        "question": "What does SIEM stand for?",
        "options": ['Security Information and Event Management', 'System Integrity and Encryption Module', 'Secure Internet Exchange Mechanism', 'Standardized Incident Evaluation Metric'],
        "correct_option": 0,
        "explanation": "<b>SIEM</b> systems provide real-time security monitoring."
    },
    {
        "question": "Which is a hardware security module?",
        "options": ['HSM', 'SSD', 'CPU', 'GPU'],
        "correct_option": 0,
        "explanation": "<b>HSM</b> (Hardware Security Module) manages digital keys securely."
    },
    {
        "question": "What is the main risk of WPS on routers?",
        "options": ['Slow speeds', 'Brute force vulnerability', 'No encryption', 'MAC filtering'],
        "correct_option": 1,
        "explanation": "<b>WPS</b> is vulnerable to brute force PIN attacks."
    },
    {
        "question": "Which protocol provides secure file transfer?",
        "options": ['FTP', 'SFTP', 'HTTP', 'Telnet'],
        "correct_option": 1,
        "explanation": "<b>SFTP</b> (SSH File Transfer Protocol) encrypts file transfers."
    },
    {
        "question": "What is a canary token used for?",
        "options": ['Network scanning', 'Breach detection', 'Password cracking', 'Traffic analysis'],
        "correct_option": 1,
        "explanation": "<b>Canary tokens</b> alert when accessed, indicating potential breaches."
    },
    {
        "question": "Which is NOT part of the OWASP Top 10?",
        "options": ['Injection', 'Broken Authentication', 'Secure Logging', 'XXE'],
        "correct_option": 2,
        "explanation": "<b>Secure Logging</b> is important but not an OWASP Top 10 category."
    },
    {
        "question": "What does PII stand for?",
        "options": ['Personal Internet Identifier', 'Public Information Index', 'Personally Identifiable Information', 'Protected Institutional Data'],
        "correct_option": 2,
        "explanation": "<b>PII</b> refers to data that can identify individuals."
    },
    {
        "question": "Which is a MAC address filtering limitation?",
        "options": ['Encryption weakness', 'MAC spoofing', 'Slow performance', 'Complex setup'],
        "correct_option": 1,
        "explanation": "<b>MAC addresses</b> can be easily spoofed by attackers."
    },
    {
        "question": "What is the main purpose of steganography?",
        "options": ['Strong encryption', 'Data compression', 'Hidden communication', 'Fast transmission'],
        "correct_option": 2,
        "explanation": "<b>Steganography</b> hides data within other files/media."
    },
    {
        "question": "Which is a secure password storage method?",
        "options": ['Plaintext', 'Encrypted', 'Hashed with salt', 'Reversible encoding'],
        "correct_option": 2,
        "explanation": "<b>Salted hashes</b> provide secure password storage."
    },
    {
        "question": "What does RTO stand for in disaster recovery?",
        "options": ['Real-Time Operation', 'Recovery Time Objective', 'Risk Tolerance Overview', 'Return To Origin'],
        "correct_option": 1,
        "explanation": "<b>RTO</b> is the maximum acceptable downtime after disaster."
    },
    {
        "question": "Which is NOT a biometric authentication factor?",
        "options": ['Fingerprint', 'Retina scan', 'Password', 'Voice recognition'],
        "correct_option": 2,
        "explanation": "<b>Passwords</b> are knowledge-based, not biometric factors."
    },
    {
        "question": "What is the main purpose of a bastion host?",
        "options": ['Store backups', 'Control network access', 'Run antivirus', 'Monitor logs'],
        "correct_option": 1,
        "explanation": "<b>Bastion hosts</b> provide controlled access to private networks."
    },
    {
        "question": "Which is a common IoT security risk?",
        "options": ['Default credentials', 'Too many features', 'Small size', 'Low cost'],
        "correct_option": 0,
        "explanation": "<b>Default credentials</b> are a major IoT vulnerability."
    },
    {
        "question": "What does RBAC stand for?",
        "options": ['Rule-Based Access Control', 'Role-Based Access Control', 'Risk-Based Access Configuration', 'Remote Backup and Control'],
        "correct_option": 1,
        "explanation": "<b>RBAC</b> assigns permissions based on organizational roles."
    },
    {
        "question": "Which is a characteristic of blockchain security?",
        "options": ['Centralized control', 'Mutable records', 'Cryptographic hashing', 'Fast transactions'],
        "correct_option": 2,
        "explanation": "<b>Cryptographic hashing</b> ensures blockchain integrity."
    },
    {
        "question": "What is the main risk of shadow IT?",
        "options": ['Unauthorized systems', 'Too many admins', 'Old hardware', 'Complex networks'],
        "correct_option": 0,
        "explanation": "<b>Shadow IT</b> refers to unauthorized systems outside security controls."
    },
    {
        "question": "Which is NOT a common cloud security model?",
        "options": ['IaaS', 'PaaS', 'SaaS', 'RaaS'],
        "correct_option": 3,
        "explanation": "<b>RaaS</b> (Ransomware as a Service) is malicious, not a security model."
    },
    {
        "question": "What does BYOD stand for?",
        "options": ['Bring Your Own Device', 'Backup Your Organizational Data', 'Best Yearly Operations Directive', 'Block Your Online Data'],
        "correct_option": 0,
        "explanation": "<b>BYOD</b> policies address personal devices in workplaces."
    },
    {
        "question": "Which is a key aspect of GDPR compliance?",
        "options": ['Data minimization', 'Maximum retention', 'Public sharing', 'No encryption'],
        "correct_option": 0,
        "explanation": "<b>Data minimization</b> means collecting only necessary personal data."
    },
    {
        "question": "What is the main purpose of a WAF?",
        "options": ['Block viruses', 'Filter web traffic', 'Encrypt emails', 'Scan networks'],
        "correct_option": 1,
        "explanation": "<b>Web Application Firewalls</b> protect against web-based attacks."
    },
    {
        "question": "Which is NOT a common phishing indicator?",
        "options": ['Urgent language', 'Mismatched URLs', 'Poor grammar', 'HTTPS protocol'],
        "correct_option": 3,
        "explanation": "<b>HTTPS</b> alone doesn't indicate legitimacy - phishing sites often use it too."
    },
    {
        "question": "What is the primary risk of public WiFi?",
        "options": ['Slow speed', 'Man-in-the-middle attacks', 'Data limits', 'Login requirements'],
        "correct_option": 1,
        "explanation": "<b>MITM attacks</b> are the main threat on unsecured public networks."
    },
    {
        "question": "Which is a secure alternative to Telnet?",
        "options": ['SSH', 'FTP', 'HTTP', 'SNMP'],
        "correct_option": 0,
        "explanation": "<b>SSH</b> provides encrypted remote access instead of clear-text Telnet."
    },
    {
        "question": "What does BIA stand for in security planning?",
        "options": ['Business Impact Analysis', 'Basic Internet Architecture', 'Backup Integrity Assessment', 'Binary Input Analysis'],
        "correct_option": 0,
        "explanation": "<b>BIA</b> identifies critical business functions and recovery needs."
    },
    {
        "question": "Which is NOT a valid certificate type?",
        "options": ['DV', 'OV', 'EV', 'PV'],
        "correct_option": 3,
        "explanation": "Certificate types are <b>DV</b> (Domain Validated), <b>OV</b> (Organization Validated), and <b>EV</b> (Extended Validation)."
    },
    {
        "question": "What is the main purpose of DNSSEC?",
        "options": ['Faster DNS', 'Encrypted DNS', 'DNS authentication', 'Block ads'],
        "correct_option": 2,
        "explanation": "<b>DNSSEC</b> authenticates DNS responses to prevent spoofing."
    },
    {
        "question": "Which is a common API security practice?",
        "options": ['Rate limiting', 'Open endpoints', 'No authentication', 'Plaintext keys'],
        "correct_option": 0,
        "explanation": "<b>Rate limiting</b> prevents API abuse and DDoS attacks."
    },
    {
        "question": "What does EDR stand for?",
        "options": ['Endpoint Detection and Response', 'Encrypted Data Recovery', 'Enterprise Disaster Recovery', 'Extended Data Retention'],
        "correct_option": 0,
        "explanation": "<b>EDR</b> solutions monitor endpoints for threats and enable response."
    },
    {
        "question": "Which is NOT a common pentesting phase?",
        "options": ['Reconnaissance', 'Exploitation', 'Reporting', 'Destruction'],
        "correct_option": 3,
        "explanation": "Penetration testing should never include actual <b>destruction</b>."
    },
    {
        "question": "What is the main purpose of a salt in cryptography?",
        "options": ['Make hashes faster', 'Prevent rainbow tables', 'Shorten passwords', 'Encrypt data'],
        "correct_option": 1,
        "explanation": "<b>Salting</b> makes precomputed hash attacks impractical."
    },
    {
        "question": "Which is a common mobile device security risk?",
        "options": ['Jailbreaking', 'Automatic updates', 'App store vetting', 'Screen locks'],
        "correct_option": 0,
        "explanation": "<b>Jailbreaking</b> removes security protections from devices."
    },
    {
        "question": "What does ZTNA stand for?",
        "options": ['Zero Trust Network Access', 'Zone Transfer Network Architecture', 'Zoned Traffic Notification Alert', 'Zigbee Transmission Network Adapter'],
        "correct_option": 0,
        "explanation": "<b>ZTNA</b> implements strict access controls in modern networks."
    },
    {
        "question": "Which is NOT a common security framework?",
        "options": ['NIST CSF', 'ISO 27001', 'PCI DSS', 'HTTP/2'],
        "correct_option": 3,
        "explanation": "<b>HTTP/2</b> is a web protocol, not a security framework."
    },
    {
        "question": "What is the main purpose of threat modeling?",
        "options": ['Count vulnerabilities', 'Identify attack surfaces', 'Monitor traffic', 'Block malware'],
        "correct_option": 1,
        "explanation": "<b>Threat modeling</b> systematically identifies potential attack vectors."
    },
    {
        "question": "Which is a secure coding practice?",
        "options": ['Input validation', 'Hardcoded credentials', 'Disable logging', 'No error handling'],
        "correct_option": 0,
        "explanation": "<b>Input validation</b> prevents injection and other attacks."
    },
    {
        "question": "What does RASP stand for?",
        "options": ['Runtime Application Self-Protection', 'Remote Application Security Protocol', 'Risk Assessment Security Plan', 'Randomized Access Security Policy'],
        "correct_option": 0,
        "explanation": "<b>RASP</b> provides real-time protection within applications."
    },
    {
        "question": "Which is NOT a common security control type?",
        "options": ['Preventive', 'Detective', 'Corrective', 'Destructive'],
        "correct_option": 3,
        "explanation": "Security controls are never intentionally <b>destructive</b>."
    },
    {
        "question": "What is the main purpose of a sandbox?",
        "options": ['Store files', 'Isolate execution', 'Encrypt data', 'Monitor networks'],
        "correct_option": 1,
        "explanation": "<b>Sandboxes</b> provide isolated environments for safe code execution."
    },
    {
        "question": "Which is a common cloud access security broker feature?",
        "options": ['Data loss prevention', 'CPU optimization', 'Disk defragmentation', 'Power management'],
        "correct_option": 0,
        "explanation": "<b>CASBs</b> often include DLP capabilities for cloud data."
    },
    {
        "question": "What does SDLC stand for in security?",
        "options": ['Software Development Life Cycle', 'Secure Data Link Control', 'System Disk Level Check', 'Standardized Digital License Code'],
        "correct_option": 0,
        "explanation": "Integrating security throughout the <b>SDLC</b> is crucial."
    },
    {
        "question": "Which is NOT a common wireless security protocol?",
        "options": ['WEP', 'WPA2', 'WPA3', 'WPS'],
        "correct_option": 3,
        "explanation": "<b>WPS</b> is a convenience feature, not a security protocol."
    },
    {
        "question": "What is the main purpose of deception technology?",
        "options": ['Trap attackers', 'Encrypt data', 'Speed networks', 'Reduce costs'],
        "correct_option": 0,
        "explanation": "<b>Deception tech</b> uses fake systems to detect and study attackers."
    },
    {
        "question": "Which is a common security misconfiguration?",
        "options": ['Default credentials', 'Multi-factor auth', 'Encrypted backups', 'Log monitoring'],
        "correct_option": 0,
        "explanation": "Leaving <b>default credentials</b> is a serious misconfiguration."
    },
    {
        "question": "What does FIM stand for?",
        "options": ['File Integrity Monitoring', 'Firewall Intrusion Management', 'Full Incident Mitigation', 'Federated Identity Management'],
        "correct_option": 0,
        "explanation": "<b>FIM</b> detects unauthorized changes to critical files."
    },
    {
        "question": "Which is NOT part of the cyber kill chain?",
        "options": ['Reconnaissance', 'Weaponization', 'Installation', 'Documentation'],
        "correct_option": 3,
        "explanation": "<b>Documentation</b> isn't a phase in the attack lifecycle model."
    },
    {
        "question": "What is the main purpose of a jump server?",
        "options": ['Control access', 'Store data', 'Run antivirus', 'Monitor logs'],
        "correct_option": 0,
        "explanation": "<b>Jump servers</b> provide controlled access to secure zones."
    },
    {
        "question": "Which is a common physical security control?",
        "options": ['Firewalls', 'Mantraps', 'Encryption', 'AV software'],
        "correct_option": 1,
        "explanation": "<b>Mantraps</b> control physical access to secure areas."
    },
    {
        "question": "What does PAM stand for in security?",
        "options": ['Personal Authentication Method', 'Privileged Access Management', 'Protected Account Monitoring', 'Public Access Mechanism'],
        "correct_option": 1,
        "explanation": "<b>PAM</b> controls and monitors privileged account access."
    },
    {
        "question": "Which is NOT a common incident response step?",
        "options": ['Preparation', 'Detection', 'Containment', 'Celebration'],
        "correct_option": 3,
        "explanation": "While important, <b>celebration</b> isn't a formal IR phase."
    },
    {
        "question": "What is the main purpose of air gapping?",
        "options": ['Network isolation', 'Faster transfers', 'Easier access', 'Reduced costs'],
        "correct_option": 0,
        "explanation": "<b>Air gapping</b> physically isolates critical systems from networks."
    },
    {
        "question": "Which is a common security awareness topic?",
        "options": ['Phishing', 'CPU speeds', 'Monitor sizes', 'Keyboard types'],
        "correct_option": 0,
        "explanation": "<b>Phishing</b> awareness is fundamental to security training."
    },
    {
        "question": "What does DLP stand for?",
        "options": ['Data Loss Prevention', 'Digital License Protection', 'Disk Level Partitioning', 'Dynamic Link Protocol'],
        "correct_option": 0,
        "explanation": "<b>DLP</b> solutions prevent unauthorized data exfiltration."
    },
    {
        "question": "Which is NOT a common red team tool?",
        "options": ['Cobalt Strike', 'Metasploit', 'Nessus', 'Burp Suite'],
        "correct_option": 2,
        "explanation": "<b>Nessus</b> is a vulnerability scanner, not typically a red team tool."
    },
    {
        "question": "What is the main purpose of a Faraday cage?",
        "options": ['Block EMI', 'Store data', 'Encrypt files', 'Monitor networks'],
        "correct_option": 0,
        "explanation": "<b>Faraday cages</b> block electromagnetic interference."
    },
    {
        "question": "Which is a common security certification?",
        "options": ['CISSP', 'CCNA', 'AWS', 'Python'],
        "correct_option": 0,
        "explanation": "<b>CISSP</b> is a premier cybersecurity certification."
    },
    {
        "question": "What does IoC stand for in security?",
        "options": ['Internet of Cars', 'Indicators of Compromise', 'Input of Code', 'Integration of Components'],
        "correct_option": 1,
        "explanation": "<b>IoC</b> are forensic artifacts indicating potential breaches."
    },
    {
        "question": "Which is NOT a common security assessment type?",
        "options": ['Penetration test', 'Vulnerability scan', 'Risk assessment', 'Speed test'],
        "correct_option": 3,
        "explanation": "<b>Speed tests</b> measure performance, not security."
    },
    {
        "question": "What is the main purpose of TPM?",
        "options": ['Store encryption keys', 'Increase speed', 'Reduce costs', 'Monitor networks'],
        "correct_option": 0,
        "explanation": "<b>Trusted Platform Modules</b> securely store cryptographic keys."
    },
    {
        "question": "Which is a common security architecture principle?",
        "options": ['Defense in depth', 'Single point of failure', 'Open access', 'No monitoring'],
        "correct_option": 0,
        "explanation": "<b>Defense in depth</b> uses multiple security layers."
    },
    {
        "question": "What does SASE stand for?",
        "options": ['Secure Access Service Edge', 'Systematic Application Security Engine', 'Standardized Authentication Security Element', 'Simple Antivirus Scanning Endpoint'],
        "correct_option": 0,
        "explanation": "<b>SASE</b> combines networking and security in cloud services."
    },
    {
        "question": "Which is NOT a common security standard?",
        "options": ['HIPAA', 'GDPR', 'PCI DSS', 'USB-C'],
        "correct_option": 3,
        "explanation": "<b>USB-C</b> is a hardware connector, not a security standard."
    },
    {
        "question": "What is the main purpose of a seed phrase in crypto?",
        "options": ['Recover wallets', 'Mine faster', 'Reduce fees', 'Anonymize transactions'],
        "correct_option": 0,
        "explanation": "<b>Seed phrases</b> allow recovery of cryptocurrency wallets."
    },
    {
        "question": "Which is a common security orchestration tool?",
        "options": ['SOAR', 'SIEM', 'EDR', 'XDR'],
        "correct_option": 0,
        "explanation": "<b>SOAR</b> (Security Orchestration, Automation and Response) tools streamline processes."
    },
    {
        "question": "What does XDR stand for?",
        "options": ['Extended Detection and Response', 'Extra Data Recovery', 'External Device Recognition', 'Expert Defense Resolution'],
        "correct_option": 0,
        "explanation": "<b>XDR</b> provides unified security across multiple layers."
    },
    {
        "question": "Which is NOT a common security awareness method?",
        "options": ['Phishing simulations', 'Training sessions', 'Policy documents', 'Password sharing'],
        "correct_option": 3,
        "explanation": "<b>Password sharing</b> violates security principles."
    },
    {
        "question": "What is the main purpose of a non-disclosure agreement?",
        "options": ['Protect secrets', 'Ensure payment', 'Guarantee service', 'Monitor employees'],
        "correct_option": 0,
        "explanation": "<b>NDAs</b> legally protect confidential information."
    },
    {
        "question": "Which is a common security compliance framework for healthcare?",
        "options": ['HIPAA', 'PCI DSS', 'SOX', 'GLBA'],
        "correct_option": 0,
        "explanation": "<b>HIPAA</b> governs protected health information in the US."
    },
    {
        "question": "What does BCP stand for?",
        "options": ['Business Continuity Planning', 'Basic Cyber Protection', 'Binary Code Processing', 'Backup Copy Protocol'],
        "correct_option": 0,
        "explanation": "<b>BCP</b> ensures organizations can continue operations during disruptions."
    },
    {
        "question": "Which is NOT a common security control for databases?",
        "options": ['Encryption', 'Access controls', 'Input validation', 'Defragmentation'],
        "correct_option": 3,
        "explanation": "<b>Defragmentation</b> is a maintenance task, not a security control."
    },
    {
        "question": "What is the main purpose of a security token?",
        "options": ['Physical authentication', 'Store data', 'Monitor networks', 'Block malware'],
        "correct_option": 0,
        "explanation": "<b>Security tokens</b> provide physical multi-factor authentication."
    },
    {
        "question": "Which is a common security consideration for APIs?",
        "options": ['Rate limiting', 'No authentication', 'Plaintext data', 'Open endpoints'],
        "correct_option": 0,
        "explanation": "<b>Rate limiting</b> prevents API abuse and denial of service."
    },
    {
        "question": "What does IR stand for in security?",
        "options": ['Internet Registry', 'Incident Response', 'Internal Routing', 'Information Retrieval'],
        "correct_option": 1,
        "explanation": "<b>Incident Response</b> plans handle security breaches."
    },
    {
        "question": "Which is NOT a common security certification body?",
        "options": ['(ISC)²', 'ISACA', 'CompTIA', 'IEEE'],
        "correct_option": 3,
        "explanation": "<b>IEEE</b> focuses on engineering, not security certifications."
    },
    {
        "question": "What is the main purpose of a security operations center?",
        "options": ['Monitor threats', 'Develop software', 'Manage HR', 'Handle finances'],
        "correct_option": 0,
        "explanation": "<b>SOCs</b> provide continuous security monitoring."
    },
    {
        "question": "Which is a common security control for mobile devices?",
        "options": ['MDM', 'SSD', 'CPU', 'GPU'],
        "correct_option": 0,
        "explanation": "<b>Mobile Device Management</b> enforces security policies."
    },
    {
        "question": "What does RMF stand for in government security?",
        "options": ['Risk Management Framework', 'Remote Monitoring Facility', 'Recovery Management Function', 'Resource Management File'],
        "correct_option": 0,
        "explanation": "<b>RMF</b> is the US government's cybersecurity risk process."
    },
    {
        "question": "Which is NOT a common security control family in NIST?",
        "options": ['Access Control', 'Incident Response', 'Security Awareness', 'Graphic Design'],
        "correct_option": 3,
        "explanation": "<b>Graphic Design</b> isn't a NIST security control family."
    },
    {
        "question": "What is the main purpose of a wildcard certificate?",
        "options": ['Cover subdomains', 'Increase speed', 'Reduce costs', 'Block attacks'],
        "correct_option": 0,
        "explanation": "<b>Wildcard certs</b> secure *.domain.com subdomains."
    },
    {
        "question": "Which is a common security consideration for IoT?",
        "options": ['Default credentials', 'Strong encryption', 'Frequent updates', 'All of above'],
        "correct_option": 3,
        "explanation": "IoT security requires addressing <b>all</b> these concerns."
    },
    {
        "question": "What does CVE stand for?",
        "options": ['Common Vulnerabilities and Exposures', 'Critical Vulnerability Engine', 'Certified Vulnerability Examiner', 'Cybersecurity Validation Entity'],
        "correct_option": 0,
        "explanation": "<b>CVE</b> is the standard identifier for publicly known vulnerabilities."
    },
    {
        "question": "Which is NOT a common security model?",
        "options": ['Bell-LaPadula', 'Biba', 'Clark-Wilson', 'Berners-Lee'],
        "correct_option": 3,
        "explanation": "<b>Berners-Lee</b> invented the web, not security models."
    },
    {
        "question": "What is the main purpose of a security questionnaire?",
        "options": ['Assess vendors', 'Test employees', 'Monitor networks', 'Block attacks'],
        "correct_option": 0,
        "explanation": "<b>Security questionnaires</b> evaluate third-party vendor risks."
    },
    {
        "question": "Which is a common security control for email?",
        "options": ['DMARC', 'HTML', 'CSS', 'JavaScript'],
        "correct_option": 0,
        "explanation": "<b>DMARC</b> prevents email spoofing and phishing."
    },
    {
        "question": "What does ASLR stand for?",
        "options": ['Address Space Layout Randomization', 'Application Security Layer Resolution', 'Automated System Log Rotation', 'Advanced Security License Registry'],
        "correct_option": 0,
        "explanation": "<b>ASLR</b> randomizes memory addresses to prevent exploits."
    },
    {
        "question": "Which is NOT a common security awareness topic for employees?",
        "options": ['Phishing', 'Social engineering', 'Password hygiene', 'CPU overclocking'],
        "correct_option": 3,
        "explanation": "<b>CPU overclocking</b> is a hardware topic, not security awareness."
    },
    {
        "question": "What is the main purpose of a bug bounty program?",
        "options": ['Reward researchers', 'Punish hackers', 'Monitor employees', 'Block attacks'],
        "correct_option": 0,
        "explanation": "<b>Bug bounties</b> incentivize ethical disclosure of vulnerabilities."
    },
    {
        "question": "Which is a common security control for source code?",
        "options": ['SAST', 'Load balancing', 'Data mining', 'Network segmentation'],
        "correct_option": 0,
        "explanation": "<b>SAST</b> (Static Application Security Testing) analyzes source code."
    },
    {
        "question": "What does MFA stand for?",
        "options": ['Multi-Factor Authentication', 'Mobile File Access', 'Managed Firewall Administration', 'Malware Forensic Analysis'],
        "correct_option": 0,
        "explanation": "<b>MFA</b> requires multiple authentication factors."
    },
    {
        "question": "Which is NOT a common security assessment technique?",
        "options": ['Penetration testing', 'Vulnerability scanning', 'Code review', 'Defragmentation'],
        "correct_option": 3,
        "explanation": "<b>Defragmentation</b> is a disk optimization process."
    },
    {
        "question": "What is the main purpose of a security policy?",
        "options": ['Define rules', 'Increase speed', 'Reduce costs', 'Monitor networks'],
        "correct_option": 0,
        "explanation": "<b>Security policies</b> establish organizational rules and standards."
    },
    {
        "question": "Which is a common security control for backups?",
        "options": ['3-2-1 rule', 'No encryption', 'Single location', 'No testing'],
        "correct_option": 0,
        "explanation": "The <b>3-2-1 rule</b> (3 copies, 2 media types, 1 offsite) ensures backup resilience."
    },
    {
        "question": "What does DDoS stand for?",
        "options": ['Direct Denial of Service', 'Distributed Denial of Service', 'Data Destruction of System', 'Digital Defense of Security'],
        "correct_option": 1,
        "explanation": "<b>DDoS</b> attacks overwhelm systems with traffic from multiple sources."
    },
    {
        "question": "Which is NOT a common security control for physical access?",
        "options": ['Badge readers', 'Biometrics', 'Mantraps', 'Firewalls'],
        "correct_option": 3,
        "explanation": "<b>Firewalls</b> are network security devices."
    },
    {
        "question": "What is the main purpose of a security champion program?",
        "options": ['Spread awareness', 'Monitor networks', 'Block attacks', 'Manage vendors'],
        "correct_option": 0,
        "explanation": "<b>Security champions</b> promote security practices within teams."
    },
    {
        "question": "Which is a common security control for cloud storage?",
        "options": ['Encryption', 'No access controls', 'Public sharing', 'No logging'],
        "correct_option": 0,
        "explanation": "<b>Encryption</b> protects data at rest in cloud environments."
    },
    {
        "question": "What does IAM stand for?",
        "options": ['Identity and Access Management', 'Internet Application Monitoring', 'Integrated Alert Mechanism', 'Internal Audit Management'],
        "correct_option": 0,
        "explanation": "<b>IAM</b> systems manage user identities and permissions."
    },
    {
        "question": "Which is NOT a common security metric?",
        "options": ['MTTD', 'MTTR', 'CVSS', 'FPS'],
        "correct_option": 3,
        "explanation": "<b>FPS</b> (Frames Per Second) measures video performance, not security."
    },
    {
        "question": "What is the main purpose of a purple team?",
        "options": ['Combine red/blue teams', 'Manage vendors', 'Handle HR', 'Process payroll'],
        "correct_option": 0,
        "explanation": "<b>Purple teams</b> integrate offensive and defensive security practices."
    }
    
]

def send_poll(question, options, correct_option, explanation):
    payload = {
        "chat_id": CHAT_ID,
        "question": question,
        "options": json.dumps(options),
        "is_anonymous": False,
        "type": "quiz",
        "correct_option_id": correct_option,
        "explanation": explanation,
        "explanation_parse_mode": "HTML"
    }
    
    try:
        response = requests.post(BASE_URL + "sendPoll", json=payload)
        response.raise_for_status()
        print(f"✅ [{datetime.now().strftime('%H:%M:%S')}] Poll sent successfully!")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ [{datetime.now().strftime('%H:%M:%S')}] Failed to send poll:")
        if hasattr(e, 'response') and e.response:
            print(f"HTTP {e.response.status_code} - {e.response.text}")
        else:
            print(str(e))
        return False

@app.route('/')
def home():
    return "Polling Bot is running!"

def run_bot():
    while True:
        for poll in polls:
            send_poll(**poll)
            time.sleep(3600)  # Wait 1 hour between polls

if __name__ == '__main__':
    # Start the bot in a separate thread
    from threading import Thread
    Thread(target=run_bot).start()
      app.run(host='0.0.0.0', port=int(os.getenv('PORT', 10000)))
