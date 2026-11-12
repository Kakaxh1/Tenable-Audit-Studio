# Tenable Nessus Universal Compliance Audit (.audit) Master Specification Guide

**Author:** kakaxh1 (Bhavy Morvadiya)  
**Standard:** Tenable Compliance Engine Specification (Universal Multi-Platform)  
**Encoding & Syntax Rules:** Strict ASCII, standard hyphens (-), valid XML tokens, zero smart quotes  
**Coverage:** Network Devices, Firewalls, Operating Systems, Databases, Cloud, Virtualization, and Middleware  

---

## Table of Contents
1. [Universal Architecture & Engine Execution Model](#1-universal-architecture--engine-execution-model)
2. [Global Matrix of All Nessus check_type Declarations](#2-global-matrix-of-all-nessus-check_type-declarations)
3. [Variables: Global Definition & Runtime Substitution](#3-variables-global-definition--runtime-substitution)
4. [Universal Key, Tag & Token Catalog](#4-universal-key-tag--token-catalog)
5. [Platform Family Specifications & Code Blueprints](#5-platform-family-specifications--code-blueprints)
   - 5.1 Network Infrastructure & Firewalls (Cisco, Fortinet, Palo Alto, Juniper, Check Point, Arista, F5, Huawei)
   - 5.2 Operating Systems (Linux, Unix, AIX, Solaris, macOS, Windows Server & Desktop)
   - 5.3 Database Management Systems (Oracle, MS SQL, MySQL, PostgreSQL, DB2, MongoDB)
   - 5.4 Cloud & Virtualization (AWS, Azure, GCP, VMware vCenter/ESXi, Docker, Kubernetes)
   - 5.5 Web Servers & Middleware (Apache, Nginx, IIS, Tomcat, WebLogic)
6. [Evaluation Logic & Matching Patterns](#6-evaluation-logic--matching-patterns)
7. [Comprehensive Troubleshooting & Real-World Error Catalog](#7-comprehensive-troubleshooting--real-world-error-catalog)
8. [Universal Offline Configuration Preparation Rules](#8-universal-offline-configuration-preparation-rules)
9. [Pre-Flight Multi-Platform Python Validation Script](#9-pre-flight-multi-platform-python-validation-script)
10. [Universal Production-Ready Boilerplate Templates](#10-universal-production-ready-boilerplate-templates)

---

## 1. Universal Architecture & Engine Execution Model

Every Tenable `.audit` file operates across a universal 5-stage evaluation pipeline regardless of whether the target is an enterprise core router, a Linux server, an Oracle database, or an AWS cloud account:

```
[Target Data Source: CLI / Config / SQL / API / Registry]
                           |
                           v
    Stage 1: Pre-Condition Check (<if><condition><item>)
                           |
            +--------------+--------------+
            |                             |
      (Condition FALSE)             (Condition TRUE)
            |                             |
            v                             v
     Route to <else>               Enter <then> Block
            |                             |
            |                             v
            |                  Stage 2: Scope Isolation
            |                  (context: / file: / reg_key: / sql_request:)
            |                             |
            |                             v
            |                  Stage 3: Element Extraction
            |                  (regex: / item: / reg_item:)
            |                             |
            |                             v
            |                  Stage 4: Compliance Validation
            |                  (expect: / not_equal: / sql_expect:)
            |                             |
            +-----------------------------+
                           |
                           v
             Stage 5: Result Generation
             (PASSED / WARNING / FAILED / ERROR)
```

### 1.1 Root Tag Grammar
Every audit file must start with a platform declaration tag `<check_type:"...">` and end with `</check_type>`. Nested immediately inside is `<group_policy:"...">`:

```xml
# This script is Copyright (C) 2026 kakaxh1 (Bhavy Morvadiya).

<check_type:"PLATFORM_IDENTIFIER">
<group_policy:"POLICY_IDENTIFIER">

# Variables, Pre-Conditions, and Custom Items

</group_policy>
</check_type>
```

---

## 2. Global Matrix of All Nessus check_type Declarations

Below is the complete reference table of official Nessus `<check_type:...>` declarations supported across the Tenable audit ecosystem:

| Target Domain | Platform / Technology | Official Header Tag | Primary Plugin ID |
| :--- | :--- | :--- | :--- |
| **Network** | Cisco IOS, IOS-XE, Catalyst, WLC | `<check_type:"Cisco">` | 24764 |
| **Network** | Cisco ASA / FTD Firewall | `<check_type:"Cisco_ASA">` | 24764 |
| **Network** | Cisco NX-OS (Nexus Data Center) | `<check_type:"Cisco_NXOS">` | 24764 |
| **Network** | Fortinet FortiOS (FortiGate, FortiAP, FortiSwitch) | `<check_type:"FortiGate">` | 84239 |
| **Network** | Palo Alto Networks PAN-OS (XML / CLI) | `<check_type:"Palo_Alto">` | 71261 |
| **Network** | Juniper Networks Junos OS | `<check_type:"Juniper">` | 33814 |
| **Network** | Check Point Gaia OS / SecurePlatform | `<check_type:"Check_Point">` | 51192 |
| **Network** | Arista Networks EOS | `<check_type:"Arista">` | 24764 |
| **Network** | F5 BIG-IP TMOS (LTM, GTM, ASM) | `<check_type:"F5">` | 58452 |
| **Network** | Huawei VRP | `<check_type:"Huawei">` | 24764 |
| **Network** | Extreme Networks (ExtremeXOS) | `<check_type:"Extreme">` | 24764 |
| **Network** | Brocade Fabric OS / IronWare | `<check_type:"Brocade">` | 24764 |
| **OS** | Linux (RHEL, Rocky, CentOS, SUSE, Debian, Ubuntu) | `<check_type:"Unix">` | 21745 |
| **OS** | Apple macOS (OS X) | `<check_type:"Unix">` | 21745 |
| **OS** | IBM AIX | `<check_type:"AIX">` | 21745 |
| **OS** | Oracle Solaris (10 / 11) | `<check_type:"Solaris">` | 21745 |
| **OS** | HP-UX | `<check_type:"HPUX">` | 21745 |
| **OS** | Microsoft Windows (Workstation 10/11, Server 2016-2025) | `<check_type:"Windows">` | 21156 |
| **Database** | Oracle Database (12c, 19c, 21c, 23c) | `<check_type:"Database" type:"Oracle">` | 21745 / DB |
| **Database** | Microsoft SQL Server (2014-2022) | `<check_type:"Database" type:"SQLServer">` | 21156 / DB |
| **Database** | MySQL / MariaDB | `<check_type:"Database" type:"MySQL">` | DB Plugin |
| **Database** | PostgreSQL | `<check_type:"Database" type:"PostgreSQL">` | DB Plugin |
| **Database** | IBM DB2 | `<check_type:"Database" type:"DB2">` | DB Plugin |
| **Database** | MongoDB | `<check_type:"Database" type:"MongoDB">` | DB Plugin |
| **Cloud** | Amazon Web Services (AWS IAM, S3, EC2, VPC) | `<check_type:"Cloud" type:"AWS">` | Cloud API |
| **Cloud** | Microsoft Azure | `<check_type:"Cloud" type:"Azure">` | Cloud API |
| **Cloud** | Google Cloud Platform (GCP) | `<check_type:"Cloud" type:"GCP">` | Cloud API |
| **Virtual** | VMware vCenter / ESXi Server | `<check_type:"VMware">` | 56984 |
| **Container** | Docker Engine & Daemon | `<check_type:"Docker">` | Docker Plugin |
| **Container** | Kubernetes Master & Node | `<check_type:"Kubernetes">` | K8s Plugin |

---

## 3. Variables: Global Definition & Runtime Substitution

Variables eliminate environment hardcoding across all platform types.

### 3.1 Syntax Structure
Declared immediately following `<group_policy:"...">`:

```xml
<variable>
  name: "AUTHORIZED_DNS_SERVERS"
  default: "10.10.1.10, 10.10.1.11"
  description: "Corporate DNS Server IP Addresses"
  info: "List of authorized DNS resolvers for domain lookups."
</variable>

<variable>
  name: "DB_AUDIT_RETENTION_DAYS"
  default: "90"
  description: "Database Audit Trail Retention (Days)"
  info: "Minimum audit log retention period mandated by regulatory baseline."
</variable>
```

### 3.2 Runtime Evaluation Rule
Every string `@VARIABLE_NAME@` occurring in any tag (`description`, `info`, `context`, `regex`, `expect`, `sql_request`, `reg_key`) is replaced at runtime with the configured value.

---

## 4. Universal Key, Tag & Token Catalog

### 4.1 Structural & Metadata Keys (Supported Universally)

| Key | Status | Description | Standard Usage |
| :--- | :--- | :--- | :--- |
| `type:` | Required | Engine check mechanism. | `CONFIG_CHECK`, `FILE_CONTENT_CHECK`, `SQL_EXEC`, `REGISTRY_SETTING` |
| `description:` | Required | Unique control identifier and title. | `"NIMF_SEC_01 Ensure NTP is Active"` |
| `info:` | Recommended | Technical justification and business risk. | Text explaining why non-compliance is dangerous. |
| `solution:` | Recommended | Remediation script or configuration change. | Specific CLI or SQL command to fix finding. |
| `reference:` | Optional | Regulatory framework mappings. | `"CIS-CSCv8\|4.1,NIST-800-53\|AC-17"` |
| `see_also:` | Optional | Hyperlink to external standard. | `"https://workbench.cisecurity.org/"` |
| `severity:` | Required | Risk rating. | `PASSED`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

---

### 4.2 Scope & Extraction Keys by Technology Domain

#### Network & Security Appliances (Cisco, FortiOS, Junos, PAN-OS)
- `context:`: Isolates section boundaries (e.g. `context: "config system global"`, `context: "router bgp 65000"`).
- `regex:`: PCRE pattern matching the specific configuration line.
- `expect:`: Expected compliant setting value.
- `match_all: YES | NO`: When YES, enforces that every matching block must satisfy `expect:`.
- `required: YES | NO`: When YES, flags violation if `context:` is absent.
- `not_equal: YES | NO`: When YES, flags violation if line matches `expect:`.

#### Operating Systems (Linux, Unix, AIX, Solaris)
- `file:`: Absolute file path (e.g. `file: "/etc/ssh/sshd_config"`).
- `regex:`: Line pattern matching regex inside file.
- `expect:`: Required directive line value.
- `mask:`: Octal permission bitmask (e.g. `mask: "027"` for `/etc/shadow`).
- `owner:`: Expected system user owner (e.g. `owner: "root"`).
- `group:`: Expected group owner (e.g. `group: "root"`).
- `cmd:`: Raw shell command executed when `type: CMD_EXEC`.

#### Windows Systems (Desktop & Server)
- `reg_key:`: Registry hive path (e.g. `reg_key: "HKLM\Software\Policies\Microsoft\Windows\System"`).
- `reg_item:`: Registry value name (e.g. `reg_item: "EnableSmartScreen"`).
- `reg_type:`: Registry data type (`REG_DWORD`, `REG_SZ`, `REG_MULTI_SZ`, `REG_BINARY`).
- `value_data:`: Expected registry value data.
- `value_type:`: Policy check comparison operator (`POLICY_DWORD`, `POLICY_TEXT`).

#### Databases (Oracle, MS SQL, MySQL, PostgreSQL)
- `sql_request:`: SQL query executed against the database catalog.
- `sql_types:`: Comma-separated column data types returned (e.g. `sql_types: POLICY_VARCHAR, POLICY_INTEGER`).
- `sql_regex:`: Pattern applied against the query result.
- `sql_expect:`: Expected compliant query return value.
- `sql_not_equal: YES | NO`: Inverts validation logic.

---

## 5. Platform Family Specifications & Code Blueprints

---

### 5.1 Network Infrastructure & Firewalls

#### A. Cisco IOS / IOS-XE / Catalyst / WLC
```xml
<check_type:"Cisco">
<group_policy:"Cisco Hardening Baseline">
<custom_item>
  type: CONFIG_CHECK
  description: "CISCO_01 Enforce SSHv2 and Terminate Insecure vty Protocols"
  info: "Ensure Telnet is prohibited on all virtual terminal lines."
  solution: "line vty 0 15 -> transport input ssh"
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-17"
  severity: HIGH
  context: "line vty [0-9]+ [0-9]+"
  regex: "^\\s*transport input "
  expect: "^\\s*transport input ssh$"
</custom_item>
</group_policy>
</check_type>
```

#### B. Fortinet FortiOS / FortiGate / FortiAP
```xml
<check_type:"FortiGate">
<group_policy:"Fortinet FortiOS Baseline">
<custom_item>
  type: CONFIG_CHECK
  description: "FORTINET_01 Relocate Admin Web GUI Port to Non-Standard"
  info: "Relocating admin HTTPS port reduces automated reconnaissance."
  solution: "config system global -> set admin-sport 8443 -> end"
  reference: "NIST-800-53|AC-17"
  severity: MEDIUM
  context: "config system global"
  regex: "set admin-sport [0-9]+"
  expect: "set admin-sport 8443"
</custom_item>

<custom_item>
  type: CONFIG_CHECK
  description: "FORTINET_02 Exclude Legacy 802.11b Rates on FortiAP Radio 1"
  info: "Legacy 802.11b rates cause severe airtime starvation and low-speed downgrade attacks."
  solution: "config wireless-controller wtp -> edit <AP> -> config radio-1 -> set band 802.11g 802.11n-2G 802.11ax-2G -> end"
  reference: "NIST-800-53|AC-18"
  severity: HIGH
  context: "config wireless-controller wtp"
  regex: "set band [^\n]+"
  expect: "set band 802.11g 802.11n-2G 802.11ax-2G"
</custom_item>
</group_policy>
</check_type>
```

#### C. Palo Alto Networks PAN-OS (XML Architecture)
```xml
<check_type:"Palo_Alto">
<group_policy:"Palo Alto PAN-OS Baseline">
<custom_item>
  type: CONFIG_CHECK
  description: "PANOS_01 Ensure Idle Admin Timeout is Configured to 15 Minutes or Less"
  info: "Administrative sessions must disconnect after inactivity."
  solution: "deviceconfig -> system -> idle-timeout <= 15"
  reference: "CIS-CSCv8|4.2,NIST-800-53|AC-12"
  severity: MEDIUM
  context: "<deviceconfig>.*<system>"
  regex: "<idle-timeout>[0-9]+</idle-timeout>"
  expect: "<idle-timeout>([1-9]|1[0-5])</idle-timeout>"
</custom_item>
</group_policy>
</check_type>
```

#### D. Juniper Networks Junos OS
```xml
<check_type:"Juniper">
<group_policy:"Juniper Junos Baseline">
<custom_item>
  type: CONFIG_CHECK
  description: "JUNOS_01 Disable Telnet Service in System Services"
  info: "Prohibit clear text Telnet management."
  solution: "delete system services telnet"
  reference: "CIS-CSCv8|4.1"
  severity: HIGH
  context: "system {"
  regex: "services {"
  expect: "^(?!.*telnet;).*$"
</custom_item>
</group_policy>
</check_type>
```

---

### 5.2 Operating Systems

#### A. Linux (RHEL 8/9, SUSE SLES, Ubuntu, Debian)
```xml
<check_type:"Unix">
<group_policy:"Linux OS Security Baseline">
<custom_item>
  type: FILE_CONTENT_CHECK
  description: "LINUX_01 Disable SSH Root Login"
  info: "Prevent direct remote login as root to enforce audit accountability."
  solution: "Edit /etc/ssh/sshd_config and set PermitRootLogin no"
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-6"
  severity: HIGH
  file: "/etc/ssh/sshd_config"
  regex: "^\\s*PermitRootLogin\\s+"
  expect: "^\\s*PermitRootLogin\\s+no\\s*$"
</custom_item>

<custom_item>
  type: FILE_CHECK
  description: "LINUX_02 Ensure /etc/shadow Permissions Are Protected"
  info: "Shadow password hashes must not be readable by unprivileged users."
  solution: "chmod 0640 /etc/shadow && chown root:root /etc/shadow"
  reference: "CIS-CSCv8|3.3"
  severity: HIGH
  file: "/etc/shadow"
  owner: "root"
  mask: "027"
</custom_item>
</group_policy>
</check_type>
```

#### B. Microsoft Windows (Server 2019/2022, Windows 10/11)
```xml
<check_type:"Windows">
<group_policy:"Windows Enterprise Hardening">
<custom_item>
  type: REGISTRY_SETTING
  description: "WIN_01 Ensure SMBv1 Protocol Driver is Disabled"
  info: "SMBv1 is vulnerable to remote code execution vulnerabilities including EternalBlue."
  solution: "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 to 0"
  reference: "CIS-CSCv8|4.1,NIST-800-53|SI-2"
  severity: CRITICAL
  reg_key: "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
  reg_item: "SMB1"
  value_type: POLICY_DWORD
  value_data: 0
  reg_option: CAN_NOT_BE_NULL
</custom_item>

<custom_item>
  type: PASSWORD_POLICY
  description: "WIN_02 Enforce Minimum Password Length of 14 Characters"
  info: "Strong password length prevents brute force hash recovery."
  solution: "Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy"
  reference: "NIST-800-53|IA-5"
  severity: HIGH
  password_policy: MINIMUM_PASSWORD_LENGTH
  value_data: 14
  check_type: CHECK_GREATER_THAN_OR_EQUAL
</custom_item>
</group_policy>
</check_type>
```

---

### 5.3 Database Management Systems

#### A. Oracle Database (19c / 21c / 23c)
```xml
<check_type:"Database" type:"Oracle">
<group_policy:"Oracle Database Security Baseline">
<custom_item>
  type: SQL_EXEC
  description: "ORA_01 Ensure Remote OS Authentication Is Disabled"
  info: "Remote OS authentication allows external clients to bypass database authentication."
  solution: "ALTER SYSTEM SET REMOTE_OS_AUTHENT=FALSE SCOPE=SPFILE;"
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-3"
  severity: HIGH
  sql_request: "SELECT UPPER(value) FROM v$parameter WHERE UPPER(name) = 'REMOTE_OS_AUTHENT';"
  sql_types: POLICY_VARCHAR
  sql_expect: "FALSE"
</custom_item>
</group_policy>
</check_type>
```

#### B. Microsoft SQL Server
```xml
<check_type:"Database" type:"SQLServer">
<group_policy:"MS SQL Server Baseline">
<custom_item>
  type: SQL_EXEC
  description: "MSSQL_01 Ensure Default 'sa' Administrator Account Is Disabled"
  info: "The default sa account is targeted by brute force authentication tools."
  solution: "ALTER LOGIN [sa] DISABLE;"
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-2"
  severity: HIGH
  sql_request: "SELECT is_disabled FROM sys.server_principals WHERE name = 'sa';"
  sql_types: POLICY_INTEGER
  sql_expect: 1
</custom_item>
</group_policy>
</check_type>
```

#### C. PostgreSQL
```xml
<check_type:"Database" type:"PostgreSQL">
<group_policy:"PostgreSQL Hardening Baseline">
<custom_item>
  type: SQL_EXEC
  description: "PGSQL_01 Ensure Log Disconnections Are Captured"
  info: "Logging disconnections provides chronological auditing of session duration."
  solution: "ALTER SYSTEM SET log_disconnections = 'on';"
  reference: "NIST-800-53|AU-2"
  severity: MEDIUM
  sql_request: "SELECT setting FROM pg_settings WHERE name = 'log_disconnections';"
  sql_types: POLICY_VARCHAR
  sql_expect: "on"
</custom_item>
</group_policy>
</check_type>
```

---

### 5.4 Cloud & Virtualization

#### A. Amazon Web Services (AWS)
```xml
<check_type:"Cloud" type:"AWS">
<group_policy:"AWS CIS Foundations Baseline">
<custom_item>
  type: AWS_IAM
  description: "AWS_01 Ensure MFA Is Enabled for Root Account"
  info: "Root credentials have unrestricted privileges across all accounts and resources."
  solution: "Enable hardware or virtual MFA device under IAM Security Credentials for root user."
  reference: "CIS-CSCv8|4.2,NIST-800-53|IA-2"
  severity: CRITICAL
  aws_action: "get-account-summary"
  json_key: "SummaryMap.AccountMFAEnabled"
  expect: "1"
</custom_item>
</group_policy>
</check_type>
```

#### B. VMware vCenter & ESXi
```xml
<check_type:"VMware">
<group_policy:"VMware vSphere Hardening">
<custom_item>
  type: CONFIG_CHECK
  description: "VMW_01 Ensure ESXi Shell and SSH Services Are Stopped"
  info: "Local and remote shell access should remain disabled during normal operation."
  solution: "Stop TSM and TSM-SSH services on ESXi host."
  reference: "NIST-800-53|AC-17"
  severity: HIGH
  vmware_item: "service[TSM-SSH].running"
  expect: "false"
</custom_item>
</group_policy>
</check_type>
```

#### C. Docker Daemon
```xml
<check_type:"Docker">
<group_policy:"Docker Daemon Baseline">
<custom_item>
  type: FILE_CONTENT_CHECK
  description: "DOCKER_01 Ensure Insecure Registries Are Prohibited"
  info: "Communication with unauthenticated registries exposes images to tampering."
  solution: "Remove 'insecure-registries' entry from /etc/docker/daemon.json"
  reference: "CIS-CSCv8|3.3"
  severity: HIGH
  file: "/etc/docker/daemon.json"
  regex: "\"insecure-registries\""
  expect: "^(?!.*insecure-registries).*$"
</custom_item>
</group_policy>
</check_type>
```

---

## 6. Evaluation Logic & Matching Patterns

### Pattern 1: Exact Value Match
Target parameter must match the expected compliant string exactly.
```xml
context: "config system global"
regex: "set admin-sport [0-9]+"
expect: "set admin-sport 8443"
```

### Pattern 2: Regex Numerical Range Match
Target parameter must fall within a compliant range (e.g. idle timeout between 1 and 15).
```xml
context: "config system global"
regex: "set admintimeout [0-9]+"
expect: "set admintimeout ([1-9]|1[0-5])$"
```

### Pattern 3: Negative Lookahead (Absence Check)
Verify that a dangerous keyword (e.g. `802.11b` or `telnet`) is absent.
```xml
context: "config radio-1"
regex: "set band [^\n]+"
expect: "^set band (?!.*802\\.11b).*$"
```

### Pattern 4: Negative Inversion with `not_equal: YES`
Flags a violation if the forbidden default is detected.
```xml
context: "config system global"
regex: "set admin-telnet-port [0-9]+"
expect: "set admin-telnet-port 23"
not_equal: YES
```

### Pattern 5: Human Inspection Flagging (`Manual Review Required`)
Flags controls that require operational auditor review without crashing the parser.
```xml
<custom_item>
  type: CONFIG_CHECK
  description: "Firmware Up to Date Inspection"
  info: "Manual Review Required: Verify firmware release notes against vendor portal."
  severity: MEDIUM
  context: "config system global"
  regex: ".*"
  expect: "^Manual Review Required$"
</custom_item>
```

---

## 7. Comprehensive Troubleshooting & Real-World Error Catalog

| Error Output | Root Cause | Target-Specific Resolution |
| :--- | :--- | :--- |
| **`Field not supported: item (line: X, col: Y)`** | Using `item:` in a check type that expects `regex:`/`expect:`, or nesting `item:` inside a FortiGate/network check. | In FortiGate and Cisco checks, use `context:`, `regex:`, and `expect:`. Never use `item:` as a field inside `CONFIG_CHECK`. |
| **`Type is not supported: CONFIG_CHECK_NOT`** | `CONFIG_CHECK_NOT` is not an engine keyword. | Use standard `type: CONFIG_CHECK` with regex negative lookahead: `expect: "^set band (?!.*802\\.11b).*$"`, or use `<condition type:"NOT">`. |
| **`Parse error line X - unknown token 'context'`** | Writing `context:` inside a Unix/Linux audit (`<check_type:"Unix">`). | `context:` is supported only in network plugins (`Cisco`, `FortiGate`). In Unix checks, use `file:` or `cmd:`. |
| **`Check type of 'FortiGate' is not supported with the Unix plugin`** | Uploading a FortiOS audit under SSH/Unix host credentials or wrong scan policy plugin family. | Set scan credentials under FortiOS / Network credentials, or select FortiOS target framework in offline compliance policy. |
| **`Parse error line X - unknown token '_type'`** | Typo in tags or attributes (e.g. `_type:` instead of `type:`, or `<item _type="...">`). | Use standard keywords: `type: CONFIG_CHECK`, `<condition type:"AND">`. |
| **`Could not lex the file ...`** | Lexical analyzer failed due to non-ASCII smart quotes, Unicode dashes, unclosed quotes, or unclosed XML tags. | Use strict ASCII with standard straight quotes (`"`) and standard hyphens (`-`). Ensure all tags (`<item>`, `<custom_item>`, `<then>`, `<if>`) are closed. |
| **`Scan evaluates 0 items / Shows nothing`** | 1. Condition mismatch: The `<condition>` looks for `config system global`, but the uploaded file is an AP snippet (`config wireless-controller wtp`).<br>2. Interactive CLI prompt strings (`NAMBORFW70_Borivali #`) pollute the config.<br>3. Missing `#config-version=` header. | 1. Align the `<condition>` block to check for sections present in the snippet.<br>2. Strip interactive shell headers (`#`, `show`).<br>3. Add `#config-version=...` to the top of offline configs. |

---

## 8. Universal Offline Configuration Preparation Rules

When performing offline audits:

1. **Remove CLI Prompts**: Strip prompt strings like `hostname #`, `(config)#`, `(wtp)#`, `mysql> `, `SQL> `.
2. **Remove Interactive Commands**: Remove command text lines like `show running-config`, `show`, `display current-configuration`.
3. **Include Header Version Banners**:
   - FortiOS: `#config-version=MODEL-VERSION-BUILD`
   - Cisco: `version 17.x` and `hostname <name>`
   - PAN-OS: `<?xml version="1.0"?> <config version="10.2">`
4. **Preserve Indentation**: Do not flatten hierarchy; child statements depend on whitespace or opening/closing blocks.
5. **Strict UTF-8 without BOM**: Save all configuration files and `.audit` files with standard UTF-8 encoding without Byte Order Mark.

---

## 9. Pre-Flight Multi-Platform Python Validation Script

Use this script to validate syntax across all audit types before uploading to Nessus:

```python
import sys
import re

def validate_universal_audit(filepath):
    print(f"Executing Universal Pre-Flight Validation for: {filepath}")
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    errors = 0

    # Test 1: Check for Unicode dashes
    em_dashes = content.count('\u2014')
    en_dashes = content.count('\u2013')
    if em_dashes > 0 or en_dashes > 0:
        print(f"[FAIL] Found Unicode dashes: {em_dashes} em-dashes, {en_dashes} en-dashes. Must use standard hyphens (-).")
        errors += 1

    # Test 2: Check for smart quotes
    smart_quotes = len(re.findall(r'[\u2018\u2019\u201C\u201D]', content))
    if smart_quotes > 0:
        print(f"[FAIL] Found {smart_quotes} curly/smart quotes. Must use ASCII straight quotes (\").")
        errors += 1

    # Test 3: Check for unsupported fake check types
    if "CONFIG_CHECK_NOT" in content:
        print("[FAIL] Found invalid check type 'CONFIG_CHECK_NOT'. Use regex negative lookahead instead.")
        errors += 1

    # Test 4: Verify check_type header tag
    if not re.search(r'<check_type:\s*"[^"]+">', content):
        print("[FAIL] Missing or malformed root <check_type:\"...\"> declaration.")
        errors += 1

    # Test 5: Verify balanced container tags
    tags = ['item', 'custom_item', 'condition', 'if', 'then', 'else', 'group_policy', 'check_type']
    for tag in tags:
        open_count = len(re.findall(rf'<{tag}(\s+[^>]*>|:\s*"[^"]*">|>)', content))
        close_count = len(re.findall(rf'</{tag}>', content))
        if open_count != close_count:
            print(f"[FAIL] Tag count mismatch for <{tag}>: {open_count} opened vs {close_count} closed.")
            errors += 1

    if errors == 0:
        print("[SUCCESS] Audit file passed all multi-platform lexer and syntax validation tests!")
        return True
    else:
        print(f"[ERROR] Found {errors} syntax violations. Correct before loading into Nessus.")
        return False

if __name__ == '__main__':
    if len(sys.argv) > 1:
        validate_universal_audit(sys.argv[1])
    else:
        print("Usage: python validate_universal_audit.py <path_to_audit_file>")
```

---

## 10. Universal Production-Ready Boilerplate Templates

### 10.1 Universal Network Boilerplate (FortiOS Example)
```xml
# This script is Copyright (C) 2026 kakaxh1 (Bhavy Morvadiya).

<check_type:"FortiGate">

<group_policy:"Universal Enterprise Baseline">

<variable>
  name: "CORP_NTP_SERVER"
  default: "10.123.32.1"
  description: "Enterprise NTP Server"
  info: "Authorized primary NTP time server IP."
</variable>

<variable>
  name: "ADMIN_PORT"
  default: "8443"
  description: "HTTPS Management Port"
  info: "Custom TCP port for administrative GUI."
</variable>

<if>
  <condition type:"AND">
    <item>
      type: CONFIG_CHECK
      description: "FortiOS System Table Detected"
      context: "config system global"
      regex: "set hostname "
      expect: "set hostname "
    </item>
  </condition>

  <then>
    <custom_item>
      type: CONFIG_CHECK
      description: "NIMF_FW_01 Enforce Custom Admin HTTPS Port"
      info: "Ensure administrative web access is relocated from default port 443 to @ADMIN_PORT@."
      solution: "config system global -> set admin-sport @ADMIN_PORT@ -> end"
      reference: "NIST-800-53|AC-17"
      severity: MEDIUM
      context: "config system global"
      regex: "set admin-sport [0-9]+"
      expect: "set admin-sport @ADMIN_PORT@"
    </custom_item>

    <custom_item>
      type: CONFIG_CHECK
      description: "NIMF_FW_02 Ensure Telnet Service Is Disabled"
      info: "Unencrypted Telnet transmits administrative credentials in clear text."
      solution: "config system global -> set admin-telnet-port 0 (or disable) -> end"
      reference: "CIS-CSCv8|4.1"
      severity: HIGH
      context: "config system global"
      regex: "set admin-telnet-port [0-9]+"
      expect: "set admin-telnet-port 23"
      not_equal: YES
    </custom_item>
  </then>

  <else>
    <custom_item>
      type: CONFIG_CHECK
      description: "FortiOS Global Settings Table Not Detected"
      info: "Target configuration is missing the global configuration table."
      severity: LOW
    </custom_item>
  </else>
</if>

</group_policy>
</check_type>
```

### 10.2 Universal Operating System Boilerplate (Linux Example)
```xml
# This script is Copyright (C) 2026 kakaxh1 (Bhavy Morvadiya).

<check_type:"Unix">

<group_policy:"Linux Enterprise Hardening Baseline">

<variable>
  name: "SYSLOG_COLLECTOR"
  default: "10.123.32.1"
  description: "Enterprise SIEM Server"
  info: "IP address of remote central syslog server."
</variable>

<if>
  <condition type:"AND">
    <item>
      type: FILE_CHECK
      description: "Verify Linux Shadow File Exists"
      file: "/etc/shadow"
    </item>
  </condition>

  <then>
    <custom_item>
      type: FILE_CONTENT_CHECK
      description: "NIMF_LNX_01 Ensure SSH Root Login is Prohibited"
      info: "Direct root login over SSH bypasses individual accountability."
      solution: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
      reference: "CIS-CSCv8|4.1,NIST-800-53|AC-6"
      severity: HIGH
      file: "/etc/ssh/sshd_config"
      regex: "^\\s*PermitRootLogin\\s+"
      expect: "^\\s*PermitRootLogin\\s+no\\s*$"
    </custom_item>

    <custom_item>
      type: FILE_CHECK
      description: "NIMF_LNX_02 Protect /etc/shadow File Permissions"
      info: "Shadow password hashes must not be world-readable."
      solution: "chmod 0640 /etc/shadow && chown root:root /etc/shadow"
      reference: "CIS-CSCv8|3.3"
      severity: HIGH
      file: "/etc/shadow"
      owner: "root"
      mask: "027"
    </custom_item>
  </then>

  <else>
    <custom_item>
      type: FILE_CHECK
      description: "Target is not a standard Linux environment"
      info: "/etc/shadow was not detected on target."
      severity: LOW
      file: "/etc/shadow"
    </custom_item>
  </else>
</if>

</group_policy>
</check_type>
```
