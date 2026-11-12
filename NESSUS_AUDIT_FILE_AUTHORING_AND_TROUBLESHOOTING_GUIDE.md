# Tenable Nessus Audit File (.audit) Authoring & Troubleshooting Guide

**Author:** kakaxh1 (Bhavy Morvadiya)  
**Target Audience:** Compliance Engineers, Security Auditors, and DevSecOps Practitioners  
**Scope:** Architecture, Syntax Rules, Real-World Parser Errors, and Target-Specific Guidelines for Tenable Nessus Compliance Auditing  

---

## 1. Core Architecture of a Nessus .audit File

A Tenable `.audit` file is an XML-like structured plain-text configuration file utilized by the Tenable Nessus compliance engine (Plugins 21745 for Unix, 24764 for Cisco, 84239 for FortiGate, 21156 for Windows, etc.) to evaluate system and network device configurations against benchmarks (CIS, NIST SP 800-53, DISA STIG, or custom internal baselines).

### 1.1 Structural Anatomy

Every `.audit` file follows a strict hierarchical structure:

```xml
# This script is Copyright (C) 2026 kakaxh1 (Bhavy Morvadiya).

<check_type:"TARGET_PLUGIN_TYPE">

<group_policy:"POLICY_NAME">

<if>
  <condition type:"AND">
    <item>
      type: CONFIG_CHECK
      description: "Target environment verification"
      # Target-specific existence test
    </item>
  </condition>

  <then>
    <custom_item>
      type: CONFIG_CHECK
      description: "NIMF_CTRL_01 Ensure baseline parameter is configured"
      info: "Detailed rationale and background information."
      solution: "Remediation command syntax."
      reference: "CIS-CSCv8|1.1,NIST-800-53|CM-6"
      see_also: "https://workbench.cisecurity.org/"
      severity: MEDIUM
      # Target-specific context, regex, and expect fields
    </custom_item>
  </then>

  <else>
    <custom_item>
      type: CONFIG_CHECK
      description: "NIMF_CTRL_01 Target environment not detected"
      info: "The target system did not match the required platform criteria."
      severity: LOW
    </custom_item>
  </else>
</if>

</group_policy>
</check_type>
```

---

## 2. Catalog of Real-World Errors & How to Fix Them

During compliance scan execution and offline parser evaluation, Nessus enforces strict grammar and lexer rules. Below are the exact errors encountered in enterprise environments and their precise technical resolutions.

---

### Error 1: `Field not supported: item (line: X, col: Y)`

#### Why It Occurs:
1. **Key-Value Name Confusion**: Using `item:` inside a check type that does not support the `item` keyword, or mistaking the tag `<item>` for a key `item:`.
2. **Duplicate or Illegal Field in Network Checks**: In `FortiGate` or `Cisco` checks, configuration blocks use `context:`, `regex:`, and `expect:`. If an auditor adds `item: "set foo"`, the parser rejects the line with `Field not supported: item`.
3. **Unix vs Network Syntax Collision**: In Unix `FILE_CONTENT_CHECK`, `regex:` and `expect:` are standard, whereas `AUDIT_ALLOWED_SERVICES` uses `service:` or `item:`. Mixing keywords across check types triggers this error.

#### Incorrect Code:
```xml
# INCORRECT in FortiGate / Cisco checks
<custom_item>
  type: CONFIG_CHECK
  description: "Check NTP Configuration"
  context: "config system ntp"
  item: "set status enable"       # ERROR: 'item' is not supported here
  expect: "set status enable"
</custom_item>
```

#### Correct Code:
```xml
# CORRECT for FortiGate / Cisco checks
<custom_item>
  type: CONFIG_CHECK
  description: "Check NTP Configuration"
  context: "config system ntp"
  regex: "set status enable"
  expect: "set status enable"
</custom_item>
```

---

### Error 2: `Type is not supported: CONFIG_CHECK_NOT`

#### Why It Occurs:
Nessus compliance engines **do not have a check type named `CONFIG_CHECK_NOT`**. Auditors attempting to verify that a command is *absent* (e.g. ensuring `telnet` or `802.11b` is not present) frequently invent `CONFIG_CHECK_NOT`, which causes immediate policy parsing abort.

#### How to Perform Negative / Absence Checks Correctly:

There are two approved patterns in Nessus for negative checks:

#### Approach A: Negative Lookahead Regex (Recommended for Single Custom Item)
Use standard `type: CONFIG_CHECK` and enforce that the forbidden parameter is never matched, or match the context and require a negated pattern:

```xml
<custom_item>
  type: CONFIG_CHECK
  description: "Ensure Legacy 802.11b Data Rates Are Excluded"
  context: "config radio-1"
  regex: "set band [^\n]+"
  expect: "^set band (?!.*802\\.11b).*$"
  severity: HIGH
</custom_item>
```

#### Approach B: `<condition type:"NOT">` with `<if>` Block
Wrap a standard check inside a `<condition type:"NOT">`:

```xml
<if>
  <condition type:"NOT">
    <item>
      type: CONFIG_CHECK
      description: "Detect Telnet Service"
      context: "config system global"
      regex: "set admin-telnet-port 23"
      expect: "set admin-telnet-port 23"
    </item>
  </condition>
  <then>
    <custom_item>
      type: CONFIG_CHECK
      description: "Telnet Service is Disabled"
      info: "Telnet is not enabled on the system."
      severity: LOW
    </custom_item>
  </then>
  <else>
    <custom_item>
      type: CONFIG_CHECK
      description: "Telnet Service is Enabled (Violation)"
      info: "Insecure Telnet was detected on port 23."
      severity: HIGH
    </custom_item>
  </else>
</if>
```

---

### Error 3: `Parse error line X - unknown token 'context'`

#### Why It Occurs:
The `context` keyword defines configuration hierarchy (e.g. Cisco `line vty 0 4` or Fortinet `config system global`). It is valid **only** in network device plugins (`<check_type:"Cisco">`, `<check_type:"FortiGate">`, `<check_type:"Extreme">`, etc.).

If you write `context:` inside a Unix, Linux, or Windows check (`<check_type:"Unix">` or `<check_type:"Windows">`), the Unix plugin does not recognize the token `context` and throws a fatal parse error.

#### Incorrect Code:
```xml
<check_type:"Unix">
<custom_item>
  type: FILE_CONTENT_CHECK
  description: "Verify SSH Protocol"
  file: "/etc/ssh/sshd_config"
  context: "Host *"               # ERROR: 'context' is unknown to the Unix plugin
  regex: "^Protocol "
  expect: "^Protocol 2$"
</custom_item>
</check_type>
```

#### Correct Code:
```xml
<check_type:"Unix">
<custom_item>
  type: FILE_CONTENT_CHECK
  description: "Verify SSH Protocol"
  file: "/etc/ssh/sshd_config"
  regex: "^Protocol "
  expect: "^Protocol 2$"
</custom_item>
</check_type>
```

---

### Error 4: `Check type of 'FortiGate' is not supported with the Unix plugin`

#### Why It Occurs:
This occurs when:
1. An audit file declaring `<check_type:"FortiGate">` is uploaded to a scan policy whose target credential type is configured as **SSH / Unix Host**, triggering Plugin 21745 instead of the Fortinet Plugin 84239.
2. An offline scan is executed without specifying the FortiOS offline configuration framework.

#### Resolution:
- For online scans: Configure credentials under **Network / FortiOS Credentials** in the Nessus scan policy, not under Host/Linux SSH.
- For offline scans: In the Nessus compliance policy, select the target platform as **FortiOS / FortiGate**, or upload the configuration under the FortiOS configuration attachment.

---

### Error 5: `Parse error line X - unknown token '_type'`

#### Why It Occurs:
A syntax typo in the opening declaration or inside tags:
- Writing `_type:` instead of `type:`.
- Writing `<check_type:"Cisco" _type:"audit">` or similar malformed XML tag attributes.
- Writing `<item _type:"CONFIG_CHECK">`.

#### Resolution:
Tags in Nessus audit files only use standard attributes:
```xml
# Valid tags and tokens:
<check_type:"Cisco">
<group_policy:"Policy Name">
<condition type:"AND">
<item>
<custom_item>
type: CONFIG_CHECK
```

---

### Error 6: `Could not lex the file C:\ProgramData\Tenable\Nessus\nessus\tmp\tmp.policy-...`

#### Why It Occurs:
"Lexing" is the lexical analysis stage where the parser turns raw characters into tokens. Lexer failures occur when:
1. **Invalid UTF-8 Characters / Smart Quotes**: Using curly quotes (`“` `”` `'` `'`) copied from Microsoft Word, Outlook, or web browsers instead of standard ASCII quotes (`"` `'`).
2. **Em-Dashes and En-Dashes**: Using Unicode em-dashes or en-dashes instead of standard ASCII hyphens (`-`).
3. **Unclosed Quotes**: A string like `description: "Check SSID Name` missing the closing quote.
4. **Unclosed Tags**: Missing closing `</item>`, `</custom_item>`, `</then>`, `</if>`, or `</check_type>`.
5. **Special XML Characters**: Using raw unescaped `<` or `>` inside `description` or `info` without quotes.

#### Resolution:
- Sanitize the entire `.audit` file into strict clean ASCII.
- Replace all curly quotes with straight quotes (`"`).
- Replace all Unicode dashes with standard hyphens (`-`).
- Always enclose string values in double quotes.

---

### Error 7: Nessus Scan Evaluates 0 Items / Shows Nothing

#### Why It Occurs:
1. **Condition Block Failure**:
   ```xml
   <if>
     <condition type:"AND">
       <item>
         type: CONFIG_CHECK
         context: "config system global"
         expect: "set hostname"
       </item>
     </condition>
     <then>
       # All 50 custom items live here!
     </then>
   </if>
   ```
   If you scan a partial configuration snippet (such as an AP export `config wireless-controller wtp` or an interface export), `config system global` is not present in the file. The `<condition>` evaluates to `FALSE`, skipping the entire `<then>` block. Because there is no matching check in `<else>`, Nessus outputs: **Total Compliance Items Evaluated: 0**.
2. **Interactive CLI Shell Headers**:
   If an administrator copies configuration directly from an active terminal:
   ```text
   NAMBORFW70_Borivali # config wireless-controller wtp
   NAMBORFW70_Borivali (wtp) # edit "FP231FTF2209C80S"
   NAMBORFW70_Borivali (FP231FTF2209C80S) # show
   ```
   The prompt string `NAMBORFW70_Borivali #` breaks the offline parser grammar.
3. **Missing Offline Header**:
   FortiOS offline configs require:
   ```text
   #config-version=FAP231F-7.6.5-FW-build1105
   ```
   Cisco offline configs require standard banner/version output (`version 17.15`, `hostname ...`).

#### Resolution:
- Align the `<condition>` block directly with the content present in the target snippet. For a FortiAP WTP snippet, use:
  ```xml
  <condition type:"AND">
    <item>
      type: CONFIG_CHECK
      description: "FortiAP WTP Configuration Detected"
      context: "config wireless-controller wtp"
      regex: "edit \"[^\"]+\""
      expect: "edit "
    </item>
  </condition>
  ```
- Strip out terminal prompts (`#`, `show`) from the configuration file before scanning.
- Ensure the offline configuration file starts with the proper version line.

---

## 3. Target-Specific Authoring Guidelines

Different target platforms utilize different plugins, check types, and grammar tokens.

---

### 3.1 Cisco IOS / IOS-XE / Catalyst 9000 / WLC

- **Header:** `<check_type:"Cisco">`
- **Primary Check Type:** `CONFIG_CHECK`
- **Key Fields:** `context`, `regex`, `expect`

#### Example Cisco Item:
```xml
<custom_item>
  type: CONFIG_CHECK
  description: "NIMF_CISCO_01 Enforce SSH Version 2"
  info: "Ensure only SSHv2 is enabled for remote administrative access."
  solution: "Configure: ip ssh version 2"
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-17"
  see_also: "https://workbench.cisecurity.org/"
  severity: HIGH
  regex: "^ip ssh version "
  expect: "^ip ssh version 2$"
</custom_item>

<custom_item>
  type: CONFIG_CHECK
  description: "NIMF_CISCO_02 Restrict VTY Lines"
  info: "Ensure VTY transport input enforces SSH only."
  solution: "Configure: line vty 0 4 -> transport input ssh"
  reference: "NIST-800-53|AC-17"
  severity: MEDIUM
  context: "line vty [0-9]+"
  regex: "^\\s*transport input "
  expect: "^\\s*transport input ssh$"
</custom_item>
```

#### Important Cisco Rules:
- Top-level commands (like `ip ssh version 2` or `service password-encryption`) do not require a `context:`.
- Sub-block commands (under `line vty`, `interface GigabitEthernet`, `router ospf`) **must** declare `context:`.
- In `context:`, use regular expressions to match dynamic ranges, e.g., `context: "line vty [0-9]+ [0-9]+"`.

---

### 3.2 Fortinet FortiOS / FortiGate / FortiAP

- **Header:** `<check_type:"FortiGate">`
- **Primary Check Type:** `CONFIG_CHECK`
- **Key Fields:** `context`, `regex`, `expect`

#### Example FortiOS Global Item:
```xml
<custom_item>
  type: CONFIG_CHECK
  description: "Fortinet_01 Enforce HTTPS Admin Port"
  info: "Ensure admin HTTPS port is shifted from default 443 to 8443."
  solution: "config system global -> set admin-sport 8443 -> end"
  reference: "NIST-800-53|AC-17"
  severity: MEDIUM
  context: "config system global"
  regex: "set admin-sport [0-9]+"
  expect: "set admin-sport 8443"
</custom_item>
```

#### Example FortiAP Radio Item:
```xml
<custom_item>
  type: CONFIG_CHECK
  description: "NIMF_WIFI_34 Exclude Legacy 802.11b Rates on Radio 1"
  info: "Ensure legacy 802.11b rates are excluded to prevent airtime starvation."
  solution: "config wireless-controller wtp -> edit <AP> -> config radio-1 -> set band 802.11g 802.11n-2G 802.11ax-2G -> end"
  reference: "NIST-800-53|AC-18,CIS-CSCv8|12.1"
  severity: HIGH
  context: "config wireless-controller wtp"
  regex: "set band [^\n]+"
  expect: "set band 802.11g 802.11n-2G 802.11ax-2G"
</custom_item>
```

#### Important FortiGate Rules:
- Context reflects FortiOS CLI hierarchy: `context: "config system global"` or `context: "config wireless-controller wtp"`.
- Do not include `end` or `next` in regex or expect. Match the parameter line directly.
- Multi-word values enclosed in quotes in FortiOS must be handled in regex, e.g. `set name "[^"]+"`.

---

### 3.3 Linux & Unix (RHEL 8 / 9, SUSE SLES 15)

- **Header:** `<check_type:"Unix">`
- **Primary Check Types:**
  - `FILE_CONTENT_CHECK`: Verify directives inside config files.
  - `FILE_CHECK`: Verify file existence, owner, and permissions.
  - `CMD_EXEC`: Execute shell commands and evaluate stdout.
  - `RPM_CHECK`: Verify package installation state on Red Hat/SUSE.

#### Example RHEL / SUSE Items:
```xml
<custom_item>
  type: FILE_CONTENT_CHECK
  description: "Ensure SSH PermitRootLogin is Disabled"
  info: "Prevent direct remote login as the root superuser."
  solution: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
  reference: "CIS-CSCv8|4.1,NIST-800-53|AC-6"
  severity: HIGH
  file: "/etc/ssh/sshd_config"
  regex: "^\\s*PermitRootLogin\\s+"
  expect: "^\\s*PermitRootLogin\\s+no\\s*$"
</custom_item>

<custom_item>
  type: FILE_CHECK
  description: "Ensure /etc/shadow permissions are 0000 or 0640"
  info: "Shadow password file must be protected from unprivileged read."
  solution: "chmod 0640 /etc/shadow"
  reference: "CIS-CSCv8|3.3"
  severity: HIGH
  file: "/etc/shadow"
  owner: "root"
  mask: "027"
</custom_item>
```

#### Important Unix Rules:
- Never use `context:` in Unix checks.
- Backslashes in regular expressions must be double-escaped: `^\\s*` instead of `^\s*`.
- Use anchors `^` and `$` to prevent substring matching false positives.

---

## 4. How to Handle "Manual Review Required" Controls

Certain security requirements cannot be audited purely through static string parsing (e.g., verifying that FortiOS firmware is currently supported and within the N-1 upgrade lifecycle, or verifying physical AP antenna mounting).

To flag these items in Nessus reports for manual auditor review without failing the parser:

```xml
<custom_item>
  type: CONFIG_CHECK
  description: "Fortinet_7_11 Keep your FortiOS firmware up to date"
  info: "Manual Review Required: Verify FortiGate firmware against the latest vendor release notes."
  solution: "Review Fortinet Upgrade Path tool and apply latest patch release."
  reference: "CIS-CSCv8|7.1,NIST-800-53|SI-2"
  see_also: "https://workbench.cisecurity.org/benchmarks/24708"
  severity: MEDIUM
  context: "config system global"
  regex: ".*"
  expect: "^Manual Review Required$"
</custom_item>
```

- When Nessus evaluates this, the `expect` pattern (`^Manual Review Required$`) will not match standard configuration lines.
- Nessus flags the item with **WARNING / Manual Review Required**, surfacing the full description and solution instructions to the compliance officer.

---

## 5. Offline Configuration File Preparation Checklist

When running offline compliance scans in Nessus:

1. **Remove Shell Prompts**:
   Remove lines starting with `hostname #`, `(config) #`, or `(wtp) #`.
2. **Remove Command Invocations**:
   Remove interactive command lines such as `show`, `show running-config`, or `display current-configuration`.
3. **Include Version Banners**:
   - For FortiOS: `#config-version=MODEL-VERSION-BUILD`
   - For Cisco: `version 17.x` and `hostname <name>`
4. **Preserve Exact Indentation**:
   FortiOS and Cisco sub-blocks rely on indentation or `config`/`edit`/`end` pairing. Do not flatten block structures.
5. **Save in UTF-8 without BOM**:
   Always save offline configuration files and `.audit` files with standard UTF-8 encoding without Byte Order Mark (BOM).

---

## 6. Pre-Flight Validation Script

Use this lightweight Python script to validate your `.audit` file for syntax errors, smart quotes, illegal dashes, and unclosed tags before uploading to Nessus:

```python
import sys
import re

def validate_audit_file(filepath):
    print(f"Validating audit file: {filepath}")
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    errors = 0

    # Check 1: Em-dashes and En-dashes
    em_dashes = content.count('\u2014')
    en_dashes = content.count('\u2013')
    if em_dashes > 0 or en_dashes > 0:
        print(f"[FAIL] Found Unicode dashes: {em_dashes} em-dashes, {en_dashes} en-dashes. Replace with hyphens (-).")
        errors += 1

    # Check 2: Smart quotes
    smart_quotes = len(re.findall(r'[\u2018\u2019\u201C\u201D]', content))
    if smart_quotes > 0:
        print(f"[FAIL] Found {smart_quotes} curly/smart quotes. Replace with standard ASCII quotes (\").")
        errors += 1

    # Check 3: Unsupported check types
    if "CONFIG_CHECK_NOT" in content:
        print("[FAIL] Found unsupported check type 'CONFIG_CHECK_NOT'. Use regex negative lookahead or <condition type:\"NOT\">.")
        errors += 1

    # Check 4: Tag pairing
    for tag in ['item', 'custom_item', 'condition', 'if', 'then', 'else', 'group_policy']:
        open_tags = len(re.findall(rf'<{tag}(\s+[^>]*>|>)', content))
        close_tags = len(re.findall(rf'</{tag}>', content))
        if open_tags != close_tags:
            print(f"[FAIL] Tag mismatch for <{tag}>: {open_tags} opened, {close_tags} closed.")
            errors += 1

    if errors == 0:
        print("[SUCCESS] All syntax and lexer validation checks passed clean!")
        return True
    else:
        print(f"[ERROR] Validation failed with {errors} issues.")
        return False

if __name__ == '__main__':
    if len(sys.argv) > 1:
        validate_audit_file(sys.argv[1])
    else:
        print("Usage: python validate_audit.py <path_to_audit_file>")
```

---

## 7. Quick Reference: Valid Tags & Values

| Field | Allowed Check Types | Description | Example |
| :--- | :--- | :--- | :--- |
| `type:` | All | The check engine mechanism | `CONFIG_CHECK`, `FILE_CONTENT_CHECK`, `CMD_EXEC` |
| `description:` | All | Human-readable control title | `"NIMF_CTRL_01 Enforce SSHv2"` |
| `info:` | All | Detailed technical explanation | `"SSHv1 is susceptible to man in the middle attacks."` |
| `solution:` | All | Step-by-step CLI remediation | `"config system global -> set admin-sport 8443"` |
| `reference:` | All | Standards alignment | `"CIS-CSCv8\|4.1,NIST-800-53\|AC-17"` |
| `see_also:` | All | Web URL reference | `"https://workbench.cisecurity.org/"` |
| `severity:` | All | Risk rating | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `PASSED` |
| `context:` | Cisco, FortiGate | Hierarchical CLI configuration section | `"config system global"`, `"line vty 0 4"` |
| `regex:` | All | PCRE regular expression to match | `"set admin-sport [0-9]+"` |
| `expect:` | All | Expected string or pattern for compliance | `"set admin-sport 8443"` |
| `file:` | Unix, Windows | Path to the target configuration file | `"/etc/ssh/sshd_config"` |
| `mask:` | Unix | Octal permission mask | `"027"` |
| `owner:` | Unix | Expected file owner | `"root"` |
